//! Steady-state allocation regression tests with per-thread measurement.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::marker::PhantomData;

use rocev2::io::FixedPacketIo;
use rocev2::wire::Opcode;
use rocev2::{
    AccessFlags, Completion, CompletionOpcode, CompletionStatus, Ipv4Path, PathMtu, Psn, QpConfig,
    QpHandle, QpState, RcEndpoint, RcEndpointConfig, RcQpConfig, RecvWorkRequest, Sge, WorkRequest,
    decode_ipv4_packet,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Counts {
    alloc: u64,
    zeroed: u64,
    realloc: u64,
    dealloc: u64,
}

thread_local! {
    // Const TLS avoids allocator recursion and excludes other test threads.
    static COUNTS: Cell<Option<Counts>> = const { Cell::new(None) };
}

struct CountingAllocator;

fn record(operation: u8) {
    let _ = COUNTS.try_with(|cell| {
        if let Some(mut counts) = cell.get() {
            match operation {
                0 => counts.alloc = counts.alloc.wrapping_add(1),
                1 => counts.zeroed = counts.zeroed.wrapping_add(1),
                2 => counts.realloc = counts.realloc.wrapping_add(1),
                _ => counts.dealloc = counts.dealloc.wrapping_add(1),
            }
            cell.set(Some(counts));
        }
    });
}

// SAFETY: every allocation operation delegates its unchanged contract to System.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(0);
        // SAFETY: the caller supplies a valid nonzero layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(1);
        // SAFETY: the caller supplies a valid nonzero layout.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(2);
        // SAFETY: the caller owns ptr under layout and provides a valid new size.
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        record(3);
        // SAFETY: the caller transfers the live allocation described by layout.
        unsafe { System.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct Measurement(PhantomData<*mut ()>);

impl Measurement {
    fn begin() -> Self {
        COUNTS.with(|cell| {
            assert!(cell.get().is_none(), "nested allocation measurement");
            cell.set(Some(Counts::default()));
        });
        Self(PhantomData)
    }

    fn finish(self) -> Counts {
        COUNTS.with(|cell| cell.take().unwrap())
    }
}

impl Drop for Measurement {
    fn drop(&mut self) {
        // A panic must not leave counting enabled on the test thread.
        let _ = COUNTS.try_with(|cell| cell.set(None));
    }
}

type Endpoint<'a> = RcEndpoint<'a, FixedPacketIo<16, 16, 512>, 1, 4, 4, 4, 8, 2>;

fn endpoint<'a>() -> Endpoint<'a> {
    RcEndpoint::new(
        FixedPacketIo::new(),
        RcEndpointConfig {
            maximum_packet_size: 512,
            ticks_per_second: 1_000_000,
            memory_key_seed: 97,
        },
    )
    .unwrap()
}

fn connect(endpoint: &mut Endpoint<'_>, local: u8, remote: u8) -> QpHandle {
    let handle = endpoint
        .create_qp(RcQpConfig {
            transport: QpConfig {
                local_qpn: u32::from(local),
                remote_qpn: u32::from(remote),
                send_psn: Psn::new_truncated(0x00ff_fffe),
                receive_psn: Psn::new_truncated(0x00ff_fffe),
                path_mtu: PathMtu::Mtu256,
                retry_count: 6,
                rnr_retry_count: 7,
                timeout: 8,
            },
            path: Ipv4Path::new([192, 0, 2, local], [192, 0, 2, remote], 49_152),
            rnr_nak_timer: 1,
        })
        .unwrap();
    for state in [QpState::Init, QpState::Rtr, QpState::Rts] {
        endpoint.transition_qp(handle, state).unwrap();
    }
    handle
}

#[derive(Clone, Copy)]
enum Fault {
    None,
    Drop(Opcode),
    Duplicate(Opcode),
}

fn transfer(source: &mut Endpoint<'_>, target: &mut Endpoint<'_>, fault: &mut Fault) {
    while let Some(frame) = source.io_mut().pop_transmitted() {
        let opcode = decode_ipv4_packet(frame.as_bytes())
            .unwrap()
            .transport
            .bth
            .opcode;
        match *fault {
            Fault::Drop(expected) if opcode == expected => {
                *fault = Fault::None;
                continue;
            }
            Fault::Duplicate(expected) if opcode == expected => {
                target.io_mut().inject_receive(frame.as_bytes()).unwrap();
                *fault = Fault::None;
            }
            _ => {}
        }
        target.io_mut().inject_receive(frame.as_bytes()).unwrap();
    }
}

fn progress(endpoint: &mut Endpoint<'_>, now: u64, batch: bool) {
    if batch {
        endpoint.progress_batch(now, 8).unwrap();
    } else {
        endpoint
            .progress(now, &mut [0; 512], &mut [0; 512])
            .unwrap();
    }
}

fn workload(batch: bool, mut forward: Fault, mut reverse: Fault, rnr: bool) {
    let mut source = [0x5a; 769];
    let mut destination = [0; 769];
    let mut readback = [0; 769];
    let mut left = endpoint();
    let mut right = endpoint();
    let source_mr = left
        .register_memory(&mut source, AccessFlags::NONE)
        .unwrap();
    let read_mr = left
        .register_memory(&mut readback, AccessFlags::LOCAL_WRITE)
        .unwrap();
    let target_mr = right
        .register_memory(
            &mut destination,
            AccessFlags::LOCAL_WRITE | AccessFlags::REMOTE_WRITE | AccessFlags::REMOTE_READ,
        )
        .unwrap();
    let left_qp = connect(&mut left, 2, 3);
    let right_qp = connect(&mut right, 3, 2);
    let measurement = Measurement::begin();
    let mut now = 0;
    for size in [0, 1, 255, 256, 257, 769] {
        for operation in 0..3 {
            let receive =
                RecvWorkRequest::new(8, Sge::new(target_mr.address(), size, target_mr.lkey()));
            if operation == 0 && !rnr {
                assert_eq!(right.post_receive_batch(right_qp, &[receive]).unwrap(), 1);
            }
            let sge = Sge::new(source_mr.address(), size, source_mr.lkey());
            let work = match operation {
                0 => WorkRequest::send(9, sge, true),
                1 => WorkRequest::write(9, sge, target_mr.address(), target_mr.rkey(), true),
                _ => WorkRequest::read(
                    9,
                    Sge::new(read_mr.address(), size, read_mr.lkey()),
                    target_mr.address(),
                    target_mr.rkey(),
                    true,
                ),
            };
            assert_eq!(left.post_work_batch(left_qp, &[work]).unwrap(), 1);
            let mut completed = false;
            for step in 0..20_000 {
                if operation == 0 && rnr && step == 32 {
                    right.post_receive(right_qp, receive).unwrap();
                }
                progress(&mut left, now, batch);
                transfer(&mut left, &mut right, &mut forward);
                progress(&mut right, now, batch);
                transfer(&mut right, &mut left, &mut reverse);
                now += 1;
                let mut completions =
                    [Completion::failure(0, CompletionOpcode::Send, CompletionStatus::Flushed); 4];
                let count = left.poll_completions(left_qp, &mut completions).unwrap();
                if count != 0 {
                    assert_eq!(count, 1);
                    assert!(completions[0].is_success(), "{:?}", completions[0]);
                    completed = true;
                    break;
                }
            }
            assert!(
                completed,
                "operation did not complete within its test deadline"
            );
            if operation == 0 {
                assert!(
                    right
                        .poll_completion(right_qp)
                        .unwrap()
                        .unwrap()
                        .is_success()
                );
                assert!(right.poll_completion(right_qp).unwrap().is_none());
            }
            let mut actual = [0; 769];
            if operation == 2 {
                left.memory_registry_mut()
                    .read_local(
                        read_mr.lkey(),
                        read_mr.address(),
                        &mut actual[..size as usize],
                    )
                    .unwrap();
            } else {
                right
                    .memory_registry_mut()
                    .read_local(
                        target_mr.lkey(),
                        target_mr.address(),
                        &mut actual[..size as usize],
                    )
                    .unwrap();
            }
            assert!(actual[..size as usize].iter().all(|&value| value == 0x5a));
        }
    }
    if rnr {
        assert!(left.stats().rnr_naks > 0);
    }
    assert!(matches!(forward, Fault::None));
    assert!(matches!(reverse, Fault::None));
    let counts = measurement.finish();
    assert_eq!(counts, Counts::default());
}

#[test]
fn scalar_and_batch_packet_paths_do_not_allocate() {
    for batch in [false, true] {
        workload(batch, Fault::None, Fault::None, false);
        workload(
            batch,
            Fault::Drop(Opcode::RdmaWriteMiddle),
            Fault::None,
            false,
        );
        workload(batch, Fault::None, Fault::Drop(Opcode::Acknowledge), false);
        workload(batch, Fault::Duplicate(Opcode::SendOnly), Fault::None, true);
    }
}

#[test]
fn allocator_instrumentation_detects_every_operation() {
    let layout = Layout::from_size_align(16, 8).unwrap();
    let measurement = Measurement::begin();
    // SAFETY: layouts are valid; each successful allocation is freed exactly once.
    unsafe {
        let ptr = std::alloc::alloc(layout);
        assert!(!ptr.is_null());
        let replacement = std::alloc::realloc(ptr, layout, 32);
        assert!(!replacement.is_null());
        std::alloc::dealloc(replacement, Layout::from_size_align(32, 8).unwrap());
        let zeroed = std::alloc::alloc_zeroed(layout);
        assert!(!zeroed.is_null());
        std::hint::black_box(std::slice::from_raw_parts(zeroed, 16));
        std::alloc::dealloc(zeroed, layout);
    }
    assert_eq!(
        measurement.finish(),
        Counts {
            alloc: 1,
            zeroed: 1,
            realloc: 1,
            dealloc: 2
        }
    );
}
