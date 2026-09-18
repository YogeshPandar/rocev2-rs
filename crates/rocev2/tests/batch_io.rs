//! batched packet ownership and endpoint progress tests.

use rocev2::io::FixedPacketIo;
use rocev2::memory::AccessFlags;
use rocev2::wire::{Bth, Opcode, PacketSpec, Reth};
use rocev2::{
    Completion, CompletionOpcode, CompletionStatus, Ipv4Path, PathMtu, Psn, QpConfig, QpState,
    RcEndpoint, RcEndpointConfig, RcQpConfig, RecvWorkRequest, Sge, WorkRequest,
    decode_ipv4_packet, encode_ipv4_packet,
};

type BatchEndpoint<'a> = RcEndpoint<'a, FixedPacketIo<8, 8, 512>, 2, 8, 8, 8, 16, 4>;

fn endpoint<'a>() -> BatchEndpoint<'a> {
    RcEndpoint::new(
        FixedPacketIo::new(),
        RcEndpointConfig {
            maximum_packet_size: 512,
            ticks_per_second: 1_000_000,
            memory_key_seed: 11,
        },
    )
    .unwrap()
}

fn config() -> RcQpConfig {
    RcQpConfig {
        transport: QpConfig {
            local_qpn: 2,
            remote_qpn: 20,
            send_psn: Psn::new_truncated(10),
            receive_psn: Psn::new_truncated(30),
            path_mtu: PathMtu::Mtu256,
            retry_count: 3,
            rnr_retry_count: 3,
            timeout: 0,
        },
        path: Ipv4Path::new([192, 0, 2, 1], [192, 0, 2, 20], 49_152),
        rnr_nak_timer: 1,
    }
}

fn ready(endpoint: &mut BatchEndpoint<'_>, qp: rocev2::QpHandle) {
    endpoint.transition_qp(qp, QpState::Init).unwrap();
    endpoint.transition_qp(qp, QpState::Rtr).unwrap();
    endpoint.transition_qp(qp, QpState::Rts).unwrap();
}

fn peer_send(psn: u32, payload: &[u8], output: &mut [u8]) -> usize {
    encode_ipv4_packet(
        Ipv4Path::new([192, 0, 2, 20], [192, 0, 2, 1], 49_152),
        PacketSpec {
            bth: Bth::new(Opcode::SendOnly, 2, psn),
            reth: None,
            aeth: None,
            immediate_data: None,
            payload,
        },
        output,
    )
    .unwrap()
}

#[test]
fn progress_batch_processes_receive_and_control_bursts() {
    let mut endpoint = endpoint();
    let mut memory = [0_u8; 16];
    let mr = endpoint
        .register_memory(&mut memory, AccessFlags::LOCAL_WRITE)
        .unwrap();
    let qp = endpoint.create_qp(config()).unwrap();
    ready(&mut endpoint, qp);

    let receives = [
        RecvWorkRequest::new(1, Sge::new(mr.address(), 3, mr.lkey())),
        RecvWorkRequest::new(2, Sge::new(mr.address() + 3, 2, mr.lkey())),
    ];
    assert_eq!(endpoint.post_receive_batch(qp, &receives).unwrap(), 2);

    let mut packet = [0_u8; 512];
    let first = peer_send(30, b"abc", &mut packet);
    endpoint.io_mut().inject_receive(&packet[..first]).unwrap();
    let second = peer_send(31, b"de", &mut packet);
    endpoint.io_mut().inject_receive(&packet[..second]).unwrap();

    let progress = endpoint.progress_batch(0, 8).unwrap();
    assert_eq!(progress.received_packets, 2);
    assert_eq!(progress.transmitted_packets, 2);
    assert_eq!(progress.completions, 2);

    let mut copied = [0_u8; 5];
    endpoint
        .memory_registry_mut()
        .read_local(mr.lkey(), mr.address(), &mut copied)
        .unwrap();
    assert_eq!(&copied, b"abcde");

    let placeholder = Completion::failure(0, CompletionOpcode::Receive, CompletionStatus::Flushed);
    let mut completions = [placeholder; 2];
    assert_eq!(endpoint.poll_completions(qp, &mut completions).unwrap(), 2);
    assert_eq!(completions[0].work_request_id, 1);
    assert_eq!(completions[1].work_request_id, 2);
    assert!(completions.into_iter().all(Completion::is_success));

    for _ in 0..2 {
        let frame = endpoint.io_mut().pop_transmitted().unwrap();
        let decoded = decode_ipv4_packet(frame.as_bytes()).unwrap();
        assert_eq!(decoded.transport.bth.opcode, Opcode::Acknowledge);
    }
}

#[test]
fn progress_batch_encodes_requester_payload_from_registered_memory() {
    let mut endpoint = endpoint();
    let mut source = *b"batch-send-payload";
    let mr = endpoint
        .register_memory(&mut source, AccessFlags::NONE)
        .unwrap();
    let qp = endpoint.create_qp(config()).unwrap();
    ready(&mut endpoint, qp);
    endpoint
        .post_work(
            qp,
            WorkRequest::send(
                7,
                Sge::new(mr.address(), u32::try_from(mr.length()).unwrap(), mr.lkey()),
                true,
            ),
        )
        .unwrap();

    let progress = endpoint.progress_batch(0, 8).unwrap();
    assert_eq!(progress.transmitted_packets, 1);
    let frame = endpoint.io_mut().pop_transmitted().unwrap();
    let decoded = decode_ipv4_packet(frame.as_bytes()).unwrap();
    assert_eq!(decoded.transport.bth.opcode, Opcode::SendOnly);
    assert_eq!(decoded.transport.bth.destination_qpn, 20);
    assert_eq!(decoded.transport.bth.psn, 10);
    assert_eq!(decoded.transport.payload, b"batch-send-payload");
}

#[test]
fn progress_batch_encodes_read_response_from_registered_memory() {
    let mut endpoint = endpoint();
    let mut source = *b"read-data";
    let mr = endpoint
        .register_memory(&mut source, AccessFlags::REMOTE_READ)
        .unwrap();
    let qp = endpoint.create_qp(config()).unwrap();
    ready(&mut endpoint, qp);

    let mut packet = [0_u8; 512];
    let request_length = encode_ipv4_packet(
        Ipv4Path::new([192, 0, 2, 20], [192, 0, 2, 1], 49_152),
        PacketSpec {
            bth: Bth::new(Opcode::RdmaReadRequest, 2, 30),
            reth: Some(Reth {
                virtual_address: mr.address(),
                remote_key: mr.rkey(),
                dma_length: u32::try_from(source.len()).unwrap(),
            }),
            aeth: None,
            immediate_data: None,
            payload: &[],
        },
        &mut packet,
    )
    .unwrap();
    endpoint
        .io_mut()
        .inject_receive(&packet[..request_length])
        .unwrap();

    let progress = endpoint.progress_batch(0, 8).unwrap();
    assert_eq!(progress.received_packets, 1);
    assert_eq!(progress.transmitted_packets, 1);
    let frame = endpoint.io_mut().pop_transmitted().unwrap();
    let decoded = decode_ipv4_packet(frame.as_bytes()).unwrap();
    assert_eq!(decoded.transport.bth.opcode, Opcode::RdmaReadResponseOnly);
    assert_eq!(decoded.transport.bth.destination_qpn, 20);
    assert_eq!(decoded.transport.bth.psn, 30);
    assert_eq!(decoded.transport.payload, b"read-data");
}

#[test]
fn batched_receive_post_is_atomic_on_capacity_failure() {
    type SmallEndpoint<'a> = RcEndpoint<'a, FixedPacketIo<2, 2, 512>, 1, 2, 1, 1, 2, 2>;
    let mut endpoint = SmallEndpoint::new(
        FixedPacketIo::new(),
        RcEndpointConfig {
            maximum_packet_size: 512,
            ticks_per_second: 1_000_000,
            memory_key_seed: 13,
        },
    )
    .unwrap();
    let mut memory = [0_u8; 8];
    let mr = endpoint
        .register_memory(&mut memory, AccessFlags::LOCAL_WRITE)
        .unwrap();
    let qp = endpoint.create_qp(config()).unwrap();
    endpoint.transition_qp(qp, QpState::Init).unwrap();
    endpoint.transition_qp(qp, QpState::Rtr).unwrap();

    let receives = [
        RecvWorkRequest::new(1, Sge::new(mr.address(), 1, mr.lkey())),
        RecvWorkRequest::new(2, Sge::new(mr.address() + 1, 1, mr.lkey())),
    ];
    assert!(matches!(
        endpoint.post_receive_batch(qp, &receives),
        Err(rocev2::ApiError::QueueFull(rocev2::QueueKind::Receive))
    ));
    assert_eq!(endpoint.stats().posted_receive_requests, 0);
}
