//! Black-box RC endpoint execution and reliability tests.

use rocev2::io::{Frame, MockIo};
use rocev2::memory::AccessFlags;
use rocev2::{
    Completion, CompletionOpcode, CompletionStatus, Ipv4Path, PathMtu, Psn, QpConfig, QpHandle,
    QpState, RcEndpoint, RcEndpointConfig, RcQpConfig, RecvWorkRequest, Sge, WorkRequest,
};

type TestEndpoint<'a> = RcEndpoint<'a, MockIo, 2, 8, 8, 8, 16>;

fn endpoint<'a>() -> TestEndpoint<'a> {
    RcEndpoint::new(
        MockIo::new(512),
        RcEndpointConfig {
            maximum_packet_size: 512,
            ticks_per_second: 1_000_000,
            memory_key_seed: 7,
        },
    )
    .unwrap()
}

fn qp_config(
    local_qpn: u32,
    remote_qpn: u32,
    send_psn: u32,
    receive_psn: u32,
    local_ip: [u8; 4],
    remote_ip: [u8; 4],
) -> RcQpConfig {
    RcQpConfig {
        transport: QpConfig {
            local_qpn,
            remote_qpn,
            send_psn: Psn::new_truncated(send_psn),
            receive_psn: Psn::new_truncated(receive_psn),
            path_mtu: PathMtu::Mtu256,
            retry_count: 3,
            rnr_retry_count: 3,
            timeout: 0,
        },
        path: Ipv4Path::new(local_ip, remote_ip, 49_152),
        rnr_nak_timer: 1,
    }
}

fn ready(endpoint: &mut TestEndpoint<'_>, handle: QpHandle) {
    endpoint.transition_qp(handle, QpState::Init).unwrap();
    endpoint.transition_qp(handle, QpState::Rtr).unwrap();
    endpoint.transition_qp(handle, QpState::Rts).unwrap();
}

fn move_packets(source: &mut TestEndpoint<'_>, destination: &mut TestEndpoint<'_>) -> usize {
    let mut moved = 0;
    while let Some(frame) = source.io_mut().pop_transmitted() {
        destination
            .io_mut()
            .inject_receive(frame.as_bytes())
            .unwrap();
        moved += 1;
    }
    moved
}

fn pump(
    first: &mut TestEndpoint<'_>,
    second: &mut TestEndpoint<'_>,
    mut now: u64,
    iterations: usize,
) {
    let mut first_rx = [0_u8; 512];
    let mut first_tx = [0_u8; 512];
    let mut second_rx = [0_u8; 512];
    let mut second_tx = [0_u8; 512];
    for _ in 0..iterations {
        first.progress(now, &mut first_rx, &mut first_tx).unwrap();
        move_packets(first, second);
        second
            .progress(now, &mut second_rx, &mut second_tx)
            .unwrap();
        move_packets(second, first);
        now += 1;
    }
}

#[test]
fn executes_segmented_send_and_generates_both_completions() {
    let mut source = [0x5a_u8; 300];
    let mut destination = [0_u8; 320];
    let mut requester = endpoint();
    let mut responder = endpoint();
    let source_mr = requester
        .register_memory(&mut source, AccessFlags::NONE)
        .unwrap();
    let destination_mr = responder
        .register_memory(&mut destination, AccessFlags::LOCAL_WRITE)
        .unwrap();

    let requester_qp = requester
        .create_qp(qp_config(2, 3, 10, 40, [192, 0, 2, 1], [192, 0, 2, 2]))
        .unwrap();
    let responder_qp = responder
        .create_qp(qp_config(3, 2, 40, 10, [192, 0, 2, 2], [192, 0, 2, 1]))
        .unwrap();
    ready(&mut requester, requester_qp);
    ready(&mut responder, responder_qp);

    responder
        .post_receive(
            responder_qp,
            RecvWorkRequest::new(
                22,
                Sge::new(
                    destination_mr.address(),
                    destination_mr.length() as u32,
                    destination_mr.lkey(),
                ),
            ),
        )
        .unwrap();
    requester
        .post_work(
            requester_qp,
            WorkRequest::send(
                11,
                Sge::new(source_mr.address(), 300, source_mr.lkey()),
                true,
            ),
        )
        .unwrap();

    pump(&mut requester, &mut responder, 0, 32);

    assert_eq!(
        requester.poll_completion(requester_qp).unwrap(),
        Some(Completion::success(11, CompletionOpcode::Send, 300))
    );
    assert_eq!(
        responder.poll_completion(responder_qp).unwrap(),
        Some(Completion::success(22, CompletionOpcode::Receive, 300))
    );
    let destination = responder.deregister_memory(destination_mr).unwrap();
    assert_eq!(&destination[..300], &[0x5a; 300]);
}

#[test]
fn executes_rdma_write_and_read() {
    let mut write_source = [0x33_u8; 300];
    let mut local_read_destination = [0_u8; 300];
    let mut remote = [0_u8; 300];
    let mut requester = endpoint();
    let mut responder = endpoint();
    let write_source_mr = requester
        .register_memory(&mut write_source, AccessFlags::NONE)
        .unwrap();
    let read_destination_mr = requester
        .register_memory(&mut local_read_destination, AccessFlags::LOCAL_WRITE)
        .unwrap();
    let remote_mr = responder
        .register_memory(
            &mut remote,
            AccessFlags::LOCAL_WRITE | AccessFlags::REMOTE_WRITE | AccessFlags::REMOTE_READ,
        )
        .unwrap();

    let requester_qp = requester
        .create_qp(qp_config(
            2,
            3,
            100,
            200,
            [198, 51, 100, 1],
            [198, 51, 100, 2],
        ))
        .unwrap();
    let responder_qp = responder
        .create_qp(qp_config(
            3,
            2,
            200,
            100,
            [198, 51, 100, 2],
            [198, 51, 100, 1],
        ))
        .unwrap();
    ready(&mut requester, requester_qp);
    ready(&mut responder, responder_qp);

    requester
        .post_work(
            requester_qp,
            WorkRequest::write(
                1,
                Sge::new(write_source_mr.address(), 300, write_source_mr.lkey()),
                remote_mr.address(),
                remote_mr.rkey(),
                true,
            ),
        )
        .unwrap();
    pump(&mut requester, &mut responder, 0, 32);
    assert_eq!(
        requester.poll_completion(requester_qp).unwrap(),
        Some(Completion::success(1, CompletionOpcode::RdmaWrite, 300))
    );

    requester
        .post_work(
            requester_qp,
            WorkRequest::read(
                2,
                Sge::new(
                    read_destination_mr.address(),
                    300,
                    read_destination_mr.lkey(),
                ),
                remote_mr.address(),
                remote_mr.rkey(),
                true,
            ),
        )
        .unwrap();
    pump(&mut requester, &mut responder, 100, 48);
    assert_eq!(
        requester.poll_completion(requester_qp).unwrap(),
        Some(Completion::success(2, CompletionOpcode::RdmaRead, 300))
    );
    let destination = requester.deregister_memory(read_destination_mr).unwrap();
    assert_eq!(destination, &[0x33; 300]);
}

#[test]
fn rnr_nak_waits_and_retries_after_receive_is_posted() {
    let mut source = [7_u8; 8];
    let mut destination = [0_u8; 8];
    let mut requester = endpoint();
    let mut responder = endpoint();
    let source_mr = requester
        .register_memory(&mut source, AccessFlags::NONE)
        .unwrap();
    let destination_mr = responder
        .register_memory(&mut destination, AccessFlags::LOCAL_WRITE)
        .unwrap();
    let requester_qp = requester
        .create_qp(qp_config(2, 3, 1, 20, [203, 0, 113, 1], [203, 0, 113, 2]))
        .unwrap();
    let responder_qp = responder
        .create_qp(qp_config(3, 2, 20, 1, [203, 0, 113, 2], [203, 0, 113, 1]))
        .unwrap();
    ready(&mut requester, requester_qp);
    ready(&mut responder, responder_qp);
    requester
        .post_work(
            requester_qp,
            WorkRequest::send(1, Sge::new(source_mr.address(), 8, source_mr.lkey()), true),
        )
        .unwrap();

    pump(&mut requester, &mut responder, 0, 4);
    assert!(requester.poll_completion(requester_qp).unwrap().is_none());
    responder
        .post_receive(
            responder_qp,
            RecvWorkRequest::new(
                2,
                Sge::new(destination_mr.address(), 8, destination_mr.lkey()),
            ),
        )
        .unwrap();
    pump(&mut requester, &mut responder, 20, 24);

    assert!(
        requester
            .poll_completion(requester_qp)
            .unwrap()
            .is_some_and(Completion::is_success)
    );
    assert!(requester.stats().rnr_naks >= 1);
    assert!(requester.stats().retransmissions >= 1);
}

#[test]
fn timeout_retransmits_a_dropped_request() {
    let mut source = [9_u8; 8];
    let mut destination = [0_u8; 8];
    let mut requester = endpoint();
    let mut responder = endpoint();
    let source_mr = requester
        .register_memory(&mut source, AccessFlags::NONE)
        .unwrap();
    let destination_mr = responder
        .register_memory(&mut destination, AccessFlags::LOCAL_WRITE)
        .unwrap();
    let requester_qp = requester
        .create_qp(qp_config(2, 3, 5, 50, [10, 0, 0, 1], [10, 0, 0, 2]))
        .unwrap();
    let responder_qp = responder
        .create_qp(qp_config(3, 2, 50, 5, [10, 0, 0, 2], [10, 0, 0, 1]))
        .unwrap();
    ready(&mut requester, requester_qp);
    ready(&mut responder, responder_qp);
    responder
        .post_receive(
            responder_qp,
            RecvWorkRequest::new(
                2,
                Sge::new(destination_mr.address(), 8, destination_mr.lkey()),
            ),
        )
        .unwrap();
    requester
        .post_work(
            requester_qp,
            WorkRequest::send(1, Sge::new(source_mr.address(), 8, source_mr.lkey()), true),
        )
        .unwrap();

    let mut rx = [0_u8; 512];
    let mut tx = [0_u8; 512];
    requester.progress(0, &mut rx, &mut tx).unwrap();
    let dropped: Option<Frame> = requester.io_mut().pop_transmitted();
    assert!(dropped.is_some());

    pump(&mut requester, &mut responder, 5, 24);
    assert!(
        requester
            .poll_completion(requester_qp)
            .unwrap()
            .is_some_and(Completion::is_success)
    );
    assert!(requester.stats().timeout_events >= 1);
    assert!(requester.stats().retransmissions >= 1);
}

#[test]
fn invalid_remote_key_completes_with_remote_access_error() {
    let mut source = [1_u8; 4];
    let mut remote = [0_u8; 4];
    let mut requester = endpoint();
    let mut responder = endpoint();
    let source_mr = requester
        .register_memory(&mut source, AccessFlags::NONE)
        .unwrap();
    let remote_mr = responder
        .register_memory(
            &mut remote,
            AccessFlags::LOCAL_WRITE | AccessFlags::REMOTE_WRITE,
        )
        .unwrap();
    let requester_qp = requester
        .create_qp(qp_config(2, 3, 9, 90, [172, 16, 0, 1], [172, 16, 0, 2]))
        .unwrap();
    let responder_qp = responder
        .create_qp(qp_config(3, 2, 90, 9, [172, 16, 0, 2], [172, 16, 0, 1]))
        .unwrap();
    ready(&mut requester, requester_qp);
    ready(&mut responder, responder_qp);
    requester
        .post_work(
            requester_qp,
            WorkRequest::write(
                1,
                Sge::new(source_mr.address(), 4, source_mr.lkey()),
                remote_mr.address(),
                remote_mr.rkey() ^ 0x1000,
                true,
            ),
        )
        .unwrap();

    pump(&mut requester, &mut responder, 0, 16);
    assert_eq!(
        requester.poll_completion(requester_qp).unwrap(),
        Some(Completion::failure(
            1,
            CompletionOpcode::RdmaWrite,
            CompletionStatus::RemoteAccessError,
        ))
    );
    assert_eq!(requester.qp_state(requester_qp), Ok(QpState::Error));
}
