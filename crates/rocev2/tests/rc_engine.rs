//! Black-box RC endpoint execution and reliability tests.

use rocev2::io::{Frame, MockIo};
use rocev2::memory::AccessFlags;
use rocev2::wire::{Aeth, AethClass, Bth, Opcode, PacketSpec};
use rocev2::{
    Completion, CompletionOpcode, CompletionStatus, Ipv4Path, PathMtu, Psn, QpConfig, QpHandle,
    QpState, RcEndpoint, RcEndpointConfig, RcQpConfig, RecvWorkRequest, Sge, WorkRequest,
    decode_ipv4_packet, encode_ipv4_packet,
};

type TestEndpoint<'a> = RcEndpoint<'a, MockIo, 2, 8, 8, 8, 16, 4>;

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

#[test]
fn rc_qpn_index_tracks_collision_removal_and_reconfiguration() {
    let mut endpoint = endpoint();
    let first = endpoint
        .create_qp(qp_config(2, 20, 10, 30, [192, 0, 2, 1], [192, 0, 2, 20]))
        .unwrap();
    let second = endpoint
        .create_qp(qp_config(3, 30, 20, 40, [192, 0, 2, 1], [192, 0, 2, 30]))
        .unwrap();
    endpoint.remove_qp(first).unwrap();
    endpoint
        .reconfigure_qp(
            second,
            qp_config(10, 30, 20, 40, [192, 0, 2, 1], [192, 0, 2, 30]),
        )
        .unwrap();
    endpoint.transition_qp(second, QpState::Init).unwrap();
    endpoint.transition_qp(second, QpState::Rtr).unwrap();

    let peer_path = Ipv4Path::new([192, 0, 2, 30], [192, 0, 2, 1], 49_152);
    let mut packet = [0_u8; 512];
    let mut receive = [0_u8; 512];
    let mut transmit = [0_u8; 512];

    let old_length = encode_ipv4_packet(
        peer_path,
        PacketSpec {
            bth: Bth::new(Opcode::SendOnly, 3, 40),
            reth: None,
            aeth: None,
            immediate_data: None,
            payload: b"old",
        },
        &mut packet,
    )
    .unwrap();
    endpoint
        .io_mut()
        .inject_receive(&packet[..old_length])
        .unwrap();
    assert!(matches!(
        endpoint.progress(0, &mut receive, &mut transmit),
        Err(rocev2::PollError::Api(
            rocev2::ApiError::UnknownDestinationQpn(3)
        ))
    ));

    let new_length = encode_ipv4_packet(
        peer_path,
        PacketSpec {
            bth: Bth::new(Opcode::SendOnly, 10, 40),
            reth: None,
            aeth: None,
            immediate_data: None,
            payload: b"new",
        },
        &mut packet,
    )
    .unwrap();
    endpoint
        .io_mut()
        .inject_receive(&packet[..new_length])
        .unwrap();
    let progress = endpoint.progress(1, &mut receive, &mut transmit).unwrap();
    assert_eq!(progress.received_packets, 1);
    assert_eq!(progress.transmitted_packets, 1);
}

fn read_replay_qps(requester: &mut TestEndpoint<'_>, responder: &mut TestEndpoint<'_>) -> QpHandle {
    let requester_qp = requester
        .create_qp(qp_config(
            2,
            3,
            100,
            200,
            [203, 0, 113, 10],
            [203, 0, 113, 11],
        ))
        .unwrap();
    let responder_qp = responder
        .create_qp(qp_config(
            3,
            2,
            200,
            100,
            [203, 0, 113, 11],
            [203, 0, 113, 10],
        ))
        .unwrap();
    ready(requester, requester_qp);
    ready(responder, responder_qp);
    requester_qp
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

fn inject_ack(endpoint: &mut TestEndpoint<'_>, path: Ipv4Path, destination_qpn: u32, psn: u32) {
    let mut packet = [0_u8; 512];
    let length = encode_ipv4_packet(
        path,
        PacketSpec {
            bth: Bth::new(Opcode::Acknowledge, destination_qpn, psn),
            reth: None,
            aeth: Some(Aeth::ack(0)),
            immediate_data: None,
            payload: &[],
        },
        &mut packet,
    )
    .unwrap();
    endpoint.io_mut().inject_receive(&packet[..length]).unwrap();
}

fn packet_identity(frame: &Frame) -> (Opcode, u32) {
    let decoded = decode_ipv4_packet(frame.as_bytes()).unwrap();
    (decoded.transport.bth.opcode, decoded.transport.bth.psn)
}

fn complete_two_packet_read(
    requester: &mut TestEndpoint<'_>,
    responder: &mut TestEndpoint<'_>,
    requester_qp: QpHandle,
    work: WorkRequest,
    request_psn: u32,
    now: u64,
) -> Frame {
    let mut requester_rx = [0_u8; 512];
    let mut requester_tx = [0_u8; 512];
    let mut responder_rx = [0_u8; 512];
    let mut responder_tx = [0_u8; 512];

    requester.post_work(requester_qp, work).unwrap();
    requester
        .progress(now, &mut requester_rx, &mut requester_tx)
        .unwrap();
    let request = requester.io_mut().pop_transmitted().unwrap();
    assert_eq!(
        packet_identity(&request),
        (Opcode::RdmaReadRequest, request_psn),
    );
    responder
        .io_mut()
        .inject_receive(request.as_bytes())
        .unwrap();
    responder
        .progress(now, &mut responder_rx, &mut responder_tx)
        .unwrap();

    for (offset, opcode) in [Opcode::RdmaReadResponseFirst, Opcode::RdmaReadResponseLast]
        .into_iter()
        .enumerate()
    {
        let response = responder.io_mut().pop_transmitted().unwrap();
        assert_eq!(
            packet_identity(&response),
            (opcode, request_psn + offset as u32),
        );
        requester
            .io_mut()
            .inject_receive(response.as_bytes())
            .unwrap();
        requester
            .progress(now + offset as u64, &mut requester_rx, &mut requester_tx)
            .unwrap();
        if offset == 0 {
            responder
                .progress(now + 1, &mut responder_rx, &mut responder_tx)
                .unwrap();
        }
    }

    assert!(
        requester
            .poll_completion(requester_qp)
            .unwrap()
            .is_some_and(Completion::is_success)
    );
    request
}

fn begin_two_packet_read(
    requester: &mut TestEndpoint<'_>,
    responder: &mut TestEndpoint<'_>,
    requester_qp: QpHandle,
    work: WorkRequest,
    request_psn: u32,
    now: u64,
) -> Frame {
    let mut requester_rx = [0_u8; 512];
    let mut requester_tx = [0_u8; 512];
    let mut responder_rx = [0_u8; 512];
    let mut responder_tx = [0_u8; 512];

    requester.post_work(requester_qp, work).unwrap();
    requester
        .progress(now, &mut requester_rx, &mut requester_tx)
        .unwrap();
    let request = requester.io_mut().pop_transmitted().unwrap();
    assert_eq!(
        packet_identity(&request),
        (Opcode::RdmaReadRequest, request_psn),
    );
    responder
        .io_mut()
        .inject_receive(request.as_bytes())
        .unwrap();
    responder
        .progress(now, &mut responder_rx, &mut responder_tx)
        .unwrap();
    let first_response = responder.io_mut().pop_transmitted().unwrap();
    assert_eq!(
        packet_identity(&first_response),
        (Opcode::RdmaReadResponseFirst, request_psn),
    );
    requester
        .io_mut()
        .inject_receive(first_response.as_bytes())
        .unwrap();
    requester
        .progress(now, &mut requester_rx, &mut requester_tx)
        .unwrap();
    request
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

#[test]
fn rejects_ack_for_reserved_but_unsent_psn() {
    let mut source = [0x6a_u8; 300];
    let mut requester = endpoint();
    let source_mr = requester
        .register_memory(&mut source, AccessFlags::NONE)
        .unwrap();
    let requester_qp = requester
        .create_qp(qp_config(2, 3, 10, 40, [192, 0, 2, 10], [192, 0, 2, 11]))
        .unwrap();
    ready(&mut requester, requester_qp);
    requester
        .post_work(
            requester_qp,
            WorkRequest::send(
                7,
                Sge::new(source_mr.address(), 300, source_mr.lkey()),
                true,
            ),
        )
        .unwrap();

    let mut rx = [0_u8; 512];
    let mut tx = [0_u8; 512];
    requester.progress(0, &mut rx, &mut tx).unwrap();
    let first = requester.io_mut().pop_transmitted().unwrap();
    assert_eq!(packet_identity(&first), (Opcode::SendFirst, 10));

    inject_ack(
        &mut requester,
        Ipv4Path::new([192, 0, 2, 11], [192, 0, 2, 10], 49_153),
        2,
        11,
    );
    requester.progress(1, &mut rx, &mut tx).unwrap();

    assert_eq!(
        requester.poll_completion(requester_qp).unwrap(),
        Some(Completion::failure(
            7,
            CompletionOpcode::Send,
            CompletionStatus::TransportError,
        ))
    );
    assert_eq!(requester.qp_state(requester_qp), Ok(QpState::Error));
}

#[test]
fn delayed_ack_after_timeout_can_cover_packets_sent_before_retry() {
    let mut source = [0x7b_u8; 300];
    let mut requester = endpoint();
    let source_mr = requester
        .register_memory(&mut source, AccessFlags::NONE)
        .unwrap();
    let requester_qp = requester
        .create_qp(qp_config(
            2,
            3,
            20,
            70,
            [198, 51, 100, 10],
            [198, 51, 100, 11],
        ))
        .unwrap();
    ready(&mut requester, requester_qp);
    requester
        .post_work(
            requester_qp,
            WorkRequest::send(
                8,
                Sge::new(source_mr.address(), 300, source_mr.lkey()),
                true,
            ),
        )
        .unwrap();

    let mut rx = [0_u8; 512];
    let mut tx = [0_u8; 512];
    requester.progress(0, &mut rx, &mut tx).unwrap();
    assert_eq!(
        packet_identity(&requester.io_mut().pop_transmitted().unwrap()),
        (Opcode::SendFirst, 20),
    );
    requester.progress(1, &mut rx, &mut tx).unwrap();
    assert_eq!(
        packet_identity(&requester.io_mut().pop_transmitted().unwrap()),
        (Opcode::SendLast, 21),
    );

    inject_ack(
        &mut requester,
        Ipv4Path::new([198, 51, 100, 11], [198, 51, 100, 10], 49_153),
        2,
        21,
    );
    requester.progress(6, &mut rx, &mut tx).unwrap();

    assert_eq!(
        requester.poll_completion(requester_qp).unwrap(),
        Some(Completion::success(8, CompletionOpcode::Send, 300))
    );
    assert_eq!(requester.qp_state(requester_qp), Ok(QpState::Rts));
    assert_eq!(requester.stats().retransmissions, 1);
}

#[test]
fn stale_duplicate_read_does_not_replace_active_response() {
    let mut local = [0_u8; 300];
    let mut remote = [0x4c_u8; 300];
    let mut requester = endpoint();
    let mut responder = endpoint();
    let local_mr = requester
        .register_memory(&mut local, AccessFlags::LOCAL_WRITE)
        .unwrap();
    let remote_mr = responder
        .register_memory(&mut remote, AccessFlags::REMOTE_READ)
        .unwrap();
    let requester_qp = read_replay_qps(&mut requester, &mut responder);

    let read = |id| {
        WorkRequest::read(
            id,
            Sge::new(local_mr.address(), 300, local_mr.lkey()),
            remote_mr.address(),
            remote_mr.rkey(),
            true,
        )
    };
    let old_request = complete_two_packet_read(
        &mut requester,
        &mut responder,
        requester_qp,
        read(1),
        100,
        0,
    );
    begin_two_packet_read(
        &mut requester,
        &mut responder,
        requester_qp,
        read(2),
        102,
        10,
    );

    let mut requester_rx = [0_u8; 512];
    let mut requester_tx = [0_u8; 512];
    let mut responder_rx = [0_u8; 512];
    let mut responder_tx = [0_u8; 512];
    responder
        .io_mut()
        .inject_receive(old_request.as_bytes())
        .unwrap();
    responder
        .progress(11, &mut responder_rx, &mut responder_tx)
        .unwrap();
    let stale_reply = responder.io_mut().pop_transmitted().unwrap();
    let decoded = decode_ipv4_packet(stale_reply.as_bytes()).unwrap();
    assert_eq!(decoded.transport.bth.opcode, Opcode::Acknowledge);
    assert!(matches!(
        decoded.transport.aeth.map(Aeth::class),
        Some(AethClass::RnrNak { .. })
    ));

    responder
        .progress(12, &mut responder_rx, &mut responder_tx)
        .unwrap();
    let current_last = responder.io_mut().pop_transmitted().unwrap();
    assert_eq!(
        packet_identity(&current_last),
        (Opcode::RdmaReadResponseLast, 103),
    );
    requester
        .io_mut()
        .inject_receive(current_last.as_bytes())
        .unwrap();
    requester
        .progress(12, &mut requester_rx, &mut requester_tx)
        .unwrap();

    assert_eq!(
        requester.poll_completion(requester_qp).unwrap(),
        Some(Completion::success(2, CompletionOpcode::RdmaRead, 300))
    );
    assert_eq!(requester.stats().retransmissions, 0);
}
