//! Black-box RC endpoint execution and reliability tests.

use rocev2::io::{
    FaultAction, FaultDirection, FaultInjectIo, FaultRule, Frame, MockIo, PacketIo,
};
use rocev2::memory::AccessFlags;
use rocev2::wire::{Aeth, AethClass, Bth, Opcode, PacketSpec, Reth};
use rocev2::{
    Completion, CompletionOpcode, CompletionStatus, Ipv4Path, PathMtu, Psn, QpConfig, QpHandle,
    QpState, RcEndpoint, RcEndpointConfig, RcQpConfig, RecvWorkRequest, Sge, WorkRequest,
    decode_ipv4_packet, encode_ipv4_packet,
};

type TestEndpoint<'a> = RcEndpoint<'a, MockIo, 2, 8, 8, 8, 16, 4>;
type FaultEndpoint<'a> = RcEndpoint<'a, FaultInjectIo<MockIo, 8, 512>, 2, 8, 8, 8, 16, 4>;

#[derive(Debug)]
struct FailOnceIo {
    fail_next_transmit: bool,
    receive: Option<Box<[u8]>>,
    transmitted: Option<Box<[u8]>>,
}

impl FailOnceIo {
    fn new() -> Self {
        Self {
            fail_next_transmit: true,
            receive: None,
            transmitted: None,
        }
    }

    fn inject_receive(&mut self, packet: &[u8]) {
        self.receive = Some(packet.into());
    }
}

impl PacketIo for FailOnceIo {
    type Error = std::io::Error;

    fn max_ipv4_packet(&self) -> usize {
        512
    }

    fn transmit_ipv4(&mut self, packet: &[u8]) -> Result<(), Self::Error> {
        if self.fail_next_transmit {
            self.fail_next_transmit = false;
            return Err(std::io::Error::other("injected transmit failure"));
        }
        self.transmitted = Some(packet.into());
        Ok(())
    }

    fn receive_ipv4(&mut self, output: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        let Some(packet) = self.receive.as_ref() else {
            return Ok(None);
        };
        if output.len() < packet.len() {
            return Err(std::io::Error::other(
                "injected receive buffer is too short",
            ));
        }
        let length = packet.len();
        output[..length].copy_from_slice(packet);
        self.receive = None;
        Ok(Some(length))
    }
}

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

fn fault_endpoint<'a>() -> FaultEndpoint<'a> {
    RcEndpoint::new(
        FaultInjectIo::new(MockIo::new(512)),
        RcEndpointConfig {
            maximum_packet_size: 512,
            ticks_per_second: 1_000_000,
            memory_key_seed: 17,
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

fn encode_read_request(
    output: &mut [u8],
    path: Ipv4Path,
    destination_qpn: u32,
    psn: u32,
    remote_address: u64,
    rkey: u32,
    length: u32,
) -> usize {
    encode_ipv4_packet(
        path,
        PacketSpec {
            bth: Bth::new(Opcode::RdmaReadRequest, destination_qpn, psn),
            reth: Some(Reth {
                virtual_address: remote_address,
                remote_key: rkey,
                dma_length: length,
            }),
            aeth: None,
            immediate_data: None,
            payload: &[],
        },
        output,
    )
    .unwrap()
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
    let dropped = endpoint.progress(0, &mut receive, &mut transmit).unwrap();
    assert_eq!(dropped.received_packets, 1);
    assert_eq!(dropped.transmitted_packets, 0);
    assert_eq!(endpoint.stats().unknown_qp_packets, 1);
    assert_eq!(endpoint.stats().dropped_packets, 1);

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

#[test]
fn malformed_and_wrong_peer_packets_are_contained_as_drops() {
    let mut endpoint = endpoint();
    let qp = endpoint
        .create_qp(qp_config(2, 3, 10, 30, [192, 0, 2, 1], [192, 0, 2, 2]))
        .unwrap();
    ready(&mut endpoint, qp);

    let mut packet = [0_u8; 512];
    let mut receive = [0_u8; 512];
    let mut transmit = [0_u8; 512];
    let wrong_peer = Ipv4Path::new([192, 0, 2, 99], [192, 0, 2, 1], 49_152);
    let length = encode_ipv4_packet(
        wrong_peer,
        PacketSpec {
            bth: Bth::new(Opcode::SendOnly, 2, 30),
            reth: None,
            aeth: None,
            immediate_data: None,
            payload: b"x",
        },
        &mut packet,
    )
    .unwrap();
    endpoint.io_mut().inject_receive(&packet[..length]).unwrap();
    let progress = endpoint.progress(0, &mut receive, &mut transmit).unwrap();
    assert_eq!(progress.received_packets, 1);
    assert_eq!(progress.transmitted_packets, 0);
    assert_eq!(endpoint.stats().peer_mismatch_packets, 1);
    assert_eq!(endpoint.stats().dropped_packets, 1);

    let correct_peer = Ipv4Path::new([192, 0, 2, 2], [192, 0, 2, 1], 49_152);
    let length = encode_ipv4_packet(
        correct_peer,
        PacketSpec {
            bth: Bth::new(Opcode::SendOnly, 2, 30),
            reth: None,
            aeth: None,
            immediate_data: None,
            payload: b"x",
        },
        &mut packet,
    )
    .unwrap();
    packet[length - 1] ^= 1;
    endpoint.io_mut().inject_receive(&packet[..length]).unwrap();
    let progress = endpoint.progress(1, &mut receive, &mut transmit).unwrap();
    assert_eq!(progress.received_packets, 1);
    assert_eq!(progress.transmitted_packets, 0);
    assert_eq!(endpoint.stats().invalid_packets, 1);
    assert_eq!(endpoint.stats().dropped_packets, 2);
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
fn fault_injector_drop_drives_real_timeout_retransmission() {
    let mut source = [0x39_u8; 8];
    let mut destination = [0_u8; 8];
    let mut requester = fault_endpoint();
    let mut responder = endpoint();
    let source_mr = requester
        .register_memory(&mut source, AccessFlags::NONE)
        .unwrap();
    let destination_mr = responder
        .register_memory(&mut destination, AccessFlags::LOCAL_WRITE)
        .unwrap();
    let requester_qp = requester
        .create_qp(qp_config(2, 3, 5, 50, [10, 4, 0, 1], [10, 4, 0, 2]))
        .unwrap();
    let responder_qp = responder
        .create_qp(qp_config(3, 2, 50, 5, [10, 4, 0, 2], [10, 4, 0, 1]))
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
        .io_mut()
        .push_rule(
            FaultRule::new(FaultAction::Drop, FaultDirection::Transmit)
                .opcode(Opcode::SendOnly)
                .qpn(3)
                .psn(5),
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
    assert_eq!(requester.io().statistics().dropped, 1);
    assert!(requester.io_mut().inner_mut().pop_transmitted().is_none());

    requester.progress(5, &mut rx, &mut tx).unwrap();
    let retry = requester
        .io_mut()
        .inner_mut()
        .pop_transmitted()
        .expect("timeout retransmission");
    responder
        .io_mut()
        .inject_receive(retry.as_bytes())
        .unwrap();
    responder.progress(5, &mut rx, &mut tx).unwrap();
    let ack = responder.io_mut().pop_transmitted().expect("send ack");
    requester
        .io_mut()
        .inner_mut()
        .inject_receive(ack.as_bytes())
        .unwrap();
    requester.progress(6, &mut rx, &mut tx).unwrap();

    assert_eq!(&destination, &source);
    assert!(
        requester
            .poll_completion(requester_qp)
            .unwrap()
            .is_some_and(Completion::is_success)
    );
    assert_eq!(requester.stats().timeout_events, 1);
    assert_eq!(requester.stats().retransmissions, 1);
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

#[test]
fn requester_ready_queue_round_robins_segmented_qps() {
    let mut source = [0x41_u8; 300];
    let mut endpoint = endpoint();
    let source_mr = endpoint
        .register_memory(&mut source, AccessFlags::NONE)
        .unwrap();
    let first = endpoint
        .create_qp(qp_config(2, 3, 10, 100, [192, 0, 2, 1], [192, 0, 2, 2]))
        .unwrap();
    let second = endpoint
        .create_qp(qp_config(4, 5, 20, 200, [192, 0, 2, 1], [192, 0, 2, 3]))
        .unwrap();
    ready(&mut endpoint, first);
    ready(&mut endpoint, second);
    endpoint
        .post_work(
            first,
            WorkRequest::send(
                1,
                Sge::new(source_mr.address(), 300, source_mr.lkey()),
                true,
            ),
        )
        .unwrap();
    endpoint
        .post_work(
            second,
            WorkRequest::send(
                2,
                Sge::new(source_mr.address(), 300, source_mr.lkey()),
                true,
            ),
        )
        .unwrap();

    let mut receive = [0_u8; 512];
    let mut transmit = [0_u8; 512];
    let mut observed = [(Opcode::Acknowledge, 0, 0); 4];
    for (now, item) in observed.iter_mut().enumerate() {
        let progress = endpoint
            .progress(now as u64, &mut receive, &mut transmit)
            .unwrap();
        assert_eq!(progress.transmitted_packets, 1);
        let frame = endpoint.io_mut().pop_transmitted().unwrap();
        let packet = decode_ipv4_packet(frame.as_bytes()).unwrap().transport;
        *item = (
            packet.bth.opcode,
            packet.bth.destination_qpn,
            packet.bth.psn,
        );
    }

    assert_eq!(
        observed,
        [
            (Opcode::SendFirst, 3, 10),
            (Opcode::SendFirst, 5, 20),
            (Opcode::SendLast, 3, 11),
            (Opcode::SendLast, 5, 21),
        ]
    );
}

#[test]
fn requester_and_responder_ready_classes_share_transmit_slots() {
    type FairEndpoint<'a> = RcEndpoint<'a, MockIo, 4, 8, 8, 8, 16, 8>;

    let mut source = [0x46_u8; 300];
    let mut remote = [0x57_u8; 8];
    let mut endpoint = FairEndpoint::new(
        MockIo::new(512),
        RcEndpointConfig {
            maximum_packet_size: 512,
            ticks_per_second: 1_000_000,
            memory_key_seed: 7,
        },
    )
    .unwrap();
    let source_mr = endpoint
        .register_memory(&mut source, AccessFlags::NONE)
        .unwrap();
    let remote_mr = endpoint
        .register_memory(&mut remote, AccessFlags::REMOTE_READ)
        .unwrap();

    let local_ip = [198, 51, 100, 1];
    let requester = endpoint
        .create_qp(qp_config(2, 3, 10, 100, local_ip, [198, 51, 100, 2]))
        .unwrap();
    let first_responder = endpoint
        .create_qp(qp_config(4, 5, 20, 200, local_ip, [198, 51, 100, 3]))
        .unwrap();
    let second_responder = endpoint
        .create_qp(qp_config(6, 7, 30, 300, local_ip, [198, 51, 100, 4]))
        .unwrap();
    for handle in [requester, first_responder, second_responder] {
        endpoint.transition_qp(handle, QpState::Init).unwrap();
        endpoint.transition_qp(handle, QpState::Rtr).unwrap();
        endpoint.transition_qp(handle, QpState::Rts).unwrap();
    }
    endpoint
        .post_work(
            requester,
            WorkRequest::send(
                1,
                Sge::new(source_mr.address(), 300, source_mr.lkey()),
                true,
            ),
        )
        .unwrap();

    let mut packet = [0_u8; 512];
    let first_request_length = encode_read_request(
        &mut packet,
        Ipv4Path::new([198, 51, 100, 3], local_ip, 49_152),
        4,
        200,
        remote_mr.address(),
        remote_mr.rkey(),
        8,
    );
    endpoint
        .io_mut()
        .inject_receive(&packet[..first_request_length])
        .unwrap();

    let mut receive = [0_u8; 512];
    let mut transmit = [0_u8; 512];
    endpoint.progress(0, &mut receive, &mut transmit).unwrap();
    let first = endpoint.io_mut().pop_transmitted().unwrap();
    let first = decode_ipv4_packet(first.as_bytes()).unwrap().transport;
    assert_eq!(first.bth.opcode, Opcode::RdmaReadResponseOnly);
    assert_eq!(first.bth.destination_qpn, 5);

    let second_request_length = encode_read_request(
        &mut packet,
        Ipv4Path::new([198, 51, 100, 4], local_ip, 49_152),
        6,
        300,
        remote_mr.address(),
        remote_mr.rkey(),
        8,
    );
    endpoint
        .io_mut()
        .inject_receive(&packet[..second_request_length])
        .unwrap();

    endpoint.progress(1, &mut receive, &mut transmit).unwrap();
    let second = endpoint.io_mut().pop_transmitted().unwrap();
    let second = decode_ipv4_packet(second.as_bytes()).unwrap().transport;
    assert_eq!(second.bth.opcode, Opcode::SendFirst);
    assert_eq!(second.bth.destination_qpn, 3);

    endpoint.progress(2, &mut receive, &mut transmit).unwrap();
    let third = endpoint.io_mut().pop_transmitted().unwrap();
    let third = decode_ipv4_packet(third.as_bytes()).unwrap().transport;
    assert_eq!(third.bth.opcode, Opcode::RdmaReadResponseOnly);
    assert_eq!(third.bth.destination_qpn, 7);

    endpoint.progress(3, &mut receive, &mut transmit).unwrap();
    let fourth = endpoint.io_mut().pop_transmitted().unwrap();
    let fourth = decode_ipv4_packet(fourth.as_bytes()).unwrap().transport;
    assert_eq!(fourth.bth.opcode, Opcode::SendLast);
    assert_eq!(fourth.bth.destination_qpn, 3);
}

#[test]
fn deadline_scheduler_services_one_expired_qp_per_progress() {
    let mut source = [0x52_u8; 8];
    let mut endpoint = endpoint();
    let source_mr = endpoint
        .register_memory(&mut source, AccessFlags::NONE)
        .unwrap();
    let first = endpoint
        .create_qp(qp_config(2, 3, 10, 100, [10, 1, 0, 1], [10, 1, 0, 2]))
        .unwrap();
    let second = endpoint
        .create_qp(qp_config(4, 5, 20, 200, [10, 1, 0, 1], [10, 1, 0, 3]))
        .unwrap();
    ready(&mut endpoint, first);
    ready(&mut endpoint, second);
    for (handle, id) in [(first, 1), (second, 2)] {
        endpoint
            .post_work(
                handle,
                WorkRequest::send(id, Sge::new(source_mr.address(), 8, source_mr.lkey()), true),
            )
            .unwrap();
    }

    let mut receive = [0_u8; 512];
    let mut transmit = [0_u8; 512];
    endpoint.progress(0, &mut receive, &mut transmit).unwrap();
    endpoint.io_mut().pop_transmitted().unwrap();
    endpoint.progress(1, &mut receive, &mut transmit).unwrap();
    endpoint.io_mut().pop_transmitted().unwrap();

    endpoint.progress(10, &mut receive, &mut transmit).unwrap();
    let first_retry = endpoint.io_mut().pop_transmitted().unwrap();
    let first_retry = decode_ipv4_packet(first_retry.as_bytes()).unwrap();
    assert_eq!(first_retry.transport.bth.destination_qpn, 3);
    assert_eq!(endpoint.stats().timeout_events, 1);

    endpoint.progress(10, &mut receive, &mut transmit).unwrap();
    let second_retry = endpoint.io_mut().pop_transmitted().unwrap();
    let second_retry = decode_ipv4_packet(second_retry.as_bytes()).unwrap();
    assert_eq!(second_retry.transport.bth.destination_qpn, 5);
    assert_eq!(endpoint.stats().timeout_events, 2);
}

#[test]
fn reset_cancels_ready_and_deadline_state() {
    let mut source = [0x63_u8; 8];
    let mut endpoint = endpoint();
    let source_mr = endpoint
        .register_memory(&mut source, AccessFlags::NONE)
        .unwrap();
    let handle = endpoint
        .create_qp(qp_config(2, 3, 7, 70, [10, 2, 0, 1], [10, 2, 0, 2]))
        .unwrap();
    ready(&mut endpoint, handle);
    endpoint
        .post_work(
            handle,
            WorkRequest::send(9, Sge::new(source_mr.address(), 8, source_mr.lkey()), true),
        )
        .unwrap();

    let mut receive = [0_u8; 512];
    let mut transmit = [0_u8; 512];
    endpoint.progress(0, &mut receive, &mut transmit).unwrap();
    endpoint.io_mut().pop_transmitted().unwrap();
    endpoint.transition_qp(handle, QpState::Reset).unwrap();

    assert_eq!(
        endpoint.poll_completion(handle).unwrap(),
        Some(Completion::failure(
            9,
            CompletionOpcode::Send,
            CompletionStatus::Flushed,
        ))
    );
    let progress = endpoint.progress(100, &mut receive, &mut transmit).unwrap();
    assert!(!progress.made_progress());
    assert!(endpoint.io_mut().pop_transmitted().is_none());
    assert_eq!(endpoint.stats().timeout_events, 0);
}

#[test]
fn requester_remains_scheduled_after_backend_transmit_failure() {
    type FailEndpoint<'a> = RcEndpoint<'a, FailOnceIo, 1, 2, 2, 2, 4, 2>;

    let mut source = [0x74_u8; 8];
    let mut endpoint = FailEndpoint::new(
        FailOnceIo::new(),
        RcEndpointConfig {
            maximum_packet_size: 512,
            ticks_per_second: 1_000_000,
            memory_key_seed: 11,
        },
    )
    .unwrap();
    let source_mr = endpoint
        .register_memory(&mut source, AccessFlags::NONE)
        .unwrap();
    let handle = endpoint
        .create_qp(qp_config(2, 3, 7, 70, [10, 3, 0, 1], [10, 3, 0, 2]))
        .unwrap();
    endpoint.transition_qp(handle, QpState::Init).unwrap();
    endpoint.transition_qp(handle, QpState::Rtr).unwrap();
    endpoint.transition_qp(handle, QpState::Rts).unwrap();
    endpoint
        .post_work(
            handle,
            WorkRequest::send(10, Sge::new(source_mr.address(), 8, source_mr.lkey()), true),
        )
        .unwrap();

    let mut receive = [0_u8; 512];
    let mut transmit = [0_u8; 512];
    assert!(matches!(
        endpoint.progress(0, &mut receive, &mut transmit),
        Err(rocev2::PollError::Io(_))
    ));
    assert_eq!(endpoint.stats().io_errors, 1);

    let progress = endpoint.progress(1, &mut receive, &mut transmit).unwrap();
    assert_eq!(progress.transmitted_packets, 1);
    let packet = endpoint.io_mut().transmitted.take().unwrap();
    let packet = decode_ipv4_packet(&packet).unwrap();
    assert_eq!(packet.transport.bth.opcode, Opcode::SendOnly);
    assert_eq!(packet.transport.bth.psn, 7);
}

#[test]
fn read_responder_remains_scheduled_after_backend_transmit_failure() {
    type FailEndpoint<'a> = RcEndpoint<'a, FailOnceIo, 1, 2, 2, 2, 4, 2>;

    let mut remote = [0x85_u8; 8];
    let mut endpoint = FailEndpoint::new(
        FailOnceIo::new(),
        RcEndpointConfig {
            maximum_packet_size: 512,
            ticks_per_second: 1_000_000,
            memory_key_seed: 12,
        },
    )
    .unwrap();
    let remote_mr = endpoint
        .register_memory(&mut remote, AccessFlags::REMOTE_READ)
        .unwrap();
    let handle = endpoint
        .create_qp(qp_config(2, 3, 7, 70, [10, 4, 0, 1], [10, 4, 0, 2]))
        .unwrap();
    endpoint.transition_qp(handle, QpState::Init).unwrap();
    endpoint.transition_qp(handle, QpState::Rtr).unwrap();
    endpoint.transition_qp(handle, QpState::Rts).unwrap();

    let mut request = [0_u8; 512];
    let request_length = encode_ipv4_packet(
        Ipv4Path::new([10, 4, 0, 2], [10, 4, 0, 1], 49_153),
        PacketSpec {
            bth: Bth::new(Opcode::RdmaReadRequest, 2, 70),
            reth: Some(Reth {
                virtual_address: remote_mr.address(),
                remote_key: remote_mr.rkey(),
                dma_length: 8,
            }),
            aeth: None,
            immediate_data: None,
            payload: &[],
        },
        &mut request,
    )
    .unwrap();
    endpoint.io_mut().inject_receive(&request[..request_length]);

    let mut receive = [0_u8; 512];
    let mut transmit = [0_u8; 512];
    assert!(matches!(
        endpoint.progress(0, &mut receive, &mut transmit),
        Err(rocev2::PollError::Io(_))
    ));
    assert_eq!(endpoint.stats().io_errors, 1);

    let progress = endpoint.progress(1, &mut receive, &mut transmit).unwrap();
    assert_eq!(progress.transmitted_packets, 1);
    let packet = endpoint.io_mut().transmitted.take().unwrap();
    let packet = decode_ipv4_packet(&packet).unwrap();
    assert_eq!(packet.transport.bth.opcode, Opcode::RdmaReadResponseOnly);
    assert_eq!(packet.transport.bth.psn, 70);
    assert_eq!(packet.transport.payload, &[0x85; 8]);
}

#[test]
fn posted_memory_stays_busy_until_reset_or_error_flush() {
    for destination in [QpState::Reset, QpState::Error] {
        let mut bytes = [0x22; 16];
        let mut endpoint = endpoint();
        let mr = endpoint
            .register_memory(&mut bytes, AccessFlags::LOCAL_WRITE)
            .unwrap();
        let qp = endpoint
            .create_qp(qp_config(2, 3, 10, 30, [192, 0, 2, 1], [192, 0, 2, 2]))
            .unwrap();
        ready(&mut endpoint, qp);
        let sge = Sge::new(mr.address(), 8, mr.lkey());
        endpoint
            .post_work_batch(
                qp,
                &[
                    WorkRequest::send(1, sge, false),
                    WorkRequest::send(2, sge, true),
                ],
            )
            .unwrap();
        endpoint
            .post_receive_batch(
                qp,
                &[RecvWorkRequest::new(3, sge), RecvWorkRequest::new(4, sge)],
            )
            .unwrap();
        assert!(matches!(
            endpoint.deregister_memory(mr),
            Err(rocev2::ApiError::Memory(rocev2::MemoryError::RegionBusy))
        ));
        let mut receive = [0; 512];
        let mut transmit = [0; 512];
        endpoint.progress(0, &mut receive, &mut transmit).unwrap();
        assert!(matches!(
            endpoint.deregister_memory(mr),
            Err(rocev2::ApiError::Memory(rocev2::MemoryError::RegionBusy))
        ));
        endpoint.transition_qp(qp, destination).unwrap();
        endpoint.deregister_memory(mr).unwrap();
        let mut completions = 0;
        while let Some(completion) = endpoint.poll_completion(qp).unwrap() {
            assert_eq!(completion.status, CompletionStatus::Flushed);
            completions += 1;
        }
        assert_eq!(completions, 4);
    }
}

#[test]
fn rejected_batch_does_not_retain_valid_prefix() {
    let mut bytes = [0; 8];
    let mut endpoint = endpoint();
    let mr = endpoint
        .register_memory(&mut bytes, AccessFlags::LOCAL_WRITE)
        .unwrap();
    let qp = endpoint
        .create_qp(qp_config(2, 3, 10, 30, [192, 0, 2, 1], [192, 0, 2, 2]))
        .unwrap();
    ready(&mut endpoint, qp);
    let good = Sge::new(mr.address(), 8, mr.lkey());
    let bad = Sge::new(mr.address(), 9, mr.lkey());
    assert!(
        endpoint
            .post_work_batch(
                qp,
                &[
                    WorkRequest::send(1, good, true),
                    WorkRequest::send(2, bad, true)
                ]
            )
            .is_err()
    );
    assert!(
        endpoint
            .post_receive_batch(
                qp,
                &[RecvWorkRequest::new(3, good), RecvWorkRequest::new(4, bad)]
            )
            .is_err()
    );
    endpoint.deregister_memory(mr).unwrap();
    assert_eq!(endpoint.poll_completion(qp).unwrap(), None);
}
