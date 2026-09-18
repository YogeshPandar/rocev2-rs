//! Bounded, deterministic fuzz oracles; no Linux syscalls or external peers.
#![forbid(unsafe_code)]

use rocev2::wire::{Aeth, Bth, Icrc, Opcode, PacketRef, PacketSpec, ParseOptions, Reth};
use rocev2::{Ipv4Path, decode_ipv4_packet, encode_ipv4_packet};

pub fn wire_decode(data: &[u8]) {
    let data = &data[..data.len().min(8192)];
    let _ = Bth::decode(data);
    let _ = Aeth::decode(data);
    let _ = Reth::decode(data);
    let _ = PacketRef::parse(data, ParseOptions::STRICT);
    let _ = decode_ipv4_packet(data);
    let _ = rocev2::RcConnectionInfo::decode(data);
    let mut crc = Icrc::new();
    crc.update(data);
    let mut reference = 0xffff_ffffu32;
    for byte in data {
        reference ^= u32::from(*byte);
        for _ in 0..8 {
            reference = (reference >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(reference & 1));
        }
    }
    assert_eq!(crc.finalize(), !reference);
}

pub fn wire_roundtrip(data: &[u8]) {
    if data.len() < 24 {
        return;
    }
    let opcode = Opcode::from_u8(data[0] % 18).unwrap();
    let word = |i| u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
    let psn = word(1) & 0xff_ffff;
    let qpn = word(5) & 0xff_ffff;
    let payload = if opcode.allows_payload() {
        &data[24..data.len().min(4120)]
    } else {
        &[]
    };
    let mut bth = Bth::new(opcode, qpn, psn);
    bth.ack_request = data[9] & 1 != 0;
    let reth = opcode.has_reth().then_some(Reth {
        virtual_address: u64::from_le_bytes(data[10..18].try_into().unwrap()),
        remote_key: word(18),
        dma_length: payload.len() as u32,
    });
    let aeth = opcode.has_aeth().then_some(Aeth::ack(word(18) & 0xff_ffff));
    let immediate_data = opcode.has_immediate().then_some(word(18));
    let spec = PacketSpec {
        bth,
        reth,
        aeth,
        immediate_data,
        payload,
    };
    let path = Ipv4Path::new([192, 0, 2, 1], [192, 0, 2, 2], 49152);
    let mut bytes = [0; 4352];
    let length = encode_ipv4_packet(path, spec, &mut bytes).unwrap();
    let packet = decode_ipv4_packet(&bytes[..length]).unwrap().transport;
    assert_eq!(packet.bth.opcode, opcode);
    assert_eq!(packet.bth.destination_qpn, qpn);
    assert_eq!(packet.bth.psn, psn);
    assert_eq!(packet.payload, payload);
    assert_eq!(packet.reth, reth);
    assert_eq!(packet.aeth, aeth);
    assert_eq!(packet.immediate_data, immediate_data);
    assert!(packet.padding.iter().all(|b| *b == 0));
    bytes[length - 1] ^= 1;
    assert!(decode_ipv4_packet(&bytes[..length]).is_err());
}

pub fn memory_registry(data: &[u8]) {
    use rocev2::{AccessFlags as A, MemoryError, MemoryRegistry};
    let mut guarded = [0xa5; 96];
    guarded[16..80].fill(0);
    let mut expected = [0; 64];
    {
        let mut available = Some(&mut guarded[16..80]);
        let mut registry = MemoryRegistry::<1>::new(19).unwrap();
        let mut handle = None;
        let mut stale = None;
        let mut lease = None;
        for command in data.chunks_exact(4).take(256) {
            match command[0] % 7 {
                0 if handle.is_none() => {
                    let buffer = available.take().unwrap();
                    handle = Some(
                        registry
                            .register(buffer, A::LOCAL_WRITE | A::REMOTE_READ | A::REMOTE_WRITE)
                            .unwrap(),
                    );
                }
                1 => {
                    if let Some(h) = handle {
                        match registry.deregister(h) {
                            Ok(buffer) => {
                                available = Some(buffer);
                                handle = None;
                                stale = Some(h);
                            }
                            Err(error) => {
                                assert_eq!(error, MemoryError::RegionBusy);
                                assert!(lease.is_some());
                            }
                        }
                    }
                }
                2 => {
                    if let Some(h) = handle {
                        let offset = usize::from(command[1]);
                        let size = usize::from(command[2] % 17);
                        let address = if command[3] & 1 == 0 {
                            h.address().saturating_add(offset as u64)
                        } else {
                            u64::MAX
                        };
                        let bytes = [command[3]; 16];
                        let result = registry.write_remote(h.rkey(), address, &bytes[..size]);
                        let valid = command[3] & 1 == 0 && offset <= 64 && size <= 64 - offset;
                        assert_eq!(result.is_ok(), valid);
                        if valid {
                            expected[offset..offset + size].copy_from_slice(&bytes[..size]);
                        }
                    }
                }
                3 if lease.is_none() => {
                    if let Some(h) = handle {
                        lease = Some(registry.retain_local(h.lkey()).unwrap());
                    }
                }
                4 => {
                    registry.release(&mut lease).unwrap();
                }
                5 => {
                    if let Some(h) = stale {
                        assert!(
                            registry
                                .validate_local_read(h.lkey(), h.address(), 1)
                                .is_err()
                        );
                        assert!(registry.deregister(h).is_err());
                    }
                }
                _ => {
                    if let Some(h) = handle {
                        assert!(
                            registry
                                .validate_remote_write(h.rkey(), u64::MAX, usize::MAX)
                                .is_err()
                        );
                    }
                }
            }
            assert!(registry.len() <= 1);
            if let Some(h) = handle {
                let mut actual = [0; 64];
                registry
                    .read_local(h.lkey(), h.address(), &mut actual)
                    .unwrap();
                assert_eq!(actual, expected);
            }
        }
        registry.release(&mut lease).unwrap();
    }
    assert_eq!(&guarded[..16], &[0xa5; 16]);
    assert_eq!(&guarded[80..], &[0xa5; 16]);
    assert_eq!(&guarded[16..80], &expected);
}

pub fn rc_events(data: &[u8]) {
    use rocev2::io::FixedPacketIo;
    use rocev2::{
        AccessFlags as A, PathMtu, Psn, QpConfig, QpState, RcEndpoint, RcEndpointConfig,
        RcQpConfig, RecvWorkRequest, Sge, WorkRequest,
    };
    let mut guarded = [0x6d; 160];
    {
        let mut endpoint: RcEndpoint<'_, FixedPacketIo<8, 8, 512>, 1, 1, 4, 4, 8, 2> =
            RcEndpoint::new(
                FixedPacketIo::new(),
                RcEndpointConfig {
                    maximum_packet_size: 512,
                    ticks_per_second: 1_000_000,
                    memory_key_seed: 13,
                },
            )
            .unwrap();
        let mr = endpoint
            .register_memory(
                &mut guarded[16..144],
                A::LOCAL_WRITE | A::REMOTE_READ | A::REMOTE_WRITE,
            )
            .unwrap();
        let config = RcQpConfig {
            transport: QpConfig {
                local_qpn: 2,
                remote_qpn: 3,
                send_psn: Psn::new_truncated(0xff_fff0),
                receive_psn: Psn::new_truncated(0xff_fff0),
                path_mtu: PathMtu::Mtu256,
                retry_count: 1,
                rnr_retry_count: 1,
                timeout: 1,
            },
            path: Ipv4Path::new([192, 0, 2, 1], [192, 0, 2, 2], 49152),
            rnr_nak_timer: 1,
        };
        let mut qp = endpoint.create_qp(config).unwrap();
        for state in [QpState::Init, QpState::Rtr, QpState::Rts] {
            endpoint.transition_qp(qp, state).unwrap();
        }
        let mut seen = [false; 256];
        let mut now = 0u64;
        for (index, command) in data.chunks(16).take(256).enumerate() {
            let size = u32::from(command.get(1).copied().unwrap_or(0) % 129);
            let sge = Sge::new(mr.address(), size, mr.lkey());
            match command[0] % 10 {
                0 => {
                    let _ = endpoint.post_work(qp, WorkRequest::send(index as u64, sge, true));
                }
                1 => {
                    let _ = endpoint.post_receive(qp, RecvWorkRequest::new(index as u64, sge));
                }
                2 => {
                    let _ = endpoint.io_mut().inject_receive(command);
                }
                3 | 4 | 5 => {
                    let psn = 0xff_fff0u32
                        .wrapping_add(u32::from(command.get(2).copied().unwrap_or(0)))
                        & 0xff_ffff;
                    let aeth = match command[0] % 10 {
                        3 => Aeth::ack(0),
                        4 => Aeth::psn_nak(0),
                        _ => Aeth::rnr_nak(0, 1),
                    };
                    let packet = PacketSpec {
                        bth: Bth::new(Opcode::Acknowledge, 2, psn),
                        reth: None,
                        aeth: Some(aeth),
                        immediate_data: None,
                        payload: &[],
                    };
                    let mut bytes = [0; 128];
                    let n = encode_ipv4_packet(
                        Ipv4Path::new([192, 0, 2, 2], [192, 0, 2, 1], 49152),
                        packet,
                        &mut bytes,
                    )
                    .unwrap();
                    let _ = endpoint.io_mut().inject_receive(&bytes[..n]);
                }
                6 => {
                    let _ = endpoint.transition_qp(qp, QpState::Error);
                }
                7 => {
                    let _ = endpoint.transition_qp(qp, QpState::Reset);
                }
                8 => {
                    while let Some(c) = endpoint.poll_completion(qp).unwrap() {
                        let id = c.work_request_id as usize;
                        assert!(id < seen.len() && !seen[id]);
                        seen[id] = true;
                    }
                    if endpoint.remove_qp(qp).is_ok() {
                        let stale = qp;
                        qp = endpoint.create_qp(config).unwrap();
                        assert!(endpoint.qp_state(stale).is_err());
                        for state in [QpState::Init, QpState::Rtr, QpState::Rts] {
                            endpoint.transition_qp(qp, state).unwrap();
                        }
                    }
                }
                _ => {
                    let _ =
                        endpoint.post_work(qp, WorkRequest::read(index as u64, sge, 0, 7, true));
                }
            }
            now += u64::from(command.get(3).copied().unwrap_or(1)) * 1024;
            endpoint.progress_batch(now, 8).unwrap();
            while endpoint.io_mut().pop_transmitted().is_some() {}
            assert!(endpoint.completion_len(qp).unwrap() <= 8);
            while let Some(c) = endpoint.poll_completion(qp).unwrap() {
                let id = c.work_request_id as usize;
                assert!(id < seen.len() && !seen[id]);
                seen[id] = true;
            }
        }
    }
    assert_eq!(&guarded[..16], &[0x6d; 16]);
    assert_eq!(&guarded[144..], &[0x6d; 16]);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_smoke_covers_every_command_byte() {
        for byte in 0..=255 {
            let data = [byte; 256];
            wire_decode(&data);
            wire_roundtrip(&data);
            memory_registry(&data);
            rc_events(&data);
        }
    }
}
