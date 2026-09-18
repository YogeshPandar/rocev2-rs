//! Native XDP steering with Linux-owned program, link, and XSKMAP descriptors.

use aya_obj::generated::{
    bpf_attach_type, bpf_attr, bpf_cmd, bpf_insn, bpf_map_type, bpf_prog_type,
};
use core::mem::{size_of, zeroed};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

const XDP_PASS: i32 = 2;
const REDIRECT_MAP: i32 = 51;

/// Interface-scoped RoCEv2 steering and queue-to-socket map.
///
/// Native XDP links require Linux 5.9 or newer and a supporting driver. Existing
/// XDP attachments are never replaced. Only untagged, unfragmented IPv4 packets
/// without IP options, addressed to UDP port 4791, are redirected. Other traffic
/// and queues without a registered socket pass to the normal network stack.
///
/// Queue assignment follows NIC RSS configuration; XSKMAP does not move packets
/// between hardware queues. Registered sockets keep this attachment alive.
#[derive(Clone, Debug)]
pub struct XdpSteering {
    inner: Arc<SteeringInner>,
}

#[derive(Debug)]
struct SteeringInner {
    // The link is detached before its program and map descriptors are closed.
    _link: OwnedFd,
    _program: OwnedFd,
    map: OwnedFd,
    interface_index: u32,
    queue_count: u32,
}

impl XdpSteering {
    /// Attach the steering program without replacing any existing XDP owner.
    pub fn attach(interface_index: u32, queue_count: u32) -> io::Result<Self> {
        if interface_index == 0 || queue_count == 0 || queue_count > 65_536 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid XDP interface or queue count",
            ));
        }
        let map = create_map(queue_count)?;
        let program = load_program(map.as_raw_fd())?;
        let mut attr = empty_attr();
        attr.link_create.__bindgen_anon_1.prog_fd = program.as_raw_fd() as u32;
        attr.link_create.__bindgen_anon_2.target_ifindex = interface_index;
        attr.link_create.attach_type = bpf_attach_type::BPF_XDP as u32;
        let link = command_fd(bpf_cmd::BPF_LINK_CREATE, &mut attr)?;
        Ok(Self {
            inner: Arc::new(SteeringInner {
                _link: link,
                _program: program,
                map,
                interface_index,
                queue_count,
            }),
        })
    }

    /// Return the interface that owns this map and native XDP link.
    #[must_use]
    pub fn interface_index(&self) -> u32 {
        self.inner.interface_index
    }

    /// Return the exclusive upper bound for registered queue IDs.
    #[must_use]
    pub fn queue_count(&self) -> u32 {
        self.inner.queue_count
    }

    pub(crate) fn register(
        &self,
        interface: u32,
        queue: u32,
        socket: RawFd,
    ) -> io::Result<QueueRegistration> {
        if interface != self.inner.interface_index || queue >= self.inner.queue_count || socket < 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "XSKMAP socket interface or queue mismatch",
            ));
        }
        let value = socket as u32;
        let mut attr = empty_attr();
        attr.__bindgen_anon_2.map_fd = self.inner.map.as_raw_fd() as u32;
        attr.__bindgen_anon_2.key = (&raw const queue) as usize as u64;
        attr.__bindgen_anon_2.__bindgen_anon_1.value = (&raw const value) as usize as u64;
        attr.__bindgen_anon_2.flags = u64::from(aya_obj::generated::BPF_NOEXIST);
        // Key and socket FD storage remain live for this synchronous kernel copy.
        command(bpf_cmd::BPF_MAP_UPDATE_ELEM, &mut attr)?;
        Ok(QueueRegistration {
            inner: Arc::clone(&self.inner),
            queue,
            registered: true,
        })
    }
}

#[derive(Debug)]
pub(crate) struct QueueRegistration {
    inner: Arc<SteeringInner>,
    queue: u32,
    registered: bool,
}

impl QueueRegistration {
    pub(crate) fn unregister(&mut self) -> io::Result<()> {
        if !self.registered {
            return Ok(());
        }
        let mut attr = empty_attr();
        attr.__bindgen_anon_2.map_fd = self.inner.map.as_raw_fd() as u32;
        attr.__bindgen_anon_2.key = (&raw const self.queue) as usize as u64;
        match command(bpf_cmd::BPF_MAP_DELETE_ELEM, &mut attr) {
            Ok(_) => {
                self.registered = false;
                Ok(())
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                self.registered = false;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for QueueRegistration {
    fn drop(&mut self) {
        // AfxdpSocket drops this guard before closing its socket descriptor.
        let _ = self.unregister();
    }
}

fn empty_attr() -> bpf_attr {
    // safety: the generated C union contains only integers, arrays, and integer unions.
    // Zero also initializes every reserved kernel ABI byte before selective writes.
    unsafe { zeroed() }
}

fn command(command: bpf_cmd, attr: &mut bpf_attr) -> io::Result<i32> {
    loop {
        // safety: attr is the generated Linux ABI layout. Private callers retain
        // all referenced buffers, with their exact lengths, throughout this call.
        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                command as u32,
                &raw mut *attr,
                size_of::<bpf_attr>(),
            )
        };
        if result >= 0 {
            return i32::try_from(result)
                .map_err(|_| io::Error::other("invalid BPF syscall result"));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn command_fd(command_id: bpf_cmd, attr: &mut bpf_attr) -> io::Result<OwnedFd> {
    let fd = command(command_id, attr)?;
    // safety: only successful FD-creating BPF commands call this function; ownership is unique.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn create_map(queues: u32) -> io::Result<OwnedFd> {
    let mut attr = empty_attr();
    attr.__bindgen_anon_1.map_type = bpf_map_type::BPF_MAP_TYPE_XSKMAP as u32;
    attr.__bindgen_anon_1.key_size = 4;
    attr.__bindgen_anon_1.value_size = 4;
    attr.__bindgen_anon_1.max_entries = queues;
    command_fd(bpf_cmd::BPF_MAP_CREATE, &mut attr)
}

fn load_program(map_fd: RawFd) -> io::Result<OwnedFd> {
    let instructions = steering_program(map_fd);
    let mut log = vec![0_u8; 65_536];
    let license = b"Dual MIT/GPL\0";
    let mut attr = empty_attr();
    attr.__bindgen_anon_3.prog_type = bpf_prog_type::BPF_PROG_TYPE_XDP as u32;
    attr.__bindgen_anon_3.expected_attach_type = bpf_attach_type::BPF_XDP as u32;
    attr.__bindgen_anon_3.insn_cnt = instructions.len() as u32;
    attr.__bindgen_anon_3.insns = instructions.as_ptr() as usize as u64;
    attr.__bindgen_anon_3.license = license.as_ptr() as usize as u64;
    attr.__bindgen_anon_3.log_level = 1;
    attr.__bindgen_anon_3.log_size = log.len() as u32;
    attr.__bindgen_anon_3.log_buf = log.as_mut_ptr() as usize as u64;
    command_fd(bpf_cmd::BPF_PROG_LOAD, &mut attr).map_err(|error| {
        let length = log.iter().position(|byte| *byte == 0).unwrap_or(log.len());
        io::Error::new(
            error.kind(),
            format!(
                "XDP verifier: {error}; {}",
                String::from_utf8_lossy(&log[..length])
            ),
        )
    })
}

fn insn(code: u8, destination: u8, source: u8, offset: i16, immediate: i32) -> bpf_insn {
    bpf_insn {
        code,
        _bitfield_align_1: [],
        _bitfield_1: bpf_insn::new_bitfield_1(destination, source),
        off: offset,
        imm: immediate,
    }
}

// Opcodes follow the Linux eBPF ISA. Packet accesses have a dominating data_end check.
// xdp_md offsets 0/4/16 are data/data_end/rx_queue_index from linux/bpf.h.
fn steering_program(map_fd: RawFd) -> Vec<bpf_insn> {
    let mut code = vec![
        insn(0xbf, 6, 1, 0, 0), // r6 = context
        insn(0x61, 2, 6, 0, 0), // r2 = data
        insn(0x61, 3, 6, 4, 0), // r3 = data_end
        insn(0xbf, 4, 2, 0, 0),
        insn(0x07, 4, 0, 0, 42),
        insn(0x2d, 4, 3, -1, 0), // incomplete Ethernet/IPv4/UDP header
        insn(0x69, 4, 2, 12, 0),
        insn(0x55, 4, 0, -1, i32::from(0x0800_u16.to_be())),
        insn(0x71, 4, 2, 14, 0),
        insn(0x55, 4, 0, -1, 0x45), // IPv4 without options
        insn(0x71, 4, 2, 23, 0),
        insn(0x55, 4, 0, -1, 17), // UDP
        insn(0x69, 4, 2, 20, 0),
        insn(0x45, 4, 0, -1, i32::from(0x3fff_u16.to_be())),
        insn(0x69, 4, 2, 36, 0),
        insn(0x55, 4, 0, -1, i32::from(4791_u16.to_be())),
        insn(0x69, 4, 2, 16, 0),
        insn(0xdc, 4, 0, 0, 16),  // IP total length, network to host
        insn(0xa5, 4, 0, -1, 44), // UDP/BTH/ICRC minimum
        insn(0xbf, 5, 2, 0, 0),
        insn(0x0f, 5, 4, 0, 0),
        insn(0x07, 5, 0, 0, 14),
        insn(0x2d, 5, 3, -1, 0),
        insn(0x69, 5, 2, 38, 0),
        insn(0xdc, 5, 0, 0, 16),
        insn(0x07, 5, 0, 0, 20),
        insn(0x5d, 5, 4, -1, 0), // UDP length must match IPv4
        insn(0x61, 2, 6, 16, 0), // XSKMAP key = ingress queue
        insn(
            0x18,
            1,
            aya_obj::generated::BPF_PSEUDO_MAP_FD as u8,
            0,
            map_fd,
        ),
        insn(0, 0, 0, 0, 0),
        insn(0xb7, 3, 0, 0, XDP_PASS),
        insn(0x85, 0, 0, 0, REDIRECT_MAP),
        insn(0x95, 0, 0, 0, 0),
        insn(0xb7, 0, 0, 0, XDP_PASS),
        insn(0x95, 0, 0, 0, 0),
    ];
    let pass = code.len() - 2;
    for (index, instruction) in code.iter_mut().enumerate() {
        if instruction.off == -1 {
            instruction.off = (pass - index - 1) as i16;
        }
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steering_branches_only_target_the_pass_exit() {
        let code = steering_program(7);
        assert_eq!(size_of::<bpf_insn>(), 8);
        for (index, instruction) in code.iter().enumerate() {
            if instruction.off > 0 && instruction.code & 7 == 5 {
                assert_eq!(index + 1 + instruction.off as usize, code.len() - 2);
            }
        }
    }

    #[test]
    #[ignore = "requires CAP_BPF and CAP_NET_ADMIN; run on the privileged Linux CI job"]
    fn kernel_verifier_and_empty_map_fallback() {
        let map = create_map(1).unwrap();
        let program = load_program(map.as_raw_fd()).unwrap();
        let mut packet = [0_u8; 64];
        packet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        packet[14] = 0x45;
        packet[16..18].copy_from_slice(&44_u16.to_be_bytes());
        packet[23] = 17;
        packet[36..38].copy_from_slice(&4791_u16.to_be_bytes());
        packet[38..40].copy_from_slice(&24_u16.to_be_bytes());
        for length in [14, 20, 41, 42, 57, 58, 64] {
            let mut attr = empty_attr();
            attr.test.prog_fd = program.as_raw_fd() as u32;
            attr.test.data_in = packet.as_ptr() as usize as u64;
            attr.test.data_size_in = length;
            attr.test.repeat = 1;
            command(bpf_cmd::BPF_PROG_TEST_RUN, &mut attr).unwrap();
            // safety: BPF_PROG_TEST_RUN initialized the retval field in this union member.
            assert_eq!(unsafe { attr.test.retval }, XDP_PASS as u32);
        }
    }
}
