//! Optional Linux worker placement; no topology reads occur in the packet path.

use std::{fs, io, mem, path::Path};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Parse a Linux cpulist, returning sorted unique CPU IDs.
///
/// Parsing is control-plane only. The explicit bound prevents unbounded
/// expansion of malformed ranges. Empty lists are accepted.
pub fn parse_cpu_list(text: &str, maximum_cpu: usize) -> io::Result<Vec<usize>> {
    let mut cpus = Vec::new();
    if text.trim().is_empty() {
        return Ok(cpus);
    }
    for range in text.trim().split(',') {
        let mut parts = range.split('-');
        let start = parts
            .next()
            .ok_or_else(|| invalid("missing CPU"))?
            .parse::<usize>()
            .map_err(|_| invalid("invalid CPU"))?;
        let end = parts.next().map_or(Ok(start), |part| {
            part.parse::<usize>()
                .map_err(|_| invalid("invalid CPU range"))
        })?;
        if parts.next().is_some() || end < start || end > maximum_cpu {
            return Err(invalid("CPU range exceeds configured bounds"));
        }
        cpus.extend(start..=end);
        // Bound duplicate-heavy input as well as individual ranges.
        if cpus.len() > maximum_cpu.saturating_add(1) {
            cpus.sort_unstable();
            cpus.dedup();
        }
    }
    cpus.sort_unstable();
    cpus.dedup();
    Ok(cpus)
}

/// Return the current thread's allowed CPUs, accounting for cpuset restrictions.
///
/// Uses libc's fixed cpu_set_t. Kernels requiring a larger affinity mask return
/// their error rather than truncating the allowed CPU set.
pub fn allowed_cpus() -> io::Result<Vec<usize>> {
    // SAFETY: zero is a valid empty cpu_set_t representation.
    let mut mask: libc::cpu_set_t = unsafe { mem::zeroed() };
    // SAFETY: mask is live, aligned, writable, and exactly the advertised size.
    if unsafe { libc::sched_getaffinity(0, mem::size_of_val(&mask), &raw mut mask) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((0..libc::CPU_SETSIZE as usize)
        .filter(|&cpu| {
            // SAFETY: cpu is bounded by CPU_SETSIZE and mask is initialized.
            unsafe { libc::CPU_ISSET(cpu, &mask) }
        })
        .collect())
}

/// Pin the calling thread to one allowed CPU before allocating its shard.
///
/// This changes only the calling thread. It does not change IRQ affinity,
/// migrate existing pages, or guarantee NUMA placement under a cpuset policy.
pub fn pin_current_thread(cpu: usize) -> io::Result<()> {
    if cpu >= libc::CPU_SETSIZE as usize || !allowed_cpus()?.contains(&cpu) {
        return Err(invalid("CPU is outside the current affinity mask"));
    }
    // SAFETY: zero is valid; CPU_SET receives a checked CPU index.
    let mut mask: libc::cpu_set_t = unsafe { mem::zeroed() };
    // SAFETY: mask is initialized and cpu is below CPU_SETSIZE.
    unsafe { libc::CPU_SET(cpu, &mut mask) };
    // SAFETY: mask is live and readable for its exact native ABI size.
    if unsafe { libc::sched_setaffinity(0, mem::size_of_val(&mask), &raw const mask) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if allowed_cpus()? != [cpu] {
        return Err(io::Error::other(
            "kernel did not preserve requested CPU affinity",
        ));
    }
    Ok(())
}

/// Discovered NUMA placement hints for one network device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NumaTopology {
    /// Device NUMA node; `None` means the kernel reports no known node.
    pub device_node: Option<u32>,
    /// Allowed CPUs local to the device; an empty list is not silently replaced.
    pub local_cpus: Vec<usize>,
    /// Number of RX queue directories exposed by the device.
    pub rx_queues: usize,
}

impl NumaTopology {
    /// Read sysfs placement hints and intersect them with the caller's cpuset.
    pub fn discover(interface: &str) -> io::Result<Self> {
        if interface.is_empty()
            || interface == "."
            || interface == ".."
            || interface.bytes().any(|b| b == b'/' || b == 0)
        {
            return Err(invalid("invalid network interface name"));
        }
        let root = Path::new("/sys/class/net").join(interface);
        let allowed = allowed_cpus()?;
        let node_path = root.join("device/numa_node");
        let device_node = match fs::read_to_string(node_path) {
            Ok(value) => {
                let node = value
                    .trim()
                    .parse::<i32>()
                    .map_err(|_| invalid("invalid NUMA node"))?;
                if node < -1 {
                    return Err(invalid("invalid NUMA node"));
                }
                u32::try_from(node).ok()
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let local_cpus = if let Some(node) = device_node {
            let list = fs::read_to_string(format!("/sys/devices/system/node/node{node}/cpulist"))?;
            parse_cpu_list(&list, libc::CPU_SETSIZE as usize - 1)?
                .into_iter()
                .filter(|cpu| allowed.contains(cpu))
                .collect()
        } else {
            Vec::new()
        };
        let mut rx_queues = 0;
        for entry in fs::read_dir(root.join("queues"))? {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("rx-"))
            {
                rx_queues += 1;
            }
        }
        Ok(Self {
            device_node,
            local_cpus,
            rx_queues,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpulists_are_bounded_and_deduplicated() {
        assert_eq!(parse_cpu_list("0-2,2,5\n", 7).unwrap(), [0, 1, 2, 5]);
        assert!(parse_cpu_list("", 7).unwrap().is_empty());
        for invalid in [
            "3-1",
            "0-8",
            "1-2-3",
            "1,",
            "-1",
            "a",
            "18446744073709551616",
        ] {
            assert!(parse_cpu_list(invalid, 7).is_err());
        }
    }
}
