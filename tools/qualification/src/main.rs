use rocev2_core::{Psn, QpnShardPlan, QpnTable, ReadyQueue, TimerEntry, TimerScheduler};
use rocev2_io::{NumaTopology, allowed_cpus, plan_workers};
use rocev2_memory::{AccessFlags, MemoryRegistry};
use rocev2_wire::Icrc;
use std::env;
use std::error::Error;
use std::hint::black_box;
use std::time::{Duration, Instant};

type DynError = Box<dyn Error + Send + Sync>;

const DEFAULT_ITERATIONS: u64 = 2_000_000;
const SCALE_QPS: u32 = 100_000;

fn parse_u64(value: Option<String>, default: u64, name: &str) -> Result<u64, DynError> {
    let Some(value) = value else {
        return Ok(default);
    };
    let parsed = value
        .parse::<u64>()
        .map_err(|error| format!("invalid {name}: {error}"))?;
    if parsed == 0 {
        return Err(format!("{name} must be nonzero").into());
    }
    Ok(parsed)
}

fn measure(mut operation: impl FnMut(), iterations: u64) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    start.elapsed()
}

fn report(name: &str, iterations: u64, elapsed: Duration) {
    let total_ns = elapsed.as_nanos();
    let scaled = total_ns
        .saturating_mul(1_000)
        .checked_div(u128::from(iterations))
        .unwrap_or(u128::MAX);
    let whole = scaled / 1_000;
    let fraction = scaled % 1_000;
    println!(
        "{{\"benchmark\":\"{name}\",\"iterations\":{iterations},\"elapsed_ns\":{total_ns},\"ns_per_op\":{whole}.{fraction:03}}}"
    );
}

fn micro(iterations: u64) -> Result<(), DynError> {
    let payload = [0x5a_u8; 4096];
    let elapsed = measure(
        || {
            let mut crc = Icrc::new();
            crc.update(black_box(&payload));
            black_box(crc.finalize());
        },
        iterations,
    );
    report("icrc_4096", iterations, elapsed);

    let mut qpn = QpnTable::<2048>::new();
    for slot in 0..1024_u32 {
        qpn.insert(slot + 2, slot)?;
    }
    let mut key = 2_u32;
    let elapsed = measure(
        || {
            black_box(qpn.get(black_box(key)));
            key += 1;
            if key == 1026 {
                key = 2;
            }
        },
        iterations,
    );
    report("qpn_lookup_1024", iterations, elapsed);

    let mut ready = ReadyQueue::<1024>::new();
    let mut ready_slot = 0_usize;
    let elapsed = measure(
        || {
            black_box(ready.schedule(ready_slot));
            black_box(ready.pop());
            ready_slot = (ready_slot + 1) & 1023;
        },
        iterations,
    );
    report("ready_schedule_pop", iterations, elapsed);

    let mut timers = TimerScheduler::<1024>::new();
    let mut timer_slot = 0_u32;
    let elapsed = measure(
        || {
            let entry = TimerEntry::new(u64::from(timer_slot) + 1, timer_slot, 1, 1);
            black_box(timers.schedule(entry));
            black_box(timers.cancel(timer_slot));
            timer_slot = (timer_slot + 1) & 1023;
        },
        iterations,
    );
    report("timer_schedule_cancel", iterations, elapsed);

    let mut psn = Psn::new_truncated(0x00ff_fff0);
    let elapsed = measure(
        || {
            psn = black_box(psn.next());
            black_box(psn.value());
        },
        iterations,
    );
    report("psn_next", iterations, elapsed);

    let mut memory = [0_u8; 4096];
    let mut registry = MemoryRegistry::<1>::new(0x5155_414c)?;
    let region = registry.register(
        &mut memory,
        AccessFlags::LOCAL_WRITE | AccessFlags::REMOTE_WRITE | AccessFlags::REMOTE_READ,
    )?;
    let elapsed = measure(
        || {
            black_box(
                registry
                    .validate_local_read(region.lkey(), region.address(), 64)
                    .is_ok(),
            );
        },
        iterations,
    );
    report("mr_lookup_validate_64", iterations, elapsed);
    Ok(())
}

fn shard_scale(shards: u32) -> Result<(), DynError> {
    let plan = QpnShardPlan::new(shards).ok_or("shard count must be a power of two <= 65536")?;
    let mut counts = vec![0_u32; usize::try_from(shards)?];
    for ordinal in 0..SCALE_QPS {
        let owner = ordinal & (shards - 1);
        let local_ordinal = ordinal / shards;
        let qpn = plan
            .qpn(owner, local_ordinal)
            .ok_or("QPN space exhausted while planning scale run")?;
        let actual = plan.owner(qpn).ok_or("generated QPN has no owner")?;
        if actual != owner {
            return Err("QPN shard assignment is inconsistent".into());
        }
        counts[usize::try_from(owner)?] += 1;
    }
    let minimum = counts.iter().copied().min().unwrap_or(0);
    let maximum = counts.iter().copied().max().unwrap_or(0);
    println!(
        "{{\"scale_qps\":{SCALE_QPS},\"shards\":{shards},\"min_qps_per_shard\":{minimum},\"max_qps_per_shard\":{maximum}}}"
    );
    Ok(())
}

fn json_node(node: Option<u32>) -> String {
    node.map_or_else(|| String::from("null"), |value| value.to_string())
}

fn placement(interface: &str, workers: usize) -> Result<(), DynError> {
    let topology = NumaTopology::discover(interface)?;
    let allowed = allowed_cpus()?;
    let topology_node = json_node(topology.device_node);
    println!(
        "{{\"interface\":\"{interface}\",\"numa_node\":{topology_node},\"rx_queues\":{},\"allowed_cpus\":{},\"local_cpus\":{}}}",
        topology.rx_queues,
        allowed.len(),
        topology.local_cpus.len()
    );
    for worker in plan_workers(interface, workers)? {
        let worker_node = json_node(worker.numa_node);
        println!(
            "{{\"shard\":{},\"rx_queue\":{},\"cpu\":{},\"numa_node\":{worker_node}}}",
            worker.shard, worker.rx_queue, worker.cpu
        );
    }
    Ok(())
}

fn usage(program: &str) {
    eprintln!(
        "usage:\n  {program} micro [iterations]\n  {program} scale [power_of_two_shards]\n  {program} placement INTERFACE [workers]"
    );
}

fn main() -> Result<(), DynError> {
    let mut args = env::args();
    let program = args
        .next()
        .unwrap_or_else(|| String::from("rocev2-qualification"));
    match args.next().as_deref() {
        Some("micro") => micro(parse_u64(args.next(), DEFAULT_ITERATIONS, "iterations")?),
        Some("scale") => {
            let shards = u32::try_from(parse_u64(args.next(), 128, "shards")?)?;
            shard_scale(shards)
        }
        Some("placement") => {
            let interface = args.next().ok_or("placement requires an interface")?;
            let workers = usize::try_from(parse_u64(args.next(), 1, "workers")?)?;
            placement(&interface, workers)
        }
        _ => {
            usage(&program);
            Err("unknown or missing command".into())
        }
    }
}
