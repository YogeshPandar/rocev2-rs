use rocev2::io::{
    AfxdpBindMode, AfxdpConfig, AfxdpError, AfxdpSocket, EthernetPath, PacketIo, RawIpv4Config,
    RawIpv4Socket, XdpSteering,
};
use rocev2::{
    AccessFlags, Completion, CompletionOpcode, CompletionStatus, QpState, RC_CONNECTION_INFO_LEN,
    RcConnectionInfo, RcEndpoint, RcEndpointConfig, RecvWorkRequest, RegionHandle, Sge,
    SystemKeyGenerator, WorkRequest,
};
use std::env;
use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(20);
const QPN: u32 = 0x0080_0002;
const UDP_SOURCE_PORT: u16 = 49_153;
const RETRY_COUNT: u8 = 6;
const RNR_RETRY_COUNT: u8 = 6;
const ACK_TIMEOUT: u8 = 14;
const RNR_TIMER: u8 = 1;
const QP_DEPTH: u8 = 1;
const REQUEST_LEN: usize = 16;

type PeerEndpoint<'a> = RcEndpoint<'a, PeerIo, 1, 1, 8, 8, 16, 2>;
type DynError = Box<dyn Error + Send + Sync>;

#[derive(Debug)]
enum PeerIoError {
    Raw(io::Error),
    Afxdp(AfxdpError),
}

impl fmt::Display for PeerIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Raw(error) => write!(formatter, "raw IPv4 I/O failed: {error}"),
            Self::Afxdp(error) => write!(formatter, "AF_XDP I/O failed: {error}"),
        }
    }
}

impl Error for PeerIoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Raw(error) => Some(error),
            Self::Afxdp(error) => Some(error),
        }
    }
}

impl From<io::Error> for PeerIoError {
    fn from(error: io::Error) -> Self {
        Self::Raw(error)
    }
}

impl From<AfxdpError> for PeerIoError {
    fn from(error: AfxdpError) -> Self {
        Self::Afxdp(error)
    }
}

#[derive(Debug)]
enum PeerIo {
    Raw(RawIpv4Socket),
    Afxdp {
        socket: AfxdpSocket,
        _steering: XdpSteering,
    },
}

impl PacketIo for PeerIo {
    type Error = PeerIoError;

    fn max_ipv4_packet(&self) -> usize {
        match self {
            Self::Raw(socket) => socket.max_ipv4_packet(),
            Self::Afxdp { socket, .. } => socket.max_ipv4_packet(),
        }
    }

    fn transmit_ipv4(&mut self, packet: &[u8]) -> Result<(), Self::Error> {
        match self {
            Self::Raw(socket) => socket.transmit_ipv4(packet).map_err(Into::into),
            Self::Afxdp { socket, .. } => socket.transmit_ipv4(packet).map_err(Into::into),
        }
    }

    fn receive_ipv4(&mut self, output: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        match self {
            Self::Raw(socket) => socket.receive_ipv4(output).map_err(Into::into),
            Self::Afxdp { socket, .. } => socket.receive_ipv4(output).map_err(Into::into),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Send = 1,
    Write = 2,
    Read = 3,
}

impl Operation {
    fn parse(value: &str) -> Result<Self, DynError> {
        match value {
            "1" | "send" => Ok(Self::Send),
            "2" | "write" => Ok(Self::Write),
            "3" | "read" => Ok(Self::Read),
            _ => Err("operation must be 1/send, 2/write, or 3/read".into()),
        }
    }

    const fn code(self) -> u8 {
        self as u8
    }

    const fn completion(self) -> CompletionOpcode {
        match self {
            Self::Send => CompletionOpcode::Send,
            Self::Write => CompletionOpcode::RdmaWrite,
            Self::Read => CompletionOpcode::RdmaRead,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Config {
    local_ip: Ipv4Addr,
    peer_ip: Ipv4Addr,
    tcp_port: u16,
    operation: Operation,
    requester: bool,
    size: u32,
    mtu: u16,
    psn: u32,
    iterations: u32,
}

impl Config {
    fn parse() -> Result<Self, DynError> {
        let mut args = env::args();
        let program = args
            .next()
            .unwrap_or_else(|| String::from("rocev2-rust-peer"));
        let values: Vec<String> = args.collect();
        if values.len() != 9 {
            return Err(format!(
                "usage: {program} LOCAL_IPV4 PEER_IPV4 TCP_PORT OP REQUESTER(0/1) SIZE MTU PSN ITERATIONS"
            )
            .into());
        }
        let local_ip = values[0].parse::<Ipv4Addr>()?;
        let peer_ip = values[1].parse::<Ipv4Addr>()?;
        let tcp_port = parse_number::<u16>(&values[2], "TCP port")?;
        let operation = Operation::parse(&values[3])?;
        let requester = match values[4].as_str() {
            "0" => false,
            "1" => true,
            _ => return Err("REQUESTER must be 0 or 1".into()),
        };
        let size = parse_number::<u32>(&values[5], "size")?;
        let mtu = parse_number::<u16>(&values[6], "MTU")?;
        if !matches!(mtu, 256 | 512 | 1024 | 2048 | 4096) {
            return Err("MTU must be 256, 512, 1024, 2048, or 4096".into());
        }
        let psn = parse_number::<u32>(&values[7], "PSN")?;
        if psn > 0x00ff_ffff {
            return Err("PSN exceeds 24 bits".into());
        }
        let iterations = parse_number::<u32>(&values[8], "iterations")?;
        if tcp_port == 0 || iterations == 0 || !is_unicast(local_ip) || !is_unicast(peer_ip) {
            return Err("addresses, TCP port, and iterations must be valid nonzero values".into());
        }
        Ok(Self {
            local_ip,
            peer_ip,
            tcp_port,
            operation,
            requester,
            size,
            mtu,
            psn,
            iterations,
        })
    }
}

fn parse_number<T>(value: &str, name: &str) -> Result<T, DynError>
where
    T: std::str::FromStr,
    T::Err: Error + Send + Sync + 'static,
{
    value
        .parse::<T>()
        .map_err(|error| format!("invalid {name}: {error}").into())
}

fn env_number<T>(name: &str) -> Result<T, DynError>
where
    T: std::str::FromStr,
    T::Err: Error + Send + Sync + 'static,
{
    let value = env::var(name).map_err(|_| format!("{name} is required for AF_XDP"))?;
    parse_number(&value, name)
}

fn parse_mac(name: &str) -> Result<[u8; 6], DynError> {
    let value = env::var(name).map_err(|_| format!("{name} is required for AF_XDP"))?;
    let mut output = [0_u8; 6];
    let mut fields = value.split(':');
    for byte in &mut output {
        let field = fields.next().ok_or_else(|| format!("invalid {name}"))?;
        if field.len() != 2 {
            return Err(format!("invalid {name}").into());
        }
        *byte = u8::from_str_radix(field, 16).map_err(|_| format!("invalid {name}"))?;
    }
    if fields.next().is_some() {
        return Err(format!("invalid {name}").into());
    }
    Ok(output)
}

fn open_io(config: Config, packet_size: usize) -> Result<PeerIo, DynError> {
    match env::var("ROCEV2_BACKEND")
        .unwrap_or_else(|_| String::from("raw"))
        .as_str()
    {
        "raw" => Ok(PeerIo::Raw(RawIpv4Socket::bind(RawIpv4Config {
            bind_address: config.local_ip,
            max_ipv4_packet: packet_size,
        })?)),
        "afxdp" => {
            let interface_index = env_number::<u32>("ROCEV2_IFINDEX")?;
            let queue_id = env::var("ROCEV2_QUEUE")
                .map_or_else(|_| Ok(0_u32), |value| parse_number(&value, "ROCEV2_QUEUE"))?;
            let queue_count = env::var("ROCEV2_QUEUE_COUNT").map_or_else(
                |_| queue_id.checked_add(1).ok_or("queue count overflow".into()),
                |value| parse_number(&value, "ROCEV2_QUEUE_COUNT"),
            )?;
            if interface_index == 0 || queue_count == 0 || queue_id >= queue_count {
                return Err("invalid AF_XDP interface or queue configuration".into());
            }
            let ethernet = EthernetPath::new(
                parse_mac("ROCEV2_SOURCE_MAC")?,
                parse_mac("ROCEV2_DEST_MAC")?,
            );
            let steering = XdpSteering::attach(interface_index, queue_count)?;
            let mut afxdp = AfxdpConfig::new(interface_index, queue_id, ethernet);
            if env::var_os("ROCEV2_ALLOW_COPY_FALLBACK").is_some() {
                afxdp.bind_mode = AfxdpBindMode::AllowCopyFallback;
            }
            let mut socket = AfxdpSocket::bind(afxdp)?;
            socket.attach_steering(&steering)?;
            if socket.max_ipv4_packet() < packet_size {
                return Err(format!(
                    "AF_XDP frame supports at most {} IPv4 bytes, workload needs {packet_size}",
                    socket.max_ipv4_packet()
                )
                .into());
            }
            Ok(PeerIo::Afxdp {
                socket,
                _steering: steering,
            })
        }
        backend => Err(format!("unknown ROCEV2_BACKEND {backend:?}; use raw or afxdp").into()),
    }
}

fn is_unicast(address: Ipv4Addr) -> bool {
    let first = address.octets()[0];
    first != 0 && first < 224
}

fn pattern(offset: usize, iteration: u32) -> u8 {
    let value = (offset as u64)
        .wrapping_mul(131)
        .wrapping_add(u64::from(iteration).wrapping_mul(17));
    (value ^ ((offset as u64) >> 8)) as u8
}

fn fill_pattern(output: &mut [u8], iteration: u32) {
    for (offset, byte) in output.iter_mut().enumerate() {
        *byte = pattern(offset, iteration);
    }
}

fn connect_control(config: Config) -> io::Result<TcpStream> {
    let deadline = Instant::now() + CONTROL_TIMEOUT;
    loop {
        match TcpStream::connect(SocketAddrV4::new(config.peer_ip, config.tcp_port)) {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                stream.set_read_timeout(Some(CONTROL_TIMEOUT))?;
                stream.set_write_timeout(Some(CONTROL_TIMEOUT))?;
                return Ok(stream);
            }
            Err(error)
                if Instant::now() < deadline
                    && matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::AddrNotAvailable
                            | io::ErrorKind::NetworkUnreachable
                    ) =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn exchange_metadata(
    stream: &mut TcpStream,
    config: Config,
    local: RcConnectionInfo,
) -> Result<RcConnectionInfo, DynError> {
    let mut request = [0_u8; REQUEST_LEN];
    request[..4].copy_from_slice(b"RQT1");
    request[4] = config.operation.code();
    request[5] = u8::from(config.requester);
    request[8..12].copy_from_slice(&config.size.to_be_bytes());
    request[12..16].copy_from_slice(&config.iterations.to_be_bytes());
    stream.write_all(&request)?;

    let mut remote = [0_u8; RC_CONNECTION_INFO_LEN];
    stream.read_exact(&mut remote)?;
    stream.write_all(&local.encode()?)?;
    let remote = RcConnectionInfo::decode(&remote)?;
    if remote.ipv4 != config.peer_ip.octets() {
        return Err("control peer advertised an unexpected IPv4 address".into());
    }
    if remote.remote_length < u64::from(config.size) {
        return Err("control peer memory region is smaller than the workload".into());
    }
    Ok(remote)
}

fn barrier(stream: &mut TcpStream) -> io::Result<()> {
    let mut token = [0_u8; 1];
    stream.read_exact(&mut token)?;
    if token != *b"R" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ready token",
        ));
    }
    stream.write_all(b"R")
}

fn local_info(config: Config, region: RegionHandle) -> RcConnectionInfo {
    RcConnectionInfo {
        ipv4: config.local_ip.octets(),
        mac: [0; 6],
        qpn: QPN,
        psn: config.psn,
        mtu: config.mtu,
        rkey: region.rkey(),
        remote_address: region.address(),
        remote_length: region.length(),
        retry_count: RETRY_COUNT,
        rnr_retry_count: RNR_RETRY_COUNT,
        timeout: ACK_TIMEOUT,
        max_rd_atomic: QP_DEPTH,
        max_dest_rd_atomic: QP_DEPTH,
        rnr_nak_timer: RNR_TIMER,
        udp_source_port: UDP_SOURCE_PORT,
    }
}

fn set_payload(
    endpoint: &mut PeerEndpoint<'_>,
    region: RegionHandle,
    size: usize,
    iteration: u32,
    source: bool,
    scratch: &mut [u8],
) -> Result<(), DynError> {
    let payload = &mut scratch[..size];
    if source {
        fill_pattern(payload, iteration);
    } else {
        payload.fill(0xa5);
    }
    endpoint
        .memory_registry_mut()
        .write_local(region.lkey(), region.address(), payload)?;
    Ok(())
}

fn verify_payload(
    endpoint: &mut PeerEndpoint<'_>,
    region: RegionHandle,
    size: usize,
    iteration: u32,
    scratch: &mut [u8],
) -> Result<(), DynError> {
    let payload = &mut scratch[..size];
    endpoint
        .memory_registry_mut()
        .read_local(region.lkey(), region.address(), payload)?;
    for (offset, byte) in payload.iter().copied().enumerate() {
        let expected = pattern(offset, iteration);
        if byte != expected {
            return Err(format!(
                "payload mismatch iteration={iteration} offset={offset}: got {byte:#04x}, expected {expected:#04x}"
            )
            .into());
        }
    }
    Ok(())
}

fn post_requester(
    endpoint: &mut PeerEndpoint<'_>,
    qp: rocev2::QpHandle,
    region: RegionHandle,
    remote: RcConnectionInfo,
    config: Config,
    iteration: u32,
) -> Result<(), DynError> {
    let sge = Sge::new(region.address(), config.size, region.lkey());
    let id = u64::from(iteration);
    let work = match config.operation {
        Operation::Send => WorkRequest::send(id, sge, true),
        Operation::Write => WorkRequest::write(id, sge, remote.remote_address, remote.rkey, true),
        Operation::Read => WorkRequest::read(id, sge, remote.remote_address, remote.rkey, true),
    };
    endpoint.post_work(qp, work)?;
    Ok(())
}

fn validate_completion(
    completion: Completion,
    expected_id: u64,
    expected_opcode: CompletionOpcode,
    expected_size: u32,
) -> Result<(), DynError> {
    if completion.work_request_id != expected_id
        || completion.opcode != expected_opcode
        || completion.status != CompletionStatus::Success
        || completion.byte_len != expected_size
    {
        return Err(format!("unexpected completion: {completion:?}").into());
    }
    Ok(())
}

fn tick(origin: Instant) -> u64 {
    u64::try_from(origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn drive_until_completion(
    endpoint: &mut PeerEndpoint<'_>,
    qp: rocev2::QpHandle,
    config: Config,
    iteration: u32,
    rx: &mut [u8],
    tx: &mut [u8],
) -> Result<(), DynError> {
    let deadline = Instant::now() + CONTROL_TIMEOUT;
    let origin = Instant::now();
    loop {
        if let Some(completion) = endpoint.poll_completion(qp)? {
            validate_completion(
                completion,
                u64::from(iteration),
                config.operation.completion(),
                config.size,
            )?;
            return Ok(());
        }
        endpoint.progress(tick(origin), rx, tx)?;
        if Instant::now() >= deadline {
            return Err("transport completion deadline expired".into());
        }
        std::hint::spin_loop();
    }
}

fn wait_done_while_progressing(
    stream: &mut TcpStream,
    endpoint: &mut PeerEndpoint<'_>,
    rx: &mut [u8],
    tx: &mut [u8],
) -> Result<(), DynError> {
    stream.set_nonblocking(true)?;
    let deadline = Instant::now() + CONTROL_TIMEOUT;
    let origin = Instant::now();
    let mut token = [0_u8; 1];
    let result = loop {
        match stream.read(&mut token) {
            Ok(1) if token == *b"D" => break Ok(()),
            Ok(1) => {
                break Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid done token",
                ));
            }
            Ok(0) => {
                break Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "control peer closed",
                ));
            }
            Ok(_) => {
                break Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid control read",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => break Err(error),
        }
        endpoint
            .progress(tick(origin), rx, tx)
            .map_err(io::Error::other)?;
        if Instant::now() >= deadline {
            break Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "peer completion deadline expired",
            ));
        }
        std::hint::spin_loop();
    };
    stream.set_nonblocking(false)?;
    result?;
    Ok(())
}

struct IterationContext<'a, 'b> {
    stream: &'a mut TcpStream,
    endpoint: &'a mut PeerEndpoint<'b>,
    qp: rocev2::QpHandle,
    region: RegionHandle,
    remote: RcConnectionInfo,
    config: Config,
    payload: &'a mut [u8],
    rx: &'a mut [u8],
    tx: &'a mut [u8],
}

fn run_iteration(
    context: &mut IterationContext<'_, '_>,
    iteration: u32,
) -> Result<Option<u64>, DynError> {
    let IterationContext {
        stream,
        endpoint,
        qp,
        region,
        remote,
        config,
        payload,
        rx,
        tx,
    } = context;
    let local_source = (config.requester && config.operation != Operation::Read)
        || (!config.requester && config.operation == Operation::Read);
    set_payload(
        endpoint,
        *region,
        usize::try_from(config.size)?,
        iteration,
        local_source,
        payload,
    )?;

    if !config.requester && config.operation == Operation::Send {
        endpoint.post_receive(
            *qp,
            RecvWorkRequest::new(
                u64::from(iteration),
                Sge::new(region.address(), config.size, region.lkey()),
            ),
        )?;
    }

    barrier(stream)?;
    let mut latency = None;
    if config.requester {
        let operation_start = Instant::now();
        post_requester(endpoint, *qp, *region, *remote, *config, iteration)?;
        drive_until_completion(endpoint, *qp, *config, iteration, rx, tx)?;
        latency = Some(tick(operation_start));
        if config.operation == Operation::Read {
            verify_payload(
                endpoint,
                *region,
                usize::try_from(config.size)?,
                iteration,
                payload,
            )?;
        }
        stream.write_all(b"D")?;
        let mut token = [0_u8; 1];
        stream.read_exact(&mut token)?;
        if token != *b"K" {
            return Err("invalid acknowledgement token".into());
        }
    } else {
        wait_done_while_progressing(stream, endpoint, rx, tx)?;
        if config.operation != Operation::Read {
            verify_payload(
                endpoint,
                *region,
                usize::try_from(config.size)?,
                iteration,
                payload,
            )?;
        }
        if config.operation == Operation::Send {
            let completion = endpoint
                .poll_completion(*qp)?
                .ok_or("SEND responder is missing its receive completion")?;
            validate_completion(
                completion,
                u64::from(iteration),
                CompletionOpcode::Receive,
                config.size,
            )?;
        }
        stream.write_all(b"K")?;
    }
    Ok(latency)
}

fn percentile(samples: &[u64], numerator: usize, denominator: usize) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let rank = samples
        .len()
        .saturating_mul(numerator)
        .div_ceil(denominator);
    samples[rank.saturating_sub(1).min(samples.len() - 1)]
}

fn run(config: Config) -> Result<(), DynError> {
    let packet_size = usize::from(config.mtu)
        .checked_add(64)
        .ok_or("packet size overflow")?;
    let io = open_io(config, packet_size)?;
    let mut endpoint = PeerEndpoint::new(
        io,
        RcEndpointConfig {
            maximum_packet_size: packet_size,
            ticks_per_second: 1_000_000_000,
            memory_key_seed: 0x7263_7632,
        },
    )?;

    let size = usize::try_from(config.size)?;
    let mut buffer = vec![0_u8; size.max(1)];
    let mut key_generator = SystemKeyGenerator::new()?;
    let region = endpoint.register_memory_with_key_generator(
        &mut buffer,
        AccessFlags::LOCAL_WRITE | AccessFlags::REMOTE_WRITE | AccessFlags::REMOTE_READ,
        &mut key_generator,
    )?;
    let local = local_info(config, region);

    let mut stream = connect_control(config)?;
    let remote = exchange_metadata(&mut stream, config, local)?;
    let qp = endpoint.create_qp(local.qp_config(remote)?)?;
    endpoint.transition_qp(qp, QpState::Init)?;
    endpoint.transition_qp(qp, QpState::Rtr)?;
    endpoint.transition_qp(qp, QpState::Rts)?;

    let mut payload = vec![0_u8; size];
    let mut rx = vec![0_u8; packet_size];
    let mut tx = vec![0_u8; packet_size];
    let mut context = IterationContext {
        stream: &mut stream,
        endpoint: &mut endpoint,
        qp,
        region,
        remote,
        config,
        payload: &mut payload,
        rx: &mut rx,
        tx: &mut tx,
    };
    let mut latencies = Vec::with_capacity(if config.requester {
        usize::try_from(config.iterations)?
    } else {
        0
    });
    let run_start = Instant::now();
    for iteration in 0..config.iterations {
        if let Some(latency) = run_iteration(&mut context, iteration)? {
            latencies.push(latency);
        }
    }
    let elapsed = tick(run_start);
    let payload_bytes = u64::from(config.size).saturating_mul(u64::from(config.iterations));
    if config.requester {
        latencies.sort_unstable();
        println!(
            "{{\"peer\":\"rocev2-rs\",\"operation\":{},\"requester\":true,\"size\":{},\"iterations\":{},\"mtu\":{},\"elapsed_ns\":{elapsed},\"payload_bytes\":{payload_bytes},\"p50_ns\":{},\"p95_ns\":{},\"p99_ns\":{},\"p999_ns\":{},\"status\":\"pass\"}}",
            config.operation.code(),
            config.size,
            config.iterations,
            config.mtu,
            percentile(&latencies, 50, 100),
            percentile(&latencies, 95, 100),
            percentile(&latencies, 99, 100),
            percentile(&latencies, 999, 1000)
        );
    } else {
        println!(
            "{{\"peer\":\"rocev2-rs\",\"operation\":{},\"requester\":false,\"size\":{},\"iterations\":{},\"mtu\":{},\"elapsed_ns\":{elapsed},\"payload_bytes\":{payload_bytes},\"status\":\"pass\"}}",
            config.operation.code(),
            config.size,
            config.iterations,
            config.mtu
        );
    }
    Ok(())
}

fn main() -> Result<(), DynError> {
    run(Config::parse()?)
}
