use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::Duration;

use clap::Parser;
use pnet::{
    datalink,
    packet::{
        tcp::{TcpPacket, MutableTcpPacket, TcpFlags, TcpOption},
        ipv4::{MutableIpv4Packet, Ipv4Flags},
        ipv6::{MutableIpv6Packet},
        ip::{IpNextHeaderProtocols},
    },
    transport::{transport_channel, TransportChannelType, TransportSender},
};
use rand::{Rng, rng};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, help = "Target IP address (required)")]
    target: Option<String>,
    
    #[clap(short, long, help = "Target port number (required)")]
    port: Option<u32>,
    
    #[clap(short, long, help = "Number of packets to send (required)")]
    count: Option<u32>,
    
    #[clap(short, long, default_value_t = false, help = "Use IPv6 instead of IPv4")]
    ipv6: bool,
    
    #[clap(short, long, default_value_t = false, help = "Run in background (daemon) mode")]
    daemon: bool,
    
    #[clap(long, default_value_t = 1, help = "Number of worker threads (1-8)")]
    threads: usize,
    
    #[clap(long, default_value_t = 0, help = "Delay between packets in milliseconds")]
    delay: u64,
}

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 32;

// 全局缓冲区池，减少内存分配
struct BufferPool {
    buffers: Vec<Vec<u8>>,
    ipv6: bool,
}

impl BufferPool {
    fn new(size: usize, ipv6: bool) -> Self {
        let buffer_size = if ipv6 {
            IPV6_HEADER_LEN + TCP_HEADER_LEN
        } else {
            IPV4_HEADER_LEN + TCP_HEADER_LEN
        };
        
        let mut buffers = Vec::with_capacity(size);
        for _ in 0..size {
            buffers.push(vec![0u8; buffer_size]);
        }
        
        BufferPool { buffers, ipv6 }
    }
    
    // 从池获取缓冲区，线程安全
    fn get(&mut self) -> Vec<u8> {
        self.buffers.pop().unwrap_or_else(|| {
            vec![0u8; if self.ipv6 {
                IPV6_HEADER_LEN + TCP_HEADER_LEN
            } else {
                IPV4_HEADER_LEN + TCP_HEADER_LEN
            }]
        })
    }
    
    // 归还缓冲区到池
    fn put(&mut self, buffer: Vec<u8>) {
        if self.buffers.len() < 1000 {  // 限制池大小，防止内存过度增长
            self.buffers.push(buffer);
        }
    }
}

fn print_usage() {
    // 英语使用方法
    println!("\nUsage Instructions (English):");
    println!("This program sends TCP packets to a specified target.");
    println!("Required parameters:");
    println!("  -t, --target <IP>    Target IP address");
    println!("  -p, --port <PORT>    Target port number");
    println!("  -c, --count <NUM>    Number of packets to send");
    println!("\nOptional parameters:");
    println!("  -6, --ipv6           Use IPv6 protocol (default: IPv4)");
    println!("  -d, --daemon         Run in background mode");
    println!("      --threads <NUM>  Number of worker threads (1-8, default: 1)");
    println!("      --delay <MS>     Delay between packets in milliseconds (default: 0)");
    println!("\nExamples:");
    println!("  ./program -t 192.168.1.1 -p 80 -c 1000 --threads 4");
    println!("  ./program -t 2001:db8::1 -p 80 -c 1000 --threads 4 --ipv6");
    
    // 汉语使用方法
    println!("\n使用说明 (中文):");
    println!("本程序用于向指定目标发送TCP数据包。");
    println!("必填参数:");
    println!("  -t, --target <IP>    目标IP地址");
    println!("  -p, --port <PORT>    目标端口号");
    println!("  -c, --count <NUM>    要发送的数据包数量");
    println!("\n可选参数:");
    println!("  -6, --ipv6           使用IPv6协议 (默认: IPv4)");
    println!("  -d, --daemon         以后台模式运行");
    println!("      --threads <NUM>  工作线程数量 (1-8, 默认: 1)");
    println!("      --delay <MS>     数据包发送间隔(毫秒) (默认: 0)");
    println!("\n示例:");
    println!("  ./program -t 192.168.1.1 -p 80 -c 1000 --threads 4");
    println!("  ./program -t 2001:db8::1 -p 80 -c 1000 --threads 4 --ipv6");
}

// 获取本机IP地址
fn get_local_ip(is_ipv6: bool) -> String {
    // 修复：直接使用接口列表，不需要Result处理
    let interfaces = datalink::interfaces();
    
    for iface in interfaces {
        // 跳过回环接口
        if iface.is_loopback() {
            continue;
        }
        
        for addr in iface.ips {
            let ip = addr.ip();
            // 检查IP版本并确保不是回环地址
            if (is_ipv6 && ip.is_ipv6() && !ip.is_loopback()) ||
               (!is_ipv6 && ip.is_ipv4() && !ip.is_loopback()) {
                return ip.to_string();
            }
        }
    }
    
    // 如果自动获取失败，返回回环地址
    if is_ipv6 {
        "::1".to_string() // IPv6回环地址
    } else {
        "127.0.0.1".to_string() // IPv4回环地址
    }
}

// 后台模式处理
#[cfg(unix)]
fn run_as_daemon() -> std::io::Result<()> {
    use std::process::Command;
    
    // Unix系统下的后台模式实现
    match Command::new(std::env::current_exe()?).arg("--daemon").spawn() {
        Ok(_) => std::process::exit(0),
        Err(e) => Err(e),
    }
}

#[cfg(windows)]
fn run_as_daemon() -> std::io::Result<()> {
    use std::ptr;
    use winapi::um::winbase::{CREATE_NO_WINDOW, DETACHED_PROCESS};
    use winapi::um::processthreadsapi::CreateProcessW;
    use winapi::um::winnt::WCHAR;
    
    // Windows系统下的后台模式实现
    let exe_path = std::env::current_exe()?;
    let cmd_line = format!("\"{}\" --daemon", exe_path.to_string_lossy());
    
    let mut wide_cmd: Vec<WCHAR> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();
    
    let mut startup_info = winapi::um::winbase::STARTUPINFOW {
        cb: std::mem::size_of::<winapi::um::winbase::STARTUPINFOW>() as u32,
        lpReserved: ptr::null_mut(),
        lpDesktop: ptr::null_mut(),
        lpTitle: ptr::null_mut(),
        dwX: 0,
        dwY: 0,
        dwXSize: 0,
        dwYSize: 0,
        dwXCountChars: 0,
        dwYCountChars: 0,
        dwFillAttribute: 0,
        dwFlags: 0,
        wShowWindow: 0,
        cbReserved2: 0,
        lpReserved2: ptr::null_mut(),
        hStdInput: ptr::null_mut(),
        hStdOutput: ptr::null_mut(),
        hStdError: ptr::null_mut(),
    };
    
    let mut process_info = winapi::um::processthreadsapi::PROCESS_INFORMATION {
        hProcess: ptr::null_mut(),
        hThread: ptr::null_mut(),
        dwProcessId: 0,
        dwThreadId: 0,
    };
    
    let success = unsafe {
        CreateProcessW(
            ptr::null_mut(),
            wide_cmd.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            CREATE_NO_WINDOW | DETACHED_PROCESS,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut startup_info,
            &mut process_info,
        )
    };
    
    if success == 0 {
        return Err(std::io::Error::last_os_error());
    }
    
    unsafe {
        winapi::um::handleapi::CloseHandle(process_info.hProcess);
        winapi::um::handleapi::CloseHandle(process_info.hThread);
    }
    
    std::process::exit(0);
}

// 工作线程函数，处理数据包发送
fn worker_thread(
    thread_id: usize,
    source: String,
    target: String,
    port: u32,
    count: u32,
    ipv6: bool,
    delay: u64,
    tx: Arc<std::sync::Mutex<TransportSender>>,
    buffer_pool: Arc<std::sync::Mutex<BufferPool>>,
    counter: Arc<AtomicU32>,
    total: u32,
) {
    let target_ip: IpAddr = match IpAddr::from_str(&target) {
        Ok(ip) => {
            // 验证IP版本是否与指定的一致
            if (ipv6 && ip.is_ipv4()) || (!ipv6 && ip.is_ipv6()) {
                eprintln!("Thread {}: IP version mismatch - specified {} but target is {}", 
                         thread_id, if ipv6 { "IPv6" } else { "IPv4" }, ip);
                return;
            }
            ip
        }
        Err(e) => {
            eprintln!("Thread {}: Invalid target IP: {}", thread_id, e);
            return;
        }
    };

    let mut rng = rng();
    
    for _ in 0..count {
        // 从缓冲区池获取缓冲区
        let mut buffer = buffer_pool.lock().unwrap().get();
        
        // 构建数据包
        let packet = if ipv6 {
            build_ipv6_packet(&source, &target, port, &mut buffer, &mut rng);
            TcpPacket::new(&buffer[IPV6_HEADER_LEN..]).unwrap()
        } else {
            build_ipv4_packet(&source, &target, port, &mut buffer, &mut rng);
            TcpPacket::new(&buffer[IPV4_HEADER_LEN..]).unwrap()
        };
        
        // 发送数据包
        let result = tx.lock().unwrap().send_to(packet, target_ip);
        
        // 更新计数器并在需要时打印进度
        let current = counter.fetch_add(1, Ordering::Relaxed) + 1;
        if current % 100 == 0 || current == total {
            println!("Sent {}/{} packets", current, total);
        }
        
        // 处理发送错误
        if let Err(e) = result {
            eprintln!("Thread {}: Failed to send packet: {}", thread_id, e);
        }
        
        // 归还缓冲区到池
        buffer_pool.lock().unwrap().put(buffer);
        
        // 延迟处理
        if delay > 0 {
            thread::sleep(Duration::from_millis(delay));
        }
    }
}

fn build_ipv4_packet<R: Rng>(
    source: &str, 
    target: &str, 
    port: u32, 
    buffer: &mut [u8],
    rng: &mut R
) {
    let ipv4_source: Ipv4Addr = source.parse().unwrap();
    let ipv4_destination: Ipv4Addr = target.parse().unwrap();
    
    // 设置IP头部
    {
        let len = (IPV4_HEADER_LEN + TCP_HEADER_LEN) as u16;
        let mut ip_header = MutableIpv4Packet::new(&mut buffer[..IPV4_HEADER_LEN]).unwrap();
        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_total_length(len);
        ip_header.set_identification(rng.random());
        ip_header.set_flags(Ipv4Flags::DontFragment);
        ip_header.set_ttl(rng.random_range(32..=128));
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(ipv4_source);
        ip_header.set_destination(ipv4_destination);
        
        let checksum = pnet::packet::ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }
    
    // 设置TCP头部
    {
        let mut tcp_header = MutableTcpPacket::new(&mut buffer[IPV4_HEADER_LEN..IPV4_HEADER_LEN + TCP_HEADER_LEN]).unwrap();
        tcp_header.set_source(rng.random_range(1000..5000));
        tcp_header.set_destination(port as u16);
        tcp_header.set_sequence(rng.random());
        tcp_header.set_acknowledgement(0);
        tcp_header.set_data_offset(8);
        tcp_header.set_flags(TcpFlags::SYN);
        tcp_header.set_window(rng.random_range(1000..5000));
        tcp_header.set_urgent_ptr(0);
        
        tcp_header.set_options(&[
            TcpOption::mss(1460),
            TcpOption::sack_perm(),
            TcpOption::nop(),
            TcpOption::nop(),
            TcpOption::wscale(7),
        ]);
        
        let tcp_checksum = pnet::packet::tcp::ipv4_checksum(
            &tcp_header.to_immutable(),
            &ipv4_source,
            &ipv4_destination,
        );
        tcp_header.set_checksum(tcp_checksum);
    }
}

fn build_ipv6_packet<R: Rng>(
    source: &str, 
    target: &str, 
    port: u32, 
    buffer: &mut [u8],
    rng: &mut R
) {
    let ipv6_source: Ipv6Addr = source.parse().unwrap();
    let ipv6_destination: Ipv6Addr = target.parse().unwrap();
    
    // 设置IP头部
    {
        let payload_len = TCP_HEADER_LEN as u16;
        let mut ip_header = MutableIpv6Packet::new(&mut buffer[..IPV6_HEADER_LEN]).unwrap();
        ip_header.set_version(6);
        ip_header.set_traffic_class(rng.random());
        ip_header.set_flow_label(rng.random::<u32>() & 0x000FFFFF); // 流标签是20位
        ip_header.set_payload_length(payload_len);
        ip_header.set_next_header(IpNextHeaderProtocols::Tcp);
        ip_header.set_hop_limit(rng.random_range(32..=128));
        ip_header.set_source(ipv6_source);
        ip_header.set_destination(ipv6_destination);
    }
    
    // 设置TCP头部
    {
        let mut tcp_header = MutableTcpPacket::new(&mut buffer[IPV6_HEADER_LEN..IPV6_HEADER_LEN + TCP_HEADER_LEN]).unwrap();
        tcp_header.set_source(rng.random_range(1000..5000));
        tcp_header.set_destination(port as u16);
        tcp_header.set_sequence(rng.random());
        tcp_header.set_acknowledgement(0);
        tcp_header.set_data_offset(8);
        tcp_header.set_flags(TcpFlags::SYN);
        tcp_header.set_window(rng.random_range(1000..5000));
        tcp_header.set_urgent_ptr(0);
        
        tcp_header.set_options(&[
            TcpOption::mss(1460),
            TcpOption::sack_perm(),
            TcpOption::nop(),
            TcpOption::nop(),
            TcpOption::wscale(7),
        ]);
        
        let tcp_checksum = pnet::packet::tcp::ipv6_checksum(
            &tcp_header.to_immutable(),
            &ipv6_source,
            &ipv6_destination,
        );
        tcp_header.set_checksum(tcp_checksum);
    }
}

fn main() {
    let args = Args::parse();
    
    // 检查是否缺少必要参数
    let target = match &args.target {
        Some(t) => t,
        None => {
            println!("Error: Missing target IP address");
            print_usage();
            return;
        }
    };
    
    let port = match args.port {
        Some(p) => p,
        None => {
            println!("Error: Missing target port");
            print_usage();
            return;
        }
    };
    
    let count = match args.count {
        Some(c) => c,
        None => {
            println!("Error: Missing packet count");
            print_usage();
            return;
        }
    };
    
    // 处理线程数量（限制在1-8之间）
    let num_threads = args.threads.clamp(1, 8);
    
    // 处理后台模式
    if args.daemon {
        #[cfg(any(unix, windows))]
        if let Err(e) = run_as_daemon() {
            eprintln!("Failed to run as daemon: {}", e);
            std::process::exit(1);
        }
    }
    
    let ipv6 = args.ipv6;
    let delay = args.delay;
    
    // 获取本机IP作为源地址
    let source = get_local_ip(ipv6);
    
    println!("Using source IP: {}", source);
    println!("target: {}, port: {}, count: {}, threads: {}, ipv6: {}, delay: {}ms", 
             target, port, count, num_threads, ipv6, delay);

    // 创建传输通道
    let protocol = if ipv6 {
        TransportChannelType::Layer3(IpNextHeaderProtocols::Ipv6)
    } else {
        TransportChannelType::Layer3(IpNextHeaderProtocols::Ipv4)
    };

    let (tx, _) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (Arc::new(std::sync::Mutex::new(tx)), rx),
        Err(e) => {
            eprintln!("Error creating transport channel: {}", e);
            std::process::exit(1);
        }
    };
    
    // 创建缓冲区池
    let buffer_pool = Arc::new(std::sync::Mutex::new(BufferPool::new(
        (count.min(1000) as usize).max(num_threads * 2),
        ipv6
    )));
    
    // 创建计数器
    let counter = Arc::new(AtomicU32::new(0));
    let total = count;
    
    // 计算每个线程需要处理的数据包数量
    let base_count = count / num_threads as u32;
    let remainder = count % num_threads as u32;
    
    // 启动工作线程
    let mut handles = Vec::with_capacity(num_threads);
    for i in 0..num_threads {
        let thread_count = base_count + if i == 0 { remainder } else { 0 };
        if thread_count == 0 {
            break;
        }
        
        let source = source.clone();
        let target = target.clone();
        let tx = Arc::clone(&tx);
        let buffer_pool = Arc::clone(&buffer_pool);
        let counter = Arc::clone(&counter);
        
        let handle = thread::spawn(move || {
            worker_thread(
                i,
                source,
                target,
                port,
                thread_count,
                ipv6,
                delay,
                tx,
                buffer_pool,
                counter,
                total,
            );
        });
        
        handles.push(handle);
    }
    
    // 等待所有线程完成
    for handle in handles {
        if let Err(e) = handle.join() {
            eprintln!("Thread panicked: {:?}", e);
        }
    }
    
    println!("Completed. Total packets sent: {}", total);
}
