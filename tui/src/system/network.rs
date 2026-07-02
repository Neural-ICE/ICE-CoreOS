use std::fs;
use std::process::{Command, Stdio};

/// Network statistics for an interface
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NetworkStats {
    pub interface: String,
    pub ip_address: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub link_speed_mbps: Option<u32>,
}

impl NetworkStats {
    /// Collect network stats for the active interface
    pub fn collect() -> Self {
        let (interface, ip_address) = get_network_info();

        if interface == "none" {
            return Self::default();
        }

        let rx_bytes = read_sys_stat(&interface, "rx_bytes").unwrap_or(0);
        let tx_bytes = read_sys_stat(&interface, "tx_bytes").unwrap_or(0);
        let link_speed_mbps = read_link_speed(&interface);

        Self {
            interface,
            ip_address,
            rx_bytes,
            tx_bytes,
            link_speed_mbps,
        }
    }
}

/// Read a network statistic from /sys/class/net/<iface>/statistics/<stat>
fn read_sys_stat(interface: &str, stat: &str) -> Option<u64> {
    let path = format!("/sys/class/net/{}/statistics/{}", interface, stat);
    fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Read link speed from /sys/class/net/<iface>/speed (returns Mbps)
fn read_link_speed(interface: &str) -> Option<u32> {
    let path = format!("/sys/class/net/{}/speed", interface);
    fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .filter(|&speed: &i32| speed > 0) // -1 means unknown
        .map(|speed| speed as u32)
}

/// Format bytes per second to human-readable string (KB/s, MB/s, GB/s)
pub fn format_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 1024.0 {
        format!("{:.0} B/s", bytes_per_sec)
    } else if bytes_per_sec < 1024.0 * 1024.0 {
        format!("{:.1} KB/s", bytes_per_sec / 1024.0)
    } else if bytes_per_sec < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} MB/s", bytes_per_sec / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB/s", bytes_per_sec / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Get network information: (interface_name, ip_address)
pub fn get_network_info() -> (String, String) {
    // Try to get active connection via nmcli
    // Redirect stderr to null to prevent console pollution
    let output = match Command::new("nmcli")
        .args([
            "-t",
            "-f",
            "NAME,TYPE,DEVICE",
            "connection",
            "show",
            "--active",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        Ok(o) => o,
        Err(_) => return ("none".to_string(), "unknown".to_string()),
    };

    if !output.status.success() {
        return ("none".to_string(), "unknown".to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            let _conn_type = parts[1];
            let device = parts[2];

            // Skip loopback
            if device == "lo" {
                continue;
            }

            let ip = get_ip_for_device(device);

            // Return just the device name (e.g., "enP7s7" or "wlan0")
            return (device.to_string(), ip);
        }
    }

    ("none".to_string(), "unknown".to_string())
}

/// Get IP address for a network device
fn get_ip_for_device(device: &str) -> String {
    let output = match Command::new("ip")
        .args(["-4", "-o", "addr", "show", device])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        Ok(o) => o,
        Err(_) => return "unknown".to_string(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = stdout.split_whitespace().collect();

    // Parse: "2: eth0    inet 192.168.1.42/24 ..."
    for (i, field) in fields.iter().enumerate() {
        if *field == "inet" {
            if let Some(ip_cidr) = fields.get(i + 1) {
                // Remove CIDR suffix
                if let Some(ip) = ip_cidr.split('/').next() {
                    return ip.to_string();
                }
                return ip_cidr.to_string();
            }
        }
    }

    "unknown".to_string()
}
