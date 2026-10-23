//! 允许名单：内置（回环地址、保留域名、系统账户、公共基础设施域名）+ 用户配置。

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use regex::Regex;

use crate::category::Category;
use crate::error::{Error, Result};

/// 系统/服务账户：出现在日志里不指向具体的人。
const SYSTEM_USERS: &[&str] = &[
    "root",
    "nobody",
    "nogroup",
    "daemon",
    "bin",
    "sys",
    "sync",
    "games",
    "man",
    "lp",
    "mail",
    "news",
    "uucp",
    "proxy",
    "www-data",
    "backup",
    "list",
    "irc",
    "gnats",
    "_apt",
    "messagebus",
    "sshd",
    "systemd-network",
    "systemd-resolve",
    "systemd-timesync",
    "systemd-journal",
    "systemd-coredump",
    "systemd-oom",
    "polkitd",
    "avahi",
    "avahi-autoipd",
    "colord",
    "gdm",
    "lightdm",
    "sddm",
    "rtkit",
    "pulse",
    "geoclue",
    "saned",
    "usbmux",
    "dnsmasq",
    "nm-openvpn",
    "nm-openconnect",
    "syslog",
    "uuidd",
    "tss",
    "tcpdump",
    "landscape",
    "pollinate",
    "fwupd-refresh",
    "kernoops",
    "whoopsie",
    "speech-dispatcher",
    "cups-pk-helper",
    "hplip",
    "postfix",
    "mysql",
    "postgres",
    "redis",
    "nginx",
    "apache",
    "http",
    "httpd",
    "chrony",
    "ntp",
    "_chrony",
    "dbus",
    "adm",
    "operator",
    "ftp",
    "halt",
    "shutdown",
    "mongodb",
    "elasticsearch",
    "grafana",
    "prometheus",
    "node_exporter",
    "docker",
    "containerd",
    "libvirt-qemu",
    "libvirt-dnsmasq",
    "qemu",
    "kvm",
    "zabbix",
    "nagios",
    "jenkins",
    "gitlab-runner",
    "git",
    "ubuntu",
    "ec2-user",
    "centos",
    "debian",
    "admin",
    "user",
    "guest",
    "test",
    "oracle",
    "pi",
    "vagrant",
    "ansible",
    "deploy",
    "system",
    "localhost",
    "anonymous",
    "public",
    "default",
    "all users",
    "default user",
    "shared",
    "defaultapppool",
];

/// 公共基础设施域名（软件源、镜像、证书、时间服务等），出现在日志里不是隐私。
const PUBLIC_DOMAINS: &[&str] = &[
    "debian.org",
    "debian.net",
    "ubuntu.com",
    "canonical.com",
    "launchpad.net",
    "launchpadcontent.net",
    "snapcraft.io",
    "snapcraft.com",
    "archlinux.org",
    "fedoraproject.org",
    "redhat.com",
    "centos.org",
    "rockylinux.org",
    "almalinux.org",
    "opensuse.org",
    "suse.com",
    "gentoo.org",
    "alpinelinux.org",
    "linuxmint.com",
    "kernel.org",
    "gnu.org",
    "freedesktop.org",
    "gnome.org",
    "kde.org",
    "mozilla.org",
    "mozilla.net",
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "docker.com",
    "docker.io",
    "quay.io",
    "ghcr.io",
    "gcr.io",
    "k8s.io",
    "kubernetes.io",
    "npmjs.org",
    "npmjs.com",
    "pypi.org",
    "pythonhosted.org",
    "python.org",
    "crates.io",
    "rust-lang.org",
    "golang.org",
    "go.dev",
    "maven.org",
    "apache.org",
    "nodejs.org",
    "flathub.org",
    "ntp.org",
    "ntppool.org",
    "letsencrypt.org",
    "digicert.com",
    "sectigo.com",
    "microsoft.com",
    "windowsupdate.com",
    "apple.com",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "cloudflare.com",
    "openssh.com",
    "openssl.org",
    "systemd.io",
    "aliyun.com",
    "tsinghua.edu.cn",
    "ustc.edu.cn",
    "huaweicloud.com",
    "tencent.com",
    "nvidia.com",
    "intel.com",
    "amd.com",
    "rsyslog.com",
    "nginx.org",
    "nginx.com",
    "postgresql.org",
    "mysql.com",
    "mariadb.org",
    "redis.io",
    "grafana.com",
    "elastic.co",
    "jetbrains.com",
    "visualstudio.com",
    "vscode-cdn.net",
    "kde.org",
    "xfce.org",
];

/// RFC 2606 / 6761 保留域名。
const RESERVED_DOMAINS: &[&str] =
    &["example.com", "example.org", "example.net", "example", "test", "invalid", "localhost", "localdomain"];

/// 不指向具体主机的 IPv4 网段：(网络地址, 前缀长度)。
const BUILTIN_V4: &[([u8; 4], u8)] = &[
    ([0, 0, 0, 0], 32),
    ([127, 0, 0, 0], 8),
    ([255, 255, 255, 255], 32),
    ([224, 0, 0, 0], 4),
    // 公共 DNS
    ([8, 8, 8, 8], 32),
    ([8, 8, 4, 4], 32),
    ([1, 1, 1, 1], 32),
    ([1, 0, 0, 1], 32),
    ([9, 9, 9, 9], 32),
    ([208, 67, 222, 222], 32),
    ([114, 114, 114, 114], 32),
    ([114, 114, 115, 115], 32),
    ([223, 5, 5, 5], 32),
    ([223, 6, 6, 6], 32),
    ([119, 29, 29, 29], 32),
    ([180, 76, 76, 76], 32),
];

const PRIVATE_V4: &[([u8; 4], u8)] =
    &[([10, 0, 0, 0], 8), ([172, 16, 0, 0], 12), ([192, 168, 0, 0], 16), ([100, 64, 0, 0], 10)];

#[derive(Debug, Default)]
pub struct Allowlist {
    exact: HashSet<String>,
    /// `*.example.com` → "example.com"，匹配自身及子域名。
    domain_suffix: Vec<String>,
    /// `*foo` → 以 foo 结尾。
    suffix: Vec<String>,
    /// `foo*` → 以 foo 开头。
    prefix: Vec<String>,
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
    regex: Vec<Regex>,
    keep_private: bool,
}

fn v4_net(addr: [u8; 4], len: u8) -> (u32, u32) {
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len as u32) };
    (u32::from_be_bytes(addr) & mask, mask)
}

fn v6_net(addr: Ipv6Addr, len: u8) -> (u128, u128) {
    let mask = if len == 0 { 0 } else { u128::MAX << (128 - len as u32) };
    (u128::from(addr) & mask, mask)
}

impl Allowlist {
    pub fn new(user: &[String], keep_private_ips: bool) -> Result<Allowlist> {
        let mut a = Allowlist { keep_private: keep_private_ips, ..Default::default() };
        for raw in user {
            let s = raw.trim();
            if s.is_empty() {
                continue;
            }
            if let Some(re) = s.strip_prefix("re:") {
                let r = regex::RegexBuilder::new(&format!("^(?:{re})$"))
                    .size_limit(1 << 22)
                    .build()
                    .map_err(|e| Error::Config(crate::t!("config.bad_allow_regex", re = re, err = e)))?;
                a.regex.push(r);
            } else if let Some((ip, len)) =
                s.split_once('/').and_then(|(ip, l)| Some((ip.parse::<IpAddr>().ok()?, l.parse::<u8>().ok()?)))
            {
                match ip {
                    IpAddr::V4(v4) if len <= 32 => a.v4.push(v4_net(v4.octets(), len)),
                    IpAddr::V6(v6) if len <= 128 => a.v6.push(v6_net(v6, len)),
                    _ => return Err(Error::Config(crate::t!("config.bad_cidr", value = s))),
                }
            } else if let Ok(ip) = s.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(v4) => a.v4.push(v4_net(v4.octets(), 32)),
                    IpAddr::V6(v6) => a.v6.push(v6_net(v6, 128)),
                }
            } else if let Some(rest) = s.strip_prefix("*.") {
                a.domain_suffix.push(rest.to_lowercase());
            } else if let Some(rest) = s.strip_prefix('*') {
                a.suffix.push(rest.to_lowercase());
            } else if let Some(rest) = s.strip_suffix('*') {
                a.prefix.push(rest.to_lowercase());
            } else {
                a.exact.insert(s.to_lowercase());
            }
        }
        Ok(a)
    }

    fn user_allowed(&self, value: &str) -> bool {
        let lower = value.to_lowercase();
        if self.exact.contains(&lower) {
            return true;
        }
        if self.domain_suffix.iter().any(|d| domain_matches(&lower, d)) {
            return true;
        }
        if self.suffix.iter().any(|s| lower.ends_with(s.as_str()))
            || self.prefix.iter().any(|p| lower.starts_with(p.as_str()))
        {
            return true;
        }
        if (!self.v4.is_empty() || !self.v6.is_empty())
            && let Some(ip) = parse_ip_loose(value)
        {
            match ip {
                IpAddr::V4(v4) => {
                    let x = u32::from(v4);
                    if self.v4.iter().any(|&(net, mask)| x & mask == net) {
                        return true;
                    }
                }
                IpAddr::V6(v6) => {
                    let x = u128::from(v6);
                    if self.v6.iter().any(|&(net, mask)| x & mask == net) {
                        return true;
                    }
                }
            }
        }
        self.regex.iter().any(|r| r.is_match(value))
    }

    /// 该值是否应当保留（不打码）。
    pub fn allowed(&self, cat: Category, value: &str) -> bool {
        if self.user_allowed(value) {
            return true;
        }
        builtin_allowed(cat, value, self.keep_private)
    }
}

fn domain_matches(host: &str, base: &str) -> bool {
    host == base
        || (host.len() > base.len() && host.ends_with(base) && host.as_bytes()[host.len() - base.len() - 1] == b'.')
}

/// 去掉端口、方括号、zone 后解析 IP。
fn parse_ip_loose(v: &str) -> Option<IpAddr> {
    let v = v.trim_matches(|c| c == '[' || c == ']');
    let v = v.split('%').next().unwrap_or(v);
    v.parse::<IpAddr>().ok()
}

fn reserved_or_listed(host: &str, list: &[&str]) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    RESERVED_DOMAINS.iter().chain(list.iter()).any(|d| domain_matches(&h, d))
}

fn builtin_allowed(cat: Category, value: &str, keep_private: bool) -> bool {
    match cat {
        Category::Ipv4 => {
            let Ok(ip) = value.parse::<Ipv4Addr>() else { return false };
            let x = u32::from(ip);
            let hit = |nets: &[([u8; 4], u8)]| {
                nets.iter().any(|&(a, l)| {
                    let (net, mask) = v4_net(a, l);
                    x & mask == net
                })
            };
            hit(BUILTIN_V4) || (keep_private && hit(PRIVATE_V4))
        }
        Category::Ipv6 => {
            let Some(IpAddr::V6(ip)) = parse_ip_loose(value) else { return false };
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                return true;
            }
            if let Some(v4) = ip.to_ipv4_mapped() {
                return builtin_allowed(Category::Ipv4, &v4.to_string(), keep_private);
            }
            keep_private && (ip.segments()[0] & 0xfe00) == 0xfc00
        }
        Category::Mac => {
            let hex: Vec<u8> = value
                .split([':', '-', '.'])
                .flat_map(|p| (0..p.len() / 2).filter_map(move |i| u8::from_str_radix(&p[i * 2..i * 2 + 2], 16).ok()))
                .collect();
            // 只对单个 6 字节 MAC 放行；iptables 的 MAC= 序列（目标+源+类型）总要打码
            if hex.len() != 6 {
                return false;
            }
            hex.iter().all(|&b| b == 0) || hex.iter().all(|&b| b == 0xff) || hex[0] & 1 == 1
        }
        Category::Email => {
            let domain = value.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
            reserved_or_listed(domain, &["openssh.com"])
        }
        Category::Hostname => {
            let h = value.trim_end_matches('.').to_ascii_lowercase();
            h == "localhost" || h.starts_with("localhost.") || reserved_or_listed(&h, PUBLIC_DOMAINS)
        }
        Category::Username => {
            let u = value.trim_matches(|c| c == '\'' || c == '"').to_ascii_lowercase();
            SYSTEM_USERS.contains(&u.as_str()) || u.starts_with("systemd-") || u.starts_with('_')
        }
        Category::Uuid | Category::MachineId => value.bytes().filter(u8::is_ascii_hexdigit).all(|b| b == b'0'),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin() {
        let a = Allowlist::new(&[], false).unwrap();
        assert!(a.allowed(Category::Ipv4, "127.0.0.1"));
        assert!(a.allowed(Category::Ipv4, "8.8.8.8"));
        assert!(!a.allowed(Category::Ipv4, "192.168.1.10"));
        assert!(a.allowed(Category::Ipv6, "::1"));
        assert!(a.allowed(Category::Ipv6, "ff02::1"));
        assert!(!a.allowed(Category::Ipv6, "fe80::1"));
        assert!(a.allowed(Category::Mac, "ff:ff:ff:ff:ff:ff"));
        assert!(a.allowed(Category::Mac, "01:00:5e:00:00:fb"));
        assert!(!a.allowed(Category::Mac, "52:54:00:12:34:56"));
        assert!(a.allowed(Category::Email, "nobody@example.com"));
        assert!(!a.allowed(Category::Email, "alice@acme-corp.internal"));
        assert!(a.allowed(Category::Hostname, "deb.debian.org"));
        assert!(!a.allowed(Category::Hostname, "nas.acme-corp.internal"));
        assert!(a.allowed(Category::Username, "root"));
        assert!(!a.allowed(Category::Username, "alice"));
    }

    #[test]
    fn private_ips() {
        let a = Allowlist::new(&[], true).unwrap();
        assert!(a.allowed(Category::Ipv4, "192.168.1.10"));
        assert!(a.allowed(Category::Ipv4, "10.1.2.3"));
        assert!(!a.allowed(Category::Ipv4, "203.0.113.7"));
        assert!(a.allowed(Category::Ipv6, "fd12:3456::1"));
    }

    #[test]
    fn user_entries() {
        let a = Allowlist::new(
            &["203.0.113.0/24".into(), "*.acme.cn".into(), "build-*".into(), "re:srv[0-9]+".into(), "Bob".into()],
            false,
        )
        .unwrap();
        assert!(a.allowed(Category::Ipv4, "203.0.113.99"));
        assert!(a.allowed(Category::Hostname, "nas.acme.cn"));
        assert!(a.allowed(Category::Hostname, "acme.cn"));
        assert!(!a.allowed(Category::Hostname, "notacme.cn"));
        assert!(a.allowed(Category::Hostname, "build-01"));
        assert!(a.allowed(Category::Hostname, "srv42"));
        assert!(a.allowed(Category::Username, "bob"));
    }
}
