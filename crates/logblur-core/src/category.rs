use serde::{Deserialize, Serialize};

/// 敏感信息类别。每个类别有一个默认保密等级：等级越高，清洗得越多。
///
/// | 等级 | 含义 |
/// |---|---|
/// | 1 | 凭据：口令、密钥、令牌、私钥、连接串 |
/// | 2 | 身份：邮箱、电话、证件号、银行卡、车牌、SSH 公钥、经纬度 |
/// | 3 | 网络与设备：IP、MAC、主机名、用户名、UUID、序列号、SSID、URL 主机 |
/// | 4 | 偏执：硬件标识、User-Agent、整条 URL、长数字/十六进制/base64 串 |
/// | 5 | 仅显式启用：时间戳 |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    // 1 凭据
    Password,
    ApiKey,
    Token,
    PrivateKey,
    // 2 身份
    Email,
    Phone,
    IdCard,
    Ssn,
    BankCard,
    Iban,
    LicensePlate,
    SshKey,
    GeoCoord,
    Imei,
    // 3 网络与设备
    Ipv4,
    Ipv6,
    Mac,
    Hostname,
    Username,
    Uuid,
    MachineId,
    Serial,
    WifiSsid,
    // 4 偏执
    Url,
    UserAgent,
    HardwareId,
    LongNumber,
    HexString,
    Base64,
    // 5 仅显式启用
    Timestamp,
    // 用户自定义
    Custom,
}

impl Category {
    pub const COUNT: usize = 31;

    pub const ALL: [Category; Category::COUNT] = [
        Category::Password,
        Category::ApiKey,
        Category::Token,
        Category::PrivateKey,
        Category::Email,
        Category::Phone,
        Category::IdCard,
        Category::Ssn,
        Category::BankCard,
        Category::Iban,
        Category::LicensePlate,
        Category::SshKey,
        Category::GeoCoord,
        Category::Imei,
        Category::Ipv4,
        Category::Ipv6,
        Category::Mac,
        Category::Hostname,
        Category::Username,
        Category::Uuid,
        Category::MachineId,
        Category::Serial,
        Category::WifiSsid,
        Category::Url,
        Category::UserAgent,
        Category::HardwareId,
        Category::LongNumber,
        Category::HexString,
        Category::Base64,
        Category::Timestamp,
        Category::Custom,
    ];

    #[inline]
    pub fn index(self) -> usize {
        self as usize
    }

    /// 稳定的机器可读 id（用于命令行、配置文件、报告）。
    pub fn id(self) -> &'static str {
        match self {
            Category::Password => "password",
            Category::ApiKey => "api_key",
            Category::Token => "token",
            Category::PrivateKey => "private_key",
            Category::Email => "email",
            Category::Phone => "phone",
            Category::IdCard => "id_card",
            Category::Ssn => "ssn",
            Category::BankCard => "bank_card",
            Category::Iban => "iban",
            Category::LicensePlate => "license_plate",
            Category::SshKey => "ssh_key",
            Category::GeoCoord => "geo_coord",
            Category::Imei => "imei",
            Category::Ipv4 => "ipv4",
            Category::Ipv6 => "ipv6",
            Category::Mac => "mac",
            Category::Hostname => "hostname",
            Category::Username => "username",
            Category::Uuid => "uuid",
            Category::MachineId => "machine_id",
            Category::Serial => "serial",
            Category::WifiSsid => "wifi_ssid",
            Category::Url => "url",
            Category::UserAgent => "user_agent",
            Category::HardwareId => "hardware_id",
            Category::LongNumber => "long_number",
            Category::HexString => "hex_string",
            Category::Base64 => "base64",
            Category::Timestamp => "timestamp",
            Category::Custom => "custom",
        }
    }

    /// 解析类别 id，大小写不敏感，`-` 与 `_` 等价。
    pub fn from_id(s: &str) -> Option<Category> {
        let norm = s.trim().to_ascii_lowercase().replace('-', "_");
        let alias = match norm.as_str() {
            "ip" => Some(Category::Ipv4),
            "host" => Some(Category::Hostname),
            "user" => Some(Category::Username),
            "card" => Some(Category::BankCard),
            "idcard" | "cn_id" => Some(Category::IdCard),
            "key" | "apikey" => Some(Category::ApiKey),
            "pem" => Some(Category::PrivateKey),
            "ssid" => Some(Category::WifiSsid),
            "hw" | "pci" => Some(Category::HardwareId),
            "date" | "time" | "dates" => Some(Category::Timestamp),
            _ => None,
        };
        alias.or_else(|| Category::ALL.into_iter().find(|c| c.id() == norm))
    }

    /// 类别默认属于哪个保密等级。
    pub fn default_level(self) -> u8 {
        use Category::*;
        match self {
            Password | ApiKey | Token | PrivateKey | Custom => 1,
            Email | Phone | IdCard | Ssn | BankCard | Iban | LicensePlate | SshKey | GeoCoord | Imei => 2,
            Ipv4 | Ipv6 | Mac | Hostname | Username | Uuid | MachineId | Serial | WifiSsid => 3,
            Url | UserAgent | HardwareId | LongNumber | HexString | Base64 => 4,
            Timestamp => 5,
        }
    }

    /// `tag` 打码模式使用的标签，如 `[IPV4]`。
    pub fn tag(self) -> &'static str {
        use Category::*;
        match self {
            Password => "PASSWORD",
            ApiKey => "API_KEY",
            Token => "TOKEN",
            PrivateKey => "PRIVATE_KEY",
            Email => "EMAIL",
            Phone => "PHONE",
            IdCard => "ID_CARD",
            Ssn => "SSN",
            BankCard => "BANK_CARD",
            Iban => "IBAN",
            LicensePlate => "PLATE",
            SshKey => "SSH_KEY",
            GeoCoord => "GEO",
            Imei => "IMEI",
            Ipv4 => "IPV4",
            Ipv6 => "IPV6",
            Mac => "MAC",
            Hostname => "HOST",
            Username => "USER",
            Uuid => "UUID",
            MachineId => "MACHINE_ID",
            Serial => "SERIAL",
            WifiSsid => "SSID",
            Url => "URL",
            UserAgent => "USER_AGENT",
            HardwareId => "HW_ID",
            LongNumber => "NUMBER",
            HexString => "HEX",
            Base64 => "BASE64",
            Timestamp => "TIME",
            Custom => "REDACTED",
        }
    }

    /// 伪名前缀，如 `IP_k3f9xq2a`。
    pub fn pseudo_prefix(self) -> &'static str {
        use Category::*;
        match self {
            Password => "PWD",
            ApiKey => "KEY",
            Token => "TOKEN",
            PrivateKey => "PRIVKEY",
            Email => "EMAIL",
            Phone => "PHONE",
            IdCard => "ID",
            Ssn => "SSN",
            BankCard => "CARD",
            Iban => "IBAN",
            LicensePlate => "PLATE",
            SshKey => "SSHKEY",
            GeoCoord => "GEO",
            Imei => "IMEI",
            Ipv4 => "IP",
            Ipv6 => "IP6",
            Mac => "MAC",
            Hostname => "HOST",
            Username => "USER",
            Uuid => "UUID",
            MachineId => "MID",
            Serial => "SN",
            WifiSsid => "SSID",
            Url => "URL",
            UserAgent => "UA",
            HardwareId => "HW",
            LongNumber => "NUM",
            HexString => "HEX",
            Base64 => "B64",
            Timestamp => "TIME",
            Custom => "X",
        }
    }

    /// 界面上显示的名称（按当前语言）。
    pub fn label(self) -> String {
        crate::i18n::tr(&format!("category.{}", self.id()))
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

/// 每个类别的命中计数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts(pub [u64; Category::COUNT]);

impl Default for Counts {
    fn default() -> Self {
        Counts([0; Category::COUNT])
    }
}

impl Serialize for Counts {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_map(self.iter().map(|(c, n)| (c.id(), n)))
    }
}

impl Counts {
    #[inline]
    pub fn add(&mut self, c: Category, n: u64) {
        self.0[c.index()] += n;
    }

    pub fn merge(&mut self, other: &Counts) {
        for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
            *a += *b;
        }
    }

    pub fn total(&self) -> u64 {
        self.0.iter().sum()
    }

    pub fn iter(&self) -> impl Iterator<Item = (Category, u64)> + '_ {
        Category::ALL.into_iter().zip(self.0.iter().copied()).filter(|(_, n)| *n > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_is_complete_and_indexed() {
        for (i, c) in Category::ALL.iter().enumerate() {
            assert_eq!(c.index(), i, "{c:?} 的序号与 ALL 中的位置不一致");
            assert_eq!(Category::from_id(c.id()), Some(*c));
        }
    }

    #[test]
    fn aliases() {
        assert_eq!(Category::from_id("IP"), Some(Category::Ipv4));
        assert_eq!(Category::from_id("bank-card"), Some(Category::BankCard));
        assert_eq!(Category::from_id("nope"), None);
    }
}
