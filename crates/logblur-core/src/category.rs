use serde::{Deserialize, Serialize};

/// Category of sensitive information. Each category has a default secrecy level: the higher the level, the more gets
/// scrubbed.
///
/// | Level | Meaning |
/// |---|---|
/// | 1 | Credentials: passwords, keys, tokens, private keys, connection strings |
/// | 2 | Identity: emails, phone numbers, ID numbers, bank cards, license plates, SSH public keys, coordinates |
/// | 3 | Network and devices: IPs, MACs, hostnames, usernames, UUIDs, serial numbers, SSIDs, URL hosts |
/// | 4 | Paranoid: hardware identifiers, User-Agent, whole URLs, long digit/hex/base64 strings |
/// | 5 | Only when explicitly enabled: timestamps |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    // 1 Credentials
    Password,
    ApiKey,
    Token,
    PrivateKey,
    // 2 Identity
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
    // 3 Network and devices
    Ipv4,
    Ipv6,
    Mac,
    Hostname,
    Username,
    Uuid,
    MachineId,
    Serial,
    WifiSsid,
    // 4 Paranoid
    Url,
    UserAgent,
    HardwareId,
    LongNumber,
    HexString,
    Base64,
    // 5 Only when explicitly enabled
    Timestamp,
    // User-defined
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

    /// Stable machine-readable id (used on the command line, in config files and in reports).
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

    /// Parses a category id, case-insensitively, treating `-` and `_` as equivalent.
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

    /// The secrecy level this category belongs to by default.
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

    /// Tag used by the `tag` mask mode, e.g. `[IPV4]`.
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

    /// Pseudonym prefix, e.g. `IP_k3f9xq2a`.
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

    /// Display name in the UI (in the current language).
    pub fn label(self) -> String {
        crate::i18n::tr(&format!("category.{}", self.id()))
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

/// Hit count for each category.
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
            assert_eq!(c.index(), i, "index of {c:?} does not match its position in ALL");
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
