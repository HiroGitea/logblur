//! Built-in rule table (the single source of truth). Order is priority: on overlap the earlier rule decides the
//! category tag.
//!
//! Conventions:
//! - Single-line rules must not match newlines (no bare `\s` across lines, no `(?s)`); the only multi-line rule is
//!   PEM private keys.
//! - All rules are compiled in multi-line + CRLF mode, so `^` means start of line.
//! - Digits are written `[0-9]` rather than `\d` (the latter includes digits of other scripts in Unicode mode).
//! - Leading context is written as a non-capturing group and the trailing boundary is left to the `after` check, so
//!   separators are not consumed.

use super::validators as v;
use super::{Cand, Rule};
use crate::category::Category as C;

/// Common default hostnames: learning them is pointless and would also hit ordinary text (e.g. "debian").
pub const GENERIC_HOSTNAMES: &[&str] = &[
    "localhost",
    "debian",
    "ubuntu",
    "raspberrypi",
    "fedora",
    "archlinux",
    "arch",
    "kali",
    "centos",
    "rocky",
    "almalinux",
    "opensuse",
    "linux",
    "server",
    "host",
    "node",
    "master",
    "worker",
    "desktop",
    "laptop",
    "pc",
    "computer",
    "router",
    "gateway",
    "default",
    "home",
    "none",
    "unknown",
    "client",
    "kernel",
    "systemd",
    "android",
    "localdomain",
    "local",
    "box",
    "vm",
    "container",
    "docker",
    "ip",
    "web",
    "db",
    "app",
    "api",
];

fn url_host(c: &Cand) -> bool {
    let h = c.payload.trim_end_matches('.');
    !h.is_empty()
        && !h.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && !h.eq_ignore_ascii_case("localhost")
        && h.bytes().any(|b| b.is_ascii_alphabetic())
}

fn not_abs_path_and_entropy(c: &Cand) -> bool {
    !c.payload.starts_with('/') && v::high_entropy(c)
}

fn cli_value(c: &Cand) -> bool {
    !c.payload.starts_with('-') && v::secret_value(c)
}

/// All built-in rules.
pub fn builtin() -> Vec<Rule> {
    vec![
        // ───────────────────────── 1 Credentials ─────────────────────────
        Rule::new(
            "pem_private_key",
            C::PrivateKey,
            1,
            "PEM / OpenSSH / PGP private key blocks (multi-line; BEGIN/END lines are kept)",
            r"(?s)-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY(?: BLOCK)?-----(.*?)-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
        )
        .group(2),
        Rule::new(
            "vendor_api_key",
            C::ApiKey,
            1,
            "Cloud and platform keys: AWS, GitHub, GitLab, Slack, Google, Stripe, OpenAI, Anthropic, npm, PyPI, Docker Hub, Hugging Face, SendGrid, Telegram, Alibaba Cloud, Tencent Cloud and more",
            concat!(
                r"(?:^|[^A-Za-z0-9_])(",
                r"(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}",
                r"|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}",
                r"|gl(?:pat|ptt|rt|dt|cbt|oas|soat|ft|imt)-[A-Za-z0-9_\-]{20,}",
                r"|xox[abposr]-[A-Za-z0-9\-]{10,}",
                r"|AIza[0-9A-Za-z_\-]{35}|ya29\.[0-9A-Za-z_\-]{20,}|GOCSPX-[0-9A-Za-z_\-]{20,}",
                r"|(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}|whsec_[0-9A-Za-z]{24,}",
                r"|sk-ant-[A-Za-z0-9_\-]{20,}|sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}",
                r"|npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_\-]{50,}|dckr_pat_[A-Za-z0-9_\-]{20,}|hf_[A-Za-z0-9]{30,}",
                r"|SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}|[0-9]{8,10}:AA[0-9A-Za-z_\-]{33}",
                r"|shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}|AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}",
                r"|tskey-[a-z]+-[A-Za-z0-9]{8,}-[A-Za-z0-9]{8,}|do[opr]_v1_[a-f0-9]{64}|hv[sbr]\.[A-Za-z0-9_\-]{24,}",
                r"|LTAI[A-Za-z0-9]{12,20}|AKID[A-Za-z0-9]{13,40}",
                r")"
            ),
        )
        .after(v::after_not_alnum),
        Rule::new(
            "jwt",
            C::Token,
            1,
            "JSON Web Tokens (eyJ….eyJ….signature)",
            r"(?:^|[^A-Za-z0-9_\-])(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*)",
        ),
        Rule::new(
            "authorization_header",
            C::Token,
            1,
            "HTTP Authorization / Proxy-Authorization headers",
            r"(?i)(?:^|[^A-Za-z0-9])(?:authorization|proxy-authorization)[\x22']?[ \t]*[:=][ \t]*[\x22']?(?:(?:bearer|basic|token|digest|negotiate|ntlm|apikey|key)[ \t]+)?([A-Za-z0-9\-._~+/=:]{8,})",
        )
        .check(v::token_value),
        Rule::new(
            "bearer_token",
            C::Token,
            1,
            "Bearer tokens",
            r"(?i)(?:^|[^A-Za-z0-9])bearer[ \t]+([A-Za-z0-9\-._~+/]{8,}=*)",
        )
        .check(v::token_value),
        Rule::new(
            "cookie_header",
            C::Token,
            1,
            "Values of Cookie / Set-Cookie headers",
            r"(?i)(?:^|[^A-Za-z0-9\-])(?:set-)?cookie[\x22']?[ \t]*:[ \t]*[\x22']?([^\r\n\x22']+)",
        )
        .check(v::token_value),
        Rule::new(
            "session_cookie",
            C::Token,
            1,
            "Session cookies and CSRF tokens: JSESSIONID=…, PHPSESSID=…, csrftoken=…",
            r"(?i)(?:^|[^A-Za-z0-9_])(?:jsessionid|phpsessid|asp\.net_sessionid|connect\.sid|sessionid|session_id|session-id|sid|csrftoken|csrf_token|csrf-token|xsrf-token|_csrf|_session|laravel_session|ci_session)[\x22']?[ \t]*[=:][ \t]*[\x22']?([^\s;&\x22',]{6,})",
        )
        .check(v::token_value),
        Rule::new(
            "kv_secret",
            C::Password,
            1,
            "Passwords and keys in key=value pairs: password=…, \"api_key\": \"…\", secret: …, psk=…",
            concat!(
                r"(?i)(?:^|[^A-Za-z0-9])(?:",
                r"pass(?:word|wd|phrase)?|pwd|passwd|userpassword|psk|wpa_passphrase|wep_key[0-3]?|pin_?code",
                r"|secret|client[_\-]?secret|app[_\-]?secret|secret[_\-]?(?:access[_\-]?)?key|shared[_\-]?secret",
                r"|api[_\-]?key|apikey|api[_\-]?token|access[_\-]?key(?:[_\-]?id)?|private[_\-]?key|signing[_\-]?key|encryption[_\-]?key|master[_\-]?key",
                r"|auth[_\-]?token|access[_\-]?token|refresh[_\-]?token|id[_\-]?token|bearer[_\-]?token|session[_\-]?(?:token|key|secret)|token",
                r"|credentials?|conn(?:ection)?[_\-]?string|dsn|accountkey",
                r"|密码|口令|密钥|秘钥|令牌)",
                r"[\x22']?[ \t]*(?:=>|:=|[:=：])[ \t]*",
                r"(?:\x22([^\x22\r\n]*)\x22|'([^'\r\n]*)'|([^\s\x22',;&<>]+))"
            ),
        )
        .first_group()
        .check(v::secret_value),
        Rule::new(
            "xml_secret",
            C::Password,
            1,
            "Passwords in XML elements: <password>…</password>",
            r"(?i)<(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|client[_\-]?secret|private[_\-]?key)>([^<\r\n]+)</",
        )
        .check(v::secret_value),
        Rule::new(
            "cli_secret",
            C::Password,
            1,
            "Passwords in command-line options: --password xxx, --token=xxx",
            r"(?i)(?:^|[ \t\x22'])--?(?:password|passwd|pass|pwd|token|secret|api-key|apikey|access-key|secret-key|auth-token|client-secret)(?:[ \t]+|=)[\x22']?([^\s\x22']+)",
        )
        .check(cli_value),
        Rule::new(
            "mysql_p",
            C::Password,
            1,
            "Password given to the mysql client as -pPASSWORD",
            r"(?:^|[ \t/])(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlshow|mysqlcheck|mariadb)[ \t][^\r\n]*?[ \t]-p([^\s\x22';\-][^\s\x22';]*)",
        )
        .check(v::secret_value),
        Rule::new(
            "uri_password",
            C::Password,
            1,
            "Passwords in URIs: scheme://user:password@host",
            r"(?i)(?:^|[^A-Za-z0-9+.\-])[a-z][a-z0-9+.\-]{1,20}://([^\s:/@\x22'<>]+):([^\s@\x22'<>/]*)@",
        )
        .group(2)
        .check(v::secret_value),
        Rule::new(
            "url_query_secret",
            C::Token,
            1,
            "Tokens and signatures in URL query strings: ?token=…&sig=…",
            r"(?i)[?&;](?:access_token|refresh_token|id_token|auth_token|token|auth|api_?key|apikey|key|secret|client_secret|password|passwd|pwd|sig|signature|x-amz-signature|x-amz-credential|x-amz-security-token|x-goog-signature|x-goog-credential|code|session|sessionid|sid|jwt|ticket|access_key|secret_key)=([^&#\s\x22'<>]+)",
        )
        .check(v::not_placeholder),
        Rule::new(
            "azure_conn",
            C::Password,
            1,
            "AccountKey / SharedAccessKey in Azure and ADO connection strings",
            r"(?i)(?:AccountKey|SharedAccessKey|SharedAccessSignature)=([^;\s\x22']+)",
        ),
        // ───────────────────────── 2 Identity ─────────────────────────
        Rule::new(
            "email",
            C::Email,
            2,
            "E-mail addresses (not systemd unit names such as user@1000.service)",
            r"(?:^|[^A-Za-z0-9._%+\-])([A-Za-z0-9][A-Za-z0-9._%+\-]*@[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,24})",
        )
        .after(v::after_email)
        .check(v::email),
        Rule::new(
            "phone_cn",
            C::Phone,
            2,
            "Mainland China mobile numbers (optional +86, spaces or dashes)",
            r"(?:^|[^0-9A-Za-z_+])((?:\+?86[ \-]?)?1[3-9][0-9][ \-]?[0-9]{4}[ \-]?[0-9]{4})",
        )
        .after(v::after_number)
        .check(v::phone_cn)
        .protect(),
        Rule::new(
            "phone_intl",
            C::Phone,
            2,
            "International phone numbers: +1 415 555 0100, +44 20 7946 0958",
            r"(?:^|[^0-9A-Za-z_+])(\+[1-9][0-9]{0,2}[ \-.]?(?:\([0-9]{1,4}\)[ \-.]?)?[0-9]{1,4}(?:[ \-.]?[0-9]{2,4}){2,4})",
        )
        .after(v::after_number)
        .check(v::phone_intl),
        Rule::new(
            "phone_kw",
            C::Phone,
            2,
            "Phone numbers after a keyword: tel: …, mobile=…",
            r"(?i)(?:^|[^A-Za-z0-9])(?:tel|telephone|phone(?:[_ ]?(?:no|num|number))?|mobile|cell(?:phone)?|fax|msisdn|手机(?:号码?)?|电话(?:号码)?|联系电话|联系方式)[\x22']?[ \t]*[:=：]?[ \t]*[\x22']?(\+?[0-9][0-9 ()\-]{5,20}[0-9])",
        )
        .after(v::after_number)
        .check(v::phone_kw),
        Rule::new(
            "cn_id_card",
            C::IdCard,
            2,
            "Chinese resident ID numbers (18 digits, checksum verified)",
            r"(?:^|[^0-9A-Za-z])([1-9][0-9]{5}(?:18|19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9Xx])",
        )
        .after(v::after_not_alnum)
        .check(v::cn_id),
        Rule::new(
            "us_ssn",
            C::Ssn,
            2,
            "US Social Security numbers 123-45-6789",
            r"(?:^|[^0-9A-Za-z\-])([0-9]{3}-[0-9]{2}-[0-9]{4})",
        )
        .after(v::after_number)
        .check(v::ssn),
        Rule::new(
            "bank_card",
            C::BankCard,
            2,
            "Payment card numbers (13–19 digits, Luhn checked)",
            r"(?:^|[^0-9A-Za-z.\-_])([2-6][0-9](?:[ \-]?[0-9]){11,17})",
        )
        .after(v::after_number)
        .check(v::bank_card)
        .protect(),
        Rule::new(
            "account_kw",
            C::BankCard,
            2,
            "Card / account numbers after a keyword: card no: … (no Luhn check)",
            r"(?i)(?:^|[^A-Za-z0-9])(?:card[_ \-]?(?:no|num|number)|cardno|credit[_ ]?card|debit[_ ]?card|pan|acct[_ \-]?(?:no|num)|account[_ \-]?(?:no|num|number)|bank[_ ]?account|卡号|银行卡号?|账号|帐号|账户|帐户)[\x22']?[ \t]*[:=：#]?[ \t]*[\x22']?([0-9][0-9 \-]{10,24}[0-9])",
        )
        .after(v::after_number)
        .check(v::account_number),
        Rule::new(
            "iban",
            C::Iban,
            2,
            "IBAN bank account numbers (mod-97 checked)",
            r"(?:^|[^A-Za-z0-9])([A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?)",
        )
        .after(v::after_not_alnum)
        .check(v::iban),
        Rule::new(
            "cn_plate",
            C::LicensePlate,
            2,
            "Chinese licence plates",
            r"(?:^|[^\p{Han}A-Za-z0-9])([京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-HJ-NP-Z][·・ ]?[A-HJ-NP-Z0-9]{4,5}[A-HJ-NP-Z0-9挂学警港澳])",
        )
        .after(v::after_not_alnum),
        Rule::new(
            "ssh_pubkey",
            C::SshKey,
            2,
            "SSH public keys (only the base64 part is masked)",
            r"(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp(?:256|384|521)|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)[ \t]+(AAAA[0-9A-Za-z+/]{16,}={0,3})",
        ),
        Rule::new(
            "ssh_fingerprint",
            C::SshKey,
            2,
            "SSH key fingerprints SHA256:… / MD5:… (common in sshd logs)",
            r"(?:^|[^A-Za-z0-9])(?:SHA256:([A-Za-z0-9+/]{43})|MD5:((?:[0-9a-f]{2}:){15}[0-9a-f]{2}))",
        )
        .first_group(),
        Rule::new(
            "geo_pair",
            C::GeoCoord,
            2,
            "Latitude / longitude pairs 39.9042, 116.4074",
            r"(?:^|[^0-9.\-A-Za-z])(-?[0-9]{1,2}\.[0-9]{4,}[ \t]*,[ \t]*-?[0-9]{1,3}\.[0-9]{4,})",
        )
        .after(v::after_number)
        .check(v::geo_pair),
        Rule::new(
            "geo_kw",
            C::GeoCoord,
            2,
            "Latitude / longitude after a keyword: lat=…, lng: …",
            r"(?i)(?:^|[^A-Za-z0-9])(?:lat|latitude|lng|lon|long|longitude|纬度|经度)[\x22']?(?:[ \t]*[:：][ \t]*|[ \t]+=[ \t]+|=)[\x22']?(-?[0-9]{1,3}\.[0-9]{3,})",
        )
        .after(v::after_number)
        .check(v::geo_single),
        Rule::new(
            "imei_kw",
            C::Imei,
            2,
            "IMEI / IMSI / MEID / ICCID after a keyword",
            r"(?i)(?:^|[^A-Za-z0-9])(?:imei|imeisv|meid|imsi|iccid)[\x22']?[ \t]*[:=：#]?[ \t]*[\x22']?([0-9A-Fa-f]{14,22})",
        )
        .after(v::after_not_alnum),
        // ───────────────────────── 3 Network and devices ─────────────────────────
        Rule::new(
            "ipv4",
            C::Ipv4,
            3,
            "IPv4 addresses (except loopback, broadcast, multicast, public DNS and version numbers)",
            r"(?:^|[^0-9A-Za-z.])((?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})",
        )
        .after(v::after_ipv4)
        .check(v::ipv4)
        .protect(),
        Rule::new(
            "ipv6",
            C::Ipv6,
            3,
            "IPv6 addresses (link-local fe80:: included; ::1 and multicast excluded)",
            r"(?:^|[^0-9A-Za-z:.])((?:[0-9A-Fa-f]{1,4})?(?::[0-9A-Fa-f]{0,4}){2,7}(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3})?(?:%[0-9A-Za-z_.\-]+)?)",
        )
        .after(v::after_ipv6)
        .check(v::ipv6),
        Rule::new(
            "mac",
            C::Mac,
            3,
            "MAC addresses aa:bb:cc:dd:ee:ff / aa-bb-… / aabb.ccdd.eeff",
            r"(?:^|[^0-9A-Za-z:\-.])((?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})",
        )
        .after(v::after_mac)
        .check(v::mac),
        Rule::new(
            "iptables_mac",
            C::Mac,
            3,
            "MAC= field of iptables / nftables logs (destination + source MAC + type)",
            r"MAC=((?:[0-9a-fA-F]{2}:){5,}[0-9a-fA-F]{2})",
        ),
        Rule::new(
            "syslog_host",
            C::Hostname,
            3,
            "Host name at the start of syslog / journalctl lines (RFC 3164 and ISO time formats)",
            r"^(?:<[0-9]{1,3}>)?(?:[A-Z][a-z]{2}[ \t]+[0-9]{1,2}[ \t]+[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?|[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.,][0-9]+)?(?:Z|[+\-][0-9]{2}:?[0-9]{2})?)[ \t]+([A-Za-z0-9][A-Za-z0-9._\-]*)[ \t]+[^ \t\r\n:\[]+(?:\[[0-9]+\])?:",
        )
        .learn(),
        Rule::new(
            "syslog5424_host",
            C::Hostname,
            3,
            "Host name field of RFC 5424 syslog",
            r"^<[0-9]{1,3}>[0-9]{1,2}[ \t]+[0-9T:.+\-Z]+[ \t]+([A-Za-z0-9][A-Za-z0-9._\-]*)[ \t]",
        )
        .learn(),
        Rule::new(
            "hostname_kv",
            C::Hostname,
            3,
            "Host names in key=value pairs: hostname=…, _HOSTNAME=…, rhost=…, \"host\": \"…\"",
            r"(?i)(?:^|[^A-Za-z0-9])_?(?:host[_\-]?name|r?host|nodename|node[_\-]?name|computer[_\-]?name|machine[_\-]?name|fqdn|server[_\-]?name|主机名)[\x22']?(?:[ \t]*[:：][ \t]*|[ \t]+=[ \t]+|=)[\x22']?([A-Za-z0-9][A-Za-z0-9._\-]*)",
        )
        .check(url_host)
        .learn(),
        Rule::new(
            "hostname_change",
            C::Hostname,
            3,
            "systemd / hostnamed: Set hostname to <…>, Changed host name to '…'",
            r"(?i)(?:host ?name|hostname) to [<'\x22‘“]?([A-Za-z0-9][A-Za-z0-9._\-]*)",
        )
        .learn(),
        Rule::new(
            "kernel_banner",
            C::Hostname,
            3,
            "user@buildhost in the kernel boot banner",
            r"Linux version [^ \t]+ \(([^ \t)@]+@[^ \t)]+)\)",
        ),
        Rule::new(
            "url_host",
            C::Hostname,
            3,
            "Host names in URLs (public infrastructure domains excluded)",
            r"(?i)(?:^|[^A-Za-z0-9+.\-])(?:https?|ftps?|sftp|wss?|smb|cifs|nfs|rtsp|rtmp|git|ssh|svn|ldaps?|mqtt|amqps?|rediss?|mongodb(?:\+srv)?|postgres(?:ql)?|mysql|jdbc:[a-z0-9]+)://(?:[^\s/@\x22'<>]*@)?([A-Za-z0-9][A-Za-z0-9.\-_]*)",
        )
        .check(url_host),
        Rule::new(
            "hostname_fqdn",
            C::Hostname,
            3,
            "Fully qualified domain names (common TLDs plus .local/.lan/.internal; public infrastructure domains and file names excluded)",
            concat!(
                r"(?i)(?:^|[^A-Za-z0-9_\-.@/\\])((?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+(?:",
                r"com|net|org|edu|gov|mil|int|info|biz|name|pro|mobi|cn|hk|tw|mo|jp|kr|sg|my|th|vn|id|ph|au|nz|uk|de|fr",
                r"|nl|be|lu|ch|at|se|no|dk|fi|ie|es|pt|pl|cz|sk|hu|ro|bg|gr|tr|ru|ua|by|kz|il|ae|sa|eg|za|ng|ke|br|ar",
                r"|cl|mx|ca|us|eu|asia|io|ai|cloud|xyz|top|online|site|tech|store|shop|dev|page|blog|wiki|club|vip",
                r"|ltd|group|work|space|live|news|fun|today|world|email|website|systems|solutions|services|company",
                r"|center|digital|global|zone|one|lan|local|internal|intranet|corp|home|private|localnet|arpa",
                // The word boundary makes the regex engine keep trying longer TLDs on prefix clashes
                // such as int/internal, de/dev and cl/cloud
                r"))(?-u:\b)"
            ),
        )
        .after(v::after_host)
        .check(v::hostname),
        Rule::new(
            "ip_dashed_host",
            C::Hostname,
            3,
            "Cloud host names embedding an IP: ip-10-0-0-1",
            r"(?:^|[^A-Za-z0-9])(ip-(?:[0-9]{1,3}-){3}[0-9]{1,3})",
        )
        .after(v::after_not_alnum),
        Rule::new(
            "ssh_login_user",
            C::Username,
            3,
            "Users who logged in through sshd: Accepted publickey for alice from …",
            r"(?i)(?:accepted|postponed) [a-z\-/]+ for ([^ \t\r\n]+) from",
        )
        .check(v::username)
        .learn(),
        Rule::new(
            "session_user",
            C::Username,
            3,
            "PAM sessions: session opened for user alice",
            r"(?i)session (?:opened|closed) for user ([^ \t\r\n(]+)",
        )
        .check(v::username)
        .learn(),
        Rule::new(
            "by_uid_user",
            C::Username,
            3,
            "PAM / su: by alice(uid=1000)",
            r"(?:^|[ \t])by ([A-Za-z_][A-Za-z0-9_.\-]*)\(uid=[0-9]+\)",
        )
        .check(v::username)
        .learn(),
        Rule::new(
            "sudo_user",
            C::Username,
            3,
            "Caller in sudo logs: sudo:    alice : TTY=…",
            r"sudo(?:\[[0-9]+\])?:[ \t]+([A-Za-z_][A-Za-z0-9_.\-]*)[ \t]*:",
        )
        .check(v::username)
        .learn(),
        Rule::new(
            "logind_user",
            C::Username,
            3,
            "systemd-logind: New session 3 of user alice",
            r"(?i)session [^ \t]+ of user ([A-Za-z_][A-Za-z0-9_.\-]*)",
        )
        .check(v::username)
        .learn(),
        Rule::new(
            "login_on_user",
            C::Username,
            3,
            "login: LOGIN ON tty1 BY alice",
            r"LOGIN ON [^ \t]+ BY ([A-Za-z_][A-Za-z0-9_.\-]*)",
        )
        .check(v::username)
        .learn(),
        Rule::new(
            "failed_login_user",
            C::Username,
            3,
            "login: FAILED LOGIN (1) on '/dev/tty1' FOR 'alice'",
            r"FAILED LOGIN[^\r\n]*? FOR '?([^ \t',\r\n]+)",
        )
        .check(v::username),
        Rule::new(
            "cron_user",
            C::Username,
            3,
            "cron: CRON[123]: (alice) CMD …",
            r"CRON\[[0-9]+\]: \(([^)\r\n]+)\)",
        )
        .check(v::username)
        .learn(),
        Rule::new(
            "account_change",
            C::Username,
            3,
            "Account changes: new user: name=alice, password changed for alice",
            r"(?i)(?:(?:new|delete|add|remove|change|lock|unlock) user: name=|(?:password|shadow) (?:changed|updated|change) for )'?([A-Za-z_][A-Za-z0-9_.\-]*)",
        )
        .check(v::username)
        .learn(),
        Rule::new(
            "su_user",
            C::Username,
            3,
            "su: (to root) alice on pts/0",
            r"\(to [^)\r\n]+\) ([A-Za-z_][A-Za-z0-9_.\-]*) on ",
        )
        .check(v::username)
        .learn(),
        Rule::new(
            "audit_acct",
            C::Username,
            3,
            "auditd: acct=\"alice\"",
            r"(?:^|[ \t])acct=\x22?([^\x22\s]+)",
        )
        .check(v::username)
        .learn(),
        Rule::new(
            "ssh_attempt_user",
            C::Username,
            3,
            "Failed / invalid sshd users (may be a mistyped password, so never learned)",
            r"(?i)(?:failed [a-z\-/]+ for (?:invalid user |illegal user )?|(?:invalid|illegal|authenticating) user |user unknown for |input_userauth_request: invalid user )([^ \t\r\n]+)",
        )
        .check(v::username),
        Rule::new(
            "user_kv",
            C::Username,
            3,
            "User names in key=value pairs: user=…, USER=…, \"username\": \"…\"",
            r"(?i)(?:^|[^A-Za-z0-9])(?:user(?:name)?|usr|login_?name|logname|ruser|suser|sudo_user|account_?name|owner|uname|principal|用户名?|账号|帐号)[\x22']?(?:[ \t]*[:：][ \t]*|[ \t]+=[ \t]+|=)[\x22']?([A-Za-z0-9_][A-Za-z0-9_.@\-$]*)",
        )
        .check(v::username),
        Rule::new(
            "uri_user",
            C::Username,
            3,
            "User names in URIs: scheme://user:pass@host",
            r"(?i)(?:^|[^A-Za-z0-9+.\-])[a-z][a-z0-9+.\-]{1,20}://([^\s:/@\x22'<>]+)(?::[^\s@\x22'<>/]*)?@",
        )
        .check(v::username),
        Rule::new(
            "home_path",
            C::Username,
            3,
            "User names in home paths: /home/alice, /Users/alice, C:\\Users\\alice, ~alice/",
            r"(?:(?:^|[^A-Za-z0-9_.\-])(?:/home|/var/home|/Users|/export/home|/usr/home|/data/home)/([A-Za-z0-9_][A-Za-z0-9_.@\-]*)|(?i:[A-Z]):\\(?:Users|Documents and Settings)\\([^\\/\s\x22':*?<>|]+)|(?:^|[ \t\x22'=:(])~([a-z_][a-z0-9_\-]*)/)",
        )
        .first_group()
        .check(v::username)
        .learn(),
        Rule::new(
            "uuid",
            C::Uuid,
            3,
            "UUIDs / GUIDs (disks, partitions, boot IDs and more)",
            r"(?:^|[^0-9A-Za-z\-])([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
        )
        .after(v::after_not_alnum)
        .check(v::uuid),
        Rule::new(
            "machine_id",
            C::MachineId,
            3,
            "machine-id / boot-id / device IDs: _MACHINE_ID=…, machine-id: …, android_id=…",
            r"(?i)(?:^|[^A-Za-z0-9])_?(?:machine[_\-]?id|boot[_\-]?id|invocation[_\-]?id|product[_\-]?uuid|system[_\-]?uuid|hardware[_\-]?uuid|dmi[_\-]?uuid|device[_\-]?id|android[_\-]?id|advertising[_\-]?id|idfa|idfv|instance[_\-]?id)[\x22']?(?:[ \t]*[:：][ \t]*|[ \t]+=[ \t]+|=)[\x22']?([0-9A-Za-z][0-9A-Za-z\-]{7,63})",
        )
        .check(v::not_placeholder)
        .learn(),
        Rule::new(
            "journal_dir_id",
            C::MachineId,
            3,
            "machine-id in journald paths: /var/log/journal/<32 hex digits>/",
            r"(?:/var/log/journal|/run/log/journal)/([0-9a-f]{32})",
        )
        .learn(),
        Rule::new(
            "serial",
            C::Serial,
            3,
            "Device serial numbers: SerialNumber: …, ID_SERIAL=…, Serial Number: …",
            r"(?i)(?:^|[^A-Za-z0-9])(?:serial(?:[ _\-]?(?:number|no|num))?|serialnumber|s/n|sn|id_serial(?:_short)?|iserial|serial_no|chassis[ _]serial|board[ _]serial|product[ _]serial|system[ _]serial(?:[ _]number)?|wwn|wwid)[\x22']?(?:[ \t]*[:：#][ \t]*|[ \t]+=[ \t]+|=)[\x22']?([A-Za-z0-9][A-Za-z0-9_.:\-]{3,})",
        )
        .check(v::serial),
        Rule::new(
            "wifi_ssid",
            C::WifiSsid,
            3,
            "Wi-Fi names: SSID 'Home', access point 'Home', connection 'Home', network \"Home\"",
            r"(?i)(?:^|[^A-Za-z0-9])(?:e?ssid|access point|network(?: name)?|connection(?: id)?|wifi[_ ]?name)[\x22']?[ \t]*[:=]?[ \t]*(?:\x22([^\x22\r\n]+)\x22|'([^'\r\n]+)'|‘([^’\r\n]+)’|“([^”\r\n]+)”)",
        )
        .first_group()
        .check(v::ssid),
        Rule::new(
            "wifi_ssid_kv",
            C::WifiSsid,
            3,
            "ssid=Home (unquoted)",
            r"(?i)(?:^|[^A-Za-z0-9])e?ssid(?:[ \t]*[:：][ \t]*|[ \t]+=[ \t]+|=)([^\s\x22',;]+)",
        )
        .check(v::ssid),
        // ───────────────────────── 4 Paranoid ─────────────────────────
        Rule::new(
            "url_full",
            C::Url,
            4,
            "Whole URLs (browsing history, download links and more)",
            r"(?i)(?:^|[^A-Za-z0-9+.\-])((?:https?|ftps?|sftp|wss?|smb|nfs|file|rtsp|rtmp|git|ssh|svn)://[^\s\x22'<>]+)",
        ),
        Rule::new(
            "hostname_any",
            C::Hostname,
            4,
            "Host names with any TLD (paranoid; file names excluded)",
            r"(?i)(?:^|[^A-Za-z0-9_\-.@/\\])((?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z][a-z0-9\-]{1,23})",
        )
        .after(v::after_host)
        .check(v::hostname),
        Rule::new(
            "user_agent",
            C::UserAgent,
            4,
            "User-Agent strings",
            r"(?i)(?:user-agent[\x22']?[ \t]*[:=][ \t]*[\x22']?([^\x22\r\n]+)|\x22((?:Mozilla|curl|Wget|python-requests|python-urllib|Go-http-client|okhttp|Dalvik|Apache-HttpClient|PostmanRuntime|axios|node-fetch|Java)/[^\x22\r\n]*)\x22)",
        )
        .first_group(),
        Rule::new(
            "pci_address",
            C::HardwareId,
            4,
            "PCI bus addresses 0000:00:1f.6 (not personal; paranoid level only)",
            r"(?:^|[^0-9A-Za-z:])((?:[0-9a-f]{4}:)?[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])",
        )
        .after(v::after_not_alnum),
        Rule::new(
            "usb_pci_ids",
            C::HardwareId,
            4,
            "USB / PCI vendor and product IDs: idVendor=046d, [8086:9a49]",
            r"(?i)(?:id(?:Vendor|Product)=([0-9a-f]{4})|\[([0-9a-f]{4}:[0-9a-f]{4})\])",
        )
        .first_group(),
        Rule::new(
            "dmi_info",
            C::HardwareId,
            4,
            "DMI / board / model information: DMI: …, Hardware name: …, Product Name: …",
            r"(?i)(?:DMI|Hardware name|Product Name|Manufacturer|Board Name|System Manufacturer|Model name|Machine model)[ \t]*:[ \t]*([^\r\n]+)",
        )
        .check(v::hardware),
        Rule::new(
            "long_number",
            C::LongNumber,
            4,
            "Numbers with 9 or more digits (timestamps excluded)",
            r"(?:^|[^0-9A-Za-z._\-])([0-9]{9,})",
        )
        .after(v::after_number)
        .protect(),
        Rule::new(
            "hex_string",
            C::HexString,
            4,
            "Hex strings of 16+ characters (hashes, IDs, git commits and more)",
            r"(?:^|[^0-9A-Za-z_\-])([0-9a-fA-F]{16,})",
        )
        .after(v::after_not_word)
        .check(v::hex_mixed)
        .protect(),
        Rule::new(
            "base64_blob",
            C::Base64,
            4,
            "High-entropy base64 / random strings (24+ characters)",
            r"(?:^|[^A-Za-z0-9+/=_\-])([A-Za-z0-9+/_\-]{24,}={0,2})",
        )
        .after(v::after_not_word)
        .check(not_abs_path_and_entropy)
        .protect(),
        // ───────────────────────── 5 Only when explicitly enabled ─────────────────────────
        Rule::new(
            "ts_iso",
            C::Timestamp,
            5,
            "ISO 8601 times",
            r"(?:^|[^0-9])([0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.,][0-9]{1,9})?(?:Z|[+\-][0-9]{2}:?[0-9]{2})?)",
        ),
        Rule::new(
            "ts_syslog",
            C::Timestamp,
            5,
            "syslog times Oct 23 11:12:13",
            r"((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[ \t]+[0-9]{1,2}[ \t]+[0-9]{2}:[0-9]{2}:[0-9]{2})",
        ),
        Rule::new(
            "ts_date",
            C::Timestamp,
            5,
            "Dates 2026-10-23 / 2026/10/23",
            r"(?:^|[^0-9])([0-9]{4}[\-/][0-9]{2}[\-/][0-9]{2})",
        )
        .after(v::after_number),
        Rule::new("ts_epoch", C::Timestamp, 5, "Unix timestamps", r"(?:^|[^0-9])(1[5-9][0-9]{8}(?:[0-9]{3})?)")
            .after(v::after_number),
    ]
}
