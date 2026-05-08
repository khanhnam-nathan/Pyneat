//! Hackingtool-Inspired Security Rules for PyNEAT
//!
//! Copyright (C) 2026 PyNEAT Authors
//!
//! Detects patterns from offensive security tools: phishing, rogue AP,
//! backdoors, C2, surveillance, credential attacks, MITM.

use crate::rules::base::{extract_snippet, Fix, Finding, Rule, Severity};
use once_cell::sync::Lazy;
use regex::Regex;
use tree_sitter::Tree;

static SEC118_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"SocialFish\.py.*(?:'|")[root|admin|user](?:'|").*(?:'|")[pass|password](?:'|")"##, "Hardcoded credentials in social engineering tool"),
    (r##"(?i)(?:maskphish|maskurl|hide.*url|url.*mask)"##, "URL masking/hiding tool"),
    (r##"(?i)(?:otp\s*phishing|phishing.*otp|otp.*bypass)"##, "OTP phishing pattern"),
    (r##"(?i)(?:login\.html.*password|index\.html.*credential|post\.php.*username)"##, "Landing page with credential harvesting"),
    (r##"(?i)(?:evilginx|evil\.ginx|phishing.*proxy|credential.*proxy)"##, "Phishing proxy / MITM credential capture"),
    (r##"(?i)(?:HiddenEye|hidden.*eye.*phish)"##, "HiddenEye phishing tool"),
    (r##"(?i)(?:blackeye|black.*eye.*phish)"##, "BlackEye phishing toolkit"),
    (r##"header\s*\(\s*['"]Location:\s*['"].*post"##, "Phishing redirect pattern"),
    (r##"(?i)(?:document\.getElementById.*password.*innerHTML|keylogger.*document)"##, "Browser-side credential harvesting"),
]);

pub struct SocialEngineeringRule;
impl Rule for SocialEngineeringRule {
    fn id(&self) -> &str { "SEC-118" }
    fn name(&self) -> &str { "Social Engineering / Phishing Patterns" }
    fn severity(&self) -> Severity { Severity::High }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell", "html", "javascript", "php"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC118_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-118".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-1021".to_string()),
                        cvss_score: Some(8.6),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Review for social engineering intent. Remove hardcoded credentials. Phishing tools only for authorized pentesting.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

static SEC119_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:wifipumpkin|wifipumpkin3)"##, "WiFi-Pumpkin rogue access point framework"),
    (r##"(?i)(?:fluxion|fluxion\.sh)"##, "Fluxion evil twin attack tool"),
    (r##"(?i)(?:wifiphisher|wifiphisher\.sh)"##, "Wifiphisher evil twin tool"),
    (r##"(?i)(?:evil.*twin|fakeap|fake.*ap)"##, "Evil Twin / Fake AP pattern"),
    (r##"(?i)(?:hostapd.*create.*fake.*ap|hostapd.*rogue)"##, "Rogue access point via hostapd"),
    (r##"(?i)(?:dnsmasq.*fake.*dhcp|dnsmasq.*rogue)"##, "Rogue DHCP/DNS via dnsmasq"),
    (r##"(?i)(?:airbase-ng|deauth.*attack|aireplay.*deauth)"##, "WiFi deauthentication attack"),
    (r##"(?i)(?:rogue.*ap.*mitm|mitm.*rogue.*ap)"##, "Rogue AP with MITM attack"),
    (r##"(?i)(?:ettercap.*filter.*spoof|ettercap.*arp.*spoof)"##, "ARP spoofing via Ettercap"),
]);

pub struct RogueAccessPointRule;
impl Rule for RogueAccessPointRule {
    fn id(&self) -> &str { "SEC-119" }
    fn name(&self) -> &str { "Rogue Access Point / Evil Twin Patterns" }
    fn severity(&self) -> Severity { Severity::High }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC119_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-119".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-669".to_string()),
                        cvss_score: Some(7.4),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Rogue AP tools create fake WiFi networks. Only for authorized red team engagements.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

static SEC120_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"curl\s+.*\|\s*(?:sudo\s+)?bash|curl\s+-sSL.*\|\s*(?:sudo\s+)?bash"##, "curl piped to bash - RCE risk"),
    (r##"wget\s+.*\|\s*(?:sudo\s+)?bash|wget\s+-O\s+-.*\|\s*bash"##, "wget piped to bash - RCE risk"),
    (r##"(?i)(?:sudo\s+pip3?\s+install|sudo\s+pip\s+install)"##, "pip install as root - system-wide risk"),
    (r##"git\s+clone\s+.*&&\s*cd\s+.*&&\s*(?:sudo\s+)?(?:pip|apt-get|make|bash|chmod)"##, "git clone pipeline with privilege escalation"),
    (r##"git\s+clone\s+.*&&\s*(?:sudo\s+)?bash\s*\|"##, "git clone followed by interactive shell"),
    (r##"(?i)(?:pip\s+install\s+https?://(?:raw\.githubusercontent|pastebin|gist))"##, "pip install from untrusted URL"),
    (r##"(?i)(?:chmod\s+777|chmod\s+-R\s+777|chmod\s+0755|chmod\s+755)"##, "Overly permissive file permissions"),
    (r##"(?i)(?:sudo\s+su|sudo\s+-i|su\s+-\s*root)"##, "Interactive root shell spawned"),
    (r##"python3?\s+-c\s+['\"].*(?:import|exec|system|pty)"##, "Python one-liner with shell execution"),
    (r##"(?i)(?:pty\.spawn|os\.fork.*exec|spawn.*pseudo)"##, "PTY spawn for interactive shell"),
    (r##"curl\s+[^|]*\|\s*(?:python|bash|sh)\s*(?!-)"##, "Unvalidated remote script execution"),
]);

pub struct InsecureInstallPipelineRule;
impl Rule for InsecureInstallPipelineRule {
    fn id(&self) -> &str { "SEC-120" }
    fn name(&self) -> &str { "Insecure Installation Pipeline Patterns" }
    fn severity(&self) -> Severity { Severity::High }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC120_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-120".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-347".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Download scripts to file first and inspect. Use venv for pip. Verify checksums. Prefer package managers.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

static SEC121_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:keylog|key.*log|keyboard.*record|key.*capture|key.*sniff)"##, "Keylogger / keyboard capture"),
    (r##"(?i)(?:pynput.*keyboard|pynput.*key|keyboard.*listener|keyboard.*hook)"##, "Keyboard input hooking (keylogger)"),
    (r##"(?i)(?:pyHook|pyhook|windows.*hook.*key|SetWindowsHookEx.*keyboard)"##, "Windows keyboard hook for keylogging"),
    (r##"(?i)(?:saycheese|say.*cheese|webcam.*capture|capture.*webcam|webcam.*snapshot)"##, "Webcam capture / surveillance tool"),
    (r##"(?i)(?:opencv.*VideoCapture|cv2\.VideoCapture|video.*capture.*webcam)"##, "OpenCV webcam capture"),
    (r##"(?i)(?:fswebcam|stream.*webcam|webcam.*stream|snapshot.*camera)"##, "Webcam snapshot/stream tool"),
    (r##"(?i)(?:msfvenom.*webcam|screenshot.*loop|screen.*capture.*every|screen.*log)"##, "Screen/webcam capture with persistence"),
    (r##"(?i)(?:microphone.*record|audio.*record.*device|record.*mic|pyaudio.*record)"##, "Microphone recording / audio surveillance"),
    (r##"(?i)(?:chrome.*history|firefox.*history|browser.*history.*steal|steal.*credential)"##, "Browser credential/history theft"),
    (r##"(?i)(?:herakeylogger|HeraKeylogger|chrome.*keylog|keylog.*chrome)"##, "Chrome keylogger pattern"),
    (r##"(?i)(?:clipboard.*read|pyperclip.*read|tkinter.*clipboard.*get)"##, "Clipboard content theft"),
]);

pub struct SurveillanceToolRule;
impl Rule for SurveillanceToolRule {
    fn id(&self) -> &str { "SEC-121" }
    fn name(&self) -> &str { "Surveillance / Keylogger / Webcam Hijacking Patterns" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell", "javascript"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC121_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-121".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        cvss_score: Some(9.1),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Surveillance tools without consent are illegal. Requires immediate security review.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

static SEC122_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:sliver|mythic|havoc|covenant|powertools|koadic|merlin)"##, "C2 framework signature"),
    (r##"(?i)(?:pwncat|pwncat-cs|Empire|empire.*ps1|cobalt.*strike)"##, "C2 / RAT framework signature"),
    (r##"(?i)(?:reverse.*shell|rev.*shell|bind.*shell|nc.*-e|ncat.*-e)"##, "Reverse shell handler pattern"),
    (r##"(?i)(?:pentestmonkey|reverse.*shell.*php|rm\s+/tmp/f\;mkfifo)"##, "Reverse shell one-liner"),
    (r##"(?i)(?:meterpreter|msf.*payload|msfvenom.*meterpreter)"##, "Meterpreter / Metasploit payload"),
    (r##"/bin/(?:ba)?sh.*-i|/dev/tcp|bash.*-i.*udp"##, "Interactive shell from network payload"),
    (r##"(?i)(?:powershell.*-enc|powershell.*-encoded|iex.*web.*client|downloadstring)"##, "PowerShell RCE / C2 pattern"),
    (r##"(?i)(?:cron.*reverse|crontab.*reverse|systemd.*reverse|persistence.*cron)"##, "Persistence mechanism for C2"),
    (r##"(?i)(?:while.*true.*sleep.*http|beacon.*sleep|check.*in.*interval)"##, "Beaconing for C2 communication"),
    (r##"(?i)(?:msfconsole.*handler|exploit.*multi.*handler|set.*payload.*reverse)"##, "Metasploit multi-handler"),
]);

pub struct C2FrameworkRule;
impl Rule for C2FrameworkRule {
    fn id(&self) -> &str { "SEC-122" }
    fn name(&self) -> &str { "C2 Framework / RAT Communication Patterns" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell", "powershell"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC122_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-122".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-506".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "C2/RAT patterns indicate compromise. Investigate source. Check persistence. Never in production code.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

static SEC123_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:backdoor|rootkit|veil|shellcode.*inject|inject.*shell)"##, "Backdoor / rootkit / shellcode injection"),
    (r##"(?i)(?:msfvenom.*-p\s+(?:linux|windows|php|java|python).*Meterpreter)"##, "Metasploit Meterpreter payload generation"),
    (r##"(?i)(?:msfvenom.*-p\s+.*--format\s+(?:exe|php|asp|war|jsp))"##, "Metasploit cross-platform payload"),
    (r##"(?i)(?:TheFatRat|fatrat.*backdoor|fatrat.*payload)"##, "TheFatRat backdoor creation"),
    (r##"(?i)(?:steganography.*inject|steg.*payload|hide.*payload.*image|image.*payload.*inject)"##, "Steganographic payload hiding"),
    (r##"(?i)(?:Vegile|ghost.*shell|rootkit.*inject|inject.*rootkit)"##, "Vegile ghost-in-the-shell rootkit"),
    (r##"(?i)(?:hide.*process|hidden.*process|libprocess|process.*inject)"##, "Process hiding / injection"),
    (r##"(?i)(?:HKLM.*Run|HKCU.*Run|startup.*reg|registry.*persist)"##, "Windows registry persistence"),
    (r##"(?i)(?:\.(?:bashrc|bash_profile|profile|zshrc).*reverse|rc.*local.*reverse)"##, "Shell RC file persistence for backdoor"),
    (r##"(?i)(?:msf.*encode|x86/shikata|shellcode.*encode|av.*evasion)"##, "AV evasion / shellcode encoding"),
    (r##"(?i)(?:dropper|download.*payload|fetch.*payload|write.*binary.*disk)"##, "Payload dropper pattern"),
    (r##"(?i)(?:hid.*attack|badusb|usb.*rubber|keyboard.*inject.*device)"##, "HID/BadUSB attack pattern"),
]);

pub struct BackdoorRootkitRule;
impl Rule for BackdoorRootkitRule {
    fn id(&self) -> &str { "SEC-123" }
    fn name(&self) -> &str { "Backdoor / Rootkit / Payload Dropper Patterns" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell", "powershell", "c"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC123_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-123".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-506".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Backdoor/rootkit patterns indicate severe compromise. Isolate affected systems immediately.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

static SEC124_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:bruteforce.*login|brute.*force.*auth|login.*brute|credential.*brute)"##, "Credential brute-forcing pattern"),
    (r##"(?i)(?:wordlist.*attack|dictionary.*attack|passlist|rockyou|cupp.*-i)"##, "Dictionary/wordlist attack"),
    (r##"(?i)(?:hashcat.*-a\s*0|hashcat.*-m\s*\d|john.*--wordlist|john.*--rules)"##, "Password cracking (hashcat/John)"),
    (r##"(?i)(?:ssh.*brute|brute.*ssh|medusa.*ssh|hydra.*ssh|patator.*ssh)"##, "SSH brute-force attack"),
    (r##"(?i)(?:hydra.*http|hydra.*form|brute.*http.*login|patator.*http)"##, "HTTP login brute-force"),
    (r##"(?i)(?:credential.*stuff|username.*list.*password.*list|stuff.*credential)"##, "Credential stuffing pattern"),
    (r##"(?i)(?:default.*credential|default.*password.*check|brute.*default.*pass)"##, "Default credential checking"),
    (r##"(?i)(?:kerbrute|kerberos.*brute|ASREPRoast|Kerberoast)"##, "Kerberos attack pattern"),
    (r##"(?i)(?:rainbow.*table|md5.*decrypt|sha1.*decrypt|hash.*lookup)"##, "Precomputed hash / rainbow table"),
    (r##"(?i)(?:aircrack|hashcat.*wpa|wpa.*crack|wifi.*crack|pmkid)"##, "WiFi credential cracking"),
]);

pub struct CredentialAttackRule;
impl Rule for CredentialAttackRule {
    fn id(&self) -> &str { "SEC-124" }
    fn name(&self) -> &str { "Password / Credential Attack Patterns" }
    fn severity(&self) -> Severity { Severity::High }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC124_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-124".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-307".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A07:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Tools for cracking passwords. Legitimate for authorized auditing. Ensure rate limiting, lockout, MFA in production.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

static SEC125_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:scapy\.sniff|sniff.*packets|packet.*capture|tcpdump.*-i)"##, "Network packet sniffing"),
    (r##"(?i)(?:scapy.*ARP.*spoof|arp.*spoof|ettercap.*arp|arpspoof)"##, "ARP spoofing / poisoning"),
    (r##"(?i)(?:bettercap|bettercap.*-X|bettercap.*-P.*HUD|bettercap.*caplet)"##, "Bettercap network attack framework"),
    (r##"(?i)(?:sslstrip|ssl.*strip|https.*downgrade|hstshijack)"##, "SSL/TLS stripping / HTTPS downgrade"),
    (r##"(?i)(?:dns.*spoof|ettercap.*dns|dnspoison|host.*-A.*fake)"##, "DNS spoofing / poisoning"),
    (r##"(?i)(?:mitmproxy|mitmproxy.*-p|mitm.*proxy|man.*in.*the.*middle)"##, "MITM proxy / traffic interception"),
    (r##"(?i)(?:responder.*-I|responder.*LLMNR|llmnr.*spoof|nbtscan)"##, "LLMNR/NBT-NS spoofing via Responder"),
    (r##"(?i)(?:packet.*inject|scapy.*send|craft.*packet.*send|netcut)"##, "Network packet injection"),
    (r##"(?i)(?:tcpdump.*-i.*-A|tcpdump.*-X.*http|tcpdump.*-w.*\.pcap)"##, "TCP dump capturing network traffic"),
]);

pub struct NetworkSniffingRule;
impl Rule for NetworkSniffingRule {
    fn id(&self) -> &str { "SEC-125" }
    fn name(&self) -> &str { "Network Sniffing / MITM / Packet Capture Patterns" }
    fn severity(&self) -> Severity { Severity::High }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC125_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-125".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-311".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Network sniffing tools. Legitimate for authorized testing. Enforce HTTPS and HSTS to prevent MITM.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ---------------------------------------------------------------------------
// SQL Injection Attack Patterns (SEC-132)
// ---------------------------------------------------------------------------

static SEC132_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:sqlmap\s+-u|sqlmap\s+--url|sqlmap\s+--batch|sqlmap\s+-r\s)"##, "SQLmap automated SQL injection scanner"),
    (r##"(?i)(?:sqlmap\s+--dbs|sqlmap\s+--tables|sqlmap\s+--columns|sqlmap\s+--dump)"##, "SQLmap database enumeration commands"),
    (r##"(?i)(?:sqlmap\s+--risk|sqlmap\s+--level|sqlmap\s+--threads|sqlmap\s+--tamper)"##, "SQLmap advanced injection options"),
    (r##"(?i)(?:nosqlmap\s+|--options|nosqlmap\s+-v|nosqlmap\s+--mongo)"##, "NoSQLMap NoSQL injection scanner"),
    (r##"(?i)(?:dsss\s+--url|dsss\s+-u\s|dsss\s+--data)"##, "DSSS (Damn Small SQLi) scanner"),
    (r##"(?i)(?: Leviathan|leviathan.*scan|leviathan.*exploit)"##, "Leviathan offensive security framework"),
    (r##"(?i)(?:sqlscan|sqlscan\.py|sqlscan\s+-t)"##, "SQLScan vulnerability scanner"),
    (r##"(?i)(?:SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY)"##, "Blind/time-based SQL injection payload"),
    (r##"(?i)(?:(?:union\s+select|UNION\s+ALL\s+SELECT).*(?:from|where))"##, "Union-based SQL injection payload"),
    (r##"(?i)(?:'\s+OR\s+'1'\s*=\s*'1|\"\s+OR\s+\"1\"\s*=\s*\"1|OR\s+1\s*=\s*1\s*--)"##, "Classic OR SQL injection bypass"),
]);

pub struct SqlInjectionAttackRule;
impl Rule for SqlInjectionAttackRule {
    fn id(&self) -> &str { "SEC-132" }
    fn name(&self) -> &str { "SQL Injection Attack Patterns" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell", "php", "javascript"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC132_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-132".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-89".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "SQL injection tools indicate database attack attempts. Use parameterized queries, ORM, and input validation.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ---------------------------------------------------------------------------
// Web Vulnerability Scanner Patterns (SEC-133)
// ---------------------------------------------------------------------------

static SEC133_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:nuclei\s+-u|nuclei\s+--target|nuclei\s+-l\s|nuclei\s+--list)"##, "Nuclei vulnerability scanner invocation"),
    (r##"(?i)(?:nuclei\s+-t\s|nuclei\s+--templates|nuclei\s+-tags|nuclei\s+-severity)"##, "Nuclei template-based scanning"),
    (r##"(?i)(?:nikto\s+-h\s|nikto\s+--host|nikto\s+-C\s|nikto\s+--tuning)"##, "Nikto web server scanner"),
    (r##"(?i)(?:gobuster\s+dir|gobuster\s+dns|gobuster\s+vhost|gobuster\s+-u\s)"##, "Gobuster directory/file enumeration"),
    (r##"(?i)(?:ffuf\s+-w\s|ffuf\s+-u\s|ffuf\s+-fc\s|ffuf\s+-mc\s)"##, "ffuf web fuzzing tool"),
    (r##"(?i)(?:dirb\s+http|dirsearch\s+-u\s|feroxbuster\s+-u\s|dirb\s+-o\s)"##, "Directory enumeration tools"),
    (r##"(?i)(?:wafw00f\s+|wafw00f\s+-a|wafw00f\s+--findall)"##, "WAF detection via wafw00f"),
    (r##"(?i)(?:sublist3r\s+-d\s|sublist3r\s+-b\s|subjack\s+-w\s)"##, "Subdomain enumeration and takeover"),
    (r##"(?i)(?:testssl\.sh|testssl\.sh\s+--fast|testssl\.sh\s+--琴)"##, "SSL/TLS testing with testssl.sh"),
    (r##"(?i)(?:arjun\s+-u\s|arjun\s+--urls|arjun\s+-m\s)"##, "Arjun HTTP parameter discovery"),
    (r##"(?i)(?:nmap\s+--script\s+(?:http|vuln|http-enum|http-)"##, "Nmap HTTP vulnerability scripts"),
    (r##"(?i)(?:skipfish\s+-o\s|skipfish\s+-S\s|skipfish\s+-I\s)"##, "Skipfish web application scanner"),
    (r##"(?i)(?:OWASP.*ZAP|owasp.*zap|zaproxy| zap-cli)"##, "OWASP ZAP active scanner"),
    (r##"(?i)(?:gospider\s+-s\s|gospider\s+-w\s|gospider\s+-r\s)"##, "Gospider web crawler"),
]);

pub struct WebVulnScannerRule;
impl Rule for WebVulnScannerRule {
    fn id(&self) -> &str { "SEC-133" }
    fn name(&self) -> &str { "Web Vulnerability Scanner Patterns" }
    fn severity(&self) -> Severity { Severity::High }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC133_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-133".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Web vulnerability scanner tools detected. Ensure these are used in authorized security testing only.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ---------------------------------------------------------------------------
// Forensics / Memory Analysis Patterns (SEC-134)
// ---------------------------------------------------------------------------

static SEC134_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:volatility\s+-f\s|volatility\s+--profile|volatility\s+windows\.)"##, "Volatility memory forensics framework"),
    (r##"(?i)(?:volatility\s+-Q\s|volatility\s+dump|volatility\s+pslist)"##, "Volatility process/memory extraction"),
    (r##"(?i)(?:binwalk\s+-e\s|binwalk\s+--dd|binwalk\s+-M\s|binwalk\s+-r)"##, "Binwalk firmware/binaries extraction"),
    (r##"(?i)(?:autopsy|autopsy\s+--琴| SleuthKit|tsk_getattr)"##, "Autopsy/SleuthKit forensic analysis"),
    (r##"(?i)(?:bulk_extractor|bulk-extractor|bulkextractor)"##, "BulkExtractor digital forensics tool"),
    (r##"(?i)(?:pspy|pspy64|pspy32|pspy\s+-p\s|pspy\s+-c\s)"##, "pspy process monitoring without root"),
    (r##"(?i)(?:wireshark|tshark|tshark\s+-r\s|tshark\s+-Y\s)"##, "Wireshark/tshark packet analysis"),
    (r##"(?i)(?:guymager|guymager\s+-d\s|affcopy|libewf)"##, "Guymager forensic imaging tool"),
    (r##"(?i)(?:toolsley|toolsley\.py|forensic.*toolsley)"##, "Toolsley forensic utility suite"),
]);

pub struct ForensicsAnalysisRule;
impl Rule for ForensicsAnalysisRule {
    fn id(&self) -> &str { "SEC-134" }
    fn name(&self) -> &str { "Forensics / Memory Analysis Patterns" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC134_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-134".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Digital forensics tools detected. Ensure authorized use only for incident response or legitimate investigations.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ---------------------------------------------------------------------------
// Steganography Patterns (SEC-135)
// ---------------------------------------------------------------------------

static SEC135_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:steghide\s+extract|steghide\s+embed|steghide\s+-sf\s)"##, "Steghide steganography tool"),
    (r##"(?i)(?:stegcracker|stegcrack|brute.*stego|john.*stego)"##, "Steganography brute-force cracking"),
    (r##"(?i)(?:zsteg\s+|zsteg\s+-a\s|zsteg\s+-E\s)"##, "zsteg PNG/BMP steganography detection"),
    (r##"(?i)(?:snow\s+|snow\s+-C\s|snow\s+-p\s)"##, "SNOW whitespace steganography"),
    (r##"(?i)(?:pngcheck|pngcheck\s+-v|outguess|outguess\s+-r\s)"##, "PNG analysis and stego extraction"),
    (r##"(?i)(?:stegano|stegano-lsb|stegano-lsb-set|openstego)"##, "OpenStego / LSB steganography"),
    (r##"(?i)(?:stegosuite|stegosuite\s+-x|stegosuite\s+-e)"##, "StegoSuite steganography tool"),
    (r##"(?i)(?:jsteg|jsteg\s+extract|jsteg\.py|hide.*data.*image)"##, "JSteg JPEG steganography"),
    (r##"(?i)(?:stegoveritas|stegoveritas\.py|veritas.*stego)"##, "StegoVeritas comprehensive stego analysis"),
]);

pub struct SteganographyRule;
impl Rule for SteganographyRule {
    fn id(&self) -> &str { "SEC-135" }
    fn name(&self) -> &str { "Steganography Patterns" }
    fn severity(&self) -> Severity { Severity::Medium }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC135_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-135".to_string(),
                        severity: Severity::Medium.as_str().to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        cvss_score: Some(5.3),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Steganography tools detected. Review for data exfiltration or hidden malware payloads.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ---------------------------------------------------------------------------
// Cloud Security / Active Directory Attack Patterns (SEC-136)
// ---------------------------------------------------------------------------

static SEC136_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:bloodhound|bloodhound-ce|bloodhound\.py|bloodhound.*--琴)"##, "BloodHound AD enumeration tool"),
    (r##"(?i)(?:bloodhound.*-c\s|bloodhound.*-CollectionMethod|bloodhound.*--gc)"##, "BloodHound data collection commands"),
    (r##"(?i)(?:netexec|nxc\s+--pass-pol|nxc\s+--sam|nxc\s+-M\s+.*)"##, "NetExec (NetExec) lateral movement tool"),
    (r##"(?i)(?:impacket|psexec\.py|smbexec\.py|wmiexec\.py|ntlmrelayx\.py)"##, "Impacket attack toolkit"),
    (r##"(?i)(?:GetUserSPNs\.py|GetNPUsers\.py|kerberoast|kerberoasting)"##, "Kerberoasting attack pattern"),
    (r##"(?i)(?:certipy|certipy-ad\s+find|certipy-ad\s+auth|certipy.*shadow)"##, "Certipy Active Directory certificate attack"),
    (r##"(?i)(?:responder|responder\s+-I\s|responder\s+-rFv|LLMNR.*responder)"##, "Responder LLMNR/NBT-NS poisoner"),
    (r##"(?i)(?:krbrelay|krbrelayx|mitm6|mitm6\s+-i\s)"##, "Kerberos relay attack (mitm6/krbrelay)"),
    (r##"(?i)(?:enum4linux|enum4linux\.py|samrdump\.py)"##, "SMB/AD enumeration via enum4linux"),
    (r##"(?i)(?:ldapsearch|ldapsearch\s+-H\s|ldapsearch\s+-D\s|ldapdomaindump)"##, "LDAP enumeration and domain dump"),
    (r##"(?i)(?:secretsdump\.py|secretsdump|lsassy)"##, "Remote SAM/SECRETS dumping (Mimikatz alternative)"),
    (r##"(?i)(?:wmiexec|wmiexec\.py|dcomexec\.py|atexec\.py)"##, "WMI/DCOM remote execution tools"),
]);

pub struct CloudADAttackRule;
impl Rule for CloudADAttackRule {
    fn id(&self) -> &str { "SEC-136" }
    fn name(&self) -> &str { "Cloud Security / Active Directory Attack Patterns" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell", "powershell"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC136_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-136".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-284".to_string()),
                        cvss_score: Some(9.3),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "AD/cloud attack tools detected. Indicates potential lateral movement, privilege escalation, or credential theft.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ---------------------------------------------------------------------------
// Mobile Security Patterns (SEC-137)
// ---------------------------------------------------------------------------

static SEC137_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:frida\s+-U|frida\s+-f\s|frida\s+-l\s|frida-trace)"##, "Frida dynamic instrumentation toolkit"),
    (r##"(?i)(?:frida.*-s\s|frida.*--enable-jit|frida.*hook|frida.*attach)"##, "Frida hooking/instrumentation patterns"),
    (r##"(?i)(?:mobsf|mobile-security-framework|mobsfapi|MobSF.*scan)"##, "MobSF mobile security framework"),
    (r##"(?i)(?:objection\s+-g\s|objection\s+explore|objection\s+ios\s)"##, "Objection mobile exploration tool"),
    (r##"(?i)(?:apktool\s+d\s|apktool\s+b\s|apktool.*if\s|jadx.*\.apk)"##, "APK decompilation and analysis"),
    (r##"(?i)(?:androguard|androguard\.py|Androguard.*decompile|dalvik.*analyze)"##, "Androguard Android analysis"),
    (r##"(?i)(?:drozer|drozer.*exploit|drozer.*module|drozer.*shell)"##, "Drozer Android security testing"),
    (r##"(?i)(?:qark\s+--source|qark\s+--apk|qark\s+--exploit)"##, "QARK Android vulnerability scanner"),
    (r##"(?i)(?:pidcat|logcat.*vuln|adb\s+logcat.*sensitive)"##, "Android logcat sensitive data exposure"),
    (r##"(?i)(?:xposed.*module|xposed.*hook|lsposed)"##, "Xposed/LSposed framework hooking"),
]);

pub struct MobileSecurityRule;
impl Rule for MobileSecurityRule {
    fn id(&self) -> &str { "SEC-137" }
    fn name(&self) -> &str { "Mobile Security Patterns" }
    fn severity(&self) -> Severity { Severity::High }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell", "java"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC137_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-137".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Mobile security testing tools detected. Ensure authorized testing on devices you own or have permission to test.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ---------------------------------------------------------------------------
// DDOS Attack Patterns (SEC-138)
// ---------------------------------------------------------------------------

static SEC138_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:slowloris|slowloris\.py|loworbit.*ion|slow.*http.*post)"##, "Slowloris DoS attack tool"),
    (r##"(?i)(?:goldeneye|goldeneye\.py|goldeneye\s+-u\s|goldeneye\s+-m\s)"##, "GoldenEye DoS testing tool"),
    (r##"(?i)(?:ufonet|ufonet\.py|ufonet\s+--target|ufonet\s+--botnet)"##, "UFONet DDoS tool"),
    (r##"(?i)(?:asyncrone|asyncrone\.py|asyncrone\s+--target)"##, "Asyncrone DoS tool"),
    (r##"(?i)(?:saphyra|saphyra\.py|hulk|hulk\.py|apache.*killer)"##, "HULK / Apache Killer DoS tool"),
    (r##"(?i)(?:rudy|tor's hammer|r-u-dead-yet|rydos)"##, "R-U-Dead-Yet slow POST DoS"),
    (r##"(?i)(?:xoic|xoic\.py|doser|doser\.py|ddos.*script)"##, "DDOS attack script patterns"),
    (r##"(?i)(?:siege|siege\s+-c\s|siege\s+-t\s|apache-bench|ab\s+-n\s)"##, "HTTP stress testing (potential DoS)"),
]);

pub struct DDOSAttackRule;
impl Rule for DDOSAttackRule {
    fn id(&self) -> &str { "SEC-138" }
    fn name(&self) -> &str { "DDOS Attack Patterns" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC138_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-138".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-400".to_string()),
                        cvss_score: Some(8.6),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "DDoS/DoS tools detected. Ensure rate limiting, CDN protection, and WAF in production. Only authorized testing.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ---------------------------------------------------------------------------
// Exploit Framework Patterns (SEC-139)
// ---------------------------------------------------------------------------

static SEC139_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:rsf\.py|rsploit|router.*exploit|router?sploit)"##, "RouterSploit framework"),
    (r##"(?i)(?:wsf\.py|websploit|websploit\s+use\s|websploit\s+set\s)"##, "WebSploit framework"),
    (r##"(?i)(?:commix|commix\.py|commix\s+--url|commix\s+--wizard)"##, "Commix command injection exploit tool"),
    (r##"(?i)(?:msfconsole|msfvenom|metasploit|msf.*use\s|msf.*exploit)"##, "Metasploit framework"),
    (r##"(?i)(?:msfvenom\s+-p\s|msfvenom\s+--payload|msfvenom\s+--format)"##, "MSFVenom payload generation"),
    (r##"(?i)(?:searchsploit|exploitdb|exploit-db|searchsploit\s+-s\s)"##, "Exploit-DB / searchsploit"),
    (r##"(?i)(?:searchsploit\s+-c\s|searchsploit\s+-m\s|searchsploit\s+-e\s)"##, "Exploit-DB search and clone"),
    (r##"(?i)(?:ploit|payload.*generate|shell.*generate|exploit.*generate)"##, "Custom exploit/payload generation script"),
    (r##"(?i)(?:sploitscan|auto.*exploit|autoexploit|mass.*exploit)"##, "Mass/automated exploit scanning"),
]);

pub struct ExploitFrameworkRule;
impl Rule for ExploitFrameworkRule {
    fn id(&self) -> &str { "SEC-139" }
    fn name(&self) -> &str { "Exploit Framework Patterns" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell", "ruby", "powershell"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC139_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-139".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-20".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Exploit framework tools detected. Ensure only used in authorized penetration testing with proper scoping.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ---------------------------------------------------------------------------
// Cloud Security Scanning Patterns (SEC-140)
// ---------------------------------------------------------------------------

static SEC140_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:trivy\s+|trivy\s+image|trivy\s+fs\s|trivy\s+--severity)"##, "Trivy vulnerability scanner"),
    (r##"(?i)(?:trivy\s+--security-checks|trivy\s+--vuln-type|trivy\s+k8s)"##, "Trivy cloud/k8s security checks"),
    (r##"(?i)(?:prowler\s+|prowler\s+v3|prowler\s+-f\s|prowler\s+-c\s)"##, "Prowler AWS security assessment"),
    (r##"(?i)(?:scoutsuite|scout\s+--琴|scout\s+-p\s|scout\s+aws)"##, "ScoutSuite multi-cloud security scanner"),
    (r##"(?i)(?:pac\w|pacu|pacu\.py|pacu\s+--help)"##, "Pacu AWS exploitation framework"),
    (r##"(?i)(?:cloud_enum|cloud-enumerate|cloud_enum\.py)"##, "Cloud resource enumeration tool"),
    (r##"(?i)(?:awscli.*--profile|aws\s+sts\s+get-caller-identity|aws.*enum)"##, "AWS CLI enumeration patterns"),
    (r##"(?i)(?:az\s+vm\s+list|az\s+account\s+list|azure.*enum|az cli.*scan)"##, "Azure CLI enumeration patterns"),
    (r##"(?i)(?:gcloud\s+--project|gcloud\s+compute\s+list|gcp.*enum|gcloud.*scan)"##, "GCP enumeration patterns"),
    (r##"(?i)(?:kube-hunter|kube-hunter\.py|kube-bench|popeye.*k8s)"##, "Kubernetes security scanners"),
]);

pub struct CloudSecurityScanRule;
impl Rule for CloudSecurityScanRule {
    fn id(&self) -> &str { "SEC-140" }
    fn name(&self) -> &str { "Cloud Security Scanning Patterns" }
    fn severity(&self) -> Severity { Severity::High }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC140_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-140".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Cloud security scanning tools detected. Verify proper IAM, least-privilege, and cloud-native security tooling in production.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

// ---------------------------------------------------------------------------
// Wireless Security Patterns (SEC-141) - Extended from SEC-119
// ---------------------------------------------------------------------------

static SEC141_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:aircrack-ng|aircrack-ng\s+-w\s|aircrack-ng\s+-b\s)"##, "Aircrack-ng WiFi security auditing"),
    (r##"(?i)(?:reaver|reaver\s+-b\s|reaver\s+-i\s|wps.*brute|wash.*-i)"##, "Reaver WPS brute-force attack"),
    (r##"(?i)(?: bully|bully\.py|bully\s+-b\s|bully\s+-逆)"##, "Bully WPS attack tool"),
    (r##"(?i)(?:kismet|kismet\s+-c\s|kismet\s+--daemon)"##, "Kismet wireless detector/sniffer"),
    (r##"(?i)(?:wifite|wifite\s+-i\s|wifite\s+--no-wep|wifite\s+--walk)"##, "Wifite automated wireless attack"),
    (r##"(?i)(?:hashcat.*wpa|hashcat\s+-m\s+2500|hashcat\s+-m\s+16800)"##, "Hashcat WPA/WPA2 handshake cracking"),
    (r##"(?i)(?:cowpatty|cowpatty\s+-r\s|cowpatty\s+-d\s|cowpatty\s+-c)"##, "Cowpatty WPA PSK cracking"),
    (r##"(?i)(?:pyrit|pyrit\s+attack|pyrit\s+-r\s|pyrit\s+strip)"##, "Pyrit GPU-based WPA cracking"),
    (r##"(?i)(?:hcxdumptool|hcxpcapngtool|hcxtools|hcxdump.*-i)"##, "hcxdumptool / hcxtools WiFi tools"),
]);

pub struct WirelessAttackRule;
impl Rule for WirelessAttackRule {
    fn id(&self) -> &str { "SEC-141" }
    fn name(&self) -> &str { "Wireless Security Attack Patterns" }
    fn severity(&self) -> Severity { Severity::High }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell", "c"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC141_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-141".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-310".to_string()),
                        cvss_score: Some(7.4),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Wireless attack tools detected. Ensure WPA3/WPA2-Enterprise with strong passwords. Use certificate-based auth.".to_string(),
                        auto_fix_available: false,
                        replacement: String::new(),
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

pub fn all_hackingtool_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(SocialEngineeringRule),
        Box::new(RogueAccessPointRule),
        Box::new(InsecureInstallPipelineRule),
        Box::new(SurveillanceToolRule),
        Box::new(C2FrameworkRule),
        Box::new(BackdoorRootkitRule),
        Box::new(CredentialAttackRule),
        Box::new(NetworkSniffingRule),
        Box::new(SqlInjectionAttackRule),
        Box::new(WebVulnScannerRule),
        Box::new(ForensicsAnalysisRule),
        Box::new(SteganographyRule),
        Box::new(CloudADAttackRule),
        Box::new(MobileSecurityRule),
        Box::new(DDOSAttackRule),
        Box::new(ExploitFrameworkRule),
        Box::new(CloudSecurityScanRule),
        Box::new(WirelessAttackRule),
    ]
}
