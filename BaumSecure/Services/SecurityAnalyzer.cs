using BaumSecure.Models;

namespace BaumSecure.Services;

/// <summary>
/// Defines the library of security rules and maps open ports to findings.
/// </summary>
public static class SecurityAnalyzer
{
    // ── Rule database ──────────────────────────────────────────────────────────
    public static readonly IReadOnlyList<SecurityRule> Rules = new List<SecurityRule>
    {
        new(21,    "TCP", "FTP",            Severity.Critical,
            "Unencrypted FTP exposed",
            "FTP transmits credentials and data in plain text. Anyone on the path between client and server can intercept files and passwords.",
            "Replace FTP with SFTP (port 22) or FTPS. If you must keep FTP, restrict it with firewall rules to trusted IPs only."),

        new(22,    "TCP", "SSH",            Severity.High,
            "SSH exposed to the internet",
            "While SSH is encrypted, an exposed SSH port is a constant target for brute-force and credential-stuffing attacks.",
            "Disable password authentication — use SSH key pairs only. Consider moving SSH to a non-standard port or placing it behind a VPN/WireGuard. Enable fail2ban or equivalent."),

        new(23,    "TCP", "Telnet",         Severity.Critical,
            "Telnet exposed — unencrypted remote access",
            "Telnet is completely unencrypted. Every command, password, and response is visible on the network in plain text.",
            "Disable Telnet immediately. Replace with SSH. If the device does not support SSH, replace the device."),

        new(25,    "TCP", "SMTP",           Severity.Medium,
            "SMTP port exposed — open relay risk",
            "An open SMTP port can be abused as an open relay to send spam, damaging your IP reputation.",
            "If you don't run a mail server, close port 25. If you do, ensure relay is locked to authenticated users only and your server is not listed on any DNSBL."),

        new(80,    "TCP", "HTTP",           Severity.Low,
            "Plain HTTP exposed",
            "HTTP transmits data unencrypted. Credentials and session cookies sent over HTTP can be intercepted.",
            "Redirect all HTTP traffic to HTTPS. If this is an intentional public web server, ensure all sensitive operations require HTTPS."),

        new(110,   "TCP", "POP3",           Severity.Medium,
            "POP3 exposed — unencrypted email",
            "POP3 without TLS transmits email and credentials in plain text.",
            "Disable plain POP3. Use POP3S (port 995) or switch to IMAP over TLS (port 993)."),

        new(135,   "TCP", "MSRPC",          Severity.High,
            "Windows RPC exposed",
            "MSRPC is an attack vector for numerous Windows remote-exploitation techniques and is not intended to be internet-facing.",
            "Block port 135 at your firewall. MSRPC should never be reachable from the internet."),

        new(139,   "TCP", "NetBIOS",        Severity.Critical,
            "NetBIOS exposed",
            "NetBIOS exposes Windows name resolution and session services. It has been exploited by worms and ransomware.",
            "Block ports 137–139 at your perimeter firewall. NetBIOS should be LAN-only."),

        new(143,   "TCP", "IMAP",           Severity.Medium,
            "IMAP exposed — unencrypted email",
            "Plain IMAP exposes email and credentials without encryption.",
            "Disable plain IMAP (143) and use IMAPS on port 993 instead."),

        new(445,   "TCP", "SMB",            Severity.Critical,
            "SMB exposed — critical ransomware risk",
            "SMB (Windows file sharing) on the internet is the primary vector for ransomware like WannaCry and NotPetya. Exposing port 445 is extremely dangerous.",
            "Block port 445 at your perimeter firewall immediately. SMB must never be internet-facing. Use a VPN for remote file access."),

        new(1080,  "TCP", "SOCKS Proxy",    Severity.High,
            "SOCKS proxy exposed",
            "An open SOCKS proxy allows anyone to route malicious traffic through your connection, potentially implicating you in attacks or illegal activity.",
            "If you run a proxy, require authentication and restrict access to known IPs. If unintentional, close the port."),

        new(1433,  "TCP", "MSSQL",          Severity.Critical,
            "SQL Server database exposed",
            "An internet-facing database server is a prime target. SQL Server has been attacked via brute force, SA account exploitation, and xp_cmdshell abuse.",
            "Never expose a database directly to the internet. Place SQL Server behind a VPN or use an application layer to proxy access."),

        new(1723,  "TCP", "PPTP VPN",       Severity.High,
            "PPTP VPN exposed — broken encryption",
            "PPTP is a legacy VPN protocol with known cryptographic weaknesses that allow decryption of traffic.",
            "Replace PPTP with WireGuard or OpenVPN. PPTP should be considered compromised."),

        new(1900,  "UDP", "UPnP/SSDP",      Severity.High,
            "UPnP/SSDP exposed — amplification and port-opening risk",
            "UPnP exposed to the internet can be abused for DDoS amplification attacks. It may also allow external devices to open ports on your router.",
            "Disable UPnP on your router. UPnP should never be reachable from the internet."),

        new(2375,  "TCP", "Docker (plain)",  Severity.Critical,
            "Docker daemon exposed without TLS",
            "An unauthenticated Docker API gives an attacker full root-equivalent access to the host, including the ability to mount the filesystem and escape containers.",
            "Immediately restrict port 2375. Either disable remote Docker API access or enable TLS mutual authentication on port 2376 and close 2375."),

        new(2376,  "TCP", "Docker (TLS)",    Severity.High,
            "Docker TLS API exposed",
            "Even with TLS, exposing Docker's remote API increases attack surface. A misconfigured certificate or stolen client cert grants full control.",
            "Restrict Docker API access to a VPN or use SSH tunnelling rather than direct internet exposure."),

        new(2379,  "TCP", "etcd",            Severity.Critical,
            "etcd cluster store exposed",
            "etcd stores Kubernetes secrets, tokens, and cluster config in plain text (base64-encoded). An unauthenticated etcd port leaks all cluster secrets.",
            "Block etcd ports (2379–2380) at the firewall. etcd must only be reachable by the Kubernetes control plane on a private network."),

        new(3306,  "TCP", "MySQL/MariaDB",   Severity.Critical,
            "MySQL/MariaDB database exposed",
            "A database exposed to the internet is at risk of brute force, SQL injection bypass, and direct credential stuffing attacks.",
            "Block port 3306 at your firewall. Use SSH tunnelling or a VPN for remote DB administration. Never allow direct internet access to a database."),

        new(3389,  "TCP", "RDP",             Severity.Critical,
            "RDP exposed — brute force and BlueKeep risk",
            "Remote Desktop Protocol is one of the most targeted services on the internet. It is vulnerable to brute force, credential stuffing, and past critical RCE vulnerabilities (BlueKeep, DejaBlue).",
            "Move RDP behind a VPN (WireGuard recommended). If public RDP is required, enforce Network Level Authentication, complex passwords, account lockout, and block unused geography at the firewall."),

        new(4444,  "TCP", "Metasploit",      Severity.Critical,
            "Metasploit default listener port open",
            "Port 4444 is the default callback port for Metasploit payloads. An open listener on this port could indicate a compromised host or misconfigured pentest tool.",
            "Investigate immediately. If this is a legitimate pentest tool, shut down listeners when not in use and restrict to internal network."),

        new(5432,  "TCP", "PostgreSQL",      Severity.Critical,
            "PostgreSQL database exposed",
            "Exposing a database directly to the internet risks data exfiltration via brute force or configuration exploitation.",
            "Block port 5432 at your firewall. Use SSH tunnels or a VPN for remote database access."),

        new(5601,  "TCP", "Kibana",          Severity.High,
            "Kibana exposed — potential data access",
            "Kibana provides a web UI to all data in your Elasticsearch cluster. Without authentication, anyone can read, delete, or modify indexed data.",
            "Enable Elasticsearch security features (X-Pack/basic auth). Place Kibana behind a reverse proxy with authentication, or restrict access to VPN."),

        new(5900,  "TCP", "VNC",             Severity.Critical,
            "VNC exposed — remote desktop without encryption",
            "VNC is frequently configured with weak or no passwords and transmits display data without encryption, making it trivial to hijack.",
            "Never expose VNC to the internet. Use SSH tunnelling to forward VNC: `ssh -L 5900:localhost:5900 user@host`. Require a strong VNC password as a secondary layer."),

        new(6379,  "TCP", "Redis",           Severity.Critical,
            "Redis exposed — typically unauthenticated",
            "Redis defaults to no authentication and no network binding restrictions. An exposed Redis instance can be used to read/write arbitrary data, gain code execution via SLAVEOF/CONFIG, or pivot into other systems.",
            "Bind Redis to 127.0.0.1 only (bind 127.0.0.1 in redis.conf). Enable requirepass authentication. Never expose Redis to the internet."),

        new(8080,  "TCP", "Alt-HTTP",        Severity.Medium,
            "Alternate HTTP port exposed",
            "Port 8080 commonly hosts developer tools, admin panels, proxy services, or misconfigured web servers that may lack hardening.",
            "Identify what is running on port 8080. If it is an admin interface, restrict access to internal IPs or a VPN. Ensure any exposed service uses HTTPS."),

        new(8006,  "TCP", "Proxmox",         Severity.High,
            "Proxmox VE management UI exposed",
            "The Proxmox web interface provides full hypervisor control. Exposing it to the internet risks brute force and exploitation of Proxmox vulnerabilities.",
            "Block 8006 from the internet. Access Proxmox management via a VPN or SSH port-forward. Enable two-factor authentication in Proxmox."),

        new(8888,  "TCP", "Jupyter Notebook", Severity.Critical,
            "Jupyter Notebook exposed — code execution risk",
            "Jupyter Notebook allows arbitrary Python code execution. Without a token or password, anyone who reaches this port can execute code as the server user.",
            "Never expose Jupyter without authentication. Set a strong password (`jupyter notebook password`). Place behind a VPN or reverse proxy with auth. Consider using JupyterHub with proper authentication."),

        new(9000,  "TCP", "Portainer/PHP-FPM", Severity.High,
            "Port 9000 exposed — admin or FastCGI service",
            "Port 9000 is commonly used by Portainer (Docker management UI) and PHP-FPM. Either exposes significant control or is a known attack vector for the PHP-FPM RCE (CVE-2019-11043).",
            "Restrict port 9000 to internal network access only. If this is PHP-FPM, ensure it binds to a Unix socket rather than a TCP port."),

        new(9090,  "TCP", "Prometheus",      Severity.High,
            "Prometheus metrics endpoint exposed",
            "Prometheus exposes detailed internal metrics and labels that can reveal infrastructure topology, service names, and sensitive configuration data.",
            "Restrict Prometheus to internal networks. If external access is needed, add authentication via a reverse proxy (e.g., nginx basic auth or OAuth2 Proxy)."),

        new(9200,  "TCP", "Elasticsearch",   Severity.Critical,
            "Elasticsearch exposed — data at risk",
            "Elasticsearch has no built-in authentication in older versions. Thousands of exposed clusters have had data stolen, deleted, or held for ransom.",
            "Enable Elasticsearch security features. Block port 9200 from the internet. Access via an authenticated reverse proxy or VPN only."),

        new(10250, "TCP", "Kubelet API",     Severity.Critical,
            "Kubernetes Kubelet API exposed",
            "The Kubelet API can be used to exec into running pods, read secrets, and escalate to full cluster control if anonymous access is enabled.",
            "Block port 10250 at your firewall. Ensure Kubelet has --anonymous-auth=false and webhook authorization enabled. Kubelet must not be internet-facing."),

        new(11211, "TCP", "Memcached",       Severity.High,
            "Memcached exposed",
            "Memcached has no authentication. Exposed instances have been used for DDoS amplification attacks exceeding 1 Tbps and for reading cached application data.",
            "Bind Memcached to localhost (--listen=127.0.0.1). Block port 11211 at the firewall. Never expose Memcached to the internet."),

        new(27017, "TCP", "MongoDB",         Severity.Critical,
            "MongoDB exposed — often unauthenticated",
            "MongoDB historically shipped with no authentication enabled. Exposed instances are regularly found and have had data stolen or deleted by ransomware bots.",
            "Enable MongoDB authentication (security.authorization: enabled in mongod.conf). Bind to localhost or internal IP only. Never expose port 27017 to the internet."),

        new(50070, "TCP", "Hadoop NameNode",  Severity.High,
            "Hadoop NameNode web UI exposed",
            "The Hadoop NameNode web interface exposes filesystem metadata, cluster configuration, and in some versions allows unauthenticated file access.",
            "Restrict Hadoop admin ports to the internal cluster network. Use Kerberos authentication for Hadoop services."),
    };

    // ── Profile port lists ─────────────────────────────────────────────────────
    public static IEnumerable<SecurityRule> GetRulesForProfile(ScanProfile profile) => profile switch
    {
        ScanProfile.Quick => Rules.Where(r => r.Severity is Severity.Critical or Severity.High),
        ScanProfile.Full  => Rules,
        _                 => Rules,
    };

    public static SecurityFinding Analyze(SecurityRule rule, bool isOpen, string? banner = null)
        => new(rule, isOpen, banner);
}
