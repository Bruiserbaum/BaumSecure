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
        // ── File Transfer ──────────────────────────────────────────────────────
        new(20,    "TCP", "FTP Data",         Severity.Critical,
            "FTP data channel exposed",
            "Port 20 is the FTP active-mode data channel. Its presence indicates an active FTP server which transmits files in plain text.",
            "Replace FTP with SFTP (port 22) or FTPS. FTP data should not be reachable from the internet."),

        new(21,    "TCP", "FTP",              Severity.Critical,
            "Unencrypted FTP exposed",
            "FTP transmits credentials and data in plain text. Anyone on the path between client and server can intercept files and passwords.",
            "Replace FTP with SFTP (port 22) or FTPS. If you must keep FTP, restrict it with firewall rules to trusted IPs only."),

        new(22,    "TCP", "SSH",              Severity.High,
            "SSH exposed to the internet",
            "While SSH is encrypted, an exposed SSH port is a constant target for brute-force and credential-stuffing attacks.",
            "Disable password authentication — use SSH key pairs only. Consider moving SSH to a non-standard port or placing it behind a VPN/WireGuard. Enable fail2ban or equivalent."),

        new(23,    "TCP", "Telnet",           Severity.Critical,
            "Telnet exposed — unencrypted remote access",
            "Telnet is completely unencrypted. Every command, password, and response is visible on the network in plain text.",
            "Disable Telnet immediately. Replace with SSH. If the device does not support SSH, replace the device."),

        new(69,    "TCP", "TFTP",             Severity.High,
            "TFTP exposed — unauthenticated file transfer",
            "TFTP (Trivial File Transfer Protocol) has no authentication. It is used by network devices for boot images but should never be exposed to the internet.",
            "Block port 69. TFTP should only be accessible within the LAN by specific devices such as PXE boot servers."),

        new(990,   "TCP", "FTPS",             Severity.Info,
            "FTPS (FTP over TLS) exposed",
            "FTPS is an encrypted FTP variant. While safer than plain FTP, it still exposes a file transfer service.",
            "Ensure FTPS is configured with strong TLS and restrict access to trusted clients. Prefer SFTP where possible."),

        new(2049,  "TCP", "NFS",              Severity.High,
            "NFS file share exposed",
            "NFS exposes filesystem shares over the network. Without proper ACLs, any client can mount your shares and read or write files.",
            "Block port 2049 at your perimeter. NFS should only be accessible within a trusted LAN. Use NFSv4 with Kerberos authentication."),

        // ── Printing ──────────────────────────────────────────────────────────
        new(515,   "TCP", "LPD/LPR",          Severity.Medium,
            "Line Printer Daemon exposed",
            "LPD (port 515) is a legacy print protocol with no authentication. Exposed to the internet it can be abused to send malicious print jobs or reveal printer status.",
            "Block port 515 at the perimeter. Modern printing should use IPP (631). Do not expose printers to the internet."),

        new(631,   "TCP", "IPP/CUPS",         Severity.Medium,
            "Internet Printing Protocol (IPP/CUPS) exposed",
            "IPP on port 631 allows sending print jobs and querying printer status. CUPS admin interfaces have had CVEs. Exposed printers can receive unsolicited print jobs.",
            "Block port 631 from the internet. Restrict IPP to local network access only."),

        new(9100,  "TCP", "Raw Print",        Severity.High,
            "Raw print port (JetDirect) exposed",
            "Port 9100 (HP JetDirect and compatible) accepts raw print jobs with no authentication. Anyone can send documents to your printer and some attacks use this to exfiltrate data.",
            "Block port 9100 at your firewall. Printers should never be internet-facing."),

        // ── Mail ──────────────────────────────────────────────────────────────
        new(25,    "TCP", "SMTP",             Severity.Medium,
            "SMTP port exposed — open relay risk",
            "An open SMTP port can be abused as an open relay to send spam, damaging your IP reputation.",
            "If you don't run a mail server, close port 25. If you do, ensure relay is locked to authenticated users only and your server is not listed on any DNSBL."),

        new(110,   "TCP", "POP3",             Severity.Medium,
            "POP3 exposed — unencrypted email",
            "POP3 without TLS transmits email and credentials in plain text.",
            "Disable plain POP3. Use POP3S (port 995) or switch to IMAP over TLS (port 993)."),

        new(143,   "TCP", "IMAP",             Severity.Medium,
            "IMAP exposed — unencrypted email",
            "Plain IMAP exposes email and credentials without encryption.",
            "Disable plain IMAP (143) and use IMAPS on port 993 instead."),

        new(465,   "TCP", "SMTPS",            Severity.Info,
            "SMTPS (SMTP over TLS) exposed",
            "Port 465 is used for secure email submission over implicit TLS.",
            "Ensure relay is locked to authenticated users. Verify TLS configuration. Monitor for abuse."),

        new(587,   "TCP", "SMTP Submission",  Severity.Medium,
            "SMTP Submission port exposed",
            "Port 587 is the standard port for authenticated email submission. An exposed submission port may be targeted by spammers.",
            "Enforce SMTP AUTH with strong passwords. Enable TLS (STARTTLS). Rate-limit and monitor for authentication failures."),

        new(993,   "TCP", "IMAPS",            Severity.Info,
            "IMAPS (IMAP over TLS) exposed",
            "IMAPS is the encrypted IMAP service. If you run a mail server, this is expected.",
            "Ensure TLS certificates are valid and enforce strong password policies. Monitor for brute force login attempts."),

        new(995,   "TCP", "POP3S",            Severity.Info,
            "POP3S (POP3 over TLS) exposed",
            "POP3S is the encrypted POP3 service. If you run a mail server, this is expected.",
            "Ensure TLS certificates are valid and enforce strong password policies. Monitor for brute force login attempts."),

        // ── Web ───────────────────────────────────────────────────────────────
        new(80,    "TCP", "HTTP",             Severity.Low,
            "Plain HTTP exposed",
            "HTTP transmits data unencrypted. Credentials and session cookies sent over HTTP can be intercepted.",
            "Redirect all HTTP traffic to HTTPS. If this is an intentional public web server, ensure all sensitive operations require HTTPS."),

        new(443,   "TCP", "HTTPS",            Severity.Info,
            "HTTPS (port 443) open",
            "Port 443 is expected for secure web traffic. Review what service is running and ensure TLS is properly configured.",
            "Verify TLS certificate is valid, cipher suites are modern (TLS 1.2+), and the service behind HTTPS is properly hardened."),

        new(3128,  "TCP", "HTTP Proxy",       Severity.High,
            "HTTP proxy (Squid/3128) exposed",
            "Port 3128 is the default Squid proxy port. An open proxy allows attackers to route traffic through your server, bypassing firewalls.",
            "If you run a proxy, require authentication and restrict to trusted IPs. If unintentional, close the port."),

        new(8006,  "TCP", "Proxmox",          Severity.High,
            "Proxmox VE management UI exposed",
            "The Proxmox web interface provides full hypervisor control. Exposing it to the internet risks brute force and exploitation of Proxmox vulnerabilities.",
            "Block 8006 from the internet. Access Proxmox management via a VPN or SSH port-forward. Enable two-factor authentication in Proxmox."),

        new(8080,  "TCP", "Alt-HTTP",         Severity.Medium,
            "Alternate HTTP port exposed",
            "Port 8080 commonly hosts developer tools, admin panels, proxy services, or misconfigured web servers that may lack hardening.",
            "Identify what is running on port 8080. If it is an admin interface, restrict access to internal IPs or a VPN. Ensure any exposed service uses HTTPS."),

        new(8443,  "TCP", "Alt-HTTPS",        Severity.Low,
            "Alternate HTTPS port exposed",
            "Port 8443 is a common alternate HTTPS port used by Tomcat, Synology DSM, and various admin panels.",
            "Identify the service on port 8443. Ensure TLS is properly configured and the service is appropriately secured."),

        new(8888,  "TCP", "Jupyter Notebook", Severity.Critical,
            "Jupyter Notebook exposed — code execution risk",
            "Jupyter Notebook allows arbitrary Python code execution. Without a token or password, anyone who reaches this port can execute code as the server user.",
            "Never expose Jupyter without authentication. Set a strong password. Place behind a VPN or reverse proxy with auth."),

        // ── Remote Access ─────────────────────────────────────────────────────
        new(512,   "TCP", "rexec",            Severity.Critical,
            "rexec (remote execution) exposed",
            "rexec is a legacy remote execution service with password authentication in plain text. It has numerous historical vulnerabilities.",
            "Disable rexec immediately. Replace with SSH."),

        new(513,   "TCP", "rlogin",           Severity.Critical,
            "rlogin exposed — trusted-host authentication",
            "rlogin can be configured with .rhosts files for password-free login from trusted hosts. This trust model is easily spoofed.",
            "Disable rlogin. Replace with SSH."),

        new(514,   "TCP", "rsh/Syslog",       Severity.High,
            "rsh or Syslog port exposed",
            "Port 514 is used by rsh (remote shell — no authentication, relies on IP trust) and by syslog. rsh is critically insecure.",
            "If this is rsh: disable it immediately. If it is syslog: restrict to known senders and consider TLS syslog."),

        new(3389,  "TCP", "RDP",              Severity.Critical,
            "RDP exposed — brute force and BlueKeep risk",
            "Remote Desktop Protocol is one of the most targeted services on the internet. It is vulnerable to brute force, credential stuffing, and past critical RCE vulnerabilities (BlueKeep, DejaBlue).",
            "Move RDP behind a VPN (WireGuard recommended). If public RDP is required, enforce NLA, complex passwords, account lockout, and block unused geography at the firewall."),

        new(4899,  "TCP", "Radmin",           Severity.High,
            "Radmin remote administration exposed",
            "Radmin (Remote Administrator) provides GUI remote access. Older versions had authentication bypass vulnerabilities. Exposure invites brute force.",
            "Update Radmin to the latest version. Restrict to known IPs or place behind a VPN. Enable IP filtering in Radmin settings."),

        new(5800,  "TCP", "VNC HTTP",         Severity.Critical,
            "VNC HTTP console exposed",
            "Port 5800 provides a web-based VNC viewer giving full remote desktop access accessible from any web browser.",
            "Block port 5800. Use SSH tunnelling for VNC access. Require a strong VNC password."),

        new(5900,  "TCP", "VNC",              Severity.Critical,
            "VNC exposed — remote desktop without encryption",
            "VNC is frequently configured with weak or no passwords and transmits display data without encryption, making it trivial to hijack.",
            "Never expose VNC to the internet. Use SSH tunnelling: ssh -L 5900:localhost:5900 user@host. Require a strong VNC password."),

        new(5901,  "TCP", "VNC :1",           Severity.Critical,
            "VNC display :1 exposed",
            "Port 5901 is VNC display :1. Like 5900, it provides weakly authenticated remote desktop access.",
            "Never expose VNC to the internet. Tunnel VNC through SSH."),

        new(5938,  "TCP", "TeamViewer",       Severity.High,
            "TeamViewer detected",
            "TeamViewer provides remote desktop access. While encrypted, stolen TeamViewer IDs/passwords have been used in breaches.",
            "Ensure TeamViewer is fully up-to-date. Use unattended access with a strong password and two-factor authentication. Disable TeamViewer when not in use."),

        new(5985,  "TCP", "WinRM HTTP",       Severity.High,
            "WinRM (Windows Remote Management) HTTP exposed",
            "WinRM on port 5985 allows remote PowerShell sessions. Exposed to the internet it is targeted by brute force and credential stuffing.",
            "Block port 5985 from the internet. Access WinRM via VPN. Restrict to specific admin hosts using firewall rules."),

        new(5986,  "TCP", "WinRM HTTPS",      Severity.Medium,
            "WinRM HTTPS exposed",
            "WinRM over HTTPS (5986) is more secure than 5985 but still exposes remote management.",
            "Restrict access to trusted IPs or a VPN. Use certificate-based authentication."),

        new(6000,  "TCP", "X11",              Severity.Critical,
            "X11 display server exposed",
            "X11 has no security by default — any connection can capture keystrokes, screenshots, and inject input into any window.",
            "Block port 6000 at the firewall. Never expose X11. Use SSH X11 forwarding (ssh -X) for remote GUI access."),

        new(22222, "TCP", "SSH (alt)",        Severity.High,
            "SSH on non-standard port exposed",
            "SSH on an alternate port may indicate security-through-obscurity. Still requires key-based auth and fail2ban.",
            "Ensure password authentication is disabled. Use SSH key pairs only. Enable fail2ban even on alternate ports."),

        // ── Windows Services ──────────────────────────────────────────────────
        new(135,   "TCP", "MSRPC",            Severity.High,
            "Windows RPC exposed",
            "MSRPC is an attack vector for numerous Windows remote-exploitation techniques and is not intended to be internet-facing.",
            "Block port 135 at your firewall. MSRPC should never be reachable from the internet."),

        new(137,   "TCP", "NetBIOS-NS",       Severity.High,
            "NetBIOS Name Service exposed",
            "NetBIOS Name Service exposes Windows network names and can be abused for name spoofing. It is associated with numerous Windows worm propagation techniques.",
            "Block ports 137-139 at your perimeter firewall. NetBIOS should be LAN-only."),

        new(138,   "TCP", "NetBIOS-DGM",      Severity.High,
            "NetBIOS Datagram Service exposed",
            "NetBIOS Datagram Service is used for Windows Browse Master elections and domain announcements. It should never be internet-facing.",
            "Block ports 137-139 at your perimeter firewall. NetBIOS should be LAN-only."),

        new(139,   "TCP", "NetBIOS",          Severity.Critical,
            "NetBIOS exposed",
            "NetBIOS exposes Windows name resolution and session services. It has been exploited by worms and ransomware.",
            "Block ports 137-139 at your perimeter firewall. NetBIOS should be LAN-only."),

        new(445,   "TCP", "SMB",              Severity.Critical,
            "SMB exposed — critical ransomware risk",
            "SMB (Windows file sharing) on the internet is the primary vector for ransomware like WannaCry and NotPetya. Exposing port 445 is extremely dangerous.",
            "Block port 445 at your perimeter firewall immediately. SMB must never be internet-facing. Use a VPN for remote file access."),

        new(593,   "TCP", "HTTP-RPC",         Severity.High,
            "HTTP RPC endpoint mapper exposed",
            "Port 593 is used by Microsoft RPC over HTTP. Exposure increases the Windows RPC attack surface over the internet.",
            "Block port 593 from the internet. Windows RPC services should not be internet-facing."),

        new(3268,  "TCP", "LDAP Global Cat.", Severity.High,
            "Active Directory Global Catalog exposed",
            "Port 3268 is the LDAP Global Catalog for Active Directory. Exposing it allows enumeration of all AD objects including users, groups, and OUs.",
            "Block port 3268 from the internet. Active Directory should never be internet-facing."),

        new(3269,  "TCP", "LDAPS Global Cat.", Severity.High,
            "Active Directory Global Catalog (SSL) exposed",
            "Port 3269 is the LDAPS Global Catalog. Even encrypted, exposing AD infrastructure to the internet is dangerous.",
            "Block port 3269 from the internet. Active Directory should only be accessible from trusted internal networks."),

        new(5357,  "TCP", "WSDAPI",           Severity.Medium,
            "Web Services for Devices (WSDAPI) exposed",
            "Port 5357 is used by Windows for device discovery (SSDP/WSD). It reveals connected device information and should not be internet-facing.",
            "Block port 5357 from the internet. Windows device discovery protocols are LAN-only services."),

        // ── Network Infrastructure ─────────────────────────────────────────────
        new(53,    "TCP", "DNS",              Severity.Medium,
            "DNS port exposed",
            "An exposed DNS server on port 53 can be abused for zone transfers, DNS amplification attacks, or internal network enumeration.",
            "Disable zone transfers to untrusted hosts. If this is an internal DNS resolver, block port 53 at your perimeter."),

        new(111,   "TCP", "RPC Portmapper",   Severity.High,
            "RPC Portmapper exposed",
            "The RPC portmapper maps RPC program numbers to ports and reveals which RPC services are running (NFS, NIS, etc.).",
            "Block port 111 at the perimeter. RPC services including NFS and NIS should not be internet-facing."),

        new(123,   "TCP", "NTP",              Severity.Low,
            "NTP service exposed",
            "NTP on port 123 can be abused for DDoS amplification (monlist queries). If not properly configured your server may be used as a reflector.",
            "Disable the monlist command (noquery directive in ntp.conf). Restrict NTP queries to legitimate clients."),

        new(161,   "TCP", "SNMP",             Severity.High,
            "SNMP exposed — network device information",
            "SNMP can expose detailed device configuration, routing tables, and system information. SNMPv1/v2c use cleartext community strings ('public'/'private' are defaults).",
            "Block port 161 from the internet. Use SNMPv3 with authentication and encryption. Change default community strings."),

        new(389,   "TCP", "LDAP",             Severity.High,
            "LDAP directory exposed — unencrypted",
            "LDAP on port 389 transmits directory queries and credentials in plain text. Exposed LDAP can allow unauthenticated directory browsing or credential interception.",
            "Block port 389 from the internet. Use LDAPS (636) or StartTLS for encrypted LDAP."),

        new(500,   "TCP", "IKE/IPsec",        Severity.Low,
            "IKE/IPsec VPN exposed",
            "Port 500 is used for IKE (Internet Key Exchange) in IPsec VPNs. Vulnerabilities in the IKE implementation could allow unauthenticated attacks.",
            "Keep VPN software up-to-date. Use IKEv2 with strong ciphers. Monitor for brute force attempts."),

        new(548,   "TCP", "AFP",              Severity.High,
            "Apple Filing Protocol (AFP) exposed",
            "AFP exposes Mac file shares. Older AFP implementations have authentication vulnerabilities and should not be internet-facing.",
            "Block port 548 at the perimeter. Mac file sharing should be LAN-only or accessed via VPN."),

        new(554,   "TCP", "RTSP",             Severity.Medium,
            "RTSP (streaming / camera) exposed",
            "RTSP is used by cameras, NVRs, and media servers. Many devices use default or no credentials, allowing unauthorized live video access.",
            "Require authentication on your RTSP stream. Place cameras behind a VPN rather than exposing RTSP to the internet."),

        new(636,   "TCP", "LDAPS",            Severity.Low,
            "LDAPS (LDAP over TLS) exposed",
            "LDAPS is the encrypted LDAP variant. While better than plain LDAP, exposing directory services to the internet still risks brute force and enumeration.",
            "Restrict LDAPS to trusted hosts or a VPN. Ensure TLS certificate is valid and authentication is required."),

        new(873,   "TCP", "rsync",            Severity.High,
            "rsync service exposed",
            "rsync can be configured to allow unauthenticated access to modules. An exposed rsync service can leak files or allow overwriting of data.",
            "Require authentication for all rsync modules. Restrict rsync access to trusted IPs. Never expose rsync to the internet without a VPN."),

        new(902,   "TCP", "VMware ESXi",      Severity.High,
            "VMware ESXi/vCenter port exposed",
            "Port 902 is used by VMware ESXi for VM console and management traffic. Exposing hypervisor management interfaces to the internet is extremely risky.",
            "Block port 902 from the internet. Access VMware management via a dedicated VPN."),

        new(1194,  "TCP", "OpenVPN",          Severity.Low,
            "OpenVPN service exposed",
            "Port 1194 is the default OpenVPN port. This is expected if you run an OpenVPN server.",
            "Keep OpenVPN updated. Use certificate-based authentication. Enable tls-crypt to prevent DDoS against the OpenVPN daemon."),

        // ── Databases ─────────────────────────────────────────────────────────
        new(1080,  "TCP", "SOCKS Proxy",      Severity.High,
            "SOCKS proxy exposed",
            "An open SOCKS proxy allows anyone to route malicious traffic through your connection, potentially implicating you in attacks or illegal activity.",
            "If you run a proxy, require authentication and restrict access to known IPs. If unintentional, close the port."),

        new(1433,  "TCP", "MSSQL",            Severity.Critical,
            "SQL Server database exposed",
            "An internet-facing database server is a prime target. SQL Server has been attacked via brute force, SA account exploitation, and xp_cmdshell abuse.",
            "Never expose a database directly to the internet. Place SQL Server behind a VPN or use an application layer to proxy access."),

        new(1521,  "TCP", "Oracle DB",        Severity.Critical,
            "Oracle Database listener exposed",
            "Oracle Database's listener on 1521 is a target for brute force, SID enumeration, and exploits. A directly exposed Oracle instance risks full database compromise.",
            "Block port 1521 from the internet. Apply current Oracle Critical Patch Updates."),

        new(3306,  "TCP", "MySQL/MariaDB",    Severity.Critical,
            "MySQL/MariaDB database exposed",
            "A database exposed to the internet is at risk of brute force, SQL injection bypass, and direct credential stuffing attacks.",
            "Block port 3306 at your firewall. Use SSH tunnelling or a VPN for remote DB administration."),

        new(5432,  "TCP", "PostgreSQL",       Severity.Critical,
            "PostgreSQL database exposed",
            "Exposing a database directly to the internet risks data exfiltration via brute force or configuration exploitation.",
            "Block port 5432 at your firewall. Use SSH tunnels or a VPN for remote database access."),

        new(5984,  "TCP", "CouchDB",          Severity.Critical,
            "CouchDB exposed — admin interface",
            "CouchDB's HTTP API on 5984 is historically unauthenticated by default ('Admin Party' mode). Exposed instances have had databases exfiltrated and ransomed.",
            "Enable CouchDB authentication and disable Admin Party mode. Bind to localhost and block port 5984 from the internet."),

        new(6379,  "TCP", "Redis",            Severity.Critical,
            "Redis exposed — typically unauthenticated",
            "Redis defaults to no authentication and no network binding restrictions. An exposed Redis instance can be used to read/write arbitrary data or gain code execution.",
            "Bind Redis to 127.0.0.1 only. Enable requirepass authentication. Never expose Redis to the internet."),

        new(7474,  "TCP", "Neo4j",            Severity.High,
            "Neo4j graph database browser exposed",
            "Neo4j's web browser UI on 7474 provides access to the graph database. Without authentication it exposes all data and allows Cypher query execution.",
            "Enable authentication in neo4j.conf. Bind to localhost and restrict external access via a VPN."),

        new(9042,  "TCP", "Cassandra CQL",    Severity.High,
            "Apache Cassandra CQL port exposed",
            "Cassandra's native query interface on 9042 can be unauthenticated by default. Exposed Cassandra allows arbitrary data reads and writes.",
            "Enable Cassandra authentication and authorization. Bind to internal interfaces. Block 9042 from the internet."),

        new(9200,  "TCP", "Elasticsearch",    Severity.Critical,
            "Elasticsearch exposed — data at risk",
            "Elasticsearch has no built-in authentication in older versions. Thousands of exposed clusters have had data stolen, deleted, or held for ransom.",
            "Enable Elasticsearch security features. Block port 9200 from the internet. Access via an authenticated reverse proxy or VPN only."),

        new(9300,  "TCP", "ES Transport",     Severity.Critical,
            "Elasticsearch cluster transport exposed",
            "Port 9300 is Elasticsearch's internal cluster communication port. It typically has no authentication and allows node joining and data access.",
            "Block port 9300 at the firewall. Elasticsearch cluster transport should never be internet-facing."),

        new(27017, "TCP", "MongoDB",          Severity.Critical,
            "MongoDB exposed — often unauthenticated",
            "MongoDB historically shipped with no authentication enabled. Exposed instances are regularly found and have had data stolen or deleted by ransomware bots.",
            "Enable MongoDB authentication. Bind to localhost or internal IP only. Never expose port 27017 to the internet."),

        new(28015, "TCP", "RethinkDB",        Severity.High,
            "RethinkDB driver port exposed",
            "RethinkDB's driver port on 28015 has historically shipped without authentication. Exposed instances allow arbitrary database operations.",
            "Enable RethinkDB authentication. Block port 28015 from the internet."),

        // ── Containers / DevOps ───────────────────────────────────────────────
        new(2375,  "TCP", "Docker (plain)",   Severity.Critical,
            "Docker daemon exposed without TLS",
            "An unauthenticated Docker API gives an attacker full root-equivalent access to the host, including the ability to mount the filesystem and escape containers.",
            "Immediately restrict port 2375. Either disable remote Docker API access or enable TLS mutual authentication on port 2376 and close 2375."),

        new(2376,  "TCP", "Docker (TLS)",     Severity.High,
            "Docker TLS API exposed",
            "Even with TLS, exposing Docker's remote API increases attack surface. A misconfigured certificate or stolen client cert grants full control.",
            "Restrict Docker API access to a VPN or use SSH tunnelling rather than direct internet exposure."),

        new(2379,  "TCP", "etcd",             Severity.Critical,
            "etcd cluster store exposed",
            "etcd stores Kubernetes secrets, tokens, and cluster config in plain text (base64-encoded). An unauthenticated etcd port leaks all cluster secrets.",
            "Block etcd ports (2379-2380) at the firewall. etcd must only be reachable by the Kubernetes control plane on a private network."),

        new(10250, "TCP", "Kubelet API",      Severity.Critical,
            "Kubernetes Kubelet API exposed",
            "The Kubelet API can be used to exec into running pods, read secrets, and escalate to full cluster control if anonymous access is enabled.",
            "Block port 10250 at your firewall. Ensure Kubelet has --anonymous-auth=false and webhook authorization enabled."),

        // ── Message Brokers / IoT ─────────────────────────────────────────────
        new(1883,  "TCP", "MQTT",             Severity.High,
            "MQTT broker exposed — unauthenticated IoT traffic",
            "MQTT is the IoT messaging protocol. Default broker configurations have no authentication, allowing anyone to subscribe to all topics and inject messages.",
            "Enable MQTT authentication and ACLs. Use MQTT over TLS (port 8883). Block port 1883 from the internet."),

        new(1900,  "TCP", "UPnP/SSDP",       Severity.High,
            "UPnP/SSDP exposed — amplification and port-opening risk",
            "UPnP exposed to the internet can be abused for DDoS amplification attacks. It may also allow external devices to open ports on your router.",
            "Disable UPnP on your router. UPnP should never be reachable from the internet."),

        new(4369,  "TCP", "Erlang EPMD",      Severity.High,
            "Erlang Port Mapper Daemon exposed",
            "EPMD maps Erlang node names to ports and is used by RabbitMQ, CouchDB, and other Erlang apps. Exposing it can allow attackers to identify and connect to Erlang nodes.",
            "Block port 4369 from the internet. Erlang nodes should communicate only within a trusted private network."),

        new(5672,  "TCP", "AMQP",             Severity.Medium,
            "AMQP (RabbitMQ) exposed",
            "AMQP on port 5672 is used by RabbitMQ. Without authentication it allows reading and injecting messages. Default credentials (guest/guest) are well known.",
            "Change default RabbitMQ credentials. Enable TLS on port 5671. Block 5672 from the internet."),

        new(8161,  "TCP", "ActiveMQ Admin",   Severity.High,
            "Apache ActiveMQ admin console exposed",
            "ActiveMQ's web admin UI on 8161 provides full broker management. It has had critical RCE vulnerabilities (CVE-2023-46604). Default credentials are admin/admin.",
            "Block port 8161 from the internet immediately. Patch ActiveMQ to the latest version. Change default credentials."),

        new(8883,  "TCP", "MQTT TLS",         Severity.Low,
            "MQTT over TLS exposed",
            "Port 8883 is encrypted MQTT. This is the preferred MQTT port for internet-facing deployments.",
            "Ensure TLS certificates are valid. Enable client certificate authentication or strong password auth. Verify broker ACLs are correctly configured."),

        new(15672, "TCP", "RabbitMQ Mgmt",    Severity.High,
            "RabbitMQ management UI exposed",
            "Port 15672 is RabbitMQ's HTTP management console. Default credentials are guest/guest. Access grants full broker control.",
            "Change default credentials. Block port 15672 from the internet. Access the management UI via VPN or SSH tunnel."),

        new(25672, "TCP", "RabbitMQ Cluster", Severity.High,
            "RabbitMQ inter-node cluster port exposed",
            "Port 25672 is used for RabbitMQ inter-node cluster communication. It relies on a shared Erlang cookie which, if intercepted, allows cluster takeover.",
            "Block port 25672 from the internet. Cluster nodes should communicate only on a private network."),

        // ── Enterprise / Java ─────────────────────────────────────────────────
        new(1723,  "TCP", "PPTP VPN",         Severity.High,
            "PPTP VPN exposed — broken encryption",
            "PPTP is a legacy VPN protocol with known cryptographic weaknesses that allow decryption of traffic.",
            "Replace PPTP with WireGuard or OpenVPN. PPTP should be considered compromised."),

        new(2181,  "TCP", "ZooKeeper",        Severity.High,
            "Apache ZooKeeper exposed",
            "ZooKeeper is used by Kafka, HBase, and other distributed systems to store configuration. It typically has no authentication and exposes cluster state.",
            "Block port 2181 from the internet. Enable ZooKeeper authentication (SASL/Kerberos). ZooKeeper should only be accessible within the cluster network."),

        new(4848,  "TCP", "GlassFish Admin",  Severity.High,
            "GlassFish application server admin exposed",
            "GlassFish's admin console on 4848 provides full application server control. Default credentials (admin/adminadmin) are widely known.",
            "Block port 4848 from the internet. Change default credentials. Restrict admin access to a VPN or jump host."),

        new(5601,  "TCP", "Kibana",           Severity.High,
            "Kibana exposed — potential data access",
            "Kibana provides a web UI to all data in your Elasticsearch cluster. Without authentication, anyone can read, delete, or modify indexed data.",
            "Enable Elasticsearch security features (X-Pack/basic auth). Place Kibana behind a reverse proxy with authentication, or restrict access to VPN."),

        new(7001,  "TCP", "WebLogic",         Severity.Critical,
            "Oracle WebLogic server exposed",
            "WebLogic on port 7001 has a history of critical deserialization and SSRF vulnerabilities allowing unauthenticated RCE (CVE-2020-14882, CVE-2021-2394).",
            "Apply all Oracle Critical Patch Updates immediately. Block port 7001 from the internet."),

        new(8500,  "TCP", "Consul",           Severity.High,
            "Consul service mesh exposed",
            "Consul's HTTP API on 8500 provides full read/write access to service registry, health checks, KV store, and ACL tokens. Without ACLs it is completely open.",
            "Enable Consul ACLs and TLS. Block port 8500 from the internet. Consul should only be accessible within the service mesh or via a VPN."),

        new(8083,  "TCP", "InfluxDB / Alt",   Severity.Medium,
            "Port 8083 exposed — InfluxDB admin or alt service",
            "Port 8083 was the InfluxDB admin console in older versions. It provided full database access with no authentication.",
            "If this is InfluxDB: upgrade to a current version and block 8083. Identify the service and restrict access appropriately."),

        new(8086,  "TCP", "InfluxDB HTTP",    Severity.High,
            "InfluxDB HTTP API exposed",
            "InfluxDB's HTTP API on 8086 stores time-series metrics data. Older versions shipped without authentication, allowing reads and writes to all measurements.",
            "Enable InfluxDB authentication. Block port 8086 from the internet. Use HTTPS."),

        new(8983,  "TCP", "Apache Solr",      Severity.High,
            "Apache Solr admin exposed",
            "Solr's admin interface on 8983 has had critical RCE vulnerabilities (Log4Shell, SSRF). Without authentication, anyone can read indexed data or gain code execution.",
            "Block port 8983 from the internet. Enable Solr authentication. Apply all security patches."),

        new(9000,  "TCP", "Portainer/PHP-FPM", Severity.High,
            "Port 9000 exposed — admin or FastCGI service",
            "Port 9000 is commonly used by Portainer (Docker management UI) and PHP-FPM. Either exposes significant control or is a known attack vector for the PHP-FPM RCE (CVE-2019-11043).",
            "Restrict port 9000 to internal network access only. If this is PHP-FPM, ensure it binds to a Unix socket rather than a TCP port."),

        new(9090,  "TCP", "Prometheus",       Severity.High,
            "Prometheus metrics endpoint exposed",
            "Prometheus exposes detailed internal metrics and labels that can reveal infrastructure topology, service names, and sensitive configuration data.",
            "Restrict Prometheus to internal networks. If external access is needed, add authentication via a reverse proxy."),

        new(9093,  "TCP", "Alertmanager",     Severity.Medium,
            "Prometheus Alertmanager exposed",
            "Alertmanager manages Prometheus alerts. Exposing it can allow alert silencing and exfiltration of alert metadata.",
            "Block port 9093 from the internet. Restrict Alertmanager to the monitoring network."),

        new(9418,  "TCP", "Git Protocol",     Severity.Medium,
            "Git protocol (git://) exposed",
            "Port 9418 is the unauthenticated Git protocol. Even read-only repos expose source code to anyone who reaches this port.",
            "Prefer SSH (port 22) or HTTPS (port 443) for Git access. The git:// protocol provides no authentication."),

        new(10050, "TCP", "Zabbix Agent",     Severity.Medium,
            "Zabbix monitoring agent exposed",
            "Zabbix agent on port 10050 can be queried for system metrics and accepts commands from the Zabbix server. Exposing this to the internet leaks system information.",
            "Block port 10050 from the internet. Restrict Zabbix agent to accept connections only from your Zabbix server IP."),

        new(10051, "TCP", "Zabbix Server",    Severity.High,
            "Zabbix server port exposed",
            "Port 10051 is the Zabbix server's active agent listener. Unauthorized access could allow injection of false monitoring data.",
            "Block port 10051 from the internet. Zabbix server should only receive data from known agents."),

        new(11211, "TCP", "Memcached",        Severity.High,
            "Memcached exposed",
            "Memcached has no authentication. Exposed instances have been used for DDoS amplification attacks exceeding 1 Tbps and for reading cached application data.",
            "Bind Memcached to localhost (--listen=127.0.0.1). Block port 11211 at the firewall. Never expose Memcached to the internet."),

        new(16992, "TCP", "Intel AMT HTTP",   Severity.Critical,
            "Intel AMT (Active Management Technology) exposed",
            "Intel AMT on port 16992 provides out-of-band remote management with full access to the system regardless of OS state. INTEL-SA-00075 allowed unauthenticated access.",
            "Block ports 16992-16993 from the internet immediately. Disable AMT if not in use in the BIOS."),

        new(16993, "TCP", "Intel AMT HTTPS",  Severity.Critical,
            "Intel AMT HTTPS exposed",
            "Intel AMT HTTPS provides the same out-of-band management capabilities as port 16992 but over TLS. Still extremely dangerous to expose.",
            "Block ports 16992-16993 from the internet. Disable AMT in BIOS if not needed."),

        new(50000, "TCP", "SAP Dispatcher",   Severity.High,
            "SAP application server dispatcher exposed",
            "Port 50000 is commonly used by SAP application servers. SAP systems contain critical business data and SAP-specific exploits are actively used by threat actors.",
            "Block SAP ports from the internet. SAP should only be accessible via a dedicated VPN or SAP Web Dispatcher with authentication."),

        new(50070, "TCP", "Hadoop NameNode",  Severity.High,
            "Hadoop NameNode web UI exposed",
            "The Hadoop NameNode web interface exposes filesystem metadata, cluster configuration, and in some versions allows unauthenticated file access.",
            "Restrict Hadoop admin ports to the internal cluster network. Use Kerberos authentication for Hadoop services."),

        // ── Misc ──────────────────────────────────────────────────────────────
        new(3690,  "TCP", "SVN",              Severity.Medium,
            "Subversion (SVN) repository exposed",
            "The SVN protocol on port 3690 may expose source code repositories. svnserve can be configured to allow anonymous read access.",
            "Require authentication for all SVN operations. Prefer HTTPS-based SVN. Do not expose source code repositories publicly without careful access control review."),

        new(4444,  "TCP", "Metasploit",       Severity.Critical,
            "Metasploit default listener port open",
            "Port 4444 is the default callback port for Metasploit payloads. An open listener on this port could indicate a compromised host or misconfigured pentest tool.",
            "Investigate immediately. If this is a legitimate pentest tool, shut down listeners when not in use and restrict to internal network."),

        new(5060,  "TCP", "SIP",              Severity.High,
            "SIP (VoIP) exposed",
            "SIP on port 5060 is used for VoIP signalling. Exposed SIP services are constantly scanned for toll fraud attacks — attackers place premium-rate calls through your PBX.",
            "Block port 5060 from the internet unless required. Enable SIP registration authentication. Use fail2ban for SIP brute force protection."),

        new(12345, "TCP", "NetBus",           Severity.Critical,
            "NetBus backdoor port open",
            "Port 12345 is associated with the NetBus remote access Trojan and several other malware families. An open listener on this port may indicate a compromised host.",
            "Investigate immediately. Scan the host for malware. Block this port at the firewall."),

        new(31337, "TCP", "Back Orifice",     Severity.Critical,
            "Back Orifice backdoor port open",
            "Port 31337 is the well-known default port for Back Orifice and other RATs. An open port here strongly suggests malware or a pentest tool.",
            "Investigate immediately. Scan the host for malware. Block this port at the firewall and audit all recent access."),
    };

    // ── Deep scan port list (~500 most commonly scanned TCP ports) ─────────────
    private static readonly HashSet<int> DeepScanPorts = new()
    {
        // Well-known ports (1-1023)
        1, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 37, 42, 43, 49, 53,
        67, 68, 69, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 99, 100, 106, 109,
        110, 111, 113, 119, 123, 125, 135, 137, 138, 139, 143, 144, 161, 162,
        179, 194, 199, 264, 389, 406, 407, 443, 444, 445, 458, 464, 465, 481,
        497, 500, 512, 513, 514, 515, 524, 543, 544, 548, 554, 563, 587, 593,
        616, 631, 636, 646, 666, 683, 700, 749, 783, 800, 808, 873, 880, 888,
        900, 902, 988, 989, 990, 992, 993, 995, 999, 1000,
        // Registered ports - remote access / VPN
        1194, 1720, 1723, 1812, 2222, 3389, 4899, 5800, 5900, 5901, 5902,
        5938, 5985, 5986, 6000, 6001, 22222,
        // Registered ports - file / storage
        2049, 3260, 4000, 4001,
        // Registered ports - mail
        1025, 1026, 1027, 1028, 1029, 1030,
        // Registered ports - databases
        1433, 1434, 1521, 3306, 4040, 5432, 5984, 6379, 7474, 9042,
        9200, 9300, 27017, 27018, 27019, 28015,
        // Registered ports - web / proxies / admin
        3000, 3001, 3128, 4443, 4567, 5000, 5001, 7001, 7002, 7070, 7777,
        7780, 8000, 8001, 8006, 8007, 8008, 8009, 8080, 8081, 8082, 8083,
        8084, 8085, 8086, 8088, 8089, 8090, 8180, 8222, 8291, 8333, 8443,
        8500, 8600, 8800, 8888, 9001, 9009, 9080, 9081, 9090, 9091, 9999,
        10000, 10001, 10443, 18080, 18443, 20000, 55443,
        // Registered ports - containers / devops
        2375, 2376, 2379, 2380, 10250, 10251, 10252,
        // Registered ports - messaging / IoT
        1080, 1883, 1900, 1935, 2181, 4369, 5060, 5061, 5222, 5269, 5357,
        5631, 5666, 5671, 5672, 8161, 8883, 9418, 15672, 25672, 61616,
        // Registered ports - monitoring
        9093, 9100, 9418, 10050, 10051, 11211, 19999,
        // Registered ports - enterprise / misc
        1099, 1337, 1443, 1503, 1801, 1863, 2000, 2001, 2082, 2083, 2086,
        2087, 2095, 2096, 2121, 2404, 3268, 3269, 3690, 4224, 4321, 4444,
        4445, 4500, 4567, 4848, 5050, 5080, 5190, 5500, 5601, 6080, 6389,
        6443, 6666, 6667, 6881, 7780, 8500, 8983, 9000, 9501, 9502, 10051,
        12345, 14147, 16992, 16993, 25000, 27374, 31337, 50000, 50070, 51820,
    };

    // ── Port-to-service name map for generic deep scan rules ──────────────────
    private static readonly Dictionary<int, string> PortNames = new()
    {
        { 1,    "TCP Port Multiplexer" }, { 7,    "Echo" }, { 9,    "Discard" },
        { 13,   "Daytime" }, { 17,   "QOTD" }, { 19,   "Chargen" },
        { 24,   "Private Mail" }, { 26,   "RSFTP" }, { 37,   "Time" },
        { 42,   "Host Name Server" }, { 43,   "WHOIS" }, { 49,   "TACACS" },
        { 67,   "DHCP Server" }, { 68,   "DHCP Client" }, { 70,   "Gopher" },
        { 79,   "Finger" }, { 81,   "HTTP alt" }, { 82,   "XFER Utility" },
        { 83,   "MIT ML Device" }, { 84,   "CTF Protocol" }, { 85,   "MIT ML Device" },
        { 88,   "Kerberos" }, { 89,   "SU/MIT Telnet" }, { 99,   "MetaGram Relay" },
        { 100,  "NIC host name" }, { 106, "3COM-TSMUX" }, { 109, "POP2" },
        { 113,  "Ident" }, { 119, "NNTP" }, { 125, "Locus-MAP" },
        { 144,  "News transfer" }, { 162, "SNMP Trap" }, { 179, "BGP" },
        { 194,  "IRC" }, { 199, "SMUX" }, { 264, "BGMP" },
        { 406,  "Interactive Mail" }, { 407, "Timbuktu" }, { 444, "SNPP" },
        { 458,  "Apple QuickTime" }, { 464, "Kpasswd" }, { 481, "Ph service" },
        { 497,  "Retrospect" }, { 524, "NCP" }, { 543, "Klogin" },
        { 544,  "Kshell" }, { 563, "NNTPS" }, { 616, "SCO System Admin" },
        { 646,  "LDP" }, { 666, "Doom" }, { 683, "CORBA IIOP" },
        { 700,  "EPP" }, { 749, "Kerberos Admin" }, { 783, "SpamAssassin" },
        { 800,  "mdbs-daemon" }, { 808, "Microsoft SOAP" }, { 880, "Unknown" },
        { 888,  "AccessBuilder" }, { 900, "OMG Initial Refs" },
        { 988,  "Pubsub" }, { 992, "Telnet TLS" }, { 999, "Puprouter" },
        { 1000, "CADLOCK2" }, { 1025, "NFS or IIS" }, { 1026, "LSA or NFS" },
        { 1027, "IIS" }, { 1028, "Unknown" }, { 1029, "MS DCOM" },
        { 1030, "MS DCOM" }, { 1099, "Java RMI" }, { 1337, "WASTE" },
        { 1434, "MSSQL Monitor" }, { 1443, "IES-LM" }, { 1503, "NetMeeting" },
        { 1720, "H.323/Q.931" }, { 1801, "MSMQ" }, { 1812, "RADIUS" },
        { 1863, "MSN Messenger" }, { 1935, "Flash/RTMP" }, { 2000, "Cisco SCCP" },
        { 2001, "CAPTAN Server" }, { 2082, "cPanel HTTP" }, { 2083, "cPanel HTTPS" },
        { 2086, "WHM HTTP" }, { 2087, "WHM HTTPS" }, { 2095, "cPanel Webmail HTTP" },
        { 2096, "cPanel Webmail HTTPS" }, { 2121, "FTP Proxy" }, { 2380, "etcd Peer" },
        { 2404, "IEC 60870-5-104" }, { 3000, "Dev Server / Grafana" },
        { 3001, "Dev Server" }, { 3260, "iSCSI" }, { 4000, "ICQ" },
        { 4001, "NewOak" }, { 4040, "Spark UI" }, { 4224, "ClearVisn" },
        { 4321, "RWHOIS" }, { 4443, "PHAROS" }, { 4445, "UPnP alt" },
        { 4500, "IPsec NAT-T" }, { 4567, "TRAM" }, { 5050, "Yahoo Messenger" },
        { 5061, "SIP TLS" }, { 5080, "OnSIP" }, { 5190, "AIM/ICQ" },
        { 5222, "XMPP Client" }, { 5269, "XMPP Server" }, { 5500, "VNC Listener" },
        { 5631, "pcANYWHERE" }, { 5666, "NRPE (Nagios)" }, { 5671, "AMQP TLS" },
        { 6080, "HTTP Alt" }, { 6389, "clariion-evr01" }, { 6443, "Kubernetes API" },
        { 6666, "IRC" }, { 6667, "IRC" }, { 6881, "BitTorrent" },
        { 7002, "WebLogic SSL" }, { 7070, "RealServer" }, { 7777, "iChat" },
        { 7780, "Unknown" }, { 8001, "VCOM Tunnel" }, { 8007, "AJP Connector" },
        { 8008, "HTTP alt" }, { 8009, "AJP Connector" }, { 8081, "BlackIce" },
        { 8082, "Synology Proxy" }, { 8084, "Unknown" }, { 8085, "Unknown" },
        { 8088, "HTTP alt" }, { 8089, "Splunk Management" }, { 8090, "HTTP alt" },
        { 8180, "HTTP alt" }, { 8222, "VMware Server" }, { 8291, "Winbox (Mikrotik)" },
        { 8333, "Bitcoin" }, { 8600, "Unknown" }, { 8800, "SunWebAdmin" },
        { 9001, "ETL Service" }, { 9009, "Pichat Server" }, { 9080, "HTTP alt" },
        { 9081, "HTTP alt" }, { 9091, "HTTP alt" }, { 9418, "Git" },
        { 9501, "Unknown" }, { 9502, "Unknown" }, { 9999, "Urchin" },
        { 10000, "Webmin" }, { 10001, "SCP Config" }, { 10051, "Zabbix Server" },
        { 10251, "Kubernetes Scheduler" }, { 10252, "Kubernetes Controller" },
        { 10443, "HTTPS alt" }, { 14147, "FileZilla Admin" }, { 18080, "HTTP alt" },
        { 18443, "HTTPS alt" }, { 19999, "Netdata" }, { 20000, "Usermin" },
        { 25000, "ICAP" }, { 27374, "Sub7 Trojan" }, { 51820, "WireGuard" },
        { 55443, "HTTPS alt" }, { 61616, "ActiveMQ Broker" },
    };

    // ── Profile port lists ─────────────────────────────────────────────────────
    public static IEnumerable<SecurityRule> GetRulesForProfile(ScanProfile profile)
    {
        if (profile != ScanProfile.Deep)
        {
            return profile switch
            {
                ScanProfile.Quick => Rules.Where(r => r.Severity is Severity.Critical or Severity.High),
                _                 => Rules,
            };
        }

        // Deep: all specific rules + generic Info rules for remaining deep-scan ports
        var rulesByPort = Rules
            .Where(r => r.Port > 0 && !string.IsNullOrEmpty(r.Title))
            .ToDictionary(r => r.Port);

        return DeepScanPorts
            .Select(port => rulesByPort.TryGetValue(port, out var rule) ? rule : MakeGenericRule(port))
            .OrderBy(r => r.Port);
    }

    private static SecurityRule MakeGenericRule(int port)
    {
        PortNames.TryGetValue(port, out var svc);
        svc ??= "Unknown service";
        return new SecurityRule(
            port, "TCP", svc, Severity.Info,
            $"Port {port} open ({svc})",
            $"Port {port} ({svc}) is open. No specific security analysis is defined for this port.",
            "Verify this port should be publicly accessible. If the service is not needed externally, close it at the firewall.");
    }

    public static SecurityFinding Analyze(SecurityRule rule, bool isOpen, string? banner = null)
        => new(rule, isOpen, banner);
}
