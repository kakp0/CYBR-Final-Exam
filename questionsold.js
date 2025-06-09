const quizData = [
    // --------------------------------------------------------------------------------
    // Network Security
    // --------------------------------------------------------------------------------
    {
        question: "Which network layer is primarily targeted by an ARP spoofing attack?",
        answers: [
            "Layer 1 (Physical Layer)",
            "Layer 2 (Data Link Layer)",
            "Layer 3 (Network Layer)",
            "Layer 4 (Transport Layer)"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "What is the main goal of a CAM table exhaustion attack?",
        answers: [
            "To intercept traffic between two specific hosts on a network.",
            "To cause the switch to act like a hub, broadcasting all packets to all ports.",
            "To assign a single MAC address to all ports on a switch.",
            "To block a specific port on the switch, denying service to one user."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "How does an ICMP Redirect attack manipulate network traffic?",
        answers: [
            "By flooding the network with ICMP echo requests to overwhelm the target.",
            "By sending fragmented ICMP packets that cannot be reassembled correctly.",
            "By tricking a host into sending traffic through a malicious gateway instead of the legitimate one.",
            "By overwhelming the CAM table with fake MAC addresses."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "Which of the following best describes a Smurf attack?",
        answers: [
            "An attack that uses a flood of TCP SYN packets from spoofed IP addresses.",
            "A denial-of-service attack where the attacker sends ICMP echo requests to a broadcast address, with the victim's IP spoofed as the source.",
            "An attack where the attacker sends malformed, oversized ICMP packets to crash the target's OS.",
            "An attack that tricks a switch into broadcasting all network traffic to the attacker's port."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "What is the primary purpose of 'banner grabbing' during a reconnaissance phase?",
        answers: [
            "To flood the target with traffic to test its bandwidth capacity.",
            "To identify the operating system, service versions, and other details of a target host.",
            "To intercept and read unencrypted data packets sent by the target.",
            "To infect the target with a malicious banner that executes code."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "The 'Ping of Death' attack exploits which vulnerability?",
        answers: [
            "A flaw in the TCP three-way handshake process.",
            "The trusting nature of ARP, which does not validate responses.",
            "A buffer overflow vulnerability caused by an IP packet larger than the maximum allowed size.",
            "The switch's limited CAM table memory."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "A TCP SYN flood is a type of what attack classification?",
        answers: [
            "Man-in-the-Middle (MitM) attack",
            "Reconnaissance attack",
            "Denial-of-Service (DoS) attack",
            "Session Hijacking attack"
        ],
        correctAnswerIndex: 2
    },
    {
        question: "Which technique is a primary defense against TCP Session Hijacking?",
        answers: [
            "Using static IP addresses for all hosts.",
            "Disabling all ICMP traffic on the firewall.",
            "Implementing encryption and using unpredictable sequence numbers.",
            "Increasing the size of the server's SYN queue."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "What is the core principle of a Reflection/Amplification attack?",
        answers: [
            "Reflecting the attacker's own traffic back to them to crash their system.",
            "Using publicly accessible servers (like DNS or NTP) to send a large amount of traffic to a victim by spoofing the victim's IP address.",
            "Hijacking a TCP session by reflecting valid packets with a modified payload.",
            "Sending a single large packet that gets fragmented and amplified by the network infrastructure."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "How does a Slowloris attack cause a denial of service on a web server?",
        answers: [
            "By sending a massive volume of GET requests to overwhelm the server's bandwidth.",
            "By exploiting an SQL injection vulnerability to drop the server's database.",
            "By opening many connections to the server and keeping them alive by sending partial HTTP requests very slowly.",
            "By sending oversized packets that cause a buffer overflow in the HTTP service."
        ],
        correctAnswerIndex: 2
    },
    // --------------------------------------------------------------------------------
    // Linux Access Control
    // --------------------------------------------------------------------------------
    {
        question: "What does the `setuid` permission on an executable file allow a user to do?",
        answers: [
            "Change the ownership of the file without being the root user.",
            "Execute the file with the permissions of the file's owner, not the user who ran it.",
            "Ensure that any new files created in the directory inherit the directory's group.",
            "Prevent the file from being deleted by anyone other than the owner."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "A user has a `umask` of 0022. What will the permissions be for a new directory they create?",
        answers: [
            "777 (rwxrwxrwx)",
            "755 (rwxr-xr-x)",
            "666 (rw-rw-rw-)",
            "644 (rw-r--r--)"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "Which command is used to change the user and group ownership of a file simultaneously?",
        answers: [
            "chmod user:group file.txt",
            "chgrp user:group file.txt",
            "setfacl -m u:user,g:group file.txt",
            "chown user:group file.txt"
        ],
        correctAnswerIndex: 3
    },
    {
        question: "What is the purpose of the 'sticky bit' when set on a directory?",
        answers: [
            "It forces all new files in the directory to be owned by the directory's owner.",
            "It prevents users from executing files within that directory.",
            "It ensures that only the file's owner, the directory's owner, or the root user can delete or rename a file within that directory.",
            "It makes the directory 'stick' in memory for faster access."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "Which command would you use to grant a specific user, 'alice', read and write access to a file named 'report.docx' without changing the file's primary owner or group?",
        answers: [
            "chmod u+rw alice report.docx",
            "chown alice report.docx",
            "setfacl -m u:alice:rw- report.docx",
            "usermod -a -G ownergroup alice"
        ],
        correctAnswerIndex: 2
    },
    // --------------------------------------------------------------------------------
    // Web Security
    // --------------------------------------------------------------------------------
    {
        question: "Which of the following is the most effective way to prevent Cross-Site Scripting (XSS) attacks?",
        answers: [
            "Using strong passwords for all user accounts.",
            "Implementing HTTPS to encrypt all traffic.",
            "Validating and sanitizing all user-provided input on both the client and server side.",
            "Using anti-CSRF tokens in all web forms."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "How does a Cross-Site Request Forgery (CSRF) attack work?",
        answers: [
            "It injects malicious scripts into a trusted website, which then execute in a victim's browser.",
            "It tricks an authenticated user's browser into sending an unintended, malicious request to a web application they are logged into.",
            "It manipulates a website's SQL queries to access or modify database information.",
            "It allows an attacker to traverse the file system of the web server to access restricted files."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "What is the primary defense against SQL Injection (SQLi) attacks?",
        answers: [
            "Using a Web Application Firewall (WAF).",
            "Regularly changing database passwords.",
            "Using parameterized queries (prepared statements) for all database access.",
            "Hiding error messages from the user interface."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "A URL contains the string `../../../../etc/passwd`. What type of attack is likely being attempted?",
        answers: [
            "Cross-Site Scripting (XSS)",
            "SQL Injection (SQLi)",
            "Path/Directory Traversal",
            "Cross-Site Request Forgery (CSRF)"
        ],
        correctAnswerIndex: 2
    },
    {
        question: "What is a key difference between Stored XSS and Reflected XSS?",
        answers: [
            "Stored XSS is permanent until removed, while Reflected XSS requires the user to click a malicious link.",
            "Stored XSS only affects the attacker, while Reflected XSS affects all users of a website.",
            "Stored XSS is a server-side attack, while Reflected XSS is a client-side attack.",
            "Stored XSS cannot be prevented with input validation, whereas Reflected XSS can."
        ],
        correctAnswerIndex: 0
    },
    // --------------------------------------------------------------------------------
    // Firewalls / iptables
    // --------------------------------------------------------------------------------
    {
        question: "In iptables, which chain would you use to filter incoming packets destined for the local machine itself?",
        answers: [
            "FORWARD",
            "PREROUTING",
            "OUTPUT",
            "INPUT"
        ],
        correctAnswerIndex: 3
    },
    {
        question: "What is the purpose of the `nat` table in iptables?",
        answers: [
            "To filter packets based on their source or destination IP address.",
            "To perform Network Address Translation, such as changing the source or destination IP of a packet.",
            "To mangle packets for altering QoS bits or other IP header fields.",
            "To log all packets that pass through the firewall."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "Which iptables command would allow all incoming traffic on port 80 (HTTP)?",
        answers: [
            "iptables -A INPUT -p tcp --dport 80 -j DROP",
            "iptables -A OUTPUT -p tcp --sport 80 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
            "iptables -A FORWARD -p tcp --dport 80 -j ALLOW"
        ],
        correctAnswerIndex: 2
    },
    {
        question: "What is the default policy of a firewall chain, and why is it important for security?",
        answers: [
            "The default policy is ACCEPT; it's secure because it ensures services are always available.",
            "The default policy is REJECT; it's secure because it informs the sender that the packet was blocked.",
            "The default policy is DROP; it's secure because it silently discards packets that don't match a rule, preventing information leakage.",
            "The default policy is LOG; it is secure because it records all traffic for later analysis."
        ],
        correctAnswerIndex: 2
    },
    // --------------------------------------------------------------------------------
    // Zero Trust
    // --------------------------------------------------------------------------------
    {
        question: "What is the fundamental principle of a Zero Trust security model?",
        answers: [
            "Trusting all devices and users inside the corporate network by default.",
            "Never trust, always verify every access request, regardless of where it originates.",
            "Creating a single, highly secure perimeter to keep attackers out.",
            "Focusing security efforts exclusively on protecting sensitive data."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "Which of the following practices is most closely aligned with implementing a Zero Trust model?",
        answers: [
            "Using a single, shared password for team access to internal resources.",
            "Allowing all devices that connect to the internal network to access all services.",
            "Implementing strong perimeter firewalls and relying on them exclusively.",
            "Enforcing multi-factor authentication (MFA) and micro-segmentation of the network."
        ],
        correctAnswerIndex: 3
    },
    // --------------------------------------------------------------------------------
    // Cloud Security
    // --------------------------------------------------------------------------------
    {
        question: "Which one of the following practices is most closely aligned with secure cloud architecture principles?",
        answers: [
            "Using a single, root-level access key for all applications to simplify management.",
            "Disabling all logging to save on storage costs.",
            "Implementing the principle of least privilege using granular Identity and Access Management (IAM) roles.",
            "Storing all data, including secrets and passwords, in a publicly accessible storage bucket."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "According to the shared responsibility model in cloud computing, who is typically responsible for securing the physical infrastructure (e.g., data centers)?",
        answers: [
            "The cloud customer.",
            "The cloud provider (e.g., AWS, Azure, GCP).",
            "A third-party auditor.",
            "Both the customer and the provider share equal responsibility."
        ],
        correctAnswerIndex: 1
    },
    // --------------------------------------------------------------------------------
    // IDS (Intrusion Detection Systems)
    // --------------------------------------------------------------------------------
    {
        question: "What is the main advantage of a Network-based IDS (NIDS) over a Host-based IDS (HIDS)?",
        answers: [
            "A NIDS can analyze encrypted traffic without any special configuration.",
            "A NIDS can detect attacks targeting the local host's operating system more effectively.",
            "A NIDS can monitor traffic for an entire network segment from a single point, offering broader visibility.",
            "A NIDS produces fewer false positives than a HIDS."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "How does a signature-based IDS detect malicious activity?",
        answers: [
            "By creating a baseline of normal network behavior and alerting on deviations from that baseline.",
            "By comparing network traffic or system activity against a database of known attack patterns.",
            "By using machine learning algorithms to predict future attacks.",
            "By analyzing the state of network protocols to see if they are used correctly."
        ],
        correctAnswerIndex: 1
    },
    // --------------------------------------------------------------------------------
    // Deception and Honeypots
    // --------------------------------------------------------------------------------
    {
        question: "Which one of the following statements is correct about honeypots?",
        answers: [
            "A honeypot is a critical production system that holds real, sensitive data.",
            "The primary goal of a honeypot is to replace the need for a traditional firewall.",
            "A honeypot is a decoy system designed to attract and trap attackers, allowing security teams to study their methods.",
            "Any traffic going to a honeypot is considered legitimate and should be ignored by security analysts."
        ],
        correctAnswerIndex: 2
    },
    // --------------------------------------------------------------------------------
    // Bastion Hosts
    // --------------------------------------------------------------------------------
    {
        question: "Which of the following is a critical step in hardening a Linux OS to serve as a bastion host?",
        answers: [
            "Installing as many services as possible (e.g., web, mail, FTP) to make it a useful multi-purpose server.",
            "Disabling all system logging and auditing to improve performance.",
            "Minimizing the attack surface by removing all non-essential software, services, and users.",
            "Configuring the firewall to allow all traffic from any source to ensure administrative access is never lost."
        ],
        correctAnswerIndex: 2
    },
    // --------------------------------------------------------------------------------
    // IoT Security
    // --------------------------------------------------------------------------------
    {
        question: "Which one of the following practices is least aligned with secure IoT design principles?",
        answers: [
            "Implementing a secure mechanism for over-the-air (OTA) firmware updates.",
            "Shipping devices with unique, randomly generated default passwords.",
            "Using encrypted communication protocols for all data transmission.",
            "Using hardcoded, unchangeable credentials for administrative access."
        ],
        correctAnswerIndex: 3
    },
    {
    question: "Which of the following describes a Ping flood attack?",
    answers: [
        "Sending oversized ICMP packets to crash the target's operating system.",
        "Tricking a host into sending traffic to a malicious gateway.",
        "Overwhelming a target with a high volume of ICMP Echo Request packets.",
        "Sending ICMP echo requests to a broadcast address with a spoofed source IP."
    ],
    correctAnswerIndex: 2
},
{
    question: "What is the mechanism behind an ICMP Teardrop attack?",
    answers: [
        "Sending a flood of ICMP reply packets without sending any requests.",
        "Sending overlapping, fragmented IP packets that the target's OS cannot reassemble, causing it to crash.",
        "Using ICMP to redirect routing paths for traffic sniffing.",
        "Blocking all ICMP traffic to prevent network diagnostics."
    ],
    correctAnswerIndex: 1
},
{
    question: "An attacker sends a stream of TCP packets where the header flags (SYN, FIN, RST, etc.) are all set to zero. What type of attack is this?",
    answers: [
        "IP Null Attack",
        "TCP SYN-ACK Flood",
        "UDP Fraggle Attack",
        "Ping of Death"
    ],
    correctAnswerIndex: 0
},
{
    question: "How is a UDP Fraggle attack similar to a Smurf attack?",
    answers: [
        "Both use TCP SYN packets to exhaust server resources.",
        "Both exploit a vulnerability in the IP fragmentation process.",
        "Both send packets to a network broadcast address to amplify traffic, but Fraggle uses UDP echo packets instead of ICMP.",
        "Both rely on sending malformed UDP packets to cause a buffer overflow."
    ],
    correctAnswerIndex: 2
},
{
    question: "What occurs during a UDP Ping-Pong attack?",
    answers: [
        "Two servers are tricked into sending UDP packets back and forth to each other in a loop, consuming network resources.",
        "A server is flooded with UDP packets from a single, high-bandwidth source.",
        "An attacker rapidly alternates between sending UDP and ICMP packets to confuse firewalls.",
        "A single large UDP packet is fragmented and sent to the target."
    ],
    correctAnswerIndex: 0
},
{
    question: "What is the primary goal of a TCP SYN-ACK flood?",
    answers: [
        "To exhaust the resources of a stateful firewall or load balancer by tricking it into creating many half-open connections.",
        "To force a target server to send a large volume of RST (reset) packets.",
        "To hijack an existing TCP session by guessing the sequence numbers.",
        "To send a client a flood of SYN-ACK packets without it ever sending a SYN."
    ],
    correctAnswerIndex: 0
},
{
    question: "In a TCP Reset (RST) attack, what is the attacker's objective?",
    answers: [
        "To open as many connections as possible on a target server.",
        "To flood the target with so many RST packets that it overwhelms its CPU.",
        "To maliciously terminate an existing, legitimate TCP connection between two hosts by sending spoofed RST packets.",
        "To reset the attacker's own connection to evade detection."
    ],
    correctAnswerIndex: 2
},
{
    question: "An attacker sends a large number of packets with the FIN flag set to a target that has no active sessions. What kind of attack is this?",
    answers: [
        "ICMP Teardrop Attack",
        "TCP RST/FIN Flood",
        "Session Hijacking",
        "UDP Ping-Pong"
    ],
    correctAnswerIndex: 1
},
{
    question: "Analyze the following Scapy code. What type of network attack is it attempting to perform? \n\n```python\nfrom scapy.all import IP, TCP, send\ntarget_ip = \"10.0.0.5\"\ntarget_port = 80\n\nip = IP(dst=target_ip)\ntcp = TCP(sport=RandShort(), dport=target_port, flags=\"S\")\nraw = Raw(b\"X\"*1024)\np = ip / tcp / raw\n\nsend(p, loop=1, verbose=0)\n```",
    answers: [
        "Ping of Death",
        "ICMP Redirect",
        "TCP SYN Flood",
        "ARP Spoofing"
    ],
    correctAnswerIndex: 2
},
{
    question: "What is the primary effect of setting the `setgid` permission on a directory?",
    answers: [
        "It causes all executable files within the directory to run with the directory owner's permissions.",
        "It prevents any user other than the owner from creating new files in the directory.",
        "It ensures that any new file or directory created within it will inherit the group ownership of the parent directory.",
        "It automatically grants write permissions to the group for all files inside."
    ],
    correctAnswerIndex: 2
},
{
    question: "Analyze the following Bash script. After it runs, what will be the group owner of the file `/srv/reports/daily.log`? \n\n```bash\n#!/bin/bash\n\ngroupadd auditors\nuseradd -G auditors reporter\nmkdir -p /srv/reports\nchgrp auditors /srv/reports\nchmod g+s /srv/reports\n\ntouch /srv/reports/daily.log\n```",
    answers: [
        "root",
        "reporter",
        "auditors",
        "users"
    ],
    correctAnswerIndex: 2
},
{
    question: "An IDS is monitoring TCP traffic and flags an alert because it sees a SYN-ACK packet from a server that never received an initial SYN packet from a client. What detection method is being used?",
    answers: [
        "Signature-based detection",
        "Anomaly-based detection",
        "Protocol state-based detection",
        "Honeypot detection"
    ],
    correctAnswerIndex: 2
},
{
    question: "An IDS is deployed on a network and spends the first week learning the patterns of normal traffic, building a 'baseline'. Later, it flags a large data transfer at 3 AM because this behavior deviates significantly from the established baseline. This is an example of what type of detection?",
    answers: [
        "Signature-based detection",
        "Anomaly-based detection",
        "Stateful protocol analysis",
        "Manual intervention"
    ],
    correctAnswerIndex: 1
},
{
    question: "An ARP spoofing attack is classified as a Man-in-the-Middle (MitM) attack. Which host-level defense is most effective at preventing it?",
    answers: [
        "Disabling all ICMP traffic on the host.",
        "Creating a static ARP entry for the gateway's IP and MAC address.",
        "Increasing the size of the dynamic ARP cache.",
        "Using a personal software firewall to block incoming connections."
    ],
    correctAnswerIndex: 1
},
{
    question: "A TCP SYN flood is a DoS attack that aims to exhaust a server's connection state table. Which host-level mitigation works by using cryptographic values in place of allocating resources for half-open connections?",
    answers: [
        "Increasing the value of 'net.ipv4.tcp_max_syn_backlog'.",
        "Implementing egress filtering to block spoofed IPs.",
        "Enabling TCP SYN cookies via 'net.ipv4.tcp_syncookies'.",
        "Decreasing the TCP connection timeout value."
    ],
    correctAnswerIndex: 2
},
{
    question: "A Smurf attack is a type of DDoS reflection attack that uses ICMP echo requests. What is the single most effective network-level configuration to PREVENT this attack?",
    answers: [
        "Blocking all inbound ICMP traffic at the firewall.",
        "Disabling IP directed broadcasts on all network routers.",
        "Rate-limiting all TCP and UDP traffic at the network edge.",
        "Implementing reverse DNS lookups for all incoming packets."
    ],
    correctAnswerIndex: 1
},
{
    question: "How can a network administrator prevent their own network from being used as an 'amplifier' in a Smurf attack against another target?",
    answers: [
        "Block all incoming ICMP echo requests at the firewall.",
        "Ensure all hosts on the network have up-to-date antivirus software.",
        "Implement egress filtering (e.g., BCP38) to block outbound packets that have a spoofed source IP.",
        "Use a network intrusion detection system (NIDS) to monitor for suspicious ICMP traffic."
    ],
    correctAnswerIndex: 2
},
// --------------------------------------------------------------------------------
// Appendix: Additional Mitigation & Command Questions for 100% Coverage
// --------------------------------------------------------------------------------
{
    question: "A web server is experiencing a Slowloris attack. Which of the following server-side configurations is the most effective mitigation?",
    answers: [
        "Increasing the server's maximum bandwidth capacity.",
        "Implementing a Web Application Firewall (WAF) with strict SQLi rules.",
        "Setting aggressive connection timeouts and limiting the number of connections per IP address.",
        "Disabling HTTP Keep-Alive functionality entirely."
    ],
    correctAnswerIndex: 2
},
{
    question: "What is the most effective defense against classic IP fragmentation attacks like the 'Ping of Death' and 'ICMP Teardrop'?",
    answers: [
        "Blocking all ICMP traffic at the network firewall.",
        "Keeping the operating system and network stack patched, as modern OSs validate fragment reassembly.",
        "Using a load balancer to distribute the fragmented packets.",
        "Implementing rate-limiting for all incoming TCP connections."
    ],
    correctAnswerIndex: 1
},
{
    question: "Which of the following is the most robust defense against TCP Session Hijacking attacks?",
    answers: [
        "Using a stateful firewall to monitor TCP connections.",
        "Encrypting the entire communication session using a protocol like TLS/SSL.",
        "Increasing the server's TCP backlog queue size.",
        "Regularly clearing the ARP cache on all network hosts."
    ],
    correctAnswerIndex: 1
},
{
    question: "Which feature on a modern network switch is specifically designed to prevent CAM table exhaustion attacks?",
    answers: [
        "Spanning Tree Protocol (STP)",
        "VLAN Tagging (802.1Q)",
        "Port Security (e.g., limiting MAC addresses per port)",
        "Link Aggregation (LACP)"
    ],
    correctAnswerIndex: 2
},
{
    question: "An administrator needs to create a new user named 'jdoe' and ensure their home directory `/home/jdoe` is also created. Which command accomplishes this?",
    answers: [
        "useradd jdoe",
        "useradd -h /home/jdoe jdoe",
        "useradd -m jdoe",
        "useradd --home jdoe"
    ],
    correctAnswerIndex: 2
},
{
    question: "Which command correctly changes only the group ownership of `file.txt` to `editors`?",
    answers: [
        "chown :editors file.txt",
        "chmod g=editors file.txt",
        "chgrp editors file.txt",
        "setgroup editors file.txt"
    ],
    correctAnswerIndex: 2
},

{
    question: "What is the primary function of the `groupadd` command in Linux?",
    answers: [
        "To add an existing user to a new group.",
        "To create a new user group on the system.",
        "To list all members of a specific group.",
        "To set the default group for a user during creation."
    ],
    correctAnswerIndex: 1
}


];