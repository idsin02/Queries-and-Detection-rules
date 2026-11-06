# ARTEX ScopeWeaver BLUEBEAM Threat Detection and Hunting
 
Author: Dhruv Singh | Date: 2026-11-06 | Status: experimental
 
Several separate operators have used ARTEX, an autonomous AI-driven penetration testing framework,
against real organisations. The activity runs from July to October 2026. ARTEX chains automated recon,
headless browser automation, a local TLS-intercepting proxy, and repeated exploit attempts. It labels
each step with a sequential intent ID (`i<digits>_…`), and those labels leave a recognisable naming
pattern in file names, URLs, and cloud deployment descriptions.
 
This package also covers an operator running BLUEBEAM PHP/ASP.NET webshells against Windows IIS and
Linux cPanel/LiteSpeed servers. One BLUEBEAM PHP sample appears in both activity sets, which is why
they share a package.
 
## 1. Summary
 
| Component | CVE / root cause | CVSS | Affected | Fixed | Exploit status | In-the-wild |
|---|---|---|---|---|---|---|
| Linux kernel | CVE-2026-31431 – local privilege escalation (root cause not described in available reporting) | Not published | Not published | Not published | Public Python PoC (`copy_fail_exp.py`) run fileless via `curl \| python3`. Successful escalation **not confirmed**. | Used against cPanel/LiteSpeed (`lsphp`) hosts |
| Unspecified | CVE-2022-31814 – associated with the activity; no exploitation event described | Not published | Not published | Not published | Unknown | Association only |
| Weaver Ecology OA | No CVE. SQLi probe on `/api/cube/form/checkVsql`, then authenticated SQL execution through the DataShow (`datashowset`) table after a credential spray | n/a | Not published | Not published | **Confirmed:** JSP webshells written by poisoning MySQL `general_log_file`. **Partial failure:** injected scriptlets broke recompilation of `/login/Login.jsp`. | Yes |
| Microsoft SQL Server | No CVE. `sqlservr.exe → cmd.exe → curl.exe` under a SQL service account; consistent with xp_cmdshell-style execution | n/a | n/a | n/a | Command execution + outbound beacon confirmed | Yes |
| Azure App Service (Kudu) | No CVE. Valid-credential abuse of `/api/command` and `/api/vfs` | n/a | n/a | n/a | Confirmed | Yes |
| AWS | No CVE. Stolen IAM credential abuse | n/a | n/a | n/a | EC2 DryRun succeeded. Multi-snapshot launch **failed** (UserData > 25,600 bytes). Anonymous `GetBucketLifecycle` **denied**. | Yes |
| IIS / cPanel web apps | Unspecified application vulnerabilities → webshells | n/a | n/a | n/a | Confirmed | Yes (South/Southeast Asia) |
 
**Version caveat:** Distro kernels backport fixes, so `uname -r` alone can't prove exposure to
CVE-2026-31431. Validate against the distro advisory or TVM. EOL kernels may never receive a fix.
 
## 2. Attack flow
1. **Recon:** TCP 8787 service probing, `/.git/HEAD`, `/nuclei.svg`, null-byte LFI tests
(`artex-probe-<n>.html%00.pdf`), and a request for an S3 presigned upload URL for a `.jspx`.
2. **Initial access:** Weaver OA SQL injection and login spraying, stolen Azure service principal or
AWS IAM credentials, and application exploits on IIS/cPanel servers.
3. **Webshell placement:** the attacker points MySQL query logging at a web path, writes JSP code
through logged queries, then disables logging with `SET GLOBAL general_log=0`. Shells accept
`?t=<token>&m=sql|ping|res|https`; a smaller probe shell accepts `?k=<token>&c=<cmd>`.
4. **Execution:** SQL Server spawns `cmd → curl` to an `ntfy.sh/artex-*` topic. On Azure, PowerShell
runs through Kudu `/api/command` as `-File i<id>_<hex>.ps1 -QF *.sql -OF *.out`. Inputs are
uploaded via VFS PUT and output pulled back via VFS GET.
5. **Credentials and pivoting:** the JSP shell tunnels to internal ADFS
(`/adfs/services/trust/13/usernamemixed`) and relays NTLM to obtain SAML tokens. Follow-on
activity: Kerberos user enumeration (0x6 failures), Kerberoasting, a Pass-the-Hash script,
local group enumeration (4798), and an internal SMB/445 sweep.
6. **Cloud:** storage ListKeys, Key Vault SecretGet, `DROP DATABASE SCOPED CREDENTIAL`, ECR/VPC
enumeration, EC2 DryRun, and CodeDeploy pushes of `*_probe_<hex>.zip` archives to production.
7. **Exfil and signalling:** curl/HTTP POST to `*.webhook.site` (AD dumps, krbtgt/gMSA secrets,
LAPS attributes) and to `ntfy.sh/artex-*`.
8. **BLUEBEAM operator:**
- Windows: certutil downloads from an open-directory staging server, then Potato-family
privilege escalation (PrintSpoofer renamed `msp.out`, JayPotato `start.exe`,
`McpManagementPotato.exe` from `C:\ProgramData\`).
- Linux: fileless CVE-2026-31431 PoC and a `/dev/tcp` reverse shell on TCP 8889.
- Every webshell command is wrapped with random hex echo boundaries.
 
## 3. MITRE ATT&CK
| Tactic | Technique |
|---|---|
| Reconnaissance | T1595.002 Vulnerability Scanning; T1590.002 DNS |
| Initial Access | T1190 Exploit Public-Facing Application; T1078.004 Cloud Accounts |
| Execution | T1059.001 PowerShell; T1059.003 Windows Command Shell; T1059.004 Unix Shell; T1059.006 Python; T1059.009 Cloud API; T1651 Cloud Administration Command |
| Persistence | T1505.003 Web Shell |
| Privilege Escalation | T1068 Exploitation for Privilege Escalation; T1134 Access Token Manipulation |
| Defense Evasion | T1070 Indicator Removal; T1036.005 Match Legitimate Name or Location; T1620 Reflective Code Loading; T1202 Indirect Command Execution |
| Credential Access | T1110.003 Password Spraying; T1558.003 Kerberoasting; T1555.006 Cloud Secrets Management Stores; T1552 Unsecured Credentials; T1649 Steal or Forge Authentication Certificates; T1606.002 SAML Tokens |
| Discovery | T1087.002 Domain Account; T1069.001 Local Groups; T1018 Remote System Discovery; T1619 Cloud Storage Object Discovery; T1580 Cloud Infrastructure Discovery |
| Lateral Movement | T1550.002 Pass the Hash; T1550.003 Pass the Ticket; T1021.002 SMB/Windows Admin Shares |
| Command and Control | T1071.001 Web Protocols; T1090.001 Internal Proxy; T1095 Non-Application Layer Protocol; T1571 Non-Standard Port; T1105 Ingress Tool Transfer |
| Exfiltration | T1567.004 Exfiltration Over Webhook; T1041 Exfiltration Over C2 Channel |
| Impact | T1491.001 Internal Defacement; T1565 Data Manipulation |
 
## 4. Detection coverage
| Layer | Signal | File(s) | Fidelity |
|---|---|---|---|
| Exposure | TVM CVE mapping | 00_* | Hunting |
| Execution | Web/DB service → shell or LOLBin | 01_*, sigma/01 | High (sqlservr) / Medium |
| Campaign marker | `artex` strings, intent-ID file names, beacon strings | 02_*, sigma/02, yara/b | High |
| Exfil | Scripted POSTs to ntfy.sh / webhook.site | 03_*, sigma/03 | Medium / Hunting |
| IOC sweep | IPs, hashes | 04_*, yara/a, iocs/ | High (staging/C2) / Hunting (VPN egress) |
| Persistence | Script files written by DB engines or web processes into media/upload paths | 05_*, yara/c | High (mysqld → .jsp) / Medium |
| Campaign marker | BLUEBEAM hex-boundary command wrapper | 06_*, sigma/06, yara/b | High |
| Privilege escalation | Potato command lines, service account → SYSTEM, CVE-2026-31431 PoC | 07_*, sigma/07 | High / Medium |
| Edge / server logs | Weaver endpoints, webshell parameters, Kudu API, probes, zh-CN header | 08_*, sigma/08a-c | High / Medium |
| Cloud | ListKeys, SecretGet, scoped credential drop, EC2 DryRun, CodeDeploy probes | 09_*, sigma/09 | High (literals) / Hunting |
| Post-exploitation | Kerberos 0x6 bursts, 4798 by SQL service, SMB sweep, AD recon tools | 10_*, sigma/10 | Medium / Hunting |
 
## 5. Triage checklist
1. Rebuild the process tree. Note the parent (`w3wp`, `sqlservr`, `lsphp`, `java`, `mysqld`) and the
account context (`IIS APPPOOL\*`, `NT SERVICE\MSSQL*`).
2. Pull web/WAF logs ±1h. Look for `t=&m=` / `k=&c=` parameters, Weaver endpoints, Kudu `/api/vfs`
and `/api/command`, the zh-CN `Accept-Language` header, and `act=` cookies.
3. Run `SHOW VARIABLES LIKE 'general_log%'` on MySQL. Diff the web root for new `.jsp`, `.jspx`,
`.aspx`, `.ashx` or `.php` files, and run yara/a + yara/c over it.
4. Review egress to ntfy.sh, webhook.site, the IOC IPs, and TCP 8889. Record any topic or webhook IDs.
5. Identity: Kerberos 0x6 bursts, TGS requests for service accounts, 4798, and elevated NTLM
network logons sourced from the host. Rotate any SP, IAM or Key Vault secret that was touched.
6. Cloud: review CloudTrail and AzureActivity for the same principal (ListKeys, SecretGet,
RunInstances DryRun, CreateDeployment). Revoke sessions and rotate storage account keys.
 
## 6. Known false positives
- Authorized pentests and red teams, including legitimate ARTEX or nuclei use. Confirm scope first.
- Dev and CI teams using webhook.site or ntfy.sh for notifications.
- Sanctioned xp_cmdshell jobs and SQL Agent tasks that call curl.
- DevOps automation using Kudu/SCM via python-requests or the Azure CLI.
- Java app servers that spawn `sh` for health or maintenance scripts.
- Kerberos 0x6 noise from stale service configs or vulnerability scanners.
- CMS plugin or theme updates writing `.php` files into `wp-content/`.
 
## Confirmed vs theoretical vs failed
- **Confirmed:** Weaver webshell deployment, SQL Server → curl beacon, Kudu execution and file
staging, webhook exfil, CodeDeploy probe deployments, BLUEBEAM webshells, and the `/dev/tcp`
reverse shell.
- **Failed:** multi-snapshot EC2 launch, anonymous S3 lifecycle read, Kerberos probe for `esxi`
(principal unknown), first SMB connection (RST), and Login.jsp recompilation.
- **Not confirmed:** CVE-2022-31814 exploitation, CVE-2026-31431 success, and xp_cmdshell as the
specific SQL execution method.
 
Detections marked **built from described technique, not a sample** have no recovered artifact behind them.
The public PoC is referenced by name only (`copy_fail`, CVE-2026-31431); no exploit repositories are linked.
