# Full Active Directory Compromise via ADCS Relay and PetitPotam Coercion

## Overview

This project demonstrates a complete Active Directory attack chain involving:

- AS-REP Roasting
- SMB Enumeration
- ADCS Discovery
- PetitPotam Coercion
- NTLM Relay
- Certificate Abuse

The objective was to obtain Domain Controller-level authentication through certificate-based attacks.

---

## Environment

- Windows Server 2022
- Active Directory
- ADCS Enabled
- SMB Signing Disabled

---

## Attack Path

1. Enumerated Active Directory users
2. Performed AS-REP roasting
3. Cracked user credentials
4. Enumerated SMB shares
5. Identified ADCS infrastructure
6. Triggered PetitPotam coercion
7. Relayed NTLM authentication to ADCS
8. Obtained Domain Controller certificate

---

## Tools Used

- Nmap
- Enum4Linux
- Kerbrute
- NetExec
- JohnTheRipper
- PetitPotam
- Impacket
- Certipy

---

## Impact

Successful exploitation allowed certificate-based authentication as the Domain Controller account.

---

## Detection Opportunities

- Monitor EFSRPC coercion activity
- Detect abnormal certificate enrollment
- Alert on NTLM relay behavior
- Monitor ADCS enrollment logs

---

## Mitigations

- Enable SMB signing
- Disable NTLM where possible
- Restrict ADCS templates
- Enforce Extended Protection for Authentication (EPA)
- Patch coercion vectors
