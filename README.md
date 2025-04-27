## Get-KerberosServiceTicketAudit - Cipher & Hash Report ##
Helps to assess Kerberos Cipher and Hash usage in Active Directory environments (e.g. Weak/Deprecated encryption types, or Quantum-resilient candidates).<br>

#### DESCRIPTION ####
Analyses all TGS found in Security event logs of all Domain Controllers in the AD domain (requires 'Event Log Readers' permissions, or equivalent/admin on DCs).<br>
Useful for On-Prem diagnostics, overall attack surface analysis and/or preparation for Server 2025 AD upgrade (by default disables RC4 tickets).<br><br>

OPTIONAL: Can limit from a certain Time and Date (optional parameter, XX hours ago), for shorter execution and avoid query overload in large environments/large Security Logs.<br>
OPTIONAL: If using an Event Forwarder to log eid 4769 (Kerberos TGS events) from all DCs - can also specify an Event Forwarding server (By default, queries all Domain Controllers' Security events logs)<br>

 #### EXAMPLES ####
```
.\Get-KerberosServiceTicketAudit.ps1
```
Analyses all kerberos service tickets, encryption types, user, IP etc. from all DCs in the domain. outputs to CSV file + opens in Grid.<br><br>

```
.\Get-KerberosServiceTicketAudit.ps1 -HoursBack 2
```
Collects events 2 hours back from all Domain Controllers (less runtime, but possibly not collecting all events).<br><br>

```
.\Get-KerberosServiceTicketAudit.ps1 -Output 'GRID ONLY'
```
Analyses all kerberos service tickets from the DCs and opens a grid. No report saved to disk.<br><br>

```
.\Get-KerberosServiceTicketAudit.ps1 -EventForwardingServerName SysFwdServer1
```
Analyses all kerberos service tickets from an event forwarder server (does not collect events from DCs).<br>
Note: Event forwarder should contain eid 4769 from DC(s)<br><br>

#### Sample screenshots ####
![Sample results](/screenshots/Get-KerberosServiceAudit1.png) <br>
##### Results summary sample #####
![Sample results](/screenshots/Get-KerberosServiceAudit2.png) <br>
##### Sample results grid #####
![Sample results](/screenshots/Get-KerberosServiceAudit3.png) <br>
##### Sample grid - showing weak/legacy & deprecated encryption #####
