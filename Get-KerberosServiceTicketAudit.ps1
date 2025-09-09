### Kerberos Service Tickets Audit - Cipher & Hash Report ###
<#
.SYNOPSIS
Helps to assess Kerberos Cipher and Hash usage in Active Directory environments (e.g. Weak/Deprecated encryption types, or Quantum-resilient candidates).

.DESCRIPTION
Analyses all TGS found in Security event logs of all Domain Controllers in the AD domain (requires 'Event Log Readers' permissions, or equivalent/admin on DCs).
Useful for On-Prem diagnostics, overall attack surface analysis and/or preparation for Server 2025 AD upgrade (by default disables RC4 tickets).

OPTIONAL: Can limit from a certain Time and Date (optional parameter, XX hours ago), for shorter execution and avoid query overload in large environments/large Security Logs.
OPTIONAL: If using an Event Forwarder to log eid 4769 (Kerberos TGS events) from all DCs - can also specify an Event Forwarding server (By default, queries all Domain Controllers' Security events logs)

.NOTES
Comments: 1nTh35h311 (yossis@protonmail.com)
v1.0.4 - Moved to xPath filter to mildly speed up event collection
v1.0.3 - Added better error handling on initial access (e.g. when attempted to perform an unauthorized operation)
v1.0.2 - Added S4U and/or Potential PAC Enumeration detection (Note: the Account performing is the enum is the SERVICE field)
v1.0.1 - Fixed issue with report + added new param to include SPNs (AddSPNsListToReport) - default: not included

.EXAMPLE
.\Get-KerberosServiceTicketAudit.ps1
Analyses all kerberos service tickets, encryption types, user, IP etc. from all DCs in the domain. outputs to CSV file + opens in Grid.

.\Get-KerberosServiceTicketAudit.ps1 -HoursBack 2
Collects events 2 hours back from all Domain Controllers (less runtime, but possibly not collecting all events).

.EXAMPLE
.\Get-KerberosServiceTicketAudit.ps1 -Output 'GRID ONLY'
Analyses all kerberos service tickets from the DCs and opens a grid. No report saved to disk.

.EXAMPLE
.\Get-KerberosServiceTicketAudit.ps1 -EventForwardingServerName SysFwdServer1
Analyses all kerberos service tickets from an event forwarder server (does not collect events from DCs).
Note: Event forwarder should contain eid 4769 from DC(s)
#>

[cmdletbinding()]
param (
        [string]$EventForwardingServerName = $null,
        [int]$HoursBack,
        [ValidateSet("GRID+CSV","GRID ONLY")]$Output = "GRID+CSV",
        [switch]$AddSPNsListToReport
    )

$CurrentEAP = $ErrorActionPreference;
$ErrorActionPreference = "silentlycontinue";

$DCs = (([adsisearcher]'(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))').FindAll() | select -ExpandProperty properties).dnshostname;

# deprecated: previous xml filters (not used on v1.0.4)
$FilterDC = @'
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4769)]]</Select>
  </Query>
</QueryList>
'@

$FilterFwdEvents = @'
<QueryList>
  <Query Id="0" Path="ForwardedEvents">
    <Select Path="ForwardedEvents">*</Select>
  </Query>
</QueryList>
'@

# Set report file name
$ReportName = "$(Get-Location)\KerberosServiceTicketsAudit_$(get-date -Format ddMMyyyyHHmmss).csv";

# Query DCs Security event logs directly (default)
if (!$EventForwardingServerName)                
{
    $Events = $DCs | ForEach-Object {
            $DC = $_;
            # ensure connectivity and at least 1 TGS event for each DC
            $TestForEvent = Get-WinEvent -FilterXPath "*[System[EventID=4769]]" -LogName security -ComputerName $DC -MaxEvents 1;
            if (!$? -or $($TestForEvent | Measure-Object).Count -lt 1)
                {
                        Write-Host "[!] No TGS events found or Access Error on domain controller $DC.`n$($Error[0].Exception.Message)" -ForegroundColor Yellow;
                }
            else
            {
                    Write-Host "Fetching events from domain controller $DC (parsing $("{0:N0}" -f ((Get-WinEvent -ComputerName $DC -ListLog Security).RecordCount)) entries)..."
                    if ($HoursBack)
                        {
                            $HoursbackInMs = $Hoursback * 3600000;
                            Get-WinEvent -ComputerName $DC -Logname Security -FilterXPath "*[System[(EventID=4769) and TimeCreated[timediff(@SystemTime) <= $HoursBackInMS]]]"
                        }
                    else
                        {
                            Get-WinEvent -FilterXPath "*[System[EventID=4769]]" -LogName security -ComputerName $DC
                        }
                }
        }
}
else 
    # Query an event forwarding server log
    {
        # ensure connectivity and at least 1 TGS event found at the forwarding server
        $TestForEvent = Get-WinEvent -FilterXPath "*[System[EventID=4769]]" -LogName 'ForwardedEvents' -ComputerName $EventForwardingServerName -MaxEvents 1;
        if (!$? -or $($TestForEvent | Measure-Object).Count -lt 1)
            {
                Write-Host "[!] No TGS events found or Access Error on $EventForwardingServerName.`n$($Error[0].Exception.Message)" -ForegroundColor Yellow;
                break
            }
        else
        {
        Write-Host "Fetching events from Event Forwarder $EventForwardingServerName (parsing $("{0:N0}" -f ((Get-WinEvent -ComputerName $EventForwardingServerName -ListLog forwardedEvents).RecordCount)) entries)..."
        if ($HoursBack)
                    {
                        $HoursbackInMs = $Hoursback * 3600000;
                        $Events = Get-WinEvent -ComputerName $EventForwardingServerName -Logname 'ForwardedEvents' -FilterXPath "*[System[(EventID=4769) and TimeCreated[timediff(@SystemTime) <= $HoursBackInMS]]]"
                    }
                else
                    {
                        $Events = Get-WinEvent -FilterXPath "*[System[EventID=4769]]"  -Logname 'ForwardedEvents' -ComputerName $EventForwardingServerName
                    }
        }
    }

if (!$Events)
    {
        Write-Warning "No relevant events found. quiting."
        exit
    }

if ($Output -ne "GRID ONLY") {
        # open stream writer for the csv report
        $SW = New-Object System.IO.StreamWriter $ReportName
        $SW.AutoFlush = $true

        if ($AddSPNsListToReport) {
            $SW.WriteLine('UserName,DomainName,Service,ServiceSid,TicketOptions,EtypeDecimal,EtypeHex,EtypeFriendlyName,HashStrengthNotes,IPAddress,IPv4,ComputerName,TimeAccessed,DC,TransmittedServices,SPNs')
        }
        else
            {
            $SW.WriteLine('UserName,DomainName,Service,ServiceSid,TicketOptions,EtypeDecimal,EtypeHex,EtypeFriendlyName,HashStrengthNotes,IPAddress,IPv4,ComputerName,TimeAccessed,DC,TransmittedServices')
        }
    }

$SPNs = @();

$Events | foreach {
    $XML = ([xml]($_.ToXml())).event.eventdata.data;
    $UserName = $XML[0].'#text';
    $DomainName = $XML[1].'#text';
    $Service = $XML[2].'#text';
    $ServiceSid = $XML[3].'#text';
    $TicketOptions = $XML[4].'#text';
    $EtypeHex = $XML[5].'#text';
    $IPAddress = $XML[6].'#text';
    #$Port = $XML[7].'#text';
    $TrasmittedServices = $XML[-1].'#text';
    
    # Attempt to resolve client name    
    if ($IPAddress -ne "::1")
        {
            $IPAddress.Split(":") | ForEach-Object {if ([ipaddress]$_) { $IPv4 = $_}}
            $ComputerName = [System.Net.Dns]::GetHostEntry($IPAddress).HostName
        }
    else
        {
            $IPv4 = "N/A";
            $ComputerName = "localhost"
        }

    #$TimeCreated = $_.timecreated
    #$DC = $_.MachineName.ToUpper()

    # Set ticket encryption values (includes all public Kerberos etypes used by Microsoft and MIT implementations, as well as rare and reserved values, and a default clause for unrecognized values
    Switch ($EtypeHex.ToLower()) {
        "0x00" { $EtypeDecimal=0;  $EtypeFriendlyName='NULL or UNKNOWN'; $HashStrengthNotes='Invalid or error state' }
        "0x01" { $EtypeDecimal=1;  $EtypeFriendlyName='des-cbc-crc'; $HashStrengthNotes='Deprecated; insecure' }
        "0x02" { $EtypeDecimal=2;  $EtypeFriendlyName='des-cbc-md4'; $HashStrengthNotes='Deprecated; insecure' }
        "0x03" { $EtypeDecimal=3;  $EtypeFriendlyName='des-cbc-md5'; $HashStrengthNotes='Deprecated; insecure' }
        "0x04" { $EtypeDecimal=4;  $EtypeFriendlyName='[reserved]'; $HashStrengthNotes='Reserved or unknown use' }
        "0x05" { $EtypeDecimal=5;  $EtypeFriendlyName='des3-cbc-md5'; $HashStrengthNotes='Weak legacy algorithm' }
        "0x06" { $EtypeDecimal=6;  $EtypeFriendlyName='[reserved]'; $HashStrengthNotes='Reserved or unknown use' }
        "0x07" { $EtypeDecimal=7;  $EtypeFriendlyName='des3-cbc-sha1'; $HashStrengthNotes='Weak legacy algorithm' }
        "0x09" { $EtypeDecimal=9;  $EtypeFriendlyName='dsaWithSHA1-CmsOID'; $HashStrengthNotes='Non-TGT OID encoding' }
        "0x0a" { $EtypeDecimal=10; $EtypeFriendlyName='md5WithRSAEncryption-CmsOID'; $HashStrengthNotes='Non-TGT OID encoding' }
        "0x0b" { $EtypeDecimal=11; $EtypeFriendlyName='sha1WithRSAEncryption-CmsOID'; $HashStrengthNotes='Non-TGT OID encoding' }
        "0x0c" { $EtypeDecimal=12; $EtypeFriendlyName='rc2CBC-EnvOID'; $HashStrengthNotes='Non-TGT OID encoding' }
        "0x0d" { $EtypeDecimal=13; $EtypeFriendlyName='rsaEncryption-EnvOID'; $HashStrengthNotes='Non-TGT OID encoding' }
        "0x0e" { $EtypeDecimal=14; $EtypeFriendlyName='rsaES-OAEP-ENV-OID'; $HashStrengthNotes='Non-TGT OID encoding' }
        "0x0f" { $EtypeDecimal=15; $EtypeFriendlyName='des-ede3-cbc-Env-OID'; $HashStrengthNotes='Non-TGT OID encoding' }
        "0x10" { $EtypeDecimal=16; $EtypeFriendlyName='des3-cbc-sha1-kd'; $HashStrengthNotes='Weak legacy algorithm' }
        "0x11" { $EtypeDecimal=17; $EtypeFriendlyName='aes128-cts-hmac-sha1-96'; $HashStrengthNotes='Acceptable; SHA1 HMAC' }
        "0x12" { $EtypeDecimal=18; $EtypeFriendlyName='aes256-cts-hmac-sha1-96'; $HashStrengthNotes='Acceptable; SHA1 HMAC' }
        "0x17" { $EtypeDecimal=23; $EtypeFriendlyName='rc4-hmac'; $HashStrengthNotes='Deprecated; weak (RC4)' }
        "0x18" { $EtypeDecimal=24; $EtypeFriendlyName='rc4-hmac-exp'; $HashStrengthNotes='Deprecated' }
        "0x19" { $EtypeDecimal=25; $EtypeFriendlyName='subkey-keymaterial'; $HashStrengthNotes='Rare or internal use' }
        "0x1a" { $EtypeDecimal=26; $EtypeFriendlyName='aes128-cts-hmac-sha256-128'; $HashStrengthNotes='Strong (SHA-256 HMAC)' }
        "0x1b" { $EtypeDecimal=27; $EtypeFriendlyName='aes256-cts-hmac-sha384-192'; $HashStrengthNotes='Strong (SHA-384 HMAC); Quantum-resilient candidate (Not PQC resistant)' }
        "0x1e" { $EtypeDecimal=30; $EtypeFriendlyName='camellia128-cts-cmac'; $HashStrengthNotes='Rare; not widely adopted' }
        "0x1f" { $EtypeDecimal=31; $EtypeFriendlyName='camellia256-cts-cmac'; $HashStrengthNotes='Rare; not widely adopted' }
        Default { $EtypeDecimal = [convert]::ToInt32($HexEtype, 16); $EtypeFriendlyName = "[Unknown]"; $HashStrengthNotes = "Unlisted or vendor-specific" }
    }

    # Handle SPNs
    if ($AddSPNsListToReport) {
    $SPNData = $([adsisearcher]"(samaccountname=$Service)").FindOne().Properties.serviceprincipalname;

    if ($($SPNData | Measure-Object).Count -gt 1) {
        $SPNData | foreach {$SPNs += "$_|"}
        $SPNs = $SPNs.Substring(0,$SPNs.Length-1)
    }
    else
    {
        $SPNs = ($SPNData | Out-String).Trim()
    }
    }

    # Check for potential S4u / PAC Enumeration
    if ($_.KeywordsDisplayNames -eq 'Audit Failure' -and $XML[8].'#text' -eq '0x1b') {
        $HashStrengthNotes = '[!] S4U | Potential PAC Enumeration'
        Write-Verbose "[!] S4U performed by user $Service | Potential PAC Enumeration"
    }

    # add properties to the event object
    Add-Member -InputObject $_ -MemberType NoteProperty -Name UserName -Value $UserName -Force;
    Add-Member -InputObject $_ -MemberType NoteProperty -Name DomainName -Value $DomainName -Force;
    Add-Member -InputObject $_ -MemberType NoteProperty -Name Service -Value $Service -Force;
    Add-Member -InputObject $_ -MemberType NoteProperty -Name ServiceSid -Value $ServiceSid -Force;
    Add-Member -InputObject $_ -MemberType NoteProperty -Name TicketOptions -Value $TicketOptions -Force;
    Add-Member -InputObject $_ -MemberType NoteProperty -Name EtypeDecimal -Value $EtypeDecimal -Force;
    Add-Member -InputObject $_ -MemberType NoteProperty -Name EtypeHex -Value $EtypeHex -Force;
    Add-Member -InputObject $_ -MemberType NoteProperty -Name EtypeFriendlyName -Value $EtypeFriendlyName -Force;
    Add-Member -InputObject $_ -MemberType NoteProperty -Name HashStrengthNotes -Value $HashStrengthNotes -Force;
    Add-Member -InputObject $_ -MemberType NoteProperty -Name IPAddress -Value $IPAddress -Force;
    Add-Member -InputObject $_ -MemberType NoteProperty -Name IPv4 -Value $IPv4 -Force;
    Add-Member -InputObject $_ -MemberType NoteProperty -Name ComputerName -Value $ComputerName -Force;
    Add-Member -InputObject $_ -MemberType NoteProperty -Name TransmittedServices -Value $TrasmittedServices -Force;
    if ($AddSPNsListToReport) {Add-Member -InputObject $_ -MemberType NoteProperty -Name SPNs -Value $SPNs -Force}
    # + TimeCreated, DC (MachineName) from event object

    # save to report, if specified
    if ($Output -ne "GRID ONLY") {
            if ($AddSPNsListToReport) {
                $SW.WriteLine("$UserName,$DomainName,$Service,$ServiceSid,$TicketOptions,$EtypeDecimal,$EtypeHex,$EtypeFriendlyName,$HashStrengthNotes,$IPAddress,$IPv4,$ComputerName,$($_.TimeCreated),$($_.MachineName),$TrasmittedServices,$SPNs")
            }
            else
                {
                $SW.WriteLine("$UserName,$DomainName,$Service,$ServiceSid,$TicketOptions,$EtypeDecimal,$EtypeHex,$EtypeFriendlyName,$HashStrengthNotes,$IPAddress,$IPv4,$ComputerName,$($_.TimeCreated),$($_.MachineName),$TrasmittedServices")
            }
        }

    Clear-Variable XML, UserName, DomainName, IPAddress, ServiceSid, IPv4, TicketOptions, etypehex, Computername, Service, TimeCreated, transmittedservices, SPNs, SPNData -ErrorAction SilentlyContinue
}

## Wrap up
# Show some statistics
"Total Number of Kerberos Service events: $("{0:N0}" -f $Events.Count)";

# Show stats for weak\deprecated eTypes
$WeakDeprecated = $Events | Where-Object {$_.EtypeHEx -in "0x01","0x02","0x03","0x05","0x07","0x10","0x17","0x18"}

if ($WeakDeprecated)
    {
        "Total Number of Weak\Deprecated Kerberos Service events: $("{0:N0}" -f $WeakDeprecated.Count)`n"
    }

# show total count per ticket eType
$Events | group eTypeHex | sort Count -Descending | select @{n="Etype (Hex)";e={$_.Name}}, @{n="Encryption type";e={$_.Group[0].EtypeFriendlyName}}, @{n="Hash Strength \ Notes";e={$_.Group[0].HashStrengthNotes}}, @{n="Count";e={$("{0:N0}" -f $_.Count)}}

# close report
if ($Output -ne "GRID ONLY") {
        # close streamWriter and handles
        $sw.Close()
        $sw.Dispose()

        if ($(Get-Content $ReportName -TotalCount 3).count -eq 1) 
            { # no TGS discovered
                Write-Host "No Kerberos Service Tickets discovered. Quiting." -NoNewline -ForegroundColor Yellow;
                Remove-Item $ReportName -Force
            }

        else
            {
                "`nReport saved to $ReportName."
            }
    }

# Open grid with detailed events
if ($AddSPNsListToReport)
    {
        $Events | select username, DomainName, service, ServiceSid, ticketoptions, etypeDecimal, eTypeHex, eTypeFriendlyName, HashStrengthNotes, ipaddress, ipv4, computername,  @{n='TimeAccessed';e={$_.TimeCreated}}, @{n='DC';e={$($_.MachineName).toupper()}}, transmittedservices, SPNs | Out-GridView -Title "Kerberos Service Tickets Cipher & Hash Audit Report"
    }
else
    {
        $Events | select username, DomainName, service, ServiceSid, ticketoptions, etypeDecimal, eTypeHex, eTypeFriendlyName, HashStrengthNotes, ipaddress, ipv4, computername,  @{n='TimeAccessed';e={$_.TimeCreated}}, @{n='DC';e={$($_.MachineName).toupper()}}, transmittedservices | Out-GridView -Title "Kerberos Service Tickets Cipher & Hash Audit Report"
    }

# release events data from memory
Clear-Variable Events;
[gc]::Collect();
$ErrorActionPreference = $CurrentEAP