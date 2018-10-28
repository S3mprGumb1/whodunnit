#Clear-Host
#Write-Output "Scraping Data Please Wait....."

#Write-Output "Pulling Date and Time Information"
# Times and Rough Location
$TargetDate = Get-Date 
$TargetTimeZone = Get-TimeZone 
$Uptime = ($TargetDate) - (GCIM Win32_OperatingSystem).LastBootUpTime

#Write-Output "Pulling Operating System Information"
# OS Info
$NumericalVersion = [environment]::OSVersion.VersionString
$EditionVersion = (Get-WindowsEdition -Online).Edition
$Hostname = (Get-WmiObject -Class Win32_ComputerSystem -Property Name).Name

#Write-Output "Pulling Hardware Information"
# System Specs
$CPUInfo = Get-CimInstance -ClassName Win32_Processor
$RAMInfo = (Get-WMIObject -class Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.sum / 1GB),2)})
$HDDInfo = Get-CimInstance -ClassName Win32_Volume -Filter "DriveType=3"

#Write-Output "Checking for Active Directory Configuration"
# DC Info
## NOTE AD STUFF IS NOT TESTED ##
$ActiveDirectory = "True"
try {Get-ADDomain} catch {
    #Write-Output "Active Directory Not Found, Skipping."
    $ActiveDirectory = "False"
}

If ($ActiveDirectory -eq "True") {
#Write-Output "Active Directory Found, Pulling Information"
    $AllDCs = (Get-ADForest).Domains | %{ Get-ADDomainController -Filter * -Server $_ }
    $Domain = Get-ADForest.Domains
    $DomainUsers = (Get-ADUser -Filter *)
}


#Write-Output "Pulling Automated Task Information"
$StartupPrograms = Get-CimInstance Win32_StartupCommand | Select-Object Name,User,Command,Location
$StartupServices = Get-Service | Where-Object -Property StartType -EQ  "Automatic" | select -Property name
$ScheduledTasks = Get-ScheduledTask

##Write-Output "Pulling Network Configuration Information"
$NetMacs = Get-NetAdapter -Physical | Select-Object -Property Name,status,macaddress
$DefaultGateway = Get-NetIPConfiguration | foreach ipv4defaultgateway | select NextHop
$DNSServers = Get-NetIPConfiguration | foreach dnsserver | where-object -Property AddressFamily -eq 2 | select -Property InterfaceAlias,ServerAddresses
$IPv4Addresses = Get-NetIPConfiguration | foreach IPv4Address | select -Property interfacealias,ipaddress
$IPv6Addresses = Get-NetIPConfiguration | foreach IPv6Address | select -Property interfacealias,ipaddress
$ARPTable = Get-NetNeighbor
$RoutingTable = Get-NetRoute

#Write-Output "Pulling Information on Listening Services"
#Listening Services
$ListeningTableTCP = @()
$ListeningTableUDP = @()

#TCP Connections

foreach ($listener in Get-NetTCPConnection -State Listen) {
    $locala = $listener.LocalAddress
    $localp = $listener.LocalPort
    $prot   = "TCP"
    $proces = (Get-Process -PID $listener.OwningProcess).ProcessName

    $Props = @{
        "Local Address" = $locala
        "Local Port" = $localp
        "Protocol" = $prot
        "Process Name" = $proces
    }
    $ListeningTableTCP += New-Object PSObject -Property $Props
}


#UDP Connections
foreach ($listener in Get-NetUDPEndpoint) {
    $locala = $listener.LocalAddress
    $localp = $listener.LocalPort
    $prot   = "UDP"
    $proces = (Get-Process -PID $listener.OwningProcess).ProcessName

    $Props = @{
        "Local Address" = $locala
        "Local Port" = $localp
        "Protocol" = $prot
        "Process Name" = $proces
    }
    $ListeningTableUDP += New-Object PSObject -Property $Props
}

#Write Listening Table
#Write-Output $ListeningTable | Format-Table @{l="Local Address";e='Local Address'},@{l="Local Port";e='Local Port'},@{l="Protocol";e='Protocol'},@{l="Process Name";e='Process Name'}

#Write-Output "Pulling Information on Established Connections"
#Established Services
$EstablishedTable = @()

foreach ($listener in Get-NetTCPConnection -State Established | Where-Object -Property LocalAddress -NE "127.0.0.1") {
    $locala = $listener.RemoteAddress
    $localp = $listener.LocalPort
    $remotp = $listener.RemotePort
    $prot   = "TCP"
    $proces = (Get-Process -PID $listener.OwningProcess).ProcessName

    $Props = @{
        "Remote Address" = $locala
        "Local Port" = $localp
        "Remote Port" = $remotp
        "Protocol" = $prot
        "Process Name" = $proces
    }
    $EstablishedTable += New-Object PSObject -Property $Props
}


#Write Established Table
#Write-Output $EstablishedTable | Format-Table @{l="Remote Address";e='Remote Address'},@{l="Remote Port";e='Remote Port'},@{l="Local Port";e='Local Port'},@{l="Protocol";e='Protocol'},@{l="Process Name";e='Process Name'}

#Write-Output "Pulling Information on Local Network Configuration"
#Other Net Artifacts
$DNSCache = Get-DnsClientCache
$NetworkShares = Get-SmbShare
$Printers = Get-Printer | select Name,Type,PortName

#Write-Output "Checking for Wireless Interfaces"
#Dump Wifi Profiles if theres a wifi adapter
If (netsh wlan show profiles -eq 'There is no wireless interface on the system.') { } else {

    #Write-Output "Wireless Interface Detected, Collecting Information"
    $Profiles = @()
    $Profiles += (netsh wlan show profiles) | Select-String "\:(.+)$" | ForEach{$_.Matches.Groups[1].Value.Trim()} |Sort-Object
        #$Profiles | Foreach{$ProfileName = $_; (netsh wlan show profile name="$_" key=clear)} | `
            #Select-String "Key Content\W+\:(.+)$" | `
                #Foreach{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | `
                   # Foreach{[PSCustomObject]@{ PROFILE_NAME=$ProfileName;PASSWORD=$pass }} | `
                       # Format-Table -AutoSize
}

#Write-Output "Collecting Installed Software"
$Software = Get-WmiObject -Class Win32_Product | Sort-Object Name | select Name

##Write-Output "Collecting Running Process Information"
#Process Listing
$Processes = Get-Process -IncludeUserName | select ProcessName,Id,Path,MainModule,UserName 

#Driver Listing
$Drivers = Get-WindowsDriver -Online -All


$ServiceUsers = @()
foreach ($Service in Get-WmiObject win32_service | select StartName) {if($ServiceUsers -notcontains $Service){$ServiceUsers += $Service}}

$UserFileList = @()
cd 'C:\Users\'
$userdirs = ls | select -Property Name
foreach ($userdir in $userdirs) {
    $userdir = $userdir.Name
    $File = @{
        "User" = $userdir
        "Downloads"=ls .\$userdir\Downloads
        "Documents"=ls .\$userdir\Documents
        
    }
    $UserFileList += New-Object PSObject -Property $File
}

$DataList = @{
    "TargetDate" = $TargetDate
    "TargetTimeZone" = $TargetTimeZone
    "Uptime" = $Uptime
    "NumericalVersion" = $NumericalVersion
    "EditionVersion" = $EditionVersion
    "Hostname" = $Hostname
    "CPUInfo" = $CPUInfo
    "RAMInfo" = $RAMInfo
    "HDDInfo" = $HDDInfo
    "ActiveDirectory" = $ActiveDirectory
    "AllDCs" = $AllDCs
    "Domain" = $Domain
    "StartupPrograms" = $StartupPrograms
    "StartupServices" = $StartupServices
    "ScheduledTasks" = $ScheduledTasks
    "NetMacs" = $NetMacs
    "DefaultGateway" = $DefaultGateway
    "DNSServers" = $DNSServers
    "IPv4Addresses" = $IPv4Addresses
    "IPv6Addresses" = $IPv6Addresses
    "ARPTable" = $ARPTable
    "RoutingTable" = $RoutingTable
    "ListeningTableTCP" = $ListeningTableTCP
    "ListeningTableUDP" = $ListeningTableUDP
    "EstablishedTable" = $EstablishedTable
    "DNSCache" = $DNSCache
    "NetworkShares" = $NetworkShares
    "Printers" = $Printers
    "Profiles" = $Profiles
    "Software" = $Software
    "Processes" = $Processes
    "Drivers" = $Drivers
    "DomainUsers" = $DomainUsers
    "LocalUsers" = Get-CimInstance win32_useraccount
    "ServiceUsers" = $ServiceUsers
    "UserFileList" = $UserFileList
}

return $DataList