$scriptDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

$UserResponse0 = Read-Host "Execute Locally or Remote? [L|R] > "
if ($UserResponse0 -eq "R") {
    $CredUser = Read-Host "Remote Target Admin Username > "
    $TargetIP = Read-Host "Target FQDN or IP > "
    
} else {
    $CredUser = Read-Host "Admin Username > "
    $TargetIP = "127.0.0.1"
}
$job = Invoke-Command -ComputerName $TargetIP -Credential $CredUser -AsJob -FilePath $scriptDir\SystemScraper.ps1 
$DataList = $null
Write-Host "`nReading Data from target... Be Patient`n"
Wait-Job $job
$DataList = Receive-Job $job  
    

    $TargetDate = $DataList.Item("TargetDate")
    $TargetTimeZone = $DataList.Item("TargetTimeZone")
    $Uptime = $DataList.Item("Uptime" )
    $NumericalVersion = $DataList.Item("NumericalVersion")
    $EditionVersion = $DataList.Item("EditionVersion")
    $Hostname = $DataList.Item("Hostname")
    $CPUInfo = $DataList.Item("CPUInfo")
    $RAMInfo = $DataList.Item("RAMInfo")
    $HDDInfo = $DataList.Item("HDDInfo")
    $ActiveDirectory = $DataList.Item("ActiveDirectory")
    $AllDCs = $DataList.Item("AllDCs")
    $Domain = $DataList.Item("Domain")
    $StartupPrograms = $DataList.Item("StartupPrograms")
    $StartupServices = $DataList.Item("StartupServices")
    $ScheduledTasks = $DataList.Item("ScheduledTasks")
    $NetMacs = $DataList.Item("NetMacs")
    $DefaultGateway = $DataList.Item("DefaultGateway")
    $DNSServers = $DataList.Item("DNSServers")
    $IPv4Addresses = $DataList.Item("IPv4Addresses")
    $IPv6Addresses = $DataList.Item("IPv6Addresses")
    $ARPTable = $DataList.Item("ARPTable")
    $RoutingTable = $DataList.Item("RoutingTable")
    $ListeningTableTCP = $DataList.Item("ListeningTableTCP")
    $ListeningTableUDP = $DataList.Item("ListeningTableUDP")
    $EstablishedTable = $DataList.Item("EstablishedTable")
    $DNSCache = $DataList.Item("DNSCache")
    $NetworkShares = $DataList.Item("NetworkShares")
    $Printers = $DataList.Item("Printers")
    $Profiles = $DataList.Item("Profiles")
    $Software = $DataList.Item("Software")
    $Processes = $DataList.Item("Processes")
    $Drivers = $DataList.Item("Drivers")
    $DomainUsers = $DataList.Item("DomainUsers")
    $LocalUsers = $DataList.Item("LocalUsers")
    $ServiceUsers = $DataList.Item("ServiceUsers")
    $UserFileList = $DataList.Item("UserFileList")


Start-Sleep 10
Clear-Host 
Write-Host "--Data Collection Complete.--`n"
Write-Host "1: Time and Location   Information   7: Scheduled Task Information"
Write-Host "2: OS + Kernel Version Information   8: Network Config Information"
Write-Host "3: System and Hardware Information   9: Wifi + Sharing Information"
Write-Host "4: Domain Controller's Information  10: Installed Software"
Write-Host "5: Hostname and Domain Information  11: Process Listing"
Write-Host "6: Domain User Account Information  12: Driver Listing"
Write-Host "7: Startup + Boot Task Information  13: User File Information`n"
Write-Host "20: Write to Local Disk"

do {
Write-Host "> " -NoNewLine
$DisplaySelection1 = $Host.UI.ReadLine()
switch ($DisplaySelection1) {

    '1' {
        Write-Host "`n-- Time and Location Information --`n"
        Write-Host "Date ......... $TargetDate"
        Write-Host "Time Zone ... $TargetTimeZone"
        Write-Host "Uptime ....... $Uptime"
        Write-Host "`n-----------------------------------`n"
    }

    '2' {
        Write-Host "`n-- OS + Kernel Version Information --`n"
        Write-Host "Numerical Version ... $NumericalVersion"
        Write-Host "Edition ............. $EditionVersion"
        Write-Host "`n-------------------------------------`n"
    
    }
    
    '3' {
        Write-Host "`n-- System and Hardware Information --`n"
        Write-Host "`n--- CPU Specs ---`n"

        foreach ($CPU in $CPUInfo) {
            Write-Host "CPU ID ............. " -NoNewline ; Write-Host $CPU.DeviceID
            Write-Host "Cpu Manufacturer ... " -NoNewline ; Write-Host $CPU.Manufacturer
            Write-Host "Cpu Name ........... " -NoNewline ; Write-Host $CPU.Name
            
        }
        Write-Host "`n--- RAM Specs ---`n"

        Write-Host "Total Installed RAM ... $RAMInfo GB"
        
        Write-Host "`n--- HDD Specs ---`n"

        foreach ($HDD in $HDDInfo) {
            Write-Host "HDD Name ......... " -NoNewline ; Write-Host $HDD.Name
            Write-Host "HDD Filesystem ... " -NoNewline ; Write-Host $HDD.FileSystem
            Write-Host "HDD Capacity ..... " -NoNewline ; $HDD | Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.sum / 1GB),2)} | % {Write-Host "$_ GB`n" }

        }

        Write-Host "`n-------------------------------------`n"
    }
    
    '4' {
        
        Write-Host "`n-- Domain Controller's Information --`n"

        if ($ActiveDirectory -eq "True") {    

            foreach ($DC in $AllDCs) {
                Write-Host "Hostame ........ " -NoNewline ; Write-Host $DC.Name
                Write-Host "IPv4 Address ... " -NoNewline ; Write-Host $DC.ipv4Address
            }       
        
        } else {Write-Host "`nActive Directory is not in use! `n"}

        foreach ($DNSserver in $DNSServers) {
            Write-Host "DNS Server ........." -NoNewline ; Write-Host $DNSserver.ServerAddress
        }
        
        Write-Host "`n-------------------------------------`n"
    }
    
    '5' { 
        Write-Host "`n-- Hostname and Domain Information --`n"

        Write-Host "Hostname ... $Hostname"
        Write-Host "Domain ..... $Domain"

        Write-Host "`n-------------------------------------`n"
    }
    
    '6' {
        
        if ($ActiveDirectory -eq "True") {
            Write-Host "AD Users ... $DomainUsers"
        }
        Write-Host "Local Users ----------"
        $LocalUsers | Select -Property Name,AccountType,SID | Write-host

        foreach ($ServiceUser in $ServiceUsers) {
            write-host "SID ............ " -NoNewline ; Get-WmiObject win32_useraccount -Filter "name = $ServiceUser"
            Write-Host "Service User ... $ServiceUser" 
        } 
    }
    
    '7' {
        Write-Host "Services -----"
        $StartupServices
        Write-host "Programs -----"
        $StartupPrograms

        $ScheduledTasks
    }
    
    '8' {
        Write-host "ARP Table -----"
        $ARPTable
        Write-Host "MAC Addresses"
        $NetMacs
        Write-Host "Routing Table"
        $RoutingTable
        Write-host "IP Addresess"
        $IPv4Addresses
        $IPv6Addresses
        Write-Host "DHCP Server"

        Write-Host "DNS Server"
        $DNSServer
        Write-Host  "Default Gateway"
        $DefaultGateway
        Write-Host "Listening Services"
        $ListeningTableTCP
        $ListeningTableUDP
        Write-Host "Established Connections"
        $EstablishedTable
        Write-Host "DNS Cache"
        $DNSCache
    }
    
    '9' {
        Write-Host "Network Shares"
        $NetworkShares
        Write-Host "Printers"
        $Printers
        Write-Host "Wifi Profiles"
        $Profiles
    
    }
    
    '10' {
        Write-Host "Installed Software"
        $InstalledSoftware
    }
    
    '11' {
        $Processes | Format-Table @{l="Process Name";e='ProcessName'},@{l="PID";e='Id'},@{l="User";e='UserName'},@{l="Location";e='Path'}
        $Processes | Format-Table @{l="Process Name";e='ProcessName'},@{l="Parent";e='MainModule'}
    }
    
    '12' {
        Write-Output "-----------Boot Critical Drivers----------"
        $Drivers | Where-Object -Property BootCritical -eq "True" | select Driver,version,date,ProviderName
        Write-Output ""
        Write-Output "---------Boot Critical Drivers Cont--------"
        $Drivers | Where-Object -Property BootCritical -eq "True" | select Driver,OriginalFilename | Format-Table

        Write-Output "-------------Non Critical Drivers--------------"
        $Drivers | Where-Object -Property BootCritical -ne "True" | select Driver,version,date,providername
        Write-Output ""
        Write-Output "-----------Non Critical Drivers Cont.----------"
        $Drivers | Where-Object -Property BootCritical -ne "True" | select Driver,OriginalFilename | Format-Table

    }
   
    '13' {
        Write-Output $UserFileList
    }

    '20' {
        Write-host "Writing to C:\cmd7983\SystemScrape.csv"
        $DataList | Export-Csv 'C:\cmd7983\SystemScrape.csv'
    }
}
} while (1 -eq 1)