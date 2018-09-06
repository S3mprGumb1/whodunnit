$NumericalVersion = $null
$DataList = $null
$job = Invoke-Command -ComputerName "192.168.1.2" -Credential "Time to Fuck Around" -AsJob -FilePath C:\Users\camdo\Desktop\SystemScraper.ps1 
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


Start-Sleep 10
Clear-Host 
Write-Host "--Data Collection Complete.--`n"
Write-Host "1: Time and Location   Information   7: Scheduled Task Information"
Write-Host "2: OS + Kernel Version Information   8: Network Config Information"
Write-Host "3: System and Hardware Information   9: Wifi + Sharing Information"
Write-Host "4: Domain Controller's Information  10: Installed Software"
Write-Host "5: Hostname and Domain Information  11: Process Listing"
Write-Host "6: Domain User Account Information  12: Driver Listing"
Write-Host "7: Startup + Boot Task Information  13: User Downloads`n"

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
    
    }
    
    '6' {
    
    }
    
    '7' {
    
    }
    
    '8' {
    
    }
    
    '9' {
    
    }
    
    '10' {
    
    }
    
    '11' {
    
    }
    
    '12' {
    
    }
    
    '13' {
    
    }


}
} while (1 -eq 1)