. $PSScriptRoot\Write-Menu\Write-Menu.ps1


# Menu Functions
function Write-Lame-Menu-Main {

    do {
        Clear-Host
        Write-Host "============================="
        Write-Host "          Whodunnit"
        Write-Host "============================="
        Write-Host
        Write-Host "1) Load Logs"
        Write-Host "2) Active Filter"
        Write-Host "3) Display Logs"
        Write-Host "4) Export Logs"
        Write-Host

    
        $UserInput = Read-Host "whodunnit> "
        
        switch($UserInput) {
            '1' {Write-Lame-Menu-Load}
            '2' {Write-Lame-Menu-Filter}
            '3' {Display-Logs}
            '4' {Export-Logs}
        }
    
    } until ($UserInput -ne "1" -and $UserInput -ne "2" -and $UserInput -ne "3" -and $UserInput -ne "4")

}

function Write-Lame-Menu-Load {

    do {
        Clear-Host
        Write-Host "============================="
        Write-Host "      Whodunnit > Load"
        Write-Host "============================="
        Write-Host
        Write-Host "1) Read From File"
        Write-Host "2) Read From Local Machine"
        Write-Host "3) Read From Remote Machine"
        Write-Host "4) Back"
        Write-Host

    
        $UserInput = Read-Host "whodunnit> Load> "
        
        switch($UserInput) {
            '1' {Import-Logs}
            '2' {Read-From-Local; Return}
            '3' {Write-Host "TODO: This ¯\_(ツ)_/¯";Read-Host}
            '4' {Return}
        }
    
    } until ($UserInput -ne "1" -and $UserInput -ne "2" -and $UserInput -ne "3" -and $UserInput -ne "4")

}

function Write-Lame-Menu-Filter {

    do {
        Clear-Host
        Write-Host "============================="
        Write-Host "     Whodunnit > Filter "
        Write-Host "============================="
        Write-Host
        Write-Host "1) Export Filter"
        Write-Host "2) Load Filter"
        Write-Host "3) Edit Filter"
        Write-Host "4) Back"
        Write-Host

    
        $UserInput = Read-Host "whodunnit> filter>"
        
        switch($UserInput) {
            '1' {Export-Filter}
            '2' {Load-Filter}
            '3' {Write-Lame-Menu-Filter-Edit}
            '4' {Return}
        }
    
    } until ($UserInput -ne "1" -and $UserInput -ne "2" -and $UserInput -ne "3" -and $UserInput -ne "4")
    
}

function Write-Lame-Menu-Filter-Edit {

    do {
        Clear-Host
        Write-Host "============================="
        Write-Host "  Whodunnit > Filter > Edit"
        Write-Host "============================="
        Write-Host
        Write-Host "1) Username"
        Write-Host "2) Time Window"
        Write-Host "3) Event Codes"
        Write-Host "4) Event Types"
        Write-Host "5) Event Sources"
        Write-Host "6) Back"
        Write-Host

    
        $UserInput = Read-Host "whodunnit> filter> edit> "
        
        switch($UserInput) {
            '1' {Change-Filter-User}
            '2' {Change-Filter-Time}
            '3' {Change-Filter-EventCodes}
            '4' {Change-Filter-EventTypes}
            '5' {Change-Filter-EventSources}
        }
    
    } until ($UserInput -ne "1" -and $UserInput -ne "2" -and $UserInput -ne "3" -and $UserInput -ne "4" -and $UserInput -ne "5")
    
    Write-Output "Filtering Logs..."
    Filter-Logs
}



# Productive Functions #

# Constructors
function Create-Filter {
    param ($Usernames, $TimeStart, $TimeEnd, $EventCodes, $EventTypes, $EventSources)

    $filter = New-Object psobject

    $filter | add-member -type NoteProperty -Name Usernames -Value $Usernames
    $filter | add-member -type NoteProperty -Name TimeStart -Value $TimeStart
    $filter | add-member -type NoteProperty -Name TimeEnd -Value $TimeEnd
    $filter | add-member -type NoteProperty -Name EventCodes -Value @("*")
    $filter | add-member -type NoteProperty -Name EventTypes -Value $EventTypes
    $filter | add-member -type NoteProperty -Name EventSources -Value $EventSources

    return $filter
}

function Create-Log-Struct {
    
    $logs = New-Object psobject

    $logs | Add-Member -type NoteProperty -Name Application -Value @()
    $logs | Add-Member -Type NoteProperty -Name HardwareEvents -Value @()
    $logs | Add-Member -Type NoteProperty -Name InternetExplorer -Value @()
    $logs | Add-Member -Type NoteProperty -Name KeyManagement -Value @()
    $logs | Add-Member -Type NoteProperty -Name OAlerts -Value @()
    $logs | Add-Member -Type NoteProperty -Name Security -Value @()
    $logs | Add-Member -Type NoteProperty -Name System -Value @()
    $logs | Add-Member -Type NoteProperty -Name WindowsAzure -Value @()
    $logs | Add-Member -Type NoteProperty -Name WindowsPowershell -Value @()
    $logs | Add-Member -Type NoteProperty -Name Loaded -Value $false

    return $logs
}


# Subroutines
function Read-From-Local {
    if ($Logs.Loaded) {
        Write-Host "Logs are already loaded!"
        $UserInput = Read-Host "Overwrite? [y/n]"

        if ($UserInput -ne "y" -and $UserInput -ne "yes") {Return}
    }

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $LogTypes = "Application", "HardwareEvents", "Internet Explorer", "Key Management Service", "OAlerts", "System", "Windows Azure", "Windows PowerShell", "Security"
    
    for ($i = 0; $i -lt $LogTypes.Length; $i++) {
        
        $LogType = $LogTypes[$i]
        $Count = $i + 1
        Write-Progress  -Activity "Loading Event Logs from Local Host" `
                        -Status "$Count of 9" `
                        -CurrentOperation "Loading $LogType Logs" `
                        -PercentComplete ($Count / 9 * 100) `
                        -Id 1

        if ($LogType -eq "Security") {
            if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                Write-Host "Warning! Insignificant priviledges to load security logs!"
                Continue
            }
        }
        
        switch ($i) {
            0 {$script:Logs.Application = Read-Local-Helper("Application")}
            1 {$script:Logs.HardwareEvents = Read-Local-Helper("HardwareEvents")}
            2 {$script:Logs.InternetExplorer = Read-Local-Helper('Internet Explorer')}
            3 {$script:Logs.KeyManagement = Read-Local-Helper('Key Management Service')}
            4 {$script:Logs.OAlerts = Read-Local-Helper('OAlerts')}
            5 {$script:Logs.System = Read-Local-Helper('System')}
            6 {$script:Logs.WindowsAzure = Read-Local-Helper('Windows Azure')}
            7 {$script:Logs.WindowsPowershell = Read-Local-Helper('Windows PowerShell')}
            8 {$script:Logs.Security = Read-Local-Helper('Security')}

        }
    
    }

    $Logs.Loaded = $true
    Write-Progress -Activity "Loading Event Logs from Local Host" -Id 1 -Completed

}

function Export-Filter {
	<# Handles exporting the filter to a file      >
	<  Takes a user input for the filepath         >
	<  Then writes the current filter to the path #>
    Export-Filter-Helper(Read-Host "whodunnit> filter> export path> ")
}

function Load-Filter {
	<# Handles loading a filter from a file                     >
	<  Takes a user input for the filepath                      >
	<  Then loads the filter in the file to the current filter #>
	$script:CurrentFilter = Load-Filter-Helper(Read-Host "whodunnit> filter> import path> ")
    Write-Output "Filtering Logs..."
    Filter-Logs
}

function Load-Filter-Helper {
    param ($FilePath)
    return Import-Clixml -LiteralPath $FilePath
}

function Change-Filter-User {
	<# Takes a user input to change the global variable $Username #>
    do {
        Clear-Host
        Write-Host "Negative Search Usernames:"

        foreach ($user in $CurrentFilter.Usernames) {if($user -ne ""){$user}}
        
        $NewUser = Read-Host "Add / Remove > "
        if ($NewUser -eq "") {
            break
        }

        $isNew = 1
        $NewUsers = @()
        for ($i=0;$i -lt $CurrentFilter.Usernames.Count; $i++) {
            if ($CurrentFilter.Usernames[$i] -eq $NewUser) {
                $isNew = 0
            } else {$NewUsers += $CurrentFilter.Usernames[$i]}
        }

        if ($isNew -eq 1) {
            $NewUsers += ($NewUser)
        }

        $script:CurrentFilter.Usernames = $NewUsers

    } while ($NewUser -ne "")
}

function Change-Filter-Time {
	<# Takes a user input for a start and end date (optional time format?)    >
	<  Then updates the global variables $TimeWindowStart and $TimeWindowEnd #>
    
    do {

        $timeTemplate = "M/dd/yyyy H:mm"

        Clear-Host
        Write-Host "Time Window:"
        Write-Host " " $CurrentFilter.TimeStart " "
        Write-Host " " $CurrentFilter.TimeEnd " "

        $type = Read-Host "Modify? [start/end] > "

        if ($type -eq "start" -or $type -eq "1") {

            Clear-Host
            Write-Host "Time Window:"
            Write-Host "+" $CurrentFilter.TimeStart "+"
            Write-Host " " $CurrentFilter.TimeEnd " "
        
            $newTime = Read-Host "New Value [M/dd/yyyy H:mm] > "

            if ($newTime -eq "") {continue}

            $newTime
            [DateTime]::ParseExact($newTime, $timeTemplate, $null)
            Read-Host
            $script:CurrentFilter.TimeStart = [DateTime]::ParseExact($newTime, $timeTemplate, $null)

        }

        if ($type -eq "end" -or $type -eq "2") {

            Clear-Host
            Write-Host "Time Window:"
            Write-Host " " $CurrentFilter.TimeStart " "
            Write-Host "+" $CurrentFilter.TimeEnd "+"
        
            $newTime = Read-Host "New Value [M/dd/yyyy H:mm] > "

            if ($newTime -eq "") {continue}

            $newTime
            [DateTime]::ParseExact($newTime, $timeTemplate, $null)
            Read-Host
            $script:CurrentFilter.TimeEnd = [DateTime]::ParseExact($newTime, $timeTemplate, $null)

        }
    } while($type -ne "")
}

function Change-Filter-EventTypes {

    do {
        Clear-Host
        Write-Host "Event Types Included:"

        foreach ($EventType in @("Error", "Warning", "Information", "Success Audit", "Failure Audit")) {
        
            $found = 0
            foreach ($event in $CurrentFilter.EventTypes) {
                if ($EventType -eq $event) {$found = 1}
            }

            if ($found -eq 1) {Write-Host "[X] " $EventType}
            else {Write-Host "[ ] " $EventType}
    
        }

        $toggle = Read-Host "Toggle? > "

        if ($toggle -eq "") {return}

        $isNew = 1
        $NewEvents = @()
        for ($i=0;$i -lt $CurrentFilter.EventTypes.Count; $i++) {
            if ($CurrentFilter.EventTypes[$i] -eq $toggle) {
               $isNew = 0
            } else {$NewEvents += $CurrentFilter.EventTypes[$i]}
        }
    
        if ($isNew -eq 1 `
            -and ($toggle.ToLower() -eq "error" `
              -or $toggle -eq "warning" `
              -or $toggle -eq "information" `
              -or $toggle -eq "success audit" `
              -or $toggle -eq "failure audit" )) {

            $NewEvents += ($toggle)
        }

        $script:CurrentFilter.EventTypes = $NewEvents
    
    } while ($toggle -ne "")

}

function Change-Filter-EventCodes {
   do {
        Clear-Host
        Write-Host "Positive Search Event Codes:"

        foreach ($event in $CurrentFilter.EventCodes) {if($event -ne ""){$event}}
        
        $NewCode = Read-Host 'Add / Remove [$ErrorCode | reset]> '
       
        if ($NewCode -eq "") {break}
        if ($NewCode -eq "reset") {$script:CurrentFilter.EventCodes = @(); continue}


        $isNew = 1
        $NewCodes = @()
        for ($i=0;$i -lt $CurrentFilter.EventCodes.Count; $i++) {
            if ($CurrentFilter.EventCodes[$i] -eq $NewCode) {
                $isNew = 0
            } else {$NewCodes += $CurrentFilter.EventCodes[$i]}
        }

        if ($isNew -eq 1) {
            $NewCodes += ($NewCode)
        }

        $CurrentFilter.EventCodes = $NewCodes

    } while ($NewCodes -ne "") 
}

function Change-Filter-EventSources {
    do {
        Clear-Host
        Write-Host "Event Types Included:"

        foreach ($EventSource in @("Application", "Hardware Events", "Internet Explorer", "Key Management", "OAlerts", "Security", "System", "Windows Azure", "Windows Powershell")) {
        
            $found = 0
            foreach ($event in $CurrentFilter.EventSources) {
                if ($EventSource -eq $event) {$found = 1}
            }

            if ($found -eq 1) {Write-Host "[X] " $EventSource}
            else {Write-Host "[ ] " $EventSource}
    
        }

        $toggle = Read-Host "Toggle? > "

        if ($toggle -eq "") {return}

        $isNew = 1
        $NewEvents = @()
        for ($i=0;$i -lt $CurrentFilter.EventSources.Count; $i++) {
            if ($CurrentFilter.EventSources[$i] -eq $toggle) {
               $isNew = 0
            } else {$NewEvents += $CurrentFilter.EventSources[$i]}
        }
    
        if ($isNew -eq 1 `
            -and ($toggle.ToLower() -eq "application" `
              -or $toggle -eq "hardware events" `
              -or $toggle -eq "internet explorer" `
              -or $toggle -eq "key management" `
              -or $toggle -eq "oalerts" `
              -or $toggle -eq "security" `
              -or $toggle -eq "system" `
              -or $toggle -eq "windows azure" `
              -or $toggle -eq "windows powershell" `
               )) {

            $NewEvents += ($toggle)
        }

        $script:CurrentFilter.EventSources = $NewEvents
    
    } while ($toggle -ne "")

}

function Read-Logs-From-File {
    
    if ($Logs.Loaded) {
        Write-Host "Logs are already loaded!"
        $UserInput = Read-Host "Overwrite? [y/n]"

        if ($UserInput -ne "y" -and $UserInput -ne "yes") {Return}
    }


    $script:Logs = Read-Logs-From-File-Helper(Read-Host "whodunnit> load> import path> ")

}

function Export-Logs {

    if ($Logs.Loaded -eq $False) {
        Read-Host "++ No Logs are Loaded! Cannot Export ++"
        Return
    }

    $exType = Read-Host "whodunnit> export all?> "
    $filePath = Read-Host "whodunnit> export path> "
    
    # Export all logs
    if ($exType -eq "y" -or $exType -eq "yes") {
        Export-Clixml -InputObject $Logs -LiteralPath $filePath
    } elseif ($exType -eq "n" -or $exType -eq "no") {
        Export-Clixml -InputObject $FilteredLogs -LiteralPath $filePath
    }

}

function Import-Logs {
    $filePath = Read-Host "whodunnit > load> file path> "
    $Logs = Import-Clixml -LiteralPath $filePath
}


# Helper Functions

function Read-Local-Helper {
    param ($LogType)

    $LogCounts = (Get-EventLog -List | Where Log -EQ $LogType).Entries.Count

    if ($LogCounts -eq 0) {Return $null}

    Return Get-EventLog -LogName $LogType 
}

function Export-Filter-Helper {
    param ($FilePath)

    Export-Clixml -LiteralPath $FilePath -InputObject $CurrentFilter

}

function Read-Logs-From-File-Helper{
    param ($FilePath)
    return Import-Clixml -LiteralPath $FilePath
}

function Filter-Logs {

    foreach ($logtype in @("Application", "HardwareEvents", "InternetExplorer", "KeyManagement", "OAlerts", "Security", "System", "WindowsAzure", "WindowsPowershell")) {
        
        $found = 0
        foreach ($event in $CurrentFilter.EventSources) {
            if ($logtype -eq $event.replace(' ', '')) {
                $currentType = $Logs.$logtype
                
                # Loop through all logs in this section
                # for each element, call the check function to determine if it fits
                # Returns true if the element is a match for the current filter

                foreach ($log in $currentType) {
                    
                    
                    # Skip non null username values, and users in the usernames list
                    if ($log.Username -ne $null) {
                        if ($CurrentFilter.Usernames.Contains($log.UserName.split('\')[1])) {
                            continue
                        }
                    }
                    
                    

                    # Exclude logs created before specified time range
                    if ($CurrentFilter.TimeStart -ne $null){
                        if ($log.TimeGenerated -lt $CurrentFilter.TimeStart) {
                            continue
                        }
                    }
                    

                    # Exclude logs created after specified time range
                    if ($CurrentFilter.TimeEnd -ne $null) {
                        if ($log.TimeGenerated -gt $CurrentFilter.TimeEnd) {
                            continue
                        }
                    }
                    
                    
                    # Include logs with matching event codes, unless * is in the event codes
                    if (-not $CurrentFilter.EventCodes.Contains("*")) {
                        if (-not $CurrentFilter.EventCodes.Contains($log.EventID)) {
                            continue
                        }
                    }
                    

                    <#
                    # Exclude unseleted types
                    if ($CurrentFilter.EventTypes.Contains($log.EventTypes)) {
                        
                    } else {continue}
                    #>

                    # Additional Filter Criteria go here


                    $script:FilteredLogs.$logtype += $log
                    $script:FilteredLogs.Loaded = $true
                    
                }
            }
        }
    }
}

# TODO

function Display-Logs {
    $Logs
    $FilteredLogs
    Read-Host
}

function Not-Yet-Implemented {
    Write-Host "TODO: This ¯\_(ツ)_/¯"
    Read-Host
}


# Command Line Interface backbone



$script:CurrentFilter = Create-Filter(@(),"","",@(),@())
$script:Logs = Create-Log-Struct
$script:FilteredLogs = Create-Log-Struct
Write-Lame-Menu-Main


<# fancy menu for later 

function Load-Menu {
    Write-Menu -Title 'Whodunnit > Load >' -Entries @{
        'Read from File' = 'Not-Yet-Implemented'
        'Read from Local Machine' = 'Read-From-Local';
        'Read from Remote Machine' = 'Not-Yet-Implemented'
    }
}

function Filter-Menu-Edit {
    
    Write-Menu -Title "Whodunnit > Filter > Edit >" -Entries @{
        'Username' = 'Change-Filter-User';
        'Time Window' = 'Change-Filter-Time'
        'Event Codes' = 'Change-Filter-EventCodes'
        'Event Types' = 'Change-Filter-EventTypes'
        'Event Sources' = 'Change-Filter-EventSources'  
    }
}

function Filter-Menu {
    Write-Menu -Title "Whodunnit > Filter >" -Entries @{
        'Export' = 'Export-Filter'
        'Load' = 'Load-Filter'
        'Edit' = 'Filter-Menu-Edit';
                
        
    
    }

}


do {
    $menuReturn = Write-Menu -Title 'Whodunnit >' -Entries @{
        'Load Logs' = 'Load-Menu';

        'Active Filter' = 'Filter-Menu';
        

        'Display Logs' = ''

        'Export Logs' = 'Export-Logs';
    }
} while ($True)


#>