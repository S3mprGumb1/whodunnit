# Import for Write-Menu, unused in the current state
# if I manage to get the commented block at the bottom working, this will be needed
#. $PSScriptRoot\Write-Menu\Write-Menu.ps1


Param (
    [parameter(Mandatory=$true, ParameterSetName = "ImportFromFile")]
        [ValidateNotNullOrEmpty()]
        [alias("Input-File")]
        [String]$i,
    
    [parameter(Mandatory=$false, ParameterSetName = "ImportFromFile")]
    [parameter(ParameterSetName = "ImportFromLocal")]
    [parameter(ParameterSetName = "CreateFilter")]
    [parameter(ParameterSetName = "LoadRemote")]
        [ValidateNotNullOrEmpty()]
        [alias("Filter-File")]
        [String]$f,
    
    [parameter(Mandatory=$false, ParameterSetName = "ImportFromFile")]
    [parameter(ParameterSetName = "ImportFromLocal")]
    [parameter(ParameterSetName = "CreateFilter")]
    [parameter(ParameterSetName = "LoadRemote")]
        [ValidateNotNullOrEmpty()]
        [alias("Output-File")]
        [String]$o,

    [parameter(Mandatory=$true, ParameterSetName = "ImportFromLocal")]
        [alias("Load-Local")]
        [switch]$l = $false,
    
    [parameter(Mandatory=$true, ParameterSetName = "CreateFilter")]
        [alias("Create-Filter")]
        [switch]$c = $false,

    [parameter(Mandatory=$true, ParameterSetName = "LoadRemote")]
        [alias("Remote-IP")]
        [String]$r,

    [parameter(Mandatory=$true, ParameterSetName = "LoadRemote")]
        [alias("Username")]
        [String]$u,
    
    [parameter(Mandatory=$true, ParameterSetName = "LoadRemote")]
        [alias("Password")]
        [String]$p = $(Read-Host "Input remote password> ")
)

if ($args.Count -eq 0) {
    $script:UseGlobals = $false
    #$script:UseGlobals = $true
    
    $script:CurrentFilter = Initialize-Filter(@(),"","",@(),@())
    $script:Logs = Initialize-Log-Struct
    $script:FilteredLogs = Initialize-Log-Struct
    Write-Lame-Menu-Main

} else {

    if ($c) {
        Export-Filter-CLI $o $f
        return 
    }

    if ($l) {
        Export-Local-Logs $o $f
        return
    }

    if ($r) {
        Write-Error "Not Implemented yet... whoopsie"
    }

}


# CLI Routines 

function Export-Filter-CLI {
    param ($FilePath, $FilterPath)

    if ($null -eq $FilterPath) {
        $Filter = Initialize-Filter
    } else {
        $Filter = Import-Filter-Helper $FilterPath
    }

    if ($null -ne $Filter) {
        Export-Filter-Script $FilePath $Filter
        return
    } 

    if ($null -eq $FilterPath) {
        Write-Error "Error: Failed to Initialize Filter!"
    } else {
        Write-Error "Error: Failed to load filter from $FilterPath!"
    }
}

function Export-Local-Logs {
    param ($OutPath, $FilterPath)

    $filter = Import-Filter-Helper $FilterPath

    if ($null -eq $filter) {
        Write-Error "Error: Failed to load filter from $FilterPath"
    }

    $logs = Read-From-Local
    ## TODO ##
    # modify filter function to work with an input filter and log set
    

}

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
            '3' {Show-Log-Stats}
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
        Write-Host "3) Read From Remote Machine [NI]"
        Write-Host "4) Back"
        Write-Host

    
        $UserInput = Read-Host "whodunnit> Load> "
        
        switch($UserInput) {
            '1' {Import-Logs}
            '2' {Read-From-Local; Return}
            '3' {Not-Yet-Implemented}
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
        Write-Host "1) Load Filter"
        Write-Host "2) Edit Filter"
        Write-Host "3) Export Filter"
        Write-Host "4) Apply"
        Write-Host "5) Back"
        Write-Host

    
        $UserInput = Read-Host "whodunnit> filter>"
        
        switch($UserInput) {
            '3' {Export-Filter}
            '1' {Import-Filter}
            '2' {Write-Lame-Menu-Filter-Edit}
            '4' {Write-Host "Filtering Logs..."; Filter-Logs}
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
            '1' {Edit-Filter-User}
            '2' {Edit-Filter-Time}
            '3' {Edit-Filter-EventCodes}
            '4' {Edit-Filter-EventTypes}
            '5' {Edit-Filter-EventSources}
        }
    
    } until ($UserInput -ne "1" -and $UserInput -ne "2" -and $UserInput -ne "3" -and $UserInput -ne "4" -and $UserInput -ne "5")
    
    Write-Output "Filtering Logs..."
    Filter-Logs
}



# Productive Functions #

# Constructors
function Initialize-Filter {
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

function Initialize-Log-Struct {
    
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


# Dot Sourceable Subroutines

function Read-From-Local {

    if ($script:UseGlobals -eq $true) {
        if ($Logs.Loaded) {
            Write-Host "Logs are already loaded!"
            $UserInput = Read-Host "Overwrite? [y/n]"

            if ($UserInput -ne "y" -and $UserInput -ne "yes") {Return}
        }
    }

    
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

            $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
            if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                if ($script:UseGlobals -eq $true) { Write-Host "Warning! Insignificant priviledges to load security logs!"; }
                Continue
            }
        }
        
        
        switch ($i) {
            0 {$script:Logs.Application = Read-Local-Script("Application")}
            1 {$script:Logs.HardwareEvents = Read-Local-Script("HardwareEvents")}
            2 {$script:Logs.InternetExplorer = Read-Local-Script('Internet Explorer')}
            3 {$script:Logs.KeyManagement = Read-Local-Script('Key Management Service')}
            4 {$script:Logs.OAlerts = Read-Local-Script('OAlerts')}
            5 {$script:Logs.System = Read-Local-Script('System')}
            6 {$script:Logs.WindowsAzure = Read-Local-Script('Windows Azure')}
            7 {$script:Logs.WindowsPowershell = Read-Local-Script('Windows PowerShell')}
            8 {$script:Logs.Security = Read-Local-Script('Security')}

        }
    
    }

    if ($script:UseGlobals -eq $true) {
        $Logs.Loaded = $true
        Write-Progress -Activity "Loading Event Logs from Local Host" -Id 1 -Completed
        return
    }

    $Logs

}

function Import-Filter {

    if ($script:UseGlobals -eq $true) {
	    $script:CurrentFilter = Import-Filter-Helper(Read-Host "whodunnit> filter> import path> ")
        Write-Output "Filtering Logs..."
        Filter-Logs

    } else {

        Import-Filter-Helper(Read-Host "filter import path> ")
    }
    
}

function Import-Filter-Helper {
    param ($FilePath)
    return Import-Clixml -LiteralPath $FilePath
}

function Import-Logs {
    if ($script:UseGlobals -eq $true) {
        if ($Logs.Loaded) {
            Write-Host "Logs are already loaded!"
            $UserInput = Read-Host "Overwrite? [y/n]"

            if ($UserInput -ne "y" -and $UserInput -ne "yes") {Return}
        }
        $script:Logs = Read-Logs-From-File-Helper(Read-Host "whodunnit> load> import path> ")
        return
    }

    Read-Logs-From-File-Helper(Read-Host "log import path> ")
}

function Export-Logs-Script {
    param ($InputObject, $path)
    Export-Clixml -InputObject $InputObject -LiteralPath $path
}

function Read-Local-Script {
    param ($LogType)

    $LogCounts = (Get-EventLog -List | Where-Object Log -EQ $LogType).Entries.Count

    if ($LogCounts -eq 0) {Return $null}

    Return Get-EventLog -LogName $LogType 
}

function Export-Filter-Script {
    param ($FilePath, $Filter)

    Export-Clixml -LiteralPath $FilePath -InputObject $Filter
}

function Read-Logs-From-File-Helper{
    param ($FilePath)
    return Import-Clixml -LiteralPath $FilePath
}


# Subroutines

function Export-Filter {

    if ($script:UseGlobals -eq $true) {
        Export-Filter-Script (Read-Host "whodunnit> filter> export path> ") $CurrentFilter
        return
    }
    
    if ($script:UseGlobals -eq $false) {
        Write-Error `
                "Function: 'Export-Filter' cannot be imported; it requires the use of global variables in an interactive environment. 
                Use Export-Filter-Script instead.
                "
        Read-Host
        return
    }

}

function Edit-Filter-User {
    
    if ($script:UseGlobals -eq $false) {
        Write-Error "Function: 'Edit-Filter-User' cannot be imported; it requires the use of global variables in an interactive environment. "
        return
    }
    
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

function Edit-Filter-Time {
	<# Takes a user input for a start and end date (optional time format?)    >
	<  Then updates the global variables $TimeWindowStart and $TimeWindowEnd #>

    if ($script:UseGlobals -eq $false) {
        Write-Error "FunctiEdit' cannot be imported; it requires the use of global variables in an interactive environment. "
        return
    }

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

function Edit-Filter-EventTypes {
    
    if ($script:UseGlobals -eq $false) {
        Write-Error "Function: 'Edit-Filter-EventTypes' cannot be imported; it requires the use of global variables in an interactive environment. "
        return
    }
    
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

function Edit-Filter-EventCodes {

    if ($script:UseGlobals -eq $false) {
        Write-Error "FunctiEdit' cannot be imported; it requires the use of global variables in an interactive environment. "
        return
    }

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

function Edit-Filter-EventSources {

    if ($script:UseGlobals -eq $false) {
        Write-Error "FunctiEdit' cannot be imported; it requires the use of global variables in an interactive environment. "
        return
    }

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

function Export-Logs {
    param($logs, $path)

    if ($script:UseGlobals -eq $true) { 
        if ($script:Logs.Loaded -eq $False) {
            Read-Host "++ No Logs are Loaded! Cannot Export ++"
            Return
        }
        
        $exType = Read-Host "whodunnit> export all?> "
        $filePath = Read-Host "whodunnit> export path> "
    
        # Export all logs
        if ($exType -eq "y" -or $exType -eq "yes") {
            Export-Logs-Script $script:Logs $filePath
        } elseif ($exType -eq "n" -or $exType -eq "no") {
            Export-Logs-Script $script:FilteredLogs $filePath
        }
        return 
    }

    Export-Logs-Script $logs $path
    
}


# Helper Functions

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

function Show-Log-Stats {
    Write-Output "============"
    Write-Output " Log Counts "
    Write-Output "============"
    Write-Output "Logtype              Unfiltered Count  Filtered Count"
    Write-Output "+---------------------------------------------------+"
    foreach ($logtype in @("Application", "Hardware Events", "Internet Explorer", "Key Management", "OAlerts", "Security", "System", "Windows Azure", "Windows Powershell")) {
        
        Write-Host -NoNewline "| "

        $FiltCount = $FilteredLogs.$logtype.Count.ToString()
        $Count = $Logs.$logtype.Count.ToString()


        $logtype = $logtype.PadRight(26, " ")
        $FiltCount = $FiltCount.PadLeft(18 - $Count.Length, " ")

        Write-Host "$logtype $Count $FiltCount" -NoNewline
        Write-Host "    |"

    }

    Write-Output "+---------------------------------------------------+"
    Read-Host
}



# TODO

function Not-Yet-Implemented {
    Write-Host "TODO: This ¯\_(ツ)_/¯"
    Read-Host
}

# Command Line Interface backbone




<# fancy menu for later
    
    Issues:
        variables do not seem to be accessible in their current state when used
            should be fixed when refactored to not use global variables
        
        menu needs a user experience overhaul
            use the title option to set a header up
            possibly a help menu or tag on the main menu 

function Load-Menu {
    Write-Menu -Title 'Whodunnit > Load >' -Entries @{
        'Read from File' = 'Not-Yet-Implemented'
        'Read from Local Machine' = 'Read-From-Local';
        'Read from Remote Machine' = 'Not-Yet-Implemented'
    }
}

function Filter-Menu-Edit {    
    Write-Menu -Title "Whodunnit > Filter > Edit >" -Entries @{
        'Username' = 'Edit-Filter-User';
        'Time WindowEdit'
        'Event CodesEdit'
        'Event Types' = 'Edit-Filter-EventTypes'
        'Event SourcesEdit'  
    }
}

function Filter-Menu {
    Write-Menu -Title "Whodunnit > Filter >" -Entries @{
        'Export' = 'Export-Filter'
        'Load' = 'Import-Filter'
        'Edit' = 'Filter-Menu-Edit';    
    }
}


do {
    $menuReturn = Write-Menu -Title 'Whodunnit >' -Entries @{
        'Load Logs' = 'Load-Menu';
        'Active Filter' = 'Filter-Menu';        
        'Display Logs' = '';
        'Export Logs' = 'Export-Logs';
    }
} while ($True)
#>