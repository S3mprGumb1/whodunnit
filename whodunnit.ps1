# Import for Write-Menu, unused in the current state
# if I manage to get the commented block at the bottom working, this will be needed
#. $PSScriptRoot\Write-Menu\Write-Menu.ps1

<#
    Parameter Declaration for CLI use.
    ## TODO ## 
    Add copy of Get-Help ./whodunnit.ps1 here
    ## ODOT ##
#>
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
        [switch]$c = $false
    
)

# Set up for use in an interactive environment when no arguments passed

<#
    Functions used by the command line interface
    Contains the backbone for the CLI, and the subroutines used
    To create filters, export local logs matching a filter, and
    export remote logs matching a filter, when it's implemented
#> 

function CLI-Backbone {
    
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
    
    $filtered = Filter-Logs-CLI $logs $filter

    Export-Logs-Script $filtered $OutPath
}


<#
    Functions used to control the User Experience are here
    Contains the backbone for the 'GUI' currently implemented
    In the future, it will contain the fancier GUI, once it is functional
    Will contain the logic to switch between the fancy and simple menu,
    favoring the fancy menu where supported
#>
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



<#
    Contains the 'constructors' for the two different data structures used
#>
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

    $logs | Add-Member -type NoteProperty -Name Application -Value (New-Object System.Collections.ArrayList)
    $logs | Add-Member -Type NoteProperty -Name HardwareEvents -Value (New-Object System.Collections.ArrayList)
    $logs | Add-Member -Type NoteProperty -Name InternetExplorer -Value (New-Object System.Collections.ArrayList)
    $logs | Add-Member -Type NoteProperty -Name KeyManagement -Value (New-Object System.Collections.ArrayList)
    $logs | Add-Member -Type NoteProperty -Name OAlerts -Value (New-Object System.Collections.ArrayList)
    $logs | Add-Member -Type NoteProperty -Name Security -Value (New-Object System.Collections.ArrayList)
    $logs | Add-Member -Type NoteProperty -Name System -Value (New-Object System.Collections.ArrayList)
    $logs | Add-Member -Type NoteProperty -Name WindowsAzure -Value (New-Object System.Collections.ArrayList)
    $logs | Add-Member -Type NoteProperty -Name WindowsPowershell -Value (New-Object System.Collections.ArrayList)
    $logs | Add-Member -Type NoteProperty -Name Loaded -Value $false

    return $logs
}



<#
    The following functions *should* be functional in an environment that 
    does not use global variables, i.e. imported into a third party script, 
    or on the powershell CLI.

    Due to the nature of powershell's weird method of determining returns, 
    User interaction is not possible when these functions are used in their 
    imported mode. When used with the variable '$script:UseGlobals', User
    Interaction is enabled, however the functions assume the use of global variables,
    and do not return anything helpful.
#>

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

function Filter-Logs-CLI {
    param ($logs, $filter)

    if ($script:UseGlobals) {
        $logs = $script:Logs
        $filter = $script:CurrentFilter
    }

    # A new, empty log struct to store matching logs
    $filteredSet = Initialize-Log-Struct


    foreach ($logtype in $filter.EventSources) {

        $found = 0
        foreach ($event in @("Application", "HardwareEvents", "InternetExplorer", "KeyManagement", "OAlerts", "Security", "System", "WindowsAzure", "WindowsPowershell")) {
            
            # Check if the log type is selected before filtering
            if ($logtype.replace(' ', '') -eq $event){
                
                # Acquire the logs from the relevant source
                $workingSet = $logs.$logtype

                foreach ($log in $workingSet) {
                    # for every log in the working set:
                    #      1) Check Username vs the User list
                    #      2) Check Event Time vs Start Time
                    #      3) Check Event Time vs End Time
                    #      4) Check Event Code vs List
                    #      5) Check Event Type vs List
                    
                    # 1) Skip non null username values, and users in the usernames list
                    if ($log.Username -ne $null) {
                        if ($filter.Usernames.Contains($log.UserName.split('\')[1])) {
                            continue
                        }
                    }

                    # 2) Exclude logs created before specified time range
                    if ($filter.TimeStart -ne $null){
                        if ($log.TimeGenerated -lt $filter.TimeStart) {
                            continue
                        }
                    }

                    # 3) Exclude logs created after specified time range
                    if ($filter.TimeEnd -ne $null) {
                        if ($log.TimeGenerated -gt $filter.TimeEnd) {
                            continue
                        }
                    }

                    # 4) Include only logs with matching event codes, unless * is in the event codes
                    if (-not $filter.EventCodes.Contains("*")) {
                        if (-not $filter.EventCodes.Contains($log.EventID)) {
                            continue
                        }
                    }

                    # 5) Exclude unselected event types
                    ## NEEDS TESTING ##
                    <#
                    if (-not $filter.EventTypes.Contains($log.EventTypes)) {
                        continue
                    } 
                    #>
                    
                    <##
                    Add additional filtration criteria here
                    ##>

                    # Only logs that match filter should make it here
                    # Add current log to filtered set
                    $filteredSet.$logtype.add($log)

                    #$filteredSet.$logtype += $log
                }
            }
        }
    }

    # After all log types are filtered, return the log struct
    return $filteredSet
}

function Show-Log-Stats {
    param ($logs, $filtered)

    if ($script:UseGlobals) {
        $logs = $script:Logs
        $filtered = $script:FilteredLogs
    }

    Write-Output "============"
    Write-Output " Log Counts "
    Write-Output "============"
    Write-Output "Logtype              Unfiltered Count  Filtered Count"
    Write-Output "+---------------------------------------------------+"
    foreach ($logtype in @("Application", "Hardware Events", "Internet Explorer", "Key Management", "OAlerts", "Security", "System", "Windows Azure", "Windows Powershell")) {
        
        Write-Host -NoNewline "| "

        $FiltCount = $filtered.$logtype.Count.ToString()
        $Count = $logs.$logtype.Count.ToString()


        $logtype = $logtype.PadRight(26, " ")
        $FiltCount = $FiltCount.PadLeft(18 - $Count.Length, " ")

        Write-Host "$logtype $Count $FiltCount" -NoNewline
        Write-Host "    |"
    }

    Write-Output "+---------------------------------------------------+"
    if ($script:UseGlobals){ Read-Host }
}



<#
    The following functions are not functional in an environment not 
    utilizing global variables, as they require user interaction. 
#>

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

        foreach ($user in $CurrentFilter.Usernames) {if($null -ne $user){$user}}
        
        $NewUser = Read-Host "Add / Remove > "
        if ($null -eq $NewUser) {
            return
        }

        $isNew = 1
        $NewUsers = New-Object System.Collections.ArrayList

        for ($i=0; $i -lt $CurrentFilter.Usernames.Count; $i++) {
            if ($CurrentFilter.Usernames[$i] -eq $NewUser) {
                $isNew = 0
            } else {$NewUsers.add($CurrentFilter.Usernames[$i])}
        }

        if ($isNew -eq 1) {
            $NewUsers.add($NewUser)
        }

        $script:CurrentFilter.Usernames = $NewUsers

    } while ($null -ne $NewUser)
}

function Edit-Filter-Time {
	<# Takes a user input for a start and end date (optional time format?)    >
	<  Then updates the global variables $TimeWindowStart and $TimeWindowEnd #>

    if ($script:UseGlobals -eq $false) {
        Write-Error "Function: Edit-Filter-Time' cannot be imported; it requires the use of global variables in an interactive environment. "
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
            
            if ($CurrentFilter.EventTypes.Contains($EventType.ToLower())) {Write-Host "[X] " $EventType} 
            else {Write-Host "[ ] " $EventType}
            <#
            $found = 0
            foreach ($event in $CurrentFilter.EventTypes) {
                if ($EventType -eq $event) {$found = 1}
            }

            if ($found -eq 1) {Write-Host "[X] " $EventType}
            else {Write-Host "[ ] " $EventType}
            #>
        }

        $toggle = Read-Host "Toggle? > "

        if ($null -eq $toggle) {return}

        $isNew = 1
        $NewEvents = @()
        for ($i=0;$i -lt $CurrentFilter.EventTypes.Count; $i++) {
            if ($CurrentFilter.EventTypes[$i].ToLower() -eq $toggle.ToLower()) {
               $isNew = 0
            } else {$NewEvents += $CurrentFilter.EventTypes[$i]}
        }
    
        if ($isNew -eq 1 `
            -and ($toggle.ToLower() -eq "error" `
              -or $toggle -eq "warning" `
              -or $toggle -eq "information" `
              -or $toggle -eq "success audit" `
              -or $toggle -eq "failure audit" )) {

            $NewEvents += ($toggle.ToLower())
        }

        $script:CurrentFilter.EventTypes = $NewEvents
    
    } while ($null -ne $toggle)
}

function Edit-Filter-EventCodes {

    if ($script:UseGlobals -eq $false) {
        Write-Error "Function: Edit-Filter-EventCodes' cannot be imported; it requires the use of global variables in an interactive environment. "
        return
    }

    do {
        Clear-Host
        Write-Host "Positive Search Event Codes:"

        foreach ($event in $CurrentFilter.EventCodes) {if($null -ne $event){$event}}
        
        $NewCode = Read-Host 'Add / Remove [$ErrorCode | reset]> '
       
        if ($null -eq $NewCode) {break}
        if ($NewCode -eq "reset") {$script:CurrentFilter.EventCodes = New-Object System.Collections.ArrayList; continue}


        $isNew = 1
        $NewCodes = New-Object System.Collections.ArrayList

        for ($i=0; $i -lt $CurrentFilter.EventCodes.Count; $i++) {
            if ($CurrentFilter.EventCodes[$i] -eq $NewCode) {
                $isNew = 0
            } else {$NewCodes.add($CurrentFilter.EventCodes[$i])}
        }

        if ($isNew -eq 1) {
            $NewCodes.add($NewCode)
        }

        $CurrentFilter.EventCodes = $NewCodes

    } while ($null -ne $NewCode) 
}

function Edit-Filter-EventSources {

    if ($script:UseGlobals -eq $false) {
        Write-Error "Function: Edit-Filter-EventSources' cannot be imported; it requires the use of global variables in an interactive environment. "
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

        if ($null -eq $toggle) {return}

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
    
    } while ($null -ne $toggle)

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

    return Export-Logs-Script $logs $path   
}

function Filter-Logs {
    $script:FilteredLogs = Filter-Logs-CLI $script:Logs $script:CurrentFilter
}



# Placeholder
function Not-Yet-Implemented {
    Write-Host "TODO: This ¯\_(ツ)_/¯"
    Read-Host
}



if ($args.Count -eq 0) {
    $script:UseGlobals = $true
    $script:CurrentFilter = Initialize-Filter @() "" "" @() @()
    $script:Logs = Initialize-Log-Struct
    $script:FilteredLogs = Initialize-Log-Struct
    Write-Lame-Menu-Main

} else {
    CLI-Backbone
}



<# fancy menu for later
    
    Issues:
    variables do not seem to be accessible in their current state when used
        should be fixed when refactored to not use global variables
            UPDATE (1/17/19): Unlikely to be fixed, unless a workaround to powershell returning all output is found. 
        
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