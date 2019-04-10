<#
    .SYNOPSIS
        Manipulate Windows Event Logs from the comfort and familiarity of a PowerShell Environment.

    .LINK
        https://github.com/1cysw0rdk0/whodunnit
#>
Param (

        # Specify a previously exported file to read in.
        [Parameter( 
            Mandatory=$true, 
            ParameterSetName = "ImportFromFile",
            HelpMessage = "Specify an input file."
        )]
        [ValidateScript({ Test-Path -LiteralPath $_ })]
        [Alias("i")]
        [System.IO.Path]$InputFile,


        # Load logs from local host.
        [Parameter(
            Mandatory=$true, 
            ParameterSetName = "ImportFromLocal"
        )]
        [Alias("l")]
        [switch]$InputLocal,


        # Create a new filter file.
        [Parameter(
            Mandatory=$true, 
            ParameterSetName = "CreateFilter"
        )]
        [Alias("c")]
        [switch]$CreateFilter = $false,


        # Specify an outfile. File is overwritten if it exists.
        [Parameter(
            ParameterSetName = "ImportFromFile", 
            Mandatory=$false,
            HelpMessage = "Specify an output path."
        )]
        [Parameter(
            ParameterSetName = "ImportFromLocal", 
            Mandatory=$false,
            HelpMessage = "Specify an output path."
        )]
        [Parameter(
            ParameterSetName = "CreateFilter", 
            Mandatory=$false,
            HelpMessage = "Specify an output path."
        )]
        [ValidateScript({ Test-Path -LiteralPath $_ -IsValid })]
        [Alias("o")]
        [System.IO.Path]$OutputPath,


        # Sepcify a previously created filter file to use.
        [Parameter(
            ParameterSetName = "ImportFromFile", 
            Mandatory=$false,
            HelpMessage = "Specify a filter file."
        )]
        [Parameter(
            ParameterSetName = "ImportFromLocal",
            Mandatory=$false,
            HelpMessage = "Specify a filter file."
        )]
        [Alias("f")]
        [System.IO.Path]$FilterPath,

    
        # Spawn an interactive session
        [Parameter(
            ParameterSetName = "UseGUI",
            Mandatory=$false
        )]
        [switch]$UseGUI=$true

)

# Imports
. $PSScriptRoot\Write-Menu\Write-Menu.ps1

# Structures 
class Log_Struct {
    [System.Collections.ArrayList]$Application
    [System.Collections.ArrayList]$HardwareEvents
    [System.Collections.ArrayList]$InternetExplorer
    [System.Collections.ArrayList]$KeyManagement
    [System.Collections.ArrayList]$OAlerts
    [System.Collections.ArrayList]$Security
    [System.Collections.ArrayList]$System
    [System.Collections.ArrayList]$WindowsAzure
    [System.Collections.ArrayList]$WindowsPowershell
    [bool]$loaded = $false
}

class Filter_Struct {
    [System.Collections.ArrayList]$Usernames
    [datetime]$TimeStart
    [datetime]$TimeEnd
    [System.Collections.ArrayList]$EventCodes
    [System.Collections.ArrayList]$EventTypes
    [System.Collections.ArrayList]$EventSources
    [Log_Struct]$MatchingLogs
    [bool]$loaded
}

# Functions
class Menu_Functions {
    
    [void]Write_Menu_Main($menu) {

        $inits = [Init_Functions]::new()
        $menu = [Menu_Functions]::new()
        $filt = [Filter_Functions]::new()
        $exp = [Export_Functions]::new()  

        $UserInput = 0
        $Logs = [Log_Struct]::new()
        $Filtered = [Log_Struct]::new()
        $Filter = $inits.Init_Filter()

        do {

            Clear-Host
            Write-Host "============================="
            Write-Host "          Whodunnit"
            Write-Host "============================="
            Write-Host
            Write-Host "1) Load Logs"
            Write-Host "2) Active Filter"
            Write-Host "3) Apply Filter"
            Write-Host "4) Show Logs"
            Write-Host "5) Export Logs"
            Write-Host

    
            $UserInput = Read-Host "whodunnit> "
        
            switch($UserInput) {
                '1' {$Logs = $menu.Write_Menu_Load($Logs)}
                '2' {$Filter = $menu.Write_Menu_Filter($Filter, $Logs)}
                '3' {$Filtered = $filt.Apply_Filter($Filter, $Logs)}
                '4' {$exp.Show_Log_Stats($Logs, $Filtered)}
                '5' {Export_Logs($Filtered)}
            }
    
        } until ($UserInput -ne "1" -and $UserInput -ne "2" -and $UserInput -ne "3" -and $UserInput -ne "4")

    }

    [Log_Struct]Write_Menu_Load($Logs) {
        
        $UserInput = 0
        $load = [Load_Functions]::new()

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
    
        
            $UserInput = Read-Host "whodunnit> load> "
            
            switch($UserInput) {
                '1' {Return $load.Import_Logs($Logs)}
                '2' {Return $load.Read_From_Local($Logs)}
                '3' {Return $Logs}
                '4' {Return $Logs}
            }
        
        } until ($UserInput -ne "1" -and $UserInput -ne "2" -and $UserInput -ne "3" -and $UserInput -ne "4")
    
        return $Logs
    }

    [Filter_Struct]Write_Menu_Filter($Filter, $Logs) {
        
        $UserInput = 0
        $filters = [Filter_Functions]::new()
        $menus = [Menu_Functions]::new() 

        do {

            Clear-Host
            Write-Host "============================="
            Write-Host "     Whodunnit > Filter "
            Write-Host "============================="
            Write-Host
            Write-Host "1) Load Filter"
            Write-Host "2) Edit Filter"
            Write-Host "3) Export Filter"
            Write-Host "4) Back"
            Write-Host

        
            $UserInput = Read-Host "whodunnit> filter>"
            
            switch($UserInput) {
                '3' {$filters.Export_Filter($Filter)}
                '1' {$Filter = $filters.Import_Filter($Filter)}
                '2' {$Filter = $menus.Write_Menu_Edit($Filter)}
            }
        
        } until ($UserInput -ne "1" -and $UserInput -ne "2" -and $UserInput -ne "3")

        Return $Filter
    }

    [Filter_Struct]Write_Menu_Edit($Filter) {
        
        $UserInput = 0
        $Bak = $Filter
        $edit = [Filter_Functions]::new()

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
                '1' {$Filter.Usernames = $edit.Username_Edit($Filter)}
                '2' {$Filter = $edit.TimeRange_Edit($Filter)}
                '3' {$Filter.EventCodes = $edit.EventCode_Edit($Filter)}
                '4' {$Filter.EventTypes = $edit.EventTypes_Edit($Filter)}
                '5' {$Filter.EventSources = $edit.EventSources_Edit($Filter)}
            }
        
        } until ($UserInput -ne "1" -and $UserInput -ne "2" -and $UserInput -ne "3" -and $UserInput -ne "4" -and $UserInput -ne "5")

        Return $Filter
    }
}

class Init_Functions {

    [Filter_Struct]Init_Filter() {
        $Filter = [Filter_Struct]::new()

        #Initialize
        $Filter.Usernames = [System.Collections.ArrayList]::new()
        $Filter.TimeStart = [datetime]::MinValue
        $Filter.TimeEnd = [datetime]::MaxValue
        $Filter.EventCodes = [System.Collections.ArrayList]::new()
        $Filter.EventTypes = [System.Collections.ArrayList]::new()
        $Filter.EventSources = [System.Collections.ArrayList]::new()
        $Filter.loaded = $false

        #Defualts
        $Filter.EventCodes.Add("*")
        $Filter.TimeStart = [datetime]::MinValue
        $Filter.TimeEnd = [datetime]::Now

        Return $Filter
    }

    [Log_Struct]Init_Log() {
        $Log = [Log_Struct]::new()

        foreach ($event in @("Application", "HardwareEvents", "InternetExplorer", "KeyManagement", "OAlerts", "Security", "System", "WindowsAzure", "WindowsPowershell")) {
            $Log.$event = [System.Collections.ArrayList]::new()
        }

        Return $Log
    }
}

class Load_Functions {
    
    <# Reads in logs from a previously exported logset #>
    [Log_Struct]Import_Logs($Logs) {
        
        if ($Logs.loaded) {
            Write-Host "Logs are already loaded!"
            $UserInput = Read-Host "Overwrite? [y/N]> "
            
            if ($UserInput.ToLower() -ne "y" -and $UserInput.ToLower() -ne "yes") {Return $Logs}
        } 

        Return Import-Clixml -LiteralPath (Read-Host "whodunnit> load> import path> ")
    }

    <# Reads in logs from the local machine #>
    [Log_Struct]Read_From_Local($Logs) {

        # Prevent Overwrites
        if ($Logs.loaded) {
            Write-Host "Logs are already loaded!"
            $UserInput = Read-Host "Overwrite? [y/N]> "
            
            if ($null -eq $UserInput) {Return $Logs}
            if ($UserInput.ToLower() -ne "y" -and $UserInput.ToLower() -ne "yes") {Return $Logs}
        }

        $LogTypes = "Application", "HardwareEvents", "Internet Explorer", "Key Management Service", "OAlerts", "System", "Windows Azure", "Windows PowerShell", "Security"

        # Loop executes for every log type
        for ($i = 0; $i -lt $LogTypes.Length; $i++) {

            $LogType = $LogTypes[$i]
            $Count = $i + 1

            # Display Progress
            Write-Progress  -Activity "Loading Event Logs from Local Host" `
                        -Status "$Count of 9" `
                        -CurrentOperation "Loading $LogType Logs" `
                        -PercentComplete ($Count / 9 * 100) `
                        -Id 1
            
            # Check Perms on security logs
            if ($LogType -eq "Security") {

                $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
                
                if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                    Write-Host "Warning! Insignificant priviledges to load security logs!"
                    Continue
                }
            }

            # If no logs, skip the call to set. Prevents error message.
            if ((Get-EventLog -List | Where-Object Log -eq $LogType).Entries.Count -eq 0) {Continue}

            # Sets the appropriate list to the contents of the log list
            $Logs.($LogType.ToString().Replace(" ","")) = Get-EventLog -LogName $LogType 

        }

        $Logs.loaded = $true
        Write-Progress -Activity "Loading Event Logs from Local Host" -Id 1 -Completed
        Return $Logs

    }

}

class Export_Functions {

    <# Exports Logs as an xml object. very space intensive. #>
    <# ROADMAP: Issue #2 #>
    [bool]Export_Logs($Logs) {
            
        if ($Logs.loaded -eq $false) {
            Read-Host "Error: No logs are loaded"
            Return $false
        }

        $UserInput = Read-Host "whodunnit> Export Path> "

        try {
            Export-Clixml -LiteralPath $UserInput -InputObject $Logs
        }
        catch {
            Read-Host "Error: Encountered Problem Writing File"
            Return $false
        }
        
        Return $true

    }

    [void]Show_Log_Stats($Logs, $Filtered) {
        
        Clear-Host
        Write-Host "============"
        Write-Host " Log Counts "
        Write-Host "============"
        Write-Host "Logtype              Unfiltered Count  Filtered Count"
        Write-Host "+---------------------------------------------------+"
        foreach ($logtype in @("Application", "Hardware Events", "Internet Explorer", "Key Management", "OAlerts", "Security", "System", "Windows Azure", "Windows Powershell")) {
        
            Write-Host -NoNewline "| "

            $FiltCount = $Filtered.$logtype.Count.ToString()
            $Count = $Logs.$logtype.Count.ToString()


            $logtype = $logtype.PadRight(26, " ")
            $FiltCount = $FiltCount.PadLeft(18 - $Count.Length, " ")

            Write-Host "$logtype $Count $FiltCount" -NoNewline
            Write-Host "    |"
        }

        Write-Host "+---------------------------------------------------+"
        Read-Host
    }
    
}

class Filter_Functions {

    <# Exports a filter as an xml object. #>
    [bool]Export_Filter($Filter) {

        $UserInput = Read-Host "whodunnit> filter> export path> "

        try {
            Export-Clixml -LiteralPath $UserInput -InputObject $Filter
        }
        catch {
            Read-Host "Error Encountered Problem Writing File"
            Return $false
        }

        Return $true

    }

    <# Imports a filter from an exported xml. #>
    [Filter_Struct]Import_Filter($Filter) {

        if ($Filter.loaded) {
            Write-Host "A filter is already loaded!"
            $UserInput = Read-Host "Overwrite? [y/N]> "

            if ($null -eq $UserInput) {Return $Filter}
            if ($UserInput.ToLower() -ne "y" -and $UserInput.ToLower() -ne "yes") {Return $Filter}
        }

        $UserInput = $null
        $UserInput = Read-Host "whodunnit> filter> import path> " 
        

        if ($null -eq $UserInput) {
            $init = [Init_Functions]::new()
            Return $init.Init_Filter()
        }

        try {
           Return Import-Clixml -LiteralPath $UserInput
        } catch {
            Read-Host "Error: File not found! Overwriting current filter with an empty filter."
            $init = [Init_Functions]::new()
            Return $init.Init_Filter()
        }

        
    }

    <# Handles editing the username list. #>
    [System.Collections.ArrayList]Username_Edit($Filter) {
        
        $NewUser = " "
        $Users = $Filter.Usernames

        do  {
            
            Clear-Host
            Write-Host "==============================="
            Write-Host "   .. > Filter > Edit > Name "
            Write-Host "==============================="
            Write-Host "Negative Search Usernames {"

            foreach ($user in $Users) {if($null -ne $user){Write-Host "    " $user}}
            Write-Host "}"

            $NewUser = Read-Host "Add / Remove > "
            if ($null -eq $NewUser) {break} else {$NewUser = $NewUser.ToLower()}

            $new = $true
            for ($i = 0; $i -lt $Users.Count; $i++) {
                if ($Users[$i] -eq $NewUser) {
                    $Users.Remove($NewUser)
                    $new = $false
                    break
                } 
            } 
            if ($new) {$Users.Add($NewUser)}

        } while ($null -ne $NewUser)
        
        Return $Users

    }

    <# Handles editing the event code list. #>
    [System.Collections.ArrayList]EventCode_Edit($Filter) {

        $Codes = $Filter.EventCodes
        $NewCode = " "

        do {

            Clear-Host
            Write-Host "==============================="
            Write-Host "   .. > Filter > Edit > Code "
            Write-Host "==============================="
            Write-Host "Positive Search Event Codes {"

            foreach ($event in $Codes) {if($null -ne $event){Write-Host "    " $event}}

            $NewCode = Read-Host 'Add / Remove [$ErrorCode | * | reset]> '
            Write-Host "}"

            if ($null -eq $NewCode) {break} else {}
            if ($NewCode -eq "reset") {$Codes = [System.Collections.ArrayList]::new(); $Codes.Add("*"); continue}
            
            $new = $true
            for ($i = 0; $i -lt $Codes.Count; $i++) {
                if ($Codes[$i] -eq $NewCode) {
                    $Codes.Remove($NewCode)
                    $new = $false
                    break
                } 
            } 
            if ($new) {$Codes.Add($NewCode)}

        } while ($null -ne $NewCode)

        Return $Codes

    }

    <# Handles editing the event type list. #>
    [System.Collections.ArrayList]EventTypes_Edit($Filter) {

        $Types = $Filter.EventTypes
        $NewType = " "

        do {

            Clear-Host
            Write-Host "==============================="
            Write-Host "   .. > Filter > Edit > Type "
            Write-Host "==============================="
            Write-Host "Event Types Included {"

            foreach ($EventType in @("Error", "Warning", "Information", "Success Audit", "Failure Audit")) {

                if ($Types.Contains($EventType.ToLower())) {Write-Host "[X] " $EventType}
                else {Write-Host "[ ] " $EventType}

            }
            Write-Host "}"
            
            $NewType = Read-Host "Toggle? > "

            if ($null -eq $NewType) {break}

            $new = $true
            for ($i = 0; $i -lt $Types.Count; $i++) {
                if ($Types[$i].ToLower() -eq $NewType.ToLower()) {
                    $new = $false
                    $Types.Remove($NewType.ToLower())
                    break
                }
            }

            if ($new) {
                if ($NewType.ToLower() -eq "error" `
                -or $NewType.ToLower() -eq "warning" `
                -or $NewType.ToLower() -eq "information" `
                -or $NewType.ToLower() -eq "success audit" `
                -or $NewType.ToLower() -eq "failure audit" ) {
                    $Types.Add($NewType.ToLower())
                }
            }

        } while ($null -ne $NewType)

        Return $Types
    }

    <# Handles editing the event source list. #>
    [System.Collections.ArrayList]EventSources_Edit($Filter) {
        $Sources = $Filter.EventSources
        $NewSource = " "

        do {

            Clear-Host
            Write-Host "==============================="
            Write-Host "  .. > Filter > Edit > Source "
            Write-Host "==============================="
            Write-Host "Event Sources Included {"

            foreach ($EventSource in @("Application", "Hardware Events", "Internet Explorer", "Key Management", "OAlerts", "Security", "System", "Windows Azure", "Windows Powershell")) {

                if ($Sources.Contains($EventSource.ToLower())) {Write-Host "[X] " $EventSource}
                else {Write-Host "[ ] " $EventSource}

            }
            Write-Host "}"

            $NewSource = Read-Host "Toggle? > "

            if ($null -eq $NewSource) {break}

            $new = $true
            for ($i = 0; $i -lt $Sources.Count; $i++) {
                if ($Sources[$i].ToLower() -eq $NewSource.ToLower()) {
                    $new = $false
                    $Sources.Remove($NewSource.ToLower())
                    break
                }
            }

            if ($new) {
                if ($NewSource.ToLower() -eq "application" `
                -or $NewSource.ToLower() -eq "hardware events" `
                -or $NewSource.ToLower() -eq "internet explorer" `
                -or $NewSource.ToLower() -eq "key management" `
                -or $NewSource.ToLower() -eq "oalerts" `
                -or $NewSource.ToLower() -eq "security" `
                -or $NewSource.ToLower() -eq "system" `
                -or $NewSource.ToLower()-eq "windows azure" `
                -or $NewSource.ToLower() -eq "windows powershell" `
                 ) {
                    $Sources.Add($NewSource.ToLower())
                }
            }

        } while ($null -ne $NewSource)

        Return $Sources
    }

    <# Handles editing the time range. #>
    [Filter_Struct]TimeRange_Edit($Filter) {
        
        $edit = [Filter_Functions]::new()
        $type = " "
        do {

            Clear-Host
            Write-Host "==============================="
            Write-Host "   .. > Filter > Edit > Time "
            Write-Host "==============================="
            Write-Host "Start Time: " $Filter.TimeStart
            Write-Host "End Time:   " $Filter.TimeEnd
            Write-Host
            $type = Read-Host "Modify [start | end] > "

            if ($null -eq $type) {Return $Filter}
            if ($type -eq "start") {$Filter.TimeStart = $edit.Time_Edit($Filter.TimeStart)}
            if ($type -eq "end") {$Filter.TimeEnd = $edit.Time_Edit($Filter.TimeEnd)}

        } while ($null -ne $type)

        Return $Filter

    }

    <# Helper function used in TimeRange_Edit. #>
    [datetime]Time_Edit($Time) {
        $timeTemplate = "M/dd/yyyy H:mm"
        $newTime = Read-Host "New Value [MM/dd/yyyy HH:mm] > "

        if ($newTime -eq "") {Return $Time}

        try {
            Return [datetime]::ParseExact($newTime, $timeTemplate, $null)
        }
        catch {
            Return $Time
        }
    }

    <# Handles sorting out events that do not match the filter. #>
   [Log_Struct]Apply_Filter($Filter, $Logs) {

        #Do Magic
        
        $Filtered_Set = ([Init_Functions]::new()).Init_Log()

        foreach ($logtype in $Filter.EventSources) {

            $found = 0
            foreach ($event in @("Application", "HardwareEvents", "InternetExplorer", "KeyManagement", "OAlerts", "Security", "System", "WindowsAzure", "WindowsPowershell")) {
                # Skip logtypes that do not apply to this type
                if ($logtype.replace(' ', '') -ne $event) {continue}

                # The set of logs that this loop refers to
                $Working_Set = $Logs.$logtype
           
           
                foreach ($log in $Working_Set) {

                    # for every log in the working set:
                    #      1) Check Username vs the User list
                    #      2) Check Event Time vs Start Time
                    #      3) Check Event Time vs End Time
                    #      4) Check Event Code vs List
                    #      5) Check Event Type vs List
               
                    # 1) Skip non null username values, and users in the usernames list
                    if ($null -ne $log.Username) {
                        if ($Filter.Usernames.Contains($log.Username.split('\')[1])) {
                            continue
                        }
                    }


                    # 2) Exclude logs created before specified time range
                    if ($null -ne $Filter.TimeStart) {
                        if ($log.TimeGenerated -lt $filter.TimeStart) {
                            continue
                        }
                    }


                    # 3) Exclude logs created after specified time range
                    if ($null -ne $Filter.TimeEnd) {
                        if ($log.TimeGenerated -gt $Filter.TimeEnd) {
                            continue
                        }
                    }


                    # 4) Include only logs with matching event codes, unless * is in the event codes list
                    if (-not $Filter.EventCodes.Contains("*")) {
                        if (-not $Filter.EventCodes.Contains($log.EventID)) {
                            continue
                        }
                    }


                    #  5) Exclude unselected event types
                    if (-not $Filter.EventTypes.Contains($log.EntryType.ToString().ToLower())) {
                        continue
                    }

                    $found += 1
                    
                    $Filtered_Set.$logtype.add($log)
                }
            }

            if ($found -ne 0) {
                $Filtered_Set.loaded = $true
            }

        }

        Return $Filtered_Set
    }


}

class New_Menu_Functions {

    [void]main() {

        $menus = [New_Menu_Functions]::new()
        $load = [Load_Functions]::new()
        $export = [Export_Functions]::new()
        $filt = [Filter_Functions]::new()
        $inits = [Init_Functions]::new()

        $Logs = $inits.Init_Log()
        $Filtered = $inits.Init_Log()
        $Filter = $inits.Init_Filter()

        do {

            $main = Write-Menu -Title 'Whodunnit >' -Sort -Entries @{
                '1) Load Logs' = '$Logs = $menus.load_menu($Logs)'
                '2) Active Filter' = '$Filter = $menus.filter_menu($Filter)'
                '3) Apply Filter' = '$Filtered = $filt.Apply_Filter($Logs, $Filter)'
                '4) Show Logs' = '$export.Show_Log_Stats($Logs, $Filtered)'
                '5) Export Logs' = '$export.Export_Logs($Filtered)'
                '6) Exit' = 'break'
            }

        } while ($true)
    }
    
    [Log_Struct]load_menu($Logs) {
        
        $load = [Load_Functions]::new()

        $load_r = Write-Menu -Title 'Whodunnit > Load >' -Sort -Entries @{
            '1) Read From File' = '$Logs = $load.Import_Logs($Logs)'
            '2) Read From Local Host' = '$Logs = $load.Read_From_Local($Logs)'
            '3) Read From Remote Host' = '$Logs = $Logs'
        }

        Return $Logs
    }

    [Filter_Struct]filter_menu($Filter) {

        $filters = [Filter_Functions]::new()
        $menus = [New_Menu_Functions]::new()

        $filter_r = Write-Menu -Title 'Whodunnit > Filter >' -Sort -Entries @{
            '1) Load Filter' = '$Filter = $filters.Import_Filter($Filter)'
            '2) Edit Filter' = '$Filter = $menus.edit_menu($Filter)'
            '3) Export Filter' = '$filters.Export_Filter($Filter)'
        }

        Return $Filter
    }

    [Filter_Struct]edit_menu($Filter) {

        $edit = [Filter_Functions]::new()

        $edit_r = Write-Menu -Title 'Whodunnit > Filter > Edit >' -Sort -Entries @{
            '1) Username' = '$Filter.Usernames = $edit.Username_Edit($Filter)'
            '2) Time Window' = '$Filter = $edit.TimeRange_Edit($Filter)'
            '3) Event Codes' = '$Filter.EventCodes = $edit.EventCode_Edit($Filter)'
            '4) Event Types' = '$Filter.EventTypes = $edit.EventTypes_Edit(($Filter)'
            '5) Event Sources' = '$Filter.EventSources = $edit.EventSources_Edit($Filter)'
            
        }

        Return $Filter
    }

    
}

<# 
([New_Menu_Functions]::new()).main()
#>

function Start-CLI {
    if ($CreateFilter) {
        Export-Clixml -Path $OutputPath -InputObject ([Init_Functions]::new()).Init_Filter()
    } elseif ($InputLocal) {

    } elseif ($InputFile) {

    } else {Write-Output "how'd you get here?"; Pause}


}

function main {
    
    if ($args.Count -eq 0 -or $UseGUI) {
        
        # Begin GUI
        ([Menu_Functions]::new()).Write_Menu_Main($menu)

    } else { Start-CLI }

}


main

