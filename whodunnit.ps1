

# Structures 
class Log_Struct {
    [Array]$Application
    [Array]$HardwareEvents
    [Array]$InternetExplorer
    [Array]$KeyManagement
    [Array]$OAlerts
    [Array]$Security
    [Array]$System
    [Array]$WindowsAzure
    [Array]$WindowsPowershell
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

        $UserInput = 0
        $Logs = [Log_Struct]::new()
        $Filter = $inits.Init_Filter()

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
                '1' {$Logs = $menu.Write_Menu_Load($Logs)}
                '2' {$Filter = $menu.Write_Menu_Filter($Filter, $Logs)}
                '3' {Show-Log-Stats}
                '4' {Export_Logs($Logs)}
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
            Write-Host "4) Apply"
            Write-Host "5) Back"
            Write-Host

        
            $UserInput = Read-Host "whodunnit> filter>"
            
            switch($UserInput) {
                '3' {$filters.Export_Filter($Filter)}
                '1' {$Filter = $filters.Import_Filter($Filter)}
                '2' {$Filter = $menus.Write_Menu_Edit($Filter)}
                '4' {$Filter = Apply-Filter($Filter, $Logs)}
            }
        
        } until ($UserInput -ne "1" -and $UserInput -ne "2" -and $UserInput -ne "3" -and $UserInput -ne "4")

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
            Write-Host "6) Save"
            Write-Host "7) Cancel"
            Write-Host
    
        
            $UserInput = Read-Host "whodunnit> filter> edit> "
            
            switch($UserInput) {
                '1' {$Filter.Usernames = $edit.Username_Edit($Filter)}
                '2' {$Filter = Edit-Filter-Time($Filter)}
                '3' {$Filter.EventCodes = $edit.EventCode_Edit($Filter)}
                '4' {$Filter.EventTypes = $edit.EventTypes_Edit($Filter)}
                '5' {$Filter.EventSources = Edit-Filter-EventSources($Filter.EventSources)}
                '6' {Return $Filter}
                '7' {Return $Bak}
            }
        
        } until ($UserInput -ne "1" -and $UserInput -ne "2" -and $UserInput -ne "3" -and $UserInput -ne "4" -and $UserInput -ne "5" -and $UserInput -ne "6" -and $UserInput -ne "7")

        Write-Host
        $UserInput = Read-Host "Save Changes? [(y)/n]> "

        if ($UserInput.ToLower() -eq "n") {Return $Bak}
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
        $Filter.MatchingLogs = [Log_Struct]::new()
        $Filter.loaded = $false

        #Defualts
        $Filter.EventCodes.Add("*")

        Return $Filter
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
            $Logs.($LogType.ToString().Remove(" ")) = Get-EventLog -LogName $LogType 

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

            if ($UserInput.ToLower() -ne "y" -and $UserInput.ToLower() -ne "yes") {Return $Filter}
        }

        Return Import-Clixml -LiteralPath (Read-Host "whodunnit> filter> import path> ")
    }

    <# Handles editing the username list. #>
    [System.Collections.ArrayList]Username_Edit($Filter) {
        
        $NewUser = " "
        $Users = $Filter.Usernames

        do  {
            
            Clear-Host
            Write-Host "Negative Search Usernames:"

            foreach ($user in $Users) {if($null -ne $user){Write-Host $user}}

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
            Write-Host "Positive Search Event Codes:"

            foreach ($event in $Codes) {if($null -ne $event){Write-Host $event}}

            $NewCode = Read-Host 'Add / Remove [$ErrorCode | * | reset]> '

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
            Write-Host "Event Types Included:"

            foreach ($EventType in @("Error", "Warning", "Information", "Success Audit", "Failure Audit")) {

                if ($Types.Contains($EventType.ToLower())) {Write-Host "[X] " $EventType}
                else {Write-Host "[ ] " $EventType}

            }

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

    

}

$menu = New-Object -TypeName Menu_Functions
$menu.write_menu_main($menu)