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
            '3' {}
            '4' {}
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
            '1' {}
            '2' {Read-From-Local}
            '3' {}
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
            '1' {}
            '2' {}
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
        Write-Host "5) Back"
        Write-Host

    
        $UserInput = Read-Host "whodunnit> filter> edit> "
        
        switch($UserInput) {
            '1' {}
            '2' {}
            '3' {}
            '4' {}
            '5' {Return}
        }
    
    } until ($UserInput -ne "1" -and $UserInput -ne "2" -and $UserInput -ne "3" -and $UserInput -ne "4" -and $UserInput -ne "5")
}



# Productive Functions
function Create-Filter {
    param ($Usernames, $TimeStart, $TimeEnd, $EventCodes, $EventTypes)

    $filter = New-Object psobject

    $filter | add-member -type NoteProperty -Name Usernames -Value $Usernames
    $filter | add-member -type NoteProperty -Name TimeStart -Value $TimeStart
    $filter | add-member -type NoteProperty -Name TimeEnd -Value $TimeEnd
    $filter | add-member -type NoteProperty -Name EventCodes -Value $EventCodes
    $filter | add-member -type NoteProperty -Name EventTypes -Value $EventTypes

    return $filter
}

function Create-Log-Struct {
    
    $logs = New-Object psobject

    $logs | Add-Member -type NoteProperty -Name Application -Value ""
    $logs | Add-Member -Type NoteProperty -Name HardwareEvents -Value ""
    $logs | Add-Member -Type NoteProperty -Name InternetExplorer -Value ""
    $logs | Add-Member -Type NoteProperty -Name KeyManagement -Value ""
    $logs | Add-Member -Type NoteProperty -Name OAlerts -Value ""
    $logs | Add-Member -Type NoteProperty -Name Security -Value ""
    $logs | Add-Member -Type NoteProperty -Name System -Value ""
    $logs | Add-Member -Type NoteProperty -Name WindowsAzure -Value ""
    $logs | Add-Member -Type NoteProperty -Name WindowsPowershell -Value ""
    $logs | Add-Member -Type NoteProperty -Name Loaded -Value $false

    return $logs
}

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

        if ($LogType = "Security") {
            if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                Write-Host "Warning! Insignificant priviledges to load security logs!"
                Continue
            }
        }
        
        switch ($i) {
            0 {$Logs.Application = Read-Local-Helper("Application")}
            1 {$Logs.HardwareEvents = Read-Local-Helper("HardwareEvents")}
            2 {$Logs.InternetExplorer = Read-Local-Helper('Internet Explorer')}
            3 {$Logs.KeyManagement = Read-Local-Helper('Key Management Service')}
            4 {$Logs.OAlerts = Read-Local-Helper('OAlerts')}
            5 {$Logs.System = Read-Local-Helper('System')}
            6 {$Logs.WindowsAzure = Read-Local-Helper('Windows Azure')}
            7 {$Logs.WindowsPowershell = Read-Local-Helper('Windows PowerShell')}
            8 {$Logs.Security = Read-Local-Helper('Security')}

        }
    
    }

    $Logs.Loaded = $true
    Write-Progress -Activity "Loading Event Logs from Local Host" -Id 1 -Completed
}

function Read-Local-Helper {
    param ($LogType)

    $LogCounts = (Get-EventLog -List | Where Log -EQ $LogType).Entries.Count

    if ($LogCounts = 0) {Return $null}

    Return Get-EventLog -LogName $LogType 
}


# TODO
function Export-Filter {
	<# Handles exporting the filter to a file      >
	<  Takes a user input for the filepath         >
	<  Then writes the current filter to the path #>	
}

function Load-Filter {
	<# Handles loading a filter from a file                     >
	<  Takes a user input for the filepath                      >
	<  Then loads the filter in the file to the current filter #>	
}

function Change-Filter-User {
	<# Takes a user input to change the global variable $Username #>	
}

function Change-Filter-Time {
	<# Takes a user input for a start and end date (optional time format?)    >
	<  Then updates the global variables $TimeWindowStart and $TimeWindowEnd #>	
}


$CurrentFilter = Create-Filter
$Logs = Create-Log-Struct
Write-Lame-Menu-Main



<# Very Fancy Menu. Will be implemented after everything else works

$menuReturn = Write-Menu -Title 'Whodunnit' -Entries @{
    'Load Logs' = @{
        'Read from File' = @(<#ReadFromFileFunc>)
        'Read from Local Machine' = @(<#ReadFromLoaclFunc>)
        'Read from Remote Machine' = @(<#ReadFromRemoteFunc>)
    }

    'Active Filter' = @{
        'Export' = (Export-Filter)
        'Load' = @(Load-Filter)
        'Current Filter' = @{
            'Username' = @(Change-Filter-User)
            'Time Window' = @(Change-Filter-Time)
            'Event Codes' = @(<#CodeFilterFunc>)
            'Event Types' = @(<#TypeFilterFunc>)
        }
    }

    'Display Logs' = @(<#DisplayFunc>)

    'Export Logs' = @(<#ExportLogFunc>)
}

#>
