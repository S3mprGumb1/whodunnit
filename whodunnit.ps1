


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
}


class Menu_Functions {
    
    [void]Write_Menu_Main() {

        $UserInput = 0

        do {

            $Logs = [Log_Struct]::new()
            $Filter = [Filter_Struct]::new()

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
                '1' {$Logs = Write-Lame-Menu-Load($Logs)}
                '2' {$Filter = Write-Menu-Filter($Filter, $Logs)}
                '3' {Show-Log-Stats}
                '4' {Export-Logs}
            }
    
        } until ($UserInput -ne "1" -and $UserInput -ne "2" -and $UserInput -ne "3" -and $UserInput -ne "4")

    }

    [Log_Struct]Write_Menu_Load($Logs) {
        
        $UserInput = 0

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
                '1' {Return Import-Logs($Logs)}
                '2' {Return Read-From-Local($Logs)}
                '3' {Return Not-Yet-Implemented}
                '4' {Return $Logs}
            }
        
        } until ($UserInput -ne "1" -and $UserInput -ne "2" -and $UserInput -ne "3" -and $UserInput -ne "4")
    
        return $null
    }

    [Filter_Struct]Write_Menu_Filter($Filter, $Logs) {
        
        $UserInput = 0

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
                '1' {$Filter = Import-Filter($Filter)}
                '2' {$Filter = Write-Lame-Menu-Filter-Edit($Filter)}
                '4' {$Filter = Apply-Filter($Filter, $Logs)}
            }
        
        } until ($UserInput -ne "1" -and $UserInput -ne "2" -and $UserInput -ne "3" -and $UserInput -ne "4")

        Return $Filter
    }

    [Filter_Struct]Write_Menu_Edit($Filter) {
        
        $UserInput = 0
        $Bak = $Filter

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
                '1' {$Filter.Username = Edit-Filter-User($Filter.Username)}
                '2' {$Filter = Edit-Filter-Time($Filter)}
                '3' {$Filter.EventCodes = Edit-Filter-EventCodes($Filter.EventCodes)}
                '4' {$Filter.EventTypes = Edit-Filter-EventTypes($Filter.EventTypes)}
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

$menu = New-Object -TypeName Menu_Functions
$menu.write_menu_main()