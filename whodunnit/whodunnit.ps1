. $PSScriptRoot\Write-Menu\Write-Menu.ps1



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
            '2' {}
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
