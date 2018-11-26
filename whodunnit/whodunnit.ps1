. $PSScriptRoot\Write-Menu\Write-Menu.ps1

$menuReturn = Write-Menu -Title 'Whodunnit' -Entries @{
    'Load Logs' = @{
        'Read from File' = @(<#ReadFromFileFunc#>)
        'Read from Local Machine' = @(<#ReadFromLoaclFunc#>)
        'Read from Remote Machine' = @(<#ReadFromRemoteFunc#>)
    }

    'Active Filter' = @{
        'Export' = @(Export-Filter)
        'Load' = @(Load-Filter)
        'Current Filter' = @{
            'Username' = @(Change-Filter-User)
            'Time Window' = @(Change-Filter-Time)
            'Event Codes' = @(<#CodeFilterFunc#>)
            'Event Types' = @(<#TypeFilterFunc#>)
        }
    }

    'Display Logs' = @(<#DisplayFunc#>)

    'Export Logs' = @(<#ExportLogFunc#>)
}


function Export-Filter {
	<# Handles exporting the filter to a file      >
	<  Takes a user input for the filepath         >
	<  Then writes the current filter to the path #>	
	Write-Output "This is a test"
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


