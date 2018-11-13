. $PSScriptRoot\Write-Menu\Write-Menu.ps1

$menuReturn = Write-Menu -Title 'Whodunnit' -Entries @{
    'Load Logs' = @{
        'Read from File' = @(<#ReadFromFileFunc#>)
        'Read from Local Machine' = @(<#ReadFromLoaclFunc#>)
        'Read from Remote Machine' = @(<#ReadFromRemoteFunc#>)
    }

    'Active Filter' = @{
        'Export' = @(<#ExportFunc#>)
        'Load' = @(<#LoadFunc#>)
        'Current Filter' = @{
            'Username' = @(<#UsernameFilterFunc#>)
            'Time Window' = @(<#TimeFilterFunc#>)
            'Event Codes' = @(<#CodeFilterFunc#>)
            'Event Types' = @(<#TypeFilterFunc#>)
        }
    }

    'Display Logs' = @(<#DisplayFunc#>)

    'Export Logs' = @(<#ExportLogFunc#>)
}