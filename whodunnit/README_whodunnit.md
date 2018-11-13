Whodunnit

A tool for parsing, filtering and presenting Windows Event Logs

Interactive mode Menu Options
```	
- Read In Log Files
	- Read from File
	- Read from Local Machine
	- Read from Remote Machine
		-Requires PSRemoting
		-Requires Admin Creds to box
		
- Set Active Filter
	- Export Active Filter to File
	- Load Filter From File
	- Filter Options
		- Username
			-Select from List??
			
		- Time Window
			-Start and end time
			
		- Event Types
			-Positive Selection
			-Negative Selection
			-Load positive events from file
			-Load negative events from file
			
		- Type
			-Positive Selection
			-Negative Selection
			-Load positive events from file
			-Load negative events from file
		
		- Source? -- NOT IMPLEMENTED CURRENTLY
			-Positive Selection
			-Negative Selection
			-Load from File
			
- Display Log Files
	- Log files which match the active filter
		
- Export Log Files
	- Export all Read Log files
	- Export all Log files that match active filter
```

Command Line Interface
```
Usage:
	whodunnit.ps1 -i=/full/path [-f=/full/path] [-o=/full/path] 							 |
	whodunnit.ps1 -l [-f=/full/path] [-o=/full/path] 										 |
	whodunnit.ps1 -r="$IPAddress" -u=$Username -p[=$Password][-f=/full/path] [-o=/full/path] |
	whodunnit.ps1 -c [-f=/full/path/old] [-o=/full/path/new]
	
Flags:
	-c, --create-filter=$PATH
		Creates a filter file at $PATH
		
		-f : copy existing filter file
		-o : output path

	-i, --input-file 
		Specify a previously exported file to read in
		
	-l, --local-logs
		Specify loading logs from local host
		
	-r, --remote-logs
		Specify loading logs from local host
		Username is required, password can be prompted
		
		-u : Administrative Username to use
		-p : Administrative Password to use
		
	-f, --filter
		Load a filter from file
		
	-o, --output-file
		Specify a file to export logs matching filter to
		
Notes:
	If -o is omitted in any command, all output is dumped to standard output.
	If -f is omitted in any command, an empty filter is used.
	if -p has no value set, it will be prompted.
	
```