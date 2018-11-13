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
