Whodunnit
=========

Parse, Filter and Present Windows Event Logs with ease, from the comfort and familiarity of a PowerShell Environment.

Key
```
- -> Incomplete
+ -> Complete
? -> Planned for Future Implementaion
```

Interactive mode Menu Options
```	
+ Read In Log Files
	+ Read from File
	+ Read from Local Machine
	? Read from Remote Machine
		?Requires PSRemoting
		?Requires Admin Creds to box
		
+ Set Active Filter
	+ Export Active Filter to File
	+ Load Filter From File
	+ Filter Options
		+ Username
			+Negative Selection
			
		+ Time Window
			+Start time
			+End time
			
		+ Event Types
			+Positive Selection

		+ Type
			+Positive Selection
		
		+ Source 
			+Positive Selection
			
			
+ Display Log Files
	+ Log files which match the active filter
		
+ Export Log Files
	+ Export all Read Log files
	+ Export all Log files that match active filter
```

Command Line Interface
```
Usage:
	whodunnit.ps1 -i=/full/path [-f=/full/path] [-o=/full/path]
	whodunnit.ps1 -l [-f=/full/path] [-o=/full/path]
	whodunnit.ps1 -r="$IPAddress" -u=$Username -p[=$Password] [-f=/full/path] [-o=/full/path]
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
		Specify loading logs from remote host
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

Roadmap
-------

| Descritption | Status | Tenative Timeframe | Date Completed |
| :------------- | :-------------: |  :-------------: | :-------------: |
| Refactor to allow basic scripting  | Complete | End Jan. 2019 | Mid Jan. 2019 |
| Refactor entire project to use classes instead of functions (See issue 4) | Complete | End Mar. 2019 | Beg Apr. 2019 |
| Refactor data types: Change arrays to ArrayLists to drastically improve performance | Complete | Mid Feb. 2019 | Beg Feb. 2019 |
| Implement Interactive Menu | Implementing | ?? |  |
| Export logs to a format that Microsoft's Windows Event Viewer can import | Not Started | ?? | N/A |
| Implement Out-GridView Support for Type and Source lists | Not Started | ?? | N/A |
| Implement Out-GridView Support for previewing Export Set | Not Started | ?? | N/A |
| Import logs from a mounted, but not booted, drive | Not Started | ?? | N/A |
| Import logs from an offline NTFS disk, using MFT | Not Started | ?? | N/A |
| Implement an interactive CLI Menu | Not Started | ?? | N/A |
| Code Formatting, Documentation, and Readability Improvements | Ongoing | N/A | N/A |

Branch Description
------------------
```
This branch was created to contain the changes made while working on Issue #4.
Status: Implementing. 
Detailed: Implemented Exporting functionality. 3-7-19
	  Finished Refactoring. Implementing CLI Functionality 4-5-19
```

Branch Descriptions
------------------
Class_Refactor:

```
This branch was created to contain the changes made while working on Issue #4.
Status: Implementing. 
Detailed: Implemented Exporting functionality. 3-7-19
	  Finished Refactoring. Implementing CLI Functionality 4-5-19

```

Credit Where Credit is Due
--------------------------
[Menu Creation](https://github.com/QuietusPlus/Write-Menu "QuietusPlus's Write-Menu Repo")
