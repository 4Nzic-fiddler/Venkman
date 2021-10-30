# Venkman
Venkman is an experimental .Net Windows application that helps defenders detect when an attacker might be muting or blocking event logs on an endpoint. This project was presented at the Texas Cyber Summit on 30 October 2021: https://texascyber.com/briefings_schedule/busting-ghosts-in-the-logs/ Venkman monitors ETW and saves information about processes and event counts to a log on a file share. It is configurable via internal DNS TXT records.

## DNS Setup
As a Domain Admin in your Active Directory environment, add two TXT records to your internal domain forward lookup zone, in the same domain where your workstations and servers that will be running Venkman are. The default names for these records are venkman-logs-path and venkman-etw-providers, but you are encouraged to change these names to be stealthier.

In the value of the logs path TXT record, put the UNC path to a location on a file share where Venkman clients should store their logs. Each Venkman client will create a file named according to their hostname in this file share. You must collect these logs to a central location that you can query (e.g. Custom Log if you are using Azure Sentinel).

In the value of the etw providers TXT record, put a pipe (|) delimited list of the names of the ETW providers that you wish the Venkman clients to subscribe to. Note that if you use any of the Kernel ETW providers, Venkman clients will need to run as Local Admin in order to subscribe successfully to those. Otherwise, Venkman clients only need to run as a user that is in the Performance Log Users group to subscribe to non-kernel ETW providers.

You may change either of these DNS settings at any time and all running Venkman clients should update their settings next time they check in (within a minute) or the next time they start if they aren't running at the time.

## Configuration 
Edit the Ecto1.settings file to change the following three settings:
 * DNSPath: Set this value to the name of the DNS TXT record that you changed venkman-logs-path to in the DNS setup above.
 * DNSETW: Set this value to the name of the DNS TXT record that you changed venkman-etw-providers to in the DNS setup above.
 * DefaultLogPath: Set this value to a UNC path to use as the default if the DNS lookups should fail. In that case, Venkman will also use a list of default ETW providers.

## Running
If you want to use any kernel ETW providers, you must run Venkman as a user in the Local Administrators group. If you don't need to subscribe to kernel providers, Venkman should run as a user in the Performance Log Users group. 

## Azure Sentinel Setup
Install the Microsoft Monitoring Agent on the computer containing the file share where the client logs will be saved. Under Agents Management in your Log Analytics Workspace, add a "Custom Log" source and give it the path where the logs can be found. Call the custom log source Venkman_CL (the _CL portion is automatically added for you).

In your Azure Sentinel Logs query view, once a few events have been added to the Venkman_CL table, save the following KQL code as a function named VenkmanLogs (or whatever you like):
```
Venkman_CL 
| where RawData startswith_cs "#"   // Get the names of the columns in order (header rows start with #)
| extend RawData = replace_string(RawData, "#", "")
| extend RawData = trim(@"[^\w]+", RawData)
| order by TimeGenerated desc
| take 1                            // Just take the most recent column headers
| extend colnames = split(RawData, "|")
| project colnames
| extend key=1   // key=1 is a trick to join all rows on something constant 
| join kind=fullouter ( Venkman_CL
    | where RawData !startswith_cs "#" // get value rows (not starting with #)
    | extend RawData = trim(@"[^\w]+", RawData)
    | extend values = split(RawData, "|") // split by delimiter character (pipe)
    | project values
    | extend key=1) 
  on key
| extend keyvals = zip(colnames, values) // put the keys and values together as a 2D array
| serialize 
| project keyvals, rownum = row_number()
| mv-expand keyvals
| extend Key = tostring(keyvals[0]), Value = tostring(keyvals[1])
| evaluate pivot(Key, any(Value), rownum)
| project-away rownum
| extend Total = toint(Total)
| extend TimeGenerated = todatetime(Date)
```

Set up a new Sentinel Alert to detect when logs stop coming from an endpoint but Venkman is still reporting in:
```
VenkmanLogs
| summarize count() by Hostname
| join kind = anti(Event | summarize count() by Computer | extend Hostname = tostring(split(Computer, ".", 0)[0]) on Hostname
```
Set this to run every five minutes or whatever period of time you wish to check for alarms. It is recommended to set up Incident grouping so that if an attacker blocks logs from an endpoint for an extended period of time, it doesn't generate a new incident every five minutes. You may want to set up rule automation to increase the severity of the alarm the longer it keeps going.
