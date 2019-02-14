# Collect-Event

Collecting Event logs from one or multiple comoputers using either FilterXPath or FilterHashtable. Formatting of logs is optional. Multi-threading for performance is supported.

### Prerequisites

#the users must have permission to read Event logs from computer

## Examples
#query local computer for EventID 1309 for the last 7 days using pipelining
(Get-ADComputer $env:COMPUTERNAME ).Name | .\Collect-Event.ps1 -Verbose -ID 1309 -StartTime (Get-Date).AddDays(-7) -Logname application

#query Exchange mailbox servers for EventID 1309 for the last 7 days using pipelining
Get-MailboxServer | .\Collect-Event.ps1 -Verbose -ID 1309 -StartTime (Get-Date).AddDays(-7) -LogName application

#query Exchange mailbox servers for EventID 1309 for the last 7 days using multi threading and formating the output using pipelining
Get-MailboxServer | .\Collect-Event.ps1 -Verbose -ID 1309 -StartTime (Get-Date).AddDays(-7) -LogName application -MultiThread -FormatOutput

#query the first 3 EVTX files for EventIDs 1309,4999 on local computer using pipelining
Get-ChildItem C:\Windows\System32\winevt\Logs -Filter *.evtx | select -First 3 | .\Collect-Event.ps1 -Verbose -ID 1309,4999 -LogName Application

#query Application and System EVTX files for EventIDs 1309,4999 on local computer providing the files to parameter FilePath
.\Collect-Event.ps1 -Verbose -ID 1309,4999 -FilePath "C:\Windows\System32\winevt\Logs\Application.evtx","C:\Windows\System32\winevt\Logs\System.evtx"

#query Application and System log for any entries, which have a value of 4420 using XPath as filter
Get-MailboxServer | .\Collect-Event.ps1 -LogName System,Application -FilterXPath "*[EventData[Data[@Name]='4420']] or *[UserData/*/*='4420']" -Verbose -FormatOutput -MultiThread

## Parameters

### -ComputerName

One or multiple computers, which will be queried. Supports pipeliening. Cannot be combined with parameter FilePath

### -FilePath

One or multiple files in EVTX format, which will be queried. Supports pipelining. Cannot be combined with parameter ComputerName.

### -Logname

Specifies the event logs that this cmdlet get events from. Enter the event log names in a comma-separated list. Wildcards are permitted.

### -ProviderName

One or multiple providers as filter.

### -Keywords

One or multiple keywords as filter. As Get-WinEvent takes filter only in LONG format, I converted the numbers into names. Accepts only the following names:

AuditFailure, AuditSuccess, CorrelationHint, EventLogClassic, ResponseTime, Sqm, WdiContext, WdiDiagnostic

### -ID

One or multiple EventIDs as filter.

### -Level

One or multiple Evet Level as filter. As Get-WinEvent takes levels only as INT, I converted the numbers into names. Accepts only the following names:

Critical, Error, Warning, Information, Verbose

### -StartTime

Timestamp as filter after all events will be queried.

### -EndTime

Timestamp as filter before all events will be queried.

### -UserID

SID as filter.

### -Data

One or multiple strings as filter.

### -FilterXPath

Use XPath as filter.

### -MaxEvents

Specifies the maximum number of events that this cmdlet gets. Enter an integer. The default is to return all the events in the logs or files.

### -Force

Gets debug and analytic logs, in addition to other event logs. The Force parameter is required to get a debug or analytic log when the value of the name parameter includes wildcard characters.

### -Oldest

Indicate that this cmdlet gets the events in oldest-first order. By default, events are returned in newest-first order.

### -Credential

Specifies a user account that has permission to perform this action. The default value is the current user.

### -FormatOutput

Switch to format the result.

### -DateFormat

Format of timestamp, when using parameter FormatOutput. Default is 'yyyy-MM-dd HH:mm:ss'.

### -MultiThread

Switch to use multi threading when querying multiple computers. Only available when using parameter ComputerName

### -Threads

Number of threads created when using parameter MultiThread. Default is 15 and maximum value is 20.

### About

For more information on this script, as well as usage and examples, see
the related blog article on [The Clueless Guy](https://ingogegenwarth.wordpress.com/).

## License

This project is licensed under the MIT License - see the LICENSE.md for details.