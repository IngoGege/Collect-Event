<#

.SYNOPSIS

Created by: https://ingogegenwarth.wordpress.com/
Version:    42 ("What do you get if you multiply six by nine?")
Changed:    26.11.2018

.LINK
https://ingogegenwarth.wordpress.com/
https://blogs.technet.microsoft.com/heyscriptingguy/2014/06/03/use-filterhashtable-to-filter-event-log-with-powershell/
https://blogs.technet.microsoft.com/ashleymcglone/2013/08/28/powershell-get-winevent-xml-madness-getting-details-from-event-logs/
https://learn-powershell.net/2013/05/07/tips-on-implementing-pipeline-support/

.DESCRIPTION

The purpose of the script is to collect from either computers or provided files events based on a give filter. Filterhashtable is used for filtering.

.PARAMETER ComputerName

One or multiple computers, which will be queried. Supports pipeliening. Cannot be combined with parameter FilePath

.PARAMETER FilePath

One or multiple files in EVTX format, which will be queried. Supports pipelining. Cannot be combined with parameter ComputerName.

.PARAMETER Logname

Specifies the event logs that this cmdlet get events from. Enter the event log names in a comma-separated list. Wildcards are permitted.

.PARAMETER ProviderName

One or multiple providers as filter.

.PARAMETER Keywords

One or multiple keywords as filter. As Get-WinEvent takes filter only in LONG format, I converted the numbers into names. Accepts only the following names:

AuditFailure, AuditSuccess, CorrelationHint, EventLogClassic, ResponseTime, Sqm, WdiContext, WdiDiagnostic

.PARAMETER ID

One or multiple EventIDs as filter.

.PARAMETER Level

One or multiple Evet Level as filter. As Get-WinEvent takes levels only as INT, I converted the numbers into names. Accepts only the following names:

Critical, Error, Warning, Information, Verbose

.PARAMETER StartTime

Timestamp as filter after all events will be queried.

.PARAMETER EndTime

Timestamp as filter before all events will be queried.

.PARAMETER UserID

SID as filter.

.PARAMETER Data

One or multiple strings as filter.

.PARAMETER FilterXPath

Use XPath as filter.

.PARAMETER MaxEvents

Specifies the maximum number of events that this cmdlet gets. Enter an integer. The default is to return all the events in the logs or files.

.PARAMETER Force

Gets debug and analytic logs, in addition to other event logs. The Force parameter is required to get a debug or analytic log when the value of the name parameter includes wildcard characters.

.PARAMETER Oldest

Indicate that this cmdlet gets the events in oldest-first order. By default, events are returned in newest-first order.

.PARAMETER Credential

Specifies a user account that has permission to perform this action. The default value is the current user.

.PARAMETER FormatOutput

Switch to format the result.

.PARAMETER DateFormat

Format of timestamp, when using parameter FormatOutput. Default is 'yyyy-MM-dd HH:mm:ss'.

.PARAMETER MultiThread

Switch to use multi threading when querying multiple computers. Only available when using parameter ComputerName

.PARAMETER Threads

Number of threads created when using parameter MultiThread. Default is 15 and maximum value is 20.

.EXAMPLE

# query local computer for EventID 1309 for the last 7 days using pipelining
(Get-ADComputer $env:COMPUTERNAME ).Name | .\Collect-Event.ps1 -Verbose -ID 1309 -StartTime (Get-Date).AddDays(-7) -Logname application

# query Exchange mailbox servers for EventID 1309 for the last 7 days using pipelining
Get-MailboxServer | .\Collect-Event.ps1 -Verbose -ID 1309 -StartTime (Get-Date).AddDays(-7) -LogName application

# query Exchange mailbox servers for EventID 1309 for the last 7 days using multi threading and formating the output using pipelining
Get-MailboxServer | .\Collect-Event.ps1 -Verbose -ID 1309 -StartTime (Get-Date).AddDays(-7) -LogName application -MultiThread -FormatOutput

# query the first 3 EVTX files for EventIDs 1309,4999 on local computer using pipelining
Get-ChildItem C:\Windows\System32\winevt\Logs -Filter *.evtx | select -First 3 | .\Collect-Event.ps1 -Verbose -ID 1309,4999 -LogName Application

# query Application and System EVTX files for EventIDs 1309,4999 on local computer providing the files to parameter FilePath
.\Collect-Event.ps1 -Verbose -ID 1309,4999 -FilePath "C:\Windows\System32\winevt\Logs\Application.evtx","C:\Windows\System32\winevt\Logs\System.evtx"

# query Application and System log for any entries, which have a value of 4420 using XPath as filter
Get-MailboxServer | .\Collect-Event.ps1 -LogName System,Application -FilterXPath "*[EventData[Data[@Name]='4420']] or *[UserData/*/*='4420']" -Verbose -FormatOutput -MultiThread

.NOTES
#>

[CmdletBinding(DefaultParameterSetName = "Computer")]
param(
    [Parameter(
        Mandatory=$false,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0,
        ParameterSetName="HashQuerySet")]
    [Parameter(
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0,
        ParameterSetName="XmlQuerySet")]
    [Parameter(
        ParameterSetName="Computer")]
    [System.String[]]
    $ComputerName,

    [Parameter(
        Mandatory=$false,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=1,
        ParameterSetName="Files")]
    [Alias('FullName')]
    [System.IO.FileInfo[]]
    $FilePath,

    [Parameter(
        Mandatory=$true,
        Position=2,
        ParameterSetName="HashQuerySet")]
    [Parameter(
        ParameterSetName="XmlQuerySet")]
    [Parameter(
        ParameterSetName="Computer")]
    [Parameter(
        ParameterSetName="Files")]
    [System.String[]]
    $LogName,

    [Parameter(
        Mandatory=$false,
        Position=3,
        ParameterSetName="HashQuerySet")]
    [Parameter(
        ParameterSetName="Files")]
    [Parameter(
        ParameterSetName="Computer")]
    [System.String[]]
    $ProviderName,

    [Parameter(
        Mandatory=$false,
        Position=4,
        ParameterSetName="HashQuerySet")]
    [Parameter(
        ParameterSetName="Files")]
    [Parameter(
        ParameterSetName="Computer")]
    [ValidateSet("AuditFailure","AuditSuccess","CorrelationHint","EventLogClassic","ResponseTime","Sqm","WdiContext","WdiDiagnostic")]
    [System.String[]]
    $Keywords,

    [Parameter(
        Mandatory=$false,
        Position=5,
        ParameterSetName="HashQuerySet")]
    [Parameter(
        ParameterSetName="Files")]
    [Parameter(
        ParameterSetName="Computer")]
    [System.Int32[]]
    $ID,

    [Parameter(
        Mandatory=$false,
        ValueFromPipelineByPropertyName=$false,
        Position=6,
        ParameterSetName="HashQuerySet")]
    [Parameter(
        ParameterSetName="Files")]
    [Parameter(
        ParameterSetName="Computer")]
    [ValidateSet("Critical", "Error", "Warning", "Information", "Verbose")]
    [System.String[]]
    $Level,

    [Parameter(
        Mandatory = $false,
        ValueFromPipelineByPropertyName=$false,
        Position=7,
        ParameterSetName="HashQuerySet")]
    [Parameter(
        ParameterSetName="Files")]
    [Parameter(
        ParameterSetName="Computer")]
    [System.DateTime]
    $StartTime,

    [Parameter(
        Mandatory = $false,
        ValueFromPipelineByPropertyName=$false,
        Position=8,
        ParameterSetName="HashQuerySet")]
    [Parameter(
        ParameterSetName="Files")]
    [Parameter(
        ParameterSetName="Computer")]
    [System.DateTime]
    $EndTime,

    [Parameter(
        Mandatory = $false,
        ValueFromPipelineByPropertyName=$false,
        Position=9,
        ParameterSetName="HashQuerySet")]
    [Parameter(
        ParameterSetName="Files")]
    [Parameter(
        ParameterSetName="Computer")]
    [System.Security.Principal.SecurityIdentifier]
    $UserID,

    [Parameter(
        Mandatory=$false,
        Position=10,
        ParameterSetName="HashQuerySet")]
    [Parameter(
        ParameterSetName="Files")]
    [Parameter(
        ParameterSetName="Computer")]
    [System.String[]]
    $Data,

    [Parameter(
        Mandatory=$false,
        Position=11,
        ParameterSetName="XmlQuerySet")]
    [System.String]
    $FilterXPath, #"*[EventData[Data[@Name]='bla']] or *[UserData/*/*='bla']"

    [Parameter(
        Mandatory=$false,
        ValueFromPipelineByPropertyName=$false,
        Position=12,
        ParameterSetName="HashQuerySet")]
    [Parameter(
        ParameterSetName="XmlQuerySet")]
    [Parameter(
        ParameterSetName="Computer")]
    [Parameter(
        ParameterSetName="Files")]
    [System.Int64]
    $MaxEvents,

    [Parameter(
        Mandatory=$false,
        ValueFromPipelineByPropertyName=$false,
        Position=13,
        ParameterSetName="HashQuerySet")]
    [Parameter(
        ParameterSetName="XmlQuerySet")]
    [Parameter(
        ParameterSetName="Computer")]
    [System.Management.Automation.SwitchParameter]
    $Force,

    [Parameter(
        Mandatory=$false,
        ValueFromPipelineByPropertyName=$false,
        Position=14,
        ParameterSetName="HashQuerySet")]
    [Parameter(
        ParameterSetName="XmlQuerySet")]
    [Parameter(
        ParameterSetName="Computer")]
    [Parameter(
        ParameterSetName="Files")]
    [System.Management.Automation.SwitchParameter]
    $Oldest,

    [Parameter(
        Mandatory=$false,
        Position=15,
        ParameterSetName="HashQuerySet")]
    [Parameter(
        ParameterSetName="XmlQuerySet")]
    [Parameter(
        ParameterSetName="Computer")]
    [System.Management.Automation.PsCredential]
    $Credential,

    [Parameter(
        Mandatory=$false,
        ValueFromPipelineByPropertyName=$false,
        Position=16,
        ParameterSetName="HashQuerySet")]
    [Parameter(
        ParameterSetName="XmlQuerySet")]
    [Parameter(
        ParameterSetName="Computer")]
    [Parameter(
        ParameterSetName="Files")]
    [System.Management.Automation.SwitchParameter]
    $FormatOutput,

    [Parameter(
        Mandatory=$false,
        ValueFromPipelineByPropertyName=$false,
        Position=17)]
    [System.String]
    $DateFormat = 'yyyy-MM-dd HH:mm:ss',

    [Parameter(
        Mandatory=$false,
        Position=18,
        ParameterSetName="Computer")]
    [Parameter(
        ParameterSetName="HashQuerySet")]
    [Parameter(
        ParameterSetName="XmlQuerySet")]
    [System.Management.Automation.SwitchParameter]
    $MultiThread,

    [Parameter(
        Mandatory=$false,
        ValueFromPipelineByPropertyName=$false,
        Position=19,
        ParameterSetName="Computer")]
    [Parameter(
        ParameterSetName="HashQuerySet")]
    [Parameter(
        ParameterSetName="XmlQuerySet")]
    [ValidateRange(0,20)]
    [System.Int16]
    $Threads= '15',

    [Parameter(
        Mandatory=$false,
        ValueFromPipeline=$false,
        ValueFromPipelineByPropertyName=$false,
        Position=20,
        ParameterSetName="EventFormat")]
    [System.Diagnostics.Eventing.Reader.EventRecord[]]
    $EventRecord

)

Begin
{

    Write-Debug "Initialize stuff in Begin block"

    if($MultiThread)
    {
        #initiate runspace and make sure we are using single-threaded apartment STA
        [int]$MaxResultTime='240'
        $Jobs = @()
        $Sessionstate = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
        $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $Threads,$Sessionstate, $Host)
        $RunspacePool.ApartmentState = "STA"
        $RunspacePool.Open()
        [int]$j='1'
    }

    $objcol = @()
    function Format-Message ()
    {
        [CmdletBinding()]
        param(
            [Parameter(
                ValueFromPipeline=$true,
                ValueFromPipelineByPropertyName=$true,
                Position=0)]
            [System.Object[]]
            $Events,

            [Parameter(
                Position=1)]
            [System.String]
            $DateFormat = 'yyyy-MM-dd HH:mm:ss'
        )
        Begin
        {
            $objcol = @()
        }

        Process
        {
            ForEach ($Event in $Events)
            {
                # Convert the event to XML
                $eventXML = [xml]$Event.ToXml()
                # Iterate through each one of the XML message properties
                $data = New-Object -TypeName PSObject
                $data | add-member -type NoteProperty -Name TimeCreatedUTC -Value $(Get-Date $((Get-Date $eventXML.Event.System.TimeCreated.SystemTime).ToUniversalTime()) -Format $DateFormat)
                $data | add-member -type NoteProperty -Name MachineName -Value $($eventXML.Event.System.Computer)
                if ([System.String] -eq $eventXML.Event.System.EventID.GetType())
                {
                    $data | add-member -type NoteProperty -Name EventID -Value $($eventXML.Event.System.EventID)
                }
                else
                {
                    $data | add-member -type NoteProperty -Name EventID -Value $($eventXML.Event.System.EventID.'#text')
                }
                if (($eventXML.Event.EventData.Data | Get-Member -MemberType Property -ErrorAction SilentlyContinue).Count -gt 1)
                {
                    $Properties = $eventXML.Event.EventData | Get-Member -MemberType property | Select-Object Name
                    [System.String]$Value = ''
                    ForEach($Property in $Properties)
                    {
                        Write-Debug "Processing property $($Property)"
                        if('System.String' -eq $eventXML.Event.EventData.($Property.Name).GetType().FullName)
                        {
                            $Value += "$($Property.Name):$($eventXML.Event.EventData.($Property.Name))"
                        }
                        else
                        {
                            $Value += ($eventXML.Event.EventData.Data | ForEach-Object {$($_.Name + ':' + $_.'#text')} ) -join '|'
                        }
                    }
                    $data | add-member -type NoteProperty -Name Data -Value $Value
                }
                else
                {
                    if([system.String]::IsNullOrEmpty($eventXML.Event.EventData))
                    {
                        $data | add-member -type NoteProperty -Name Data -Value $($Event.FormatDescription())
                    }
                    elseif ($eventXML.Event.EventData.Data.Name.Count -gt 1)
                    {
                        [System.String]$Value = ''
                        [System.Int16]$i = 0
                        While ($i -lt $eventXML.Event.EventData.Data.Name.Count)
                        {
                            $Value += ($eventXML.Event.EventData.Data[$i].Name +":"+$eventXML.Event.EventData.Data[$i].'#text' + '|')
                            $Value = $Value.Trim('|')
                            $i++
                        }
                        $data | add-member -type NoteProperty -Name Data -Value $Value
                    }
                    else
                    {
                        $data | add-member -type NoteProperty -Name Data -Value $($eventXML.Event.EventData.Data -join '|')
                    }
                }

                $objcol += $data
            }
        }
        End
        {
            $objcol
        }
    }

    $timer = [System.Diagnostics.Stopwatch]::StartNew()

}

Process
{
    Write-Debug "Process block"

    if(-not $EventRecord)
    {
    try
    {
        $advparams = @{}
        if($MaxEvents -gt 0)
        {
            $advparams.Add('MaxEvents',$MaxEvents)
        }
        if($Force)
        {
            $advparams.Add('Force',$Force)
        }
        if($Oldest)
        {
            $advparams.Add('Oldest',$Oldest)
        }
        if([System.String]::IsNullOrEmpty($FilterXPath))
        {
            #build filter hash
            Write-Verbose "Building FilterHashTable..."
            $filterHash = @{}
            if (-not [System.String]::IsNullOrEmpty($LogName))
            {
                $filterHash.Add('LogName',$LogName)
            }
            if (-not [System.String]::IsNullOrEmpty($ProviderName))
            {
                $filterHash.Add('ProviderName',$ProviderName)
            }
            if (-not [System.String]::IsNullOrEmpty($Keywords))
            {
                $keywordsFilter = @()
                ForEach ($keyword in $Keywords)
                {
                    switch ($keyword)
                        {
                            "AuditFailure"      {$keyValue = '4503599627370496'}
                            "AuditSuccess"      {$keyValue = '9007199254740992'}
                            "CorrelationHint"   {$keyValue = '18014398509481984'}
                            "EventLogClassic"   {$keyValue = '36028797018963968'}
                            "ResponseTime"      {$keyValue = '281474976710656'}
                            "Sqm"               {$keyValue = '2251799813685248'}
                            "WdiContext"        {$keyValue = '562949953421312'}
                            "WdiDiagnostic"     {$keyValue = '1125899906842624'}
                        }
                    Write-Verbose "Adding keyword $($keyword) with value $($keyValue)"
                    $keywordsFilter += $keyValue
                }

                $filterHash.Add('Keywords',$keywordsFilter)
            }
            if (-not [System.String]::IsNullOrEmpty($ID))
            {
                $filterHash.Add('ID',$ID)
            }
            if (-not [System.String]::IsNullOrEmpty($Level))
            {
                $levelFilter = @()
                ForEach ($severity in $Level)
                {
                    switch ($severity)
                        {
                            "Critical"      {$sev = 1}
                            "Error"         {$sev = 2}
                            "Warning"       {$sev = 3}
                            "Information"   {$sev = 4}
                            "Verbose"       {$sev = 5}
                        }
                    $levelFilter += $sev
                }

                $filterHash.Add('Level',$levelFilter)
            }
            if (-not [System.String]::IsNullOrEmpty($StartTime))
            {
                $filterHash.Add('StartTime',$StartTime)
            }
            if (-not [System.String]::IsNullOrEmpty($EndTime))
            {
                $filterHash.Add('EndTime',$EndTime)
            }
            if (-not [System.String]::IsNullOrEmpty($UserID))
            {
                $filterHash.Add('UserID',$UserID)
            }
            if (-not [System.String]::IsNullOrEmpty($Data))
            {
                $filterHash.Add('Data',$Data)
            }
            if (-not [System.String]::IsNullOrEmpty($FilePath))
            {
                Write-Verbose "Processing files..."
                Write-Verbose "Adding FilePath:$($FilePath -join ',')"
                $filterHash.Add('Path',$($FilePath -join ','))
            }

            $params = @{
                    FilterHashtable = $filterHash
                    ErrorAction = 'SilentlyContinue'
                    Verbose = $VerbosePreference
                }
            Write-Verbose "Done building FilterHashTable..."
        }
        else
        {
            $params = @{
                ErrorAction = 'SilentlyContinue'
                Verbose = $VerbosePreference
                FilterXPath = $FilterXPath
                LogName = $LogName
            }
        }

        if('Inquire' -eq $DebugPreference)
        {
            $params
            $params.FilterHashtable
            $advparams
        }

        #query logs

        if ($MultiThread)
        {
            ForEach ($Computer in $Computername)
            {
                try{
                    $j++ | Out-Null
                    <##if ('Microsoft.ActiveDirectory.Management.ADComputer' -eq $Computer.GetType().FullName)
                    {
                        $Computer = $Computer.Name
                    }##>

                    if ($params.ContainsKey('Computer'))
                    {
                        $params.Remove('Computer')
                    }

                    $params.Add('Computer',$Computer)
                    $PowershellThread = [powershell]::Create().AddCommand("Get-WinEvent")
                    #adding parameters
                    $params.GetEnumerator() | ForEach-Object {
                        $PowershellThread.AddParameter($_.Key,$_.Value) | Out-Null
                    }
                    $advparams.GetEnumerator() | ForEach-Object {
                        $PowershellThread.AddParameter($_.Key,$_.Value) | Out-Null
                    }
                    $PowershellThread.RunspacePool = $RunspacePool
                    $Handle = $PowershellThread.BeginInvoke()
                    $Job = "" | Select-Object Handle, Thread, object
                    $Job.Handle = $Handle
                    $Job.Thread = $PowershellThread
                    $Job.Object = $Computer
                    $Jobs += $Job
                }
                catch{
                    $Error[0].Exception
                }
            }
        }
        else
        {
            if ($FilePath)
            {
                #fix for duplicates when piping files
                $objcol = @()
                $objcol += Get-WinEvent @params @advparams
            }
            else
            {
                ForEach ($Computer in $ComputerName)
                {
                    <##if ('Microsoft.ActiveDirectory.Management.ADComputer' -eq $Computer.GetType().FullName)
                    {
                        Write-Verbose "Object is type Microsoft.ActiveDirectory.Management.ADComputer"
                        $Computer = $Computer.Name
                    }##>

                    if ($params.ContainsKey('Computer'))
                    {
                        $params.Remove('Computer')
                    }

                    $params.Add('Computer',$Computer)
                    Write-Verbose "Processing computer $($Computer)..."
                    #query logs
                    $objcol += Get-WinEvent @params @advparams
                }
            }
        }
    }
    catch{
        #create object
        $returnValue = New-Object -TypeName PSObject
        #get all properties from last error
        $ErrorProperties = $Error[0] | Get-Member -MemberType Property
        #add existing properties to object
        ForEach ($property in $ErrorProperties)
        {
            if ($property.Name -eq 'InvocationInfo'){
                $returnValue | Add-Member -Type NoteProperty -Name 'InvocationInfo' -Value $($Error[0].InvocationInfo.PositionMessage)
            }
            else {
                $returnValue | Add-Member -Type NoteProperty -Name $($property.Name) -Value $($Error[0].$($property.Name))
            }
        }
        #return object
        $returnValue
        break
    }
    }

}

End
{
    Write-Debug "Final work in End block"

    if ($MultiThread)
    {
        $SleepTimer = 200
        $ResultTimer = Get-Date
        While (@($Jobs | Where-Object {$_.Handle -ne $Null}).count -gt 0) {
            $Remaining = "$($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False}).object)"
            If ($Remaining.Length -gt 60){
                $Remaining = $Remaining.Substring(0,60) + "..."
            }
            Write-Progress `
                -id 1 `
                -Activity "Waiting for Jobs - $($Threads - $($RunspacePool.GetAvailableRunspaces())) of $Threads threads running" `
                -PercentComplete (($Jobs.count - $($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False}).count)) / $Jobs.Count * 100) `
                -Status "$(@($($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False})).count) remaining - $Remaining"

            ForEach ($Job in $($Jobs | Where-Object {$_.Handle.IsCompleted -eq $True})) {
                $objcol += $Job.Thread.EndInvoke($Job.Handle)
                $Job.Thread.Dispose()
                $Job.Thread = $Null
                $Job.Handle = $Null
                $ResultTimer = Get-Date
            }

            If (($(Get-Date) - $ResultTimer).totalseconds -gt $MaxResultTime) {
                Write-Warning "Child script appears to be frozen for $($Job.Object), try increasing MaxResultTime"
                #Exit
            }

            Start-Sleep -Milliseconds $SleepTimer
            # kill all incomplete threads when hit "CTRL+q"
            If ($Host.UI.RawUI.KeyAvailable) {
                $KeyInput = $Host.UI.RawUI.ReadKey("IncludeKeyUp,NoEcho")
                If (($KeyInput.ControlKeyState -cmatch '(Right|Left)CtrlPressed') -and ($KeyInput.VirtualKeyCode -eq '81')) {
                    Write-Host -fore red "Kill all incomplete threads....."
                        ForEach ($Job in $($Jobs | Where-Object {$_.Handle.IsCompleted -eq $False})) {
                            Write-Host -fore yellow "Stopping job $($Job.Object) ...."
                            $Job.Thread.Stop()
                            $Job.Thread.Dispose()
                        }
                    Write-Host -fore red "Exit script now!"
                    Exit
                }
            }
        }
        Write-Progress `
                -id 1 `
                -Activity "Waiting for Jobs - $($Threads - $($RunspacePool.GetAvailableRunspaces())) of $Threads threads running" `
                -Completed `
                -Status "Completed"
        # clean-up
        $RunspacePool.Close() | Out-Null
        $RunspacePool.Dispose() | Out-Null
        [System.GC]::Collect()
    }
    if ($FormatOutput)
    {
        Write-Verbose "Formatting output. This might take a while..."
        #$objcol | Sort-Object TimeCreated | Format-Message -DateFormat $DateFormat
        [int]$o = 0
        ForEach ($obj in ($objcol | Sort-Object TimeCreated))
        {
            Format-Message -Events $obj -DateFormat $DateFormat
            Write-Progress `
                -id 1 `
                -Activity "Processing events" `
                -PercentComplete ($o / $objcol.Count * 100) `
                -Status "Total - $($objcol.Count) Remaining - $($objcol.Count - $o)"
            $o++
        }
    }
    elseif ($EventRecord)
    {
        Write-Verbose "Formatting output. This might take a while..."
        #$objcol | Sort-Object TimeCreated | Format-Message -DateFormat $DateFormat
        [int]$o = 0
        ForEach ($obj in ($EventRecord | Sort-Object TimeCreated))
        {
            Format-Message -Events $obj -DateFormat $DateFormat
            Write-Progress `
                -id 1 `
                -Activity "Processing events" `
                -PercentComplete ($o / $EventRecord.Count * 100) `
                -Status "Total - $($EventRecord.Count) Remaining - $($EventRecord.Count - $o)"
            $o++
        }
    }
    else
    {
        $objcol | Sort-Object TimeCreated
    }

    $timer.Stop()
    Write-Verbose "ScriptRuntime:$($timer.Elapsed.ToString())"
}