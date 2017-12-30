<#
.SYNOPSIS
    Disables inactive Active Directory accounts.

.DESCRIPTION
    Disables inactive Active Directory accounts.

.NOTES
    Author: PowerMonkey500
    Date: 9/22/2017

    Edited: JBear
    Date: 12/29/2017

    WARNING: THIS SCRIPT WILL OVERWRITE EXTENSIONATTRIBUTE3 FOR INACTIVE USERS, MAKE SURE YOU ARE NOT USING IT FOR ANYTHING ELSE
    This script is SLOW because it gets the most accurate last logon possible by comparing results from all DCs. By default the lastlogontimestamp is only replicated every 14 days minus a random percentage of 5.
#>

#Function declarations
Function Start-Logging {
    <#
    .SYNOPSIS
    This function starts a transcript in the specified directory and cleans up any files older than the specified number of days. 

    .DESCRIPTION
    Please ensure that the log directory specified is empty, as this function will clean that folder.

    .EXAMPLE
    Start-Logging -LogDirectory "C:\ScriptLogs\LogFolder" -LogName $LogName -LogRetentionDays 30

    .LINK
    https://github.com/AndrewEllis93/PowerShell-Scripts

    .NOTES
    #>
    param (
    
        [Parameter(Mandatory=$true)]
        [String]$LogDirectory,
        [Parameter(Mandatory=$true)]
        [String]$LogName,
        [Parameter(Mandatory=$true)]
        [Int]$LogRetentionDays
    )

    #Sets screen buffer from 120 width to 500 width. This stops truncation in the log.
    $ErrorActionPreference = 'SilentlyContinue'
    $pshost = Get-Host
    $pswindow = $pshost.UI.RawUI
 
    $newsize = $pswindow.BufferSize
    $newsize.Height = 3000
    $newsize.Width = 500
    $pswindow.BufferSize = $newsize
 
    $newsize = $pswindow.WindowSize
    $newsize.Height = 50
    $newsize.Width = 500
    $pswindow.WindowSize = $newsize
    $ErrorActionPreference = 'Continue'

    #Remove the trailing slash ifpresent. 
    if($LogDirectory -like "*\") {
    
        $LogDirectory = $LogDirectory.Substring((0,($LogDirectory.Length-1))
    }

    #Create log directory ifit does not exist already
    if(!(Test-Path $LogDirectory)) {
    
        New-Item -ItemType Directory $LogDirectory -Force | Out-Null
    }

    $Today = Get-Date -Format M-d-y
    Start-Transcript -Append -Path ($LogDirectory + "\" + $LogName + "." + $Today + ".log") | Out-Null

    #Shows proper date in log.
    Write-Output ("Start time: " + (Get-Date))

    #Purges log files older than X days
    $RetentionDate = (Get-Date).AddDays(-$LogRetentionDays)
    Get-ChildItem -Path $LogDirectory -Recurse -Force | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $RetentionDate -and $_.Name -like "*.log"} | Remove-Item -Force
} 

Function Disable-InactiveADAccounts {
    <#
    .SYNOPSIS
    This script disables AD accounts older than the threshold (in days) and stamps them in ExtensionAttribute3 with the disabled date. It also sends an email report.

    .DESCRIPTION
    Make sure you read through the comments (as with all of these scripts). It just finds the last logon for all AD accounts and disables any that have been inactive for X number of days (depending on what threshold you set). The difference with this script is that it gets the most accurate last logon available by comparing the results from all domain controllers. By default the lastlogontimestamp is only replicated every 14 days minus a random percentage of 5. This makes it much more accurate. It also supports an exclusion AD group that you can put things like service accounts in to prevent them from being disabled. It will also email a report to the specified email addresses.
    "-ReportOnly" will skip actually disabling the AD accounts and just send an email report of inactivity instead. 

    .EXAMPLE
    Disable-InactiveADAccounts -To @("email@domain.com","email2@domain.com") -From "noreply@domain.com" -SMTPServer "server.domain.local" -UTCSkew -5 -OutputDirectory "C:\ScriptLogs\Disable-InactiveADAccounts" -ExclusionGroup "ServiceAccounts" -DaysThreshold 30 -ReportOnly $True

    .LINK
    https://github.com/AndrewEllis93/PowerShell-Scripts

    .NOTES
    #>

    Param(

        [Parameter(Mandatory=$true)]
        [String]$From,

        #If $true, email report will be sent without disabling or stamping any AD accounts.
        [Boolean]$ReportOnly = $False, 

        [Parameter(Mandatory=$true)]
        [String]$SMTPServer,

        #Array. You can add more than one entry.
        [Parameter(Mandatory=$true)]
        [Array]$To, 

        #Accounting for the time zone difference, since some results are given in UTC. Eastern time is UTC-5. 
        [Parameter(Mandatory=$true)]
        [Int]$UTCSkew, 

        #Threshold of days of inactivity before disabling the user. Defaults to 30 days.
        [Int]$DaysThreshold = 30, 

        #Where to export CSVs etc.
        [Parameter(Mandatory=$true)]
        [String]$OutputDirectory, 

        [String]$Subject = "Account Cleanup Report",

        #Amount of times to try for identical DC results before giving up. 30 second retry delay after each failure.
        [Int]$MaxTryCount = 20, 

        #AD group containing accounts to exclude.
        [String]$ExclusionGroup 
    )

    #Remove trailing slash ifpresent.
    if($OutputDirectory -like "*\") {
    
        $OutputDirectory = $OutputDirectory.substring(0,($OutputDirectory.Length-1))
    }

    #Declare try count at 0.
    $TryCount= 0

    #Get all DCs, add array names to vars array
    $DCnames = (Get-ADGroupMember 'Domain Controllers').Name

    #Check that results match from each DC by comparing all results in order. ifthere is a mismatch, wait 30 seconds and retry, up to the MaxTryCount (default 20)
    While(($ComparisonResults -contains $False -or !$ComparisonResults) -and $TryCount -lt $MaxTryCount) {

        #Fetch AD users from each DC, add to named array
        $DCnames | ForEach-Object {

            #Filters / Exclusions. 
            Write-Output ("Fetching last logon times from " + $_ + "...")
            New-Variable -Name $_ -Value (Get-ADUser -Filter { Enabled -eq $True } -Server $_ -Properties DistinguishedName,LastLogon,LastLogonTimestamp,whenCreated,Description | Sort SamAccountName) -Force
        } 

        $ComparisonResults = ForEach($i in 0..(($DCnames.Count)-1)) {

            if($i -le (($DCnames.Count)-2)) {

                Write-Output ("Comparing results from " + $DCnames[$i] + " and " + $DCnames[$i+1] + "...")
                $NotEqual = Compare-Object (Get-Variable -Name $DCnames[$i]).Value (Get-Variable -Name $DCnames[$i+1]).Value -Property SamAccountName

                if(!$NotEqual) {
                
                    $True
                }

                else {
                
                    $False
                }
            }
        }

        if($ComparisonResults -contains $False) {

            Write-Warning "One or more DCs returned differing results. This is likely just replication delay. Retrying in 30 seconds..."
            $TryCount++
            Start-Sleep 30
        }
    }

    if($TryCount -lt $MaxTryCount) {
    
        Write-Output "All DC results are identical!"
    }

    else {
    
        Throw "Try limit exceeded. Aborting."
    }

    #Get current time for comparison later. 
    $StartTime = Get-Date

    #User count so we know how many times to loop.
    $UserCount = (Get-Variable -Name $DCnames[0]).Value.Count

    #Create results array of the same size
    $FullResults = @($null) * $UserCount

    $UserEntries = foreach($DC in $DCNames) { 

        (Get-Variable -Name $DC).Value
    }

    #Loop through array indexes
    ForEach ($i in 0..($UserCount -1)) {

        Write-Progress -Activity "Comparing Domain Controller data..." -Status ("Percent Complete:" + "{0:N0}" -f ((($i) / 0..($UserCount -1)) * 100) + "%") -PercentComplete ((($i) / 0..($UserCount -1)) * 100) -ErrorAction SilentlyContinue

        #Grab user object from each resultant array, make array of each user object
        if(($UserEntries.SamAccountName | Select-Object -Unique).Count -gt 1) {
        
            Throw "A user mismatch at index $i has occurred. Aborting."
        }

        #Find most recent LastLogon, whenCreated, and LastLogonTimestamp.
        if($UserEntries.LastLogon) {

            [DateTime]$LastLogon = [DateTime]::FromFileTimeUtc(($UserEntries | Measure-Object -Property LastLogon -Maximum).Maximum)
            [DateTime]$TrueLastLogon = $LastLogon
        }

        else {
        
            [DateTime]$LastLogon = 0
            $TrueLastLogon = 0
        } 

        if($UserEntries.whenCreated) {

            [DateTime]$whenCreated = $UserEntries[0].whenCreated
        }

        else {
        
            [DateTime]$whenCreated = 0
        }

        if($UserEntries.LastLogonTimestamp) {

            [DateTime]$LastLogonTimestamp = [DateTime]::FromFileTimeUtc(($UserEntries | Measure-Object -Property LastLogonTimestamp -Maximum).Maximum)
        }

        else {
        
            [DateTime]$LastLogonTimestamp = 0
        }

        #ifLastLogonTimestamp is newer, use that instead of LastLogon.
        if($LastLogonTimestamp -gt $LastLogon) {
        
            $TrueLastLogon = $LastLogonTimestamp
        }

        #UTC conversion
        if($TrueLastLogon -ne 0) {
        
            $TrueLastLogon = $TrueLastLogon.AddHours($UTCSkew)
        }

        #ifTrueLastLogon is older than 20 years (essentially null/zero), set to true zero
        if((New-TimeSpan -Start $TrueLastLogon -End $StartTime).Days -gt 7300) {
        
            [String]$TrueLastLogon = $null
        }

        #Calculate days of inactivity.
        if($TrueLastLogon -ne $null -and $TrueLastLogon -ne "") {
        
            $DaysInactive = (New-TimeSpan -Start $TrueLastLogon -End $StartTime).Days
        }

        else {
        
            $DaysInactive = (New-TimeSpan -Start $whenCreated -End $StartTime).Days
        }

        [PSCustomObject] @{
    
            SamAccountName=$UserEntries[0].SamAccountName
            Enabled=$UserEntries[0].Enabled
            LastLogon=$TrueLastLogon
            WhenCreated=$whenCreated
            DaysInactive=$DaysInactive
            GivenName=$UserEntries[0].GivenName
            Surname=$UserEntries[0].SurName
            Name=$UserEntries[0].Name
            DistinguishedName=$UserEntries[0].DistinguishedName
            Description=$UserEntries[0].Description
        }  

        #Write-Output ("User: " + $_.SamAccountName + " - Last logon: $TrueLastLogon ($DaysInactive day(s) inactivity) - $PercentComplete% complete.")
    }

    Write-Output "Getting exclusion group members..."
    $UserExclusions = (Get-ADGroupMember -Identity $ExclusionGroup -ErrorAction Stop).SamAccountName

    #Splits "other" and "real" users into two different arrays.
    Write-Output "Filtering users..."
    $RealUsersResults = $FullResults | Where-Object { $UserExclusions -notcontains $_.SamAccountName }

    $FullResults = $FullResults | Where-Object { $_ -ne $null }

    #For some reason compare-object is not working properly without specifying all properties. Don't know why. 
    $OtherUsersResults = Compare-Object $RealUsersResults $FullResults `
    -Property SamAccountName,enabled,lastlogon,whencreated,DaysInactive,givenname,surname,name,distinguishedname,Description | 
    Select-Object SamAccountName,enabled,lastlogon,whencreated,DaysInactive,givenname,surname,name,distinguishedname,Description

    #Add to UsersDisabled array for CSV report. Also disable and stamp accounts ifReportOnly is set to false (default).
    if(!$ReportOnly) {

        $UsersDisabled = $RealUsersResults | ForEach-Object {

            if($_.DaysInactive -ge $DaysThreshold) {

                Write-Output ("Disabling " + $_.SamAccountName + "...")
                Disable-ADAccount -Identity $_.SamAccountName
                $Date = "INACTIVE SINCE " + (Get-Date)
                Set-ADUser -Identity $_.SamAccountName -Replace @{ExtensionAttribute3=$Date}
            }
        }
    }

    else {

        $UsersDisabled = $RealUsersResults | ForEach-Object {

            if($_.DaysInactive -ge $DaysThreshold) {
                
                $_
            }
        }
    }

    #Filtered users - add to UsersNotDisabled array for CSV report
    $OtherInactiveUsers = $OtherUsersResults | ForEach-Object {

        if($_.DaysInactive -ge $DaysThreshold) {

            $_
        }
    }

    #Reports exclusion group members.
    $ExcludedUsersReport = $FullResults | Where-Object {$UserExclusions -contains $_.SamAccountName} | Select-Object * -ExcludeProperty Enabled,LastLogon,whenCreated,DaysInactive

    #Export CSVs to output directory
    if(!(Test-Path $OutputDirectory)) {
    
        New-Item -ItemType Directory $OutputDirectory
    }

    $UsersDisabledCSV = $OutputDirectory + "\InactiveUsers-Disabled.csv"
    $UsersNotDisabledCSV = $OutputDirectory + "\InactiveUsers-Excluded.csv"
    $ExcludedUsersReportCSV = $OutputDirectory + "\Auto-Disable Exclusions.csv"
    $UsersDisabled | Export-CSV $UsersDisabledCSV -NoTypeInformation -Force
    $OtherInactiveUsers | Export-CSV $UsersNotDisabledCSV -NoTypeInformation -Force
    $ExcludedUsersReport | Export-CSV $ExcludedUsersReportCSV -NoTypeInformation -Force

    <#
    # This is here ifyou want to use it in conjunction with my Move-Disabled script. Just uncomment and replace with your scheduled task path. 
    Write-Output "Starting Move-Disabled task..."
    Start-ScheduledTask -TaskName "\Move-Disabled"
    #>

    #Send email with CSVs as attachments
    Write-Output "Sending email..."
    Send-MailMessage -Attachments @($UsersDisabledCSV,$UsersNotDisabledCSV,$ExcludedUsersReportCSV) -From $From -SmtpServer $SMTPServer -To $To -Subject $Subject

}

Function Get-ADUserLastLogon ([string]$UserName) {
    ###NOT USED IN SCRIPT, JUST FOR UTILITY WHEN TWEAKING###
    #Credit: https://www.reddit.com/r/PowerShell/comments/3u737j/getaduser_lastlogon/ (user deleted their account)
    #I made some tweaks.

    $dcs = Get-ADDomainController -Filter { Name -like "*" }
    $Time = 0
        foreach($dc in $dcs) {

        Try {

            $User = Get-ADUser -Server $dc -identity $UserName -properties LastLogon,LastLogonTimestamp
            
            if($User.LastLogonTimeStamp -gt $Time) {

                $Time = $User.LastLogonTimeStamp
            }

            if($User.LastLogon -gt $Time) {

                $Time = $User.LastLogon
            }   
        }

        Catch {
            
            #Nothing
        }
    }

    $DT = [DateTime]::FromFileTime($Time)

    [PSCustomObject] @{

        SamAccountName=$User.SamAccountName
        Enabled=$User.Enabled
        LastLogon=$DT
        GivenName=$User.GivenName
        Surname=$User.SurName
        Name=$User.Name
        DistinguishedName=$User.DistinguishedName
    }

    #Return $OutputObj
}

#Start logging.
Start-Logging -logdirectory "C:\ScriptLogs\Disable-InactiveADAccounts" -logname "Disable-InactiveADAccounts" -LogRetentionDays 30

#Start function.
Disable-InactiveADAccounts -To @("email@domain.com","email2@domain.com") -From "noreply@domain.com" -SMTPServer "server.domain.local" -UTCSkew -5 -OutputDirectory "C:\ScriptLogs\Disable-InactiveADAccounts" -ExclusionGroup "ServiceAccounts"

#Stop logging.
Stop-Transcript
