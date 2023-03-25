# remove the scheduled task if exists
$taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName }
if ($taskExists) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
