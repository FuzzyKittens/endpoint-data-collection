$taskName = 'MasterEndpointRecord'

# remove the scheduled task if exists
$taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName }
if ($taskExists) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }

# create the scheduled task
$null = Register-ScheduledTask -xml (Get-Content .\Scheduled-Task.xml | Out-String) -TaskName $taskName -TaskPath "\" -User system

# run the scheduled task
Start-ScheduledTask -TaskName $taskName
