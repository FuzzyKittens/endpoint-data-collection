$taskName = 'MasterEndpointRecord'
$taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -eq $taskName}

if($taskExists) {
    Write-Output "Success"
    Exit 0
}
else {
    Exit 1
}