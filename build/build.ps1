$baseXmlPath = '.\source\Scheduled-TaskBase.xml'
$scriptPath = '.\source\Get-Data.ps1'
$releaseXmlPath = '.\intune\Scheduled-Task.xml'

[xml]$baseXml = Get-Content -Path $baseXmlPath
$script = Get-Content -Path $scriptPath -Raw
$baseXml.Task.Actions.Exec.Arguments += '-NoProfile -WindowStyle Hidden -Command "& {'
$baseXml.Task.Actions.Exec.Arguments += "`n"
$baseXml.Task.Actions.Exec.Arguments += $script
$baseXml.Task.Actions.Exec.Arguments += '}"'
$baseXml.Task.Actions.Exec.Arguments += "`n      "
$baseXml.Save($releaseXmlPath)
