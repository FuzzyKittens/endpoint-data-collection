$baseXmlPath = '.\source\Scheduled-TaskBase.xml'
$scriptPath = '.\source\Get-Data.ps1'
$releaseXmlPath = './release/intune-source/Scheduled-Task.xml'

# update xml used for scheduled task
[xml]$baseXml = Get-Content -Path $baseXmlPath
$script = Get-Content -Path $scriptPath -Raw
$baseXml.Task.Actions.Exec.Arguments += '-NoProfile -WindowStyle Hidden -Command "& {'
$baseXml.Task.Actions.Exec.Arguments += "`n"
$baseXml.Task.Actions.Exec.Arguments += $script
$baseXml.Task.Actions.Exec.Arguments += '}"'
$baseXml.Task.Actions.Exec.Arguments += "`n      "
$baseXml.Save($releaseXmlPath)

# build intunewin
# .\source\IntuneWinAppUtil.exe -c ".\release\intune-source" -s "install.ps1" -o ".\release\w32-app" -q
