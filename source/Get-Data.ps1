function New-DeterministicGuid {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseShouldProcessForStateChangingFunctions",
        "",
        Justification = "Creates in-memory object only."
    )]
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$UniqueString
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($UniqueString)
    $sha1CryptoServiceProvider = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
    $hashedBytes = $sha1CryptoServiceProvider.ComputeHash($bytes)
    [System.Array]::Resize([ref]$hashedBytes, 16);
    return New-Object System.Guid -ArgumentList @(,$hashedBytes)
}

function Get-MDEProperty {
    $uniqueProperties = @(
        'SerialNumber'
        'Manufacturer'
        'Product'
    )
    $uniqueString = ''
    $baseBoard = Get-CimInstance win32_baseboard -Property $uniqueProperties
    foreach ($uniqueProperty in $uniqueProperties) {
        $uniqueString += $($baseBoard.$uniqueProperty)
    }
    $uniqueString += $(Get-CimInstance Win32_ComputerSystemProduct -Property 'UUID').UUID
    $masterGuid = New-DeterministicGuid -UniqueString $uniqueString
    $senseGuidRegPath = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Advanced Threat Protection'
    $senseGuidValueName = 'senseGuid'
    $senseGuid = [Microsoft.Win32.Registry]::GetValue($senseGuidRegPath, $senseGuidValueName, $null)

    $computerSystem = Get-CimInstance win32_computersystem

    $mdeTagRegPath = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging'
    $mdeTagRegValueName = 'Group'
    $mdeTag = [Microsoft.Win32.Registry]::GetValue($mdeTagRegPath, $mdeTagRegValueName, $null)

    $merRegPath = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MasterEndpointRecord'
    $masterGUIDValueName = 'MasterGUID'
    $masterGUIDPrevious = [Microsoft.Win32.Registry]::GetValue($merRegPath, $masterGUIDValueName, $null)
    if ($masterGUIDPrevious -eq $masterGuid) {
        $masterGUIDPrevious = $null
    }

    [PSCustomObject]$mdeProperties = [ordered]@{
        MasterGUID = $masterGuid
        MasterGUIDPrevious = $masterGUIDPrevious
        SenseGUID = $senseGuid
        MDETag = $mdeTag
        ComputerName = $computerSystem.Name
        DomainName = $computerSystem.Domain
        Manufacturer = $baseBoard.Manufacturer
        Product = $baseBoard.Product
        SerialNumber = $baseBoard.SerialNumber
    }

    # Write the hashtable to the registry
    $mdeProperties.keys | ForEach-Object {
        if ($null -ne $mdeProperties[$_]) {
            [Microsoft.Win32.Registry]::SetValue($merRegPath, $_, $mdeProperties[$_])
        }
    }
    return $mdeProperties
}

#TODO: add FQDN / Exposed Service Info
function Get-NetworkConfig {
    $networkConfig = @()
    $networkInterfaces = Get-CimInstance -Class Win32_NetworkAdapter | Select-Object *
    $networkInterfaceConfigurations = Get-CimInstance -Class Win32_NetworkAdapterConfiguration | Select-Object *
    foreach ($networkInterface in $networkInterfaces) {
        $networkInterfaceConfiguration = $networkInterfaceConfigurations | Where-Object {$_.InterfaceIndex -eq $networkInterface.Index}
        $properties = [ordered]@{
            NicID = $networkInterface.DeviceID
            NicVendor = $networkInterface.Manufacturer
            NicModel = $networkInterface.ProductName
            NicDHCPEnabled = $networkInterfaceConfiguration.DHCPEnabled
            NicNetworkName = $networkInterfaceConfiguration.DNSDomain
            NicMACAddress = $networkInterface.MACAddress
            NicIPAddress = $networkInterfaceConfiguration.IPAddress
            NicDefaultGateway = $networkInterfaceConfiguration.DefaultIPGateway
            NicDNSServer = $networkInterfaceConfiguration.DNSServerSearchOrder
        }
        $networkConfig += $properties
    }
    return $networkConfig
}

function Get-HardwareConfig {
    $baseBoard = Get-CimInstance -Class Win32_BaseBoard | Select-Object *
    $bios = Get-CimInstance -Class Win32_Bios | Select-Object *
    $computerSystemProduct = Get-CimInstance -Class Win32_ComputerSystemProduct | Select-Object *
    $processor = Get-CimInstance -Class Win32_Processor | Select-Object *
    $physicalDisk = Get-CimInstance -Class Win32_DiskDrive | Select-Object *
    $logicalDisk = Get-CimInstance -Class win32_LogicalDisk | Select-Object *
    $operatingSystem = Get-CimInstance -Class win32_OperatingSystem | Select-Object *
    $physicalMemory = Get-CimInstance -Class win32_PhysicalMemory | Select-Object *

    $cpu = @()
    foreach ($node in $processor) {
        $cpu += [ordered]@{
            CpuId = $node.DeviceId
            CpuSpeed = $node.CurrentClockSpeed
            CpuManufacturur = $node.Manufacturer
            CpuModel = $node.Name
        }
    }

    $hardDrive = @()
    foreach ($node in $physicalDisk) {
        $hardDrive += [ordered]@{
            HardDriveId = $node.DeviceID
            HardDriveSize = $node.Size
            HardDriveUsedSpace = 'TODO'
            HardDriveFreeSpace = 'TODO'
        }
    }

    $volume = @()
    foreach ($node in $logicalDisk) {
        $volume += [ordered]@{
            VolumeId = $node.DeviceID
            VolumeSize = $node.Size
        }
    }

    $memory = @()
    foreach ($node in $physicalMemory) {
        $memory += [ordered]@{
            Label = $node.BankLabel
            Capacity = $node.Capacity
        }
    }

    #TODO: some fields need revisit
    $hwConfig = [ordered]@{
        MotherboardSN = $baseBoard.SerialNumber
        BiosManufacturer = $bios.Manufacturer
        BiosVersion = $bios.SMBIOSBIOSVersion
        BiosGUID = $computerSystemProduct.UUID
        TpmVersion = $baseBoard.SerialNumber
        TpmEKPublicKey = $(Get-TpmEndorsementKeyInfo -HashAlgorithm sha256).PublicKeyHash
        CPU = $cpu
        HardDrive = $hardDrive
        Volume = $volume
        OsVendor = $operatingSystem.Manufacturer
        OsName = $operatingSystem.Caption
        OsVersion = $operatingSystem.Version
        OsBuild = $operatingSystem.BuildNumber
        OsArchitecture = $operatingSystem.OSArchitecture
        OsEdition = $operatingSystem.BuildType
        OsSupportPlan = 'TODO'
        OsCompositeDispName = $operatingSystem.Name
        OsWindowsDeviceId = $operatingSystem.SerialNumber #need to revisit
        Memory = $memory
    }
    return $hwConfig
}

# create the object
[PSCustomObject]$masterEndpointRecord = [ordered]@{
    MDEProperties = Get-MDEProperty
    NetworkConfig = Get-NetworkConfig
    HardwareConfig = Get-HardwareConfig
    }

# log data
$eventSource = 'DISAMasterEndpointRecord'
$eventLog = 'System'
$eventType = 'Information'
$eventId = 5075
$eventMessage = ConvertTo-Json -InputObject $masterEndpointRecord -Depth 5
$category = 0

# create the log source if not exists
if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
    #[System.Diagnostics.EventLog]::new($eventSource, $eventLog)
    New-EventLog -LogName $eventLog -Source $eventSource
}

# write the data to the event log
try {
    Write-EventLog -LogName $eventLog -Source $eventSource -EventId $eventId -EntryType $eventType -Message $eventMessage -Category $category
}
catch {
    $_ | Out-File -FilePath 'c:\MER.log' -Append
}
