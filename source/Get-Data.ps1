function New-DeterministicGuid {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'Creates in-memory object only.'
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

function Get-GeneralConfig {
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

    # MDE MachineId
    $mdeMachineIdRegPath = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Advanced Threat Protection'
    $mdeMachineIdValueName = 'senseId'
    $mdeMachineId = [Microsoft.Win32.Registry]::GetValue($mdeMachineIdRegPath, $mdeMachineIdValueName, $null)

    $computerSystem = Get-CimInstance win32_computersystem

    # MDE tag
    $mdeTagRegPath = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging'
    $mdeTagRegValueName = 'Group'
    $mdeTag = [Microsoft.Win32.Registry]::GetValue($mdeTagRegPath, $mdeTagRegValueName, $null)

    $merRegPath = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MasterEndpointRecord'
    $masterGUIDValueName = 'MasterGUID'
    $masterGUIDPrevious = [Microsoft.Win32.Registry]::GetValue($merRegPath, $masterGUIDValueName, $null)
    if ($masterGUIDPrevious -eq $masterGuid) {
        $masterGUIDPrevious = $null
    }

    # AAD deviceId
    $aadDeviceId = $(Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Issuer -like '*CN=MS-Organization-Access*'}).Subject.Replace('CN=','')

    # Intune mdmDeviceId
    $intuneMDMDeviceIdRegPath = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot\EstablishedCorrelations'
    $intuneMDMDeviceIdValueName = 'EntDMID'
    $intuneMDMDeviceId = [Microsoft.Win32.Registry]::GetValue($intuneMDMDeviceIdRegPath, $intuneMDMDeviceIdValueName, $null)

    [PSCustomObject]$GeneralConfig = [ordered]@{
        MasterGUID = $masterGuid
        MasterGUIDPrevious = $masterGUIDPrevious
        AADDeviceGUID = $aadDeviceId
        IntuneDeviceGUID = $intuneMDMDeviceId
        SenseGUID = $senseGuid
        MDEMachineId = $mdeMachineId
        MDETag = $mdeTag
        ComputerName = $computerSystem.Name
        DomainName = $computerSystem.Domain
        Manufacturer = $baseBoard.Manufacturer
        Product = $baseBoard.Product
        SerialNumber = $baseBoard.SerialNumber
    }

    # Write the hashtable to the registry
    $GeneralConfig.keys | ForEach-Object {
        if ($null -ne $GeneralConfig[$_]) {
            [Microsoft.Win32.Registry]::SetValue($merRegPath, $_, $GeneralConfig[$_])
        }
    }
    return $GeneralConfig
}

function Get-NetworkConfig {
    #region Network Interface
    $networkInterface = @()
    $networkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter | Select-Object *
    $networkAdapterConfigurations = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Select-Object *
    foreach ($networkAdapter in $networkAdapters) {
        $networkAdapterConfiguration = $networkAdapterConfigurations | Where-Object {$_.Index -eq $networkAdapter.DeviceId}
        $properties = [ordered]@{
            NicID = $networkAdapter.DeviceID
            NicVendor = $networkAdapter.Manufacturer
            NicModel = $networkAdapter.ProductName
            NicDHCPEnabled = $networkAdapterConfiguration.DHCPEnabled
            NicNetworkName = $networkAdapterConfiguration.DNSDomain
            NicMACAddress = $networkAdapter.MACAddress
            NicIPAddress = $networkAdapterConfiguration.IPAddress
            NicDefaultGateway = $networkAdapterConfiguration.DefaultIPGateway
            NicDNSServer = $networkAdapterConfiguration.DNSServerSearchOrder
        }
        $networkInterface += $properties
    }
    #endregion

    #region FQDN
    $computerSystem = Get-CimInstance win32_computersystem
    $domainType = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty DomainRole #change to ciminstance?

    switch ($computerSystem.DomainRole) {
        0 { $domainType = "Standalone Workstation" }
        1 { $domainType = "Member Workstation" }
        2 { $domainType = "Standalone Server" }
        3 { $domainType = "Member Server" }
        4 { $domainType = "Backup Domain Controller" }
        5 { $domainType = "Primary Domain Controller" }
        default { $domainType = "Unknown" }
    }
    $fqdn = [ordered]@{
        Domain = $computerSystem.Domain
        OrganizationalUnit = 'TODO'
        DomainType = $domainType
        DNS = $computerSystem.DNSHostName
        NetBios = 'N/A'
        HostName = $env:COMPUTERNAME
        }
    #endregion

    #region Exposed Service
    $exposedService = @()
    $interestingPorts = @{
        DomainController = 389 #need to also check if it's only an LDAP server
        ManagedDomain = 0
        DNSServer = 53
        NTPServer = 123
        FileServer = 445 #also looking for LanmanServer service running? or maybe get-smbshare?
        WebServer = 80
        WebServerHttps = 443
        DKC = 0
        TGS = 88
        AttributeRepo = 0
        LDAPDirectory = 389
        X500Directory = 389
    }

    $listeningServices = Get-NetTCPConnection -State Listen
    foreach ($interestingPort in $interestingPorts.Keys) {
        if ($listeningServices.localport -contains $interestingPorts[$interestingPort]) {
            $exposedService += $interestingPort
        }
    }
    #endregion

    [PSCustomObject]$networkConfig = [ordered]@{
    NetworkInterface = $networkInterface
    FQDN = $fqdn
    ExposedService = $exposedService
    }
    return $networkConfig
}

function Get-HardwareConfig {
    $baseBoard = Get-CimInstance -ClassName Win32_BaseBoard | Select-Object *
    $bios = Get-CimInstance -ClassName Win32_Bios | Select-Object *
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object *
    $computerSystemProduct = Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object *
    $processor = Get-CimInstance -ClassName Win32_Processor | Select-Object *
    $operatingSystem = Get-CimInstance -ClassName win32_OperatingSystem | Select-Object *
    $physicalMemory = Get-CimInstance -ClassName win32_PhysicalMemory | Select-Object *
    $tpmExists = $(Get-Tpm).TpmPresent
    if ($tpmExists) {
        $tpmPublicKey = $(Get-TpmEndorsementKeyInfo -HashAlgorithm sha256).PublicKeyHash
    }
    $virtualized = $false
    if ($computerSystem.Model.Contains('Virtual')) {
        $virtualized = $true
    }

    $memory = @()
    $totalMemory = 0
    foreach ($node in $physicalMemory) {
        $memory += [ordered]@{
            Label = $node.BankLabel
            Capacity = $node.Capacity
        }
        $totalMemory += $node.Capacity
    }

    #region Device Info
    $deviceInfo = [ordered]@{
        USCYBERCOMCategory = 'TODO'
        VirtualizationStatus = $virtualized
        UpTime = (Get-Date) - $operatingSystem.LastBootUpTime
        MotherboardSerialNumber = $baseBoard.SerialNumber
        MotherboardChipset = $baseBoard.Product
        BiosManufacturer = $bios.Manufacturer
        BiosVersion = $bios.SMBIOSBIOSVersion
        BiosGUID = $computerSystemProduct.UUID
        TPMVersion = $baseBoard.SerialNumber
        TPMEKPublicKey = $tpmPublicKey
        CPEOS = $operatingSystem.Caption
        OSVendor = $operatingSystem.Manufacturer
        OSName = $operatingSystem.Name
        OSVersion = $operatingSystem.Version
        OSBuild = $operatingSystem.BuildNumber
        OSArchitecture = $operatingSystem.OSArchitecture
        OSEdition = $operatingSystem.BuildType
        SupportPlan = 'TODO'
        CompositeDispName = 'TODO'
        WindowsDevID = $operatingSystem.SerialNumber
        SystemDescription = $computerSystem.Description
        ExtendedSupportLicense = 'TODO'
        Expiration = 'TODO'
        MemorySize = $($totalMemory / 1MB)
        Memory = $memory
    }
    #endregion

    #region CPU
    $cpu = @()
    foreach ($node in $processor) {
        $cpu += [ordered]@{
            CpuId = $node.DeviceId
            CpuSpeed = $node.CurrentClockSpeed
            CpuManufacturer = $node.Manufacturer
            CpuModel = $node.Name
        }
    }
    #endregion

    #region HardDrive
    $physicalDisks = Get-CimInstance -ClassName Win32_DiskDrive -KeyOnly
    $hardDrive = @()
    foreach ($physicalDisk in $physicalDisks) {
        $volumes = @()
        $freeSpace = 0
        $partitions = Get-CimAssociatedInstance -InputObject $physicalDisk -ResultClassName win32_DiskPartition -KeyOnly
        foreach ($partition in $partitions) {
            $logicalDisks = Get-CimAssociatedInstance -InputObject $partition -ResultClassName Win32_LogicalDisk
            foreach ($logicalDisk in $logicalDisks) {
                $freeSpace += $logicalDisk.FreeSpace
                $volumes += [ordered]@{
                    VolumeId = $logicalDisk.DeviceID
                    VolumeDescription = $logicalDisk.Description
                    VolumeSize = [math]::Round($($logicalDisk.Size / 1MB))
                    VolumeUsedSpace = [math]::Round($(($logicalDisk.Size - $logicalDisk.FreeSpace) / 1MB))
                    VolumeFreeSpace = [math]::Round($($logicalDisk.FreeSpace / 1MB))
                }
            }
        }
        $physicalDiskInstance = Get-CimInstance -InputObject $physicalDisk | Select-Object *
        $hardDrive += [ordered]@{
            HardDriveId = $physicalDiskInstance.Index
            HardDriveSize = [math]::Round($($physicalDiskInstance.Size / 1MB), 0)
            HardDriveUsedSpace = [math]::Round($(($physicalDiskInstance.Size - $freeSpace) / 1MB))
            HardDriveFreeSpace = [math]::Round($($freeSpace / 1MB))
            HardDrivePath = $physicalDiskInstance.DeviceID
            HardDriveVolume = $volumes
        }
    }
    #endregion

    $hwConfig = [ordered]@{
        DeviceInfo = $deviceInfo
        CPU = $cpu
        HardDrive = $hardDrive
    }
    return $hwConfig
}

function Get-SoftwareConfig {
    $installedApps = Get-CimInstance -ClassName Win32_Product
    $results = @()

    foreach ($app in $installedApps) {
        $lastRunTime = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$($app.IdentifyingNumber)" | Select-Object -ExpandProperty InstallDate
        $results += [PSCustomObject] @{
            "Name" = $app.Name
            "Version" = $app.Version
            "Last Run Time" = $lastRunTime
        }
    }
    $results | Sort-Object -Property "Name" | Format-Table -AutoSize
}

function Get-OperationalContext {
    return 'TODO'
}

function Get-VulnResults {
    return 'TODO'
}

function Get-UserData {
    $logonCache = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache'

    $users = @()
    foreach ($node in $logonCache) {
        $path = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache\$($node.PSChildName)\Name2Sid"
        $validPath = Test-Path -Path $path
        if ($validPath) {
            $subPaths = Get-ChildItem -Path $path
            foreach ($subPath in $subPaths) {
                $users += @{
                    'UPN' = $subPath.GetValue('IdentityName')
                    'UserName' = $subPath.GetValue('IdentityName').Split('@')[0]
                    'Domain' = $subPath.GetValue('AuthenticatingAuthority')
                    'SID' = $subPath.GetValue('Sid')
                }
            }
        }
    }
    return $users
}


try {
    # create the object
    [PSCustomObject]$masterEndpointRecord = [ordered]@{
        GeneralConfig = Get-GeneralConfig
        NetworkConfig = Get-NetworkConfig
        HardwareConfig = Get-HardwareConfig
        SoftwareConfig = 'TODO'
        OperationalContext = 'TODO'
        VulnResults = 'TODO'
        UserData = Get-UserData
        }

    # log data
    $eventSource = 'MasterEndpointRecord'
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
    Write-EventLog -LogName $eventLog -Source $eventSource -EventId $eventId -EntryType $eventType -Message $eventMessage -Category $category
}
catch {
    $_ | Out-File -FilePath 'c:\MER.log' -Append
}
