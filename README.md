# Endpoint Data Collection

This solution collects data on endpoints and drops it into a windows system event on a daily basis through a Windows scheduled task.  The idea with this is to capture endpoint data that can be consumed by an [Azure Log Analytics workspace](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-analytics-workspace-overview) through [Data Collection Rules in Azure Monitor](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection).

## Get started

To use this solution, you will need to have your endpoints managed by Intune.  The latest released intunewin file can be found [here](https://github.com/FuzzyKittens/endpoint-data-collection/blob/main/release/w32-app/install.intunewin).  Simply download the file and upload it as a win32 app in Intune to be published to your endpoints.  More information on that process can be found [here](https://learn.microsoft.com/en-us/mem/intune/apps/apps-win32-add).  For the app settings, use the following:
- **Install command**: Powershell.exe -ExecutionPolicy ByPass -File .\install.ps1
- **Uninstall command**: Powershell.exe -ExecutionPolicy ByPass -File .\uninstall.ps1
- **Install behavior**: System
- **Detection Rules**: Use a custom script which can be found [here](https://github.com/FuzzyKittens/endpoint-data-collection/blob/main/release/intune-source/detection.ps1)

## Event info
- **Event ID**: 5075
- **Event source**: MasterEndpointRecord

## Scheduled task info
- **Name**: MER
- **Scheduled**: Daily at 0900 with random offset up to 8 hours
- **Runtime**: Approximately n Minutes

## Collected data
**GeneralProperties**
- MasterGUID
  - This is a deterministic GUID created from a set of endpoint properties which should always be the same for the life of an endpoint
- MasterGUIDPrevious
- SenseGUID
- MDETag
- ComputerName
- DomainName
- Manufacturer
- Product
- SerialNumber

**NetworkConfig**
- NicID
- NicVendor
- NicModel
- NicDHCPEnabled
- NicNetworkName
- NicMACAddress
- NicIPAddress
- NicDefaultGateway
- NicDNSServer

**HardwareConfig**
- MotherboardSN
- BiosManufacturer
- BiosVersion
- BiosGUID
- TpmVersion
- TpmEKPublicKey
- CPU
- HardDrive
- Volume
- OsVendor
- OsName
- OsVersion
- OsBuild
- OsArchitecture
- OsEdition
- OsSupportPlan
- OsCompositeDispName
- OsWindowsDeviceId
- Memory
