# Endpoint Data Collection

This solution collects data on endpoints and drops it into a Windows system event on a daily basis through a Windows scheduled task.
The idea with this is to capture endpoint data that can be consumed by an [Azure Log Analytics workspace](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-analytics-workspace-overview) through [Data Collection Rules in Azure Monitor](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection).
The [Azure Monitor Agent for Client Devices](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-windows-client) would be used for Windows 10/11 Endpoints in this architecture.

## Getting started

To use this solution, you will need to have your endpoints managed by Intune.
The latest released intunewin file can be found in [/release/w32-app/install.intunewin](/release/w32-app/install.intunewin).
Simply download the file and upload it as a [win32 app](https://learn.microsoft.com/en-us/mem/intune/apps/apps-win32-add) in Intune to be published to your endpoints.

For the app settings, use the following:
- **Install command**: Powershell.exe -ExecutionPolicy ByPass -File .\install.ps1
- **Uninstall command**: Powershell.exe -ExecutionPolicy ByPass -File .\uninstall.ps1
- **Install behavior**: System
- **Detection Rules**: Use a custom script - [/release/intune-source/detection.ps1](/release/intune-source/detection.ps1)

## Event info
- **Event log**: System
- **Event ID**: 5075
- **Event level**: Information
- **Event source**: MasterEndpointRecord

## Scheduled task info
- **Name**: MasterEndpointRecord
- **Scheduled**: Daily at 0900 with random offset up to 8 hours
- **Runtime**: Less than a 5 seconds

## Collected data
**GeneralProperties**
- **MasterGUID** *(deterministic GUID created from a set of endpoint properties which should always be the same for the life of an endpoint)*
- **MasterGUIDPrevious** *(in the unlikely situation the MasterGUID has changed, this property will contain the previous MasterGUID)*
- **AADDeviceGUID** *(for mapping to AAD data via AAD deviceId)*
- **IntuneDeviceGUID** *(for mapping to Intune data via Intune deviceId)*
- **SenseGUID** *(for mapping to MDE data via MDE MachineId)*
- **MDETag**
- **ComputerName**
- **DomainName**
- **Manufacturer**
- **Product**
- **SerialNumber**

**NetworkConfig**
- **NicID**
- **NicVendor**
- **NicModel**
- **NicDHCPEnabled**
- **NicNetworkName**
- **NicMACAddress**
- **NicIPAddress**
- **NicDefaultGateway**
- **NicDNSServer**

**HardwareConfig**
- **MotherboardSN**
- **BiosManufacturer**
- **BiosVersion**
- **BiosGUID**
- **TpmVersion**
- **TpmEKPublicKey**
- **CPU**
- **HardDrive**
- **Volume**
- **OsVendor**
- **OsName**
- **OsVersion**
- **OsBuild**
- **OsArchitecture**
- **OsEdition**
- **OsSupportPlan**
- **OsCompositeDispName**
- **OsWindowsDeviceId**
- **Memory**

## Source code
The source code can be found in [/source/](/source/) and consists of three main files:
- [Get-Data.ps1](/source/Get-Data.ps1)
  - This is the main script that collects the data during the scheduled task on the endpoint and writes that data to an event.
- [Scheduled-TaskBase.xml](/source/Scheduled-TaskBase.xml)
  - This xml contains the base properties for the scheduled task.
- [IntuneWinAppUtil.exe](/source/IntuneWinAppUtil.exe)
  - This is the executable called as part of a release trigger to build the .intunewin file for the w32-app.

## Release
Releases are built automatically through a GitHub action triggered on any file in [/source/](/source/) getting updated through a Pull Request merge.
The current release can be found in [/release/](/release/) and contains 5 files:
- [/w32-app/install.intunewin](/release/w32-app/install.intunewin)
  - This is the w32 app package to be uploaded to Intune
- [/intune-source/Scheduled-Task.xml](/release/intune-source/Scheduled-Task.xml)
  - This is the fully built xml to create the Scheduled task, and is included in the install.intunewin package
- [/intune-source/detection.ps1](/release/intune-source/detection.ps1)
  - This is the detection script to be uploaded to Intune
- [/intune-source/install.ps1](/release/intune-source/install.ps1)
  - This is the install script used by the w32 app, and is included in the install.intunewin package
- [/intune-source/uninstall.ps1](/release/intune-source/uninstall.ps1)
  - This is the uninstall script used by the w32 app, and is included in the install.intunewin package
