﻿#
# Module manifest for module 'PSGet_RDPCertificate'
#
# Generated by: Mike Garvey
#
# Generated on: 5/22/2018
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'RDPCertificate.dll'

# Version number of this module.
ModuleVersion = '2.1.0'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '0b274da8-7d7e-499e-95c2-21cc6aaffa33'

# Author of this module
Author = 'Mike Garvey'

# Company or vendor of this module
CompanyName = 'DGRSystems, LLC.'

# Copyright statement for this module
Copyright = '(c) 2018 DGRSystems, LLC.  All rights reserved.'

# Description of the functionality provided by this module
Description = 'A module for generating and applying certificates for use with Remote Desktop Services on local and remote machines.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '4.0'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = @(
	'Dynamic.Parameter.dll',
    'Microsoft.Management.Infrastructure',
    'Microsoft.WSMan.Management',
	'Security.Cryptography.dll'
)

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = ''

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
NestedModules = @('RemoteActions.psm1')

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @('New-RemoteRDPCertificate')

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @('Get-RDPCertificate', 'Set-RDPCertificate')

# Variables to export from this module
# VariablesToExport = @()

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = 'setrdcert', 'Get-InstalledRDPCertificate', 'getrdcert'

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
FileList = @(
	'Dynamic.Parameter.dll',
	'Security.Cryptography.dll',
	'RDPCertificate.dll',
	'RDPCertificate.psd1',
	'RemoteActions.psm1'
)

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = 'RDP','Remote','Desktop','Certificate','Self-Signed','new','external','help','generate','thumbprint',
			'Cim', 'CimSession', 'PSSession', 'winrm'

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        ProjectUri = 'https://git.yevrag35.com/gityev/rdpcertificate.git'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        ReleaseNotes = 'Adding a new, strictly, PowerShell function specifically for creating a self-signed cert on a remote machine ("New-RemoteRDPCertificate").'

        # External dependent modules of this module
        # ExternalModuleDependencies = ''

    } # End of PSData hashtable

 } # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

