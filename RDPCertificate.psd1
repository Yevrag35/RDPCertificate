@{
    GUID = '0b274da8-7d7e-499e-95c2-21cc6aaffa33'
    Author = 'Mike Garvey'
    Description = 'A module for generating and applying certificates for use with Remote Desktop Services on local and remote machines.'
    CompanyName = 'DGRSystems, LLC.'
    Copyright = "© 2018 DGRSystems, LLC.  All rights reserved."
    ModuleVersion = '1.0.3'
	PowerShellVersion = '5.0'
	NestedModules = @('RDPCertificate.psm1')
	ScriptsToProcess = @('ImportScript.ps1')
	FunctionsToExport = @('Set-RDPCertificate')
	AliasesToExport = @('setrdcert')
	CmdletsToExport = ''
	VariablesToExport = ''
	FileList = @(
		'ImportScript.ps1',
		'RDPCertificate.psd1',
		'RDPCertificate.psm1',
		'en-US\RDPCertificate.psm1-Help.xml'
	)
	ReleaseNotes = 'Fixed error that would occur when the personal certificate store was empty.'
}