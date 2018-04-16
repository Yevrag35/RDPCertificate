@{
    GUID = '04fd9617-2c81-497a-b325-ec02c62653a4'
    Author = 'Mike Garvey'
    Description = 'A module for generating and applying certificates for use with Remote Desktop Services on local and remote machines.'
    Copyright = '© 2018 Yevrag35, LLC.  All rights reserved.'
    ModuleVersion = '1.0.0'
    PowerShellVersion = '5.0'
    NestedModules = @('RDPCertificate.psm1')
    FunctionsToExport = '*'
    AliasesToExport = '*'
    CmdletsToExport = ''
    FileList = @(
        'RDPCertificate.psd1',
        'RDPCertificate.psm1'
    )
}