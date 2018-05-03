Function Set-RDPCertificate
{
    <#
        .SYNOPSIS
            Binds a new or existing certificate to the Remote Desktop service.
        .DESCRIPTION
            You either pick an existing, installed certificate on your local computer or generate a new certificate with
            the native Windows 10 "New-SelfSignedCertificate" cmdlet (the module will try to download the "PowerShell PKI"
            module from the PSGallery if the OS is less than Windows 10).  Using this certificate's thumbprint, the cmdlet
            binds the thumbprint to the service.  Changes are immediate, and no reboots (or service restarts) are required.
        .PARAMETER SHA1Thumbprint
            Specifies an already installed certificate thumbprint (in the LocalMachine certificate store).
        .PARAMETER WithNewSelfSignedCertificate
            Specifies that the script will create a new self-signed certificate using either the built-in cmdlet or the PSPKI module.
        .PARAMETER ValidUntil
            Specifies the "end" date the newly-created certificate will be good to.  By default, the date will 2 years from the current date.
        .PARAMETER HashAlgorithm
            Specifies the hash algorithm the cmdlets will use to generate the certificate with.  By default, it will use SHA-256.  Valid values are "SHA256", "SHA384", and "SHA512".
        .PARAMETER KeyLength
            Specifies the key length the cmdlets will generate.  By default, an RSA 2048-bit key is created.  Valid values are "2048", "4096", "8192", and "16384".
        .EXAMPLE
            Set-RDPCertificate -SHA1Thumbprint XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        .EXAMPLE
            *** Using a generated self-signed cert with the default values ***
            Set-RDPCertificate -WithNewSelfSignedCertificate
        .EXAMPLE
            Set-RDPCertificate -WithNewSelfSignedCertificate -ValidUntil $([datetime]::Now.AddYears(10)) -HashAlgorithm SHA356 -KeyLength 8192
        .LINK
            https://github.com/Crypt32/PSPKI
    #>
    [CmdletBinding(PositionalBinding=$false,    
        DefaultParameterSetName='ExistingCert')]
    [alias("setrdcert")]
    param
    (
        [parameter(Mandatory=$true,ParameterSetName='CreateNewCert')]
        [switch] $WithNewSelfSignedCertificate
        ,
        [parameter(Mandatory=$false,ParameterSetName='CreateNewCert')]
        [datetime] $ValidUntil = [datetime]::Now.AddYears(2)
        ,
        [parameter(Mandatory=$false,ParameterSetName='CreateNewCert')]
        [ValidateSet("SHA256", "SHA384", "SHA512")]
        [string] $HashAlgorithm = "SHA256"
        ,
        [parameter(Mandatory=$false,ParameterSetName='CreateNewCert')]
        [ValidateSet(2048, 4096, 8192, 16384)]
        [int] $KeyLength = 2048
    )
    DynamicParam
    {
        $name = 'SHA1Thumbprint'
        $dict = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $attCol = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $props = @{ Mandatory = $true; Position = 0; ValueFromPipelineByPropertyName = $true; ParameterSetName='ExistingCert' }
        $pAtt = New-Object System.Management.Automation.ParameterAttribute -Property $props
        $attCol.Add($pAtt)
        $aAtt = New-Object System.Management.Automation.AliasAttribute("sha1", "thumb", "Thumbprint")
        $attCol.Add($aAtt)
        $tprints = (Get-ChildItem Cert:\LocalMachine\My).Thumbprint
        $valSet = New-Object System.Management.Automation.ValidateSetAttribute($tprints)
        $attCol.Add($valSet)
        
        $rtParam = New-Object System.Management.Automation.RuntimeDefinedParameter(
            $name, [string], $attCol
        )
        $dict.Add($name, $rtParam)
        return $dict
    }
    Begin
    {
        if ($PSBoundParameters["SHA1Thumbprint"])
        {
            $SHA1Thumbprint = $PSBoundParameters["SHA1Thumbprint"]
        }
        else
        {
            if ($null -ne (Get-Module PSPKI))
            {
                $opts = @{
                    Subject = "CN=$env:COMPUTERNAME"
                    EnhancedKeyUsage = "Client Authentication", "Server Authentication"
                    FriendlyName = "RDP Certificate"
                    IsCA = $false
                    KeyLength = 2048
                    KeyUsage = "DigitalSignature", "KeyEncipherment"
                    NotBefore = $([datetime]::Now.AddMinutes(-5))
                    NotAfter = $([datetime]::Now.AddYears(2))
                    SignatureAlgorithm = "SHA256"
                    StoreLocation = "LocalMachine"
                }
                if (![String]::IsNullOrEmpty($env:USERDNSDOMAIN))
                {
                    [string[]]$names = "dns:$($env:COMPUTERNAME)", "dns:$($env:COMPUTERNAME).$($env:USERDNSDOMAIN.ToLower())"
                }
                else
                {
                    [string[]]$names = "dns:$($env:COMPUTERNAME)"
                }
                $opts.Add("SubjectAlternativeName", $names)
                $SHA1Thumbprint = $(New-SelfSignedCertificateEx @opts).Thumbprint
            } 
            else
            {
                $opts = @{ Subject = $env:COMPUTERNAME ; NotAfter = $ValidUntil; HashAlgorithm = $HashAlgorithm; KeyLength = $KeyLength }
                if (![String]::IsNullOrEmpty($env:USERDNSDOMAIN))
                {
                    $opts.Add("DnsName", $env:COMPUTERNAME, "$(("$env:COMPUTERNAME.$env:USERDNSDOMAIN").ToLower())")
                }
                $SHA1Thumbprint = $(New-SelfSignedCertificate @opts).Thumbprint                
            }
        }
    }
    Process
    {
        Set-CimInstance `
            -Namespace 'root\cimv2\TerminalServices' `
            -Query 'SELECT * FROM Win32_TSGeneralSetting WHERE TerminalName = "RDP-Tcp"' `
            -Property @{ SSLCertificateSHA1Hash = $SHA1Thumbprint }
            
        if ($EnableFirewallRules)
        {
            # I don't use "Set-NetFirewallRule" here because of backwards compatibilty.
            & netsh.exe advfirewall firewall set rule 'group="Remote Desktop"' new enable=yes > $null
        }
    }
}