Function Set-RDPCertificate()
{
    [CmdletBinding(PositionalBinding=$false)]
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
        [int] $KeyLength
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
            $opts = @{ Subject = $env:COMPUTERNAME ; NotAfter = $ValidUntil; HashAlgorithm = $HashAlgorithm; KeyLength = $KeyLength }
            if (![String]::IsNullOrEmpty($env:USERDNSDOMAIN))
            {
                $opts.Add("DnsName", $env:COMPUTERNAME, "$(("$env:COMPUTERNAME.$env:USERDNSDOMAIN").ToLower())")
            }
            $SHA1Thumbprint = $(New-SelfSignedCertificate @opts
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