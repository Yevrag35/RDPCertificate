﻿Function New-RemoteRDPCertificate()     # Kind of redudant; I know... (¬､¬)
{
    <#
        .SYNOPSIS
            To be used instead of the standard 'Set-RDPCertificate' when you want to create a new
            self-signed certificate on the remote computer.
    #>
    [CmdletBinding(DefaultParameterSetName="ByComputerName", PositionalBinding=$false)]
    [OutputType([psobject])]
    param
    (
        [parameter(Mandatory=$true, ParameterSetName="ByComputerName", Position=0)]
        [string] $ComputerName,

        [parameter(Mandatory=$true, ParameterSetName="ByPSSession", ValueFromPipeline=$true)]
        [System.Management.Automation.Runspaces.PSSession]
        $PSSession,

        [parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [datetime] $ValidUntil = [datetime]::Now.AddYears(1),

        [parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [MG.RDP.Certificates.Algorithm]
        $HashAlgorithm = [MG.RDP.Certificates.Algorithm]::SHA256,

        [parameter(Mandatory=$false)]
        [ValidateSet('2048','4096','8192','16384')]
        [int] $KeyLength = 2048,

        [parameter(Mandatory=$false)]
        [switch] $PassThru
    )
    BEGIN
    {
        $newCert = New-Object MG.RDP.Certificates.NewCertificate;

        if ($PSBoundParameters["ComputerName"])
        {
            $PSSession = New-PSSession -ComputerName $ComputerName
        }
    }
    PROCESS
    {
        $sessionArgs = @($ValidUntil, $HashAlgorithm.ToString(), $KeyLength)

        $result = Invoke-Command -Session $PSSession -HideComputerName -ArgumentList $sessionArgs -ScriptBlock {
            param
            (
                [datetime] $validUntil = $args[0],
                [string] $algorithm = $args[1],
                [int] $KeyLength = $args[2]
            )
            Add-Type -AssemblyName System.Security;
            $extsToAdd = New-Object 'System.Collections.Generic.List[object]';

            # Enhanced Key Usage
            $ekuOids = New-Object -com 'X509Enrollment.CObjectIds.1';
            $serverAuthOid = New-Object -com 'X509Enrollment.CObjectId.1';
            $eu = [System.Security.Cryptography.Oid]::FromFriendlyName("Server Authentication", [System.Security.Cryptography.OidGroup]::EnhancedKeyUsage);
            $serverAuthOid.InitializeFromValue($eu.Value);
            $ekuOids.Add($serverAuthOid);
            $ekuExt = New-Object -com 'X509Enrollment.CX509ExtensionEnhancedKeyUsage.1';
            $ekuExt.InitializeEncode($ekuOids);
            $extsToAdd.Add($ekuExt);

            # Key Usage
            $ku = New-Object -com 'X509Enrollment.CX509ExtensionKeyUsage.1';
            $ku.InitializeEncode(48);
            $ku.Critical = $false;
            $extsToAdd.Add($ku);

            # Basic Constraints
            $bc = New-Object -com 'X509Enrollment.CX509ExtensionBasicConstraints.1';
            $bc.InitializeEncode($false, -1);
            $bc.Critical = $true;
            $extsToAdd.Add($bc);

            # Private Key
            $key = New-Object -com 'X509Enrollment.CX509PrivateKey.1';
            $algId = New-Object -com 'X509Enrollment.CObjectId.1';
            $algVal = [System.Security.Cryptography.Oid]::FromFriendlyName("RSA", [System.Security.Cryptography.OidGroup]::PublicKeyAlgorithm);
            $algId.InitializeFromValue($algVal.Value);
            $key.ProviderName = 'Microsoft RSA SChannel Cryptographic Provider';
            $key.Algorithm = $algId;
            $key.KeySpec = 1;
            $key.Length = $KeyLength;
            $key.SecurityDescriptor = 'D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)';
            $key.MachineContext = 1;
            $key.ExportPolicy = 0;
            $key.Create();

            # Subject Name
            $name = New-Object -com 'X509Enrollment.CX500DistinguishedName.1';
            $name.Encode("CN=$($env:COMPUTERNAME)", 0);

            # Certificate Request
            $cert = New-Object -Com 'X509Enrollment.CX509CertificateRequestCertificate.1';
            $cert.InitializeFromPrivateKey(2, $key, [string]::Empty);
            $cert.Subject = $name;
            $cert.Issuer = $cert.Subject;
            $cert.NotBefore = [datetime]::Now;
            $cert.NotAfter = $validUntil;
            for ($i = 0; $i -lt $extsToAdd.Count; $i++)
            {
                $ext = $extsToAdd[$i];
                $cert.X509Extensions.Add($ext);
            }
            $sigId = New-Object -com 'X509Enrollment.CObjectId.1';
            $hash = [System.Security.Cryptography.Oid]::FromFriendlyName($algorithm, [System.Security.Cryptography.OidGroup]::HashAlgorithm);
            $sigId.InitializeFromValue($hash.Value);
            $cert.SignatureInformation.HashAlgorithm = $sigId;
            $cert.Encode();

            # Complete the Request to Create!
            $enroll = New-Object -com 'X509Enrollment.CX509Enrollment.1';
            $enroll.CertificateFriendlyName = "$env:COMPUTERNAME RDP";
            $enroll.InitializeFromRequest($cert);

            $endCert = $enroll.CreateRequest(1);
            $enroll.InstallResponse(2, $endCert, 1, [string]::Empty);

            [byte[]]$certBytes = [System.Convert]::FromBase64String($endCert);

            # Now use it as the RDP certificate
            $rdpCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes);
            $inst = Get-CimInstance -Namespace 'root\cimv2\TerminalServices' -ClassName "Win32_TSGeneralSetting" -Filter 'TerminalName = "RDP-Tcp"';
            $inst | Set-CimInstance -Property @{ SSLCertificateSHA1Hash = $rdpCert.Thumbprint };

            return $(New-Object PSObject -Property @{
                NewCertificate = $rdpCert
            });
        }

        if ($PassThru)
        {
            Write-Output $result -NoEnumerate;
        }
    }
}

Function New-RemoteRDPSignedCertificate()
{
    [CmdletBinding(DefaultParameterSetName="ByComputerName")]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param
    (
        [parameter(Mandatory=$true, ParameterSetName="ByComputerName", Position=0)]
        [string] $ComputerName,

        [parameter(Mandatory=$true, ParameterSetName="ByPSSession", ValueFromPipeline=$true)]
        [System.Management.Automation.Runspaces.PSSession]
        $PSSession,

        [parameter(Mandatory=$false,Position=1)]
        [string] $TemplateId = "1.3.6.1.4.1.311.21.8.12017375.10856495.934812.8687423.15807460.10.5731641.6795722",

        [parameter(Mandatory=$false,Position=2)]
        [string[]] $SubjectAlternativeNames
    )
    BEGIN
    {
        if ($PSBoundParameters["ComputerName"])
        {
            $PSSession = New-PSSession -ComputerName $ComputerName;
        }
        $SessionArgs = @{ TemplateId = $TemplateId }
        if ($PSBoundParameters["SubjectAlternativeNames"])
        {
            $list = New-Object 'System.Collections.Generic.List[string]' $SubjectAlternativeNames.Length;
            foreach ($n in $SubjectAlternativeNames)
            {
                $list.Add($n)
            }
            $SessionArgs.DnsNames = $list;
        }
    }
    PROCESS
    {
        $cert = Invoke-Command -Session $PSSession -ArgumentList $SessionArgs -HideComputerName -ScriptBlock {
            param
            (
                [hashtable] $ArgList = $args[0]
            )
            $pkcs10 = New-Object -com "X509Enrollment.CX509CertificateRequestPkcs10.1";
            $pkcs10.InitializeFromTemplateName(2, $ArgList.TemplateId)

            $objDN = New-Object -com 'X509Enrollment.CX500DistinguishedName.1';
            $objDN.Encode("CN=$env:COMPUTERNAME", 0);
            $pkcs10.Subject = $objDN;

            if ($null -ne $ArgList.DnsNames)
            {
                $altNames = New-Object -com 'X509Enrollment.CAlternativeNames.1';
                $extNames = New-Object -com 'X509Enrollment.CX509ExtensionAlternativeNames.1';
                if ($true -notin $ArgList.DnsNames.ToArray().ForEach({[string]::Equals($_, $env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase)}))
                {
                    $ArgList.DnsNames.Insert(0, $env:COMPUTERNAME);
                }
                foreach ($name in $ArgList.DnsNames)
                {
                    $altName = New-Object -com 'X509Enrollment.CAlternativeName.1';
                    $altName.InitializeFromString(3, $name);
                    $altNames.Add($altName);
                }
                $extNames.InitializeEncode($altNames);
                $pkcs10.X509Extensions.Add($extNames);
            }

            $objEnroll = New-Object -com 'X509Enrollment.CX509Enrollment.1';
            $objEnroll.InitializeFromRequest($pkcs10);

            $strRequest = $objEnroll.CreateRequest(1);       # With BASE64-Encoding

            ### Create the Enrollment Request ###
            $certConfig = New-Object -com 'CertificateAuthority.Config';
            $certRequest = New-Object -com 'CertificateAuthority.Request';
            $caConfig = $certConfig.GetConfig(0);

            ### Submit the Request ###
            $disposition = $certRequest.Submit(
                1,
                $strRequest,
                $null,
                $caConfig
            );

            if (3 -ne $disposition)  # Not enrolled
            {
                throw "Certificate could not be enrolled!";
            }

            ### Get the Certificate ###
            $strCert = $certRequest.GetCertificate(257);     # CR_OUT_BASE64 | CR_OUT_CHAIN

            ### Install the Response ###
            $objEnroll.InstallResponse(0, $strCert, 1, $null);

            $justCert = $certRequest.GetCertificate(1);      # CR_OUT_BASE64
            [byte[]]$bytes = [System.Convert]::FromBase64String($justCert);

            ### Now use it as the RDP certificate ###
            $rdpCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes);
            $inst = Get-CimInstance -Namespace 'root\cimv2\TerminalServices' -ClassName "Win32_TSGeneralSetting" -Filter 'TerminalName = "RDP-Tcp"';
            $inst | Set-CimInstance -Property @{ SSLCertificateSHA1Hash = $rdpCert.Thumbprint };

            return $rdpCert;
        };

        Write-Output $cert -NoEnumerate;
    }
}