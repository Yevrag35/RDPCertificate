<#
.SYNOPSIS
 Outputs an object consisting of the template name (Template), an OID (OID), the minor version (MinorVersion), and the major version (MajorVersion).

.DESCRIPTION
 Outputs an object consisting of the template name (Template), an OID (OID), the minor version (MinorVersion), and the major version (MajorVersion).
 This information is derived from the Certificate Extensions.

.PARAMETER Certificate
 A X509Certificate2 object

.EXAMPLE
 Get-ChildItem "Cert:\LocalMachine\My" | Get-CertificateTemplate

.EXAMPLE
 Get-ChildItem "Cert:\LocalMachine\My" | Select-Object Name,Thumbprint,@{Name="Template";Expression={Get-CertificateTemplate $_}}

.INPUTS
 Any X509Certificate2 object

.OUTPUTS
 [PSCustomObject] @{Template=<template name; OID=<oid string>; MajorVersion=<major version num>; MinorVersion=<minor version num> }
#>
function Get-CertificateTemplate
{
    [CmdletBinding(SupportsShouldProcess = $false)]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        [Parameter(Mandatory = $false)]
        [switch] $ShowRootCertificate
    )

    Process
    {
        $regExPrimary = [System.Text.RegularExpressions.Regex]::new("Template=([\w\s\d\.]+)\(((?:\d+.)+)\), Major Version Number=(\d+), Minor Version Number=(\d+)", [System.Text.RegularExpressions.RegexOptions]::None)
        $regExSecondary = [System.Text.RegularExpressions.Regex]::new("Template=((?:\d+.)+), Major Version Number=(\d+), Minor Version Number=(\d+)", [System.Text.RegularExpressions.RegexOptions]::None)

        $ext = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq "1.3.6.1.4.1.311.21.7" }
        if ($null -eq $ext)
        {
            Write-Verbose "No Certificate Template Extension found for $($Certificate.Thumbprint)"
            return
        }

        $Matches = $regExPrimary.Matches($ext.Format($false))
        if ($Matches.Count -gt 0)
        {
            $object = @{Template = $Matches[0].Groups[1].Value; OID = $Matches[0].Groups[2].Value;
                MajorVersion = $Matches[0].Groups[3].Value; MinorVersion = $Matches[0].Groups[4].Value;
                Thumbprint = $Certificate.Thumbprint
            }
        }
        else
        {
            $Matches = $regExSecondary.Matches($ext.Format($false))
            if ($Matches.Count -gt 0)
            {
                Write-Verbose "Found certificate without a valid Template Name"
                $object = @{Template = $Matches[0].Groups[1].Value; OID = $Matches[0].Groups[1].Value;
                    MajorVersion = $Matches[0].Groups[2].Value; MinorVersion = $Matches[0].Groups[3].Value;
                    Thumbprint = $Certificate.Thumbprint
                }

            }
            elseif ($ShowRootCertificate)
            {
                Write-Verbose "Found root certificate"
                $object = @{Template = "Root Certificate"; OID = ""; MajorVersion = ""; MinorVersion = ""; Thumbprint = $Certificate.Thumbprint }
            }
            else
            {
                Write-Verbose "Skipping root certificate"
                return
            }
        }
        return [PSCustomObject]$object
    }
}