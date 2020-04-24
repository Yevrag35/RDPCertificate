

Function GetCertScriptBlock()
{
    {
        Function CheckStoreForCert([string]$name)
        {
            try
            {
                $x509Store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store(
                    $name,
                    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
                )

                $x509Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

                $x509Store.Certificates.Find(
                    [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
                    $cimRdpCert,
                    $false
                )
            }
            finally
            {
                if ($null -ne $x509store)
                {
                    $x509Store.Close()
                }
            }
        }

        $exceptions = New-Object -TypeName 'System.Collections.Generic.List[System.Exception]'

        $thumProp = "SSLCertificateSHA1Hash"
        $cimGetArgs = @{
            Namespace = "ROOT\cimv2\TerminalServices"
            ClassName = "Win32_TSGeneralSetting"
            Filter    = "TerminalName = 'RDP-Tcp'"
            Property  = $thumProp
        }

        try
        {
            $cimRdp = Get-CimInstance @cimGetArgs -ErrorAction Stop
            if ($null -ne $cimRdp)
            {
                $cimRdpCert = $cimRdp.$thumProp
            }
        }
        catch
        {
            $exceptions.Add($_.Exception)
        }

        if (-not [string]::IsNullOrEmpty($cimRdpCert))
        {
            # Check 'My' store first
            $certCol = CheckStoreForCert -name "My"
            if ($certCol.Count -gt 0)
            {
                $foundCert = $certCol
                $foundStore = "My"
            }
            else
            {

                $stores = Get-Item Cert:\LocalMachine | ForEach-Object StoreNames
                foreach ($store in $stores.GetEnumerator().Where( { $_.Key -ne "My" }))
                {
                    $storeName = $store.Key

                    try
                    {
                        $certCol = CheckStoreForCert -name $storeName
                    }
                    catch
                    {
                        $exceptions.Add($_.Exception)
                        continue
                    }

                    if ($certCol.Count -gt 0)
                    {
                        $foundCert = $certCol
                        $foundStore = $storeName
                        break
                    }
                    else
                    {
                        continue
                    }
                }
            }
        }


        [pscustomobject]@{
            PublishedThumbprint = $cimRdpCert
            Certificates        = $foundCert
            StoreName           = $foundStore
            Exceptions          = $exceptions
        }
    }
}
Function Get-RDPCertificate()
{
    [CmdletBinding(DefaultParameterSetName = "None")]
    [OutputType([RDPCertificateResult])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "ByComputerName")]
        [string[]] $ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = "ByComputerName")]
        [pscredential] $Credential,

        [Parameter(Mandatory = $true, ParameterSetName = "BySession")]
        [System.Management.Automation.Runspaces.PSSession] $Session
    )

    $selectProps = [System.Collections.Generic.List[object]]@(
        @{L = "Certificate"; E = { $_.Certificates | Select-Object -First 1 } },
        "Exceptions",
        "PublishedThumbprint"
        "StoreName"
    )

    if ($PSCmdlet.ParameterSetName -like "By*")
    {
        $sesArgs = @{ }
        if ($PSBoundParameters.ContainsKey("Session"))
        {
            $sesArgs.Add("Session", $Session)
        }
        else
        {
            $sesArgs.Add("ComputerName", $ComputerName)
            if ($PSBoundParameters.ContainsKey("Credential"))
            {
                $sesArgs.Add("Credential", $Credential)
            }
        }

        $selectProps.Insert(1, @{L = "ComputerName"; E = "PSComputerName" })

        $result = Invoke-Command @sesArgs -ScriptBlock (GetCertScriptBlock) | Select-Object -Property $selectProps
    }
    else
    {
        $result = $(GetCertScriptBlock).Invoke() | Select-Object -Property $selectProps

    }
    New-Object -TypeName "RDPCertificateResult" -ArgumentList $result
}