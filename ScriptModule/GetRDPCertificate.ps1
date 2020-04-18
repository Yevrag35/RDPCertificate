

Function GetCertScriptBlock()
{
    {
        Function CheckStoreForCert([string]$name)
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
            $x509Store.Close()
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
                        $x509Store.Close()
                        continue
                    }

                    if ($certCol.Count -gt 0)
                    {
                        $foundCert = $certCol
                        $foundStore = $storeName
                        $x509Store.Close()
                        break
                    }
                    else
                    {
                        $x509Store.Close()
                        continue
                    }
                }
            }
        }


        [pscustomobject]@{
            PublishedThumbprint = $cimRdpCert
            Exists              = $foundCert.Count -gt 0
            Certificates        = $foundCert
            StoreName           = $foundStore
            Exceptions          = $exceptions
            IsFaulted           = $exceptions.Count -gt 0
        }
    }
}
Function Get-RDPCertificate()
{
    [CmdletBinding(DefaultParameterSetName = "None")]
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
        "Exists",
        "IsFaulted",
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

        Invoke-Command @sesArgs -ScriptBlock (GetCertScriptBlock) | Select-Object $selectProps
    }
    else
    {
        $(GetCertScriptBlock).Invoke()
    }
}