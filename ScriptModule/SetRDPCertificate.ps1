Function SetLocalRDPCertificate()
{
    [CmdletBinding()]
    param
    (
        [ciminstance]$CimInstance,
        [string]$Thumbprint
    )
    
    if (-not [string]::IsNullOrEmpty($Thumbprint) -and $null -ne $CimInstance)
    {
        try
        {
            Set-CimInstance -InputObject $CimInstance -Property @{
                SSLCertificateSHA1Hash = $Thumbprint.ToUpper()
            } -ErrorAction Stop
        }
        catch [Microsoft.Management.Infrastructure.CimException]
        {
            if ($_.Exception.Message -like "*Invalid Parameter*")
            {
                $msg = "The specified certificate more than likely does not support Server Authentication."
                $aggEx = New-Object System.AggregateException($msg, $_.Exception)
                $errRec = New-Object System.Management.Automation.ErrorRecord($aggEx, $_.Exception.GetType().FullName, "InvalidArgument", $SHA1Thumbprint)
                $weArgs = @{
                    ErrorRecord = $errRec
                    CategoryActivity = "Setting CimInstance"
                    CategoryReason = "Invalid SHA1Thumbprint"
                    RecommendedAction = "Select a different certificate"
                }
                Write-Error @weArgs
            }
            else
            {
                Write-Error -Exception $_.Exception
            }
        }
    }
}

Function SetRemoteRDPCertificate()
{
    [CmdletBinding()]
    param
    (
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string[]]$ComputerName,
        [pscredential]$Credential,
        [byte[]]$CertData,
        [string]$Thumbprint,
        [bool]$Exportable
    )
    $script = {
        param
        (
            [byte[]]$certData,
            [string]$thumbprint,
            [bool]$exportable
        )
        if ([string]::IsNullOrEmpty($thumbprint) -and $null -ne $certData -and $certData.Length -gt 0)
        {
            if ($exportable)
            {
                $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]"PersistKeySet,Exportable"
            }
            else
            {
                $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
            }

            try
            {
                $cert = New-Object -TypeName "System.Security.Cryptography.X509Certificates.X509Certificate2" -ArgumentList $certData, $using:PfxPassword, $flags
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList "My", "LocalMachine"
                $store.Open("ReadWrite")
                $store.Add($cert)
                $store.Close()
                $thumbprint = $cert.Thumbprint
            }
            catch
            {
                $ex = $_.Exception
                $result = $false
            }
        }
        
        if (-not [string]::IsNullOrEmpty($thumbprint))
        {
            $wmiNamespace = "ROOT\cimv2\TerminalServices"
            $wmiClass = "Win32_TSGeneralSetting"
            $wmiFilter = "TerminalName = 'RDP-Tcp'"
            $cimQueryArgs = @{
                Namespace = $wmiNamespace
                ClassName = $wmiClass
                Filter = $wmiFilter
            }
            try
            {
                Get-CimInstance @cimQueryArgs -ErrorAction Stop | Set-CimInstance -Property @{
                    SSLCertificateSHA1Hash = $thumbprint.ToUpper()
                } -ErrorAction Stop
                $result = $true
            }
            catch
            {
                $ex = $_.Exception
                $result = $false
            }
        }
        else
        {
            $ex = New-Object System.ArgumentException("Thumbprint was not supplied or pfx was not successfully installed.")
        }

        [pscustomobject]@{
            Result = $result
            Exception = $ex
        }
    }

    $invokeArgs = @{
        ArgumentList = @($CertData, $Thumbprint, $Exportable)
        ScriptBlock = $script
    }
    if ($PSBoundParameters.ContainsKey("ComputerName"))
    {
        $invokeArgs.Add("ComputerName", $ComputerName)
        if ($PSBoundParameters.ContainsKey("Credential"))
        {
            $invokeArgs.Add("Credential", $Credential)
        }
    }
    else
    {
        $invokeArgs.Add("Session", $Session)
    }
    $allResults = @(Invoke-Command @invokeArgs)
    foreach ($res in $allResults)
    {
        if (-not $res.Result)
        {
            $res.Exception
        }
    }
}

Function Set-RDPCertificate()
{
    [CmdletBinding(DefaultParameterSetName="LocalByThumbprint")]
    param
    (
        [Parameter(Mandatory = $true, Position=1, ParameterSetName = "ByComputerNameWithPfx")]
        [Parameter(Mandatory = $true, Position=1, ParameterSetName = "ByComputerNameByThumbprint")]
        [string[]] $ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = "ByComputerNameWithPfx")]
        [Parameter(Mandatory = $false, ParameterSetName = "ByComputerNameByThumbprint")]
        [pscredential] $Credential,

        [Parameter(Mandatory = $true, ParameterSetName = "BySessionWithPfx")]
        [Parameter(Mandatory = $true, ParameterSetName = "BySessionByThumbprint")]
        [System.Management.Automation.Runspaces.PSSession] $Session,

        [Parameter(Mandatory=$true, ParameterSetName="LocalWithPfx")]
        [Parameter(Mandatory=$true, ParameterSetName="ByComputerNameWithPfx")]
        [Parameter(Mandatory=$true, ParameterSetName="BySessionWithPfx")]
        [string] $PfxFilePath,

        [Parameter(Mandatory=$true, ParameterSetName="LocalWithPfx")]
        [Parameter(Mandatory=$true, ParameterSetName="ByComputerNameWithPfx")]
        [Parameter(Mandatory=$true, ParameterSetName="BySessionWithPfx")]
        [securestring] $PfxPassword,

        [Parameter(Mandatory=$false, ParameterSetName="LocalWithPfx")]
        [Parameter(Mandatory=$false, ParameterSetName="ByComputerNameWithPfx")]
        [Parameter(Mandatory=$false, ParameterSetName="BySessionWithPfx")]
        [switch] $Exportable,

        [Parameter(Mandatory=$true, ParameterSetName="LocalByThumbprint", ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true, ParameterSetName="ByComputerNameByThumbprint", ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true, ParameterSetName="BySessionByThumbprint", ValueFromPipelineByPropertyName=$true)]
        [Alias("Thumbprint", "PublishedThumbprint")]
        [string] $SHA1Thumbprint
    )
    Begin
    {
        $wmiNamespace = "ROOT\cimv2\TerminalServices"
        $wmiClass = "Win32_TSGeneralSetting"
        $wmiFilter = "TerminalName = 'RDP-Tcp'"
        $cimQueryArgs = @{
            Namespace = $wmiNamespace
            ClassName = $wmiClass
            Filter = $wmiFilter
        }

        if ($PSBoundParameters.ContainsKey("PfxFilePath"))
        {
            if ($PSCmdlet.ParameterSetName -notlike "Local*")
            {
                $pfxData = Get-PfxData -FilePath $PfxFilePath -Password $PfxPassword -ErrorAction Stop
                $cert = $pfxData.EndEntityCertificates | Select-Object -First 1
                [byte[]]$certData = $cert.Export("Pfx", $PfxPassword)
            }
            else
            {
                $importPfxArgs = @{
                    FilePath = $PfxFilePath
                    Password = $PfxPassword
                    CertStoreLocation = "Cert:\LocalMachine\My"
                    Exportable = $Exportable.ToBool()
                }
                $SHA1Thumbprint = Import-PfxCertificate @importPfxArgs | Select-Object -ExpandProperty Thumbprint
            }
        }
        $sesArgs = @{}
        if ($PSBoundParameters.ContainsKey("Session"))
        {
            $sesArgs.Add("Session", $Session)
        }
        elseif ($PSBoundParameters.ContainsKey("ComputerName"))
        {
            $sesArgs.Add("ComputerName", $ComputerName)
            if ($PSBoundParameters.ContainsKey("Credential"))
            {
                $sesArgs.Add("Credential", $Credential)
            }
        }
    }
    Process
    {
        if ($PSCmdlet.ParameterSetName -like "Local*")
        {
            $instance = Get-CimInstance @cimQueryArgs
            SetLocalRDPCertificate -CimInstance $instance -Thumbprint $SHA1Thumbprint
        }
        else
        {
            SetRemoteRDPCertificate @sesArgs -CertData $certData -Thumbprint $SHA1Thumbprint -Exportable $Exportable.ToBool()
        }
    }
}

$answer = Set-RDPCertificate -ComputerName garvmedia -PfxFilePath "E:\Local_Repos\RDPCertificate\test.pfx" -PfxPassword $(Get-Credential blah).Password -Exportable
$answer