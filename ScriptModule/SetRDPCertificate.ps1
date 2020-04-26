

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

        [Parameter(Mandatory=$true, ParameterSetName="LocalByThumbprint", ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true, ParameterSetName="ByComputerNameByThumbprint", ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true, ParameterSetName="BySessionByThumbprint", ValueFromPipelineByPropertyName=$true)]
        [Alias("Thumbprint", "PublishedThumbprint")]
        [string] $SHA1Thumbprint
    )
    Begin
    {
        if ($PSBoundParameters.ContainsKey("PfxFilePath"))
        {
            $pfxData = Get-PfxData -FilePath $PfxFilePath -Password $PfxPassword -ErrorAction Stop
            if ($pfxData.EndEntityCertificates.Count -gt 1)
            {
                throw "The specified Pfx file contains more than 1 end-entity certificate."
            }

            if ($PSCmdlet.ParameterSetName -notlike "Local*")
            {
                [byte[]]$certData = $pfxData.EndEntityCertificates | Select-Object -First 1 | ForEach-Object -MemberName GetRawCertData
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
            elseif ($PSBoundParameters.ContainsKey("Credential"))
            {
                $sesArgs.Add("Credential", $Credential)
            }
        }
    }
    Process
    {
        if ($PSCmdlet.ParameterSetName -like "Local*")
        {

        }
    }
}