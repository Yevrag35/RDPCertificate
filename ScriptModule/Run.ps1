. "$PSScriptRoot\RDPCertificateResult.ps1"
gci $PSScriptRoot -Filter *.ps1 -Exclude "RDPCertificateResult.ps1", "Run.ps1" -Recurse | %{
    . $_.FullName
}