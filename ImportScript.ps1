$ErrorActionPreference = "Stop"
$os = [Version](Get-CimInstance -ClassName Win32_OperatingSystem).Version
if ($os.Major -eq 6)
{
    if ($null -eq (Get-Module PSPKI -ListAvailable))
    {
        try
        {
            Install-PackageProvider -Name NuGet -Force
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            Install-Module PSPKI
        }
        catch
        {
            Write-Error -ErrorRecord $_ -ErrorAction Stop
        }
    }
    Import-Module PSPKI
    $ErrorActionPreference = "Continue"
}