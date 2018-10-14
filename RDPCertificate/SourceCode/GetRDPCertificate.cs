using System;
using System.Management.Automation;

namespace MG.RDP
{
    [Cmdlet(VerbsCommon.Get, "RDPCertificate")]
    [Alias("Get-InstalledRDPCertificate", "getrdcert")]
    [OutputType(typeof(CurrentCertificate))]
    [CmdletBinding(PositionalBinding = false)]
    public class GetInstalledCertificate : PSCmdlet
    {
        private protected const string p = "SSLCertificateSHA1Hash";
        private protected const string lh = "localhost";

        #region Parameters

        [Parameter(Mandatory = false, Position = 0)]
        public PSCredential Credential = null;

        [Parameter(Mandatory = false, Position = 1)]
        public string ComputerName = lh;

        #endregion

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            var rdp = new RDPOperations(ComputerName, Credential);
            bool isRemote = false;
            if (ComputerName != lh && ComputerName != Environment.GetEnvironmentVariable("COMPUTERNAME"))
            {
                isRemote = true;
                if (Credential != null)
                {
                    WriteWarning("Checking the presence of the remote certificate is not possible with explicit credentials.");
                }
            }
            WriteObject(rdp.GetCurrentCertificate(isRemote));
        }
    }
}
