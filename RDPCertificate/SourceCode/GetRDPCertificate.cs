using System.Management.Automation;

namespace MG.RDP
{
    [Cmdlet(VerbsCommon.Get, "InstalledRDPCertificate")]
    [OutputType(typeof(CurrentCertificate))]
    [CmdletBinding(PositionalBinding = false)]
    public class GetInstalledCertificate : PSCmdlet
    {
        private protected const string p = "SSLCertificateSHA1Hash";
        private protected const string lh = "localhost";

        #region Parameters
        [Parameter(Mandatory = false, DontShow = true)]
        public string ComputerName = lh;

        [Parameter(Mandatory = false, Position = 1)]
        public AuthOptions Authentication = AuthOptions.Passthrough;

        [Parameter(Mandatory = false, Position = 0)]
        public PSCredential Credential = null;

        #endregion

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            var rdp = new RDPOperations(Authentication, ComputerName, Credential);
            WriteObject(rdp.GetCurrentCertificate());
        }
    }
}
