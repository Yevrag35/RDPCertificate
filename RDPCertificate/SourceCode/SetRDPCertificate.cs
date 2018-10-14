using Dynamic;
using MG.RDP.Certificates;
using Microsoft.Management.Infrastructure;
using Security.Cryptography.X509Certificates;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MG.RDP
{
    [Cmdlet(VerbsCommon.Set, "RDPCertificate", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High,
        DefaultParameterSetName = "SpecifyCertLocally")]
    [Alias("setrdcert")]
    [OutputType(typeof(void))]
    [CmdletBinding(PositionalBinding = false)]
    public class Certificate : PSCmdlet, IDynamicParameters
    {
        #region Fields
        private Library rtDict = null;
        private bool IsRemote = false;
        private ShouldProcessReason reason;
        private Certs _c;
        private string chosen;
        private protected const string lh = "localhost";

        #endregion

        #region Parameters
        [Parameter(Mandatory = true, ParameterSetName = "SpecifyCertRemotely")]
        public string ComputerName;
        
        [Parameter(Mandatory = false, ParameterSetName = "SpecifyCertRemotely")]
        public string RemoteThumbprint { get; set; }

        [Parameter(Mandatory = false)]
        public PSCredential Credential = null;

        private bool _sw;
        [Parameter(Mandatory = true, ParameterSetName = "NewCertLocally")]
        public SwitchParameter WithNewSelfSignedCert
        {
            get => _sw;
            set => _sw = value;
        }

        [Parameter(Mandatory = false, ParameterSetName = "NewCertLocally")]
        public DateTime ValidUntil = DateTime.Now.AddYears(1);

        [Parameter(Mandatory = false, ParameterSetName = "NewCertLocally")]
        public Algorithm HashAlgorithm = Algorithm.SHA256;

        [Parameter(Mandatory = false, ParameterSetName = "NewCertLocally")]
        [ValidateSet("2048", "4096", "8192", "16384", IgnoreCase = true)]
        public int KeyLength = 2048;

        #endregion

        private protected NewCertificate newcer = new NewCertificate();

        public object GetDynamicParameters()
        {
            if (string.IsNullOrEmpty(ComputerName) || _sw == false)
            {
                if (_c == null)
                    _c = new Certs();

                rtDict = _c;
            }
            else
            {
                rtDict = null;
            }
            return rtDict;
        }

        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            if (!string.IsNullOrEmpty(RemoteThumbprint) && !string.IsNullOrEmpty(ComputerName))
            {
                IsRemote = true;
                chosen = RemoteThumbprint;
            }
            else
            {
                chosen = _sw
                    ? newcer.GenerateNewCert(Environment.GetEnvironmentVariable("COMPUTERNAME"),
                                    "RDP Certificate", ValidUntil, HashAlgorithm, KeyLength).Thumbprint
                    : rtDict[_c.Name].Value as string;
            }
        }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            string pc = !IsRemote ? lh : ComputerName;
            var rdp = new RDPOperations(pc, Credential);
            rdp.SetRDPCertificate(chosen);
        }
    }
}
