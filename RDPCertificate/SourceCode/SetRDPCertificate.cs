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

namespace RDPCertificate
{
    [Cmdlet(VerbsCommon.Set, "RDPCertificate", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High)]
    [OutputType(typeof(void))]
    [CmdletBinding(PositionalBinding = false)]
    public class Certificate : PSCmdlet, IDynamicParameters
    {
        #region Fields
        private RuntimeDefinedParameterDictionary rtDict;
        private ShouldProcessReason reason;
        private Certs _c;
        private string chosen;
        private const string pc = "localhost";

        #endregion

        #region Parameters
        private bool _sw;
        [Parameter(Mandatory = true, ParameterSetName = "CreateNewCert")]
        public SwitchParameter WithNewSelfSignedCert
        {
            get { return _sw; }
            set { _sw = value; }
        }

        [Parameter(Mandatory = false, ParameterSetName = "CreateNewCert")]
        public DateTime ValidUntil = DateTime.Now.AddYears(2);

        [Parameter(Mandatory = false, ParameterSetName = "CreateNewCert")]
        public CreateNew.HashAlgorithm HashAlgorithm = CreateNew.HashAlgorithm.SHA256;

        [Parameter(Mandatory = false, ParameterSetName = "CreateNewCert")]
        [ValidateSet("2048", "4096", "8192", "16384", IgnoreCase = true)]
        public int KeyLength = 2048;

        #endregion

        public object GetDynamicParameters()
        {
            if (_c == null)
            {
                _c = new Certs();
            }
            rtDict = _c.Generate();
            if (_c.CertPrints.Count <= 0)
            {
                return String.Empty;
            }
            return rtDict;
        }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            CimSession ses = CimSession.Create(pc);
            if (!CimStuff.IsCurrentInstalled(ses) || ShouldProcess("Changing SHA1Thumbprint for RDP", "Performing a CimInstance Modification", "Change the encryption certificate for RDP", out reason))
                switch (ParameterSetName)
                {
                    case "ExistingCert":
                        if (rtDict != null)
                        {
                            chosen = rtDict[_c.pName].Value as string;
                        }
                        if (String.IsNullOrEmpty(chosen))
                        {
                            throw new Exception("Cannot set certificate with a NULL thumbprint!");
                        }
                        WriteVerbose("Setting Thumbprint for RDP services...");
                        CimStuff.SetCertificate(ses, chosen);
                        break;
                    case "CreateNewCert":
                        WriteVerbose("Creating new certificate...");
                        CreateNew creator = new CreateNew(ValidUntil, HashAlgorithm, (CreateNew.KeyLengths)KeyLength);
                        X509Certificate2 newCert = creator.GenerateCertificate();
                        WriteVerbose("Setting Thumbprint for RDP services to " + newCert.Thumbprint + "...");
                        CimStuff.SetCertificate(ses, newCert.Thumbprint);
                        break;
                }
        }
    }
}
