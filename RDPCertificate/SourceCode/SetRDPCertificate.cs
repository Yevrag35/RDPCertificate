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

namespace RDPCertificate
{
    [Cmdlet(VerbsCommon.Set, "RDPCertificate", SupportsShouldProcess = true, ConfirmImpact = ConfirmImpact.High,
        DefaultParameterSetName = "LocalCertsOnly")]
    [OutputType(typeof(void))]
    [CmdletBinding(PositionalBinding = false)]
    public class Certificate : PSCmdlet, IDynamicParameters
    {
        #region Fields
        private Library rtDict = null;
        private ShouldProcessReason reason;
        private Certs _c;
        private string chosen;

        #endregion

        #region Parameters
        [Parameter(Mandatory = true, ParameterSetName = "CreateNewCertRemotely")]
        [Parameter(Mandatory = true, ParameterSetName = "SpecifyCertRemotely")]
        public string ComputerName;

        [Parameter(Mandatory = true, ParameterSetName = "CreateNewCertRemotely")]
        [Parameter(Mandatory = true, ParameterSetName = "SpecifyCertRemotely")]
        public string RemoteThumbprint { get; set; }


        private bool _sw;
        [Parameter(Mandatory = true, ParameterSetName = "CreateNewCertRemotely")]
        [Parameter(Mandatory = true, ParameterSetName = "CreateNewCertLocally")]
        public SwitchParameter WithNewSelfSignedCert
        {
            get => _sw;
            set => _sw = value;
        }

        [Parameter(Mandatory = false, ParameterSetName = "CreateNewCertRemotely")]
        [Parameter(Mandatory = false, ParameterSetName = "CreateNewCertLocally")]
        public DateTime ValidUntil = DateTime.Now.AddYears(2);

        [Parameter(Mandatory = false, ParameterSetName = "CreateNewCertRemotely")]
        [Parameter(Mandatory = false, ParameterSetName = "CreateNewCertLocally")]
        public Algorithm HashAlgorithm = Algorithm.SHA256;

        [Parameter(Mandatory = false, ParameterSetName = "CreateNewCertRemotely")]
        [Parameter(Mandatory = false, ParameterSetName = "CreateNewCertLocally")]
        [ValidateSet("2048", "4096", "8192", "16384", IgnoreCase = true)]
        public int KeyLength = 2048;

        #endregion

        public object GetDynamicParameters()
        {
            if (string.IsNullOrEmpty(ComputerName))
            {
                if (_c == null)
                {
                    rtDict = new Certs();
                }
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
            chosen = rtDict != null ? 
                rtDict[_c.Name].Value as string : 
                !string.IsNullOrEmpty(RemoteThumbprint) ?
                    RemoteThumbprint : null;

            WriteObject(chosen);
        }

        //protected override void ProcessRecord()
        //{
        //    base.ProcessRecord();
        //    CimSession ses = CimSession.Create(pc);
        //    if (!CimStuff.IsCurrentInstalled(ses) || ShouldProcess("Changing SHA1Thumbprint for RDP", "Performing a CimInstance Modification", "Change the encryption certificate for RDP", out reason))
        //        switch (ParameterSetName)
        //        {
        //            case "ExistingCert":
        //                if (rtDict != null)
        //                {
        //                    chosen = rtDict[_c.pName].Value as string;
        //                }
        //                if (String.IsNullOrEmpty(chosen))
        //                {
        //                    throw new Exception("Cannot set certificate with a NULL thumbprint!");
        //                }
        //                WriteVerbose("Setting Thumbprint for RDP services...");
        //                CimStuff.SetCertificate(ses, chosen);
        //                break;
        //            case "CreateNewCert":
        //                WriteVerbose("Creating new certificate...");
        //                CreateNew creator = new CreateNew(ValidUntil, HashAlgorithm, (CreateNew.KeyLengths)KeyLength);
        //                X509Certificate2 newCert = creator.GenerateCertificate();
        //                WriteVerbose("Setting Thumbprint for RDP services to " + newCert.Thumbprint + "...");
        //                CimStuff.SetCertificate(ses, newCert.Thumbprint);
        //                break;
        //        }
        //}
    }
}
