using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Generic;
using Microsoft.Management.Infrastructure.Options;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace RDP
{
    [Cmdlet(VerbsCommon.Set, "RDPCertificate")]
    [OutputType(typeof(void))]
    [CmdletBinding(PositionalBinding = false)]
    public class Certificate : PSCmdlet, IDynamicParameters
    {
        #region Fields
        private RuntimeDefinedParameterDictionary rtDict;
        private Certs _c;
        private string chosen;
        private const string ns = @"root\cimv2\TerminalServices";
        private const string dia = "WQL";
        private const string query = "SELECT * FROM Win32_TSGeneralSetting WHERE TerminalName = 'RDP-Tcp'";
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
        [ValidateSet("SHA256", "SHA384", "SHA512", IgnoreCase = true)]
        public string HashAlgorithm = "SHA256";

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
            if (_c.CertPrints.Length <= 0)
            {
                return String.Empty;
            }
            return rtDict;
        }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
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
                    Console.WriteLine(chosen);
                    SetCertificate(chosen);
                    break;
                case "CreateNewCert":
                    Console.WriteLine("Creating new certificate...");
                    break;
            }
        }

        private void SetCertificate(string SHA1Thumbrpint)
        {
            
            CimSession ses = CimSession.Create(pc);
            CimInstance c = ses.QueryInstances(ns, dia, query).ToArray()[0];
            CimProperty prop = c.CimInstanceProperties["SSLCertificateSHA1Hash"];
            prop.Value = SHA1Thumbrpint;
            ses.ModifyInstance(c);
        }
    }
}
