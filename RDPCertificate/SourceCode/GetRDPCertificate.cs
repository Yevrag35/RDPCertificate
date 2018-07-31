using Microsoft.Management.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;

namespace RDPCertificate
{
    [Cmdlet(VerbsCommon.Get, "InstalledRDPCertificate")]
    [OutputType(typeof(X509Certificate2))]
    public class GetInstalledCertificate : PSCmdlet
    {
        private const string p = "SSLCertificateSHA1Hash";
        private const string pc = "localhost";

        protected override void ProcessRecord()
        {
            base.ProcessRecord();
            X509Certificate2 installed;
            CimSession ses = CimSession.Create(pc);
            if (CimStuff.IsCurrentInstalled(ses))
            {
                installed = GetInstalledCert(ses);
            }
            else
            {
                installed = null;
            }
            WriteObject(installed);
        }

        private X509Certificate2 GetInstalledCert(CimSession ses)
        {
            X509Certificate2 installed;
            CimInstance c = CimStuff.GetCimInstance(ses);
            string thumbprint = (string)c.CimInstanceProperties[p].Value;
            X509Store store = new X509Store(StoreLocation.LocalMachine);
            store.Open(OpenFlags.MaxAllowed);
            X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
            if (certs.Count > 0)
            {
                installed = certs[0];
            }
            else
            {
                installed = null;
            }
            store.Close();
            store.Dispose();
            GC.Collect();
            return installed;
        }
    }
}
