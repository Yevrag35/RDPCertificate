using MG.Attributes;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;
using Security.Cryptography.X509Certificates;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MG.RDP
{
    public class RDPOperations : AttributeResolver
    {
        private X509Certificate2 _curCert;
        private readonly CimSession _cim;
        private static readonly string pc = Environment.GetEnvironmentVariable("COMPUTERNAME");
        private protected const string lh = "localhost";
        private protected const string ns = @"root\cimv2\TerminalServices";
        private protected const string dia = "WQL";
        private protected const string query = "SELECT * FROM Win32_TSGeneralSetting WHERE TerminalName = 'RDP-Tcp'";
        private protected const string p = "SSLCertificateSHA1Hash";

        public X509Certificate2 CurrentCertificate => _curCert;
        public CimSession CimSession => _cim;

        public RDPOperations(AuthOptions authOption = AuthOptions.Passthrough, string machineName = lh,PSCredential psCreds = null)
        {
            if (machineName == lh || machineName == pc)
            {
                _cim = CimSession.Create(pc);
            }
            else
            {
                var auth = GetAttributeValue<object>(authOption, typeof(AuthAttribute));
                if (auth is ImpersonatedAuthenticationMechanism)
                {
                    new
                }
            }
        }
        private RDPOperations(RDPCredential rdpCreds)
        {

        }

        #region Methods
        public CurrentCertificate GetCurrentCertificate()
        {
            _curCert = null;
            CimInstance c = GetCimInstance(_cim);
            var thumbprint = c.CimInstanceProperties[p].Value as string;
            using (var store = new X509Store(StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.MaxAllowed);
                X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                try
                {
                    _curCert = certs.Cast<X509Certificate2>().ToArray().FirstOrDefault();
                }
                catch (ArgumentNullException ex)
                {
                    throw new ArgumentNullException("certs");
                }
            }
            return new CurrentCertificate(thumbprint, _curCert);
        }

        private protected CimInstance GetCimInstance(CimSession ses) =>
            ses.QueryInstances(ns, dia, query).ToArray().FirstOrDefault();

        #endregion
    }

    public class CurrentCertificate
    {
        private readonly string _th;
        private readonly X509Certificate2 _cert = null;

        public string PublishedThumbprint => _th;
        public bool Exists => _cert != null;
        public X509Certificate2 Certificate => _cert;

        internal CurrentCertificate(string pubThumb, X509Certificate2 cert)
        {
            _th = pubThumb;
            _cert = cert;
        }
    }

    public class RDPCredential : CimCredential
    {
        public RDPCredential(ImpersonatedAuthenticationMechanism impAuth)
            : base(impAuth)
        {
        }
        public RDPCredential(PasswordAuthenticationMechanism passAuth, string domain, string userName, SecureString password)
            : base(passAuth, domain, userName, password)
        {
        }
        public RDPCredential(PasswordAuthenticationMechanism passAuth, PSCredential psCreds)
            : base(passAuth, ParseDomain(psCreds), ParseUser(psCreds), psCreds.Password)
        {
        }

        #region Operators/Casts
        public static implicit operator RDPCredential(PSCredential psc) => 
            new RDPCredential(PasswordAuthenticationMechanism.Negotiate, psc);

        #endregion

        internal static string ParseDomain(PSCredential psc)
        {
            string un = psc.UserName;
            string domain = null;
            if (un.Contains("\\"))
            {
                domain = un.Split(new string[1] { @"\\" }, StringSplitOptions.RemoveEmptyEntries).First();
            }
            else if (un.Contains("@"))
            {
                domain = un.Split(new string[1] { @"\" }, StringSplitOptions.RemoveEmptyEntries).Last();
            }
            return domain;
        }
        internal static string ParseUser(PSCredential psc)
        {
            string un = psc.UserName;
            string real = null;
            if (un.Contains("\\"))
            {
                real = un.Split(new string[1] { @"\\" }, StringSplitOptions.RemoveEmptyEntries).Last();
            }
            else if (un.Contains("@"))
            {
                real = un;
            }
            return real;
        }
    }
}
