using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;
using Security.Cryptography.X509Certificates;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MG.RDP
{
    public class RDPOperations
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
        private protected bool UsingCredentials = false;

        public RDPOperations(string machineName = lh,PSCredential psCreds = null)
        {
            var dComOpts = new DComSessionOptions()
            {
                Culture = CultureInfo.CurrentCulture,
                UICulture = CultureInfo.CurrentUICulture,
                PacketIntegrity = true,
                PacketPrivacy = true,
                Timeout = new TimeSpan(0)
            };
            if (psCreds != null)
            {
                UsingCredentials = true;
                var user = RDPCredential.ParseUser(psCreds);
                var dom = RDPCredential.ParseDomain(psCreds);
                var cimCred = new CimCredential(PasswordAuthenticationMechanism.Default,
                    dom, user, psCreds.Password);
                dComOpts.AddDestinationCredentials(cimCred);
            }
            _cim = CimSession.Create(machineName, dComOpts);
        }

        #region Methods
        public CurrentCertificate GetCurrentCertificate(bool IsRemote = false)
        {
            _curCert = null;
            RemoteSearchStatus status;
            CimInstance c = GetCimInstance(_cim);
            var thumbprint = c.CimInstanceProperties[p].Value as string;
            if (!IsRemote)
            {
                using (var store = new X509Store(StoreLocation.LocalMachine))
                {
                    store.Open(OpenFlags.ReadOnly);
                    X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                    try
                    {
                        _curCert = certs.Cast<X509Certificate2>().ToArray().FirstOrDefault();
                    }
                    catch (ArgumentNullException)
                    {
                        throw new ArgumentNullException("certs");
                    }
                }
                return new CurrentCertificate(thumbprint, _curCert, RemoteSearchStatus.NotNeeded);
            }
            else if (IsRemote && !UsingCredentials)
            {
                // Unfortunately, this doesn't support explicit credential authentication.
                // ...so if you don't have access with your current session credentials, the
                // best info you'll get back is the thumbprint by itself.
                status = RemoteSearchStatus.Performed;

                // Check "RemoteDesktop" store first...
                using (var rdStore = new X509Store(@"\\" + _cim.ComputerName + "\\Remote Desktop", StoreLocation.LocalMachine))
                {
                    rdStore.Open(OpenFlags.ReadOnly);
                    X509Certificate2Collection certs = rdStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                    try
                    {
                        _curCert = certs.Cast<X509Certificate2>().ToArray().FirstOrDefault();
                    }
                    catch (ArgumentNullException)
                    {
                        _curCert = null;
                    }
                }
                // If not found in the RD Store, check the Personal/My store...
                if (_curCert == null)
                {
                    using (var myStore = new X509Store(@"\\" + _cim.ComputerName + "\\My", StoreLocation.LocalMachine))
                    {
                        myStore.Open(OpenFlags.ReadOnly);
                        X509Certificate2Collection certs = myStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                        try
                        {
                            _curCert = certs.Cast<X509Certificate2>().ToArray().FirstOrDefault();
                        }
                        catch (ArgumentNullException)
                        {
                            _curCert = null;
                        }
                    }
                }
            }
            else
            {
                status = RemoteSearchStatus.NotPerformed;
            }
            return new CurrentCertificate(thumbprint, _curCert, status);
        }

        public void SetRDPCertificate(string thumbprint)
        {
            CimInstance c = GetCimInstance(_cim);
            var check = !c.CimInstanceProperties[p].Value.Equals(thumbprint);
            if (check)
            {
                var prop = c.CimInstanceProperties[p];
                prop.Value = thumbprint;
                _cim.ModifyInstance(c);
            }
        }

        private protected CimInstance GetCimInstance(CimSession ses) =>
            ses.QueryInstances(ns, dia, query).ToArray().FirstOrDefault();

        #endregion
    }

    public class CurrentCertificate
    {
        private readonly string _th;
        private readonly X509Certificate2 _cert = null;
        private readonly RemoteSearchStatus _stat;

        public string PublishedThumbprint => _th;
        public RemoteSearchStatus RemoteSearch => _stat;
        public bool? Exists => _stat != RemoteSearchStatus.NotPerformed ? _cert != null : (bool?)null;
        public X509Certificate2 Certificate => _cert;

        internal CurrentCertificate(string pubThumb, X509Certificate2 cert, RemoteSearchStatus status)
        {
            _th = pubThumb;
            _cert = cert;
            _stat = status;
        }
    }

    public enum RemoteSearchStatus
    {
        NotNeeded = 0,
        Performed = 1,
        NotPerformed = 2
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
        public static explicit operator RDPCredential(PSCredential psc) => 
            new RDPCredential(PasswordAuthenticationMechanism.Default, psc);

        #endregion

        internal static string ParseDomain(PSCredential psc)
        {
            string un = psc.UserName;
            string domain = null;
            if (un.Contains(@"\"))
            {
                domain = un.Split(new string[1] { @"\" }, StringSplitOptions.RemoveEmptyEntries).First();
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
                real = un.Split(new string[1] { @"\" }, StringSplitOptions.RemoveEmptyEntries).Last();
            }
            else if (un.Contains("@"))
            {
                real = un;
            }
            return real;
        }
    }
}
