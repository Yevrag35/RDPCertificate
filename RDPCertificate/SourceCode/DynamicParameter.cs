using Dynamic;
using Security.Cryptography.X509Certificates;
using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;

namespace RDPCertificate
{
    public class Certs : Parameter
    {
        #region Constants
        internal const string pName = "SHA1Thumbrpint";
        private protected static readonly Type type = typeof(string);
        private protected readonly Dictionary<string, object> atts = new Dictionary<string, object>(3)
        {
            { "Mandatory", true },
            { "Position", 0 },
            { "ParameterSetName", "LocalCertsOnly" }
        };

        internal X509Certificate2Collection CertCol;

        public override bool AllowNull { get; set; }
        public override bool AllowEmptyCollection { get; set; }
        public override bool AllowEmptyString { get; set; }
        public override bool ValidateNotNull { get; set; }
        public override bool ValidateNotNullOrEmpty { get; set; }

        #endregion

        #region Constructor
        public Certs()
            : base(pName, type)
        {
            X509Certificate2Collection tempCol = null;
            using (var st = new X509Store(StoreLocation.LocalMachine))
            {
                st.Open(OpenFlags.ReadOnly);
                tempCol = st.Certificates;
                for (int c = tempCol.Count - 1; c >= 0; c--)
                {
                    var crt = tempCol[c];
                    if (!HasPrivateKey(crt))
                    {
                        tempCol.Remove(crt);
                    }
                }
            }
            CertCol = tempCol;
            var arr = new string[CertCol.Count];
            for (int i = 0; i < CertCol.Count; i++)
            {
                var cert = CertCol[i];
                arr[i] = cert.Thumbprint;
            }
            ValidatedItems = arr;
            Aliases = new string[1] { "sha1" };

            SetParameterAttributes(atts);

            CommitAttributes();
        }

        #endregion

        #region Methods

        private bool HasPrivateKey(X509Certificate2 cert)
        {
            bool haskey = X509CertificateExtensionMethods.HasCngKey(cert);
            if (!haskey)
            {
                haskey = cert.HasPrivateKey;
            }
            return haskey;
        }

        public override string ToString() => this.GetType().FullName;

        #endregion

        #region Operators/Casts
        public static implicit operator Library(Certs certs) =>
            new Library() { { certs.Name, certs } };

        #endregion
    }
}
