using Dynamic;
using Security.Cryptography.X509Certificates;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;

namespace RDPCertificate
{
    public class Certs : Parameter
    {
        #region Constants
        public const string pName = "SHA1Thumbrpint";

        #endregion

        public override bool AllowNull => true;
        public override bool AllowEmptyCollection => false;
        public override bool AllowEmptyString => false;
        public override bool ValidateNotNull => false;
        public override bool ValidateNotNullOrEmpty => false;


        public Certs()
            : base(pName, typeof(string))
        {
            AddAliases(new string[1] { "cert" });
        }

        public void GetValidatedItems(StoreLocation store)
        {
            X509Store st = new X509Store(store);
            st.Open(OpenFlags.MaxAllowed);
            X509Certificate2Collection certCol = st.Certificates;
            for (int i = 0; i < certCol.Count; i++)
            {
                X509Certificate2 cert = certCol[i];
                if (HasPrivateKey(cert))
                {
                    ValidatedItems.Add(cert.Thumbprint);
                }
            }
            st.Close();
            st.Dispose();
        }

        //public RuntimeDefinedParameterDictionary Generate()
        //{
        //    if (CertPrints == null)
        //    {
        //        GetValidatedItems(StoreLocation.LocalMachine);
        //    }
        //    Collection<Attribute> colAtt = new Collection<Attribute>();
        //    IDictionary pAtts = new Dictionary<string, object>()
        //    {
        //        { "Mandatory", true },
        //        { "Position", 0 },
        //        { "ParameterSetName", "ExistingCert" },
        //        { "ValueFromPipelineByPropertyName", true }
        //    };
        //    DynamicParameter dynParam = new DynamicParameter(pName, CertPrints.ToArray(), pAtts, new string[] { "sha1" }, typeof(string));
        //    return dynParam.GenerateLibrary();
        //}

        private bool HasPrivateKey(X509Certificate2 cert)
        {
            bool haskey = X509CertificateExtensionMethods.HasCngKey(cert);
            if (!haskey)
            {
                haskey = cert.HasPrivateKey;
            }
            return haskey;
        }

        public override string ToString()
        {
            return this.GetType().FullName;
        }
    }
}
