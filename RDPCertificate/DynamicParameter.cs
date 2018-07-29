using Dynamic;
using Microsoft.Management.Infrastructure;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace RDP
{
    public class Certs
    {
        #region Constants
        public string pName = "SHA1Thumbrpint";

        #endregion
        public Certs() { }
        public string[] CertPrints;

        public void GetValidatedItems(StoreLocation store)
        {
            X509Store st = new X509Store(store);
            st.Open(OpenFlags.MaxAllowed);
            X509Certificate2Collection certCol = st.Certificates;
            CertPrints = new string[certCol.Count];
            for (int i = 0; i < certCol.Count; i++)
            {
                CertPrints[i] = certCol[i].Thumbprint;
            }
            st.Close();
            st.Dispose();
        }

        public RuntimeDefinedParameterDictionary Generate()
        {
            if (CertPrints == null)
            {
                GetValidatedItems(StoreLocation.LocalMachine);
            }
            Collection<Attribute> colAtt = new Collection<Attribute>();
            IDictionary pAtts = new Dictionary<string, object>()
            {
                { "Mandatory", true },
                { "Position", 0 },
                { "ParameterSetName", "ExistingCert" },
                { "ValueFromPipelineByPropertyName", true }
            };
            DynamicParameter dynParam = new DynamicParameter(pName, CertPrints, pAtts, new string[] { "sha1" }, typeof(string));
            return dynParam.GenerateLibrary();
        }
    }
}
