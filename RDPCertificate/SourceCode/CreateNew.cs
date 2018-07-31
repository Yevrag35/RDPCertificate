using CERTENROLLLib;
using Security.Cryptography;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web.Security;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace RDPCertificate
{
    public class ValueAttribute : Attribute
    {
        private string _vl;
        public string Value { get { return _vl; } }
        public ValueAttribute(string value)
        {
            _vl = value;
        }
    }

    public class CreateNew
    {
        private const string provName = "Microsoft Enhanced RSA and AES Cryptographic Provider";

        private List<CX509Extension> ExtensionsToAdd = new List<CX509Extension>();
        private string SubjectName { get; set; }
        public DateTime ValidUntil { get; }
        public string Algorithm { get; }
        public int KeyLength { get; }

        public CreateNew(DateTime validUntil, HashAlgorithm hash, KeyLengths keyLength)
        {
            ValidUntil = validUntil;
            Algorithm = GetValue(hash);
            KeyLength = (int)keyLength;
        }

        #region Enums
        public enum HashAlgorithm : int
        {
            [Value("SHA256")]
            SHA256 = 0,

            [Value("SHA384")]
            SHA384 = 1,

            [Value("SHA512")]
            SHA512 = 2
        }

        public enum KeyLengths : int
        {
            Two048 = 2048,
            Four096 = 4096,
            Eight192 = 8192,
            Sixteen384 = 16384
        }

        #endregion

        #region Methods
        public X509Certificate2 GenerateCertificate()
        {
            EnhancedUsages();
            KeyUsages();
            BasicConstraints();

            CX509CertificateRequestCertificate certReq = CreateRequest();
            certReq = FinalizeRequest(certReq);
            return CreateNewCertificate(certReq);
        }

        private void EnhancedUsages()
        {
            CObjectIds oids = new CObjectIds();
            foreach (string s in new string[2] { "Client Authentication", "Server Authentication" })
            {
                CObjectId oid = new CObjectId();
                Oid eu = Oid.FromFriendlyName(s, System.Security.Cryptography.OidGroup.EnhancedKeyUsage);
                oid.InitializeFromValue(eu.Value);
                oids.Add(oid);
            }
            CX509ExtensionEnhancedKeyUsage eku = new CX509ExtensionEnhancedKeyUsage();
            eku.InitializeEncode(oids);
            ExtensionsToAdd.Add((CX509Extension)eku);
        }

        private void KeyUsages()
        {
            CX509ExtensionKeyUsage ku = new CX509ExtensionKeyUsage();
            ku.InitializeEncode(CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE | CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE);
            ku.Critical = true;
            ExtensionsToAdd.Add((CX509Extension)ku);
        }

        private void BasicConstraints()
        {
            CX509ExtensionBasicConstraints bc = new CX509ExtensionBasicConstraints();
            bc.InitializeEncode(false, -1);
            bc.Critical = true;
            ExtensionsToAdd.Add((CX509Extension)bc);
        }

        private CX509CertificateRequestCertificate CreateRequest()
        {
            CX509PrivateKey pk = new CX509PrivateKey();
            pk.ProviderName = provName;
            CObjectId algId = new CObjectId();
            Oid algVal = Oid.FromFriendlyName("RSA", System.Security.Cryptography.OidGroup.PublicKeyAlgorithm);
            algId.InitializeFromValue(algVal.Value);
            pk.Algorithm = algId;
            pk.KeySpec = (X509KeySpec)2;
            pk.Length = KeyLength;
            pk.MachineContext = true;
            pk.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG;
            pk.Create();

            CX509CertificateRequestCertificate req = new CX509CertificateRequestCertificate();
            req.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextMachine, pk, String.Empty);
            return req;
        }

        private CX509CertificateRequestCertificate FinalizeRequest(CX509CertificateRequestCertificate cert)
        {
            CX500DistinguishedName subDN = new CX500DistinguishedName();
            subDN.Encode("CN=" + Environment.GetEnvironmentVariable("COMPUTERNAME"), X500NameFlags.XCN_CERT_NAME_STR_NONE);
            cert.Subject = subDN;
            cert.Issuer = cert.Subject;
            cert.NotBefore = DateTime.Now;
            cert.NotAfter = ValidUntil;
            foreach (CX509Extension e in ExtensionsToAdd)
            {
                cert.X509Extensions.Add(e);
            }
            CObjectId sigId = new CObjectId();
            Oid hash = Oid.FromFriendlyName(Algorithm, System.Security.Cryptography.OidGroup.HashAlgorithm);
            sigId.InitializeFromValue(hash.Value);
            cert.SignatureInformation.HashAlgorithm = sigId;

            // Complete it
            cert.Encode();
            ExtensionsToAdd.Clear();
            return cert;
        }

        private X509Certificate2 CreateNewCertificate(CX509CertificateRequestCertificate cert)
        {
            CX509Enrollment enr = new CX509Enrollment();
            enr.InitializeFromRequest(cert);
            enr.CertificateFriendlyName = "RDP Certificate";
            string endCert = enr.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);
            enr.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate, endCert, EncodingType.XCN_CRYPT_STRING_BASE64, String.Empty);

            byte[] certBytes = Convert.FromBase64String(endCert);
            return new X509Certificate2(certBytes);
        }

        private string GetValue(HashAlgorithm _e)
        {
            FieldInfo fi = _e.GetType().GetField(_e.ToString());
            ValueAttribute att = ((fi.GetCustomAttributes(typeof(ValueAttribute), false)) as ValueAttribute[])[0];
            return att.Value;
        }

        #endregion
    }
}
