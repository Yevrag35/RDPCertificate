using CERTENROLLLib;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MG.RDP.Certificates
{
    public class NewCertificate
    {
        private const string provName = "Microsoft Enhanced RSA and AES Cryptographic Provider";
        private readonly string[] EnhancedUsages = new string[1] { "Server Authentication" };

        private List<CX509Extension> ExtensionsToAdd;

        public NewCertificate() { }

        #region Constructors
        public X509Certificate2 GenerateNewCert(string subject, string friendlyName, DateTime validUntil,
            Algorithm hash, int keyLength)
        {
            if (ExtensionsToAdd == null)
                ExtensionsToAdd = new List<CX509Extension>();

            SetEnhancedUsages();
            SetKeyUsages();
            SetBasicConstraints();

            CX509CertificateRequestCertificate certReq = CreateRequest((KeyLengths)keyLength);
            certReq = FinalizeRequest(certReq, subject, validUntil, hash);
            X509Certificate2 cert = CreateNewCertificate(certReq, friendlyName);
            ExtensionsToAdd.Clear();
            return cert;
        }

        #endregion

        #region Methods

        private void SetEnhancedUsages()
        {
            var oids = new CObjectIds();

            for (int i = 0; i < EnhancedUsages.Length; i++)
            {
                var s = EnhancedUsages[i];
                var oid = new CObjectId();
                var eu = Oid.FromFriendlyName(s, OidGroup.EnhancedKeyUsage);
                oid.InitializeFromValue(eu.Value);
                oids.Add(oid);
            }
            var eku = new CX509ExtensionEnhancedKeyUsage();
            eku.InitializeEncode(oids);
            ExtensionsToAdd.Add((CX509Extension)eku);
        }

        private void SetKeyUsages()
        {
            var ku = new CX509ExtensionKeyUsage
            {
                Critical = false
            };
            ku.InitializeEncode(
                CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE |
                CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE);
            ExtensionsToAdd.Add((CX509Extension)ku);
        }

        private void SetBasicConstraints()
        {
            var bc = new CX509ExtensionBasicConstraints();
            bc.InitializeEncode(false, -1);
            bc.Critical = true;
            ExtensionsToAdd.Add((CX509Extension)bc);
        }

        private CX509CertificateRequestCertificate CreateRequest(KeyLengths keyLength)
        {
            var pk = new CX509PrivateKey
            {
                ProviderName = provName
            };
            var algId = new CObjectId();
            var algVal = Oid.FromFriendlyName("RSA", OidGroup.PublicKeyAlgorithm);
            algId.InitializeFromValue(algVal.Value);
            pk.Algorithm = algId;
            pk.KeySpec = X509KeySpec.XCN_AT_KEYEXCHANGE;    // If this value is anything other KEYEXCHANGE, the certificate cannot be used for decrypting content.
            pk.Length = (int)keyLength;
            pk.MachineContext = true;
            pk.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_NONE;
            pk.Create();

            var req = new CX509CertificateRequestCertificate();
            var useCtx = (X509CertificateEnrollmentContext)StoreLocation.LocalMachine;
            req.InitializeFromPrivateKey(useCtx, pk, string.Empty);
            return req;
        }

        private CX509CertificateRequestCertificate FinalizeRequest(CX509CertificateRequestCertificate cert,
            string subjectName, DateTime validUntil, Algorithm algorithm)
        {
            var subDN = new CX500DistinguishedName();
            subDN.Encode("CN=" + subjectName, X500NameFlags.XCN_CERT_NAME_STR_NONE);
            cert.Subject = subDN;
            cert.Issuer = cert.Subject;
            cert.NotBefore = DateTime.Now;
            cert.NotAfter = validUntil;
            for (int i = 0; i < ExtensionsToAdd.Count; i++)
            {
                var ext = ExtensionsToAdd[i];
                cert.X509Extensions.Add(ext);
            }
            var sigId = new CObjectId();
            var hash = Oid.FromFriendlyName(algorithm.ToString(), OidGroup.HashAlgorithm);
            sigId.InitializeFromValue(hash.Value);
            cert.SignatureInformation.HashAlgorithm = sigId;

            // Complete it
            cert.Encode();
            ExtensionsToAdd.Clear();
            return cert;
        }

        private X509Certificate2 CreateNewCertificate(CX509CertificateRequestCertificate cert, string friendlyName)
        {
            var enr = new CX509Enrollment
            {
                CertificateFriendlyName = friendlyName
            };
            enr.InitializeFromRequest(cert);
            string endCert = enr.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);
            enr.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate, endCert, EncodingType.XCN_CRYPT_STRING_BASE64, string.Empty);

            byte[] certBytes = Convert.FromBase64String(endCert);
            return new X509Certificate2(certBytes);
        }

        #endregion
    }

    #region Enums
    public enum Algorithm : int
    {
        SHA256 = 0,
        SHA384 = 1,
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
}
