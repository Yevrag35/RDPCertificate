using CERTCLILib;
using CERTENROLLLib;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MG.RDP.Certificates
{
    public class NewSignedCertificate
    {
        private protected const string provName = "Microsoft Enhanced RSA and AES Cryptographic Provider";
        private readonly string[] EnhancedUsages = new string[1] { "Server Authentication" };

        private protected const int CC_DEFAULTCONFIG = 0;
        private protected const int CC_UIPICKCONFIG = 0x1;
        private protected const int CR_IN_BASE64 = 0x1;
        private protected const int CR_IN_FORMATANY = 0;
        private protected const int CR_IN_PKCS10 = 0x100;
        private protected const int CR_DISP_ISSUED = 0x3;
        private protected const int CR_DISP_UNDER_SUBMISSION = 0x5;
        private protected const int CR_OUT_BASE64 = 0x1;
        private protected const int CR_OUT_CHAIN = 0x100;

        public NewSignedCertificate() { }

        public string CreateRequest()
        {
            // Create all the objects that will be required
            var objPkcs10 = new CX509CertificateRequestPkcs10();
            var objPrivKey = new CX509PrivateKey();
            var objCSP = new CCspInformation();
            var objCSPs = new CCspInformations();
            var objDN = new CX500DistinguishedName();
            var objEnroll = new CX509Enrollment();
            var objObjIds = new CObjectIds();
            var objObjId = new CObjectId();
            var objExtKeyUsage = new CX509ExtensionKeyUsage();
            var objExtEnhKeyUsage = new CX509ExtensionEnhancedKeyUsage();
            string strRequest;

            //objCSP.InitializeFromName(provName);
            //objCSPs.Add(objCSP);

            //objPrivKey.Length = 2048;
            //objPrivKey.KeySpec = X509KeySpec.XCN_AT_KEYEXCHANGE;
            //objPrivKey.KeyUsage = X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_ALL_USAGES;
            //objPrivKey.MachineContext = true;

            //objPrivKey.CspInformations = objCSPs;
            //objPrivKey.Create();

            var strTemplateName = "1.3.6.1.4.1.311.21.8.12017375.10856495.934812.8687423.15807460.10.5731641.6795722"; // RDP All Names
            objPkcs10.InitializeFromTemplateName(X509CertificateEnrollmentContext.ContextMachine, strTemplateName);

            // Encode the name in using the DN object
            objDN.Encode("CN=" + Environment.GetEnvironmentVariable("COMPUTERNAME"),
                X500NameFlags.XCN_CERT_NAME_STR_NONE);

            // Adding the subject name by using the DN object initialized above
            objPkcs10.Subject = objDN;

            var dnsDom = Environment.GetEnvironmentVariable("USERDNSDOMAIN").ToLower();
            var altName = new CAlternativeName();
            var objAlternateNames = new CAlternativeNames();
            var objExtAltNames = new CX509ExtensionAlternativeNames();
            altName.InitializeFromString(AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME,
                Environment.GetEnvironmentVariable("COMPUTERNAME") + "." + dnsDom);
            var altName2 = new CAlternativeName();
            altName2.InitializeFromString(AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME,
                Environment.GetEnvironmentVariable("COMPUTERNAME"));


            objAlternateNames.Add(altName2);
            objAlternateNames.Add(altName);
            objExtAltNames.InitializeEncode(objAlternateNames);
            objPkcs10.X509Extensions.Add((CX509Extension)objExtAltNames);

            // Create the enrollment request
            objEnroll.InitializeFromRequest(objPkcs10);
            strRequest = objEnroll.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);

            return strRequest;
        }

        public string SendRequestToCA(string certRequest)
        {
            // Create objects
            var certConfig = new CCertConfig();
            var objCertRequest = new CCertRequest();
            var caConfig = certConfig.GetConfig(CC_DEFAULTCONFIG);

            // Submit the request

            var iDisposition = objCertRequest.Submit(
                CR_IN_BASE64 | CR_IN_FORMATANY,
                certRequest,
                null,
                caConfig
            );

            // Check the submission status
            if (CR_DISP_ISSUED != iDisposition)  // Not enrolled
            {
                var strDis = objCertRequest.GetDispositionMessage();
                Console.WriteLine(strDis);
            }

            // Get the certificate
            var strCert = objCertRequest.GetCertificate(CR_OUT_BASE64 | CR_OUT_CHAIN);
            return strCert;
        }

        public void InstallResponse(string strCert, string strRequest)
        {
            // Create Objects
            var objEnroll = new CX509Enrollment();

            // Install the cert
            objEnroll.Initialize(X509CertificateEnrollmentContext.ContextMachine);
            objEnroll.InstallResponse(InstallResponseRestrictionFlags.AllowNone,
                strCert, EncodingType.XCN_CRYPT_STRING_BASE64, null);
        }
    }
}
