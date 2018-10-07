using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Reflection;
using System.Security;
using System.Text;

namespace RDPCertificate
{
    internal static class CimStuff
    {

        private const string ns = @"root\cimv2\TerminalServices";
        private const string dia = "WQL";
        private const string query = "SELECT * FROM Win32_TSGeneralSetting WHERE TerminalName = 'RDP-Tcp'";
        private const string pc = "localhost";
        private const string p = "SSLCertificateSHA1Hash";

        internal static CimSession MakeCimSession(string machineName, AuthOptions authentication = AuthOptions.Passthrough, PSCredential creds = null)
        {
            if (machineName != pc)
            {
                object[] newObjs;
                CimSessionOptions wsMan = new CimSessionOptions();
                object matchAuth = MatchAuth(authentication);
                if (matchAuth.GetType() == typeof(ImpersonatedAuthenticationMechanism))
                {
                    newObjs = new object[1] { (ImpersonatedAuthenticationMechanism)matchAuth };
                }
                else
                {
                    PasswordAuthenticationMechanism newAuth = (PasswordAuthenticationMechanism)matchAuth;
                    newObjs = new object[4]
                    {
                        newAuth, String.Empty, creds.UserName, creds.Password
                    };
                }
                Type methodType = typeof(CimCredential);
                CimCredential cimCreds = (CimCredential)Activator.CreateInstance(methodType, newObjs);
                wsMan.AddDestinationCredentials(cimCreds);
                wsMan.SetCustomOption("Protocol", CimCmdlets.
                CimSession ses = CimSession.Create(machineName, wsMan);
                return ses;
            }
            else
            {
                CimSession ses = CimSession.Create(pc);
                return ses;
            }
        }

        internal static object MatchAuth(AuthOptions opt)
        {
            switch (opt)
            {
                case AuthOptions.Passthrough:
                    return ImpersonatedAuthenticationMechanism.Negotiate;
                case AuthOptions.Negotiate:
                    return PasswordAuthenticationMechanism.Negotiate;
                case AuthOptions.Kerberos:
                    return PasswordAuthenticationMechanism.Kerberos;
                case AuthOptions.CredSSP:
                    return PasswordAuthenticationMechanism.CredSsp;
                default:
                    return ImpersonatedAuthenticationMechanism.Negotiate;
            }
        }

        internal static T Cast<T>(Enum e)
        {
            return (T)Convert.ChangeType(e, typeof(T));
        }

        internal static bool IsCurrentInstalled(CimSession ses)
        {
            CimInstance c = GetCimInstance(ses);
            CimProperty cimProp = c.CimInstanceProperties[p];
            if (cimProp != null && cimProp.Value != null)
            {
                return !cimProp.Value.Equals(String.Empty);
            }
            return false;
        }

        internal static CimInstance GetCimInstance(CimSession ses)
        {
            return ses.QueryInstances(ns, dia, query).ToArray()[0];
        }

        internal static void SetCertificate(CimSession ses, string SHA1Thumbrpint)
        {
            CimInstance c = GetCimInstance(ses);
            CimProperty prop = c.CimInstanceProperties[p];
            prop.Value = SHA1Thumbrpint;
            ses.ModifyInstance(c);
        }
    }

    public enum AuthOptions : int
    {
        Passthrough = 0,
        Kerberos = 1,
        Negotiate = 2,
        CredSSP = 3
    }
}
