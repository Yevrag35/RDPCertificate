using Microsoft.Management.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;

namespace RDPCertificate
{
    public static class CimStuff
    {
        private const string ns = @"root\cimv2\TerminalServices";
        private const string dia = "WQL";
        private const string query = "SELECT * FROM Win32_TSGeneralSetting WHERE TerminalName = 'RDP-Tcp'";
        private const string pc = "localhost";
        private const string p = "SSLCertificateSHA1Hash";

        public static bool IsCurrentInstalled(CimSession ses)
        {
            CimInstance c = GetCimInstance(ses);
            CimProperty cimProp = c.CimInstanceProperties[p];
            if (cimProp != null && cimProp.Value != null)
            {
                return !cimProp.Value.Equals(String.Empty);
            }
            return false;
        }

        public static CimInstance GetCimInstance(CimSession ses)
        {
            return ses.QueryInstances(ns, dia, query).ToArray()[0];
        }

        public static void SetCertificate(CimSession ses, string SHA1Thumbrpint)
        {
            CimInstance c = GetCimInstance(ses);
            CimProperty prop = c.CimInstanceProperties[p];
            prop.Value = SHA1Thumbrpint;
            ses.ModifyInstance(c);
        }
    }
}
