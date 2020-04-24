$code = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;

public class RDPCertificateResult
{
    private X509Certificate2 _cert;
    private string _computer;
    private ReadOnlyCollection<Exception> _exs;
    private string _store;
    private string _thumb;

    public X509Certificate2 Certificate { get { return _cert; } }
    public string ComputerName { get { return _computer; } }
    public bool Exists { get { return _cert != null; } }
    public ReadOnlyCollection<Exception> Exceptions { get { return _exs; } }
    public bool IsFaulted { get { return _exs != null && _exs.Count > 0; } }
    public string PublishedThumbprint { get { return _thumb; } }
    public string StoreName { get { return _store; } }

    public static IEnumerable<RDPCertificateResult> FromObjects(params PSObject[] objs)
    {
        if (objs == null)
        {
            yield break;
        }

        foreach (PSObject pso in objs)
        {
            yield return new RDPCertificateResult(pso);
        }
    }

    private RDPCertificateResult(PSObject pso)
    {
        foreach (PSPropertyInfo prop in pso.Properties)
        {
            if (prop.Name == "Certificate" && prop.Value != null)
            {
                PSObject certPso = prop.Value as PSObject;
                if (certPso != null)
                {
                    _cert = (X509Certificate2)certPso.ImmediateBaseObject;
                }
                else
                {
                    _cert = (X509Certificate2)prop.Value;
                }
            }
            else if (prop.Name == "ComputerName")
            {
                _computer = prop.Value as string;
            }
            else if (prop.Name == "PublishedThumbprint")
            {
                _thumb = prop.Value as string;
            }
            else if (prop.Name == "StoreName")
            {
                _store = prop.Value as string;
            }
            else if (prop.Name == "Exceptions" && prop.Value != null)
            {
                List<Exception> list = new List<Exception>();
                IEnumerable excps = prop.Value as IEnumerable;
                if (excps != null)
                {
                    list.AddRange(excps.OfType<Exception>());
                }
                _exs = list.AsReadOnly();
                if (list.Count > 0)
                {
                    list.Clear();
                }
            }
        }
    }
}

'@

Add-Type -TypeDefinition $code -Language CSharp -ErrorAction Stop