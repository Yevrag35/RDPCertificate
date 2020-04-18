$code = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;

public class RDPCertificateResult
{
    private X509Certificate2[] _certs;
    private Exception[] _exs;
    private string _store;
    private string _thumb;

    public X509Certificate2[] Certificates { get { return _certs; } }
    public bool Exists { get { return _certs != null && _certs.Length > 0; } }
    public Exception[] Exceptions { get { return _exs; } }
    public bool IsFaulted { get { return _exs != null && _exs.Length > 0; } }
    public string PublishedThumbprint { get { return _thumb; } }
    public string StoreName { get { return _store; } }

    public RDPCertificateResult(PSObject pso)
    {
        foreach (PSPropertyInfo prop in pso.Properties)
        {
            if (prop.Name == "Certificates" && prop.Value != null)
            {
                this.SetCertificates(prop.Value);
            }
            else if (prop.Name == "PublishedThumbprint")
            {
                _thumb = prop.Value as string;
            }
            else if (prop.Name == "StoreName")
            {
                _store = prop.Value as string;
            }
            else if (prop.Name == "Exceptions")
            {
                if (prop.Value is IList list)
                {
                    _exs = new Exception[list.Count];
                    for (int i = 0; i < list.Count; i++)
                    {
                        _exs[i] = (Exception)list[i];
                    }
                }
                else
                {
                    _exs = new Exception[] { };
                }
            }
        }
    }

    private void SetCertificates(object propVal)
    {
        if (propVal is IList list)
        {
            _certs = new X509Certificate2[list.Count];
            for (int i1 = 0; i1 < list.Count; i1++)
            {
                _certs[i1] = (X509Certificate2)list[i1];
            }
        }
        else if (propVal is object[] objArr)
        {
            _certs = new X509Certificate2[objArr.Length];
            for (int i2 = 0; i2 < objArr.Length; i2++)
            {
                _certs[i2] = (X509Certificate2)objArr[i2];
            }
        }
    }
}

'@

Add-Type -TypeDefinition $code -Language CSharp -ErrorAction Stop