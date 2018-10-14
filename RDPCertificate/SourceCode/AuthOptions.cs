using MG.Attributes;
using Microsoft.Management.Infrastructure.Options;
using System;

namespace MG.RDP
{
    public enum AuthOptions
    {
        [Auth(ImpersonatedAuthenticationMechanism.Negotiate)]
        Passthrough = 0,

        [Auth(ImpersonatedAuthenticationMechanism.Kerberos)]
        Kerberos = 1,

        [Auth(PasswordAuthenticationMechanism.CredSsp)]
        CredSSP = 2
    }

    internal class AuthAttribute : MGAbstractAttribute
    {
        public AuthAttribute(object mech)
            : base(mech)
        {
        }
    }
}
