//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.IdentityModel.Tokens.Saml
{
    using System.Xml;

    public interface ISignatureValueSecurityElement : ISecurityElement
    {
        byte[] GetSignatureValue();
    }
}
