//-----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//-----------------------------------------------------------------------------

namespace Microsoft.IdentityModel.Tokens.Saml
{
    using System.Runtime.Serialization;

    //TODO - why is this an enum and DC?
    [DataContract]
    public enum SamlAccessDecision
    {
        [EnumMember]
        Permit,
        [EnumMember]
        Deny,
        [EnumMember]
        Indeterminate
    }
}
