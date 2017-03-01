//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    public class TransformFactory
    {
        static TransformFactory instance = new TransformFactory();

        protected TransformFactory() { }

        internal static TransformFactory Instance
        {
            get { return instance; }
        }

        public virtual Transform CreateTransform(string transform)
        {
            if (transform == SecurityAlgorithms.ExclusiveC14n)
            {
                return new ExclusiveCanonicalizationTransform();
            }
            else if (transform == SecurityAlgorithms.ExclusiveC14nWithComments)
            {
                return new ExclusiveCanonicalizationTransform(false, true);
            }
            else if (transform == SecurityAlgorithms.StrTransform)
            {
                return new StrTransform();
            }
            else if (transform == SecurityAlgorithms.EnvelopedSignature)
            {
                return new EnvelopedSignatureTransform();
            }            
            else
            {
                throw LogHelper.LogExceptionMessage(new CryptographicException("UnsupportedTransformAlgorithm"));
            }
        }
    }
}
