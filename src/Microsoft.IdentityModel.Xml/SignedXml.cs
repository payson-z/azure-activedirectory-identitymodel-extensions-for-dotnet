//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System.Security.Cryptography;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    public class SignedXml : ISignatureValueSecurityElement
    {
        internal const string DefaultPrefix = XmlSignatureStrings.Prefix;

        XmlSignature _signature;
        TransformFactory _transformFactory;
        DictionaryManager _dictionaryManager;

        public SignedXml(DictionaryManager dictionaryManager)
            : this(new StandardSignedInfo(dictionaryManager), dictionaryManager)
        {
        }

        public SignedXml(SignedInfo signedInfo, DictionaryManager dictionaryManager)
        {
            if (signedInfo == null)
                throw LogHelper.LogArgumentNullException(nameof(signedInfo));

            if (dictionaryManager == null)
                throw LogHelper.LogArgumentNullException(nameof(dictionaryManager));

            _transformFactory = TransformFactory.Instance;
            _signature = new XmlSignature(this, signedInfo);
            _dictionaryManager = dictionaryManager;
        }

        public bool HasId
        {
            get { return true; }
        }

        public string Id
        {
            get { return _signature.Id; }
            set { _signature.Id = value; }
        }

        public XmlSignature Signature
        {
            get { return _signature; }
        }

        public TransformFactory TransformFactory
        {
            get { return _transformFactory; }
            set { _transformFactory = value; }
        }

        public void ComputeSignature(SigningCredentials credentials)
        {
            // TODO - shouldn't need to create the hash algorithm.
            //var hash = credentials.CryptoProviderFactory.CreateHashAlgorithm(credentials.Algorithm);
            var hash = credentials.Key.CryptoProviderFactory.CreateHashAlgorithm(SecurityAlgorithms.Sha256);
            this.Signature.SignedInfo.ComputeReferenceDigests();
            this.Signature.SignedInfo.ComputeHash(hash);
            byte[] signature = hash.Hash;
            this.Signature.SetSignatureValue(signature);
        }

        void ComputeSignature(KeyedHashAlgorithm hash)
        {
            this.Signature.SignedInfo.ComputeReferenceDigests();
            this.Signature.SignedInfo.ComputeHash(hash);
            byte[] signature = hash.Hash;
            this.Signature.SetSignatureValue(signature);
        }

        public void ComputeSignature(SecurityKey signingKey)
        {
            // TODO SignatureFactory
            //string signatureMethod = this.Signature.SignedInfo.SignatureMethod;
            //SymmetricSecurityKey symmetricKey = signingKey as SymmetricSecurityKey;
            //if (symmetricKey != null)
            //{
            //    using (KeyedHashAlgorithm algorithm = symmetricKey.GetKeyedHashAlgorithm(signatureMethod))
            //    {
            //        if (algorithm == null)
            //        {
            //            throw LogHelper.LogExceptionMessage(new InvalidOperationException(
            //                SR.GetString(SR.UnableToCreateKeyedHashAlgorithm, symmetricKey, signatureMethod)));
            //        }
            //        ComputeSignature(algorithm);
            //    }
            //}
            //else
            //{
            //    AsymmetricSecurityKey asymmetricKey = signingKey as AsymmetricSecurityKey;
            //    if (asymmetricKey == null)
            //    {
            //        throw LogHelper.LogExceptionMessage(new InvalidOperationException(
            //            SR.GetString(SR.UnknownICryptoType, signingKey)));
            //    }
            //    using (HashAlgorithm hash = asymmetricKey.GetHashAlgorithmForSignature(signatureMethod))
            //    {
            //        if (hash == null)
            //        {
            //            throw LogHelper.LogExceptionMessage(new InvalidOperationException(
            //                SR.GetString(SR.UnableToCreateHashAlgorithmFromAsymmetricCrypto, signatureMethod, asymmetricKey)));
            //        }

            //        AsymmetricSignatureFormatter formatter = asymmetricKey.GetSignatureFormatter(signatureMethod);
            //        if (formatter == null)
            //        {
            //            throw LogHelper.LogExceptionMessage(new InvalidOperationException(
            //                SR.GetString(SR.UnableToCreateSignatureFormatterFromAsymmetricCrypto, signatureMethod, asymmetricKey)));
            //        }
            //        ComputeSignature(hash, formatter, signatureMethod);
            //    }
            //}
        }

        public void CompleteSignatureVerification()
        {
            this.Signature.SignedInfo.EnsureAllReferencesVerified();
        }

        public void EnsureDigestValidity(string id, object resolvedXmlSource)
        {
            this.Signature.SignedInfo.EnsureDigestValidity(id, resolvedXmlSource);
        }

        public bool EnsureDigestValidityIfIdMatches(string id, object resolvedXmlSource)
        {
            return this.Signature.SignedInfo.EnsureDigestValidityIfIdMatches(id, resolvedXmlSource);
        }

        public byte[] GetSignatureValue()
        {
            return this.Signature.GetSignatureBytes();
        }

        public void ReadFrom(XmlReader reader)
        {
            ReadFrom(XmlDictionaryReader.CreateDictionaryReader(reader));
        }

        public void ReadFrom(XmlDictionaryReader reader)
        {
            _signature.ReadFrom(reader, _dictionaryManager);
        }

        void VerifySignature(KeyedHashAlgorithm hash)
        {
            this.Signature.SignedInfo.ComputeHash(hash);
            if (!Utility.AreEqual(hash.Hash, GetSignatureValue()))
            {
                throw LogHelper.LogExceptionMessage(new CryptographicException("SignatureVerificationFailed"));
            }
        }

        public void StartSignatureVerification(SecurityKey verificationKey)
        {
            // TODO - use Signature
            //string signatureMethod = this.Signature.SignedInfo.SignatureMethod;
            //SymmetricSecurityKey symmetricKey = verificationKey as SymmetricSecurityKey;
            //if (symmetricKey != null)
            //{
            //    using (KeyedHashAlgorithm hash = symmetricKey.GetKeyedHashAlgorithm(signatureMethod))
            //    {
            //        if (hash == null)
            //        {
            //            throw LogHelper.LogExceptionMessage(new CryptographicException(
            //                SR.GetString(SR.UnableToCreateKeyedHashAlgorithmFromSymmetricCrypto, signatureMethod, symmetricKey)));
            //        }
            //        VerifySignature(hash);
            //    }
            //}
            //else
            //{
            //    AsymmetricSecurityKey asymmetricKey = verificationKey as AsymmetricSecurityKey;
            //    if (asymmetricKey == null)
            //    {
            //        throw LogHelper.LogExceptionMessage(new InvalidOperationException(SR.GetString(SR.UnknownICryptoType, verificationKey)));
            //    }
            //    using (HashAlgorithm hash = asymmetricKey.GetHashAlgorithmForSignature(signatureMethod))
            //    {
            //        if (hash == null)
            //        {
            //            throw LogHelper.LogExceptionMessage(new CryptographicException(
            //                SR.GetString(SR.UnableToCreateHashAlgorithmFromAsymmetricCrypto, signatureMethod, asymmetricKey)));
            //        }
            //        AsymmetricSignatureDeformatter deformatter = asymmetricKey.GetSignatureDeformatter(signatureMethod);
            //        if (deformatter == null)
            //        {
            //            throw LogHelper.LogExceptionMessage(new CryptographicException(
            //                SR.GetString(SR.UnableToCreateSignatureDeformatterFromAsymmetricCrypto, signatureMethod, asymmetricKey)));
            //        }

            //        VerifySignature(hash, deformatter, signatureMethod);
            //    }
            //}
        }

        public void WriteTo(XmlDictionaryWriter writer)
        {
            this.WriteTo(writer, _dictionaryManager);
        }

        public void WriteTo(XmlDictionaryWriter writer, DictionaryManager dictionaryManager)
        {
            _signature.WriteTo(writer, dictionaryManager);
        }
    }    
}