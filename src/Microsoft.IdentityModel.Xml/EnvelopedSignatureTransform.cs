//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System;
using System.Security.Cryptography;
using System.Xml;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    sealed class EnvelopedSignatureTransform : Transform
    {
        string prefix = XmlSignatureStrings.Prefix;

        public EnvelopedSignatureTransform()
        {
        }

        public override string Algorithm
        {
            get { return XD.XmlSignatureDictionary.EnvelopedSignature.Value; }
        }

        public override object Process(object input, SignatureResourcePool resourcePool, DictionaryManager dictionaryManager)
        {
            XmlTokenStream tokenStream = input as XmlTokenStream;
            if (tokenStream != null)
            {
                tokenStream.SetElementExclusion(XmlSignatureStrings.Signature, XmlSignatureStrings.Namespace);
                return tokenStream;
            }

            WrappedReader reader = input as WrappedReader;
            if ( reader != null )
            {
                // The Enveloped Signature Transform is supposed to remove the
                // Signature which encloses the transform element. Previous versions
                // of this code stripped out all Signature elements at any depth, 
                // which did not allow nested signed structures. By specifying '1' 
                // as the depth, we narrow our range of support so that we require
                // that the enveloped signature be a direct child of the element
                // being signed.
                reader.XmlTokens.SetElementExclusion( SignatureConstants.Elements.Signature, SignatureConstants.Namespace, 1 );
                return reader;
            }

            throw LogHelper.LogExceptionMessage(new NotSupportedException("UnsupportedInputTypeForTransform, input.GetType()"));
        }

        // this transform is not allowed as the last one in a chain
        public override byte[] ProcessAndDigest(object input, SignatureResourcePool resourcePool, string digestAlgorithm, DictionaryManager dictionaryManager)
        {
            throw LogHelper.LogExceptionMessage(new NotSupportedException("UnsupportedLastTransform"));
        }

        public override void ReadFrom(XmlDictionaryReader reader, DictionaryManager dictionaryManager, bool preserveComments)
        {
            reader.MoveToContent();
            string algorithm = Util.ReadEmptyElementAndRequiredAttribute(reader,
                dictionaryManager.XmlSignatureDictionary.Transform, dictionaryManager.XmlSignatureDictionary.Namespace, dictionaryManager.XmlSignatureDictionary.Algorithm, out this.prefix);
            if (algorithm != this.Algorithm)
            {
                throw LogHelper.LogExceptionMessage(new CryptographicException("AlgorithmMismatchForTransform"));
            }
        }

        public override void WriteTo(XmlDictionaryWriter writer, DictionaryManager dictionaryManager)
        {
            writer.WriteStartElement(this.prefix, dictionaryManager.XmlSignatureDictionary.Transform, dictionaryManager.XmlSignatureDictionary.Namespace);
            writer.WriteAttributeString(dictionaryManager.XmlSignatureDictionary.Algorithm, null, this.Algorithm);
            writer.WriteEndElement(); // Transform
        }
    }
}
