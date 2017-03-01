//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System;
using System.IO;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    sealed class PreDigestedSignedInfo : SignedInfo
    {
        const int InitialReferenceArraySize = 8;
        bool addEnvelopedSignatureTransform;
        int count;
        string digestMethod;
        XmlDictionaryString digestMethodDictionaryString;
        ReferenceEntry[] references;

        public PreDigestedSignedInfo(DictionaryManager dictionaryManager)
            : base(dictionaryManager)
        {
            this.references = new ReferenceEntry[InitialReferenceArraySize];
        }

        public PreDigestedSignedInfo(DictionaryManager dictionaryManager, string canonicalizationMethod, XmlDictionaryString canonicalizationMethodDictionaryString, string digestMethod, XmlDictionaryString digestMethodDictionaryString, string signatureMethod, XmlDictionaryString signatureMethodDictionaryString)
            : base(dictionaryManager)
        {
            this.references = new ReferenceEntry[InitialReferenceArraySize];
            this.CanonicalizationMethod = canonicalizationMethod;
            this.CanonicalizationMethodDictionaryString = canonicalizationMethodDictionaryString;
            this.DigestMethod = digestMethod;
            this.digestMethodDictionaryString = digestMethodDictionaryString;
            this.SignatureMethod = signatureMethod;
            this.SignatureMethodDictionaryString = signatureMethodDictionaryString;
        }

        public bool AddEnvelopedSignatureTransform
        {
            get { return this.addEnvelopedSignatureTransform; }
            set { this.addEnvelopedSignatureTransform = value; }
        }

        public string DigestMethod
        {
            get { return this.digestMethod; }
            set { this.digestMethod = value; }
        }

        public override int ReferenceCount
        {
            get { return this.count; }
        }

        public void AddReference(string id, byte[] digest)
        {
            AddReference(id, digest, false);
        }

        public void AddReference(string id, byte[] digest, bool useStrTransform)
        {
            if (this.count == this.references.Length)
            {
                ReferenceEntry[] newReferences = new ReferenceEntry[this.references.Length * 2];
                Array.Copy(this.references, 0, newReferences, 0, this.count);
                this.references = newReferences;
            }
            this.references[this.count++].Set(id, digest, useStrTransform);
        }

        protected override void ComputeHash(HashStream hashStream)
        {
            if (this.AddEnvelopedSignatureTransform)
            {
                base.ComputeHash(hashStream);
            }
            else
            {
                SignedInfoCanonicalFormWriter.Instance.WriteSignedInfoCanonicalForm(
                    hashStream, this.SignatureMethod, this.DigestMethod,
                    this.references, this.count,
                    this.ResourcePool.TakeEncodingBuffer(), this.ResourcePool.TakeBase64Buffer());
            }
        }

        public override void ComputeReferenceDigests()
        {
            // all digests pre-computed
        }

        public override void ReadFrom(XmlDictionaryReader reader, TransformFactory transformFactory, DictionaryManager dictionaryManager)
        {
            // WriteOnly
            throw LogHelper.LogExceptionMessage(new NotSupportedException()); 
        }

        public override void EnsureAllReferencesVerified()
        {
            // WriteOnly
            throw LogHelper.LogExceptionMessage(new NotSupportedException());
        }

        public override bool EnsureDigestValidityIfIdMatches(string id, object resolvedXmlSource)
        {
            // WriteOnly
            throw LogHelper.LogExceptionMessage(new NotSupportedException());
        }

        public override void WriteTo(XmlDictionaryWriter writer, DictionaryManager dictionaryManager)
        {
            string prefix = XmlSignatureStrings.Prefix;
            XmlDictionaryString ns = dictionaryManager.XmlSignatureDictionary.Namespace;

            writer.WriteStartElement(prefix, dictionaryManager.XmlSignatureDictionary.SignedInfo, ns);
            if (this.Id != null)
            {
                writer.WriteAttributeString(dictionaryManager.UtilityDictionary.IdAttribute, null, this.Id);
            }
            WriteCanonicalizationMethod(writer, dictionaryManager);
            WriteSignatureMethod(writer, dictionaryManager);
            for (int i = 0; i < this.count; i++)
            {
                writer.WriteStartElement(prefix, dictionaryManager.XmlSignatureDictionary.Reference, ns);
                writer.WriteStartAttribute(dictionaryManager.XmlSignatureDictionary.URI, null);
                writer.WriteString("#");
                writer.WriteString(this.references[i].id);
                writer.WriteEndAttribute();

                writer.WriteStartElement(prefix, dictionaryManager.XmlSignatureDictionary.Transforms, ns);
                if (this.addEnvelopedSignatureTransform)
                {
                    writer.WriteStartElement(prefix, dictionaryManager.XmlSignatureDictionary.Transform, ns);
                    writer.WriteStartAttribute(dictionaryManager.XmlSignatureDictionary.Algorithm, null);
                    writer.WriteString(dictionaryManager.XmlSignatureDictionary.EnvelopedSignature);
                    writer.WriteEndAttribute();
                    writer.WriteEndElement(); // Transform
                }

                if (this.references[i].useStrTransform)
                {
                    writer.WriteStartElement(prefix, dictionaryManager.XmlSignatureDictionary.Transform, ns);
                    writer.WriteStartAttribute(dictionaryManager.XmlSignatureDictionary.Algorithm, null);
                    writer.WriteString(SecurityAlgorithms.StrTransform);
                    writer.WriteEndAttribute();
                    writer.WriteStartElement(XmlSignatureStrings.SecurityJan2004Prefix, XmlSignatureStrings.TransformationParameters, XmlSignatureStrings.SecurityJan2004Namespace);  //<wsse:TransformationParameters>
                    writer.WriteStartElement(prefix, dictionaryManager.XmlSignatureDictionary.CanonicalizationMethod, ns);
                    writer.WriteStartAttribute(dictionaryManager.XmlSignatureDictionary.Algorithm, null);
                    writer.WriteString(dictionaryManager.SecurityAlgorithmDictionary.ExclusiveC14n);
                    writer.WriteEndAttribute();
                    writer.WriteEndElement(); //CanonicalizationMethod 
                    writer.WriteEndElement(); // TransformationParameters
                    writer.WriteEndElement(); // Transform
                }
                else
                {
                    writer.WriteStartElement(prefix, dictionaryManager.XmlSignatureDictionary.Transform, ns);
                    writer.WriteStartAttribute(dictionaryManager.XmlSignatureDictionary.Algorithm, null);
                    writer.WriteString(dictionaryManager.SecurityAlgorithmDictionary.ExclusiveC14n);
                    writer.WriteEndAttribute();
                    writer.WriteEndElement(); // Transform
                }

                writer.WriteEndElement(); // Transforms

                writer.WriteStartElement(prefix, dictionaryManager.XmlSignatureDictionary.DigestMethod, ns);
                writer.WriteStartAttribute(dictionaryManager.XmlSignatureDictionary.Algorithm, null);
                if (this.digestMethodDictionaryString != null)
                {
                    writer.WriteString(this.digestMethodDictionaryString);
                }
                else
                {
                    writer.WriteString(this.digestMethod);
                }
                writer.WriteEndAttribute();
                writer.WriteEndElement(); // DigestMethod

                byte[] digest = this.references[i].digest;
                writer.WriteStartElement(prefix, dictionaryManager.XmlSignatureDictionary.DigestValue, ns);
                writer.WriteBase64(digest, 0, digest.Length);
                writer.WriteEndElement(); // DigestValue

                writer.WriteEndElement(); // Reference
            }
            writer.WriteEndElement(); // SignedInfo
        }


        struct ReferenceEntry
        {
            internal string id;
            internal byte[] digest;
            internal bool useStrTransform;

            public void Set(string id, byte[] digest, bool useStrTransform)
            {
                if (useStrTransform && string.IsNullOrEmpty(id))
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentNullException(id));
                }

                this.id = id;
                this.digest = digest;
                this.useStrTransform = useStrTransform;
            }
        }

        sealed class SignedInfoCanonicalFormWriter : CanonicalFormWriter
        {
            const string xml1 = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></CanonicalizationMethod><SignatureMethod Algorithm=\"";
            const string xml2 = "\"></SignatureMethod>";
            const string xml3 = "<Reference URI=\"#";
            const string xml4 = "\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform></Transforms><DigestMethod Algorithm=\"";
            const string xml4WithStrTransform = "\"><Transforms><Transform Algorithm=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform\"><o:TransformationParameters xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></CanonicalizationMethod></o:TransformationParameters></Transform></Transforms><DigestMethod Algorithm=\"";
            const string xml5 = "\"></DigestMethod><DigestValue>";
            const string xml6 = "</DigestValue></Reference>";
            const string xml7 = "</SignedInfo>";

            readonly byte[] fragment1;
            readonly byte[] fragment2;
            readonly byte[] fragment3;
            readonly byte[] fragment4;
            readonly byte[] fragment4StrTransform;
            readonly byte[] fragment5;
            readonly byte[] fragment6;
            readonly byte[] fragment7;
            readonly byte[] sha256Digest;
            readonly byte[] hmacSha2Signature;
            readonly byte[] rsaSha2Signature;

            static readonly SignedInfoCanonicalFormWriter instance = new SignedInfoCanonicalFormWriter();

            SignedInfoCanonicalFormWriter()
            {
                var encoding = Utf8WithoutPreamble;
                this.fragment1 = encoding.GetBytes(xml1);
                this.fragment2 = encoding.GetBytes(xml2);
                this.fragment3 = encoding.GetBytes(xml3);
                this.fragment4 = encoding.GetBytes(xml4);
                this.fragment4StrTransform = encoding.GetBytes(xml4WithStrTransform);
                this.fragment5 = encoding.GetBytes(xml5);
                this.fragment6 = encoding.GetBytes(xml6);
                this.fragment7 = encoding.GetBytes(xml7);
                this.sha256Digest = encoding.GetBytes(SecurityAlgorithms.Sha256Digest);
                this.hmacSha2Signature = encoding.GetBytes(SecurityAlgorithms.HmacSha256Signature);
                this.rsaSha2Signature = encoding.GetBytes(SecurityAlgorithms.RsaSha256Signature);
            }

            public static SignedInfoCanonicalFormWriter Instance
            {
                get { return instance; }
            }

            // optimization 
            byte[] EncodeDigestAlgorithm(string algorithm)
            {
                if (algorithm == SecurityAlgorithms.Sha256Digest)
                {
                    return this.sha256Digest;
                }
                else
                {
                    return Utf8WithoutPreamble.GetBytes(algorithm);
                }
            }

            byte[] EncodeSignatureAlgorithm(string algorithm)
            {
                if (algorithm == SecurityAlgorithms.HmacSha256Signature)
                {
                    return this.hmacSha2Signature;
                }
                else if (algorithm == SecurityAlgorithms.RsaSha256Signature)
                {
                    return this.rsaSha2Signature;
                }
                else
                {
                    return Utf8WithoutPreamble.GetBytes(algorithm);
                }
            }

            public void WriteSignedInfoCanonicalForm(
                Stream stream, string signatureMethod, string digestMethod,
                ReferenceEntry[] references, int referenceCount,
                byte[] workBuffer, char[] base64WorkBuffer)
            {
                stream.Write(this.fragment1, 0, this.fragment1.Length);
                byte[] signatureMethodBytes = EncodeSignatureAlgorithm(signatureMethod);
                stream.Write(signatureMethodBytes, 0, signatureMethodBytes.Length);
                stream.Write(this.fragment2, 0, this.fragment2.Length);

                byte[] digestMethodBytes = EncodeDigestAlgorithm(digestMethod);
                for (int i = 0; i < referenceCount; i++)
                {
                    stream.Write(this.fragment3, 0, this.fragment3.Length);
                    EncodeAndWrite(stream, workBuffer, references[i].id);
                    if (references[i].useStrTransform)
                    {
                        stream.Write(this.fragment4StrTransform, 0, this.fragment4StrTransform.Length);
                    }
                    else
                    {
                        stream.Write(this.fragment4, 0, this.fragment4.Length);
                    }

                    stream.Write(digestMethodBytes, 0, digestMethodBytes.Length);
                    stream.Write(this.fragment5, 0, this.fragment5.Length);
                    Base64EncodeAndWrite(stream, workBuffer, base64WorkBuffer, references[i].digest);
                    stream.Write(this.fragment6, 0, this.fragment6.Length);
                }

                stream.Write(this.fragment7, 0, this.fragment7.Length);
            }
        }
    }
}
