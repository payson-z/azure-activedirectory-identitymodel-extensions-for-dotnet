//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    public class SignedInfo : ISecurityElement
    {
        readonly ExclusiveCanonicalizationTransform canonicalizationMethodElement = new ExclusiveCanonicalizationTransform(true);
        ElementWithAlgorithmAttribute signatureMethodElement;
        SignatureResourcePool resourcePool;
        DictionaryManager dictionaryManager;
        MemoryStream canonicalStream;
        ISignatureReaderProvider readerProvider;
        object signatureReaderProviderCallbackContext;
        bool sendSide = true;
        List<Reference> references;

        public SignedInfo(DictionaryManager dictionaryManager)
        {
            if (dictionaryManager == null)
                throw LogHelper.LogArgumentNullException(nameof(dictionaryManager));

            this.signatureMethodElement = new ElementWithAlgorithmAttribute(dictionaryManager.XmlSignatureDictionary.SignatureMethod);
            this.dictionaryManager = dictionaryManager;
            this.references = new List<Reference>();
            Prefix = SignedXml.DefaultPrefix;
        }

        protected DictionaryManager DictionaryManager
        {
            get { return this.dictionaryManager; }
        }

        protected MemoryStream CanonicalStream
        {
            get { return this.canonicalStream; }
            set { this.canonicalStream = value; }
        }

        protected bool SendSide
        {
            get { return this.sendSide; }
            set { this.sendSide = value; }
        }

        public void AddReference(Reference reference)
        {
            reference.ResourcePool = this.ResourcePool;
            this.references.Add(reference);
        }

        public ISignatureReaderProvider ReaderProvider
        {
            get { return this.readerProvider; }
            set { this.readerProvider = value; }
        }

        public object SignatureReaderProviderCallbackContext
        {
            get { return this.signatureReaderProviderCallbackContext; }
            set { this.signatureReaderProviderCallbackContext = value; }
        }

        public string CanonicalizationMethod
        {
            get { return this.canonicalizationMethodElement.Algorithm; }
            set
            {
                if (value != this.canonicalizationMethodElement.Algorithm)
                {
                    throw LogHelper.LogExceptionMessage(new NotSupportedException("UnsupportedTransformAlgorithm"));
                }
            }
        }

        public XmlDictionaryString CanonicalizationMethodDictionaryString
        {
            set
            {
                if (value != null && value.Value != this.canonicalizationMethodElement.Algorithm)
                {
                    throw LogHelper.LogExceptionMessage(new NotSupportedException("UnsupportedTransformAlgorithm"));
                }
            }
        }

        public bool HasId
        {
            get { return true; }
        }

        public string Id
        {
            get; set;
        }

        public virtual int ReferenceCount
        {
            get { return this.references.Count; }
        }

        public Reference this[int index]
        {
            get { return this.references[index]; }
        }

        public string SignatureMethod
        {
            get { return this.signatureMethodElement.Algorithm; }
            set { this.signatureMethodElement.Algorithm = value; }
        }

        public XmlDictionaryString SignatureMethodDictionaryString
        {
            get { return this.signatureMethodElement.AlgorithmDictionaryString; }
            set { this.signatureMethodElement.AlgorithmDictionaryString = value; }
        }

        public SignatureResourcePool ResourcePool
        {
            get
            {
                if (this.resourcePool == null)
                {
                    this.resourcePool = new SignatureResourcePool();
                }
                return this.resourcePool;
            }
            set
            {
                this.resourcePool = value;
            }
        }

        public void ComputeHash(HashAlgorithm algorithm)
        {
            if ((this.CanonicalizationMethod != SecurityAlgorithms.ExclusiveC14n) && (this.CanonicalizationMethod != SecurityAlgorithms.ExclusiveC14nWithComments))
            {
                throw LogHelper.LogExceptionMessage(new CryptographicException("UnsupportedTransformAlgorithm"));
            }
            HashStream hashStream = this.ResourcePool.TakeHashStream(algorithm);
            ComputeHash(hashStream);
            hashStream.FlushHash();
        }

        protected virtual void ComputeHash(HashStream hashStream)
        {
            if (this.sendSide)
            {
                XmlDictionaryWriter utf8Writer = this.ResourcePool.TakeUtf8Writer();
                utf8Writer.StartCanonicalization(hashStream, false, null);
                WriteTo(utf8Writer, this.dictionaryManager);
                utf8Writer.EndCanonicalization();
            }
            else if (this.canonicalStream != null)
            {
                this.canonicalStream.WriteTo(hashStream);
            }
            else
            {
                if (this.readerProvider == null)
                    throw LogHelper.LogExceptionMessage(new CryptographicException("InclusiveNamespacePrefixRequiresSignatureReader"));

                XmlDictionaryReader signatureReader = this.readerProvider.GetReader(this.signatureReaderProviderCallbackContext);

                if (!signatureReader.CanCanonicalize)
                {
                    MemoryStream stream = new MemoryStream();
                    XmlDictionaryWriter bufferingWriter = XmlDictionaryWriter.CreateBinaryWriter(stream, this.DictionaryManager.ParentDictionary);
                    string[] inclusivePrefix = GetInclusivePrefixes();
                    if (inclusivePrefix != null)
                    {
                        bufferingWriter.WriteStartElement("a");
                        for (int i = 0; i < inclusivePrefix.Length; ++i)
                        {
                            string ns = GetNamespaceForInclusivePrefix(inclusivePrefix[i]);
                            if (ns != null)
                            {
                                bufferingWriter.WriteXmlnsAttribute(inclusivePrefix[i], ns);
                            }
                        }
                    }
                    signatureReader.MoveToContent();
                    bufferingWriter.WriteNode(signatureReader, false);
                    if (inclusivePrefix != null)
                        bufferingWriter.WriteEndElement();
                    bufferingWriter.Flush();
                    byte[] buffer = stream.ToArray();
                    int bufferLength = (int)stream.Length;
                    bufferingWriter.Close();

                    signatureReader.Close();

                    // Create a reader around the buffering Stream.
                    signatureReader = XmlDictionaryReader.CreateBinaryReader(buffer, 0, bufferLength, this.DictionaryManager.ParentDictionary, XmlDictionaryReaderQuotas.Max);
                    if (inclusivePrefix != null)
                        signatureReader.ReadStartElement("a");
                }
                signatureReader.ReadStartElement(dictionaryManager.XmlSignatureDictionary.Signature, dictionaryManager.XmlSignatureDictionary.Namespace);
                signatureReader.MoveToStartElement(dictionaryManager.XmlSignatureDictionary.SignedInfo, dictionaryManager.XmlSignatureDictionary.Namespace);
                signatureReader.StartCanonicalization(hashStream, false, GetInclusivePrefixes());
                signatureReader.Skip();
                signatureReader.EndCanonicalization();
                signatureReader.Close();
            }
        }

        public virtual void ComputeReferenceDigests()
        {
            if (this.references.Count == 0)
            {
                throw LogHelper.LogExceptionMessage(new CryptographicException("AtLeastOneReferenceRequired"));
            }

            for (int i = 0; i < this.references.Count; i++)
            {
                this.references[i].ComputeAndSetDigest();
            }
        }


        public virtual void EnsureAllReferencesVerified()
        {
            for (int i = 0; i < this.references.Count; i++)
            {
                if (!this.references[i].Verified)
                {
                    throw LogHelper.LogExceptionMessage(new CryptographicException("UnableToResolveReferenceUriForSignature, this.references[i].Uri"));
                }
            }
        }

        protected string[] GetInclusivePrefixes()
        {
            return this.canonicalizationMethodElement.GetInclusivePrefixes();
        }

        protected virtual string GetNamespaceForInclusivePrefix(string prefix)
        {
            if (Context == null)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException());

            if (prefix == null)
                throw LogHelper.LogArgumentNullException(nameof(prefix));

            return Context[prefix];
        }

        public void EnsureDigestValidity(string id, object resolvedXmlSource)
        {
            if (!EnsureDigestValidityIfIdMatches(id, resolvedXmlSource))
            {
                throw LogHelper.LogExceptionMessage(new CryptographicException("RequiredTargetNotSigned, id"));
            }
        }

        public virtual bool EnsureDigestValidityIfIdMatches(string id, object resolvedXmlSource)
        {
            for (int i = 0; i < this.references.Count; i++)
            {
                if (this.references[i].EnsureDigestValidityIfIdMatches(id, resolvedXmlSource))
                {
                    return true;
                }
            }
            return false;
        }


        public virtual bool HasUnverifiedReference(string id)
        {
            for (int i = 0; i < this.references.Count; i++)
            {
                if (!this.references[i].Verified && this.references[i].ExtractReferredId() == id)
                {
                    return true;
                }
            }
            return false;
        }

        protected void ReadCanonicalizationMethod(XmlDictionaryReader reader, DictionaryManager dictionaryManager)
        {
            // we will ignore any comments in the SignedInfo elemnt when verifying signature
            this.canonicalizationMethodElement.ReadFrom(reader, dictionaryManager, false);
        }

        public virtual void ReadFrom(XmlDictionaryReader reader, TransformFactory transformFactory, DictionaryManager dictionaryManager)
        {
            this.SendSide = false;
            if (reader.CanCanonicalize)
            {
                this.CanonicalStream = new MemoryStream();
                reader.StartCanonicalization(this.CanonicalStream, false, null);
            }

            reader.MoveToStartElement(dictionaryManager.XmlSignatureDictionary.SignedInfo, dictionaryManager.XmlSignatureDictionary.Namespace);
            Prefix = reader.Prefix;
            Id = reader.GetAttribute(dictionaryManager.UtilityDictionary.IdAttribute, null);
            reader.Read();

            ReadCanonicalizationMethod(reader, dictionaryManager);
            ReadSignatureMethod(reader, dictionaryManager);
            while (reader.IsStartElement(dictionaryManager.XmlSignatureDictionary.Reference, dictionaryManager.XmlSignatureDictionary.Namespace))
            {
                Reference reference = new Reference(dictionaryManager);
                reference.ReadFrom(reader, transformFactory, dictionaryManager);
                AddReference(reference);
            }
            reader.ReadEndElement(); // SignedInfo

            if (reader.CanCanonicalize)
                reader.EndCanonicalization();

            string[] inclusivePrefixes = GetInclusivePrefixes();
            if (inclusivePrefixes != null)
            {
                // Clear the canonicalized stream. We cannot use this while inclusive prefixes are
                // specified.
                this.CanonicalStream = null;
                Context = new Dictionary<string, string>(inclusivePrefixes.Length);
                for (int i = 0; i < inclusivePrefixes.Length; i++)
                {
                    Context.Add(inclusivePrefixes[i], reader.LookupNamespace(inclusivePrefixes[i]));
                }
            }
        }

        public virtual void WriteTo(XmlDictionaryWriter writer, DictionaryManager dictionaryManager)
        {
            writer.WriteStartElement(Prefix, dictionaryManager.XmlSignatureDictionary.SignedInfo, dictionaryManager.XmlSignatureDictionary.Namespace);
            if (Id != null)
                writer.WriteAttributeString(dictionaryManager.UtilityDictionary.IdAttribute, null, Id);

            WriteCanonicalizationMethod(writer, dictionaryManager);
            WriteSignatureMethod(writer, dictionaryManager);
            foreach (var reference in references)
                reference.WriteTo(writer, dictionaryManager);

            writer.WriteEndElement(); // SignedInfo
        }

        protected void ReadSignatureMethod(XmlDictionaryReader reader, DictionaryManager dictionaryManager)
        {
            this.signatureMethodElement.ReadFrom(reader, dictionaryManager);
        }

        protected void WriteCanonicalizationMethod(XmlDictionaryWriter writer, DictionaryManager dictionaryManager)
        {
            this.canonicalizationMethodElement.WriteTo(writer, dictionaryManager);
        }

        protected void WriteSignatureMethod(XmlDictionaryWriter writer, DictionaryManager dictionaryManager)
        {
            this.signatureMethodElement.WriteTo(writer, dictionaryManager);
        }

        protected string Prefix
        {
            get; set;
        }

        protected Dictionary<string, string> Context
        {
            get; set;
        }
    }
}