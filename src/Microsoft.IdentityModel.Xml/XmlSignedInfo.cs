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
    public abstract class SignedInfo : ISecurityElement
    {
        readonly ExclusiveCanonicalizationTransform canonicalizationMethodElement = new ExclusiveCanonicalizationTransform(true);
        string id;
        ElementWithAlgorithmAttribute signatureMethodElement;
        SignatureResourcePool resourcePool;
        DictionaryManager dictionaryManager;
        MemoryStream canonicalStream;
        ISignatureReaderProvider readerProvider;
        object signatureReaderProviderCallbackContext;
        bool sendSide = true;

        protected SignedInfo(DictionaryManager dictionaryManager)
        {
            if (dictionaryManager == null)
                throw LogHelper.LogArgumentNullException(nameof(dictionaryManager));

            this.signatureMethodElement = new ElementWithAlgorithmAttribute(dictionaryManager.XmlSignatureDictionary.SignatureMethod);
            this.dictionaryManager = dictionaryManager;
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
            get { return this.id; }
            set { this.id = value; }
        }

        public abstract int ReferenceCount
        {
            get;
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

        public abstract void ComputeReferenceDigests();

        protected string[] GetInclusivePrefixes()
        {
            return this.canonicalizationMethodElement.GetInclusivePrefixes();
        }

        protected virtual string GetNamespaceForInclusivePrefix(string prefix)
        {
            throw LogHelper.LogExceptionMessage(new NotSupportedException());
        }

        public abstract void EnsureAllReferencesVerified();

        public void EnsureDigestValidity(string id, object resolvedXmlSource)
        {
            if (!EnsureDigestValidityIfIdMatches(id, resolvedXmlSource))
            {
                throw LogHelper.LogExceptionMessage(new CryptographicException("RequiredTargetNotSigned, id"));
            }
        }

        public abstract bool EnsureDigestValidityIfIdMatches(string id, object resolvedXmlSource);

        public virtual bool HasUnverifiedReference(string id)
        {
            throw LogHelper.LogExceptionMessage(new NotSupportedException());
        }

        protected void ReadCanonicalizationMethod(XmlDictionaryReader reader, DictionaryManager dictionaryManager)
        {
            // we will ignore any comments in the SignedInfo elemnt when verifying signature
            this.canonicalizationMethodElement.ReadFrom(reader, dictionaryManager, false);
        }

        public abstract void ReadFrom(XmlDictionaryReader reader, TransformFactory transformFactory, DictionaryManager dictionaryManager);

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

        public abstract void WriteTo(XmlDictionaryWriter writer, DictionaryManager dictionaryManager);
    }

    // whitespace preservation convention: ws1 immediately inside open tag; ws2 immediately after end tag.
    public class StandardSignedInfo : SignedInfo
    {
        string prefix = SignedXml.DefaultPrefix;
        List<XmlReference> references;
        Dictionary<string, string> context;

        public StandardSignedInfo(DictionaryManager dictionaryManager)
            : base(dictionaryManager)
        {
            this.references = new List<XmlReference>();
        }

        public override int ReferenceCount
        {
            get { return this.references.Count; }
        }

        public XmlReference this[int index]
        {
            get { return this.references[index]; }
        }

        public void AddReference(XmlReference reference)
        {
            reference.ResourcePool = this.ResourcePool;
            this.references.Add(reference);
        }

        public override void EnsureAllReferencesVerified()
        {
            for (int i = 0; i < this.references.Count; i++)
            {
                if (!this.references[i].Verified)
                {
                    throw LogHelper.LogExceptionMessage(new CryptographicException("UnableToResolveReferenceUriForSignature, this.references[i].Uri"));
                }
            }
        }

        public override bool EnsureDigestValidityIfIdMatches(string id, object resolvedXmlSource)
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

        public override bool HasUnverifiedReference(string id)
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

        public override void ComputeReferenceDigests()
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

        public override void ReadFrom(XmlDictionaryReader reader, TransformFactory transformFactory, DictionaryManager dictionaryManager)
        {
            this.SendSide = false;
            if (reader.CanCanonicalize)
            {
                this.CanonicalStream = new MemoryStream();
                reader.StartCanonicalization(this.CanonicalStream, false, null);
            }

            reader.MoveToStartElement(dictionaryManager.XmlSignatureDictionary.SignedInfo, dictionaryManager.XmlSignatureDictionary.Namespace);
            this.prefix = reader.Prefix;
            this.Id = reader.GetAttribute(dictionaryManager.UtilityDictionary.IdAttribute, null);
            reader.Read();

            ReadCanonicalizationMethod(reader, dictionaryManager);
            ReadSignatureMethod(reader, dictionaryManager);
            while (reader.IsStartElement(dictionaryManager.XmlSignatureDictionary.Reference, dictionaryManager.XmlSignatureDictionary.Namespace))
            {
                XmlReference reference = new XmlReference(dictionaryManager);
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
                this.context = new Dictionary<string, string>(inclusivePrefixes.Length);
                for (int i = 0; i < inclusivePrefixes.Length; i++)
                {
                    this.context.Add(inclusivePrefixes[i], reader.LookupNamespace(inclusivePrefixes[i]));
                }
            }
        }

        public override void WriteTo(XmlDictionaryWriter writer, DictionaryManager dictionaryManager)
        {
            writer.WriteStartElement(this.prefix, dictionaryManager.XmlSignatureDictionary.SignedInfo, dictionaryManager.XmlSignatureDictionary.Namespace);
            if (this.Id != null)
            {
                writer.WriteAttributeString(dictionaryManager.UtilityDictionary.IdAttribute, null, this.Id);
            }
            WriteCanonicalizationMethod(writer, dictionaryManager);
            WriteSignatureMethod(writer, dictionaryManager);
            for (int i = 0; i < this.references.Count; i++)
            {
                this.references[i].WriteTo(writer, dictionaryManager);
            }
            writer.WriteEndElement(); // SignedInfo
        }

        protected override string GetNamespaceForInclusivePrefix(string prefix)
        {
            if (this.context == null)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException());

            if (prefix == null)
                throw LogHelper.LogArgumentNullException(nameof(prefix));

            return context[prefix];
        }

        protected string Prefix
        {
            get { return prefix; }
            set { prefix = value; }
        }

        protected Dictionary<string, string> Context
        {
            get { return context; }
            set { context = value; }
        }
    }

    sealed class WifSignedInfo : StandardSignedInfo, IDisposable
    {
        MemoryStream _bufferedStream;
        string _defaultNamespace = String.Empty;
        bool _disposed;

        public WifSignedInfo(DictionaryManager dictionaryManager)
            : base(dictionaryManager)
        {
        }

        ~WifSignedInfo()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                //
                // Free all of our managed resources
                //                
                if (_bufferedStream != null)
                {
                    _bufferedStream.Close();
                    _bufferedStream = null;
                }
            }

            // Free native resources, if any.

            _disposed = true;

        }

        protected override void ComputeHash(HashStream hashStream)
        {
            if (SendSide)
            {
                using (XmlDictionaryWriter utf8Writer = XmlDictionaryWriter.CreateTextWriter(Stream.Null, Encoding.UTF8, false))
                {
                    utf8Writer.StartCanonicalization(hashStream, false, null);
                    WriteTo(utf8Writer, DictionaryManager);
                    utf8Writer.EndCanonicalization();
                }
            }
            else if (CanonicalStream != null)
            {
                CanonicalStream.WriteTo(hashStream);
            }
            else
            {
                _bufferedStream.Position = 0;
                // We are creating a XmlDictionaryReader with a hard-coded Max XmlDictionaryReaderQuotas. This is a reader that we
                // are creating over an already buffered content. The content was initially read off user provided XmlDictionaryReader
                // with the correct quotas and hence we know the data is valid.
                // Note: signedinfoReader will close _bufferedStream on Dispose.
                using (XmlDictionaryReader signedinfoReader = XmlDictionaryReader.CreateTextReader(_bufferedStream, XmlDictionaryReaderQuotas.Max))
                {
                    signedinfoReader.MoveToContent();
                    using (XmlDictionaryWriter bufferingWriter = XmlDictionaryWriter.CreateTextWriter(Stream.Null, Encoding.UTF8, false))
                    {
                        bufferingWriter.WriteStartElement("a", _defaultNamespace);
                        string[] inclusivePrefix = GetInclusivePrefixes();
                        for (int i = 0; i < inclusivePrefix.Length; ++i)
                        {
                            string ns = GetNamespaceForInclusivePrefix(inclusivePrefix[i]);
                            if (ns != null)
                            {
                                bufferingWriter.WriteXmlnsAttribute(inclusivePrefix[i], ns);
                            }
                        }
                        bufferingWriter.StartCanonicalization(hashStream, false, inclusivePrefix);
                        bufferingWriter.WriteNode(signedinfoReader, false);
                        bufferingWriter.EndCanonicalization();
                        bufferingWriter.WriteEndElement();
                    }
                }
            }
        }

        public override void ReadFrom(XmlDictionaryReader reader, TransformFactory transformFactory, DictionaryManager dictionaryManager)
        {
            reader.MoveToStartElement(XmlSignatureConstants.Elements.SignedInfo, XmlSignatureConstants.Namespace);

            SendSide = false;
            _defaultNamespace = reader.LookupNamespace(String.Empty);
            _bufferedStream = new MemoryStream();


            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Encoding = Encoding.UTF8;
            settings.NewLineHandling = NewLineHandling.None;

            using (XmlWriter bufferWriter = XmlTextWriter.Create(_bufferedStream, settings))
            {
                bufferWriter.WriteNode(reader, true);
                bufferWriter.Flush();
            }

            _bufferedStream.Position = 0;

            //
            // We are creating a XmlDictionaryReader with a hard-coded Max XmlDictionaryReaderQuotas. This is a reader that we
            // are creating over an already buffered content. The content was initially read off user provided XmlDictionaryReader
            // with the correct quotas and hence we know the data is valid.
            // Note: effectiveReader will close _bufferedStream on Dispose.
            //
            using (XmlDictionaryReader effectiveReader = XmlDictionaryReader.CreateTextReader(_bufferedStream, XmlDictionaryReaderQuotas.Max))
            {
                CanonicalStream = new MemoryStream();
                effectiveReader.StartCanonicalization(CanonicalStream, false, null);

                effectiveReader.MoveToStartElement(XmlSignatureConstants.Elements.SignedInfo, XmlSignatureConstants.Namespace);
                Prefix = effectiveReader.Prefix;
                // TODO - need to use dictionary
                Id = effectiveReader.GetAttribute("Id", null);
                effectiveReader.Read();

                ReadCanonicalizationMethod(effectiveReader, DictionaryManager);
                ReadSignatureMethod(effectiveReader, DictionaryManager);
                while (effectiveReader.IsStartElement(XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Namespace))
                {
                    XmlReference reference = new XmlReference(DictionaryManager);
                    reference.ReadFrom(effectiveReader, transformFactory, DictionaryManager);
                    AddReference(reference);
                }
                effectiveReader.ReadEndElement();

                effectiveReader.EndCanonicalization();
            }

            string[] inclusivePrefixes = GetInclusivePrefixes();
            if (inclusivePrefixes != null)
            {
                // Clear the canonicalized stream. We cannot use this while inclusive prefixes are
                // specified.
                CanonicalStream = null;
                Context = new Dictionary<string, string>(inclusivePrefixes.Length);
                for (int i = 0; i < inclusivePrefixes.Length; i++)
                {
                    Context.Add(inclusivePrefixes[i], reader.LookupNamespace(inclusivePrefixes[i]));
                }
            }
        }
    }
}