//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;

namespace Microsoft.IdentityModel.Xml
{
    sealed class WifSignedInfo : SignedInfo, IDisposable
    {
        MemoryStream _bufferedStream;
        string _defaultNamespace = string.Empty;
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
            reader.MoveToStartElement(SignatureConstants.Elements.SignedInfo, SignatureConstants.Namespace);

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

                effectiveReader.MoveToStartElement(SignatureConstants.Elements.SignedInfo, SignatureConstants.Namespace);
                Prefix = effectiveReader.Prefix;
                // TODO - need to use dictionary
                Id = effectiveReader.GetAttribute("Id", null);
                effectiveReader.Read();

                ReadCanonicalizationMethod(effectiveReader, DictionaryManager);
                ReadSignatureMethod(effectiveReader, DictionaryManager);
                while (effectiveReader.IsStartElement(SignatureConstants.Elements.Reference, SignatureConstants.Namespace))
                {
                    Reference reference = new Reference(DictionaryManager);
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