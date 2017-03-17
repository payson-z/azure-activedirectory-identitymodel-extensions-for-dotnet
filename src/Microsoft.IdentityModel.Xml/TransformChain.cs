//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System.Collections.Generic;
using System.Security.Cryptography;
using System.Xml;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    public class TransformChain
    {
        string prefix = SignedXml.DefaultPrefix;
        
        //MostlySingletonList<Transform> transforms;
        List<Transform> transforms = new List<Transform>();

        public TransformChain()
        {
        }

        public int TransformCount
        {
            get { return this.transforms.Count; }
        }

        public Transform this[int index]
        {
            get
            {
                return this.transforms[index];
            }
        }

        public bool NeedsInclusiveContext
        {
            get
            {
                for (int i = 0; i < this.TransformCount; i++)
                {
                    if (this[i].NeedsInclusiveContext)
                    {
                        return true;
                    }
                }
                return false;
            }
        }

        public void Add(Transform transform)
        {
            this.transforms.Add(transform);
        }

        public void ReadFrom(XmlDictionaryReader reader, TransformFactory transformFactory, DictionaryManager dictionaryManager, bool preserveComments)
        {
            reader.MoveToStartElement(dictionaryManager.XmlSignatureDictionary.Transforms, dictionaryManager.XmlSignatureDictionary.Namespace);
            this.prefix = reader.Prefix;
            reader.Read();

            while (reader.IsStartElement(dictionaryManager.XmlSignatureDictionary.Transform, dictionaryManager.XmlSignatureDictionary.Namespace))
            {
                string transformAlgorithmUri = reader.GetAttribute(dictionaryManager.XmlSignatureDictionary.Algorithm, null);
                Transform transform = transformFactory.CreateTransform(transformAlgorithmUri);
                transform.ReadFrom(reader, dictionaryManager, preserveComments);
                Add(transform);
            }
            reader.MoveToContent();
            reader.ReadEndElement(); // Transforms
            if (this.TransformCount == 0)
            {
                throw LogHelper.LogExceptionMessage(new CryptographicException("AtLeastOneTransformRequired"));
            }
        }

        public byte[] TransformToDigest(object data, SignatureResourcePool resourcePool, string digestMethod, DictionaryManager dictionaryManager)
        {
            for (int i = 0; i < this.TransformCount - 1; i++)
            {
                data = this[i].Process(data, resourcePool, dictionaryManager);
            }
            return this[this.TransformCount - 1].ProcessAndDigest(data, resourcePool, digestMethod, dictionaryManager);
        }

        public void WriteTo(XmlDictionaryWriter writer, DictionaryManager dictionaryManager)
        {
            writer.WriteStartElement(this.prefix, dictionaryManager.XmlSignatureDictionary.Transforms, dictionaryManager.XmlSignatureDictionary.Namespace);
            for (int i = 0; i < this.TransformCount; i++)
            {
                this[i].WriteTo(writer, dictionaryManager);
            }
            writer.WriteEndElement(); // Transforms
        }
    }
}