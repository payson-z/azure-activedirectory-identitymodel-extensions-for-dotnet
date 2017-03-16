//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    struct ElementWithAlgorithmAttribute
    {
        readonly XmlDictionaryString elementName;
        string algorithm;
        XmlDictionaryString algorithmDictionaryString;
        string prefix;

        public ElementWithAlgorithmAttribute(XmlDictionaryString elementName)
        {
            if (elementName == null)
            {
                throw LogHelper.LogArgumentNullException(nameof(elementName));
            }
            this.elementName = elementName;
            this.algorithm = null;
            this.algorithmDictionaryString = null;
            this.prefix = SignedXml.DefaultPrefix;
        }

        public string Algorithm
        {
            get { return this.algorithm; }
            set { this.algorithm = value; }
        }

        public XmlDictionaryString AlgorithmDictionaryString
        {
            get { return this.algorithmDictionaryString; }
            set { this.algorithmDictionaryString = value; }
        }

        public void ReadFrom(XmlDictionaryReader reader, DictionaryManager dictionaryManager)
        {
            reader.MoveToStartElement(this.elementName, dictionaryManager.XmlSignatureDictionary.Namespace);
            this.prefix = reader.Prefix;
            bool isEmptyElement = reader.IsEmptyElement;
            this.algorithm = reader.GetAttribute(dictionaryManager.XmlSignatureDictionary.Algorithm, null);
            if (this.algorithm == null)
            {
                throw LogHelper.LogExceptionMessage(new CryptographicException(
                    "RequiredAttributeMissing, dictionaryManager.XmlSignatureDictionary.Algorithm, this.elementName"));
            }
            reader.Read();
            reader.MoveToContent();

            if (!isEmptyElement)
            {
                reader.MoveToContent();
                reader.ReadEndElement();
            }
        }

        public void WriteTo(XmlDictionaryWriter writer, DictionaryManager dictionaryManager)
        {
            writer.WriteStartElement(this.prefix, this.elementName, dictionaryManager.XmlSignatureDictionary.Namespace);
            writer.WriteStartAttribute(dictionaryManager.XmlSignatureDictionary.Algorithm, null);
            if (this.algorithmDictionaryString != null)
            {
                writer.WriteString(this.algorithmDictionaryString);
            }
            else
            {
                writer.WriteString(this.algorithm);
            }
            writer.WriteEndAttribute();
            writer.WriteEndElement();
        }
    }
}