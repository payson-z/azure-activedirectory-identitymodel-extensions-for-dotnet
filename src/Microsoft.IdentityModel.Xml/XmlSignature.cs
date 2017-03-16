//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System.Xml;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    public class XmlSignature
    {
        SignedXml signedXml;
        string id;
        string prefix = SignedXml.DefaultPrefix;
        readonly SignatureValueElement signatureValueElement = new SignatureValueElement();
        readonly SignedInfo signedInfo;

        public XmlSignature(SignedXml signedXml, SignedInfo signedInfo)
        {
            this.signedXml = signedXml;
            this.signedInfo = signedInfo;
        }

        public SecurityKey Key
        {
            get;set;
        }

        public string Id
        {
            get { return this.id; }
            set { this.id = value; }
        }

        public SignedInfo SignedInfo
        {
            get { return this.signedInfo; }
        }

        public ISignatureValueSecurityElement SignatureValue
        {
            get { return this.signatureValueElement; }
        }

        public byte[] GetSignatureBytes()
        {
            return this.signatureValueElement.Value;
        }

        public void ReadFrom(XmlDictionaryReader reader, DictionaryManager dictionaryManager)
        {
            reader.MoveToStartElement(dictionaryManager.XmlSignatureDictionary.Signature, dictionaryManager.XmlSignatureDictionary.Namespace);
            this.prefix = reader.Prefix;
            this.Id = reader.GetAttribute(dictionaryManager.UtilityDictionary.IdAttribute, null);
            reader.Read();

            this.signedInfo.ReadFrom(reader, signedXml.TransformFactory, dictionaryManager);
            this.signatureValueElement.ReadFrom(reader, dictionaryManager);

            reader.ReadEndElement(); // Signature
        }

        public void SetSignatureValue(byte[] signatureValue)
        {
            this.signatureValueElement.Value = signatureValue;
        }

        public void WriteTo(XmlDictionaryWriter writer, DictionaryManager dictionaryManager)
        {
            writer.WriteStartElement(this.prefix, dictionaryManager.XmlSignatureDictionary.Signature, dictionaryManager.XmlSignatureDictionary.Namespace);
            if (this.id != null)
            {
                writer.WriteAttributeString(dictionaryManager.UtilityDictionary.IdAttribute, null, this.id);
            }
            this.signedInfo.WriteTo(writer, dictionaryManager);
            this.signatureValueElement.WriteTo(writer, dictionaryManager);

            writer.WriteEndElement(); // Signature
        }

        sealed class SignatureValueElement : ISignatureValueSecurityElement
        {
            string id;
            string prefix = SignedXml.DefaultPrefix;
            byte[] signatureValue;
            string signatureText;

            public bool HasId
            {
                get { return true; }
            }

            public string Id
            {
                get { return this.id; }
                set { this.id = value; }
            }

            internal byte[] Value
            {
                get { return this.signatureValue; }
                set
                {
                    this.signatureValue = value;
                    this.signatureText = null;
                }
            }

            public void ReadFrom(XmlDictionaryReader reader, DictionaryManager dictionaryManager)
            {
                reader.MoveToStartElement(dictionaryManager.XmlSignatureDictionary.SignatureValue, dictionaryManager.XmlSignatureDictionary.Namespace);
                this.prefix = reader.Prefix;
                this.Id = reader.GetAttribute(UtilityStrings.IdAttribute, null);
                reader.Read();

                this.signatureText = reader.ReadString();
                this.signatureValue = System.Convert.FromBase64String(signatureText.Trim());

                reader.ReadEndElement(); // SignatureValue
            }

            public void WriteTo(XmlDictionaryWriter writer, DictionaryManager dictionaryManager)
            {
                writer.WriteStartElement(this.prefix, dictionaryManager.XmlSignatureDictionary.SignatureValue, dictionaryManager.XmlSignatureDictionary.Namespace);
                if (this.id != null)
                {
                    writer.WriteAttributeString(dictionaryManager.UtilityDictionary.IdAttribute, null, this.id);
                }
                if (this.signatureText != null)
                {
                    writer.WriteString(this.signatureText);
                }
                else
                {
                    writer.WriteBase64(this.signatureValue, 0, this.signatureValue.Length);
                }
                writer.WriteEndElement(); // SignatureValue
            }

            byte[] ISignatureValueSecurityElement.GetSignatureValue()
            {
                return this.Value;
            }
        }
    }
}