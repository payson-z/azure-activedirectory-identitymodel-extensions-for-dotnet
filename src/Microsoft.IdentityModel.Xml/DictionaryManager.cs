//-----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//-----------------------------------------------------------------------------

using System;
using System.Xml;

namespace Microsoft.IdentityModel.Xml
{

    public class DictionaryManager
    {
        SamlDictionary samlDictionary;
        XmlSignatureDictionary sigantureDictionary;
        UtilityDictionary utilityDictionary;
        ExclusiveC14NDictionary exclusiveC14NDictionary;
        SecurityAlgorithmDictionary securityAlgorithmDictionary;
        XmlEncryptionDictionary xmlEncryptionDictionary;
        IXmlDictionary parentDictionary;

        public DictionaryManager()
        {
            this.samlDictionary = XD.SamlDictionary;
            this.sigantureDictionary = XD.XmlSignatureDictionary;
            this.utilityDictionary = XD.UtilityDictionary;
            this.exclusiveC14NDictionary = XD.ExclusiveC14NDictionary;
            this.securityAlgorithmDictionary = XD.SecurityAlgorithmDictionary;
            this.parentDictionary = XD.Dictionary;
            this.xmlEncryptionDictionary = XD.XmlEncryptionDictionary;
        }

        public DictionaryManager(IXmlDictionary parentDictionary)
        {
            this.samlDictionary = new SamlDictionary(parentDictionary);
            this.sigantureDictionary = new XmlSignatureDictionary(parentDictionary);
            this.utilityDictionary = new UtilityDictionary(parentDictionary);
            this.exclusiveC14NDictionary = new ExclusiveC14NDictionary(parentDictionary);
            this.securityAlgorithmDictionary = new SecurityAlgorithmDictionary(parentDictionary);
            this.xmlEncryptionDictionary = new XmlEncryptionDictionary(parentDictionary);
            this.parentDictionary = parentDictionary;
        }

        public SamlDictionary SamlDictionary
        {
            get { return this.samlDictionary; }
            set { this.samlDictionary = value; }
        }

        public XmlSignatureDictionary XmlSignatureDictionary
        {
            get { return this.sigantureDictionary; }
            set { this.sigantureDictionary = value; }
        }

        public UtilityDictionary UtilityDictionary
        {
            get { return this.utilityDictionary; }
            set { this.utilityDictionary = value; }
        }

        public ExclusiveC14NDictionary ExclusiveC14NDictionary
        {
            get { return this.exclusiveC14NDictionary; }
            set { this.exclusiveC14NDictionary = value; }
        }

        public SecurityAlgorithmDictionary SecurityAlgorithmDictionary
        {
            get { return this.securityAlgorithmDictionary; }
            set { this.securityAlgorithmDictionary = value; }
        }
 
        public XmlEncryptionDictionary XmlEncryptionDictionary
        {
            get { return this.xmlEncryptionDictionary; }
            set { this.xmlEncryptionDictionary = value; }
        }

        public IXmlDictionary ParentDictionary
        {
            get { return this.parentDictionary; }
            set { this.parentDictionary = value; }
        }
    }
}