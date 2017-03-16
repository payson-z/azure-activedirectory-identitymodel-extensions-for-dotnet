//-----------------------------------------------------------------------
// <copyright file="XmlUtil.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Schema;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    // Merged System.IdentityModel.XmlUtil with Microsoft.IdentityModel.XmlUtil by porting methods from the Microsoft.IdentityModel.XmlUtil to this.
    static class XmlUtil
    {
        public const string XmlNs = "http://www.w3.org/XML/1998/namespace";
        public const string XmlNsNs = "http://www.w3.org/2000/xmlns/";

        public const string LanguagePrefix = "xml";
        public const string LanguageLocalname = "lang";
        public const string LanguageAttribute = LanguagePrefix + ":" + LanguageLocalname;


        //public static string GetXmlLangAttribute(XmlReader reader)
        //{
        //    string xmlLang = null;
        //    if (reader.MoveToAttribute("lang", XmlNs))
        //    {
        //        xmlLang = reader.Value;
        //        reader.MoveToElement();
        //    }

        //    if (xmlLang == null)
        //        throw LogHelper.LogExceptionMessage(new XmlException(SR.GetString(SR.XmlLangAttributeMissing)));

        //    return xmlLang;
        //}

        //public static void ReadContentAsQName(XmlReader reader, out string localName, out string ns)
        //{
        //    ParseQName(reader, reader.ReadContentAsString(), out localName, out ns);
        //}

        public static bool IsWhitespace(char ch)
        {
            return (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n');
        }

        public static string Trim(string s)
        {
            int i;
            for (i = 0; i < s.Length && IsWhitespace(s[i]); i++);
            if (i >= s.Length)
            {
                return string.Empty;
            }

            int j;
            for (j = s.Length; j > 0 && IsWhitespace(s[j - 1]); j--);

            if (i != 0 || j != s.Length)
            {
                return s.Substring(i, j - i);
            }
            return s;
        }

        //public static void ParseQName(XmlReader reader, string qname, out string localName, out string ns)
        //{
        //    int index = qname.IndexOf(':');
        //    string prefix;
        //    if (index < 0)
        //    {
        //        prefix = "";
        //        localName = TrimStart(TrimEnd(qname));
        //    }
        //    else
        //    {
        //        if (index == qname.Length - 1)
        //            throw LogHelper.LogExceptionMessage(new XmlException(SR.GetString(SR.InvalidXmlQualifiedName, qname)));
        //        prefix = TrimStart(qname.Substring(0, index));
        //        localName = TrimEnd(qname.Substring(index + 1));
        //    }
        //    ns = reader.LookupNamespace(prefix);
        //    if (ns == null)
        //        throw LogHelper.LogExceptionMessage(new XmlException(SR.GetString(SR.UnboundPrefixInQName, qname)));
        //}


        // Everything below is from WIF
        public static XmlQualifiedName GetXsiType(XmlReader reader)
        {
            string xsiType = reader.GetAttribute("type", XmlSchema.InstanceNamespace);
            reader.MoveToElement();

            if (string.IsNullOrEmpty(xsiType))
            {
                return null;
            }

            return ResolveQName(reader, xsiType);
        }

        public static bool EqualsQName(XmlQualifiedName qname, string localName, string namespaceUri)
        {
            return null != qname
                && StringComparer.Ordinal.Equals(localName, qname.Name)
                && StringComparer.Ordinal.Equals(namespaceUri, qname.Namespace);
        }

        public static bool IsNil(XmlReader reader)
        {
            string xsiNil = reader.GetAttribute("nil", XmlSchema.InstanceNamespace);
            return !string.IsNullOrEmpty(xsiNil) && XmlConvert.ToBoolean(xsiNil);
        }

        public static string NormalizeEmptyString(string s)
        {
            return string.IsNullOrEmpty(s) ? null : s;
        }

        public static XmlQualifiedName ResolveQName(XmlReader reader, string qstring)
        {
            string name = qstring;
            string prefix = String.Empty;
            string ns = null;

            int colon = qstring.IndexOf(':'); // index of char is always ordinal
            if (colon > -1)
            {
                prefix = qstring.Substring(0, colon);
                name = qstring.Substring(colon + 1, qstring.Length - (colon + 1));
            }

            ns = reader.LookupNamespace(prefix);

            return new XmlQualifiedName(name, ns);
        }

        public static void ValidateXsiType(XmlReader reader, string expectedTypeName, string expectedTypeNamespace)
        {
            ValidateXsiType(reader, expectedTypeName, expectedTypeNamespace, false);
        }

        public static void ValidateXsiType(XmlReader reader, string expectedTypeName, string expectedTypeNamespace, bool requireDeclaration)
        {
            XmlQualifiedName declaredType = GetXsiType(reader);

            if (null == declaredType)
            {
                if (requireDeclaration)
                {
                    throw LogHelper.LogExceptionMessage(new XmlException("reader.LocalName, reader.NamespaceURI"));
                }
            }
            else if (!(StringComparer.Ordinal.Equals(expectedTypeNamespace, declaredType.Namespace)
                && StringComparer.Ordinal.Equals(expectedTypeName, declaredType.Name)))
            {
                throw LogHelper.LogExceptionMessage(new XmlException("SR.ID4102, expectedTypeName, expectedTypeNamespace, declaredType.Name, declaredType.Namespace"));
                //throw LogHelper.ThrowHelperXml(reader,
                //    SR.GetString(SR.ID4102, expectedTypeName, expectedTypeNamespace, declaredType.Name, declaredType.Namespace));
            }
        }

        public static string SerializeSecurityKeyIdentifier(SecurityKeyIdentifier ski)
        {
            StringBuilder sb = new StringBuilder();
            using (StringWriter stringWriter = new StringWriter(sb, CultureInfo.InvariantCulture))
            {
                XmlWriterSettings settings = new XmlWriterSettings();
                settings.OmitXmlDeclaration = true;
                using (XmlWriter xmlWriter = XmlWriter.Create(stringWriter, settings))
                {
                    // TODO write out string
//                    tokenSerializer.WriteKeyIdentifierClause(xmlWriter, ski[0]);
                }
            }

            return sb.ToString();
        }

        public static bool IsValidXmlIDValue(string val)
        {
            if (string.IsNullOrEmpty(val))
            {
                return false;
            }

            // The first character of the ID should be a letter, '_' or ':'
            return (((val[0] >= 'A') && (val[0] <= 'Z')) ||
                ((val[0] >= 'a') && (val[0] <= 'z')) ||
                (val[0] == '_') || (val[0] == ':'));
        }

        public static void WriteElementStringAsUniqueId(XmlDictionaryWriter writer, XmlDictionaryString localName, XmlDictionaryString ns, string id)
        {
            writer.WriteStartElement(localName, ns);
            writer.WriteValue(id);
            writer.WriteEndElement();
        }

        public static void WriteElementContentAsInt64(XmlDictionaryWriter writer, XmlDictionaryString localName, XmlDictionaryString ns, Int64 value)
        {
            writer.WriteStartElement(localName, ns);
            writer.WriteValue(value);
            writer.WriteEndElement();
        }

        public static Int64 ReadElementContentAsInt64(XmlDictionaryReader reader)
        {
            reader.ReadFullStartElement();
            Int64 i = reader.ReadContentAsLong();
            reader.ReadEndElement();
            return i;
        }

        // Takes a collection of node list and returns a list of XmlElements
        // from the list (skipping past any XmlComments and CDATA nodes).
        public static List<XmlElement> GetXmlElements(XmlNodeList nodeList)
        {
            if (nodeList == null)
            {
                throw LogHelper.LogArgumentNullException(nameof(nodeList));
            }

            List<XmlElement> xmlElements = new List<XmlElement>();
            foreach (XmlNode node in nodeList)
            {
                XmlElement tempElement = node as XmlElement;
                if (tempElement != null)
                {
                    xmlElements.Add(tempElement);
                }
            }

            return xmlElements;
        }

        internal static string GetWhiteSpace(XmlReader reader)
        {
            string s = null;
            StringBuilder sb = null;
            while (reader.NodeType == XmlNodeType.Whitespace || reader.NodeType == XmlNodeType.SignificantWhitespace)
            {
                if (sb != null)
                {
                    sb.Append(reader.Value);
                }
                else if (s != null)
                {
                    sb = new StringBuilder(s);
                    sb.Append(reader.Value);
                    s = null;
                }
                else
                {
                    s = reader.Value;
                }
                if (!reader.Read())
                {
                    break;
                }
            }
            return sb != null ? sb.ToString() : s;
        }

        internal static void OnRequiredAttributeMissing(string attrName, string elementName)
        {
            throw LogHelper.LogExceptionMessage(new XmlException("RequiredAttributeMissing, attrName, elementName"));
        }

        internal static string ReadEmptyElementAndRequiredAttribute(XmlDictionaryReader reader,
            XmlDictionaryString name, XmlDictionaryString namespaceUri, XmlDictionaryString attributeName,
            out string prefix)
        {
            reader.MoveToStartElement(name, namespaceUri);
            prefix = reader.Prefix;
            bool isEmptyElement = reader.IsEmptyElement;
            string value = reader.GetAttribute(attributeName, null);
            if (value == null)
            {
                OnRequiredAttributeMissing(attributeName.Value, null);
            }
            reader.Read();

            if (!isEmptyElement)
            {
                reader.ReadEndElement();
            }
            return value;
        }

        internal static string ReadTextElementAsTrimmedString(XmlElement element)
        {
            if (element == null)
            {
                throw LogHelper.LogArgumentNullException(nameof(element));
            }

            XmlReader reader = new XmlNodeReader(element);
            reader.MoveToContent();
            return XmlUtil.Trim(reader.ReadElementContentAsString());
        }

        internal static void OnRequiredElementMissing(string elementName, string elementNamespace)
        {
            throw LogHelper.LogExceptionMessage(new XmlException("ExpectedElementMissing, elementName, elementNamespace"));
        }

        internal static void OnUnexpectedChildNodeError(string parentName, XmlReader r)
        {
            throw LogHelper.LogExceptionMessage(new XmlException("UnexpectedXmlChildNode, r.Name, r.NodeType, parentName"));
        }

        internal static void OnUnexpectedChildNodeError(XmlElement parent, XmlNode n)
        {
            throw LogHelper.LogExceptionMessage(new XmlException("UnexpectedXmlChildNode, n.Name, n.NodeType, parent.Name"));
        }

        internal static System.Xml.UniqueId GetAttributeAsUniqueId(XmlDictionaryReader reader, XmlDictionaryString localName, XmlDictionaryString ns)
        {
            return GetAttributeAsUniqueId(reader, localName.Value, (ns != null ? ns.Value : null));
        }

        static System.Xml.UniqueId GetAttributeAsUniqueId(XmlDictionaryReader reader, string name, string ns)
        {
            if (!reader.MoveToAttribute(name, ns))
            {
                return null;
            }

            System.Xml.UniqueId id = reader.ReadContentAsUniqueId();
            reader.MoveToElement();

            return id;
        }

        static public void WriteAttributeStringAsUniqueId(XmlDictionaryWriter writer, string prefix, XmlDictionaryString localName, XmlDictionaryString ns, System.Xml.UniqueId id)
        {
            writer.WriteStartAttribute(prefix, localName, ns);
            writer.WriteValue(id);
            writer.WriteEndAttribute();
        }
    }
}