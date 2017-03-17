//-----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//-----------------------------------------------------------------------------

using System;
using System.Globalization;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    public class SamlSerializer
    {
        private DictionaryManager _dictionaryManager;

        public SamlSerializer()
            :this(null)
        {
        }

        public SamlSerializer(IXmlDictionary dictionary)
        {
            if (dictionary == null)
                _dictionaryManager = new DictionaryManager();
            else
                _dictionaryManager = new DictionaryManager(dictionary);
        }

        public DictionaryManager DictionaryManager
        {
            get
            {
                return _dictionaryManager;
            }
        }

        public virtual SamlSecurityToken ReadToken(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            SamlAssertion assertion = ReadAssertion(reader);
            if (assertion == null)
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLUnableToLoadAssertion"));

            //if (assertion.Signature == null)
            //    throw LogHelper.LogExceptionMessage(new SecurityTokenException(SR.GetString(SR.SamlTokenMissingSignature)));

            return new SamlSecurityToken(assertion);
        }

        public virtual SamlAssertion ReadAssertion(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            var dictionary = DictionaryManager.SamlDictionary;
            SamlAssertion assertion = new SamlAssertion();
            WrappedReader wrappedReader = new WrappedReader(reader);
            if (!wrappedReader.IsStartElement(DictionaryManager.SamlDictionary.Assertion, DictionaryManager.SamlDictionary.Namespace))
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLElementNotRecognized"));

            string attributeValue = wrappedReader.GetAttribute(DictionaryManager.SamlDictionary.MajorVersion, null);
            if (string.IsNullOrEmpty(attributeValue))
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAssertionMissingMajorVersionAttributeOnRead"));

            int majorVersion = Int32.Parse(attributeValue, CultureInfo.InvariantCulture);

            attributeValue = wrappedReader.GetAttribute(dictionary.MinorVersion, null);
            if (string.IsNullOrEmpty(attributeValue))
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAssertionMissingMinorVersionAttributeOnRead"));

            int minorVersion = Int32.Parse(attributeValue, CultureInfo.InvariantCulture);
            if ((majorVersion != SamlConstants.MajorVersionValue) || (minorVersion != SamlConstants.MinorVersionValue))
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLTokenVersionNotSupported, majorVersion, minorVersion, SamlConstants.MajorVersionValue, SamlConstants.MinorVersionValue"));

            attributeValue = wrappedReader.GetAttribute(dictionary.AssertionId, null);
            if (string.IsNullOrEmpty(attributeValue))
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAssertionIdRequired"));

            if (!IsAssertionIdValid(attributeValue))
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAssertionIDIsInvalid, attributeValue"));

            assertion.AssertionId = attributeValue;

            attributeValue = wrappedReader.GetAttribute(dictionary.Issuer, null);
            if (string.IsNullOrEmpty(attributeValue))
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAssertionMissingIssuerAttributeOnRead"));

            assertion.Issuer = attributeValue;

            attributeValue = wrappedReader.GetAttribute(dictionary.IssueInstant, null);
            // TODO - try/catch throw SamlReadException
            if (!string.IsNullOrEmpty(attributeValue))
                assertion.IssueInstant = DateTime.ParseExact(
                    attributeValue, SamlConstants.AcceptedDateTimeFormats, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None).ToUniversalTime();

            wrappedReader.MoveToContent();
            wrappedReader.Read();

            if (wrappedReader.IsStartElement(dictionary.Conditions, dictionary.Namespace))
            {

                var conditions = ReadConditions(wrappedReader);
                if (conditions == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLUnableToLoadCondtions"));

                assertion.Conditions = conditions;
            }

            if (wrappedReader.IsStartElement(dictionary.Advice, dictionary.Namespace))
            {
                var advice = ReadAdvice(wrappedReader);
                if (advice == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLUnableToLoadAdvice"));

                assertion.Advice = advice;
            }

            while (wrappedReader.IsStartElement())
            {
                if (wrappedReader.IsStartElement(DictionaryManager.XmlSignatureDictionary.Signature, DictionaryManager.XmlSignatureDictionary.Namespace))
                {
                    break;
                }
                else
                {
                    SamlStatement statement = ReadStatement(wrappedReader);
                    if (statement == null)
                        throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLUnableToLoadStatement"));

                    assertion.Statements.Add(statement);
                }
            }

            if (assertion.Statements.Count == 0)
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAssertionRequireOneStatementOnRead"));

            //if (wrappedReader.IsStartElement(samlSerializer.DictionaryManager.XmlSignatureDictionary.Signature, samlSerializer.DictionaryManager.XmlSignatureDictionary.Namespace))
            //    this.ReadSignature(wrappedReader, samlSerializer);

            wrappedReader.MoveToContent();
            wrappedReader.ReadEndElement();

            // set as property on assertion
            //this.tokenStream = wrappedReader.XmlTokens;

            return assertion;
        }

        protected virtual SamlCondition ReadCondition(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (reader.IsStartElement(DictionaryManager.SamlDictionary.AudienceRestrictionCondition, DictionaryManager.SamlDictionary.Namespace))
            {
                return ReadAudienceRestrictionCondition(reader);
            }
            else if (reader.IsStartElement(DictionaryManager.SamlDictionary.DoNotCacheCondition, DictionaryManager.SamlDictionary.Namespace))
            {
                return ReadDoNotCacheCondition(reader);
            }
            else
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLUnableToLoadUnknownElement, reader.LocalName"));
        }

        /// <summary>
        /// Read saml:AudienceRestrictionCondition from the given XmlReader.
        /// </summary>
        /// <param name="reader">XmlReader positioned at a saml:AudienceRestrictionCondition.</param>
        /// <returns>SamlAudienceRestrictionCondition</returns>
        /// <exception cref="ArgumentNullException">The inpur parameter 'reader' is null.</exception>
        /// <exception cref="XmlException">The XmlReader is not positioned at saml:AudienceRestrictionCondition.</exception>
        protected virtual SamlAudienceRestrictionCondition ReadAudienceRestrictionCondition(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (!reader.IsStartElement(SamlConstants.ElementNames.AudienceRestrictionCondition, SamlConstants.Namespace))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SamlConstants.ElementNames.AudienceRestrictionCondition, SamlConstants.Namespace, reader.LocalName, reader.NamespaceURI"));

            reader.ReadStartElement();

            SamlAudienceRestrictionCondition audienceRestrictionCondition = new SamlAudienceRestrictionCondition();
            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(SamlConstants.ElementNames.Audience, SamlConstants.Namespace))
                {
                    string audience = reader.ReadString();
                    if (string.IsNullOrEmpty(audience))
                    {
                        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("ID4083"));
                    }

                    audienceRestrictionCondition.Audiences.Add(new Uri(audience, UriKind.RelativeOrAbsolute));
                    reader.MoveToContent();
                    reader.ReadEndElement();
                }
                else
                {
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SamlConstants.ElementNames.Audience, SamlConstants.Namespace, reader.LocalName, reader.NamespaceURI"));
                }
            }

            if (audienceRestrictionCondition.Audiences.Count == 0)
            {
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("ID4084"));
            }

            reader.MoveToContent();
            reader.ReadEndElement();

            return audienceRestrictionCondition;
        }

        protected virtual SamlDoNotCacheCondition ReadDoNotCacheCondition(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            SamlDictionary dictionary = DictionaryManager.SamlDictionary;

            if (!reader.IsStartElement(dictionary.DoNotCacheCondition, dictionary.Namespace))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLBadSchema, dictionary.DoNotCacheCondition.Value"));

            // TODO what is this about
            // saml:DoNotCacheCondition is a empty element. So just issue a read for
            // the empty element.
            if (reader.IsEmptyElement)
            {
                reader.MoveToContent();
                reader.Read();
                return new SamlDoNotCacheCondition();
            }

            reader.MoveToContent();
            reader.Read();
            reader.ReadEndElement();

            return new SamlDoNotCacheCondition();
        }

        protected virtual SamlAdvice ReadAdvice(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            SamlDictionary dictionary = DictionaryManager.SamlDictionary;

            var advice = new SamlAdvice();

            // SAML Advice is an optional element and all its child elements are optional 
            // too. So we may have an empty saml:Advice element in the saml token.
            if (reader.IsEmptyElement)
            {
                // Just issue a read for the empty element.
                reader.MoveToContent();
                reader.Read();
                return advice;
            }

            reader.MoveToContent();
            reader.Read();

            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(dictionary.AssertionIdReference, dictionary.Namespace))
                {
                    reader.MoveToContent();
                    advice.AssertionIdReferences.Add(reader.ReadString());
                    reader.MoveToContent();
                    reader.ReadEndElement();
                }
                else if (reader.IsStartElement(dictionary.Assertion, dictionary.Namespace))
                {
                    advice.Assertions.Add(ReadAssertion(reader));
                }
                else
                {
                    throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLBadSchema"));
                }
            }

            reader.MoveToContent();
            reader.ReadEndElement();

            return advice;
        }

        protected virtual SamlAuthorizationDecisionStatement ReadAuthorizationDecisionStatement(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            var dictionary = DictionaryManager.SamlDictionary;
            var statement = new SamlAuthorizationDecisionStatement();

            var resource = reader.GetAttribute(dictionary.Resource, null);
            if (string.IsNullOrEmpty(resource))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorizationDecisionStatementMissingResourceAttributeOnRead"));

            string decisionString = reader.GetAttribute(dictionary.Decision, null);
            if (string.IsNullOrEmpty(decisionString))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorizationDecisionStatementMissingDecisionAttributeOnRead"));

            if (decisionString.Equals(SamlAccessDecision.Deny.ToString(), StringComparison.OrdinalIgnoreCase))
                statement.AccessDecision = SamlAccessDecision.Deny;
            else if (decisionString.Equals(SamlAccessDecision.Permit.ToString(), StringComparison.OrdinalIgnoreCase))
                statement.AccessDecision = SamlAccessDecision.Permit;
            else
                statement.AccessDecision = SamlAccessDecision.Indeterminate;

            reader.MoveToContent();
            reader.Read();

            if (!reader.IsStartElement(dictionary.Subject, dictionary.Namespace))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorizationDecisionStatementMissingSubjectOnRead"));

            statement.Subject = ReadSubject(reader);
            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(dictionary.Action, dictionary.Namespace))
                {
                    statement.Actions.Add(ReadAction(reader));
                }
                else if (reader.IsStartElement(dictionary.Evidence, dictionary.Namespace))
                {
                    if (statement.Evidence != null)
                        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorizationDecisionHasMoreThanOneEvidence"));

                    statement.Evidence = ReadEvidence(reader);
                }
                else
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLBadSchema, dictionary.AuthorizationDecisionStatement"));
            }

            if (statement.Actions.Count == 0)
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorizationDecisionShouldHaveOneActionOnRead"));

            reader.MoveToContent();
            reader.ReadEndElement();

            return statement;
        }

        protected virtual SamlEvidence ReadEvidence(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            var dictionary = DictionaryManager.SamlDictionary;
            var evidence = new SamlEvidence();

            reader.MoveToContent();
            reader.Read();
            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(dictionary.AssertionIdReference, dictionary.Namespace))
                {
                    reader.MoveToContent();
                    evidence.AssertionIdReferences.Add(reader.ReadString());
                    reader.ReadEndElement();
                }
                else if (reader.IsStartElement(dictionary.Assertion, dictionary.Namespace))
                {
                    evidence.Assertions.Add(ReadAssertion(reader));
                }
                else
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLBadSchema, dictionary.Evidence.Value"));
            }

            if ((evidence.AssertionIdReferences.Count == 0) && (evidence.Assertions.Count == 0))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLEvidenceShouldHaveOneAssertionOnRead"));

            reader.MoveToContent();
            reader.ReadEndElement();

            return evidence;
        }

        /// <summary>
        /// Read the saml:AuthenticationStatement.
        /// </summary>
        /// <param name="reader">XmlReader positioned at a saml:AuthenticationStatement.</param>
        /// <returns>SamlAuthenticationStatement</returns>
        /// <exception cref="ArgumentNullException">The input parameter 'reader' is null.</exception>
        /// <exception cref="XmlException">The XmlReader is not positioned on a saml:AuthenticationStatement
        /// or the statement contains a unknown child element.</exception>
        protected virtual SamlAuthenticationStatement ReadAuthenticationStatement(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            var dictionary = DictionaryManager.SamlDictionary;
            var authenticationStatement = new SamlAuthenticationStatement();

            string authInstance = reader.GetAttribute(dictionary.AuthenticationInstant, null);
            if (string.IsNullOrEmpty(authInstance))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthenticationStatementMissingAuthenticationInstanceOnRead"));

            var authenticationInstant = DateTime.ParseExact(
                authInstance, SamlConstants.AcceptedDateTimeFormats, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None).ToUniversalTime();

            var authenticationMethod = reader.GetAttribute(dictionary.AuthenticationMethod, null);
            if (string.IsNullOrEmpty(authenticationMethod))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthenticationStatementMissingAuthenticationMethodOnRead"));

            reader.MoveToContent();
            reader.Read();

            if (!reader.IsStartElement(dictionary.Subject, dictionary.Namespace))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthenticationStatementMissingSubject"));

            authenticationStatement.Subject = ReadSubject(reader);
            if (reader.IsStartElement(dictionary.SubjectLocality, dictionary.Namespace))
            {
                var dnsAddress = reader.GetAttribute(dictionary.SubjectLocalityDNSAddress, null);
                var ipAddress = reader.GetAttribute(dictionary.SubjectLocalityIPAddress, null);

                if (reader.IsEmptyElement)
                {
                    reader.MoveToContent();
                    reader.Read();
                }
                else
                {
                    reader.MoveToContent();
                    reader.Read();
                    reader.ReadEndElement();
                }
            }

            while (reader.IsStartElement())
            {
                if (!reader.IsStartElement(dictionary.AuthorityBinding, dictionary.Namespace))
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLBadSchema, dictionary.AuthenticationStatement"));

                authenticationStatement.AuthorityBindings.Add(ReadAuthorityBinding(reader));
            }

            reader.MoveToContent();
            reader.ReadEndElement();

            return authenticationStatement;
        }

        protected virtual SamlAuthorityBinding ReadAuthorityBinding(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            SamlDictionary dictionary = DictionaryManager.SamlDictionary;

            string authKind = reader.GetAttribute(dictionary.AuthorityKind, null);
            if (string.IsNullOrEmpty(authKind))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorityBindingMissingAuthorityKindOnRead"));

            string[] authKindParts = authKind.Split(':');
            if (authKindParts.Length > 2)
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAuthorityBindingInvalidAuthorityKind"));

            string localName;
            string prefix;
            string nameSpace;
            if (authKindParts.Length == 2)
            {
                prefix = authKindParts[0];
                localName = authKindParts[1];
            }
            else
            {
                prefix = String.Empty;
                localName = authKindParts[0];
            }

            nameSpace = reader.LookupNamespace(prefix);
            var authorityKind = new XmlQualifiedName(localName, nameSpace);

            var binding = reader.GetAttribute(dictionary.Binding, null);
            if (string.IsNullOrEmpty(binding))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorityBindingMissingBindingOnRead"));

            var location = reader.GetAttribute(dictionary.Location, null);
            if (string.IsNullOrEmpty(location))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorityBindingMissingLocationOnRead"));

            if (reader.IsEmptyElement)
            {
                reader.MoveToContent();
                reader.Read();
            }
            else
            {
                reader.MoveToContent();
                reader.Read();
                reader.ReadEndElement();
            }

            return new SamlAuthorityBinding(authorityKind, binding, location);
        }

        protected virtual SamlConditions ReadConditions(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            //var conditions = new SamlConditions();
            var nbf = DateTimeUtil.GetMinValue(DateTimeKind.Utc);
            string time = reader.GetAttribute(SamlConstants.AttributeNames.NotBefore, null);
            if (!string.IsNullOrEmpty(time))
                nbf = DateTime.ParseExact(time, SamlConstants.AcceptedDateTimeFormats, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None).ToUniversalTime();
        
            var notOnOrAfter = DateTimeUtil.GetMaxValue(DateTimeKind.Utc);
            time = reader.GetAttribute(SamlConstants.AttributeNames.NotOnOrAfter, null);
            if (!string.IsNullOrEmpty(time))
                notOnOrAfter = DateTime.ParseExact(time, SamlConstants.AcceptedDateTimeFormats, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None).ToUniversalTime();

            var conditions = new SamlConditions(nbf, notOnOrAfter);
            // Saml Conditions element is an optional element and all its child element
            // are optional as well. So we can have a empty <saml:Conditions /> element
            // in a valid Saml token.
            if (reader.IsEmptyElement)
            {
                // Just issue a read to read the Empty element.
                reader.MoveToContent();
                reader.Read();
                return conditions;
            }

            reader.ReadStartElement();
            while (reader.IsStartElement())
            {
                conditions.Conditions.Add(ReadCondition(reader));
            }

            reader.ReadEndElement();

            return conditions;
        }

        /// <summary>
        /// Read saml:Action element.
        /// </summary>
        /// <param name="reader">XmlReader positioned at saml:Action element.</param>
        /// <returns>SamlAction</returns>
        /// <exception cref="ArgumentNullException">The parameter 'reader' is null.</exception>
        /// <exception cref="XmlException">The saml:Action element contains unknown elements.</exception>
        protected virtual SamlAction ReadAction(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (!reader.IsStartElement(SamlConstants.ElementNames.Action, SamlConstants.Namespace))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SamlConstants.ElementNames.Action, SamlConstants.Namespace, reader.LocalName, reader.NamespaceURI"));

            // The Namespace attribute is optional.
            string ns = reader.GetAttribute(SamlConstants.AttributeNames.Namespace, null);

            reader.MoveToContent();
            string action = reader.ReadString();
            if (string.IsNullOrEmpty(action))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("ID4073"));

            reader.MoveToContent();
            reader.ReadEndElement();

            return (string.IsNullOrEmpty(ns)) ? new SamlAction(action) : new SamlAction(action, ns);
        }

        protected virtual SamlStatement ReadStatement(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (reader.IsStartElement(DictionaryManager.SamlDictionary.AuthenticationStatement, DictionaryManager.SamlDictionary.Namespace))
                return ReadAuthenticationStatement(reader);
            else if (reader.IsStartElement(DictionaryManager.SamlDictionary.AttributeStatement, DictionaryManager.SamlDictionary.Namespace))
                return ReadAttributeStatement(reader);
            else if (reader.IsStartElement(DictionaryManager.SamlDictionary.AuthorizationDecisionStatement, DictionaryManager.SamlDictionary.Namespace))
                return ReadAuthorizationDecisionStatement(reader);
            else
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLUnableToLoadUnknownElement, reader.LocalName"));
        }

        /// <summary>
        /// Read the SamlSubject from the XmlReader.
        /// </summary>
        /// <param name="reader">XmlReader to read the SamlSubject from.</param>
        /// <returns>SamlSubject</returns>
        /// <exception cref="ArgumentNullException">The input argument 'reader' is null.</exception>
        /// <exception cref="XmlException">The reader is not positioned at a SamlSubject.</exception>
        protected virtual SamlSubject ReadSubject(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            SamlDictionary dictionary = DictionaryManager.SamlDictionary;

            var subject = new SamlSubject();

            reader.MoveToContent();
            reader.Read();
            if (reader.IsStartElement(dictionary.NameIdentifier, dictionary.Namespace))
            {
                subject.NameFormat = reader.GetAttribute(dictionary.NameIdentifierFormat, null);
                subject.NameQualifier = reader.GetAttribute(dictionary.NameIdentifierNameQualifier, null);

                // TODO - check for string ??
                reader.MoveToContent();
                subject.Name = reader.ReadString();

                if (string.IsNullOrEmpty(subject.Name))
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLNameIdentifierMissingIdentifierValueOnRead"));

                reader.MoveToContent();
                reader.ReadEndElement();
            }

            if (reader.IsStartElement(dictionary.SubjectConfirmation, dictionary.Namespace))
            {
                reader.MoveToContent();
                reader.Read();

                while (reader.IsStartElement(dictionary.SubjectConfirmationMethod, dictionary.Namespace))
                {
                    string method = reader.ReadString();
                    if (string.IsNullOrEmpty(method))
                        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLBadSchema, dictionary.SubjectConfirmationMethod.Value"));

                    subject.ConfirmationMethods.Add(method);
                    reader.MoveToContent();
                    reader.ReadEndElement();
                }

                if (subject.ConfirmationMethods.Count == 0)
                {
                    // A SubjectConfirmaton clause should specify at least one 
                    // ConfirmationMethod.
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLSubjectConfirmationClauseMissingConfirmationMethodOnRead"));
                }

                if (reader.IsStartElement(dictionary.SubjectConfirmationData, dictionary.Namespace))
                {
                    reader.MoveToContent();
                    // An Authentication protocol specified in the confirmation method might need this
                    // data. Just store this content value as string.
                    subject.ConfirmationData = reader.ReadString();
                    reader.MoveToContent();
                    reader.ReadEndElement();
                }

                if (reader.IsStartElement(DictionaryManager.XmlSignatureDictionary.KeyInfo, DictionaryManager.XmlSignatureDictionary.Namespace))
                {
                    XmlDictionaryReader dictionaryReader = XmlDictionaryReader.CreateDictionaryReader(reader);
                    // TODO - we need to get the key
                    /// subject.Key = ReadSecurityKey(dictionaryReader);
                    //this.crypto = SamlSerializer.ResolveSecurityKey(this.securityKeyIdentifier, outOfBandTokenResolver);
                    //if (this.crypto == null)
                    //{
                    //    throw LogHelper.LogExceptionMessage(new SecurityTokenException(SR.GetString(SR.SamlUnableToExtractSubjectKey)));
                    //}
                    //this.subjectToken = SamlSerializer.ResolveSecurityToken(this.securityKeyIdentifier, outOfBandTokenResolver);
                }


                if ((subject.ConfirmationMethods.Count == 0) && (string.IsNullOrEmpty(subject.Name)))
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLSubjectRequiresNameIdentifierOrConfirmationMethodOnRead"));

                reader.MoveToContent();
                reader.ReadEndElement();
            }

            reader.MoveToContent();
            reader.ReadEndElement();

            return subject;
        }

        protected virtual SamlAttributeStatement ReadAttributeStatement(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            SamlDictionary dictionary = DictionaryManager.SamlDictionary;

            reader.MoveToContent();
            reader.Read();

            if (!reader.IsStartElement(dictionary.Subject, dictionary.Namespace))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAttributeStatementMissingSubjectOnRead"));

            var statement = new SamlAttributeStatement();
            statement.Subject = ReadSubject(reader);
            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(dictionary.Attribute, dictionary.Namespace))
                {
                    // SAML Attribute is a extensibility point. So ask the SAML serializer 
                    // to load this part.
                    SamlAttribute attribute = ReadAttribute(reader);
                    if (attribute == null)
                        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLUnableToLoadAttribute"));

                    statement.Attributes.Add(attribute);
                }
                else
                {
                    break;
                }
            }

            if (statement.Attributes.Count == 0)
            {
                // Each Attribute statement should have at least one attribute.
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAttributeStatementMissingAttributeOnRead"));
            }

            reader.MoveToContent();
            reader.ReadEndElement();

            return statement;
        }

        /// <summary>
        /// Read the SamlSubject KeyIdentifier from a XmlReader.
        /// </summary>
        /// <param name="reader">XmlReader positioned at the SamlSubject KeyIdentifier.</param>
        /// <returns>SamlSubject Key as a SecurityKeyIdentifier.</returns>
        /// <exception cref="ArgumentNullException">Input parameter 'reader' is null.</exception>
        /// <exception cref="XmlException">XmlReader is not positioned at a valid SecurityKeyIdentifier.</exception>
        protected virtual SecurityKeyIdentifier ReadSubjectKeyInfo(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            // TODO - get the key
            //if (KeyInfoSerializer.CanReadKeyIdentifier(reader))
            //{
            //    return KeyInfoSerializer.ReadKeyIdentifier(reader);
            //}

            throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("ID4090"));
        }

        public virtual SamlAttribute ReadAttribute(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            SamlDictionary dictionary = DictionaryManager.SamlDictionary;
            SamlAttribute attribute = new SamlAttribute();

            var name = reader.GetAttribute(dictionary.AttributeName, null);
            if (string.IsNullOrEmpty(name))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAttributeMissingNameAttributeOnRead"));
            
            var nameSpace = reader.GetAttribute(dictionary.AttributeNamespace, null);
            if (string.IsNullOrEmpty(nameSpace))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAttributeMissingNamespaceAttributeOnRead"));

            // TODO is this the right thing?
            var claimType = string.IsNullOrEmpty(nameSpace) ? name : nameSpace + "/" + name;

            reader.MoveToContent();
            reader.Read();
            while (reader.IsStartElement(dictionary.AttributeValue, dictionary.Namespace))
            {
                // We will load all Attributes as a string value by default.
                string attrValue = reader.ReadString();
                attribute.AttributeValues.Add(attrValue);

                reader.MoveToContent();
                reader.ReadEndElement();
            }

            if (attribute.AttributeValues.Count == 0)
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAttributeShouldHaveOneValue"));

            reader.MoveToContent();
            reader.ReadEndElement();

            return attribute;
        }

        /// <summary>
        /// Reads an attribute value.
        /// </summary>
        /// <param name="reader">XmlReader to read from.</param>
        /// <param name="attribute">The current attribute that is being read.</param>
        /// <returns>The attribute value as a string.</returns>
        /// <exception cref="ArgumentNullException">The input parameter 'reader' is null.</exception>
        protected virtual string ReadAttributeValue(XmlDictionaryReader reader, SamlAttribute attribute)
        {
            // This code was designed realizing that the writter of the xml controls how our
            // reader will report the NodeType. A completely differnet system (IBM, etc) could write the values. 
            // Considering NodeType is important, because we need to read the entire value, end element and not loose anything significant.
            // 
            // Couple of cases to help understand the design choices.
            //
            // 1. 
            // "<MyElement xmlns=""urn:mynamespace""><another>complex</another></MyElement><sibling>value</sibling>"
            // Could result in the our reader reporting the NodeType as Text OR Element, depending if '<' was entitized to '&lt;'
            //
            // 2. 
            // " <MyElement xmlns=""urn:mynamespace""><another>complex</another></MyElement><sibling>value</sibling>"
            // Could result in the our reader reporting the NodeType as Text OR Whitespace.  Post Whitespace processing, the NodeType could be 
            // reported as Text or Element, depending if '<' was entitized to '&lt;'
            //
            // 3. 
            // "/r/n/t   "
            // Could result in the our reader reporting the NodeType as whitespace.
            //
            // Since an AttributeValue with ONLY Whitespace and a complex Element proceeded by whitespace are reported as the same NodeType (2. and 3.)
            // the whitespace is remembered and discarded if an found is found, otherwise it becomes the value. This is to help users who accidently put a space when adding claims in ADFS
            // If we just skipped the Whitespace, then an AttributeValue that started with Whitespace would loose that part and claims generated from the AttributeValue
            // would be missing that part.
            // 

            if (reader == null)
            {
                throw LogHelper.LogArgumentNullException(nameof(reader));
            }

            string result = String.Empty;
            string whiteSpace = String.Empty;

            reader.ReadStartElement(SamlConstants.ElementNames.AttributeValue, SamlConstants.Namespace);

            while (reader.NodeType == XmlNodeType.Whitespace)
            {
                whiteSpace += reader.Value;
                reader.Read();
            }

            reader.MoveToContent();
            if (reader.NodeType == XmlNodeType.Element)
            {
                while (reader.NodeType == XmlNodeType.Element)
                {
                    result += reader.ReadOuterXml();
                    reader.MoveToContent();
                }
            }
            else
            {
                result = whiteSpace;
                result += reader.ReadContentAsString();
            }

            reader.ReadEndElement();
            return result;
        }

        protected virtual void WriteAction(XmlDictionaryWriter writer, SamlAction action)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (action == null)
                throw LogHelper.LogArgumentNullException(nameof(action));

            var dictionary = DictionaryManager.SamlDictionary;
            writer.WriteStartElement(dictionary.PreferredPrefix.Value, dictionary.Action, dictionary.Namespace);
            if (!string.IsNullOrEmpty(action.Namespace))
            {
                writer.WriteStartAttribute(dictionary.ActionNamespaceAttribute, null);
                writer.WriteString(action.Namespace);
                writer.WriteEndAttribute();
            }

            writer.WriteString(action.Action);
            writer.WriteEndElement();
        }

        protected virtual void WriteAdvice(XmlDictionaryWriter writer, SamlAdvice advice)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (advice == null)
                throw LogHelper.LogArgumentNullException(nameof(advice));

            var dictionary = DictionaryManager.SamlDictionary;
            writer.WriteStartElement(dictionary.PreferredPrefix.Value, dictionary.Advice, dictionary.Namespace);

            foreach (var reference in advice.AssertionIdReferences)
            {
                writer.WriteStartElement(dictionary.PreferredPrefix.Value, dictionary.AssertionIdReference, dictionary.Namespace);
                writer.WriteString(reference);
                writer.WriteEndElement();
            }

            foreach (var assertion in advice.Assertions)
                WriteAssertion(writer, assertion);

            writer.WriteEndElement();
        }

        public virtual void WriteAssertion(XmlDictionaryWriter writer, SamlAssertion assertion)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (assertion == null)
                throw LogHelper.LogArgumentNullException(nameof(assertion));

            if (string.IsNullOrEmpty(assertion.AssertionId))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAssertionIdRequired"));

            if (!IsAssertionIdValid(assertion.AssertionId))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAssertionIDIsInvalid"));

            if (string.IsNullOrEmpty(assertion.Issuer))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAssertionIssuerRequired"));

            if (assertion.Statements.Count == 0)
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAssertionRequireOneStatement"));

            var dictionary = DictionaryManager.SamlDictionary;

            try
            {
                writer.WriteStartElement(dictionary.PreferredPrefix.Value, dictionary.Assertion, dictionary.Namespace);
                writer.WriteStartAttribute(dictionary.MajorVersion, null);
                writer.WriteValue(SamlConstants.MajorVersionValue);
                writer.WriteEndAttribute();
                writer.WriteStartAttribute(dictionary.MinorVersion, null);
                writer.WriteValue(SamlConstants.MinorVersionValue);
                writer.WriteEndAttribute();
                writer.WriteStartAttribute(dictionary.AssertionId, null);
                writer.WriteString(assertion.AssertionId);
                writer.WriteEndAttribute();
                writer.WriteStartAttribute(dictionary.Issuer, null);
                writer.WriteString(assertion.Issuer);
                writer.WriteEndAttribute();
                writer.WriteStartAttribute(dictionary.IssueInstant, null);
                writer.WriteString(assertion.IssueInstant.ToString(SamlConstants.GeneratedDateTimeFormat, CultureInfo.InvariantCulture));
                writer.WriteEndAttribute();

                // Write out conditions
                if (assertion.Conditions != null)
                    WriteConditions(writer, assertion.Conditions);

                // Write out advice if there is one
                if (assertion.Advice != null)
                    WriteAdvice(writer, assertion.Advice);

                foreach (var statement in assertion.Statements)
                    WriteStatement(writer, statement);

                writer.WriteEndElement();
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLTokenNotSerialized", ex));
            }
        }

        protected virtual void WriteStatement(XmlDictionaryWriter writer, SamlStatement statement)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (statement == null)
                throw LogHelper.LogArgumentNullException(nameof(statement));

            var attributeStatement = statement as SamlAttributeStatement;
            if (attributeStatement != null)
            {
                WriteAttributeStatement(writer, attributeStatement);
                return;
            }

            var authenticationStatement = statement as SamlAuthenticationStatement;
            if (authenticationStatement != null)
            {
                WriteAuthenticationStatement(writer, authenticationStatement);
                return;
            }

            var authorizationStatement = statement as SamlAuthorizationDecisionStatement;
            if (authorizationStatement != null)
            {
                WriteAuthorizationDecisionStatement(writer, authorizationStatement);
                return;
            }

            throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException($"unknown statement type: {statement.GetType()}."));
        }

        protected virtual void WriteAttributeStatement(XmlDictionaryWriter writer, SamlAttributeStatement statement)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (statement == null)
                throw LogHelper.LogArgumentNullException(nameof(statement));

            writer.WriteStartElement(DictionaryManager.SamlDictionary.PreferredPrefix.Value, DictionaryManager.SamlDictionary.AttributeStatement, DictionaryManager.SamlDictionary.Namespace);

            WriteSubject(writer, statement.Subject);
            foreach (var attribute in statement.Attributes)
                WriteAttribute(writer, attribute);

            writer.WriteEndElement();
        }

        public virtual void WriteAttribute(XmlDictionaryWriter writer, SamlAttribute attribute)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (attribute == null)
                throw LogHelper.LogArgumentNullException(nameof(attribute));

            SamlDictionary dictionary = DictionaryManager.SamlDictionary;

            writer.WriteStartElement(dictionary.PreferredPrefix.Value, dictionary.Attribute, dictionary.Namespace);

            writer.WriteStartAttribute(dictionary.AttributeName, null);
            writer.WriteString(attribute.Name);
            writer.WriteEndAttribute();
            writer.WriteStartAttribute(dictionary.AttributeNamespace, null);
            writer.WriteString(attribute.Namespace);
            writer.WriteEndAttribute();

            foreach (var attributeValue in attribute.AttributeValues)
            {
                if (string.IsNullOrEmpty(attributeValue))
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SamlAttributeValueCannotBeNull"));

                writer.WriteElementString(dictionary.PreferredPrefix.Value, dictionary.AttributeValue, dictionary.Namespace, attributeValue);
            }

            writer.WriteEndElement();
        }

        protected virtual void WriteAuthenticationStatement(XmlDictionaryWriter writer, SamlAuthenticationStatement statement)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (statement == null)
                throw LogHelper.LogArgumentNullException(nameof(statement));

            var dictionary = DictionaryManager.SamlDictionary;

            writer.WriteStartElement(dictionary.PreferredPrefix.Value, dictionary.AuthenticationStatement, dictionary.Namespace);
            writer.WriteStartAttribute(dictionary.AuthenticationMethod, null);
            writer.WriteString(statement.AuthenticationMethod);
            writer.WriteEndAttribute();
            writer.WriteStartAttribute(dictionary.AuthenticationInstant, null);
            writer.WriteString(statement.AuthenticationInstant.ToString(SamlConstants.GeneratedDateTimeFormat, CultureInfo.InvariantCulture));
            writer.WriteEndAttribute();

            WriteSubject(writer, statement.Subject);

            if ((!string.IsNullOrEmpty(statement.IPAddress)) || (!string.IsNullOrEmpty(statement.DnsAddress)))
            {
                writer.WriteStartElement(dictionary.PreferredPrefix.Value, dictionary.SubjectLocality, dictionary.Namespace);

                if (!string.IsNullOrEmpty(statement.IPAddress))
                {
                    writer.WriteStartAttribute(dictionary.SubjectLocalityIPAddress, null);
                    writer.WriteString(statement.IPAddress);
                    writer.WriteEndAttribute();
                }

                if (!string.IsNullOrEmpty(statement.DnsAddress))
                {
                    writer.WriteStartAttribute(dictionary.SubjectLocalityDNSAddress, null);
                    writer.WriteString(statement.DnsAddress);
                    writer.WriteEndAttribute();
                }

                writer.WriteEndElement();
            }

            foreach (var binding in statement.AuthorityBindings)
            {
                WriteAuthorityBinding(writer, binding);
            }

            writer.WriteEndElement();
        }

        protected virtual void WriteAuthorityBinding(XmlDictionaryWriter writer, SamlAuthorityBinding authorityBinding)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (authorityBinding == null)
                throw LogHelper.LogArgumentNullException(nameof(authorityBinding));

            var dictionary = DictionaryManager.SamlDictionary;
            writer.WriteStartElement(DictionaryManager.SamlDictionary.PreferredPrefix.Value, dictionary.AuthorityBinding, dictionary.Namespace);

            string prefix = null;
            if (!string.IsNullOrEmpty(authorityBinding.AuthorityKind.Namespace))
            {
                writer.WriteAttributeString(string.Empty, dictionary.NamespaceAttributePrefix.Value, null, authorityBinding.AuthorityKind.Namespace);
                prefix = writer.LookupPrefix(authorityBinding.AuthorityKind.Namespace);
            }

            writer.WriteStartAttribute(dictionary.AuthorityKind, null);
            if (string.IsNullOrEmpty(prefix))
                writer.WriteString(authorityBinding.AuthorityKind.Name);
            else
                writer.WriteString(prefix + ":" + authorityBinding.AuthorityKind.Name);
            writer.WriteEndAttribute();

            writer.WriteStartAttribute(dictionary.Location, null);
            writer.WriteString(authorityBinding.Location);
            writer.WriteEndAttribute();

            writer.WriteStartAttribute(dictionary.Binding, null);
            writer.WriteString(authorityBinding.Binding);
            writer.WriteEndAttribute();

            writer.WriteEndElement();
        }

        protected virtual void WriteAuthorizationDecisionStatement(XmlDictionaryWriter writer, SamlAuthorizationDecisionStatement statement)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (statement == null)
                throw LogHelper.LogArgumentNullException(nameof(statement));

            var dictionary = DictionaryManager.SamlDictionary;

            writer.WriteStartElement(dictionary.PreferredPrefix.Value, dictionary.AuthorizationDecisionStatement, dictionary.Namespace);

            writer.WriteStartAttribute(dictionary.Decision, null);
            writer.WriteString(statement.AccessDecision.ToString());
            writer.WriteEndAttribute();

            writer.WriteStartAttribute(dictionary.Resource, null);
            writer.WriteString(statement.Resource);
            writer.WriteEndAttribute();

            WriteSubject(writer, statement.Subject);

            foreach (var action in statement.Actions)
                WriteAction(writer, action);

            if (statement.Evidence != null)
                WriteEvidence(writer, statement.Evidence);

            writer.WriteEndElement();
        }

        // TODO - figure this out when signing and maintaing node list

        ///// <summary>
        ///// Writes the source data, if available.
        ///// </summary>
        ///// <exception cref="InvalidOperationException">When no source data is available</exception>
        ///// <param name="writer"></param>
        //public virtual void WriteSourceData(XmlWriter writer)
        //{
        //    if (!this.CanWriteSourceData)
        //    {
        //        throw LogHelper.LogExceptionMessage(new InvalidOperationException("SR.ID4140"));
        //    }

        //    // This call will properly just reuse the existing writer if it already qualifies
        //    XmlDictionaryWriter dictionaryWriter = XmlDictionaryWriter.CreateDictionaryWriter(writer);
        //    this.sourceData.SetElementExclusion(null, null);
        //    this.sourceData.GetWriter().WriteTo(dictionaryWriter, null);
        //}

        //internal void WriteTo(XmlWriter writer, SamlSerializer samlSerializer)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    XmlDictionaryWriter dictionaryWriter = XmlDictionaryWriter.CreateDictionaryWriter(writer);

        //    if (this.signingCredentials != null)
        //    {
        //        using (HashAlgorithm hash = CryptoProviderFactory.Default.CreateHashAlgorithm(this.signingCredentials.Algorithm))
        //        {
        //            this.hashStream = new HashStream(hash);
        //            this.dictionaryManager = samlSerializer.DictionaryManager;
        //            SamlDelegatingWriter delegatingWriter = new SamlDelegatingWriter(dictionaryWriter, this.hashStream, this, samlSerializer.DictionaryManager.ParentDictionary);
        //            this.WriteXml(delegatingWriter, samlSerializer);
        //        }
        //    }
        //    else
        //    {
        //        this.tokenStream.SetElementExclusion(null, null);
        //        this.tokenStream.WriteTo(dictionaryWriter, samlSerializer.DictionaryManager);
        //    }
        //}

        protected virtual void WriteDoNotCacheCondition(XmlDictionaryWriter writer, SamlDoNotCacheCondition condition)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            var dictionary = DictionaryManager.SamlDictionary;

            writer.WriteStartElement(dictionary.PreferredPrefix.Value, dictionary.DoNotCacheCondition, dictionary.Namespace);
            writer.WriteEndElement();
        }

        protected virtual void WriteAudienceRestrictionCondition(XmlDictionaryWriter writer, SamlAudienceRestrictionCondition condition)
        {
            if (condition == null)
                throw LogHelper.LogArgumentNullException(nameof(condition));

            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            SamlDictionary dictionary = DictionaryManager.SamlDictionary;

            writer.WriteStartElement(dictionary.PreferredPrefix.Value, dictionary.AudienceRestrictionCondition, dictionary.Namespace);

            foreach (var audience in condition.Audiences)
            {
                // TODO - should we throw ?
                if (audience != null)
                    writer.WriteElementString(dictionary.Audience, dictionary.Namespace, audience.AbsoluteUri);
            }

            writer.WriteEndElement();
        }

        protected virtual void WriteEvidence(XmlDictionaryWriter writer, SamlEvidence evidence)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (evidence == null)
                throw LogHelper.LogArgumentNullException(nameof(evidence));

            var dictionary = DictionaryManager.SamlDictionary;

            writer.WriteStartElement(dictionary.PreferredPrefix.Value, dictionary.Evidence.Value, dictionary.Namespace.Value);

            foreach (var assertionId in evidence.AssertionIdReferences)
            {
                writer.WriteStartElement(dictionary.PreferredPrefix.Value, dictionary.AssertionIdReference, dictionary.Namespace);
                writer.WriteString(assertionId);
                writer.WriteEndElement();
            }

            foreach (var assertion in evidence.Assertions)
                WriteAssertion(writer, assertion);

            writer.WriteEndElement();
        }

        protected virtual void WriteSubject(XmlDictionaryWriter writer, SamlSubject subject)
        {

            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (subject == null)
                throw LogHelper.LogArgumentNullException(nameof(subject));

            SamlDictionary dictionary = DictionaryManager.SamlDictionary;
            writer.WriteStartElement(dictionary.PreferredPrefix.Value, dictionary.Subject, dictionary.Namespace);

            if (!string.IsNullOrEmpty(subject.Name))
            {
                writer.WriteStartElement(dictionary.PreferredPrefix.Value, dictionary.NameIdentifier, dictionary.Namespace);
                if (!string.IsNullOrEmpty(subject.NameFormat))
                {
                    writer.WriteStartAttribute(dictionary.NameIdentifierFormat, null);
                    writer.WriteString(subject.NameFormat);
                    writer.WriteEndAttribute();
                }

                if (!string.IsNullOrEmpty(subject.NameQualifier))
                {
                    writer.WriteStartAttribute(dictionary.NameIdentifierNameQualifier, null);
                    writer.WriteString(subject.NameQualifier);
                    writer.WriteEndAttribute();
                }

                writer.WriteString(subject.Name);
                writer.WriteEndElement();
            }

            if (subject.ConfirmationMethods.Count > 0)
            {
                writer.WriteStartElement(dictionary.PreferredPrefix.Value, dictionary.SubjectConfirmation, dictionary.Namespace);
                foreach (string method in subject.ConfirmationMethods)
                    writer.WriteElementString(dictionary.SubjectConfirmationMethod, dictionary.Namespace, method);

                if (!string.IsNullOrEmpty(subject.ConfirmationData))
                    writer.WriteElementString(dictionary.SubjectConfirmationData, dictionary.Namespace, subject.ConfirmationData);

                if (subject.KeyIdentifier != null)
                {
                    XmlDictionaryWriter dictionaryWriter = XmlDictionaryWriter.CreateDictionaryWriter(writer);
                    // TODO - write keyinfo
                    //SamlSerializer.WriteSecurityKeyIdentifier(dictionaryWriter, this.securityKeyIdentifier, keyInfoSerializer);
                }
                writer.WriteEndElement();
            }

            writer.WriteEndElement();
        }

        protected virtual void WriteConditions(XmlDictionaryWriter writer, SamlConditions conditions)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (conditions == null)
                throw LogHelper.LogArgumentNullException(nameof(conditions));

            var dictionary = DictionaryManager.SamlDictionary;
            writer.WriteStartElement(dictionary.PreferredPrefix.Value, dictionary.Conditions, dictionary.Namespace);
            if (conditions.NotBefore != SecurityUtils.MinUtcDateTime)
            {
                writer.WriteStartAttribute(dictionary.NotBefore, null);
                writer.WriteString(conditions.NotBefore.ToString(SamlConstants.GeneratedDateTimeFormat, DateTimeFormatInfo.InvariantInfo));
                writer.WriteEndAttribute();
            }

            if (conditions.NotOnOrAfter != SecurityUtils.MaxUtcDateTime)
            {
                writer.WriteStartAttribute(dictionary.NotOnOrAfter, null);
                writer.WriteString(conditions.NotOnOrAfter.ToString(SamlConstants.GeneratedDateTimeFormat, DateTimeFormatInfo.InvariantInfo));
                writer.WriteEndAttribute();
            }

            foreach (var condition in conditions.Conditions)
                WriteCondition(writer, condition);

            writer.WriteEndElement();
        }

        protected virtual void WriteCondition(XmlDictionaryWriter writer, SamlCondition condition)
        {
            var audienceRestrictionCondition = condition as SamlAudienceRestrictionCondition;
            if (audienceRestrictionCondition != null)
                WriteAudienceRestrictionCondition(writer, audienceRestrictionCondition);

            var donotCacheCondition = condition as SamlDoNotCacheCondition;
            if (donotCacheCondition != null)
                WriteDoNotCacheCondition(writer, donotCacheCondition);
        }

        public virtual void WriteToken(XmlDictionaryWriter writer, SamlSecurityToken token)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (token == null)
                throw LogHelper.LogArgumentNullException(nameof(token));

            WriteAssertion(writer, token.Assertion);
        }

        // Helper metods to read and write SecurityKeyIdentifiers.
        internal static SecurityKey ReadSecurityKey(XmlReader reader)
        {
            throw LogHelper.LogExceptionMessage(new InvalidOperationException("SamlSerializerUnableToReadSecurityKeyIdentifier"));
        }

        internal static bool IsAssertionIdValid(string assertionId)
        {
            if (string.IsNullOrEmpty(assertionId))
                return false;

            // The first character of the Assertion ID should be a letter or a '_'
            return (((assertionId[0] >= 'A') && (assertionId[0] <= 'Z')) ||
                ((assertionId[0] >= 'a') && (assertionId[0] <= 'z')) ||
                (assertionId[0] == '_'));
        }
    }
}
