//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    public class SamlAssertion //: ICanonicalWriterEndRootElementCallback
    {
        string assertionId = SamlConstants.AssertionIdPrefix + Guid.NewGuid().ToString();
        string issuer;
        DateTime issueInstant = DateTime.UtcNow.ToUniversalTime();
        SamlConditions conditions;
        SamlAdvice advice;
        private Collection<SamlStatement> statements = new Collection<SamlStatement>();
        SigningCredentials signingCredentials;
        SecurityToken signingToken;
        //HashStream hashStream;
        XmlTokenStream tokenStream;
        XmlTokenStream sourceData;

        public SamlAssertion()
        {
        }

        public SamlAssertion(
            string assertionId,
            string issuer,
            DateTime issueInstant,
            SamlConditions samlConditions,
            SamlAdvice samlAdvice,
            IEnumerable<SamlStatement> samlStatements
            )
        {
            if (string.IsNullOrEmpty(assertionId))
                throw LogHelper.LogArgumentNullException(nameof(assertionId));

            tokenStream = new XmlTokenStream(32);

            // TODO warning
            //if (!IsAssertionIdValid(assertionId))
            //    throw LogHelper.ExceptionUtility.ThrowHelperArgument(SR.GetString(SR.SAMLAssertionIDIsInvalid, assertionId));

            if (string.IsNullOrEmpty(issuer))
                throw LogHelper.LogArgumentNullException(nameof(issuer));

            if (samlStatements == null)
                throw LogHelper.LogArgumentNullException(nameof(samlStatements));

            this.assertionId = assertionId;
            this.issuer = issuer;
            this.issueInstant = issueInstant.ToUniversalTime();
            this.conditions = samlConditions;
            this.advice = samlAdvice;

            foreach (SamlStatement samlStatement in samlStatements)
            {
                if (samlStatement == null)
                    throw LogHelper.LogArgumentNullException("SAMLEntityCannotBeNullOrEmpty");

                this.statements.Add(samlStatement);
            }

            if (this.statements.Count == 0)
                throw LogHelper.LogExceptionMessage(new ArgumentException("SAMLAssertionRequireOneStatement"));
        }

        public SecurityKey SecurityKey { get; set; }

        public int MinorVersion
        {
            get { return SamlConstants.MinorVersionValue; }
        }

        public int MajorVersion
        {
            get { return SamlConstants.MajorVersionValue; }
        }

        public string AssertionId
        {
            get { return this.assertionId; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogHelper.LogArgumentNullException(nameof(value));

                this.assertionId = value;
            }
        }

        /// <summary>
        /// Indicates whether this assertion was deserialized from XML source
        /// and can re-emit the XML data unchanged.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The default implementation preserves the source data when read using
        /// Saml2AssertionSerializer.ReadAssertion and is willing to re-emit the
        /// original data as long as the Id has not changed from the time that 
        /// assertion was read.
        /// </para>
        /// <para>
        /// Note that it is vitally important that SAML assertions with different
        /// data have different IDs. If implementing a scheme whereby an assertion
        /// "template" is loaded and certain bits of data are filled in, the Id 
        /// must be changed.
        /// </para>
        /// </remarks>
        /// <returns></returns>
        public virtual bool CanWriteSourceData
        {
            get { return null != this.sourceData; }
        }

        public string Issuer
        {
            get { return this.issuer; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogHelper.LogArgumentNullException(nameof(value));

                this.issuer = value;
            }
        }

        public DateTime IssueInstant
        {
            get { return this.issueInstant; }
            set
            {
                this.issueInstant = value;
            }
        }

        public SamlConditions Conditions
        {
            get { return this.conditions; }
            set
            {
                this.conditions = value;
            }
        }

        public SamlAdvice Advice
        {
            get { return this.advice; }
            set
            {
                this.advice = value;
            }
        }

        public IList<SamlStatement> Statements
        {
            get
            {
                return this.statements;
            }
        }

        public SigningCredentials SigningCredentials
        {
            get { return this.signingCredentials; }
            set
            {
                this.signingCredentials = value;
            }
        }

        public SignedXml Signature
        {
            get; set;
        }

        public SecurityKey SignatureVerificationKey
        {
            get; set;
        }

        public SecurityToken SigningToken
        {
            get { return this.signingToken; }
            set
            {
                this.signingToken = value;
            }
        }

        /// <summary>
        /// Captures the XML source data from an EnvelopedSignatureReader. 
        /// </summary>
        /// <remarks>
        /// The EnvelopedSignatureReader that was used to read the data for this
        /// assertion should be passed to this method after the &lt;/Assertion>
        /// element has been read. This method will preserve the raw XML data
        /// that was read, including the signature, so that it may be re-emitted
        /// without changes and without the need to re-sign the data. See 
        /// CanWriteSourceData and WriteSourceData.
        /// </remarks>
        /// <param name="reader"></param>
        internal virtual void CaptureSourceData(EnvelopedSignatureReader reader)
        {
            if (null == reader)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            this.sourceData = reader.XmlTokens;
        }

        protected void ReadSignature(XmlDictionaryReader reader, SamlSerializer samlSerializer)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (samlSerializer == null)
                throw LogHelper.LogArgumentNullException(nameof(samlSerializer));

            //if (this.signature != null)
            //    throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLSignatureAlreadyRead"));

            // If the reader cannot canonicalize then buffer the signature element to a canonicalizing reader.
            XmlDictionaryReader effectiveReader = reader;
            if (!effectiveReader.CanCanonicalize)
            {
                MemoryStream stream = new MemoryStream();
                XmlDictionaryWriter writer = XmlDictionaryWriter.CreateBinaryWriter(stream, samlSerializer.DictionaryManager.ParentDictionary);
                writer.WriteNode(effectiveReader, false);
                writer.Flush();
                stream.Position = 0;
                effectiveReader = XmlDictionaryReader.CreateBinaryReader(stream.GetBuffer(), 0, (int)stream.Length, samlSerializer.DictionaryManager.ParentDictionary, reader.Quotas);
                effectiveReader.MoveToContent();
                writer.Close();
            }
            SignedXml signedXml = new SignedXml(new StandardSignedInfo(samlSerializer.DictionaryManager), samlSerializer.DictionaryManager);
            signedXml.TransformFactory = TransformFactory.Instance;
            signedXml.ReadFrom(effectiveReader);
            SecurityKey securityKey = signedXml.Signature.Key;
            //this.verificationKey = SamlSerializer.ResolveSecurityKey(securityKeyIdentifier, outOfBandTokenResolver);
            //if (this.verificationKey == null)
            //    throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLUnableToResolveSignatureKey"));

            //this.signature = signedXml;
            //this.signingToken = SamlSerializer.ResolveSecurityToken(securityKeyIdentifier, outOfBandTokenResolver);
            if (this.signingToken == null)
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SamlSigningTokenNotFound"));

            if (!ReferenceEquals(reader, effectiveReader))
                effectiveReader.Close();
        }

        bool IsAssertionIdValid(string assertionId)
        {
            if (string.IsNullOrEmpty(assertionId))
                return false;

            // The first character of the Assertion ID should be a letter or a '_'
            return (((assertionId[0] >= 'A') && (assertionId[0] <= 'Z')) ||
                ((assertionId[0] >= 'a') && (assertionId[0] <= 'z')) ||
                (assertionId[0] == '_'));
        }

        // TODO - move signature validation outside of reading.
        //ReadOnlyCollection<SecurityKey> BuildCryptoList()
        //{
        //    List<SecurityKey> cryptoList = new List<SecurityKey>();

        //    for (int i = 0; i < this.statements.Count; ++i)
        //    {
        //        SamlSubjectStatement statement = this.statements[i] as SamlSubjectStatement;
        //        if (statement != null)
        //        {
        //            bool skipCrypto = false;
        //            SecurityKey crypto = null;
        //            if (statement.Subject != null)
        //                crypto = statement.Subject.Key;

        //            SymmetricSecurityKey inMemorySymmetricSecurityKey = crypto as SymmetricSecurityKey;
        //            if (inMemorySymmetricSecurityKey != null)
        //            {

        //                // Verify that you have not already added this to crypto list.
        //                for (int j = 0; j < cryptoList.Count; ++j)
        //                {
        //                    if ((cryptoList[j] is SymmetricSecurityKey) && (cryptoList[j].KeySize == inMemorySymmetricSecurityKey.KeySize))
        //                    {
        //                        byte[] key1 = ((SymmetricSecurityKey)cryptoList[j]).Key;
        //                        byte[] key2 = inMemorySymmetricSecurityKey.Key;
        //                        int k = 0;
        //                        for (k = 0; k < key1.Length; ++k)
        //                        {
        //                            if (key1[k] != key2[k])
        //                            {
        //                                break;
        //                            }
        //                        }
        //                        skipCrypto = (k == key1.Length);
        //                    }

        //                    if (skipCrypto)
        //                        break;
        //                }
        //            }
        //            if (!skipCrypto && (crypto != null))
        //            {
        //                cryptoList.Add(crypto);
        //            }
        //        }
        //    }

        //    return cryptoList.AsReadOnly();

        //}

        //void VerifySignature(SignedXml signature, SecurityKey signatureVerificationKey)
        //{
        //    if (signature == null)
        //        throw LogHelper.LogArgumentNullException(nameof(signature));

        //    if (signatureVerificationKey == null)
        //        throw LogHelper.LogArgumentNullException(nameof(signatureVerificationKey));

        //    signature.StartSignatureVerification(signatureVerificationKey);
        //    signature.EnsureDigestValidity(this.assertionId, tokenStream);
        //    signature.CompleteSignatureVerification();
        //}

        //void ICanonicalWriterEndRootElementCallback.OnEndOfRootElement(XmlDictionaryWriter dictionaryWriter)
        //{
        //    byte[] hashValue = this.hashStream.FlushHashAndGetValue();

        //    PreDigestedSignedInfo signedInfo = new PreDigestedSignedInfo(this.dictionaryManager);
        //    signedInfo.AddEnvelopedSignatureTransform = true;
        //    signedInfo.CanonicalizationMethod = SecurityAlgorithms.ExclusiveC14n;
        //    signedInfo.SignatureMethod = this.signingCredentials.Algorithm;
        //    signedInfo.AddReference(this.assertionId, hashValue);

        //    SignedXml signedXml = new SignedXml(signedInfo, this.dictionaryManager);
        //    signedXml.ComputeSignature(this.signingCredentials.Key);
        //    signedXml.Signature.Key = this.signingCredentials.Key;
        //    signedXml.WriteTo(dictionaryWriter);
        //}
    }
}
