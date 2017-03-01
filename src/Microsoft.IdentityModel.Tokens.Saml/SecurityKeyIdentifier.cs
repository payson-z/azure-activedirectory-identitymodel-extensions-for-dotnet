//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using Microsoft.IdentityModel.Logging;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Globalization;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    public class SecurityKeyIdentifier : IEnumerable<SecurityKeyIdentifierClause>
    {
        const int InitialSize = 2;
        readonly List<SecurityKeyIdentifierClause> clauses;

        public SecurityKeyIdentifier()
        {
            this.clauses = new List<SecurityKeyIdentifierClause>(InitialSize);
        }

        public SecurityKeyIdentifier(params SecurityKeyIdentifierClause[] clauses)
        {
            if (clauses == null)
            {
                throw LogHelper.LogArgumentNullException(nameof(clauses));
            }

            this.clauses = new List<SecurityKeyIdentifierClause>(clauses.Length);
            for (int i = 0; i < clauses.Length; i++)
            {
                Add(clauses[i]);
            }
        }

        public SecurityKeyIdentifierClause this[int index]
        {
            get { return this.clauses[index]; }
        }

        public bool CanCreateKey
        {
            get
            {
                for (int i = 0; i < this.Count; i++)
                {
                    if (this[i].CanCreateKey)
                    {
                        return true;
                    }
                }
                return false;
            }
        }

        public int Count
        {
            get { return this.clauses.Count; }
        }

        public void Add(SecurityKeyIdentifierClause clause)
        {
            if (clause == null)
            {
                throw LogHelper.LogArgumentNullException(nameof(clause));
            }

            this.clauses.Add(clause);
        }

        public SecurityKey CreateKey()
        {
            for (int i = 0; i < this.Count; i++)
            {
                if (this[i].CanCreateKey)
                {
                    return this[i].CreateKey();
                }
            }
            throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("KeyIdentifierCannotCreateKey"));
        }

        public TClause Find<TClause>() where TClause : SecurityKeyIdentifierClause
        {
            TClause clause;
            if (!TryFind<TClause>(out clause))
            {
                //throw LogHelper.LogExceptionMessage(new ArgumentException(SR.GetString(SR.NoKeyIdentifierClauseFound, typeof(TClause)), "TClause"));
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("NoKeyIdentifierClauseFound"));
            }
            return clause;
        }

        public IEnumerator<SecurityKeyIdentifierClause> GetEnumerator()
        {
            return this.clauses.GetEnumerator();
        }

        public override string ToString()
        {
            using (StringWriter writer = new StringWriter(CultureInfo.InvariantCulture))
            {
                writer.WriteLine("SecurityKeyIdentifier");
                writer.WriteLine("    (");
                writer.WriteLine("    Count = {0}{1}", this.Count, this.Count > 0 ? "," : "");
                for (int i = 0; i < this.Count; i++)
                {
                    writer.WriteLine("    Clause[{0}] = {1}{2}", i, this[i], i < this.Count - 1 ? "," : "");
                }
                writer.WriteLine("    )");
                return writer.ToString();
            }
        }

        public bool TryFind<TClause>(out TClause clause) where TClause : SecurityKeyIdentifierClause
        {
            for (int i = 0; i < this.clauses.Count; i++)
            {
                TClause c = this.clauses[i] as TClause;
                if (c != null)
                {
                    clause = c;
                    return true;
                }
            }
            clause = null;
            return false;
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return this.GetEnumerator();
        }
    }
}

