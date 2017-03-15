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
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Saml
{

    public class SamlAudienceRestrictionCondition : SamlCondition
    {
        // TODO - should this be strings?
        Collection<Uri> _audiences = new Collection<Uri>();

        // TODO - remove this internal
        internal SamlAudienceRestrictionCondition()
        {
        }

        public SamlAudienceRestrictionCondition(IEnumerable<Uri> audiences)
        {
            if (audiences == null)
                throw LogHelper.LogArgumentNullException(nameof(audiences));

            foreach (Uri audience in audiences)
            {
                if (audience == null)
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLEntityCannotBeNullOrEmpty, XD.SamlDictionary.Audience.Value"));

                _audiences.Add(audience);
            }

            if (_audiences.Count == 0)
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAudienceRestrictionShouldHaveOneAudience"));
        }

        public ICollection<Uri> Audiences
        {
            get { return _audiences; }
        }
    }
}
