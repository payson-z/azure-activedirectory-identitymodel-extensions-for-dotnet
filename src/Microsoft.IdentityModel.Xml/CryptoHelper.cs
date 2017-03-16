//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    using System.Collections.Generic;
    using System.Reflection;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    static class CryptoHelper
    {
        static RandomNumberGenerator random;

        /// <summary>
        /// Provides an integer-domain mathematical operation for 
        /// Ceiling( dividend / divisor ). 
        /// </summary>
        /// <param name="dividend"></param>
        /// <param name="divisor"></param>
        /// <returns></returns>
        public static int CeilingDivide(int dividend, int divisor)
        {
            int remainder, quotient;

            remainder = dividend % divisor;
            quotient = dividend / divisor;

            if (remainder > 0)
            {
                quotient++;
            }

            return quotient;
        }

        public static RandomNumberGenerator RandomNumberGenerator
        {
            get
            {
                if (random == null)
                {
                    random = new RNGCryptoServiceProvider();
                }
                return random;
            }
        }

        // TODO - this may be handy
        //public static byte[] GenerateDerivedKey(byte[] key, string algorithm, byte[] label, byte[] nonce, int derivedKeySize, int position)
        //{
        //    if ((algorithm != SecurityAlgorithms.Psha1KeyDerivation) && (algorithm != SecurityAlgorithms.Psha1KeyDerivationDec2005))
        //    {
        //        throw LogHelper.ExceptionUtility.ThrowHelperWarning(new InvalidOperationException(SR.GetString(SR.UnsupportedKeyDerivationAlgorithm, algorithm)));
        //    }
        //    return new Psha1DerivedKeyGenerator(key).GenerateDerivedKey(label, nonce, derivedKeySize, position);
        //}

        /// <summary>
        /// This generates the entropy using random number. This is usually used on the sending 
        /// side to generate the requestor's entropy.
        /// </summary>
        /// <param name="data">The array to fill with cryptographically strong random nonzero bytes.</param>
        public static void GenerateRandomBytes(byte[] data)
        {
            RandomNumberGenerator.GetNonZeroBytes(data);
        }

        /// <summary>
        /// This method generates a random byte array used as entropy with the given size. 
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <returns></returns>
        public static byte[] GenerateRandomBytes(int sizeInBits)
        {
            int sizeInBytes = sizeInBits / 8;
            if (sizeInBits <= 0)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("sizeInBits"));
            }
            else if (sizeInBytes * 8 != sizeInBits)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException("sizeInBits"));
            }

            byte[] data = new byte[sizeInBytes];
            GenerateRandomBytes(data);

            return data;
        }
    }
}



