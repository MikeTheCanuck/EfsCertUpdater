﻿using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ParanoidMike
{
    class EFSCertificateFunctions
    {
        const string subKey =    @"Software\Microsoft\Windows NT\CurrentVersion\EFS\CurrentKeys";
        const string valueName = "CertificateHash";

        /// <summary>
        /// This function compares the hash calculated for the current certificate to the EFS CertificateHash Registry value for the current user.
        /// </summary>
        /// <param name="CertificateThumbprint">
        /// The "Thumbprint" value calculated for the current certificate.
        /// </param>
        /// <param name="_certificateHashValue">
        /// The data from the CertificateHash Registry value for the current user.
        /// </param>
        /// <returns>
        /// True if the two values match.
        /// False if the two values do not match.
        /// </returns>
        public static bool DoesCertificateMatchEfsCertificateHashRegistryValue(byte[] CertificateThumbprint, 
                                                                               byte[] _certificateHashValue)
        {
            // First test the input values to make sure they're not null
            if ((CertificateThumbprint != null) || (_certificateHashValue != null))
            {
                try
                {
                    if (Utility.DoByteArraysMatch(CertificateThumbprint, _certificateHashValue))
                    {
                        Trace.WriteLine("The user's EFS certificate configuration does not need to be updated." + 
                                        Environment.NewLine);
                        return true;
                    }

                    else
                    {
                        Trace.WriteLine("The user's EFS certificate configuration will be updated." + 
                                        Environment.NewLine);
                        //Console.WriteLine("The original EFS CertificateHash registry setting was one value" + Environment.NewLine); // + _certificateHashValue + Environment.NewLine);
                        //Console.WriteLine("The new EFS CertificateHash setting will be something else" + Environment.NewLine); // + CertificateThumbprint + Environment.NewLine);
                        return false;
                    }
                }

                // TODO: figure out what kind of Exception(s) would occur when the Registry value doesn't exist
                // TODO: Exception for when the user doesn't have permission to the Registry key
                catch (NotSupportedException)
                {
                    // Keep passing the error back up to the original caller
                    throw;
                }

            }
            // Throw an Exception because one of the arrays is null
            // TODO: update ApplicationException with a more appropriate (custom?) Exception
            throw new ApplicationException("One of the arrays is null and could not be processed");
        }

        /// <summary>
        /// This function returns a byte array representation of the current CertificateHash Registry value, 
        /// so that it can be compared with X509Certificate2.GetCertHashString().
        /// </summary>
        /// <returns>
        /// The value of the CertificateHash from the current user's HKCU Registry hive.
        /// </returns>
        public static byte[] GetCertificateHashValueFromRegistry()
        {
            /* 
             * TODO: If the user's CertificateHash Registry setting is not found, then throw a custom exception
             * indicating that no hash is currently stored (implying that EFS has never been used by this user - 
             * or that the user hasn't used EFS/accessed an EFS'd file since their current user profile was created).
             */

            // NOTE: CertificateHash is exactly the same as the Thumbprint value that is stored in the Cert http://support.microsoft.com/kb/295680
            // NOTE: Certificate thumbprint is the SHA-1 hash of the digital certificate's public key (i.e. 160 bits) http://msdn2.microsoft.com/en-us/library/Aa376064.aspx
            // NOTE: or the Cert thumbprint is the SHA-1 hash of the binary DER cert blob http://groups.google.com/group/microsoft.public.platformsdk.security/msg/1f126505c454662d

            // Declare a variable to hold the current CertificateHash Registry setting
            byte[] _certificateHashRegistryValue;

            // Confirm that the CertificateHash Registry value exists
            try
            {
                _certificateHashRegistryValue = Utility.GetRegistryValue(true, 
                                                                         subKey, 
                                                                         valueName);

                // NOTE: Previously I tried to derive a string that can be compared to X509Certificate2.GetCertHashString()
                // e.g. "C480C669C22270BACD51E65C6AC28596DFF93D0D"
                // Note: I tried this conversion code I found on the 'Net http://forums.microsoft.com/MSDN/ShowPost.aspx?PostID=1656747&SiteId=1, but couldn't get it to work

                return _certificateHashRegistryValue;
            }

            catch (ArgumentNullException e)
            {
                // If the Registry setting hasn't been selected correctly, this error will be needed

                // TODO: confirm whether this is the exception we receive if the Registry key and/or value does not exist?  If not, catch that exception separately.
                Trace.WriteLine("Error = " + 
                                e.Message + 
                                Environment.NewLine);
                Trace.WriteLine("Error data = " + 
                                e.Data + 
                                Environment.NewLine);

                throw;
            }

            catch (Exception e)
            // TODO: figure out which kind of exception needs to be caught here
            {
                // If Windows throws an error indicating the Registry value does not exist, then we'll know that we can create it safely
                Trace.WriteLine("Error = " + 
                                e.Message + 
                                Environment.NewLine);
                Trace.WriteLine("Error data = " + 
                                e.Data + 
                                Environment.NewLine);
                Trace.WriteLine("Inner exception = " + 
                                e.InnerException + 
                                Environment.NewLine);

                // TODO: figure out what to put into this throw statement, if anything
                throw;
            }
        }

        /// <summary>
        /// Compares the Thumbprint of the certificate to the value of the CertificateHash registry setting.
        /// This determines which certificate is actively being used by the EFS component driver.
        /// </summary>
        /// <param name="x509Cert">
        /// A digital certificate, passed in as an X509Certificate2 object.
        /// </param>
        /// <returns>
        /// True if the certificate is the one currently configured for use in the current user's CertificateHash Registry setting.
        /// False if the certificate is *not* the one currently configured for use in the current user's CertificateHash Registry setting.
        /// </returns>
        public static bool IsCertificateTheCurrentlyConfiguredEFSCertificate(X509Certificate2 x509Cert)
        {
            // Create a variable to store the passed-in certificate's thumbprint value
            byte[] _certificateThumbprint;

            // Create a variable to store the current CertificateHash registry value
            byte[] _certificateHashRegistryValue;

            // First test whether the CertificateHash Registry value even exists - if it doesn't, by definition there cannot be a match
            _certificateHashRegistryValue = EFSCertificateFunctions.GetCertificateHashValueFromRegistry();

            if (_certificateHashRegistryValue == null)
            {
                return false;
            }

            /*
             * TODO: what if the CertificateHash Registry value is malformed - e.g. it somehow got written with bad data, or 
             *       is stored as an incorrect data type (e.g. REG_DWORD)?
             *       Q: what is considered "good, safe input"?
             *       1. REG_BINARY values >>>  Does the Get...() function automatically fail if the data type is not REG_BINARY?
             */


            // Extract the passed-in certificate's thumbprint value
            _certificateThumbprint = x509Cert.GetCertHash();

            // Console.WriteLine("Current cert hash in Registry   = " + GetCertificateHashValueFromRegistry() + Environment.Newline);

            try
            {
                // Validating whether the current certificate is the same one currently configured for the current user's EFS CertificateHash Registry value
                if (EFSCertificateFunctions.DoesCertificateMatchEfsCertificateHashRegistryValue(_certificateThumbprint, EFSCertificateFunctions.GetCertificateHashValueFromRegistry()))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (NotSupportedException)
            {
                // TODO: handle the exception to express that array sizes were mismatched
                throw;
            }
        }

        /// <summary>
        /// This function will write the binary hash value for the specified Certificate to the Registry location needed to support EFS.
        /// </summary>
        /// <param name="x509Cert">
        /// A digital certificate, passed in as an X509Certificate2 object.
        /// </param>
        public static bool WriteCertificateHashToRegistry(X509Certificate2 x509Cert)
        {
            // Write this certificate's hash value to the CertificateHash Registry setting
            try
            {
                Utility.SetRegistryValue(true, 
                                         subKey, 
                                         valueName, 
                                         x509Cert.GetCertHash());
            }

            catch (CryptographicException)
            {
                // This exception = "m_safeCertContext is an invalid handle."
                throw;
            }

            catch (UnauthorizedAccessException)
            {
                // This exception = "Cannot write to the registry key."
                throw;
            }

            catch (Exception e)
            {
                // No idea what else could go wrong, so let's just spew the exception details to the command line for now.
                Console.WriteLine(e.Message + 
                                  Environment.NewLine);
                Console.WriteLine(e.StackTrace + 
                                  Environment.NewLine);
                throw;
            }

            // Tell the calling code that CertificateHash value has successfully been updated
            return true;
        }

    }
}