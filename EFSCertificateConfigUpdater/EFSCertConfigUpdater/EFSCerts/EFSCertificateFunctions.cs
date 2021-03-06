﻿//-----------------------------------------------------------------------
// <copyright file="EFSCertificateFunctions.cs" company="ParanoidMike">
//     Copyright (c) ParanoidMike. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace ParanoidMike
{
    using System;
    using System.Diagnostics;
    using System.Security;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Microsoft.Win32;
    using ParanoidMike;

    /// <summary>
    /// Provides a set of functions for manipulating EFS digital certificates and Windows configuration properties that support EFS.
    /// </summary>
    public static class EFSCertificateFunctions
    {
        #region Constants

        /// <summary>
        /// The OID that indicates the EFS Extended Key Usage.
        /// </summary>
        private const string EFS_EKU = "1.3.6.1.4.1.311.10.3.4";

        /// <summary>
        /// The full path to the Registry key that contains user EFS certificate configuration settings.
        /// </summary>
        private const string FullKey =   @"HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\EFS\CurrentKeys";

        /// <summary>
        /// The subkey (from the HKCU hive) where the user's EFS certificate configuration settings are stored.
        /// </summary>
        private const string SubKey =    @"Software\Microsoft\Windows NT\CurrentVersion\EFS\CurrentKeys";

        /// <summary>
        /// The name of the Registry value which contains the user's EFS certificate configuration.
        /// </summary>
        private const string ValueName =  "CertificateHash";

        #endregion

        #region Public Methods

        /// <summary>
        /// Determines whether the certificate is an EFS certificate or not.
        /// </summary>
        /// <param name="x509Cert">
        /// A digital certificate, passed in as an X509Certificate2 object.
        /// </param>
        /// <returns>
        /// True if the certificate is an EFS certificate.
        /// False if the certificate is *not* an EFS certificate.</returns>
        public static bool IsCertificateAnEfsCertificate(X509Certificate2 x509Cert)
        {
            bool returnValue = false;

            if (CertificateFunctions.DoesCertificateHaveSpecifiedEku(x509Cert, EFS_EKU))
            {
                returnValue = true;
            }

            return returnValue;
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
            byte[] certificateThumbprint;

            // Create a variable to store the current CertificateHash registry value
            byte[] certificateHashRegistryValue;

            // First test whether the CertificateHash Registry value even exists - if it doesn't, by definition there cannot be a match
            certificateHashRegistryValue = EFSCertificateFunctions.GetCertificateHashValueFromRegistry();

            if (certificateHashRegistryValue == null)
            {
                return false;
            }

            /*
             * TODO: what if the CertificateHash Registry value is malformed - e.g. it somehow got written with bad data, or 
             *       is stored as an incorrect data type (e.g. REG_DWORD)?
             *       Q: what is considered "good, safe input"?
             *       1. REG_BINARY values >>>  Does the Get...() function automatically fail if the data type is not REG_BINARY?
             *       2. return value is always byte[20] in size
             */

            // Extract the passed-in certificate's thumbprint value
            certificateThumbprint = x509Cert.GetCertHash();

            //// Console.WriteLine("Current cert hash in Registry   = " + GetCertificateHashValueFromRegistry() + Environment.Newline);

            try
            {
                // Validating whether the current certificate is the same one currently configured for the current user's EFS CertificateHash Registry value
                if (EFSCertificateFunctions.DoesCertificateMatchEfsCertificateHashRegistryValue(certificateThumbprint, EFSCertificateFunctions.GetCertificateHashValueFromRegistry()))
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
        /// Updates the user's EFS configuration settings with the newly-selected EFS certificate, and logs the result (success or exceptions).
        /// </summary>
        /// <param name="efsCertificate">
        /// A digital certificate, passed in as an X509Certificate2 object.
        /// </param>
        /// <returns>
        /// True if the EFS configuration update is successful.
        /// False if the EFS configuration update is unsuccessful.
        /// </returns>
        public static bool UpdateUserEfsConfiguration(X509Certificate2 efsCertificate)
        {
            bool returnValue;

            try
            {
                // WriteEfsCertificateHashToRegistry() returns true only if the CertificateHash value is successfully updated
                returnValue = WriteEfsCertificateHashToRegistry(efsCertificate);

                if (returnValue)
                {
                    Trace.WriteLine("The user's EFS configuration has been updated with a suitable digital certificate." +
                                    Environment.NewLine);
                }
            }
            catch (CryptographicException e)
            {
                Trace.WriteLine("Cryptographic Exception when trying to write CertificateHash value to the Registry:" +
                                Environment.NewLine);
                Trace.WriteLine(e.Message +
                                Environment.NewLine);
                Trace.WriteLine(e.InnerException +
                                Environment.NewLine);
                returnValue = false;
            }

            return returnValue;
        }
        
        #endregion

        #region Private Methods

        /// <summary>
        /// This function compares the hash calculated for the current certificate to the EFS CertificateHash Registry value for the current user.
        /// </summary>
        /// <param name="certificateThumbprint">
        /// The "Thumbprint" value calculated for the current certificate.
        /// </param>
        /// <param name="certificateHashValue">
        /// The data from the CertificateHash Registry value for the current user.
        /// </param>
        /// <returns>
        /// True if the two values match.
        /// False if the two values do not match.
        /// </returns>
        private static bool DoesCertificateMatchEfsCertificateHashRegistryValue(
            byte[] certificateThumbprint,
            byte[] certificateHashValue)
        {
            // First test the input values to make sure they're not null
            if ((certificateThumbprint != null) || (certificateHashValue != null))
            {
                try
                {
                    if (Utility.DoByteArraysMatch(certificateThumbprint, certificateHashValue))
                    {
                        Trace.WriteLine("Result of examination: The user's EFS certificate configuration does not need to be updated." +
                                        Environment.NewLine);
                        return true;
                    }
                    else
                    {
                        Trace.WriteLine("The user's EFS certificate configuration will be updated." +
                                        Environment.NewLine);
                        return false;
                    }
                }
                catch (NotSupportedException)
                {
                    // TODO: figure out what kind of Exception(s) would occur when the Registry value doesn't exist
                    // TODO: Exception for when the user doesn't have permission to the Registry key
                    // Keep passing the error back up to the original caller
                    throw;
                }
            }

            // Throw an ArgumentNullException because one of the arrays is null
            if (certificateThumbprint == null)
            {
                throw new ArgumentNullException("certificateThumbprint");
            }
            else
            {
                throw new ArgumentNullException("certificateHashValue");
            }
        }

        /// <summary>
        /// This function returns a byte array representation of the current CertificateHash Registry value, 
        /// so that it can be compared with X509Certificate2.GetCertHashString().
        /// </summary>
        /// <returns>
        /// The value of the CertificateHash from the current user's HKCU Registry hive.
        /// </returns>
        private static byte[] GetCertificateHashValueFromRegistry()
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
            byte[] certificateHashRegistryValue;

            // Confirm that the CertificateHash Registry value exists
            try
            {
                // HACK: I've added an explicit Cast to byte[] for Registry.GetValue() because the "default value" can't be immediately converted from object to byte[]
                // If this doesn't work, I could try again with the more complex (but more flexible) RegistryKey class.
                certificateHashRegistryValue = (byte[])Registry.GetValue(FullKey, ValueName, null);
                ////certificateHashRegistryValue = Utility.GetRegistryValue(true, 
                ////                                                         SubKey, 
                ////                                                         ValueName);

                // NOTE: Previously I tried to derive a string that can be compared to X509Certificate2.GetCertHashString()
                // e.g. "C480C669C22270BACD51E65C6AC28596DFF93D0D"
                // Note: I tried this conversion code I found on the 'Net http://forums.microsoft.com/MSDN/ShowPost.aspx?PostID=1656747&SiteId=1, but couldn't get it to work
                return certificateHashRegistryValue;
            }
            catch (ArgumentException e)
            {
                // If the Registry setting hasn't been specified correctly, this exception will be thrown
                Trace.WriteLine("Error = " +
                                e.Message +
                                Environment.NewLine);
                Trace.WriteLine("Error data = " +
                                e.Data +
                                Environment.NewLine);

                throw;
            }
            catch (SecurityException e)
            {
                // TODO: figure out which kind of exception needs to be caught here
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
        /// This function will write the binary hash value for the specified Certificate to the Registry location needed to support EFS.
        /// </summary>
        /// <param name="x509Cert">
        /// A digital certificate, passed in as an X509Certificate2 object.
        /// </param>
        /// <returns>
        /// True if the update to the CertificateHash registry value is successful.
        /// False if the update to the CertificateHash registry value is unsuccessful.
        /// </returns>
        private static bool WriteEfsCertificateHashToRegistry(X509Certificate2 x509Cert)
        {
            // Write this certificate's hash value to the CertificateHash Registry setting
            try
            {
                Registry.SetValue(FullKey, ValueName, x509Cert.GetCertHash(), RegistryValueKind.Binary);
            }
            catch (CryptographicException)
            {
                // This exception = "m_safeCertContext is an invalid handle."
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                // This exception = "Cannot write to the registry key."
                // Most common cause: not calling OpenSubKey() with the writeable bit set = "True".  D'oh!
                // TODO: find a way to get the current application's executable name, rather than the Assembly's "full name"
                Trace.WriteLine("When attempting to update the user's CertificateHash registry setting, the app (" +
                                System.Reflection.Assembly.GetCallingAssembly().FullName +
                                ") encountered an UnauthorizedAccessException for the CurrentKeys Registry key." +
                                Environment.NewLine +
                                "The EFS certificate configuration has not been updated - please investigate and try again." +
                                Environment.NewLine);
                return false;
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
        
        #endregion
    }
}
