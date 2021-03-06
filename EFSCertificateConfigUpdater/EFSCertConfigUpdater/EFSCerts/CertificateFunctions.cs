﻿//-----------------------------------------------------------------------
// <copyright file="CertificateFunctions.cs" company="ParanoidMike">
//     Copyright (c) ParanoidMike. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace ParanoidMike
{
    using System;
    using System.Diagnostics;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Provides a set of functions for manipulating digital certificates.
    /// </summary>
    public static class CertificateFunctions
    {
        // All Microsoft OIDs are documented here: http://support.microsoft.com/default.aspx/kb/287547

        /// <summary>
        /// Microsoft calls this the "v1 template": http://groups.google.com/group/microsoft.public.platformsdk.security/msg/dfbcd18553da98e4?dmode=source
        /// </summary>
        private const string OID_ENROLL_CERTTYPE_EXTENSION = "1.3.6.1.4.1.311.20.2";

        /// <summary>
        /// Microsoft calls this "v2 template"
        /// </summary>
        private const string OID_CERTIFICATE_TEMPLATE = "1.3.6.1.4.1.311.21.7";

        /// <summary>
        /// Determines whether the certificate includes the EKU (Enhanced Key Usage) specified by the passed-in OID.
        /// </summary>
        /// <param name="x509Cert">
        /// A digital certificate, passed in as an X509Certificate2 object.
        /// </param>
        /// <param name="oid">
        /// OID to be tested, in string form.
        /// </param>
        /// <returns>
        /// True if the OID is included in the certificate.
        /// False if the OID is not found in the certificate.
        /// </returns>
        public static bool DoesCertificateHaveSpecifiedEku(
            X509Certificate2 x509Cert, 
            string oid)
        {
            // First test input to ensure it's not null
            if ((x509Cert != null) || (oid != null))
            {
                // Set initial value to false, only to be set to true if the specified EKU is detected
                bool returnValue = false;
                foreach (X509Extension extension in x509Cert.Extensions)
                {
                    if (extension.Oid.FriendlyName == "Enhanced Key Usage")
                    {
                        X509EnhancedKeyUsageExtension ext = (X509EnhancedKeyUsageExtension)extension;
                        OidCollection oids = ext.EnhancedKeyUsages;
                        foreach (Oid objectIdentifier in oids)
                        {
                            if (objectIdentifier.Value == oid)
                            {
                                returnValue = true;
                            }
                        }
                    }
                }

                // Once all extensions have been exhausted, return the resulting boolean state
                return returnValue;
            }

            // Throw a NullReferenceException because one of the parameters is null
            if (x509Cert == null)
            {
                throw new ArgumentNullException("x509Cert");
            }
            else
            {
                throw new ArgumentNullException("oid");
            }
        }

        /// <summary>
        /// Function determines whether the selected digital certificate was enrolled from a specified Certificate Template.
        /// Certificates enrolled from Certificate Templates are known as either "v1 certificates" or "v2 certificates" (depending on the template Version).
        /// </summary>
        /// <param name="x509Cert">
        /// A digital certificate, passed in as an X509Certificate2 object.
        /// </param>
        /// <param name="template">
        /// The certificate template to compare to the certificate.
        /// </param>
        /// <returns>
        /// Returns "true" if Certificate Template Information field matches specified string.
        /// Returns "false" if Certificate Template Information field does not exist or does not match.
        /// </returns>
        public static bool IsCertificateEnrolledFromSpecifiedTemplate(
            X509Certificate2 x509Cert, 
            string template)
        {
            bool returnValue = false;

            X509ExtensionCollection extensions = x509Cert.Extensions;

            foreach (X509Extension extension in extensions)
            {
                // This determines that the digital certificate was enrolled from a v2 certificate template
                Trace.WriteLine("The extension's OID is          " + 
                                extension.Oid.Value + 
                                Environment.NewLine);
                Trace.WriteLine("The extension's FriendlyName is " + 
                                extension.Oid.FriendlyName + 
                                Environment.NewLine);
                if (extension.Oid.Value == OID_ENROLL_CERTTYPE_EXTENSION)
                {
                    // This should determine whether this certificate extension identifies the intended template
                    // NOTE: the FriendlyName can only be resolved when the AD (or CA?) is accessible to the client - otherwise, just the OID is stored in the cert
                    if (extension.Oid.FriendlyName == template)
                    {
                        returnValue = true;
                    }
                }
            }

            return returnValue;
        }

        /// <summary>
        /// Function determines whether the selected digital certificate was enrolled from a v2 certificate template.
        /// </summary>
        /// <param name="x509Cert">
        /// A digital certificate, passed in as an X509Certificate2 object.
        /// </param>
        /// <returns>
        /// Returns "true" if evidence indicates enrollment from the use of a v2 certificate template.
        /// Returns "false" if evidence is against this theory.
        /// </returns>
        /// <remarks>
        /// This will currently look for a field matching the OID "OID_ENROLL_CERTTYPE_EXTENSION".
        /// </remarks>
        public static bool IsCertificateEnrolledFromV2Template(X509Certificate2 x509Cert)
        {
            bool returnValue = false;

            X509ExtensionCollection extensions = x509Cert.Extensions;

            foreach (X509Extension extension in extensions)
            {
                if (extension.Oid.Value == OID_CERTIFICATE_TEMPLATE)
                {
                    // If there is a match, then this certificate was enrolled from a v2 certificate template
                    returnValue = true;
                    return returnValue;
                }
            }

            return returnValue;
        }

        /// <summary>
        /// Determines whether the certificate was issued by the specified Certificate Authority.
        /// </summary>
        /// <param name="x509Cert">
        /// A digital certificate, passed in as an X509Certificate2 object.
        /// </param>
        /// <param name="certificateAuthorityIdentifier">
        /// String which uniquely identifies the Certificate Authority, which should be of the form x509Cert.IssuerName.ToString().
        /// </param>
        /// <returns>
        /// True if certificate was issued by the specified Certificate Authority.
        /// False if not.
        /// </returns>
        public static bool IsCertificateIssuedBySpecifiedCA(
            X509Certificate2 x509Cert, 
            string certificateAuthorityIdentifier)
        {
            // TODO: investigate whether there are other CA identifiers that would work better in other use cases than certificateAuthorityIdentifier             *       e.g. DNS name of CA, thumbprint of CA cert

            // TODO: verify if I've got the right formats of each of the DN's, since the comparison would also fail if the formats aren't the same
            if (x509Cert.IssuerName.ToString() != certificateAuthorityIdentifier)
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        /// <summary>
        /// Examine a digital certificate to determine whether it is self-signed.
        /// </summary>
        /// <param name="x509Cert">
        /// A digital certificate, passed in as an X509Certificate2 object.
        /// </param>
        /// <returns>
        /// True if certificate is self-signed.
        /// False if certificate is not self-signed.
        /// </returns>
        public static bool IsCertificateSelfSigned(X509Certificate2 x509Cert)
        {
            // If Issuer = Subject, then it's a so-called self-signed certificate
            if (x509Cert.IssuerName.Name == x509Cert.Subject)
            {
                return true;

                // Archive the self-signed certificate - it's not strictly necessary for this function, but it's a best practice  

                // TODO: re-enable this archiving code (and get it to actually invoke archiving, once ReadWrite access is enabled for the cert store)
                ////x509Cert.Archived set;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Determines whether the certificate is considered a valid certificate.
        /// Currently only tests that the certificate has not yet expired.
        /// </summary>
        /// <param name="x509Cert">
        /// A digital certificate, passed in as an X509Certificate2 object.
        /// </param>
        /// <returns>
        /// True if certificate is valid.
        /// False if the certificate is not valid.
        /// </returns>
        public static bool IsCertificateValid(X509Certificate2 x509Cert)
        {
            // Currently all the application needs to check for is whether the digital certificate has expired yet            
            return x509Cert.NotAfter > DateTime.Now;
        }

        /// <summary>
        /// Opens a handle to the user's MY certificate store (i.e. the Microsoft CryptoAPI user cert store).
        /// </summary>
        /// <returns>
        /// The user's MY certificate store, in the form of an x509Store object.
        /// </returns>
        public static X509Store OpenUserMyStore()
        {
            // Some of this code was cloned/inherited from http://msdn.microsoft.com/library/system.security.cryptography.x509certificates.x509certificate2ui.aspx and other various locations
            // Create a new instance of X509Store to associate with the user's My store
            X509Store myStore = new X509Store("MY", StoreLocation.CurrentUser);

            // Open the store read-only so as not to accidently munge my certs, and so as to NOT create a new store
            try
            {
                // TODO: (v2) Change this myStore.Open() call to ReadWrite when I'm ready to Archive existing certs and/or enroll for new Certificates
                myStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            }
            catch (Exception e)
            {
                // TODO: Find out what kind of exception is thrown when the store isn't available, and fill it in as a specific Exception  e.g. run this code with a restricted token using e.g. DropMyRights.exe
                Trace.WriteLine("Couldn't open your MY certificate store: error = " +
                  e.Message);

                Console.WriteLine("Couldn't open your MY certificate store: error = " +
                                  e.Message);
                throw; // TODO: examine this for a better throw option...
            }

            return myStore;
        }
    }
}