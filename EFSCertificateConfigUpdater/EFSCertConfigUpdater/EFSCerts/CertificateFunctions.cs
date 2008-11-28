using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ParanoidMike
{
    class CertificateFunctions
    {

        // All Microsoft OIDs are documented here: http://support.microsoft.com/default.aspx/kb/287547

        /// <summary>
        /// Microsoft calls this the "v1 template": http://groups.google.com/group/microsoft.public.platformsdk.security/msg/dfbcd18553da98e4?dmode=source
        /// </summary>
        const string OID_ENROLL_CERTTYPE_EXTENSION = "1.3.6.1.4.1.311.20.2";

        /// <summary>
        /// Microsoft calls this "v2 template"
        /// </summary>
        const string OID_CERTIFICATE_TEMPLATE = "1.3.6.1.4.1.311.21.7";


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
        public static bool DoesCertificateHaveSpecifiedEku(X509Certificate2 x509Cert, 
                                                           string oid)
        {
            // First test input to ensure it's not null
            if ((x509Cert != null) || (oid != null))
            {
                // Set initial value to false, only to be set to true if the specified EKU is detected
                bool _returnvalue = false;
                foreach (X509Extension _extension in x509Cert.Extensions)
                {
                    if (_extension.Oid.FriendlyName == "Enhanced Key Usage")
                    {
                        X509EnhancedKeyUsageExtension ext = (X509EnhancedKeyUsageExtension)_extension;
                        OidCollection _oids = ext.EnhancedKeyUsages;
                        foreach (Oid _oid in _oids)
                        {
                            if (_oid.Value == oid)
                            {
                                _returnvalue = true;
                            }
                        }
                    }
                }
                // Once all extensions have been exhausted, return the resulting boolean state
                return _returnvalue;

            }
            // Throw a NullReferenceException because one of the parameters is null
            throw new ApplicationException("One of the parameters is null and could not be processed");

        }

        /// <summary>
        /// Function determines whether the selected digital certificate was enrolled from a specified Certificate Template.
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
        public static bool IsCertificateEnrolledFromSpecifiedTemplate(X509Certificate2 x509Cert, 
                                                                      string template)
        {
            bool _returnvalue = false;

            // Parse this certificate's fields to determine if there is a Certificate Template Information field
            //   If this certificate lacks such a field, then return false
            //   If this certificate includes this field, then it *may* be a v2 certificate

            X509ExtensionCollection _extensions = x509Cert.Extensions;

            foreach (X509Extension _extension in _extensions)
            {
                // This determines that the digital certificate was enrolled from a v2 certificate template
                Trace.WriteLine("The extension's OID is          " + 
                                _extension.Oid.Value + 
                                Environment.NewLine);
                Trace.WriteLine("The extension's FriendlyName is " + 
                                _extension.Oid.FriendlyName + 
                                Environment.NewLine);
                if (_extension.Oid.Value == OID_ENROLL_CERTTYPE_EXTENSION)
                {
                    // This should determine whether this certificate extension identifies the intended template
                    // NOTE: the FriendlyName can only be resolved when the AD (or CA?) is accessible to the client - otherwise, just the OID is stored in the cert
                    if (_extension.Oid.FriendlyName == template)
                    {
                        _returnvalue = true;
                    }
                }
            }

            return _returnvalue;
        }

        /// <summary>
        /// Function determines whether the selected digital certificate was enrolled from a v2 certificate template.
        /// </summary>
        /// <param name="x509Cert">
        /// A digital certificate, passed in as an X509Certificate2 object.
        /// </param>
        /// <returns>
        /// Returns "true" if evidence suggests the use of a v2 certificate template
        /// Returns "false" if evidence is against this theory
        /// </returns>
        public static bool IsCertificateEnrolledFromV2Template(X509Certificate2 x509Cert)
        {
            // Parse this certificate's fields to determine if there is a field matching the OID "OID_ENROLL_CERTTYPE_EXTENSION"
            //   If this certificate lacks such a field, then it is definitely not a v2 certificate
            //   If this certificate includes this field, then it is a v2 certificate

            bool _returnvalue = false;

            X509ExtensionCollection extensions = x509Cert.Extensions;

            foreach (X509Extension extension in extensions)
            {
                if (extension.Oid.Value == OID_CERTIFICATE_TEMPLATE)
                {
                    // If there is a match, then this certificate was enrolled from a v2 certificate template
                    _returnvalue = true;
                    return _returnvalue;
                }
            }

            return _returnvalue;
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
        public static bool IsCertificateIssuedBySpecifiedCA(X509Certificate2 x509Cert, 
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
                //x509Cert.Archived set;
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

    }
}