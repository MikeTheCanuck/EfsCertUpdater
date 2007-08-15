using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using System.Text;
using Microsoft.Win32;
using MikeSL;

// TODO: restrict this down to just PathDiscovery & Write for the user's LOCALAPPDATA folder
[assembly:FileIOPermission(SecurityAction.RequestMinimum, AllLocalFiles=FileIOPermissionAccess.AllAccess)]
[assembly:RegistryPermission(SecurityAction.RequestMinimum, ViewAndModify=@"HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\EFS\CurrentKeys")]
// TODO: expand these permissions when EFS cert archiving is enabled
[assembly:StorePermission(SecurityAction.RequestMinimum, OpenStore=true, EnumerateCertificates=true)]

namespace EFSConfiguration
{
    class Program
    {
        const string subKey = @"Software\Microsoft\Windows NT\CurrentVersion\EFS\CurrentKeys";
        const string valueName = "CertificateHash";
        const string EFS_EKU =                       "1.3.6.1.4.1.311.10.3.4";
        const string OID_ENROLL_CERTTYPE_EXTENSION = "1.3.6.1.4.1.311.20.2"; // Microsoft calls this "v1 template" http://groups.google.com/group/microsoft.public.platformsdk.security/msg/dfbcd18553da98e4?dmode=source
        // TODO: Confirm with Microsoft whether ...21.7 or ...21.8 is the current v2 cert template OID - v2 certs from Intel CA have ...21.8 OID
        const string OID_CERTIFICATE_TEMPLATE =      "1.3.6.1.4.1.311.21.7"; // Microsoft calls this "v2 template"

        // Boolean tracks whether the CertificateHash Registry value is already populated with an acceptable certificate
        static bool CertificateHashValueIsOK;
        
        // Boolean tracks whether the CertificateHash Registry value has been updated by this application
        static bool CertificateHashValueUpdated;

        // Variable to trace whatever exit code is necessary to send to StdOut
        static int ExitCode;

        // Command line arguments
        static string CertificateTemplateName; //TODO: Confirm whether the template name exists in the certificates as a string, or only as an OID?
        static string IssuingCAIdentifier;
        static bool LimitToV2Only;

        /* 
         * Usage behaviour for this application:
         * 0 arguments = select the first non-self-signed EFS certificate
         * 1 argument  = select the first non-self-signed EFS certificate enrolled from the specified certificate template
         * 2 arguments = select the first non-self-signed EFS certificate enrolled from the specified cert template and CA
         */

        static void Main(string[] args)
        {
            /*
             * Purpose of this application: automate the migration of a user's current EFS certificate from a self-signed 
             * EFS certificate to a CA-issued EFS certificate.  This will ensure that the organization has the ability to 
             * recover the user's private key in the unlikely event that the user's private key gets deleted, the hard disk
             * fails or the user's Profile becomes unavailable.
            
             * This supports a recovery process that is complementary to the more traditional approach of recovering EFS files using
             * the Data Recovery Agent keys defined through Group Policy.
             * 
             * The application may optionally take as an argument the name of the Certificate Template (from which the preferred 
             * EFS certificate was issued) as a command-line parameter, or it may support the ability to read that value from the 
             * Registry (as defined and distributed through Group Policy).  This functionality hasn't been decided yet.
             */

            // If the application has no arguments passed in, then operate without; otherwise, parse those arguments.
            if (args.Length > 0)
            {
                ParseArguments(args) ;
            }

            // Setup a trace log for capturing information on what the application is doing
            Utility.AddTraceLog("EFSConfigUpdate", "EFSConfigUpdateTraceLog.txt");
            // Write the date & time to the trace log
            Trace.WriteLine("Tracing started at " + DateTime.Now.ToString());

            // Variable represents the certificate selected by this application to configure as the active EFS certificate
            // TODO: initialize with a dummy value or some other way to get around the problem that new X509Certificate2() leads to a CryptographicException
            X509Certificate2 EfsCertificateToUse = new X509Certificate2();
            EfsCertificateToUse = null;

            // Some of this code was cloned/inherited from http://msdn2.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509certificate2ui(vs.80).aspx and other various locations
            // Create a new instance of X509Store to associate with the user's My store
            X509Store MyStore = new X509Store("MY", StoreLocation.CurrentUser) ;

            // Open the store read-only so as not to accidently munge my certs, and do NOT create a new store
            try
            {
                // TODO: (v2) Change this MyStore.Open() call to ReadWrite when I'm ready to Archive existing certs and/or enroll for new Certificates
                MyStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            }

            catch (Exception e)
                // TODO: Find out what kind of exception is thrown when the store isn't available, and fill it in as a specific Exception
                //       e.g. run this code with a restricted token using e.g. DropMyRights.exe
            {
                Console.WriteLine("Couldn't open your MY certificate store: error = " + e.Message) ;
                throw; // TODO: examine this for a better throw option...
            }
            
            /* 
             * Create a collection to enumerate the existing Certs in the MY store, and perform a Cast.
             * (Note to self: I don't know if I'm casting from or to the MyStore.Certificates collection.)
             */
            X509Certificate2Collection UserCerts = (X509Certificate2Collection)MyStore.Certificates;
            
            /* 
             * There are two potential approaches for finding the CA-issued EFS certificate(s):
             * 
             * 1. Find all certificates that contain the EFS EKU, then examine those certificates for issuer and/or Certificate 
             * Template.  Examining the issuer will let us find self-signed certificates and optionally archive them; examining 
             * the Certificate Template field will let us find the cert(s) issued by the target CA (where presumably key escrow 
             * has been performed).
             * 
             * 2. Find all the certificate(s) enrolled for a specified Certificate Template.
             * 
             * Unfortunately there is no measure on the client that will definitively indicate the cert and its keys are currently 
             * in the Keys Archive, but we usually make the assumption that any cert enrolled from a key-archival-enabled Cert Template 
             * had in fact had its keys archived (i.e. this is a success criteria for any enrollment from a Key Archival-required 
             * cert template).  If a cert was issued from a Key Archival-required cert template, it is likely a reasonable enough 
             * approximation of the desired state "my cert's private key is currently archived in the CA's database".
             */        

            // This is a very elegant method to narrow the user's certificates down to just the EFS certificates; unfortunately, it doesn't work
            //X509Certificate2Collection UserCertsWithEku = (X509Certificate2Collection)UserCerts.Find(X509FindType.FindByExtension, EFS_EKU, true);
            X509Certificate2Collection UserCertsWithEku = (X509Certificate2Collection)UserCerts.Find(X509FindType.FindByExtension, "Enhanced Key Usage", true);
                        
            /* 
             * Iterate through each user Certificate in this collection to 
             *   (a) identify an EFS cert that is valid for our purpose, 
             *   (b) determine whether the selected certificate matches the current EFS configuration, and if not,
             *   (c) update the EFS configuration.
             */

            foreach (X509Certificate2 x509Cert in UserCertsWithEku)
            {
                Trace.WriteLine("Certificate being examined:" + Environment.NewLine + 
                                "     Friendly Name: " + x509Cert.FriendlyName + Environment.NewLine +
                                "     Subject:       " + x509Cert.Subject + Environment.NewLine +
                                "     Thumbprint:    " + x509Cert.GetCertHashString() + Environment.NewLine);

                // Check the enrolled template version, IF this was specified at runtime
                if (LimitToV2Only == true)
                {
                    // Stop processing this certificate if it is NOT enrolled from a v2 certificate template, as that means 
                    //   there was no opportunity for a Microsoft CA to archive the keypair during enrollment
                    if (IsCertificateEnrolledFromV2Template(x509Cert) == false)
                    {
                        Trace.WriteLine("Certificate Rejected: certificate is enrolled from v2 certificate." + Environment.NewLine);
                        continue;
                    }
                    
                }


                // Stop processing this certificate if it is NOT Valid, so that the user doesn't end up encrypting files using an expired certificate
                else if (IsCertificateValid(x509Cert) == false)
                {
                    Trace.WriteLine("Certificate Rejected: certificate is not valid." + Environment.NewLine);
                    continue;
                }

                // Determine whether this certificate was enrolled from the specified Certificate Template
                // If this command-line parameter is not passed in, then we should skip this check
                else if (CertificateTemplateName != null)
                {
                    if (IsCertificateEnrolledFromSpecifiedTemplate(x509Cert, CertificateTemplateName) == false)
                    {
                        Trace.WriteLine("Certificate Rejected: certificate is not enrolled from template." + Environment.NewLine);
                        continue;
                    }
                }

                // TODO: re-enable this code once the CA-identifying argument is re-enabled
                //// If cert isn't self-signed, then it was issued by a Certificate Authority, but it could've been issued potentially by any CA
                //// Skip the cert if it was NOT issued by the intended CA
                //else if (IssuingCAIdentifier != null)
                //{
                //    (IsCertificateIssuedByIntendedCA(x509Cert, IssuingCAIdentifier) == false)
                //    {
                //        continue;
                //    }
                //}

                // Skip the cert if it is self-signed, since self-signed certificates can never automatically be archived by a 
                // Windows Server CA, and are not the focus of this application.                
                else if (IsCertificateSelfSigned(x509Cert) == true)
                {
                    Trace.WriteLine("Certificate Rejected: certificate is self-signed." + Environment.NewLine);
                    continue;
                }

                // Skip the cert if it DOES NOT contain the EFS EKU
                else if (DoesCertificateHaveSpecifiedEku(x509Cert, EFS_EKU) == false)
                {
                    Trace.WriteLine("Certificate Rejected: certificate does not contain the EFS EKU." + Environment.NewLine);
                    continue;
                }

                // Skip the cert if the user does NOT have a Private Key for this certificate (i.e. ensure that they didn't just accidently 
                // or unintentionally import an EFS certificate without its private key)
                else if (x509Cert.HasPrivateKey == false)
                {
                    Trace.WriteLine("Certificate Rejected: certificate has no matching private key." + Environment.NewLine);
                    continue;
                }

                /* 
                 * Determine whether the selected certificate is the currently configured EFS certificate.
                 * If so, then no further certificate action is necessary -- not for updating the user's CertificateHash 
                 * registry setting at least.
                 * 
                 * NOTE: this function should be the 2nd-to-last function in this foreach loop, so that we're only bailing 
                 * out of the loop if we've ensured that the cert meets all criteria AND happens to be the currently-configured cert.
                 */

                else if (IsSelectedCertificateTheCurrentlyConfiguredEFSCertificate(x509Cert))
                {
                    Trace.WriteLine("The selected certificate is already configured as the active EFS certificate." + Environment.NewLine);

                    CertificateHashValueIsOK = true;

                    // Stop checking any additional certificates, as the EFS cert currently in use has met all criteria
                    break;
                }

                else
                {
                    // This certificate is the candidate for use as the active EFS certificate
                    EfsCertificateToUse = x509Cert;

                    Trace.WriteLine("Certificate Accepted: \"" + x509Cert.FriendlyName + "\", serial number " + x509Cert.SerialNumber + "." + Environment.NewLine);

                    // Exit the loop to stop checking any additional certificates
                    /* 
                     * TODO: Now that we've selected a candidate certificate, we'll stop examining other certificates - just in case 
                     * there are two or more valid certs from the same Template. In the future, we'll continue examining all certs, and
                     * create an array of candidate certs from which we'll select the best one, and potentially archive the rest.
                     */
                    break;
                }

                /* 
                 * TODO: investigate implementing an advanced mode whereby this application doesn't just select the first matching certificate,
                 * but picks the "best" of those certs.  For example, the "best" of all matching certs could be the one with the latest
                 * "Valid From:" date, one (if any) that was issued from a v2 certificate template, and the one that has the longest RSA key.
                 * 
                 * TODO: (v3 or 4) If multiple certs were available, then Archive all other matching certificates.
                 */

            }

            // If the foreach loop has identified an EFS certificate, then update the user's CertificateHash registry value with the selected certificate's hash value
            if (CertificateHashValueIsOK != true && EfsCertificateToUse != null)
            {
                try
                {
                    WriteCertificateHashToRegistry(EfsCertificateToUse);
                }
                catch (CryptographicException e)
                {
                    ExitCode = 2;
                    Trace.WriteLine("Cryptographic Exception when trying to write CertificateHash value to the Registry:" + Environment.NewLine);
                    Trace.WriteLine(e.Message + Environment.NewLine);
                    Trace.WriteLine(e.InnerException + Environment.NewLine);
                }
            }

            // Were any suitable certificates identified?  If not, then indicate that no suitable certificates were found
            if (CertificateHashValueUpdated != true  && CertificateHashValueIsOK != true)
            {
                // TODO: send an error code to StdErr, for those IT admins that want to use this utility in a script (and prefer StdErr as a way to capture issues)
                // TODO: v2 - implement an Application Event Log message as well - try this sample code: http://www.thescarms.com/dotnet/EventLog.aspx
                Trace.WriteLine("The user has no EFS certificates suitable for updating their EFS configuration - please notify the administrator.");
                ExitCode = 1;

               /* 
                * TODO: (v3 or v4) The application could attempt to enroll a cert from the desired cert template, since no suitable certs were found.
                * If no such cert could be enrolled, then write an error to the Application Event Log.
                * 
                * Once this application implements the logic to enroll a suitable certificate, remove the reference to stdErr.
                */
            }

            // If the user ultimately succeeded in configuring a suitable EFS certificate, then ExitCode=0; otherwise, it should be some non-zero value.
            if (CertificateHashValueUpdated || CertificateHashValueIsOK)
            {
                ExitCode = 0;
            }

            if (CertificateHashValueUpdated == true)
            {
               /* 
                * TODO: (v3) Assuming the application has updated the CertificateHash Registry value with the thumbprint from the selected EFS cert, 
                * the application could optionally deal with updating all encrypted files - either by notifying the user 
                * that they should run the EFS Assistant tool or CIPHER.EXE /U, or by running one of these tools in the background.
                */
            }

            // Now that all certificate store operations have completed, close the Handle to the user's MY store.
            MyStore.Close();

            // TODO: report (Trace log, Application Event Log, non-zero Exit Code) if the user has no suitable certs but has CertificateHash configured (and report whether
            //       that configured cert is available in the user's cert store, is valid, and has a private key).

            // Close the Trace Log before exiting
            Utility.DisposeTraceLog("EFSConfigUpdateTraceLog.txt");

            // Lastly, terminate the application
            System.Environment.Exit(ExitCode);
        }


        private static void DisplayUsage()
        {
            {
                // Get the name of the process executable, so that updates to the process name are automatically mirrored
                Process _process = System.Diagnostics.Process.GetCurrentProcess();
                string _processName = _process.ProcessName;
                string _processNameUpperCase = _processName.ToUpper();

                Console.WriteLine("Updates your EFS configuration to use a centrally-managed EFS certificate." + Environment.NewLine);
                Console.WriteLine("" + Environment.NewLine);
                Console.WriteLine("  " + _processNameUpperCase + " [argument1]" + Environment.NewLine);
                Console.WriteLine("" + Environment.NewLine);
                Console.WriteLine("  " + _processNameUpperCase + " [argument1] [argument2]" + Environment.NewLine);
                Console.WriteLine("" + Environment.NewLine);
                Console.WriteLine("      [argument1] specifies the name of the desired Certificate Template" + Environment.NewLine);
                Console.WriteLine("                   e.g. \"Company EFS certificate version 2\"" + Environment.NewLine);
                Console.WriteLine("" + Environment.NewLine);
                Console.WriteLine("      [argument2] specifies the distinguished name of the Issuing CA" + Environment.NewLine);
                Console.WriteLine("                   e.g. \"IssuingCA01\"" + Environment.NewLine);
                Console.WriteLine("" + Environment.NewLine);
                Console.WriteLine("  Used without parameters, " + _processNameUpperCase + " will select the first non-self-" + Environment.NewLine);
                Console.WriteLine("  signed EFS certificate it finds in the user's personal certificate store." + Environment.NewLine);
                Console.WriteLine("" + Environment.NewLine);
            }
        }

        private static bool DoesCertificateHaveSpecifiedEku(X509Certificate2 x509Cert, string oid)
        {
            // Set initial value to false, only to be reset to true if the EFS EKU is detected
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

        private static bool DoesCertificateMatchCertificateHashRegistryValue(byte[] CertificateThumbprint, byte[] _certificateHashValue)
        {
            // Compare CertificateHash registry value to the calculated value for the selected certificate
            try
            {
                if (Utility.DoByteArraysMatch(CertificateThumbprint, _certificateHashValue))
                {
                    Trace.WriteLine("The user's EFS certificate configuration does not need to be updated." + Environment.NewLine);
                    return true;
                }

                else
                {
                    Trace.WriteLine("The user's EFS certificate configuration will be updated." + Environment.NewLine);
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

            catch (NullReferenceException)
            {
                // DoByteArraysMatch() threw exception because one of the arrays is null
                throw;
            }
        }

        private static byte[] GetCertificateHashValueFromRegistry()
        {
            /* 
             * TODO: If the user's CertificateHash Registry setting is not found, then throw a custom exception
             * indicating that no hash is currently stored (implying that EFS 
             * has never been used by this user - or that the user hasn't used EFS/accessed 
             * an EFS'd file since their current user profile was created).
             */

            // This function returns a byte array representation of the current CertificateHash Registry value, 
            // so that it can be compared with X509Certificate2.GetCertHashString().

            // NOTE: CertificateHash is exactly the same as the Thumbprint value that is stored in the Cert http://support.microsoft.com/kb/295680
            // NOTE: Certificate thumbprint is the SHA-1 hash of the digital certificate's public key (i.e. 160 bits) http://msdn2.microsoft.com/en-us/library/Aa376064.aspx
            // NOTE: or the Cert thumbprint is the SHA-1 hash of the binary DER cert blob http://groups.google.com/group/microsoft.public.platformsdk.security/msg/1f126505c454662d

            // Declare a variable to hold the current CertificateHash Registry setting
            byte[] _certificateHashRegistryValue;

            // Confirm that the CertificateHash Registry value exists
            try
            {
                //const string subKey = "Software\\Microsoft\\Windows NT\\CurrentVersion\\EFS\\CurrentKeys";
                //const string valueName = "CertificateHash";

                RegistryKey _hkcu = Registry.CurrentUser;
                RegistryKey _registrySubKey = _hkcu.OpenSubKey(subKey);

                _certificateHashRegistryValue = (byte[])_registrySubKey.GetValue(valueName, null);

                // NOTE: Previously I tried to derive a string that can be compared to X509Certificate2.GetCertHashString()
                // e.g. "C480C669C22270BACD51E65C6AC28596DFF93D0D"
                // Note: I tried this conversion code I found on the 'Net http://forums.microsoft.com/MSDN/ShowPost.aspx?PostID=1656747&SiteId=1, but couldn't get it to work

                _registrySubKey.Close();
                _hkcu.Close();

                return _certificateHashRegistryValue;

            }

            catch (ArgumentNullException e)
            {
                // If the Registry setting hasn't been selected correctly, this error will be needed

                // TODO: confirm whether this is the exception we receive if the Registry key and/or value does not exist?  If not, catch that exception separately.
                Trace.WriteLine("Error = " + e.Message + Environment.NewLine);
                Trace.WriteLine("Error data = " + e.Data + Environment.NewLine);

                throw ;
            }

            catch (Exception e)
            // TODO: figure out which kind of exception needs to be caught here
            {
                // If Windows throws an error indicating the Registry value does not exist, then we'll know that we can create it safely
                Trace.WriteLine("Error = " + e.Message + Environment.NewLine);
                Trace.WriteLine("Error data = " + e.Data + Environment.NewLine);
                Trace.WriteLine("Inner exception = " + e.InnerException + Environment.NewLine);

                // TODO: figure out what to put into this throw statement, if anything
                throw ;
            }
        }


        /// Function determines whether the selected digital certificate was enrolled from a specified Certificate Template
        ///    Returns "true" if Certificate Template Information field matches specified string
        ///    Returns "false" if Certificate Template Information field does not exist or does not match
        private static bool IsCertificateEnrolledFromSpecifiedTemplate(X509Certificate2 cert, string template)
        {

            bool _returnvalue = false;

            // Parse this certificate's fields to determine if there is a Certificate Template Information field
            //   If this certificate lacks such a field, then return false
            //   If this certificate includes this field, then it *may* be a v2 certificate

            X509ExtensionCollection _extensions = cert.Extensions;

            foreach (X509Extension _extension in _extensions)
            {
                // This determines that the digital certificate was enrolled from a v2 certificate template
                Trace.WriteLine("The extension's OID is          " + _extension.Oid.Value + Environment.NewLine);
                Trace.WriteLine("The extension's FriendlyName is " + _extension.Oid.FriendlyName + Environment.NewLine);
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


        /// Function determines whether the selected digital certificate was enrolled from a v2 certificate template
        ///    Returns "true" if evidence suggests the use of a v2 certificate template
        ///    Returns "false" if evidence is against this theory
        private static bool IsCertificateEnrolledFromV2Template(X509Certificate2 cert)
        {
            // Parse this certificate's fields to determine if there is a field matching the OID "OID_ENROLL_CERTTYPE_EXTENSION"
            //   If this certificate lacks such a field, then it is definitely not a v2 certificate
            //   If this certificate includes this field, then it is a v2 certificate

            bool _returnvalue = false;

            X509ExtensionCollection extensions = cert.Extensions;
            
            foreach (X509Extension extension in extensions)
                {
                    if (extension.Oid.Value == OID_ENROLL_CERTTYPE_EXTENSION)
                    {
                        // If there is a match, then this certificate was enrolled from a v2 certificate template
                        _returnvalue = true;
                    }
                }

            return _returnvalue;
        }
        
        private static bool IsCertificateIssuedByIntendedCA(X509Certificate2 cert, string certificateAuthorityIdentifier)
        {
            // TODO: investigate whether there are other CA identifiers that would work better in other use cases than certificateAuthorityIdentifier             *       e.g. DNS name of CA, thumbprint of CA cert
             
            // TODO: verify if I've got the right formats of each of the DN's, since the comparison would also fail if the formats aren't the same
            if (cert.IssuerName.ToString() != certificateAuthorityIdentifier)
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        private static bool IsCertificateSelfSigned(X509Certificate2 x509Cert)
        {
            // For any digital certificate, compare its Issuer extension to its Subject extension
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


        private static bool IsCertificateValid(X509Certificate2 x509Cert)
        {
            // Currently all the application needs to check for is whether the digital certificate has expired yet            
            return x509Cert.NotAfter > DateTime.Now;
        }

        /// Compares the Thumbprint of the passed-in certificate to the value of the CertificateHash registry setting
        /// This determines which certificate is actively being used by the EFS component driver
        private static bool IsSelectedCertificateTheCurrentlyConfiguredEFSCertificate(X509Certificate2 x509Cert)
        {
            // Create a variable to store the passed-in certificate's thumbprint value
            byte[] _certificateThumbprint;

            // Create a variable to store the current CertificateHash registry value
            byte[] _certificateHashRegistryValue;

            // First test whether the CertificateHash Registry value even exists - if it doesn't, by definition there cannot be a match
            _certificateHashRegistryValue = GetCertificateHashValueFromRegistry();
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
                if (DoesCertificateMatchCertificateHashRegistryValue(_certificateThumbprint, GetCertificateHashValueFromRegistry()))
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

        private static void ParseArguments(string[] args)

            /* 
             * This function should parse the values of as many arguments as were found on the application's StdIn.
             * If the only argument is "/?", then show usage and exit.
             * Otherwise, read the arguments and assign them to the appropriate variables.
             */

            // TODO: enable the use of flags using the Community Content here: http://msdn2.microsoft.com/en-US/library/kztbsa4b(VS.80).aspx
        {
            if (args.Length == 1 && args[0].EndsWith("?"))
            {
                DisplayUsage();

                // Exit the application successfully
                System.Environment.Exit(0);
            }

            // TODO: enable this argument to receive the identifier of a specific CA
            // //Optional command-line argument specifying the name of the Certificate Template which the organization may want users to use for EFS
            //CertificateTemplateName = args[0];

            // TODO: Certificate template name should be returned in a form that is either:
            //   (a) directly useable in an expression examining a field of the digital certificate, or 
            //   (b) useable in more than one context (e.g. if there was some other Registry setting that recorded a form of the cert template)




            // TODO: enable an additional argument to receive an identifier of a targeted CA (e.g. Subject field's "CN", Serial number)
            // // Optional command-line argument specifying the CA from which the selected EFS certificate must be issued
             IssuingCAIdentifier = args[1];


            // TODO: enable a boolean argument that limits the candidate certificates to those enrolled from a v2 template only
            // This argument would be useful as a stepping stone towards a specific CA or specific cert template - it could be considered "close enough" by many organizations
            // If (args[2] = "LimitToV2Only")
             LimitToV2Only = true;
        }

        private static void WriteCertificateHashToRegistry(X509Certificate2 certificate)
        {
            // Write this certificate's hash value to the CertificateHash Registry setting
            RegistryKey _hkcu = Registry.CurrentUser;
            RegistryKey _registrySubKey = _hkcu.OpenSubKey(subKey, true);

            try
            {
                _registrySubKey.SetValue("CertificateHash", certificate.GetCertHash(), Microsoft.Win32.RegistryValueKind.Binary);
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
                Console.WriteLine(e.Message + Environment.NewLine);
                Console.WriteLine(e.StackTrace + Environment.NewLine);
                throw;
            }

            _registrySubKey.Close();
            _hkcu.Close();

            // Update the variable to indicate that CertificateHash value has been updated
            CertificateHashValueUpdated = true;
            Trace.WriteLine("The user's EFS configuration has been updated with a suitable digital certificate." + Environment.NewLine);
        }
    }
}
