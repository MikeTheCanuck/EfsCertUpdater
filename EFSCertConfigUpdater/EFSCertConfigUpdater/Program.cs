using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Text;

namespace EFSConfiguration
{
    class Program
    {
        static void Main(string[] args)
        {
            /*
             * Purpose of this application: automate the migration of a user's current EFS certificate from a self-signed 
             * EFS certificate to a CA-issued EFS certificate.  This will ensure that the organization has the ability to 
             * recover the user's private key in the unlikely event that the user's private key gets deleted, the hard disk
             * fails or the user's Profile becomes unavailable.
            
             * This supports a complementary recovery process to the more traditional ability to recover EFS files using
             * the Data Recovery Agent keys defined through Group Policy.
             * 
             * The application may optionally take as an argument the name of the Certificate Template (from which the preferred 
             * EFS certificate was issued) as a command-line parameter, or it may support the ability to read that value from the 
             * Registry (as defined and distributed through Group Policy).  This functionality hasn't been decided yet.
             */

             const string EFS_EKU = "1.3.6.1.4.1.311.10.3.4";
           
            /* 
             * Usage behaviour for this application:
             * 0 arguments = select the first non-self-signed EFS certificate
             * 1 argument  = select the first non-self-signed EFS certificate enrolled from the specified certificate template
             * 2 arguments = select the first non-self-signed EFS certificate enrolled from the specified cert template and CA
             */

             // TODO: enable this argument to receive an identifier of a targeted CA
            // //Optional command-line argument specifying the name of the Certificate Template which the organization may want users to use for EFS
            //string CertificateTemplateName;
            //CertificateTemplateName = args[0];

            // TODO: enable the additional argument to receive an identifier of a targeted CA
            // // Optional command-line argument specifying the DistinguishedName of the CA from which the selected EFS certificate must have been issued
            // string IssuingCADistinguishedName = args[1];

            if (args.Length == 1 && args[0].EndsWith("?"))
            {
                DisplayUsage();
            }

            // Some of this code was cloned/inherited from http://msdn2.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509certificate2ui(vs.80).aspx and other various locations
            // Create an instance of X509Store to associate with the user's My store
            X509Store MyStore = new X509Store("MY", StoreLocation.CurrentUser);

            // Open the store read-only so as not to accidently munge my certs, and do NOT create a new store
            // TODO: change to ReadWrite when I'm ready to Archive existing certs and/or enroll for new Certificates
            MyStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            
            // Create a collection to enumerate the existing Certs in the My store, and perform a cast (note: I don't know if I'm casting from or to the MyStore.Certificates collection)
            X509Certificate2Collection UserCerts = (X509Certificate2Collection)MyStore.Certificates;
            
            /* 
             * There are two potential approaches for finding the CA-issued EFS certificate(s):
             * 1. Find all certificates with the EFS EKU, then examine those certificates for issuer and/or Certificate 
             * Template.  Examining the issuer will let us find self-signed certificates and optionally archive them; examining 
             * the Certificate Template field will let us find the cert(s) issued by the target CA (where presumably key escrow 
             * has been performed).
             * 2. Find the certificate(s) enrolled from the Certificate Template of interest.
             * 
             * Unfortunately there is no way from the client to be absolutely certain that the cert and its keys are currently 
             * in the Keys Archive, but we can be certain that any cert enrolled from a Cert Template that uses key archival 
             * had in fact had its keys archived (i.e. this is a success criteria for any enrollment from a Key Archival-required 
             * cert template).  This is likely a reasonable enough approximation of the desired state "my cert's private key is 
             * currently archived in the CA's database".
             */        

            // This is a very elegant method to narrow the user's certificates down to just the EFS certificates; unfortunately, it doesn't work
            //X509Certificate2Collection UserCertsFiltered = (X509Certificate2Collection)UserCerts.Find(X509FindType.FindByExtension, EFS_EKU, true);
            X509Certificate2Collection UserCertsFiltered = (X509Certificate2Collection)UserCerts.Find(X509FindType.FindByExtension, "Enhanced Key Usage", true);
                        
            // Iterate through each user Certificate in this collection to (a) identify an EFS cert that is valid for our purpose, (b) determine whether 
            // the selected certificate matches the current EFS configuration, and (c) update the EFS configuration if not.
            // TODO: move the code for making EFS configuration changes so that it is outside the foreach loop, thus restoring the foreach loop to merely a 
            //       tool for selecting an EFS certificate to be used
            foreach (X509Certificate2 x509Cert in UserCertsFiltered)
            {
                Console.WriteLine("Cert being investigated is named " + x509Cert.Subject);

                // Confirm that the certificate is Valid so the user doesn't encrypt with an expired cert
                if (IsCertificateValid(x509Cert))
                {
                    continue;
                }

                // Skip the certificate if it is self-signed, since self-signed certificates can never automatically be archived by a Windows Server CA
                if (IsCertificateSelfSigned(x509Cert))
                {
                    continue;
                }

                // Confirm whether the certificate contains the EFS EKU, and skip it if not
                if (DoesCertificateHaveSpecifiedEku(x509Cert, EFS_EKU) == false)
                {
                    continue;
                }

                /* 
                 * TODO: determine whether it's better to handle a null value in "CertificateTemplateName" (i.e. if no arguments were supplied) 
                 * in the foreach loop or inside the function that is about to be called
                 */
                // Determine whether the certificate was enrolled from the specified Certificate Template
                // TODO: enable a function for this, once the arguments can be read in


                
                // TODO: re-enable this code once the CA-identifying argument is re-enabled
                //// If cert isn't self-signed, then it was issued by a Certificate Authority, but it could've been issued potentially by any CA
                //// Confirm that the cert was issued by the intended CA
                //if (IsCertificateIssuedByIntendedCA(x509Cert, IssuingCADistinguishedName) == false)
                //{
                //    continue;
                //}

                // Confirm that the user has a Private Key for this certificate (i.e. that they didn't just accidently 
                // or unintentionally import an EFS certificate without its private key)
                if (x509Cert.HasPrivateKey != true)
                {
                    continue;
                }

                // Determine whether the selected certificate is the currently configured EFS certificate
                // If so, then no further action is necessary - not for updating the user's CertificateHash registry setting at least

                if (IsCertificateTheCurrentEFSCertificate(x509Cert))
                {
                    continue;
                }
                
                // Write the certificate's hash value to the CertificateHash Registry setting
                // HACK: writing the hash to a dummy value while I confirm that I've done this right
                // TODO: determine the right combination of conversions to get the correct format for the hash
                Microsoft.Win32.Registry.CurrentUser.SetValue("CertificateHash2", x509Cert.GetCertHashString(), Microsoft.Win32.RegistryValueKind.String);

                
                /* Now that we've updated the CertificateHash Registry value with the thumbprint for a cert enrolled from 
                 * the desired Template, this application must stop looping - just in case there are two or more valid 
                 * certs from the same Template. Otherwise the application could overwrite a perfectly valid thumbprint - not 
                 * necessarily bad, but totally unnecessary.
                 */
                break;
                
                /* TODO: determine how to implement an advanced mode whereby the application doesn't just select the first matching 
                 * certificate, but picks the "best" of those certs.  The "Best" of all matching certs would be the one with the latest
                 * "Valid From:" date; should this application then Archive all other matching certificates?
                 */

                
                /* TODO: what if there were *no* desired certificates in the My store?  Should this application attempt to enroll a cert
                 * from that Template, and write an error to the Event Log if no such cert could be enrolled?
                 */


            }

            // Were there any certificates identified in this loop?  If not, then indicate that no matching certificates were found
            Console.WriteLine("No matching EFS certificates were identified - please notify your IT organization.", Environment.NewLine);
            
            /* 
             * Assuming the application has updated the CertificateHash Registry value with the thumbprint from the selected EFS cert,  
             * the application could optionally deal with updating all encrypted files - either by notifying the user 
             * that they should run the EFS Assistant tool or CIPHER.EXE /U, or by running one of these tools in the background.
             */
            

            // Finally, close the MY store:
            MyStore.Close();

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

        private static void DisplayUsage()
        {
            {
                Console.WriteLine("This application will allow you to update your EFS configuration to use a centrally-managed EFS certificate", Environment.NewLine);
                Console.WriteLine(Environment.NewLine);
                Console.WriteLine("Usage: EFSConfiguration [argument1] [argument2]", Environment.NewLine);
                Console.WriteLine("       [argument1] specifies the name of the Certificate Template to be targeted e.g. \"Company EFS certificate version 2\"", Environment.NewLine);
                Console.WriteLine("       [argument2] specifies the distinguished name of the Issuing CA e.g. \"IssuingCA01\"", Environment.NewLine);
                Console.WriteLine(Environment.NewLine);
                Console.WriteLine("Note: you can specify neither of the arguments, only the first, or both the first and second");
            }
        }

        private static bool IsCertificateTheCurrentEFSCertificate(X509Certificate2 x509Cert)
        {
            /* 
             * Determine if the digital certificate matches the EFS configuration for the current user
             */

            // Create a Variable to store the selected certificate's thumbprint value
            String _certificateThumbprintHexString;

            // Extract the current certificate's thumbprint value
            _certificateThumbprintHexString = x509Cert.GetCertHashString();
            Console.WriteLine("Selected cert's hash string = " + _certificateThumbprintHexString);
            Console.WriteLine("Current value in Registry   = " + GetCertificateHashValueFromRegistry());

            if (DoesCertificateMatchEfsConfiguration(_certificateThumbprintHexString, GetCertificateHashValueFromRegistry()))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private static bool IsCertificateValid(X509Certificate2 x509Cert)
        {
            // Currently all the application needs to check for is whether the digital certificate has expired yet            
            return x509Cert.NotAfter < DateTime.Now;
        }

        private static bool IsCertificateSelfSigned(X509Certificate2 x509Cert)
        {
            // For any digital certificate, compare its Issuer extension to its Subject extension
            // If Issuer = Subject, then it's a so-called self-signed certificate
            if (x509Cert.IssuerName.Name == x509Cert.Subject)
            {
                return true;

                // Archive the self-signed certificate - it's not strictly necessary for this exercise, but it's a best practice  
                // TODO: re-enable this archiving code (and get it to actually invoke archiving)
                //x509Cert.Archived set;
            }
            else
            {
                return false;
            }
        }

        private static bool IsCertificateIssuedByIntendedCA(X509Certificate2 cert, string certificateAuthorityIdentifier)
        {
            // TODO: investigate whether there are other CA identifiers that would work better in other use cases
            //       e.g. DNS name of CA, thumbprint of CA cert

            // TODO: verify the format of each of the DN's, since the comparison would also fail if the formats aren't the same
            if (cert.IssuerName.ToString() != certificateAuthorityIdentifier)
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        private static byte[] GetCertificateHashValueFromRegistry()
        {
            // Declare a variable to hold the original CertificateHash registry setting
            byte[] _certificateHashValue;

            // Confirm that the CertificateHash Registry value exists
            try
            {
                const string userRoot = "HKEY_CURRENT_USER";
                const string subKey = "Software\\Microsoft\\Windows NT\\CurrentVersion\\EFS\\CurrentKeys";
                const string keyName = userRoot + "\\" + subKey;
                const string valueName = "CertificateHash";

                // HACK: debugging why I'm getting a null error...
                Console.WriteLine("Registry value to open = " + keyName + "\\" + valueName);

                _certificateHashValue = (byte[])Microsoft.Win32.Registry.CurrentUser.GetValue(keyName + "\\" + valueName);

                return _certificateHashValue;
            }
                // TODO: structure the catch (Exception) call
            catch (Exception e)
            {
                // If Windows throws an error indicating the Registry value does not exist, then we'll know that we can create it safely
                Console.WriteLine("Error = " + e.Message, Environment.NewLine);
                Console.WriteLine("Error data = " + e.Data, Environment.NewLine);
                Console.WriteLine("Inner exception = " + e.InnerException, Environment.NewLine);

                throw;
            }
        }

        private static bool DoesCertificateMatchEfsConfiguration(String CertificateThumbprintHexString, byte[] _certificateHashValue)
        {
            /*
             * Compare CertificateHash registry value to the calculated value for the selected certificate.  
             */

            if (CertificateThumbprintHexString == Convert.ToBase64String(_certificateHashValue))
            {
                Console.WriteLine("Your EFS certificate setting is already up to date");
                return true;
            }
            else
            {
                Console.WriteLine("Your currently configured EFS cert hash is " + _certificateHashValue, Environment.NewLine);
                Console.WriteLine("The new EFS cert hash will be " + CertificateThumbprintHexString, Environment.NewLine);
                return false;
            }
        }

       

        // Create a function that searches the user's MY store for a desired EFS certificate and returns the hash for the identified certificate (if any).
        // If no certificate is identified, then return an error value.


        // Create a function that obtains the current value from the user's CertificateHash Registry setting, and if the value is not found, then
        // return an error indicating that no hash is currently stored (implying that EFS has never been used by this user - or that the user hasn't 
        // accessed an EFS'd file since their current user profile was created)


        // Create a function that compares the hash of the desired EFS certificate with the current CertificateHash Registry setting, and that returns 
        // True if the values are the same, and False if they are different


        // Create a function that updates the user's CertificateHash registry value, and that returns True if successful and various errors if it fails, 
        // including if the value does not exist OR if the update does not succeed (e.g. a permissions error, or some other error).

        // TODO: add Strong Name and digital signature
    }
}
