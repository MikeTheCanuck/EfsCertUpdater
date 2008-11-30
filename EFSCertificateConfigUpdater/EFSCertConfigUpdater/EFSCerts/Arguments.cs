//-----------------------------------------------------------------------
// <copyright file="Arguments.cs" company="ParanoidMike">
//     Copyright (c) ParanoidMike. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------
namespace EFSConfiguration
{
    using System;
    using CommandLine;

    /// <summary>
    /// Specifies the command-line arguments that are provided for the EFSCertConfigUpdater tool.
    /// </summary>
    class Arguments
    {
        //// EXAMPLE
        ////[Argument(ArgumentType.Required, HelpText = "The name of the csproj file of the website.")]
        ////public string ProjectFileName;

        //// EXAMPLE
        ////[Argument(ArgumentType.AtMostOnce, DefaultValue = "SiteMap.generated.cs", HelpText = "The name of the generated file.")]
        ////public string OutputFileName;

        /// <summary>
        /// The name of the Certificate Template to which to migrate the user's EFS configuration.
        /// </summary>
        [Argument(ArgumentType.AtMostOnce, LongName = "template", ShortName = "t", HelpText = "The name of the Certificate Template to which to migrate the user's EFS configuration.")]
        private string certificateTemplateName;

        public string CertificateTemplateName
        {
            get
            {
                return this.certificateTemplateName;
            }

            set
            {
                this.certificateTemplateName = value;
            }
        }

        /// <summary>
        /// The name of the Certificate Authority whose EFS certificate should be selected.
        /// </summary>
        [Argument(ArgumentType.AtMostOnce, LongName = "issuingca", ShortName = "i", HelpText = "The name of the Certificate Authority whose EFS certificate should be selected.")]
        private string issuingCAIdentifier;

        public string IssuingCAIdentifier
        {
            get
            {
                return this.issuingCAIdentifier;
            }

            set
            {
                this.issuingCAIdentifier = value;
            }
        }

        /// <summary>
        /// Call this parameter to migrate v1 certificates in addition to migrating self-signed certificates.
        /// </summary>
        [Argument(ArgumentType.AtMostOnce, LongName = "migratev1", ShortName = "m1", HelpText = "Call this parameter to migrate v1 certificates in addition to migrating self-signed certificates.", DefaultValue = false)]
        private bool migrateV1Certs;

        public bool MigrateV1Certs
        {
            get
            {
                return this.migrateV1Certs;
            }

            set
            {
                this.migrateV1Certs = value;
            }
        }

        // TODO: determine whether this can be modified to handle the case where only one of the two arguments is specified
        // Currently, if one argument is properly specified, the other will always create the Console.Error
        ////public bool IsValid()
        ////{
        ////    if (string.IsNullOrEmpty(certificateTemplateName))
        ////    {
        ////        Console.Error.WriteLine("You must specify a Certificate Template name with this parameter");
        ////        return false;
        ////    }

        ////    if (string.IsNullOrEmpty(issuingCAIdentifier))
        ////    {
        ////        Console.Error.WriteLine("You must specify an Issuing CA identifier with this parameter");
        ////        return false;
        ////    }

        ////    return true;
        ////}
    }
}
