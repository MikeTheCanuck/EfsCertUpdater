using System;
using CommandLine;

namespace EFSConfiguration
{
    class Arguments
    {
        // EXAMPLE
        //[Argument(ArgumentType.Required, HelpText = "The name of the csproj file of the website.")]
        //public string ProjectFileName;

        // EXAMPLE
        //[Argument(ArgumentType.AtMostOnce, DefaultValue = "SiteMap.generated.cs", HelpText = "The name of the generated file.")]
        //public string OutputFileName;

        [Argument(ArgumentType.AtMostOnce, LongName = "template", ShortName = "t", HelpText = "The name of the Certificate Template to which to migrate the user's EFS configuration.")]
        public string CertificateTemplateName;

        // This parameter enables the user to specify the CA from which the chosen EFS certificate must be issued
        [Argument(ArgumentType.AtMostOnce, LongName = "issuingca", ShortName = "i", HelpText = "The name of the Certificate Authority whose EFS certificate should be selected.")]
        public string IssuingCAIdentifier;

        // This parameter enables the user to limit the EFS certificates to be used to only those enrolled with a v2 Template
        [Argument(ArgumentType.AtMostOnce, LongName = "migratev1", ShortName = "m1", HelpText = "Call this parameter to migrate v1 certificates in addition to migrating self-signed certificates.", DefaultValue = false)]
        public bool MigrateV1Certs;

        // TODO: determine whether this can be modified to handle the case where only one of the two arguments is specified
        // Currently, if one argument is properly specified, the other will always create the Console.Error
        //public bool IsValid()
        //{
        //    if (string.IsNullOrEmpty(CertificateTemplateName))
        //    {
        //        Console.Error.WriteLine("You must specify a Certificate Template name with this parameter");
        //        return false;
        //    }

        //    if (string.IsNullOrEmpty(IssuingCAIdentifier))
        //    {
        //        Console.Error.WriteLine("You must specify an Issuing CA identifier with this parameter");
        //        return false;
        //    }

        //    return true;
        //}

    }
}
