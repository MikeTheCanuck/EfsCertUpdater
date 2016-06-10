# EfsCertUpdater
Helps migrate Windows' EFS encryption to use centrally-enrolled encryption keys.

One of the most critical unresolved issues with using Windows EFS at scale is that the EFS component 'driver' does not automatically start using "better" EFS certificates when they are enrolled. This command-line application helps by re-encrypting the EFS "master key" with a centrally-enrolled (and ideally key-archival backed) digital certificate suitable for EFS.

## How it works
* By default the application will update the user's EFS configuration (the per-user CertificateHash registry value) with the first valid non-self-signed EFS certificate that it finds.
* If no such certificates are found, the application will exit.
* If the CertificateHash value is already configured with the selected certificate, the application will exit.
* The application creates a log of all significant activity that it performs, to give some visibility into how it selects a suitable EFS certificate, whether it succeeds and why.
* This log file is found under %APPDATA%\EFSCertConfigUpdate\ and is named "EFSCertConfigUpdateTraceLog.txt".

## Parameters
__/m1__ or __/migrate1__: the tool will also migrate v1 certificates, as well as self-signed certificates

## Notes
Last tested to work on Windows XP.

(Repo cloned from Codeplex to reflect the fact that Codeplex is on "death watch", given Microsoft's [massive migration to Github](http://www.theregister.co.uk/2015/01/15/codeplex_repository_out_of_favour_as_microsoft_moves_major_projects_to_github/))
