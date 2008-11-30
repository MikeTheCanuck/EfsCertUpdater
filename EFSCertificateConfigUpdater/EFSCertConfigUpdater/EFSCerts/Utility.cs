//-----------------------------------------------------------------------
// <copyright file="Utility.cs" company="ParanoidMike">
//     Copyright (c) ParanoidMike. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace ParanoidMike
{
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Runtime.Serialization.Formatters.Binary;
    using Microsoft.Win32;

    /// <summary>
    /// Reusable functions for many uses.
    /// </summary>
    public static class Utility
    {
        #region Variables

        /// <summary>
        /// Variable for the HKCU hive, to be used with functions that use the RegistryKey class.
        /// </summary>
        private static RegistryKey hkcu = Registry.CurrentUser;

        /// <summary>
        /// Variable for the HKLM hive, to be used with functions that use the RegistryKey class.
        /// </summary>
        private static RegistryKey hklm = Registry.LocalMachine;

        /// <summary>
        /// Variable for identifying the major version of the Operating System.
        /// </summary>
        private static int osVersion = -1; // contains os major version number

        #endregion

        #region Properties

        /// <summary>
        /// Gets the major version of the operating system.
        /// </summary>
        public static int OSVersion
        {
            get
            {
                if (osVersion == -1)
                {
                    OperatingSystem os = Environment.OSVersion;
                    osVersion = os.Version.Major;
                }

                return osVersion;
            }
        }

        #endregion

        #region Public Methods

        ////public static string ConvertByteArrayToString(byte[] inputArray)
        ////    /// Converts an arbitrary-sized byte array into an arbitrary-sized string

        ////    // TODO: determine if there's a way to prevent buffer overrun, or check the incoming size of convertee, so a huge array doesn't overflow the string buffer
        ////{
        ////    // NOTE: I tried this conversion code I found on the 'Net http://forums.microsoft.com/MSDN/ShowPost.aspx?PostID=1656747&SiteId=1, but couldn't get it to work
        ////    // Previously I tried to derive a string that can be compared to X509Certificate2.GetCertHashString()
        ////    // e.g. "C480C669C22270BACD51E65C6AC28596DFF93D0D"

        ////}

        /// <summary>
        /// Instantiates a Trace log for detailed tracking of an application's internal activities.
        /// </summary>
        /// <param name="appLoggingFolder">
        /// Name of folder to create in the current user's %LOCALAPPDATA% profile location.
        /// </param>
        /// <param name="traceLogFileName">
        /// Name of file to create in the appLoggingFolder location.
        /// </param>
        public static void AddTraceLog(
            string appLoggingFolder,
            string traceLogFileName)
        {
            // Setup Trace log
            TextWriterTraceListener traceLog;
            string traceLogBaseFolder;
            traceLogBaseFolder = System.Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            Directory.CreateDirectory(Path.Combine(traceLogBaseFolder, appLoggingFolder));

            // concatenate the full path
            string fullPath = traceLogBaseFolder + "\\" + appLoggingFolder;

            try
            {
                Stream traceLogFile = File.Open(Path.Combine(fullPath, traceLogFileName), FileMode.Create, FileAccess.Write);

                // Create a new text writer using the output stream, and add it to the trace listeners.
                traceLog = new TextWriterTraceListener(traceLogFile);
                ((StreamWriter)(traceLog.Writer)).AutoFlush = true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message, Environment.NewLine);
                Console.WriteLine(e.StackTrace, Environment.NewLine);
                throw;
            }

            Trace.AutoFlush = true;
            Trace.Listeners.Clear();
            Trace.Listeners.Add(traceLog);
        }

        /// <summary>
        /// Convert a byte array to an Object.
        /// Copied from http://snippets.dzone.com/posts/show/3897
        /// </summary>
        /// <param name="arrBytes">
        /// The byte[] array to be converted.
        /// </param>
        /// <returns>
        /// The object to which the byte array is converted.
        /// </returns>
        public static object ByteArrayToObject(byte[] arrBytes)
        {
            MemoryStream memStream = new MemoryStream();
            BinaryFormatter binForm = new BinaryFormatter();

            memStream.Write(arrBytes, 0, arrBytes.Length);
            memStream.Seek(0, SeekOrigin.Begin);

            object obj = (object)binForm.Deserialize(memStream);

            return obj;
        }

        /// <summary>
        /// Takes in any string and convert it into a Byte array, suitable for e.g. insertion into a REG_BINARY Registry value.
        /// </summary>
        /// <param name="inputString">
        /// String value to be converted to a Byte array.
        /// </param>
        /// <returns>
        /// Byte array, converted from the input String value.
        /// </returns>
        public static byte[] ConvertStringToByteArray(string inputString)
        {
            byte[] outputByteArray;
            string[] hexCodesFromString = inputString.Split(',');
            int upperBound = hexCodesFromString.GetUpperBound(0);
            outputByteArray = new byte[upperBound]; // doing this to resolve uninitialized variable error that appeared below

            for (int i = 0; i < upperBound; i++)
            {
                outputByteArray[i] = Convert.ToByte(hexCodesFromString[i], 16);
            }

            return outputByteArray;
        }

        /// <summary>
        /// Closes all existing Trace Log.
        /// </summary>
        public static void DisposeTraceLog()
        {
            if (Trace.Listeners.Count == 0)
            {
                Trace.Close();
            }
        }

        /// <summary>
        /// Compares the values of two byte arrays, and returns true only if every array member is identical
        /// </summary>
        /// <param name="firstArray">
        /// First array to be compared.
        /// </param>
        /// <param name="secondArray">
        /// Second array to be compared.
        /// </param>
        /// <returns>
        /// True if first array is identical to second array.
        /// False if the arrays are not identical.
        /// </returns>
        public static bool DoByteArraysMatch(
            byte[] firstArray, 
            byte[] secondArray)
        {
            // Check to be sure they two arrays match in length before doing anything else; if not, then they cannot possibly match
            int upperBound = firstArray.GetUpperBound(0);

            try
            {
                if (upperBound != secondArray.GetUpperBound(0))
                {
                    // Caller must've screwed something up, as this function is only intended to compare arrays with the same number of elements
                    throw (new NotSupportedException("EFSConfiguration.EFSConfiguration.MismatchInSize"));
                }
            }
            catch (NullReferenceException)
            {
                // One of the arrays is null
                throw;
            }

            // Perform comparison of each byte[i] array value; if any comparison fails, the arrays must be unequal
            for (int i = 0; i < upperBound; i++)
            {
                if (firstArray[i] != secondArray[i])
                {
                    ////Console.WriteLine("Array contents are dissimilar: element " + i.ToString + " is equal to \"" + firstArray[i].ToString + "\" in ");
                    ////Console.WriteLine("the first array and \"" + secondArray[i].ToString + "\" in the second array.", Environment.NewLine);

                    return false;
                }
            }

            // If function has made it this far, then the byte arrays are (almost) certainly identical
            return true;
        }

        /// <summary>
        /// Retrieves any Registry value that uses the REGBINARY data type.
        /// </summary>
        /// <param name="userHive">
        /// Specifies whether to retrieve from the HKCU hive:
        /// - if True, retrieves from HKCU
        /// - if False, retrieves from HKLM
        /// </param>
        /// <param name="subKey">
        /// The relative path (within the specified hive) to the Registry Key where the value is found.
        /// </param>
        /// <param name="valueName">
        /// The Registry value whose data is retrieved.
        /// </param>
        /// <returns>
        /// The data in the specified Registry value.
        /// </returns>
        public static byte[] GetRegistryValue(
            bool   userHive, 
            string subKey, 
            string valueName)
        {
            ////const string SubKey = "Software\\Microsoft\\Windows NT\\CurrentVersion\\EFS\\CurrentKeys";
            ////const string ValueName = "CertificateHash";

            RegistryKey registrySubKey;
            byte[] registryValue; // Declare a variable to hold the returned Registry value

            if (userHive)
            {
                registrySubKey = hkcu.OpenSubKey(subKey);
            }
            else
            {
                registrySubKey = hklm.OpenSubKey(subKey);
            }

            registryValue = (byte[]) registrySubKey.GetValue(valueName, null);

            // NOTE: Previously I tried to derive a string that can be compared to X509Certificate2.GetCertHashString()
            // e.g. "C480C669C22270BACD51E65C6AC28596DFF93D0D"
            // Note: I tried this conversion code I found on the 'Net http://forums.microsoft.com/MSDN/ShowPost.aspx?PostID=1656747&SiteId=1, but couldn't get it to work
            registrySubKey.Close();

            if (userHive)
            {
                hkcu.Close();
            }
            else
            {
                hklm.Close();
            }

            return registryValue;
        }

        /// <summary>
        /// Convert an object to a byte array.
        /// Copied from http://snippets.dzone.com/posts/show/3897
        /// </summary>
        /// <param name="obj">
        /// The object to be converted.
        /// </param>
        /// <returns>
        /// The byte[] array to which the object is converted.
        /// </returns>
        public static byte[] ObjectToByteArray(object obj)
        {
            if (obj == null)
            {
                return null;
            }

            BinaryFormatter bf = new BinaryFormatter();
            MemoryStream ms = new MemoryStream();
            bf.Serialize(ms, obj);
            return ms.ToArray();
        }

        /// <summary>
        /// Writes a Registry value to the Registry.
        /// </summary>
        /// <param name="userHive">
        /// Specifies whether to write to the HKCU hive:
        /// - if True, writes to HKCU
        /// - if False, writes to HKLM
        /// </param>
        /// <param name="subKey">
        /// The relative path (within the specified hive) to the Registry Key where the value is found.
        /// </param>
        /// <param name="valueName">
        /// The Registry value whose data is written.
        /// </param>
        /// <param name="valueData">
        /// The data to be written to the specified Registry value.
        /// </param>
        public static void SetRegistryValue(
            bool   userHive, 
            string subKey, 
            string valueName, 
            byte[] valueData)
        {
            RegistryKey registrySubKey;

            // Note - don't forget to set writeable = True anytime you're going to write to the Registry.  How embarrassing to miss this for two days!
            if (userHive)
            {
                registrySubKey = hkcu.OpenSubKey(subKey, true);
            }
            else
            {
                registrySubKey = hklm.OpenSubKey(subKey, true);
            }

            registrySubKey.SetValue(
                valueName, 
                valueData, 
                RegistryValueKind.Binary);

            registrySubKey.Close();

            if (userHive)
            {
                hkcu.Close();
            }
            else
            {
                hklm.Close();
            }
        }

        #endregion
    }
}
