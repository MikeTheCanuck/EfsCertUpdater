using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.Win32;

namespace ParanoidMike
{
    static class Utility
    {
        # region Variables

        private static RegistryKey hkcu = Registry.CurrentUser;
        private static RegistryKey hklm = Registry.LocalMachine;
        private static int _osVersion = -1; // contains os major version number

        # endregion

        # region Public Methods

        //public static string ConvertByteArrayToString(byte[] inputArray)
        //    /// Converts an arbitrary-sized byte array into an arbitrary-sized string

        //    // TODO: determine if there's a way to prevent buffer overrun, or check the incoming size of convertee, so a huge array doesn't overflow the string buffer
        //{
        //    // NOTE: I tried this conversion code I found on the 'Net http://forums.microsoft.com/MSDN/ShowPost.aspx?PostID=1656747&SiteId=1, but couldn't get it to work
        //    // Previously I tried to derive a string that can be compared to X509Certificate2.GetCertHashString()
        //    // e.g. "C480C669C22270BACD51E65C6AC28596DFF93D0D"

        //}

        /// <summary>
        /// Instantiates a Trace log for detailed tracking of an application's internal activities.
        /// </summary>
        /// <param name="appLoggingFolder">
        /// Name of folder to create in the current user's %LOCALAPPDATA% profile location.
        /// </param>
        /// <param name="traceLogFileName">
        /// Name of file to create in the appLoggingFolder location.
        /// </param>
        public static void AddTraceLog(string appLoggingFolder,
                                       string traceLogFileName)
        {
            // Setup Trace log
            TextWriterTraceListener traceLog;
            string _traceLogBaseFolder;
            _traceLogBaseFolder = System.Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            Directory.CreateDirectory(Path.Combine(_traceLogBaseFolder, appLoggingFolder));

            // concatenate the full path
            string _fullPath = _traceLogBaseFolder + "\\" + appLoggingFolder;

            try
            {
                Stream traceLogFile = File.Open(Path.Combine(_fullPath, traceLogFileName), FileMode.Create, FileAccess.Write);
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
        public static Object ByteArrayToObject(byte[] arrBytes)
        {
            MemoryStream memStream = new MemoryStream();
            BinaryFormatter binForm = new BinaryFormatter();
            memStream.Write(arrBytes, 0, arrBytes.Length);
            memStream.Seek(0, SeekOrigin.Begin);
            Object obj = (Object)binForm.Deserialize(memStream);
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

            byte[] _outputByteArray;
            string[] _hexCodesFromString = inputString.Split(',');
            int _upperBound = _hexCodesFromString.GetUpperBound(0);
            _outputByteArray = new byte[_upperBound]; // doing this to resolve uninitialized variable error that appeared below

            for (int i = 0; i < _upperBound; i++)
            {
                _outputByteArray[i] = Convert.ToByte(_hexCodesFromString[i], 16);
            }

            return _outputByteArray;
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
        /// Second array to be compared.
        /// <param name="secondArray">
        /// </param>
        /// <returns>
        /// True if first array is identical to second array.
        /// False if the arrays are not identical.
        /// </returns>
        public static bool DoByteArraysMatch(byte[] firstArray, 
                                             byte[] secondArray)
        {
            // Check to be sure they two arrays match in length before doing anything else; if not, then they cannot possibly match
            int _upperBound = firstArray.GetUpperBound(0);

            try
            {
                if (_upperBound != secondArray.GetUpperBound(0))
                {
                    // Caller must've screwed something up, as this function is only intended to compare arrays with the same number of elements
                    throw (new NotSupportedException(EFSConfiguration.EFSConfiguration.MismatchInSize));
                }

            }
            catch (NullReferenceException)
            {
                // One of the arrays is null
                throw;
            }

            // Perform comparison of each byte[i] array value; if any comparison fails, the arrays must be unequal
            for (int i = 0; i < _upperBound; i++)
            {
                if (firstArray[i] != secondArray[i])
                {
                    //Console.WriteLine("Array contents are dissimilar: element " + i.ToString + " is equal to \"" + firstArray[i].ToString + "\" in ");
                    //Console.WriteLine("the first array and \"" + secondArray[i].ToString + "\" in the second array.", Environment.NewLine);

                    return false;
                }
            }

            // If function has made it this far, then the byte arrays are (almost) certainly identical
            return true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userHive">
        /// 
        /// </param>
        /// <param name="subKey">
        /// 
        /// </param>
        /// <param name="valueName">
        /// 
        /// </param>
        /// <returns>
        /// 
        /// </returns>
        public static byte[] GetRegistryValue(bool   userHive, 
                                              string subKey, 
                                              string valueName)
        {
            //const string subKey = "Software\\Microsoft\\Windows NT\\CurrentVersion\\EFS\\CurrentKeys";
            //const string valueName = "CertificateHash";

            RegistryKey _registrySubKey;
            byte[] _registryValue; // Declare a variable to hold the returned Registry value

            if (userHive)
            {
                _registrySubKey = hkcu.OpenSubKey(subKey);
            }
            else
            {
                _registrySubKey = hklm.OpenSubKey(subKey);
            }

            _registryValue = (byte[]) _registrySubKey.GetValue(valueName, null);

            // NOTE: Previously I tried to derive a string that can be compared to X509Certificate2.GetCertHashString()
            // e.g. "C480C669C22270BACD51E65C6AC28596DFF93D0D"
            // Note: I tried this conversion code I found on the 'Net http://forums.microsoft.com/MSDN/ShowPost.aspx?PostID=1656747&SiteId=1, but couldn't get it to work

            _registrySubKey.Close();

            if (userHive)
            {
                hkcu.Close();
            }
            else
            {
                hklm.Close();
            }

            return _registryValue;
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
        public static byte[] ObjectToByteArray(Object obj)
        {
            if (obj == null)
                return null;
            BinaryFormatter bf = new BinaryFormatter();
            MemoryStream ms = new MemoryStream();
            bf.Serialize(ms, obj);
            return ms.ToArray();
        }

        /// <summary>
        /// Gets the major version of the operating system.
        /// </summary>
        public static int OSVersion
        {
            get
            {
                if (_osVersion == -1)
                {
                    OperatingSystem os = Environment.OSVersion;
                    _osVersion = os.Version.Major;
                }
                return _osVersion;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userHive">
        /// 
        /// </param>
        /// <param name="subKey">
        /// 
        /// </param>
        /// <param name="valueName">
        /// 
        /// </param>
        /// <param name="valueData">
        /// 
        /// </param>
        public static void SetRegistryValue(bool   userHive, 
                                            string subKey, 
                                            string valueName, 
                                            byte[] valueData)
        {

            RegistryKey _registrySubKey;

            // Note - don't forget to set writeable = True anytime you're going to write to the Registry.  How embarrassing to miss this for two days!
            if (userHive)
            {
                _registrySubKey = hkcu.OpenSubKey(subKey, true);
            }
            else
            {
                _registrySubKey = hklm.OpenSubKey(subKey, true);
            }

            _registrySubKey.SetValue(valueName, 
                                     valueData, 
                                     RegistryValueKind.Binary);

            _registrySubKey.Close();

            if (userHive)
            {
                hkcu.Close();
            }
            else
            {
                hklm.Close();
            }

        }

        # endregion
    }
}
