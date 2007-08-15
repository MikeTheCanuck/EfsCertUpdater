using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace MikeSL
{
    static class Utility
    {
        //public static string ConvertByteArrayToString(byte[] inputArray)
        //    /// Converts an arbitrary-sized byte array into an arbitrary-sized string

        //    // TODO: determine if there's a way to prevent buffer overrun, or check the incoming size of convertee, so a huge array doesn't overflow the string buffer
        //{
        //    // NOTE: I tried this conversion code I found on the 'Net http://forums.microsoft.com/MSDN/ShowPost.aspx?PostID=1656747&SiteId=1, but couldn't get it to work
        //    // Previously I tried to derive a string that can be compared to X509Certificate2.GetCertHashString()
        //    // e.g. "C480C669C22270BACD51E65C6AC28596DFF93D0D"

        //}


        /// Takes in any string and convert it into a Byte array, suitable for e.g. insertion into a REG_BINARY Registry value
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

        /// Compares the values of two byte arrays, and returns true only if every array member is identical
        public static bool DoByteArraysMatch(byte[] firstArray, byte[] secondArray)
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

        public static void AddTraceLog(string applicationDataFolder, string traceLogFileName)
{
            // Setup Trace log
            TextWriterTraceListener traceLog;
            string _userLocalApplicationData;
            _userLocalApplicationData = System.Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            Directory.CreateDirectory(Path.Combine(_userLocalApplicationData, applicationDataFolder));

            // concatenate the full path
            string _fullPath = _userLocalApplicationData + "\\" + applicationDataFolder;

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

        /// Closes the Trace Log
        public static void DisposeTraceLog(string traceLogFileName)
        {
            if (Trace.Listeners.Count >0)
            {
            Trace.Close();
            }
        }

        private static int _osVersion = -1; // contains os major version number
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
        
    }
}
