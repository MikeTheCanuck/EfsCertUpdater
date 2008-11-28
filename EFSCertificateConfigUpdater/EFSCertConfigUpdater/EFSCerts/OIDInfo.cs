//**************************************************
// OIDInfo.cs
// downloaded from: http://web.archive.org/web/20050113193533/http://www.jensign.com/JavaScience/dotnet/OIDInfo/source/OIDInfo.txt
//
// This C# utility for .NET Framework 1.0/1.1
//  - displays OID info for a dotted OID.
//
// Copyright (C) 2003.  Michel I. Gallant
//***************************************************

using System;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace JavaScience
{
public class Win32 {
 [DllImport("crypt32.dll", SetLastError=true)]
	public static extern IntPtr CryptFindOIDInfo(
	uint dwKeyType,
	[MarshalAs(UnmanagedType.LPStr)] String szOID,
	uint dwGroupId);
}


 [StructLayout(LayoutKind.Sequential)]
	public struct CRYPT_OID_INFO
	{
		public uint cbSize;
		[MarshalAs(UnmanagedType.LPStr)] public String pszOID;
		[MarshalAs(UnmanagedType.LPWStr)]public String pwszName;
		public uint dwGroupID;
		public uint dwValue;
		public int cbData;   //ExtraInfo blob
		public IntPtr pbData;
	}


public class OIDInfo {
 const  uint CRYPT_OID_INFO_OID_KEY = 1;
 const String MSOIDs = "http://support.microsoft.com/default.aspx?scid=kb;en-us;Q287547";

 public static void Main(String[] args){ 
  if(args.Length < 1){
	 Usage();
	 return;
	}
  String oidname = OIDInfo.OIDName(args[0]) ;
  if(oidname==null){
	if(args[0].IndexOf("1.3.6.1.4.1.311")>=0)
	  Console.WriteLine("\n{0} is a Microsoft-specific OID\nCheck:  {1}", args[0], MSOIDs);
	else
	  Console.WriteLine("\nOID {0} not recognized\nCheck:  {1}", args[0], MSOIDs);
   }
  else
	Console.WriteLine("\n{0}\n{1}", args[0], oidname);
 }



 //------ get friendly name for OID -------
 private static string OIDName(String OID){
   IntPtr poidinfo = Win32.CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, OID, 0) ;
   if(poidinfo == IntPtr.Zero)
	return null;
   CRYPT_OID_INFO coinfo = (CRYPT_OID_INFO)Marshal.PtrToStructure(poidinfo, typeof(CRYPT_OID_INFO));
   return coinfo.pwszName;
 }


 private static void Usage() {
   Console.WriteLine("\nUsage:\nOIDInfo  <dotted OID>");
  }


 private static void showWin32Error(int errorcode){
       Win32Exception myEx=new Win32Exception(errorcode);
       Console.WriteLine("Error message: {0}  (Code: 0x{1:X})", myEx.Message, myEx.ErrorCode);
 }

}
}

