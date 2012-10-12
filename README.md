upek-ps-pass-decrypt
====================

UPEK Protector Suite Password Decrypter

This is a little .NET 4.0 C# console application that demonstrates how to decrypt Windows logon credentials from registry keys created by UPEK (now AuthenTec)'s Protector Suite software.

Run it with "-h" to see how to use it. By default it spits out all the Windows usernames, passwords, and domains it can find, but you can specify everything with verbose mode (-v).

Depending on the version of Protector Suite you have installed, you may need to run this tool as NT AUTHORITY\SYSTEM. You can do this by downloading and using psexec.exe (Google for it) and bringing up a command prompt via:

psexec.exe -s -i cmd.exe

You can then navigate to the directory for this tool and run it.

If this tool doesn't work for you and you want it to, feel free to let me know at brandonlw@gmail.com along with a sample of your data so support can be added.
