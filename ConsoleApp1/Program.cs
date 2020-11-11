using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;

namespace ConsoleApp9
{
    class Program
    {
        static void Main(string[] args)
        {
            var dpp =
                DataProtectionProvider.Create(
                    keyDirectory:
                        new DirectoryInfo(
                            @"C:\tmp\2020-11-09\DataProtectionTestKeyStore"),
                    setupAction:
                        cfg =>
                        {
                            cfg.ProtectKeysWithCertificate(
                                new X509Certificate2(
                                    fileName: @"C:\tmp\2020-11-09\DataProtectionTest20201110.pfx",
                                    password: @"Ldjuy7FjEcWRJ_6UEHUT"));
                        });

            var dp = dpp.CreateProtector("test");
            var secret = dp.Protect("test");
            Console.WriteLine(secret);
        }
    }
}
