using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using CertificateManager;
using CertificateManager.Models;
using Microsoft.Extensions.DependencyInjection;

namespace CertMan.Shared
{
    public class Certs
    {

        public static X509Certificate2 MakeCA()
        {
            var serviceProvider = new ServiceCollection()
               .AddCertificateManager()
               .BuildServiceProvider();

            var createClientServerAuthCerts = serviceProvider.GetService<CreateCertificatesClientServerAuth>();

            var rootCaL1 = createClientServerAuthCerts.NewRootCertificate(
                new DistinguishedName { CommonName = "Whalebone Sinkhole CA", Country = "CZ" },
                new ValidityPeriod { ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddYears(10) },
                2, "localhost");

            var cabytes = rootCaL1.Export(X509ContentType.Pfx, "1234");
            File.WriteAllBytes("cert.pfx", cabytes);

            rootCaL1 = new X509Certificate2(cabytes, "1234");

            using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);


            store.Open(OpenFlags.ReadWrite);
            if (!store.Certificates.Contains(rootCaL1))
            {
                store.Add(rootCaL1);
            }

            store.Close();

            return rootCaL1;
        }


        public static X509Certificate2 MakeChild(string domain, X509Certificate2 root, string password)
        {
            var serviceProvider = new ServiceCollection()
                .AddCertificateManager()
                .BuildServiceProvider();

            var path = Path.Combine("certs", domain);
            if (!Directory.Exists("certs"))
                Directory.CreateDirectory("certs");

            if (File.Exists(path))
            {
                try
                {
                    var srvcrt = new X509Certificate2(path, password);
                    if (DateTime.Parse(srvcrt.GetExpirationDateString()) > DateTime.UtcNow)
                        return srvcrt;
                }
                catch (Exception ex)
                {
                    //Log.Error($"Unable to load certificate {path} {ex}");
                    try
                    {
                        File.Delete(path);
                    }
                    catch
                    {
                        //Log.Error($"Unable to delete certificate {path} {ex}");
                    }
                }
            }

            var createClientServerAuthCerts = serviceProvider.GetService<CreateCertificatesClientServerAuth>();
            var server = createClientServerAuthCerts.NewServerChainedCertificate(
                new DistinguishedName { CommonName = domain, Country = "CZ" },
                new ValidityPeriod { ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddYears(10) },
                domain, root);

            var certbytes = server.Export(X509ContentType.Pfx, password);
            server = new X509Certificate2(certbytes, password);
            File.WriteAllBytes(path, certbytes);

            return server;

        }

    }
    
}
