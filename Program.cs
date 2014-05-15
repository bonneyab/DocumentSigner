using System;
using System.Configuration;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace DocumentSigner
{
    class Program
    {
        static void Main()
        {
            try
            {
                var filePath = ConfigurationManager.AppSettings["TargetFile"];
                var doc = new XmlDocument();
                doc.Load(File.OpenRead(filePath));

                var certThumbprint = ConfigurationManager.AppSettings["CertificateThumbPrint"];
                var cert = GetCertificate(certThumbprint);

                var id = doc.DocumentElement.Attributes["ID"].InnerText;
                var signature = SigningHelper.SignDoc(doc, cert, "ID", id);

                doc.DocumentElement.InsertBefore(signature, doc.DocumentElement.ChildNodes[1]);

                var destination = ConfigurationManager.AppSettings["DestinationFIle"];
                File.WriteAllText(destination, doc.OuterXml);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        private static X509Certificate2 GetCertificate(string certThumbrintName)
        {
            var store = new X509Store(StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2 cert;
            try
            {
                cert = store.Certificates.Find(X509FindType.FindByThumbprint, certThumbrintName, false)[0];
            }
            catch (IndexOutOfRangeException)
            {
                throw new IndexOutOfRangeException("Unable to find certificate specified, please make sure you have the correct thumbprint");
            }

            store.Close();

            return cert;
        }
    }
}
