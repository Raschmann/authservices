using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;

namespace Kentor.AuthServices.TestHelpers
{
    public class SignedXmlHelper
    {
        public static readonly X509Certificate2 TestCert = new X509Certificate2("Kentor.AuthServices.Tests.pfx");

        public static readonly X509Certificate2 TestCert2 = new X509Certificate2("Kentor.AuthServices.Tests2.pfx");

        public static readonly AsymmetricAlgorithm TestKey = TestCert.PublicKey.Key;

        public static string SignXml(string xml)
        {
            var xmlDoc = new XmlDocument { PreserveWhitespace = true };
            xmlDoc.LoadXml(xml);

            xmlDoc.Sign(TestCert);

            return xmlDoc.OuterXml;
        }

        public static string EncryptXml(string xml, string elementToEncryptName)
        {
            var xmlDoc = new XmlDocument { PreserveWhitespace = true };
            xmlDoc.LoadXml(xml);

            // Create a new TripleDES key. 
            var sessionKey = new RijndaelManaged { KeySize = 256 };

            var encryptedData = new EncryptedData
            {
                Type = EncryptedXml.XmlEncElementUrl,
                EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url)
            };

            var elementToEncrypt = (XmlElement) xmlDoc.GetElementsByTagName(elementToEncryptName, Saml2Namespaces.Saml2Name)[0];

            // Encrypt the assertion and add it to the encryptedData instance.
            var encryptedXml = new EncryptedXml();
            var encryptedElement = encryptedXml.EncryptData(elementToEncrypt, sessionKey, false);
            encryptedData.CipherData.CipherValue = encryptedElement;

            // Add an encrypted version of the key used.
            encryptedData.KeyInfo = new KeyInfo();

            var encryptedKey = new EncryptedKey
            {
                EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url),
                CipherData = new CipherData(EncryptedXml.EncryptKey(sessionKey.Key, (RSA)TestCert2.PublicKey.Key, false))
            };

            encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));

            EncryptedXml.ReplaceElement(elementToEncrypt, encryptedData, false);

            return xmlDoc.OuterXml;
        }

        public static XmlDocument SignAssertionXml(string xml)
        {
            var xmlDoc = new XmlDocument { PreserveWhitespace = false };
            xmlDoc.LoadXml(xml);

            SignAssertion(xmlDoc, TestCert);

            return xmlDoc;
        }

        public static readonly string KeyInfoXml;

        static SignedXmlHelper()
        {
            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(TestCert));

            KeyInfoXml = keyInfo.GetXml().OuterXml;
        }

        private static void SignAssertion(XmlDocument xmlDocument, X509Certificate2 cert)
        {            
            var signedXml = new SignedXml(xmlDocument);

            // The transform XmlDsigExcC14NTransform and canonicalization method XmlDsigExcC14NTransformUrl is important for partially signed XML files
            // see: http://msdn.microsoft.com/en-us/library/system.security.cryptography.xml.signedxml.xmldsigexcc14ntransformurl(v=vs.110).aspx
            // The reference URI has to be set correctly to avoid assertion injections
            // For both, the ID/Reference and the Transform/Canonicalization see as well: 
            // https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf section 5.4.2 and 5.4.3

            signedXml.SigningKey = cert.PrivateKey;
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            var reference = new Reference { Uri = "#" + xmlDocument.DocumentElement.GetAttribute("ID") };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());

            signedXml.AddReference(reference);


            // Include the public key of the certificate in the assertion.
            signedXml.KeyInfo = new KeyInfo();
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(cert, X509IncludeOption.WholeChain));

            signedXml.ComputeSignature();              

            // Append the computed signature. The signature must be placed as the sibling of the Issuer element.
            var nodes = xmlDocument.DocumentElement.GetElementsByTagName("Issuer", Saml2Namespaces.Saml2.NamespaceName);            

            xmlDocument.DocumentElement.InsertAfter(xmlDocument.ImportNode(signedXml.GetXml(), true), nodes[0]);     
        }
    }
}
