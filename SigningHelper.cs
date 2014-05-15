using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace DocumentSigner {
    public static class SigningHelper {
        public static XmlElement SignDoc(XmlDocument doc, X509Certificate2 cert2, string referenceId, string referenceValue) {
            var sig = new MySignedXml(doc, referenceId) {SigningKey = cert2.PrivateKey};

            // Create a reference to be signed. 
            var reference = new Reference { Uri = "#" + referenceValue };

            // Add an enveloped transformation to the reference. 
            var env = new  XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);
            // Add the reference to the SignedXml object. 
            sig.AddReference(reference);

            // Add an RSAKeyValue KeyInfo (optional; helps recipient find key to validate). 
            var keyInfo = new KeyInfo();
            var keyData = new KeyInfoX509Data(cert2);

            keyInfo.AddClause(keyData);
            sig.KeyInfo = keyInfo;
            sig.ComputeSignature();

            // Get the XML representation of the signature and save it to an XmlElement object. 
            var xmlDigitalSignature = sig.GetXml();

            return xmlDigitalSignature;
        }
    }

    /// <summary>
    /// MySignedXml - Class is used to sign xml, basically the when the ID is retreived the correct ID is used.  
    /// without this, the id reference would not be valid.
    /// </summary>
    public class MySignedXml : SignedXml
    {
        private readonly string _referenceAttributeId = "";
        public MySignedXml(XmlDocument document, string referenceAttributeId)
            : base(document)
        {
            _referenceAttributeId = referenceAttributeId;
        }
        public override XmlElement GetIdElement(
            XmlDocument document, string idValue)
        {
            return (XmlElement)
                document.SelectSingleNode(
                    string.Format("//*[@{0}='{1}']",
                    _referenceAttributeId, idValue));
        }
    }
}
