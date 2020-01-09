using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace BouncyCastleSignerUtilitiesPemRsaDemo
{
    /// <summary>
    /// BouncyCastle SignerUtilities demo: PEM key format and SHA-256 with RSA.
    /// </summary>
    public class Program
    {
        public static AsymmetricKeyParameter GetPrivateKey(string pem)
        {
            var asymmetricCipherKeyPair = (AsymmetricCipherKeyPair)new PemReader(new StringReader(pem)).ReadObject();
            //return (RsaPrivateCrtKeyParameters)asymmetricCipherKeyPair.Private;
            return asymmetricCipherKeyPair.Private;
        }

        public static AsymmetricKeyParameter GetExtractedPublicKey(string pem)
        {
            var asymmetricCipherKeyPair = (AsymmetricCipherKeyPair)new PemReader(new StringReader(pem)).ReadObject();
            // return (RsaKeyParameters)asymmetricCipherKeyPair.Public;
            return asymmetricCipherKeyPair.Public;
        }

        public static RsaKeyParameters GetRsaPublicKey(string pem)
        {
            return (RsaKeyParameters)new PemReader(new StringReader(pem)).ReadObject();
        }

        public static void Main()
        {
            // openssl genrsa -out key.pem 2048
            // openssl rsa -in key.pem -outform PEM -pubout -out public.pem

            const string s = "Hello World!";
            var input = Encoding.UTF8.GetBytes(s);
            Console.WriteLine($"Input: {s}");

            var signer = SignerUtilities.GetSigner("SHA-256withRSA");
            // This must not be "-----BEGIN PRIVATE KEY-----"!
            signer.Init(true, GetPrivateKey(File.ReadAllText("key.pem")));
            signer.BlockUpdate(input, 0, input.Length);
            var signature = signer.GenerateSignature();
            Console.WriteLine($"Signature: {Convert.ToBase64String(signature)}");

            signer.Reset();
            signer.Init(false, GetExtractedPublicKey(File.ReadAllText("key.pem")));
            signer.BlockUpdate(input, 0, input.Length);
            var verified = signer.VerifySignature(signature);
            Console.WriteLine($"Verified: {verified}");

            signer.Reset();
            signer.Init(false, GetRsaPublicKey(File.ReadAllText("public.pem")));
            signer.BlockUpdate(input, 0, input.Length);
            verified = signer.VerifySignature(signature);
            Console.WriteLine($"Verified: {verified}");

            input[0] = 0;
            signer.BlockUpdate(input, 0, input.Length);
            verified = signer.VerifySignature(signature);
            Console.WriteLine($"Verified: {verified}");
        }
    }
}