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
            const string s = "Hello World!";
            var input = Encoding.UTF8.GetBytes(s);
            Console.WriteLine($"Input: {s}");

            // openssl genrsa -out key.pem 2048
            // This is "-----BEGIN RSA PRIVATE KEY-----",
            // and not "-----BEGIN PRIVATE KEY-----"!
            // Note that this RSA private key contains the public key.
            var key_pem = File.ReadAllText("key.pem");
            Console.WriteLine($"RSA Private Key: {key_pem}");

            // openssl rsa -in key.pem -outform PEM -pubout -out public.pem
            // This is "-----BEGIN PUBLIC KEY-----",
            // the extracted public key from the RSA private key.
            var public_pem = File.ReadAllText("public.pem");
            Console.WriteLine($"Public Key: {public_pem}");
            
            var signer = SignerUtilities.GetSigner("SHA-256withRSA");
            signer.Init(true, GetPrivateKey(key_pem));
            signer.BlockUpdate(input, 0, input.Length);
            var signature = signer.GenerateSignature();
            Console.WriteLine($"Signature: {Convert.ToBase64String(signature)}");

            signer.Reset();
            signer.Init(false, GetExtractedPublicKey(key_pem));
            signer.BlockUpdate(input, 0, input.Length);
            var verified = signer.VerifySignature(signature);
            Console.WriteLine($"Verified: {verified}");
            
            signer.Reset();
            signer.Init(false, GetRsaPublicKey(public_pem));
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
