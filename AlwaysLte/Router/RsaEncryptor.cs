using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace AlwaysLte.Router
{
    public class RsaEncryptor
    {
        private List<byte> _publicKey;
        private List<byte> _exponent;

        public RsaEncryptor(string publicKey, string exponent)
        {
            _publicKey = GetBytesFromHex(publicKey);
            _exponent = GetBytesFromHex(exponent);
        }

        public string EncryptData(string data)
        {
            try
            {
                //initialze the byte arrays to the public key information.
                byte[] PublicKey = _publicKey.ToArray();
                byte[] Exponent = _exponent.ToArray();

                //Create a new instance of RSACryptoServiceProvider.
                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();

                //Create a new instance of RSAParameters.
                RSAParameters RSAKeyInfo = new RSAParameters();

                //Set RSAKeyInfo to the public key values. 
                RSAKeyInfo.Modulus = PublicKey;
                RSAKeyInfo.Exponent = Exponent;

                //Import key parameters into RSA.
                RSA.ImportParameters(RSAKeyInfo);

                var dataBytes = ASCIIEncoding.ASCII.GetBytes(data);
                var encryptedBytes = RSA.Encrypt(dataBytes, false);
                var encryptedValue = BitConverter.ToString(encryptedBytes).Replace("-", "").ToLower();
                return encryptedValue;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
            }

            return null;
        }

        private static List<byte> GetBytesFromHex(string input)
        {
            var result = new List<byte>();
            for (int i = 0; i < input.Length; i += 2)
            {
                var pair = input.Substring(i, 2);
                result.Add(Convert.ToByte(pair, 16));
            }
            return result;
        }
    }
}