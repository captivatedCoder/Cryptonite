﻿using CustomExtensions;
using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace Cryptonite
{
    public static class Cryptonite
    {
        public static string Encrypt(SecureString secureStringText, SecureString password)
        {
            return EncryptString(secureStringText, password);
        }

        public static string Decrypt(SecureString secureStringText, SecureString password)
        {
            return DecryptString(secureStringText, password);
        }

        private const int saltLength = 512;

        private static byte[] GetRandomBytes()
        {
            var ba = new byte[saltLength];

            RandomNumberGenerator.Create().GetBytes(ba);

            return ba;
        }

        private static string EncryptString(SecureString text, SecureString password)
        {
            var passwordBytes = Encoding.UTF8.GetBytes(password.ToInsecureString());

            var passwordHash = SHA512.Create().ComputeHash(passwordBytes);
            var textBytes = Encoding.UTF8.GetBytes(text.ToInsecureString());

            var saltBytes = GetRandomBytes();
            var encryptedBytes = new byte[saltBytes.Length + textBytes.Length];

            for (var i = 0; i < saltBytes.Length; i++)
                encryptedBytes[i] = saltBytes[i];
            for (var i = 0; i < textBytes.Length; i++)
                encryptedBytes[i + saltBytes.Length] = textBytes[i];

            encryptedBytes = AES_Encrypt(encryptedBytes, passwordHash);

            return Convert.ToBase64String(encryptedBytes);
        }

        private static string DecryptString(SecureString text, SecureString password)
        {
            var passwordHash = SHA512.Create().ComputeHash(Encoding.UTF8.GetBytes(password.ToInsecureString()));
            var textBytes = Convert.FromBase64String(text.ToInsecureString());

            var decryptedBytes = AES_Decrypt(textBytes, passwordHash);
            var resultBytes = new byte[decryptedBytes.Length - saltLength];

            for (var i = 0; i < resultBytes.Length; i++)
                resultBytes[i] = decryptedBytes[i + saltLength];

            return Encoding.UTF8.GetString(resultBytes);
        }

        private static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;
            var saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (var ms = new MemoryStream())
            {
                using (var AES = new AesManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }

        private static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;
            var saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (var ms = new MemoryStream())
            {
                using (var AES = new AesManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }
    }
}
