// --------------------------------------------------------------------------------------------------------------------
// <copyright file="Cognition.cs" company="Pasi J. Elo">
//   Copyright © Pasi J. Elo 2014 All rights reserved.
// </copyright>
// <summary>
//   Defines the Crypto type.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace WPF_License_Manager
{
    using System;
    using System.IO;
    using System.Linq.Expressions;
    using System.Security;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// The crypto.
    /// </summary>
    internal class Cognition
    {
        /// <summary>
        /// The entropy.
        /// </summary>
        private readonly byte[] entropy = Encoding.Unicode.GetBytes("QBtyMJ4PsWNApang7f8xh5Fg");

        /// <summary>
        /// The to secure string.
        /// </summary>
        /// <param name="input">
        /// The input.
        /// </param>
        /// <returns>
        /// The <see cref="SecureString"/>.
        /// </returns>
        public static SecureString ToSecureString(string input)
        {
            var secure = new SecureString();
            foreach (var c in input)
            {
                secure.AppendChar(c);
            }

            secure.MakeReadOnly();
            return secure;
        }

        /// <summary>
        /// The to insecure string.
        /// </summary>
        /// <param name="input">
        /// The input.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        public static string ToInsecureString(SecureString input)
        {
            string returnValue;
            var ptr = System.Runtime.InteropServices.Marshal.SecureStringToBSTR(input);
            try
            {
                returnValue = System.Runtime.InteropServices.Marshal.PtrToStringBSTR(ptr);
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.ZeroFreeBSTR(ptr);
            }

            return returnValue;
        }

        /// <summary>
        /// The encrypt stream.
        /// </summary>
        /// <param name="plainText">
        /// The plain text.
        /// </param>
        /// <param name="sharedSecret">
        /// The shared secret.
        /// </param>
        /// <returns>
        /// The <see cref="Stream"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// The exception.
        /// </exception>
        public Stream EncryptStream(Stream plainText, SecureString sharedSecret)
        {
            if (plainText.Length <= 0)//string.IsNullOrEmpty(plainText))
            {
                throw new ArgumentNullException("plainText");
            }

            Stream outStr;                       // Encrypted string to return
            RijndaelManaged aesAlg = null;              // RijndaelManaged object used to encrypt the data.
            try
            {
                //// generate the key from the shared secret and the salt

                var key = new Rfc2898DeriveBytes(ToInsecureString(sharedSecret), this.entropy);

                // Create a RijndaelManaged object
                aesAlg = new RijndaelManaged();
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                key.Dispose();
                //// Create a decryptor to perform the stream transform.
                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (var msencrypt = new MemoryStream())
                {
                    // prepend the IV
                    msencrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
                    msencrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                    using (var csencrypt = new CryptoStream(msencrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swencrypt = new StreamWriter(csencrypt))
                        {
                            ////Write all data to the stream.
                            swencrypt.Write(plainText);
                        }
                    }

                    outStr = msencrypt; //= Convert.ToBase64String(msencrypt.ToArray());
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                if (aesAlg != null)
                {
                    aesAlg.Clear();
                }
            }

            // Return the encrypted bytes from the memory stream.
            return outStr;
        }

        /// <summary>
        /// The decrypt stream.
        /// </summary>
        /// <param name="cipherText">
        /// The cipher text.
        /// </param>
        /// <param name="sharedSecret">
        /// The shared secret.
        /// </param>
        /// <returns>
        /// The <see cref="Stream"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// The exception.
        /// </exception>
        public Stream DecryptStream(Stream cipherText, SecureString sharedSecret)
        {
            if (cipherText.Length <= 0)//string.IsNullOrEmpty(cipherText))
            {
                throw new ArgumentNullException("cipherText");
            }

            // Declare the RijndaelManaged object
            // used to decrypt the data.
            RijndaelManaged aesAlg = null;

            // Declare the string used to hold
            // the decrypted text.
            Stream plaintext;

            try
            {
                // generate the key from the shared secret and the salt
                var key = new Rfc2898DeriveBytes(ToInsecureString(sharedSecret), this.entropy);

                // Create the streams used for decryption.                
                // var bytes = Convert.FromBase64String(cipherText);
                using (var msdecrypt = new MemoryStream())
                {
                    cipherText.CopyTo(msdecrypt);

                    // Create a RijndaelManaged object
                    // with the specified key and IV.
                    aesAlg = new RijndaelManaged();
                    aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                    key.Dispose();
                    //// Get the initialization vector from the encrypted stream
                    aesAlg.IV = ReadByteArray(msdecrypt);
                    //// Create a decrytor to perform the stream transform.
                    var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    using (var csdecrypt = new CryptoStream(msdecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srdecrypt = new StreamReader(csdecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srdecrypt.BaseStream;
                            //srdecrypt.BaseStream.CopyTo(plaintext);//.ReadToEnd();
                        }
                    }
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                if (aesAlg != null)
                {
                    aesAlg.Clear();
                }
            }

            return plaintext;
        }

        /// <summary>
        /// The encrypt string.
        /// </summary>
        /// <param name="input">
        /// The input.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        public string IncognitoString(SecureString input)
        {
            var encryptedData = ProtectedData.Protect(
                Encoding.Unicode.GetBytes(ToInsecureString(input)),
                this.entropy,
                DataProtectionScope.CurrentUser);
            return Convert.ToBase64String(encryptedData);
        }

        /// <summary>
        /// The decrypt string.
        /// </summary>
        /// <param name="encryptedData">
        /// The encrypted data.
        /// </param>
        /// <returns>
        /// The <see cref="SecureString"/>.
        /// </returns>
        public SecureString CognitoString(string encryptedData)
        {
            try
            {
                var decryptedData = ProtectedData.Unprotect(
                    Convert.FromBase64String(encryptedData),
                    this.entropy,
                    DataProtectionScope.CurrentUser);
                return ToSecureString(Encoding.Unicode.GetString(decryptedData));
            }
            catch
            {
                return new SecureString();
            }
        }

        /// <summary>
        /// The read byte array.
        /// </summary>
        /// <param name="stream">
        /// The stream.
        /// </param>
        /// <returns>
        /// The <see>
        ///         <cref>byte[]</cref>
        ///     </see>
        ///     .
        /// </returns>
        /// <exception cref="SystemException">
        /// The exception.
        /// </exception>
        private static byte[] ReadByteArray(Stream stream)
        {
            var rawLength = new byte[sizeof(int)];
            if (stream.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
            {
                throw new SystemException("Stream did not contain properly formatted byte array");
            }

            var buffer = new byte[BitConverter.ToInt32(rawLength, 0)];
            if (stream.Read(buffer, 0, buffer.Length) != buffer.Length)
            {
                throw new SystemException("Did not read byte array properly");
            }

            return buffer;
        }
    }
}
