using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionLibrary
{
    /// <summary>
    /// 文字列の暗号化と復号を管理する
    /// </summary>
    public class Encryption
    {
        #region Private consts

        /// <summary>
        /// 初期化ベクトル
        /// </summary>
        /// <remarks>
        /// 16文字(8bit*16文字=128bit)
        /// </remarks>
        private const string AES_IV = "EncryptionAES_IV";

        /// <summary>
        /// 暗号化鍵
        /// </summary>
        /// <remarks>
        /// 16文字(8bit*16文字=128bit)
        /// </remarks>
        private const string AES_KEY = "EncryptionAESKEY";
        #endregion

        #region Public methods

        /// <summary>
        /// 文字列をAES暗号化する
        /// </summary>
        /// <param name="text">暗号化する文字列</param>
        /// <returns>暗号化した文字列(Base64形式)</returns>
        public string Encrypt(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return null;

            // 暗号化鍵と初期ベクトルをバイト配列に変換
            byte[] key = Encoding.UTF8.GetBytes(AES_KEY);
            byte[] iv = Encoding.UTF8.GetBytes(AES_IV);

            // 暗号化対象の文字列をバイト配列に変換
            byte[] src = Encoding.UTF8.GetBytes(text);

            /* 
            以下の設定はデフォルト値となっているので特別な設定は行わない。
            ブロックサイズ:128bit
            暗号化利用モード:CBC
            パディング:PKCS7
            */
            using (var am = new AesManaged())
            using (var encryptor = am.CreateEncryptor(key, iv))
            using (var outStream = new MemoryStream())
            {
                using (var cs = new CryptoStream(outStream, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(src, 0, src.Length);
                }

                byte[] result = outStream.ToArray();
                return Convert.ToBase64String(result);
            }
        }

        /// <summary>
        /// Base64形式の文字列をAES復号する
        /// </summary>
        /// <param name="base64Text">暗号化された文字列(Base64形式)</param>
        /// <returns>復号した文字列</returns>
        public string Decrypt(string base64Text)
        {
            if (string.IsNullOrWhiteSpace(base64Text)) return null;

            // 暗号化鍵と初期ベクトルをバイト配列に変換
            byte[] key = Encoding.UTF8.GetBytes(AES_KEY);
            byte[] iv = Encoding.UTF8.GetBytes(AES_IV);

            // 復号対象の文字列をバイト配列に変換
            byte[] src = Convert.FromBase64String(base64Text);

            /* 
            以下の設定はデフォルト値となっているので特別な設定は行わない。
            ブロックサイズ:128bit
            暗号化利用モード:CBC
            パディング:PKCS7
            */
            using (var am = new AesManaged())
            using (var decryptor = am.CreateDecryptor(key, iv))
            using (var instream = new MemoryStream(src, false))
            using (var outStream = new MemoryStream())
            {
                using (var cs = new CryptoStream(instream, decryptor, CryptoStreamMode.Read))
                {
                    // バッファーサイズはBlockSizeの倍数用意する
                    int i = 4096;
                    byte[] buffer = new byte[i];
                    int len = 0;
                    while ((len = cs.Read(buffer, 0, i)) > 0)
                    {
                        outStream.Write(buffer, 0, len);
                    }
                }
                byte[] result = outStream.ToArray();
                return Encoding.UTF8.GetString(result);
            }
        }
        #endregion
    }
}