using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EncryptionLibrary.Test
{
    /// <summary>
    /// 暗号化・復号機能のテストクラス
    /// </summary>
    [TestClass]
    public class EncryptionTest
    {
        private Encryption _encryption;

        [TestInitialize]
        public void TestInitialize()
        {
            _encryption = new Encryption();
        }

        /// <summary>
        /// Encryptメソッドの引数がnullの場合、戻り値はnullとなる
        /// </summary>
        [TestMethod]
        public void Encrypt_TextIsNull()
        {
            string text = null;
            var result = _encryption.Encrypt(text);

            Assert.AreEqual(null, result);
        }

        /// <summary>
        /// Encryptメソッドの引数が空の場合、戻り値はnullとなる
        /// </summary>
        [TestMethod]
        public void Encrypt_TextIsEmpty()
        {
            string text = "";
            var result = _encryption.Encrypt(text);

            Assert.AreEqual(null, result);
        }

        /// <summary>
        /// Encryptメソッドの引数が空白の場合、戻り値はnullとなる
        /// </summary>
        [TestMethod]
        public void Encrypt_TextIsWhiteSpace()
        {
            string text = " ";
            var result = _encryption.Encrypt(text);

            Assert.AreEqual(null, result);
        }

        /// <summary>
        /// 暗号化に成功していること
        /// </summary>
        [TestMethod]
        public void Encrypt_Success()
        {
            string text = "test";
            var result = _encryption.Encrypt(text);

            Assert.AreNotEqual(text, result);
        }

        /// <summary>
        /// Decryptメソッドの引数がnullの場合、戻り値はnullとなる
        /// </summary>
        [TestMethod]
        public void Decrypt_TextIsNull()
        {
            string base64Text = null;
            var result = _encryption.Decrypt(base64Text);

            Assert.AreEqual(null, result);
        }

        /// <summary>
        /// Decryptメソッドの引数が空の場合、戻り値はnullとなる
        /// </summary>
        [TestMethod]
        public void Decrypt_TextIsEmpty()
        {
            string base64Text = "";
            var result = _encryption.Decrypt(base64Text);

            Assert.AreEqual(null, result);
        }

        /// <summary>
        /// Decryptメソッドの引数が空白の場合、戻り値はnullとなる
        /// </summary>
        [TestMethod]
        public void Decrypt_TextIsWhiteSpace()
        {
            string base64Text = " ";
            var result = _encryption.Decrypt(base64Text);

            Assert.AreEqual(null, result);
        }

        /// <summary>
        /// 復号に成功していること
        /// </summary>
        [TestMethod]
        public void Decrypt_Success()
        {
            string base64Text = _encryption.Encrypt("test");
            var result = _encryption.Decrypt(base64Text);

            Assert.AreEqual("test", result);
        }

        /// <summary>
        /// Decryptメソッドの引数が正しく暗号化された文字列でない場合、復号に失敗すること
        /// </summary>
        [TestMethod]
        public void Decrypt_Fail()
        {
            string text = "test";
            string errorMessage = "復号化するデータの長さが無効です。";

            var ex = Assert.ThrowsException<CryptographicException>(() => _encryption.Decrypt(text));
            Assert.AreEqual(errorMessage, ex.Message);
        }
    }
}