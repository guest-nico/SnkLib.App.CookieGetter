﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace SunokoLibrary.Application.Browsers
{
    /// <summary>
    /// GoogleChromeからCookieを取得します。
    /// </summary>
    public class BlinkCookieImporter : SqlCookieImporter
    {
#pragma warning disable 1591

        public BlinkCookieImporter(CookieSourceInfo info, int primaryLevel) : base(info, primaryLevel) { }
        const string SELECT_QUERY_VERSION = "SELECT value FROM meta WHERE key='version';";
        const string SELECT_QUERY = "SELECT value, name, host_key, path, expires_utc FROM cookies";
        const string SELECT_QUERY_V7 = "SELECT encrypted_value, name, host_key, path, expires_utc FROM cookies";

        public override ICookieImporter Generate(CookieSourceInfo newInfo)
        { return new BlinkCookieImporter(newInfo, PrimaryLevel); }
        protected override CookieImportResult ProtectedGetCookies(Uri targetUrl)
        {
            if (IsAvailable == false)
                return new CookieImportResult(null,CookieImportState.Unavailable);
            try
            {
                var formatVersionRec = LookupEntry(SourceInfo.CookiePath, SELECT_QUERY_VERSION);
                int formatVersion;
                if (formatVersionRec.Count == 0
                    || formatVersionRec[0].Length == 0
                    || int.TryParse((string)formatVersionRec[0][0], out formatVersion) == false)
                    return new CookieImportResult(null,CookieImportState.ConvertError);

                //Local Stateファイル名を取得
                //EngineIdをクラス名としてインスタンス作成
                string localstate = null;
                var ty = Type.GetType(this.SourceInfo.EngineId);
                var obj = Activator.CreateInstance(ty);
                //その中のGetStateFileメソッド呼び出し
                var mt = ty.GetMethod("GetStateFile");
                try { localstate = (string)mt.Invoke(obj, new object[] { this.SourceInfo.CookiePath }); }
                catch (Exception) { localstate = null; }
                
                string query;
                query = formatVersion < 7 ? SELECT_QUERY : SELECT_QUERY_V7;
                query = string.Format("{0} {1} ORDER BY creation_utc DESC", query, MakeWhere(targetUrl));
                var cookies = new CookieCollection();
                var l = LookupCookies(SourceInfo.CookiePath, query, rec => DataToCookie(rec, formatVersion, localstate));
                foreach (var item in l)
                    cookies.Add(item);
                return new CookieImportResult(cookies, CookieImportState.Success);
            }
            catch (CookieImportException ex)
            {
                TraceError(this, "取得に失敗しました。", ex.ToString());
                return new CookieImportResult(null, ex.Result);
            }
        }
        protected Cookie DataToCookie(object[] data, int formatVersion, string localstate)
        {
            if (formatVersion < 7
                ? data.Take(4).Where(rec => rec is string == false).Any() || data[4] is long == false
                : data[0] is byte[] == false || data.Skip(1).Take(3).Where(rec => rec is string == false).Any() || data[4] is long == false)
                throw new CookieImportException(
                    "未知の項目をレコードから発見。レコードからCookieオブジェクトへの変換に失敗しました。", CookieImportState.ConvertError);

            var expiresDt = (ulong)(long)data[4];
            var baseObj = new Cookie()
            {
                Name = data[1] as string,
                Domain = data[2] as string,
                Path = data[3] as string,
                Expires = expiresDt > 0
                    ? Utility.UnixTimeToDateTime(expiresDt / 1000000 - 11644473600) : DateTime.MinValue,
            };

            //Cookieの値の読み込み。値はURLエンコード済みなのでそのまま放り込む。
            //列数6ならばCookie格納方法のバージョンはCookieが暗号化された7以降と分かる
            if (formatVersion >= 7)
            {
                var cipher = data[0] as byte[];
                if (cipher == null)
                    throw new CookieImportException(
                        "Cookieファイルから暗号化データを取得できませんでした。", CookieImportState.ConvertError);

                if (cipher.Length == 0)
                    baseObj.Value = string.Empty;
                else
                {
                	var isAead = cipher[0] == 118 && cipher[1] == 49 && cipher[2] == 48;//starts with v10
                	if (isAead)
                    //if (formatVersion >= 12)
                    {
                        var plain = decryptAeadProtectedData(cipher, localstate);
                        if (plain == null)
                            throw new CookieImportException(
                                "Cookieの暗号化データを復号化できませんでした。aead", CookieImportState.ConvertError);
                        baseObj.Value = plain;
                    }
                    else
                    {
                        var plain = Win32Api.DecryptProtectedData(cipher);
                        if (plain == null)
                            throw new CookieImportException(
                                "Cookieの暗号化データを復号化できませんでした。", CookieImportState.ConvertError);
                        baseObj.Value = Encoding.UTF8.GetString(plain);
                    }
                }
            }
            else
                baseObj.Value = data[0] as string;
            return baseObj;
        }
        protected string MakeWhere(Uri url)
        {
            //A.B.comを[[com], [B, com], [A, B, com]]な形にする
            //メインドメインまでのサブドメインの全パターンを持った配列を作る
            var domains = url.Host.Split('.')
                .Reverse().Aggregate(
                    Enumerable.Repeat(Enumerable.Empty<string>(), 1),
                    (tmp, val) => tmp.Concat(Enumerable.Repeat(Enumerable.Repeat(val, 1).Concat(tmp.Last()), 1)))
                .Skip(2)
                .Select(levels => string.Join(".", levels.ToArray()))
                .SelectMany(domain => new[] { domain, "." + domain });
            //全てのドメインをOR文で結ぶ
            var query = string.Format(" WHERE ({0})", string.Join(
                " OR ", domains.Select(domain => string.Format("host_key = \"{0}\"", domain)).ToArray()));
            return query;
        }

        private string decryptAeadProtectedData(byte[] payload, string localstate)
        {
            var nonce = new List<byte>(payload).GetRange(3, 96 / 8);
            var cipher = new List<byte>(payload).GetRange(3 + 96 / 8, payload.Length - (3 + 96 / 8));
            var oskey = getOsKey(localstate);

            if (nonce == null || cipher == null || oskey == null) return null;
            var dec = decodeAead(cipher.ToArray(), nonce.ToArray(), oskey);
            return dec;
        }
        private byte[] getOsKey(string localstate)
        {
            try
            {
                var path = localstate;
                if (localstate == null)
                    path = getLocalStateFile(this.SourceInfo.CookiePath);
                if (path == null) return null;
                using (var f = new StreamReader(path))
                {
                    var t = f.ReadToEnd();

                    var m = new System.Text.RegularExpressions.Regex("\"encrypted_key\":\"(.+?)\"").Match(t);
                    if (m.Groups.Count < 2) return null;

                    var b = Convert.FromBase64String(m.Groups[1].ToString());
                    b = new List<byte>(b).GetRange(5, b.Length - 5).ToArray();
                    var plain = Win32Api.DecryptProtectedData(b);
                    return plain;
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.Message + e.Source + e.StackTrace + e.TargetSite);
                return null;
            }
        }
        public static string getLocalStateFile(string cookiepath)
        {
            DirectoryInfo parent = Directory.GetParent(cookiepath);
            string path = null;
            try
            {
                int count = 3;
                while (count > 0)
                {
                    var fList = from file in parent.EnumerateFiles()
                                where file.Name.ToLower().Replace(" ", "").EndsWith("localstate")
                                select new { file.FullName };
                    if (fList.ToList().Count > 0)
                    {
                        path = fList.FirstOrDefault().FullName;
                        break;
                    }
                    count--;
                    parent = parent.Parent;
                }
            }
            catch (Exception)
            {
                return null;
            }
            return path;
        }
        private string decodeAead(byte[] chunk, byte[] nonce, byte[] oskey)
        {
            var iv = generateNonce(nonce, 0);
            if (iv == null) return null;
            var dec = DecryptWithKey(chunk, oskey, iv);
            if (dec == null) return null;
            return Encoding.ASCII.GetString(dec);

        }
        private byte[] DecryptWithKey(byte[] encryptedMessage, byte[] key, byte[] nonce)
        {
        	try {
	            int _macSize = 128;
	
	            if (encryptedMessage == null || encryptedMessage.Length == 0)
	            {
	                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");
	            }
	
	            using (var cipherStream = new MemoryStream(encryptedMessage))
	            using (var cipherReader = new BinaryReader(cipherStream))
	            {
	
	                var cipher = new GcmBlockCipher(new AesEngine());
	                var parameters = new AeadParameters(new KeyParameter(key), _macSize, nonce);
	                cipher.Init(false, parameters);
	
	                //Decrypt Cipher Text
	                var cipherText = cipherReader.ReadBytes(encryptedMessage.Length);
	                var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];
	                var outSize = cipher.GetOutputSize(cipherText.Length);
	
	                var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
	                cipher.DoFinal(plainText, len);
	
	                return plainText;
	                //return null;
	            }
        	} catch (Exception e) {
        		Debug.WriteLine(e.Message + e.Source + e.StackTrace + e.TargetSite);
        		return null;
        	}
        }
        private byte[] generateNonce(byte[] _base, int index)
        {
            if (index >= System.Math.Pow(2, 48))
            {
                Debug.WriteLine("Nonce index is too large  BAD_CRYPTO");
                return null;
            }
            var nonce = new byte[12];
            Array.Copy(_base, 0, nonce, 0, 12);


            for (var i = 0; i < 6; ++i)
            {
                var b = System.Math.Pow(256, i);
                int num0 = (int)(index / System.Math.Pow(256, i));
                var tes0 = num0 & (byte)0xff;

                //byte b = nonce[nonce.Length - 1 - i] ^ yte)num1 & (byte)3);
                var nonceI = nonce.Length - 1 - i;
                nonce[nonceI] ^= (byte)tes0;
                //nonce[nonce.Length - 1 - i] ^= (byte)(index / System.Math.Pow(256, i)) & 0xff;
                //(index / Math.pow(256, i)) & 0xff;
            }

            return nonce;
        }

#pragma warning restore 1591
    }
}
