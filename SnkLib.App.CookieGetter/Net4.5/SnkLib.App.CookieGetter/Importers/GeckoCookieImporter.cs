using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;

namespace SunokoLibrary.Application.Browsers
{
    /// <summary>
    /// FirefoxからCookieを取得します。
    /// </summary>
    public class GeckoCookieImporter : SqlCookieImporter
    {
#pragma warning disable 1591

        public GeckoCookieImporter(CookieSourceInfo info, int primaryLevel)
            : base(info, primaryLevel)
        {
        }

        // Firefox 142以降ではexpiryがミリ秒単位
        private const int MILLISECOND_EXPIRY_SCHEMA_VERSION = 16;

        public override ICookieImporter Generate(CookieSourceInfo newInfo)
        {
            return new GeckoCookieImporter(newInfo, PrimaryLevel);
        }

        protected override CookieImportResult ProtectedGetCookies(Uri targetUrl)
        {
            if (IsAvailable == false)
                return new CookieImportResult(
                    null, CookieImportState.Unavailable);

            try
            {
                int schemaVersion = GetDatabaseSchemaVersion();
                Debug.WriteLine("SchemaVersion: "+schemaVersion);

                var cookies = new CookieCollection();

                // FirefoxのCookieデータベースから必要な項目を取得
                var query = string.Format(
                    "SELECT value, name, host, path, expiry, isSecure " +
                    "FROM moz_cookies {0} ORDER BY expiry",
                    MakeWhere(targetUrl));

                foreach (var item in LookupCookies(
                    SourceInfo.CookiePath,
                    query,
                    data => DataToCookie(data, schemaVersion)))
                {
                    cookies.Add(item);
                }

                return new CookieImportResult(
                    cookies, CookieImportState.Success);
            }
            catch (CookieImportException ex)
            {
                TraceError(this, "取得に失敗しました。", ex.ToString());

                return new CookieImportResult(null, ex.Result);
            }
        }

        /// <summary>
        /// Firefox Cookie DBのスキーマバージョンを取得します。
        /// </summary>
        private int GetDatabaseSchemaVersion()
        {
            var records = LookupEntry(
                SourceInfo.CookiePath,
                "PRAGMA user_version;");

            if (records.Count == 0 ||
                records[0] == null ||
                records[0].Length == 0 ||
                records[0][0] == DBNull.Value)
            {
                throw new CookieImportException(
                    "Firefox Cookie DBのバージョンを取得できませんでした。",
                    CookieImportState.ConvertError);
            }

            try
            {
                return Convert.ToInt32(records[0][0]);
            }
            catch (Exception ex)
            {
                throw new CookieImportException(
                    "Firefox Cookie DBのバージョン変換に失敗しました。",
                    CookieImportState.ConvertError,
                    ex);
            }
        }

        protected Cookie DataToCookie(object[] data)
        {
            // 既存の呼び出しとの互換性を維持します。
            return DataToCookie(data, 0);
        }

        /// <summary>
        /// DBのスキーマバージョンに応じてCookieを変換します。
        /// </summary>
        protected Cookie DataToCookie(
            object[] data,
            int schemaVersion)
        {
            if (data == null ||
                data.Length < 6 ||
                data.Take(4).Any(
                    rec => rec is string == false) ||
                data[4] == null ||
                data[4] == DBNull.Value ||
                data[5] == null ||
                data[5] == DBNull.Value)
            {
                throw new CookieImportException(
                    "レコードからCookieオブジェクトへの変換に失敗しました。",
                    CookieImportState.ConvertError);
            }

            string value = (string)data[0];
            string name = (string)data[1];

            if (string.IsNullOrEmpty(value) ||
                string.IsNullOrEmpty(name))
            {
                return null;
            }

            long expiry;

            try
            {
                expiry = Convert.ToInt64(data[4]);
            }
            catch (Exception ex)
            {
                throw new CookieImportException(
                    "Cookieの有効期限の変換に失敗しました。",
                    CookieImportState.ConvertError,
                    ex);
            }

            // Firefox 142（スキーマバージョン16）以降はミリ秒単位
            if (schemaVersion >= MILLISECOND_EXPIRY_SCHEMA_VERSION)
            {
                expiry /= 1000L;
            }

            bool isSecure;

            try
            {
                isSecure = Convert.ToBoolean(
                    Convert.ToInt32(data[5]));
            }
            catch (Exception ex)
            {
                throw new CookieImportException(
                    "CookieのSecure属性の変換に失敗しました。",
                    CookieImportState.ConvertError,
                    ex);
            }

            var cookie = new Cookie()
            {
                Value = Uri.UnescapeDataString(value)
                    .Replace(";", "%3b")
                    .Replace(",", "%2c"),

                Name = name,
                Domain = (string)data[2],
                Path = (string)data[3],
                Expires = Utility.UnixTimeToDateTime((ulong)expiry),
                Secure = isSecure
            };

            return cookie;
        }

        protected string MakeWhere(Uri url)
        {
            Stack<string> hostStack =
                new Stack<string>(url.Host.Split('.'));

            StringBuilder hostBuilder =
                new StringBuilder('.' + hostStack.Pop());

            String[] pathes = url.Segments;

            StringBuilder sb = new StringBuilder();
            sb.Append("WHERE (");

            bool needOr = false;

            while (hostStack.Count != 0)
            {
                if (needOr)
                {
                    sb.Append(" OR");
                }

                if (hostStack.Count != 1)
                {
                    hostBuilder.Insert(
                        0, '.' + hostStack.Pop());

                    sb.AppendFormat(
                        " host = \"{0}\"",
                        hostBuilder.ToString());
                }
                else
                {
                    hostBuilder.Insert(
                        0, '%' + hostStack.Pop());

                    sb.AppendFormat(
                        " host LIKE \"{0}\"",
                        hostBuilder.ToString());
                }

                needOr = true;
            }

            sb.Append(')');
            return sb.ToString();
        }

#pragma warning restore 1591
    }
}