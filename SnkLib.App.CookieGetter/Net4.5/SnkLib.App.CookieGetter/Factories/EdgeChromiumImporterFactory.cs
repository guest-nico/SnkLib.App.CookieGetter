using System;
using System.Collections.Generic;
using System.Text;

namespace SunokoLibrary.Application.Browsers
{
    /// <summary>
    /// MicrosoftEdge(Chromium)からICookieImporterを取得します。
    /// </summary>
    public class EdgeChromiumImporterFactory : BlinkImporterFactory
    {
#pragma warning disable 1591
        public EdgeChromiumImporterFactory() : base("MicrosoftEdge", "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data", 1) { }
#pragma warning restore 1591
    }
}