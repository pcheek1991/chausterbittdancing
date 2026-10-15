#requires -Version 7.6.6
#requires -PSEdition Core

<#
====================================================================
LU ZU MONOLITH ADBLOCK ENGINE
Version: 3.0-Core

Required runtime:
    PowerShell Core 7.6.6+

Purpose:
    - Inlined C# Filter Engine compiling in volatile memory via Add-Type
    - Integrated LuZuRot Cryptographic ROT Engine (ROT13/EBG13/ROTN)
    - Asynchronous HTTP background scheduler using HttpClient (.NET Core)
    - Full Thread-Safe domain lookups and live statistics
====================================================================
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' LU ZU MONOLITH ADBLOCK ENGINE & ROT ARCHIVIST' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host (
    ' Runtime: PowerShell {0} {1}' -f
    $PSVersionTable.PSVersion,
    $PSVersionTable.PSEdition
) -ForegroundColor Green
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ''

$cSharpSource = @"
using System;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;

namespace LuZuEngine
{
    // ==============================================================
    // EMBEDDED C# ROT ENGINE (LuZuRot)
    // ==============================================================
    public static class LuZuRot
    {
        private static readonly byte[] _signingKey;
        private static volatile int _ROTN_VOLATILE;

        static LuZuRot()
        {
            _signingKey = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(_signingKey);
            }
            _ROTN_VOLATILE = 0;
        }

        public static string ROT13(string value)
        {
            string sanitized = null;
            byte[] stringSignature = null;
            byte[] integerSignature = null;

            try
            {
                sanitized = Sanitize(value);
                stringSignature = SignString(sanitized);
                integerSignature = SignInt(13);

                return ROTN(sanitized, stringSignature, 13, integerSignature);
            }
            finally
            {
                ClearBytes(stringSignature);
                ClearBytes(integerSignature);
            }
        }

        public static string EBG13(string value)
        {
            string sanitized = null;
            byte[] stringSignature = null;
            byte[] integerSignature = null;

            try
            {
                sanitized = Sanitize(value);
                stringSignature = SignString(sanitized);
                integerSignature = SignInt(-13);

                return ROTN(sanitized, stringSignature, -13, integerSignature);
            }
            finally
            {
                ClearBytes(stringSignature);
                ClearBytes(integerSignature);
            }
        }

        private static string ROTN(string signedSanitizedString, byte[] signedStringSignature, int signedDistance, byte[] signedIntegerSignature)
        {
            Interlocked.Exchange(ref _ROTN_VOLATILE, 1);
            uint unsignedDistance = 0;

            try
            {
                ValidateSignedString(signedSanitizedString, signedStringSignature);
                ValidateSignedInt(signedDistance, signedIntegerSignature);

                int normalized = ((signedDistance % 26) + 26) % 26;
                unsignedDistance = (uint)normalized;

                return _rot(signedSanitizedString, unsignedDistance);
            }
            finally
            {
                ClearBytes(signedStringSignature);
                ClearBytes(signedIntegerSignature);
                Interlocked.Exchange(ref _ROTN_VOLATILE, 0);

                GC.Collect(0, GCCollectionMode.Optimized, false);
            }
        }

        private static string _rot(string value, uint distance)
        {
            if (string.IsNullOrEmpty(value)) return value;
            distance %= 26u;
            if (distance == 0u) return value;

            int dist = (int)distance;
            char[] chars = value.ToCharArray();

            try
            {
                for (int i = 0; i < chars.Length; ++i)
                {
                    int c = chars[i];
                    if (c >= 65 && c <= 90)
                    {
                        chars[i] = (char)(65 + ((c - 65 + dist) % 26));
                    }
                    else if (c >= 97 && c <= 122)
                    {
                        chars[i] = (char)(97 + ((c - 97 + dist) % 26));
                    }
                }
                return new string(chars);
            }
            finally
            {
                Array.Clear(chars, 0, chars.Length);
            }
        }

        private static string Sanitize(string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));
            if (value.IndexOf('\0') >= 0) throw new ArgumentException("NUL character detected.", nameof(value));
            return value;
        }

        private static byte[] SignString(string value) => Sign("ROT-STRING", value);
        private static byte[] SignInt(int value) => Sign("ROT-INTEGER", value.ToString(CultureInfo.InvariantCulture));

        private static void ValidateSignedString(string value, byte[] signature)
        {
            if (!ValidateSignature("ROT-STRING", value, signature))
                throw new CryptographicException("ROTN string signature mismatch.");
        }

        private static void ValidateSignedInt(int value, byte[] signature)
        {
            if (!ValidateSignature("ROT-INTEGER", value.ToString(CultureInfo.InvariantCulture), signature))
                throw new CryptographicException("ROTN integer signature mismatch.");
        }

        private static byte[] Sign(string domain, string payload)
        {
            byte[] data = Encoding.UTF8.GetBytes(domain + "\0" + payload);
            try
            {
                using (HMACSHA256 hmac = new HMACSHA256(_signingKey))
                {
                    return hmac.ComputeHash(data);
                }
            }
            finally
            {
                Array.Clear(data, 0, data.Length);
            }
        }

        private static bool ValidateSignature(string domain, string payload, byte[] supplied)
        {
            if (supplied == null) return false;
            byte[] expected = Sign(domain, payload);

            if (expected.Length != supplied.Length) return false;

            int difference = 0;
            for (int i = 0; i < expected.Length; ++i)
            {
                difference |= expected[i] ^ supplied[i];
            }
            Array.Clear(expected, 0, expected.Length);
            return difference == 0;
        }

        private static void ClearBytes(byte[] bytes)
        {
            if (bytes != null && bytes.Length > 0) Array.Clear(bytes, 0, bytes.Length);
        }
    }

    // ==============================================================
    // ADBLOCK FILTER ENGINE
    // ==============================================================
    public class FilterEngine
    {
        private const long UpdateIntervalMs = 24 * 60 * 60 * 1000;
        private HashSet<string> _blockedDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly object _lock = new object();
        private Timer _timer;
        private static readonly HttpClient _httpClient = new HttpClient();

        private static readonly string[][] FilterSources = new string[][]
        {
            new string[] { "EasyList", "https://easylist.to/easylist/easylist.txt" },
            new string[] { "EasyPrivacy", "https://easylist.to/easylist/easyprivacy.txt" },
            new string[] { "uBlock Filters", "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt" },
            new string[] { "AdGuard Base", "https://filters.adtidy.org/extension/ublock/filters/2.txt" },
            new string[] { "Peter Lowe", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext" },
            new string[] { "Fanboy Annoyance", "https://easylist.to/easylist/fanboy-annoyance.txt" },
            new string[] { "EasyList Cookie", "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt" },
            new string[] { "URLhaus Malicious", "https://urlhaus.abuse.ch/downloads/hostfile/" },
            new string[] { "Steven Black Unified", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" }
        };

        static FilterEngine()
        {
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) LuZuMonolithEngine/2.1");
        }

        public void StartScheduler()
        {
            _timer = new Timer(UpdateCallback, null, 0, UpdateIntervalMs);
        }

        private void UpdateCallback(object state)
        {
            Console.WriteLine("[LuZu Monolith] Starting background update cycle...");
            HashSet<string> tempSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var source in FilterSources)
            {
                string name = source[0];
                string url = source[1];

                try
                {
                    Console.WriteLine("[LuZu Monolith] Fetching: " + name);
                    string data = _httpClient.GetStringAsync(url).GetAwaiter().GetResult();
                    ParseFilterList(data, tempSet);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[LuZu Monolith] Failed to fetch " + name + ": " + ex.Message);
                }
            }

            lock (_lock)
            {
                _blockedDomains = tempSet;
            }

            Console.WriteLine("[LuZu Monolith] Cycle Complete! Total unique rules loaded: " + _blockedDomains.Count);
        }

        private void ParseFilterList(string content, HashSet<string> targetSet)
        {
            using (StringReader reader = new StringReader(content))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    line = line.Trim();
                    if (string.IsNullOrEmpty(line) || line.StartsWith("!") || line.StartsWith("["))
                        continue;

                    if (line.StartsWith("0.0.0.0 ") || line.StartsWith("127.0.0.1 "))
                    {
                        string[] parts = line.Split((char[])null, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length > 1)
                        {
                            targetSet.Add(parts[1]);
                        }
                    }
                    else if (line.StartsWith("||"))
                    {
                        string domain = line.Substring(2);
                        int caretIdx = domain.IndexOf('^');
                        if (caretIdx != -1) domain = domain.Substring(0, caretIdx);
                        int slashIdx = domain.IndexOf('/');
                        if (slashIdx != -1) domain = domain.Substring(0, slashIdx);

                        if (!string.IsNullOrEmpty(domain))
                        {
                            targetSet.Add(domain);
                        }
                    }
                }
            }
        }

        public bool IsDomainBlocked(string domain)
        {
            if (string.IsNullOrEmpty(domain)) return false;
            lock (_lock)
            {
                return _blockedDomains.Contains(domain);
            }
        }

        public int GetRuleCount()
        {
            lock (_lock)
            {
                return _blockedDomains.Count;
            }
        }
    }
}
"@

# ============================================================================
# POWERSHELL EXECUTION
# ============================================================================

Write-Host "Compiling LuZu C# Engine & ROT Archivist in-memory..." -ForegroundColor Cyan
Add-Type -TypeDefinition $cSharpSource -Language CSharp

# Self-Test Embedded C# ROT Engine
$testString = "LuZu-Archivist-Test"
$rotEncoded = [LuZuEngine.LuZuRot]::ROT13($testString)
$rotDecoded = [LuZuEngine.LuZuRot]::EBG13($rotEncoded)

if ($rotDecoded -ne$testString) {
    throw "LuZuRot Engine Self-Test Failed!"
}
Write-Host "[PASS] LuZuRot Engine cryptographically verified." -ForegroundColor Green

# Initialize Filter Engine
$engine = New-Object LuZuEngine.FilterEngine
Write-Host "Starting scheduler on background thread..." -ForegroundColor Green
$engine.StartScheduler()

Start-Sleep -Seconds 10

Write-Host "`n--- Performing Domain Lookups ---" -ForegroundColor Yellow
$testDomains = @("doubleclick.net", "analytics.google.com", "example.com", "s0.2mdn.net")

foreach ($domain in $testDomains) {
    $isBlocked = $engine.IsDomainBlocked($domain)
    if ($isBlocked) {
        Write-Host "[BLOCKED] $domain" -ForegroundColor Red
    } else {
        Write-Host "[ALLOWED] $domain" -ForegroundColor Green
    }
}

Write-Host "`nTotal Rules Cached in Memory: $($engine.GetRuleCount())" -ForegroundColor Cyan