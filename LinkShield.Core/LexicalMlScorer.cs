using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;

namespace LinkShield.Core;

/// <summary>
/// Machine Learning-based URL threat scorer using ONNX Runtime.
/// Extracts lexical features from URLs and predicts phishing probability.
/// 
/// This is the final fallback in the threat detection waterfall:
///   1. Bootstrap blocklist -> Block if found
///   2. SQLite threats.db -> Block if found
///   3. ML Model (this class) -> Block if score >= 0.85
/// </summary>
public class LexicalMlScorer : IDisposable
{
    private readonly ILogger<LexicalMlScorer> _logger;
    private readonly InferenceSession _session;
    private readonly string _inputName;
    private bool _disposed;

    // Suspicious keywords - must match Python training script exactly
    private static readonly HashSet<string> SuspiciousKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "login", "signin", "sign-in", "log-in", "verify", "verification",
        "secure", "security", "account", "update", "confirm", "confirmation",
        "password", "credential", "banking", "bank", "paypal", "ebay",
        "amazon", "apple", "microsoft", "google", "facebook", "netflix",
        "support", "helpdesk", "suspended", "locked", "unusual", "activity",
        "wallet", "crypto", "bitcoin", "alert", "warning", "urgent",
        "validate", "restore", "recover", "reset", "expire", "limited"
    };

    // Special characters to count
    private static readonly HashSet<char> SpecialChars = new()
    {
        '-', '@', '?', '=', '&', '%', '#', '!', '$', '+', '~', '_',
        '[', ']', '{', '}', '|', '\\', ';', ':', ',', '<', '>'
    };

    // IPv4 pattern for detection
    private static readonly Regex Ipv4Regex = new(
        @"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        RegexOptions.Compiled);

    /// <summary>
    /// Initialize the ML scorer by loading the ONNX model from embedded resources.
    /// </summary>
    public LexicalMlScorer(ILogger<LexicalMlScorer> logger)
    {
        _logger = logger;

        try
        {
            // Load model from embedded resource
            var assembly = Assembly.GetExecutingAssembly();
            var resourceName = "LinkShield.Core.Resources.linkshield_model.onnx";
            
            using var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream == null)
            {
                // Try loading from file as fallback (for development)
                var filePath = Path.Combine(AppContext.BaseDirectory, "Resources", "linkshield_model.onnx");
                if (File.Exists(filePath))
                {
                    _session = new InferenceSession(filePath);
                    _logger.LogInformation("ML model loaded from file: {Path}", filePath);
                }
                else
                {
                    throw new FileNotFoundException(
                        $"ONNX model not found. Tried embedded resource '{resourceName}' and file '{filePath}'");
                }
            }
            else
            {
                // Load from embedded resource
                using var ms = new MemoryStream();
                stream.CopyTo(ms);
                _session = new InferenceSession(ms.ToArray());
                _logger.LogInformation("ML model loaded from embedded resource");
            }

            // Get input name from model metadata
            _inputName = _session.InputMetadata.Keys.First();
            _logger.LogDebug("ML model input name: {InputName}", _inputName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load ONNX model. ML scoring will be disabled.");
            throw;
        }
    }

    /// <summary>
    /// Calculate the phishing threat score for a URL.
    /// </summary>
    /// <param name="url">The URL to analyze</param>
    /// <returns>Probability score between 0.0 (safe) and 1.0 (phishing)</returns>
    public float GetThreatScore(string url)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(LexicalMlScorer));

        try
        {
            // Extract features (must match Python exactly)
            var features = ExtractFeatures(url);
            
            // Create input tensor
            var inputTensor = new DenseTensor<float>(features, new[] { 1, 10 });
            var inputs = new List<NamedOnnxValue>
            {
                NamedOnnxValue.CreateFromTensor(_inputName, inputTensor)
            };

            // Run inference
            using var results = _session.Run(inputs);
            
            // Get probabilities - RandomForest outputs probabilities for each class
            // Output shape is [1, 2] for [legitimate_prob, phishing_prob]
            var probabilitiesResult = results.FirstOrDefault(r => r.Name == "probabilities");
            
            if (probabilitiesResult != null)
            {
                var probabilities = probabilitiesResult.AsTensor<float>();
                // Shape is [1, 2] - need to use 2D indexing: [batch_index, class_index]
                // Class 0 = legitimate, Class 1 = phishing
                var phishingScore = probabilities[0, 1]; // Row 0, Column 1 (phishing probability)
                
                _logger.LogDebug("ML score for {Url}: {Score:P2}", 
                    url.Length > 50 ? url[..50] + "..." : url, phishingScore);
                return phishingScore;
            }

            // Fallback: try to get label output
            var labelResult = results.FirstOrDefault(r => r.Name == "label");
            if (labelResult != null)
            {
                var label = labelResult.AsTensor<long>();
                // If we only have labels, return 1.0 for phishing, 0.0 for safe
                return label[0] == 1 ? 1.0f : 0.0f;
            }

            _logger.LogWarning("Unexpected model output format. Returning safe score.");
            return 0.0f;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error running ML inference for URL: {Url}. Failing safe.", url);
            return 0.0f; // Fail-open: treat as safe on error
        }
    }

    /// <summary>
    /// Extract features from a URL for ML prediction.
    /// IMPORTANT: Must match the Python training script exactly!
    /// 
    /// Features (10 total):
    /// 0. url_length: Total length of URL
    /// 1. digit_count: Number of digits
    /// 2. special_char_count: Number of special characters
    /// 3. entropy: Shannon entropy of URL
    /// 4. suspicious_keyword_count: Count of suspicious keywords
    /// 5. subdomain_count: Number of subdomains
    /// 6. has_ip: Whether URL uses IP instead of domain (0 or 1)
    /// 7. path_length: Length of the path component
    /// 8. query_length: Length of the query string
    /// 9. dot_count: Number of dots in the domain
    /// </summary>
    private static float[] ExtractFeatures(string url)
    {
        var urlLower = url.ToLowerInvariant();
        
        // Feature 0: URL length
        float urlLength = url.Length;

        // Feature 1: Digit count
        float digitCount = url.Count(char.IsDigit);

        // Feature 2: Special character count
        float specialCharCount = url.Count(c => SpecialChars.Contains(c));

        // Feature 3: Shannon entropy
        float entropy = CalculateEntropy(url);

        // Feature 4: Suspicious keyword count
        float suspiciousKeywordCount = SuspiciousKeywords.Count(kw => urlLower.Contains(kw));

        // Feature 5: Subdomain count
        float subdomainCount = CountSubdomains(url);

        // Feature 6: Has IP address
        float hasIp = Ipv4Regex.IsMatch(url) ? 1.0f : 0.0f;

        // Features 7 & 8: Path and query lengths
        float pathLength = 0;
        float queryLength = 0;
        
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            pathLength = uri.AbsolutePath?.Length ?? 0;
            queryLength = uri.Query?.TrimStart('?').Length ?? 0;
        }

        // Feature 9: Dot count in domain
        float dotCount = CountDotsInDomain(url);

        return new[]
        {
            urlLength,
            digitCount,
            specialCharCount,
            entropy,
            suspiciousKeywordCount,
            subdomainCount,
            hasIp,
            pathLength,
            queryLength,
            dotCount
        };
    }

    /// <summary>
    /// Calculate Shannon entropy of a string.
    /// </summary>
    private static float CalculateEntropy(string s)
    {
        if (string.IsNullOrEmpty(s))
            return 0.0f;

        var freq = new Dictionary<char, int>();
        foreach (var c in s)
        {
            freq[c] = freq.GetValueOrDefault(c, 0) + 1;
        }

        var length = (float)s.Length;
        var entropy = 0.0f;

        foreach (var count in freq.Values)
        {
            var probability = count / length;
            if (probability > 0)
            {
                entropy -= probability * MathF.Log2(probability);
            }
        }

        return entropy;
    }

    /// <summary>
    /// Count the number of subdomains in a URL.
    /// </summary>
    private static float CountSubdomains(string url)
    {
        try
        {
            var match = Regex.Match(url, @"://([^/]+)");
            if (!match.Success)
                return 0;

            var domain = match.Groups[1].Value.Split(':')[0]; // Remove port
            var parts = domain.Split('.');
            
            // Subtract 2 for TLD and main domain (e.g., example.com)
            return Math.Max(0, parts.Length - 2);
        }
        catch
        {
            return 0;
        }
    }

    /// <summary>
    /// Count dots in the domain portion of a URL.
    /// </summary>
    private static float CountDotsInDomain(string url)
    {
        try
        {
            var match = Regex.Match(url, @"://([^/]+)");
            if (!match.Success)
                return 0;

            var domain = match.Groups[1].Value.Split(':')[0];
            return domain.Count(c => c == '.');
        }
        catch
        {
            return 0;
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _session?.Dispose();
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }
}
