#!/usr/bin/env python3
"""
LinkShield ML Model Training Script
====================================
Generates an ONNX model for zero-day phishing URL detection.

Features extracted from URLs:
1. URL length
2. Number of digits
3. Number of special characters (-, @, ?, =, &, %, etc.)
4. Shannon entropy of the URL string
5. Number of suspicious keywords (login, verify, secure, account, update, etc.)
6. Number of subdomains
7. Has IP address instead of domain
8. Path length
9. Query string length
10. Number of dots in domain

Usage:
    pip install scikit-learn skl2onnx numpy pandas
    python train_model.py
    
Output:
    linkshield_model.onnx - The trained model for C# integration
"""

import math
import re
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import warnings

warnings.filterwarnings('ignore')

# Suspicious keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification',
    'secure', 'security', 'account', 'update', 'confirm', 'confirmation',
    'password', 'credential', 'banking', 'bank', 'paypal', 'ebay',
    'amazon', 'apple', 'microsoft', 'google', 'facebook', 'netflix',
    'support', 'helpdesk', 'suspended', 'locked', 'unusual', 'activity',
    'wallet', 'crypto', 'bitcoin', 'alert', 'warning', 'urgent',
    'validate', 'restore', 'recover', 'reset', 'expire', 'limited'
]


def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    
    # Count character frequencies
    freq = {}
    for char in s:
        freq[char] = freq.get(char, 0) + 1
    
    # Calculate entropy
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def has_ip_address(url: str) -> int:
    """Check if URL contains an IP address instead of domain."""
    # IPv4 pattern
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    # IPv6 pattern (simplified)
    ipv6_pattern = r'\[?[0-9a-fA-F:]+\]?'
    
    if re.search(ipv4_pattern, url):
        return 1
    if re.search(ipv6_pattern, url) and '::' in url:
        return 1
    return 0


def count_subdomains(url: str) -> int:
    """Count number of subdomains in the URL."""
    try:
        # Extract domain part
        domain_match = re.search(r'://([^/]+)', url)
        if not domain_match:
            return 0
        
        domain = domain_match.group(1).split(':')[0]  # Remove port
        parts = domain.split('.')
        
        # Subtract 2 for TLD and main domain (e.g., example.com)
        # Handle special TLDs like .co.uk
        if len(parts) >= 2:
            return max(0, len(parts) - 2)
        return 0
    except:
        return 0


def extract_features(url: str) -> list:
    """
    Extract features from a URL for ML prediction.
    
    Features (10 total):
    0. url_length: Total length of URL
    1. digit_count: Number of digits
    2. special_char_count: Number of special characters
    3. entropy: Shannon entropy of URL
    4. suspicious_keyword_count: Count of suspicious keywords
    5. subdomain_count: Number of subdomains
    6. has_ip: Whether URL uses IP instead of domain (0 or 1)
    7. path_length: Length of the path component
    8. query_length: Length of the query string
    9. dot_count: Number of dots in the domain
    """
    url_lower = url.lower()
    
    # Feature 0: URL length
    url_length = len(url)
    
    # Feature 1: Count of digits
    digit_count = sum(c.isdigit() for c in url)
    
    # Feature 2: Count of special characters
    special_chars = set('-@?=&%#!$+~_[]{}|\\;:,<>')
    special_char_count = sum(c in special_chars for c in url)
    
    # Feature 3: Shannon entropy
    entropy = calculate_entropy(url)
    
    # Feature 4: Suspicious keyword count
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    
    # Feature 5: Subdomain count
    subdomain_count = count_subdomains(url)
    
    # Feature 6: Has IP address
    has_ip = has_ip_address(url)
    
    # Feature 7 & 8: Path and query lengths
    path_length = 0
    query_length = 0
    try:
        # Extract path
        path_match = re.search(r'://[^/]+(/[^?]*)?', url)
        if path_match and path_match.group(1):
            path_length = len(path_match.group(1))
        
        # Extract query
        query_match = re.search(r'\?(.*)$', url)
        if query_match:
            query_length = len(query_match.group(1))
    except:
        pass
    
    # Feature 9: Dot count in domain
    dot_count = 0
    try:
        domain_match = re.search(r'://([^/]+)', url)
        if domain_match:
            domain = domain_match.group(1).split(':')[0]
            dot_count = domain.count('.')
    except:
        pass
    
    return [
        float(url_length),
        float(digit_count),
        float(special_char_count),
        float(entropy),
        float(suspicious_keyword_count),
        float(subdomain_count),
        float(has_ip),
        float(path_length),
        float(query_length),
        float(dot_count)
    ]


def generate_training_data():
    """
    Generate training dataset with legitimate and phishing URLs.
    In production, you would use real datasets like PhishTank exports.
    """
    
    # Legitimate URLs - typical patterns
    legitimate_urls = [
        "https://www.google.com/search?q=weather",
        "https://github.com/microsoft/vscode",
        "https://stackoverflow.com/questions/12345678",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://docs.python.org/3/library/re.html",
        "https://en.wikipedia.org/wiki/Machine_learning",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://www.linkedin.com/in/johndoe",
        "https://twitter.com/elonmusk/status/123456789",
        "https://www.reddit.com/r/programming/",
        "https://mail.google.com/mail/u/0/",
        "https://drive.google.com/drive/my-drive",
        "https://www.netflix.com/browse",
        "https://www.spotify.com/us/premium/",
        "https://www.nytimes.com/2024/01/15/technology/ai.html",
        "https://www.bbc.com/news/world",
        "https://www.cnn.com/politics",
        "https://www.apple.com/iphone/",
        "https://www.microsoft.com/en-us/windows",
        "https://azure.microsoft.com/en-us/services/",
        "https://aws.amazon.com/s3/",
        "https://cloud.google.com/compute",
        "https://www.dropbox.com/home",
        "https://www.paypal.com/myaccount/home",
        "https://www.ebay.com/itm/123456789",
        "https://www.etsy.com/shop/artisan",
        "https://www.airbnb.com/rooms/12345",
        "https://www.booking.com/hotel/us/hilton",
        "https://www.expedia.com/Flights",
        "https://www.zillow.com/homes/for_sale/",
        "https://www.indeed.com/jobs?q=developer",
        "https://www.glassdoor.com/Reviews/",
        "https://www.yelp.com/biz/restaurant-name",
        "https://www.tripadvisor.com/Hotels",
        "https://www.walmart.com/browse/electronics",
        "https://www.target.com/c/electronics/-/N-5xtg6",
        "https://www.bestbuy.com/site/computers-pcs/",
        "https://www.homedepot.com/b/Tools/N-5yc1v",
        "https://www.lowes.com/pl/Power-tools",
        "https://www.costco.com/electronics.html",
        "https://www.ikea.com/us/en/cat/furniture-fu001/",
        "https://www.wayfair.com/furniture/",
        "https://www.overstock.com/Home-Garden/",
        "https://www.nordstrom.com/browse/women",
        "https://www.macys.com/shop/womens-clothing",
        "https://www.gap.com/browse/category.do?cid=5664",
        "https://www.hm.com/en_us/women.html",
        "https://www.zara.com/us/en/woman-shirts-l1217.html",
        "https://www.uniqlo.com/us/en/men",
        "https://www.nike.com/w/mens-shoes-nik1zy7ok",
        # More legitimate patterns
        "https://account.microsoft.com/security",
        "https://myaccount.google.com/security",
        "https://www.facebook.com/settings",
        "https://www.instagram.com/accounts/edit/",
        "https://www.tiktok.com/@username",
        "https://discord.com/channels/@me",
        "https://slack.com/workspace-signin",
        "https://zoom.us/join",
        "https://meet.google.com/abc-defg-hij",
        "https://teams.microsoft.com/",
    ]
    
    # Phishing URLs - suspicious patterns
    phishing_urls = [
        # IP-based URLs
        "http://192.168.1.1/login/verify-account.php",
        "http://45.33.32.156/paypal/secure/login.html",
        "http://185.234.72.10/microsoft/signin.aspx",
        "http://91.134.248.19/apple-id/verify.php",
        "http://23.94.5.133/banking/secure-login.html",
        
        # Suspicious subdomains
        "https://secure-login.paypal.com.verification-center.tk/signin",
        "https://account-verify.microsoft.com.secure-portal.xyz/login",
        "https://signin.apple.com.id-verification.info/authenticate",
        "https://login.facebook.com.security-check.ru/confirm",
        "https://secure.bankofamerica.com.account-update.net/verify",
        
        # Typosquatting
        "https://www.paypa1.com/signin",
        "https://www.arnazon.com/ap/signin",
        "https://www.micros0ft.com/account/login",
        "https://www.g00gle.com/accounts/login",
        "https://www.faceb00k.com/login.php",
        "https://www.netfliix.com/login",
        "https://www.arnerica-bank.com/login",
        "https://www.wells-farg0.com/signin",
        
        # Suspicious keywords
        "https://verify-your-account-paypal.com/secure/login",
        "https://update-your-password-now.com/microsoft/signin",
        "https://confirm-your-identity-apple.com/verify",
        "https://urgent-security-alert-amazon.com/confirm",
        "https://suspended-account-netflix.com/reactivate",
        "https://locked-account-recovery-fb.com/restore",
        "https://unusual-activity-detected-google.com/verify",
        "https://credential-verification-required.com/banking",
        
        # Long, obfuscated URLs
        "https://secure-verification-portal-service-2024.com/login.php?user=verify&session=abc123def456&redirect=account&token=xyz789",
        "https://www.account-security-update-required-immediately.net/signin?ref=email&id=12345&verify=true&urgent=yes",
        "https://login-secure-authentication-portal-services.info/validate.aspx?account=suspended&action=restore",
        
        # Numeric/random domains
        "https://x7829abc.com/paypal/login",
        "https://secure-193847562.tk/microsoft/signin",
        "https://verify-account-38475.xyz/amazon/login",
        "https://login-service-9382746.info/banking",
        
        # Free hosting/suspicious TLDs
        "https://paypal-login.000webhostapp.com/signin.php",
        "https://microsoft-verify.herokuapp.com/login",
        "https://apple-id-confirm.netlify.app/authenticate",
        "https://amazon-security.vercel.app/verify",
        "https://facebook-login.wixsite.com/secure",
        "https://google-signin.blogspot.com/verify",
        
        # Crypto scams
        "https://bitcoin-wallet-verify.com/restore-access",
        "https://ethereum-security-alert.net/confirm-wallet",
        "https://crypto-account-suspended.io/verify-now",
        "https://metamask-verification-required.com/connect",
        
        # More phishing patterns
        "http://www.security-update-required-apple-id.com/verify.php",
        "http://confirm-paypal-account.suspicious-domain.tk/login",
        "https://www1.bank-of-america-online-signin.ru/login",
        "http://192.168.0.1:8080/admin/login.php?verify=account",
        "https://login-microsoft-0ffice365.com/signin.aspx?session=expired",
        "https://secure.wellsfargo-online.com-verify.info/banking",
        "https://update-billing-info-amazon.com/payment?account=suspended",
        "https://netflix-payment-failed.com/update-billing",
        "https://chase-online-banking-login.tk/secure/signin",
        "https://capital0ne-signin.com/verify-identity",
        "http://45.77.123.45:443/cgi-bin/login.php?bank=chase",
        "https://www.validate-your-apple-id-now.com/confirm",
        "https://www.urgent-paypal-notification.info/verify-account",
        "https://www.amazon-delivery-notification.com/confirm-address?track=ABC123",
        "https://login.office365-security-update.com/signin",
        "https://account-recovery-google.com/restore?user=email@gmail.com",
    ]
    
    # Extract features for all URLs
    X = []
    y = []
    
    for url in legitimate_urls:
        X.append(extract_features(url))
        y.append(0)  # 0 = legitimate
    
    for url in phishing_urls:
        X.append(extract_features(url))
        y.append(1)  # 1 = phishing
    
    # Add some noise/variations to make the model more robust
    np.random.seed(42)
    
    # Generate synthetic legitimate URLs with variations
    for _ in range(100):
        base_features = extract_features(np.random.choice(legitimate_urls))
        # Add small random noise
        noisy_features = [f + np.random.normal(0, 0.1) for f in base_features]
        noisy_features = [max(0, f) for f in noisy_features]  # Ensure non-negative
        X.append(noisy_features)
        y.append(0)
    
    # Generate synthetic phishing URLs with variations
    for _ in range(100):
        base_features = extract_features(np.random.choice(phishing_urls))
        noisy_features = [f + np.random.normal(0, 0.1) for f in base_features]
        noisy_features = [max(0, f) for f in noisy_features]
        X.append(noisy_features)
        y.append(1)
    
    return np.array(X, dtype=np.float32), np.array(y)


def train_and_export_model():
    """Train the model and export to ONNX format."""
    
    print("=" * 60)
    print("LinkShield ML Model Training")
    print("=" * 60)
    
    # Generate training data
    print("\n[1/4] Generating training data...")
    X, y = generate_training_data()
    print(f"      Total samples: {len(X)}")
    print(f"      Legitimate: {sum(y == 0)}, Phishing: {sum(y == 1)}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"      Training set: {len(X_train)}, Test set: {len(X_test)}")
    
    # Train model
    print("\n[2/4] Training RandomForest classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    
    # Evaluate
    print("\n[3/4] Evaluating model...")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"      Accuracy: {accuracy:.2%}")
    print("\n      Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    # Feature importance
    feature_names = [
        'url_length', 'digit_count', 'special_char_count', 'entropy',
        'suspicious_keyword_count', 'subdomain_count', 'has_ip',
        'path_length', 'query_length', 'dot_count'
    ]
    print("\n      Feature Importance:")
    importance = list(zip(feature_names, model.feature_importances_))
    importance.sort(key=lambda x: x[1], reverse=True)
    for name, score in importance:
        print(f"        {name}: {score:.4f}")
    
    # Export to ONNX
    print("\n[4/4] Exporting to ONNX format...")
    
    # Define input type (10 float features)
    initial_type = [('features', FloatTensorType([None, 10]))]
    
    # Convert to ONNX
    onnx_model = convert_sklearn(
        model, 
        initial_types=initial_type,
        target_opset=12,
        options={'zipmap': False}  # Return raw probabilities
    )
    
    # Save model
    output_path = "linkshield_model.onnx"
    with open(output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    
    print(f"      Model saved to: {output_path}")
    
    # Test the model with sample URLs
    print("\n" + "=" * 60)
    print("Testing Model with Sample URLs")
    print("=" * 60)
    
    test_urls = [
        ("https://www.google.com/search?q=test", "Legitimate"),
        ("https://github.com/microsoft/vscode", "Legitimate"),
        ("http://192.168.1.1/paypal/login.php", "Phishing"),
        ("https://verify-your-paypal-account.tk/signin", "Phishing"),
        ("https://www.amazon.com/dp/B08N5WRWNW", "Legitimate"),
        ("https://amazon-account-suspended.info/verify", "Phishing"),
    ]
    
    for url, expected in test_urls:
        features = np.array([extract_features(url)], dtype=np.float32)
        proba = model.predict_proba(features)[0]
        phishing_score = proba[1]
        prediction = "PHISHING" if phishing_score >= 0.5 else "SAFE"
        status = "✓" if (prediction == "PHISHING" and expected == "Phishing") or \
                        (prediction == "SAFE" and expected == "Legitimate") else "✗"
        print(f"\n{status} URL: {url[:50]}...")
        print(f"   Score: {phishing_score:.2%} | Predicted: {prediction} | Expected: {expected}")
    
    print("\n" + "=" * 60)
    print("Training Complete!")
    print("=" * 60)
    print(f"\nNext steps:")
    print(f"1. Copy '{output_path}' to LinkShield.Core/Resources/")
    print(f"2. Build and run LinkShield")
    print(f"\nThe model will be used as a fallback when URLs aren't in the database.")
    

if __name__ == "__main__":
    train_and_export_model()
