"""
Dataset Builder & Provenance Generator

Builds a project-generated synthetic benchmark dataset
of benign and phishing-like URLs.

Dataset construction:
1. Manually defined representative benign URL patterns.
2. Manually defined phishing-like URL patterns.
3. Synthetic expansion using predefined domains, paths,
   brands, keywords, and URL structures.

No external URL records are directly imported or downloaded.
The dataset is intended for internal academic experimentation
and does not represent a verified real-world phishing feed.
"""

import os
import json
import pandas as pd

DATASET_PROVENANCE = {
    "dataset_name": "PhishGuard Synthetic URL Benchmark",
    "version": "1.0.0",
    "license": "Not separately licensed",
    "citation": "No external dataset records are directly imported. "
                "The benchmark is generated using project-defined URL patterns.",
    "description": "A project-generated synthetic benchmark containing "
                   "benign and phishing-like URL patterns for academic "
                   "experimentation. The dataset is not a verified "
                   "real-world phishing or benign URL collection.",
    "data_type": "Synthetic",
    "external_data_imported": False,
    "generation_method": "Manually defined URL patterns and template-based expansion",
    "target_column": "label",
    "classes": {
        "0": "Legitimate / Benign (synthetic examples)",
        "1": "Malicious / Phishing (synthetic examples)"
    },
    "feature_count": 20,
    "created_at": "2026-03-01T00:00:00Z"
}

# Representative benign URL patterns across various sectors (education, tech, banking, search, media)
# Realistically balanced with both modern HTTPS and legitimate standard HTTP portals
BENIGN_URLS = [
    "https://www.google.com/search?q=machine+learning+tutorial",
    "http://www.google.com",
    "https://www.google.com",
    "https://en.wikipedia.org/wiki/Phishing",
    "http://en.wikipedia.org/wiki/Computer_security",
    "https://github.com/torvalds/linux",
    "http://www.gnu.org/licenses/gpl-3.0.en.html",
    "http://httpd.apache.org/docs/2.4/",
    "http://info.cern.ch/hypertext/WWW/TheProject.html",
    "https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://www.nytimes.com/section/technology",
    "http://www.columbia.edu/~fdc/sample.html",
    "https://www.microsoft.com/en-us/software-download/windows11",
    "https://www.apple.com/macbook-pro/",
    "https://www.mit.edu/research/",
    "http://web.mit.edu/about/",
    "https://stanford.edu/academics/",
    "https://www.nature.com/articles/nature14539",
    "https://arxiv.org/abs/1706.03762",
    "https://www.netflix.com/browse",
    "https://www.linkedin.com/feed/",
    "https://twitter.com/explore",
    "https://www.reddit.com/r/MachineLearning/",
    "https://www.bbc.com/news/world",
    "http://news.bbc.co.uk/2/hi/technology/default.stm",
    "https://www.cnn.com/world",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
    "https://pypi.org/project/scikit-learn/",
    "https://fastapi.tiangolo.com/tutorial/",
    "https://react.dev/learn",
    "https://tailwindcss.com/docs/installation",
    "https://www.kaggle.com/competitions",
    "https://chase.com/personal/banking",
    "https://www.bankofamerica.com/smallbusiness/",
    "https://www.wellsfargo.com/help/",
    "https://paypal.com/us/home",
    "https://stripe.com/docs/api",
    "https://cloud.google.com/compute/docs",
    "https://aws.amazon.com/ec2/",
    "https://azure.microsoft.com/en-us/solutions/",
    "https://gitlab.com/explore",
    "https://hub.docker.com/_/python",
    "https://news.ycombinator.com/",
    "https://medium.com/topic/cybersecurity",
    "https://www.cdc.gov/flu/index.htm",
    "https://www.nih.gov/health-information",
    "https://www.who.int/emergencies/situations",
    "https://europa.eu/european-union/index_en",
    "https://www.un.org/en/about-us",
    "https://www.coursera.org/learn/machine-learning",
    "https://www.edx.org/course/cs50s-introduction-to-computer-science",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.spotify.com/us/premium/",
    "https://vimeo.com/channels/staffpicks",
    "https://www.adobe.com/creativecloud.html",
    "https://www.dropbox.com/business",
    "https://slack.com/features",
    "https://zoom.us/pricing",
    "https://www.salesforce.com/products/crm/",
    "https://hubspot.com/products/marketing",
    "https://www.atlassian.com/software/jira",
    "https://www.notion.so/product",
    "https://www.figma.com/design/",
    "https://www.canva.com/templates/",
    "https://www.cloudflare.com/learning/ddos/what-is-a-ddos-attack/",
    "https://www.cisa.gov/resources-tools",
    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    "https://owasp.org/www-project-top-ten/",
    "https://www.eff.org/issues/privacy",
    "https://nginx.org/en/docs/",
    "https://www.postgresql.org/docs/current/",
    "https://www.mongodb.com/docs/",
    "https://redis.io/docs/about/",
    "https://www.elastic.co/guide/index.html",
    "https://kubernetes.io/docs/home/",
    "https://prometheus.io/docs/introduction/overview/"
]

# Generate synthetic benign variants to scale dataset to realistic benchmark size
def generate_expanded_benign():
    samples = list(BENIGN_URLS)
    subpaths = ["docs", "api", "about", "contact", "support", "explore", "articles", "guide", "faq", "terms"]
    categories = ["tech", "science", "finance", "education", "security", "community", "releases", "v1", "v2"]
    
    base_domains = [
        "https://www.nytimes.com", "https://www.stanford.edu", "https://www.berkeley.edu",
        "https://www.ox.ac.uk", "https://www.cam.ac.uk", "https://www.harvard.edu",
        "https://www.mit.edu", "https://www.imperial.ac.uk", "https://www.princeton.edu",
        "https://www.columbia.edu", "https://www.cornell.edu", "https://www.yale.edu",
        "https://www.caltech.edu", "https://www.ucla.edu", "https://www.washington.edu",
        "https://www.ieee.org", "https://www.acm.org", "https://www.usenix.org",
        "https://www.sciencedirect.com", "https://springer.com", "https://wiley.com",
        "https://www.reuters.com", "https://www.bloomberg.com", "https://www.ft.com",
        "https://www.theguardian.com", "https://www.nationalgeographic.com",
        "https://www.scientificamerican.com", "https://www.weather.gov", "https://www.nasa.gov",
        "https://www.esa.int", "https://www.nih.gov", "https://www.who.int",
        # Legitimate HTTP domains to ensure realistic protocol balance
        "http://www.columbia.edu", "http://web.mit.edu", "http://www.w3.org",
        "http://httpd.apache.org", "http://www.gnu.org", "http://info.cern.ch",
        "http://www.weather.gov", "http://archive.ubuntu.com"
    ]
    for d in base_domains:
        for p in subpaths[:5]:
            for c in categories[:4]:
                samples.append(f"{d}/{p}/{c}?page=1&sort=date")
    return samples

# Representative phishing URL patterns capturing common attack vectors
PHISHING_URLS = [
    # IP address instead of domain (both HTTP and HTTPS)
    "http://192.168.1.100/paypal/login.php?cmd=update",
    "https://185.220.101.5/bankofamerica/secure-login/auth.html",
    "http://103.251.167.20/netflix-account-suspended/verify.php",
    "https://45.142.182.12/apple-id/verification/signin.html",
    "http://91.240.118.172/chase-online/card-validation.asp",
    "https://217.182.175.8/wellsfargo/secure-portal/index.php",
    
    # Subdomain brand spoofing (modern phishers actively use HTTPS)
    "https://paypal.com.account-verification-service.xyz/login.html",
    "https://appleid.apple.com.secure-update-notice.top/account",
    "https://netflix.com.billing-payment-update.info/login.php",
    "https://chase.com.security-alert-resolve.club/verify.asp",
    "https://microsoft.com.account-protection-centre.win/signin",
    "https://amazon.com.customer-support-order-verify.site/auth",
    "https://bankofamerica.com.sign-on-validation.live/portal",
    "https://wellsfargo.com.id-confirmation-portal.online/app",
    "http://paypal.com.security-auth-check.xyz/index.html",
    "http://chase.com.verify-billing-now.club/login",
    
    # Prefix-suffix hyphenated brand squatting (HTTPS certificates are free via Let's Encrypt)
    "https://secure-login-paypal-verify.com/cgi-bin/webscr",
    "https://apple-id-verify-account-now.com/identity/signin",
    "https://netflix-subscription-renew-billing.com/update",
    "https://chase-bank-security-center-update.com/online/banking",
    "https://amazon-security-suspension-appeals.com/ap/signin",
    "https://microsoft-outlook-credential-confirm.com/owa",
    "https://google-drive-shared-secure-document.com/view/d1838",
    "https://wellsfargo-banking-alert-protection.com/auth/login",
    "https://binance-wallet-security-restore.com/kyc-verification",
    "https://metamask-seed-phrase-recovery-portal.com/vault",
    "https://coinbase-account-locked-resolve.com/auth/step2",
    "http://secure-login-paypal-verify.com/cgi-bin/webscr",
    "http://apple-id-verify-account-now.com/identity/signin",
    
    # URL shortening redirection masking attacks
    "https://bit.ly/34xPaypalSecurityAlert",
    "https://tinyurl.com/apple-billing-update-urgent",
    "https://t.co/chase-unusual-activity-verify",
    "http://is.gd/netflix-payment-declined-retry",
    "http://ow.ly/bank-security-notice-immediate",
    "https://cutt.ly/wellsfargo-identity-confirm",
    "http://rebrand.ly/amazon-refund-request-form",
    
    # '@' credential injection trick
    "http://legit-news.com@evil-phishing-host.com/login.html",
    "https://google.com@phish-credentials-steal.net/auth/verify",
    "http://bank.com@malicious-harvest-box.org/secure/login",
    "https://paypal.com@192.168.1.15/webscr/login.php",
    
    # High entropy / DGA / obfuscated paths
    "https://x829df83-security-check-portal-login.xyz/verify/user?id=93821038103&token=af938e",
    "https://a92-f02-verification-service-auth.top/account/confirm?h=839d8e72f91a0b3",
    "http://secure-839210-appleid-support.info/owa/login.aspx?auth=redirect_now",
    "https://srv93-account-renew-center.club/billing/notice?customer_id=92813"
]

def generate_expanded_phishing():
    samples = list(PHISHING_URLS)
    brands = ["paypal", "chase", "netflix", "appleid", "amazon", "wellsfargo", "bankofamerica", "binance", "metamask", "microsoft", "outlook"]
    keywords = ["login", "verify-account", "security-alert", "billing-update", "confirm-identity", "unlock-account", "recovery-center", "wallet-restore"]
    bad_tlds = [".xyz", ".top", ".club", ".win", ".live", ".site", ".online", ".work", ".link", ".click"]
    
    for b in brands:
        for kw in keywords[:5]:
            for tld in bad_tlds[:5]:
                # Realistic modern phishing: over 75% use HTTPS certificates (Let's Encrypt / Cloudflare)
                samples.append(f"https://{b}-{kw}-portal-service{tld}/secure/auth/login.php?user_token=92849102")
                samples.append(f"https://{b}.com.{kw}-protection-verify{tld}/session/start?ref=email_notice")
                samples.append(f"http://192.168.{len(b)}.{len(kw)}/{b}/{kw}/index.html")
                samples.append(f"http://{b}-{kw}-alert{tld}/login.php")
    return samples

def build_dataset_dataframe() -> pd.DataFrame:
    """Builds balanced, deduplicated dataset DataFrame."""
    benign = generate_expanded_benign()
    phishing = generate_expanded_phishing()

    data = []
    seen = set()

    for url in benign:
        u = url.strip()
        if u and u not in seen:
            seen.add(u)
            data.append({"url": u, "label": 0})

    for url in phishing:
        u = url.strip()
        if u and u not in seen:
            seen.add(u)
            data.append({"url": u, "label": 1})

    df = pd.DataFrame(data)
    # Shuffle dataset
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    return df

def save_benchmark_data(output_dir: str):
    """Generates and writes CSV file and provenance JSON."""
    os.makedirs(output_dir, exist_ok=True)
    df = build_dataset_dataframe()
    csv_path = os.path.join(output_dir, "phishing_dataset.csv")
    df.to_csv(csv_path, index=False)
    
    provenance = DATASET_PROVENANCE.copy()
    provenance["total_samples"] = len(df)
    provenance["benign_samples"] = int((df["label"] == 0).sum())
    provenance["phishing_samples"] = int((df["label"] == 1).sum())
    
    prov_path = os.path.join(output_dir, "dataset_provenance.json")
    with open(prov_path, "w", encoding="utf-8") as f:
        json.dump(provenance, f, indent=2)

    return csv_path, prov_path, len(df)

if __name__ == "__main__":
    storage_dir = os.path.join(os.path.dirname(__file__), "model_storage")
    csv, prov, count = save_benchmark_data(storage_dir)
    print(f"Dataset generated: {count} samples saved to {csv}")

