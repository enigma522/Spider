import re
from typing import List, Dict



class SecretFinder:
    regex_patterns = {
        'google_api': r'AIza[0-9A-Za-z-_]{35}',
        'docs_file_extension': r'^.*\.(xls|xlsx|doc|docx)$',
        'bitcoin_address': r'([13][a-km-zA-HJ-NP-Z0-9]{26,33})',
        'slack_api_key': r'xox.-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}',
        'us_cn_zipcode': r'(^\d{5}(-\d{4})?$)|(^[ABCEGHJKLMNPRSTVXY]{1}\d{1}[A-Z]{1} *\d{1}[A-Z]{1}\d{1}$)',
        'google_cloud_platform_auth': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        'google_cloud_platform_api': r'[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}',
        'amazon_secret_key': r'[0-9a-zA-Z/+]{40}',
        'gmail_auth_token': r'[0-9(+-[0-9A-Za-z_]{32}.apps.qooqleusercontent.com',
        'github_auth_token': r'[0-9a-fA-F]{40}',
        'Instagram_token': r'[0-9a-fA-F]{7}\.[0-9a-fA-F]{32}',
        'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
        'google_captcha': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
        'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
        'amazon_aws_access_key_id': r'A[SK]IA[0-9A-Z]{16}',
        'amazon_mws_auth_token': r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        'amazon_aws_url': r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
        'facebook_access_token': r'EAACEdEose0cBA[0-9A-Za-z]+',
        'authorization_basic': r'basic\s*[a-zA-Z0-9=:_\+\/-]+',
        'authorization_bearer': r'bearer\s*[a-zA-Z0-9_\-\.=:_\+\/]+',
        'authorization_api': r'api[key|\s*]+[a-zA-Z0-9_\-]+',
        'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
        'twilio_api_key': r'SK[0-9a-fA-F]{32}',
        'twilio_account_sid': r'AC[a-zA-Z0-9_\-]{32}',
        'twilio_app_sid': r'AP[a-zA-Z0-9_\-]{32}',
        'paypal_braintree_access_token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
        'square_oauth_secret': r'sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
        'square_access_token': r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
        'stripe_standard_api': r'sk_live_[0-9a-zA-Z]{24}',
        'stripe_restricted_api': r'rk_live_[0-9a-zA-Z]{24}',
        'github_access_token': r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
        'rsa_private_key': r'-----BEGIN RSA PRIVATE KEY-----',
        'ssh_dsa_private_key': r'-----BEGIN DSA PRIVATE KEY-----',
        'ssh_dc_private_key': r'-----BEGIN EC PRIVATE KEY-----',
        'pgp_private_block': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'json_web_token': r'ey[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*|ey[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*'
    }

    def __init__(self,content):
        self.response_content = content

    def find_sensitive_data(self) -> Dict[str, List[str]]:
        """Find and return sensitive data from the response content."""
        if not self.response_content:
            print("No content to scan.")
            return {}

        sensitive_data_found = {}

        for name, pattern in self.regex_patterns.items():
            matches = set(re.findall(pattern, self.response_content))
            if matches:
                sensitive_data_found[name] = matches

        return sensitive_data_found
