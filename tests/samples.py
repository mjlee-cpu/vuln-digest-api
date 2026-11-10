"""테스트에서 같이 쓰는 고정 샘플 데이터. (KEV 데이터의 실제 구조를 따라 만든 것)"""

ZYXEL = {
    "cveID": "CVE-2020-29583",
    "vendorProject": "Zyxel",
    "product": "Multiple Products",
    "vulnerabilityName": "Zyxel Multiple Products Use of Hard-Coded Credentials Vulnerability",
    "dateAdded": "2021-11-03",
    "shortDescription": "Zyxel firewalls contain a use of hard-coded credentials vulnerability.",
    "requiredAction": "Apply updates per vendor instructions.",
    "dueDate": "2022-05-03",
    "knownRansomwareCampaignUse": "Unknown",
    "forensicTriage": "No",
    "notes": "https://nvd.nist.gov/vuln/detail/CVE-2020-29583",
    "cwes": ["CWE-522"],
}

APPLE_NOTES = (
    "https://support.apple.com/en-us/120896 ; "
    "https://support.apple.com/en-us/120898 ; "
    "BOD 26-04: https://www.cisa.gov/news-events/directives"
)
