"""정제 규칙 단위 테스트.

외부 호출 없이, 아래의 고정된 샘플 데이터만 사용한다.
(KEV 데이터의 실제 구조를 따라 만든 샘플이다.)
"""

import unittest

from app.cleaner import clean_kev_catalog, clean_kev_entry, extract_links

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


class CleanEntryTest(unittest.TestCase):
    def test_normal_entry_is_converted(self):
        item = clean_kev_entry(ZYXEL)
        self.assertEqual(item["cveId"], "CVE-2020-29583")
        self.assertEqual(item["vendor"], "Zyxel")
        self.assertEqual(item["addedOn"], "2021-11-03")
        self.assertEqual(item["dueDate"], "2022-05-03")
        self.assertEqual(item["cwes"], ["CWE-522"])
        self.assertFalse(item["ransomwareUse"])

    def test_ransomware_known_becomes_true(self):
        raw = dict(ZYXEL, knownRansomwareCampaignUse="Known")
        self.assertTrue(clean_kev_entry(raw)["ransomwareUse"])

    def test_cve_id_is_normalized_to_upper_case(self):
        raw = dict(ZYXEL, cveID="  cve-2020-29583 ")
        self.assertEqual(clean_kev_entry(raw)["cveId"], "CVE-2020-29583")

    def test_missing_cve_id_is_dropped(self):
        raw = {k: v for k, v in ZYXEL.items() if k != "cveID"}
        self.assertIsNone(clean_kev_entry(raw))

    def test_invalid_cve_id_format_is_dropped(self):
        self.assertIsNone(clean_kev_entry(dict(ZYXEL, cveID="NOT-A-CVE")))

    def test_invalid_added_date_is_dropped(self):
        self.assertIsNone(clean_kev_entry(dict(ZYXEL, dateAdded="2021-13-45")))

    def test_missing_added_date_is_dropped(self):
        raw = {k: v for k, v in ZYXEL.items() if k != "dateAdded"}
        self.assertIsNone(clean_kev_entry(raw))

    def test_invalid_due_date_becomes_none_but_entry_is_kept(self):
        item = clean_kev_entry(dict(ZYXEL, dueDate="soon"))
        self.assertIsNotNone(item)
        self.assertIsNone(item["dueDate"])

    def test_extra_whitespace_is_collapsed(self):
        item = clean_kev_entry(dict(ZYXEL, vendorProject="  Zyxel   Networks "))
        self.assertEqual(item["vendor"], "Zyxel Networks")

    def test_non_dict_input_is_dropped(self):
        self.assertIsNone(clean_kev_entry("not a dict"))
        self.assertIsNone(clean_kev_entry(None))


class ExtractLinksTest(unittest.TestCase):
    def test_single_nvd_link_gets_nvd_label(self):
        links = extract_links("https://nvd.nist.gov/vuln/detail/CVE-2020-29583")
        self.assertEqual(
            links,
            [{"label": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-29583"}],
        )

    def test_semicolon_separated_links_and_prefix_text(self):
        links = extract_links(APPLE_NOTES)
        # CISA 링크가 우선순위가 높아서 앞으로 오고, 같은 순위끼리는 원래 순서를 지킨다.
        self.assertEqual(
            [link["url"] for link in links],
            [
                "https://www.cisa.gov/news-events/directives",
                "https://support.apple.com/en-us/120896",
                "https://support.apple.com/en-us/120898",
            ],
        )
        self.assertEqual([link["label"] for link in links], ["CISA", "Reference", "Reference"])

    def test_nvd_link_is_kept_even_when_it_appears_after_the_limit(self):
        references = " ; ".join(f"https://example.com/{i}" for i in range(6))
        notes = references + " ; https://nvd.nist.gov/vuln/detail/CVE-2020-29583"
        links = extract_links(notes, max_links=5)
        self.assertEqual(len(links), 5)
        self.assertEqual(links[0]["label"], "NVD")

    def test_http_links_are_rejected(self):
        self.assertEqual(extract_links("http://example.com/insecure"), [])

    def test_duplicate_links_are_kept_once(self):
        notes = "https://example.com/a ; https://example.com/a"
        self.assertEqual(len(extract_links(notes)), 1)

    def test_links_are_limited(self):
        notes = " ; ".join(f"https://example.com/{i}" for i in range(10))
        self.assertEqual(len(extract_links(notes, max_links=5)), 5)

    def test_trailing_period_is_removed(self):
        links = extract_links("See https://example.com/page.")
        self.assertEqual(links[0]["url"], "https://example.com/page")

    def test_non_string_or_empty_input(self):
        self.assertEqual(extract_links(None), [])
        self.assertEqual(extract_links(""), [])
        self.assertEqual(extract_links(123), [])


class CleanCatalogTest(unittest.TestCase):
    def test_duplicates_and_invalid_entries_are_skipped(self):
        catalog = {
            "vulnerabilities": [
                ZYXEL,
                dict(ZYXEL),  # 같은 CVE가 한 번 더 나옴
                dict(ZYXEL, cveID="bad"),  # 형식이 잘못됨
            ]
        }
        items, skipped = clean_kev_catalog(catalog)
        self.assertEqual(len(items), 1)
        self.assertEqual(skipped, 2)

    def test_empty_or_unexpected_catalog(self):
        self.assertEqual(clean_kev_catalog({}), ([], 0))
        self.assertEqual(clean_kev_catalog(None), ([], 0))
        self.assertEqual(clean_kev_catalog({"vulnerabilities": "oops"}), ([], 0))


if __name__ == "__main__":
    unittest.main()
