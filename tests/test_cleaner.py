"""정제 규칙 단위 테스트. 외부 호출 없이 tests/samples.py의 고정 샘플만 쓴다."""

import pytest

from app.cleaner import clean_kev_catalog, clean_kev_entry, extract_links
from tests.samples import APPLE_NOTES, ZYXEL


def without(raw, key):
    """raw에서 key 하나를 뺀 복사본."""
    return {k: v for k, v in raw.items() if k != key}


# --- clean_kev_entry -------------------------------------------------


def test_normal_entry_is_converted():
    item = clean_kev_entry(ZYXEL)
    assert item["cveId"] == "CVE-2020-29583"
    assert item["vendor"] == "Zyxel"
    assert item["addedOn"] == "2021-11-03"
    assert item["dueDate"] == "2022-05-03"
    assert item["cwes"] == ["CWE-522"]
    assert item["ransomwareUse"] is False


def test_ransomware_known_becomes_true():
    raw = dict(ZYXEL, knownRansomwareCampaignUse="Known")
    assert clean_kev_entry(raw)["ransomwareUse"] is True


def test_cve_id_is_normalized_to_upper_case():
    raw = dict(ZYXEL, cveID="  cve-2020-29583 ")
    assert clean_kev_entry(raw)["cveId"] == "CVE-2020-29583"


@pytest.mark.parametrize(
    "raw",
    [
        without(ZYXEL, "cveID"),
        dict(ZYXEL, cveID="NOT-A-CVE"),
        without(ZYXEL, "dateAdded"),
        dict(ZYXEL, dateAdded="2021-13-45"),
        "not a dict",
        None,
    ],
    ids=["no-cve-id", "bad-cve-id", "no-added-date", "bad-added-date", "string", "none"],
)
def test_unusable_entry_is_dropped(raw):
    assert clean_kev_entry(raw) is None


def test_invalid_due_date_becomes_none_but_entry_is_kept():
    item = clean_kev_entry(dict(ZYXEL, dueDate="soon"))
    assert item is not None
    assert item["dueDate"] is None


def test_extra_whitespace_is_collapsed():
    item = clean_kev_entry(dict(ZYXEL, vendorProject="  Zyxel   Networks "))
    assert item["vendor"] == "Zyxel Networks"


# --- extract_links ---------------------------------------------------


def test_single_nvd_link_gets_nvd_label():
    links = extract_links("https://nvd.nist.gov/vuln/detail/CVE-2020-29583")
    assert links == [{"label": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-29583"}]


def test_semicolon_separated_links_and_prefix_text():
    links = extract_links(APPLE_NOTES)
    # CISA 링크가 우선순위가 높아서 앞으로 오고, 같은 순위끼리는 원래 순서를 지킨다.
    assert [link["url"] for link in links] == [
        "https://www.cisa.gov/news-events/directives",
        "https://support.apple.com/en-us/120896",
        "https://support.apple.com/en-us/120898",
    ]
    assert [link["label"] for link in links] == ["CISA", "Reference", "Reference"]


def test_nvd_link_is_kept_even_when_it_appears_after_the_limit():
    references = " ; ".join(f"https://example.com/{i}" for i in range(6))
    notes = references + " ; https://nvd.nist.gov/vuln/detail/CVE-2020-29583"
    links = extract_links(notes, max_links=5)
    assert len(links) == 5
    assert links[0]["label"] == "NVD"


def test_http_links_are_rejected():
    assert extract_links("http://example.com/insecure") == []


def test_duplicate_links_are_kept_once():
    notes = "https://example.com/a ; https://example.com/a"
    assert len(extract_links(notes)) == 1


def test_links_are_limited():
    notes = " ; ".join(f"https://example.com/{i}" for i in range(10))
    assert len(extract_links(notes, max_links=5)) == 5


def test_trailing_period_is_removed():
    links = extract_links("See https://example.com/page.")
    assert links[0]["url"] == "https://example.com/page"


@pytest.mark.parametrize("notes", [None, "", 123])
def test_non_string_or_empty_input(notes):
    assert extract_links(notes) == []


# --- clean_kev_catalog -----------------------------------------------


def test_duplicates_and_invalid_entries_are_skipped():
    catalog = {
        "vulnerabilities": [
            ZYXEL,
            dict(ZYXEL),  # 같은 CVE가 한 번 더 나옴
            dict(ZYXEL, cveID="bad"),  # 형식이 잘못됨
        ]
    }
    items, skipped = clean_kev_catalog(catalog)
    assert len(items) == 1
    assert skipped == 2


@pytest.mark.parametrize("catalog", [{}, None, {"vulnerabilities": "oops"}])
def test_empty_or_unexpected_catalog(catalog):
    assert clean_kev_catalog(catalog) == ([], 0)
