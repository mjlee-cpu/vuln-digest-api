"""CISA KEV(악용이 확인된 취약점) 원본 데이터를 앱 내부 형식으로 정리한다.

이 모듈은 외부 호출이나 데이터베이스를 쓰지 않는다.
입력이 같으면 항상 같은 결과가 나오므로 단위 테스트하기 쉽다.
"""

import re
from datetime import date
from urllib.parse import urlparse

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
URL_PATTERN = re.compile(r"https?://[^\s;,)\]]+")
MAX_LINKS = 5


def _text(value):
    """문자열이면 공백을 정리해서 돌려주고, 아니면 빈 문자열을 돌려준다."""
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())


def _parse_date(value):
    """'2026-11-04' 형식의 날짜면 date를, 아니면 None을 돌려준다."""
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value.strip())
    except ValueError:
        return None


def _label_for(url):
    """링크의 주소(도메인)를 보고 화면에 보일 이름을 정한다."""
    host = (urlparse(url).hostname or "").lower()
    if host == "nvd.nist.gov":
        return "NVD"
    if host == "cisa.gov" or host.endswith(".cisa.gov"):
        return "CISA"
    return "Reference"


LABEL_PRIORITY = {"NVD": 0, "CISA": 1, "Reference": 2}


def extract_links(notes, max_links=MAX_LINKS):
    """notes 문자열에서 https 링크만 뽑는다.

    중복은 한 번만 남긴다. 개수를 제한할 때 NVD, CISA 링크가 먼저 남도록
    우선순위(NVD → CISA → 그 외)로 정렬한 뒤 앞에서부터 자른다.
    """
    if not isinstance(notes, str):
        return []
    links = []
    seen = set()
    for match in URL_PATTERN.findall(notes):
        url = match.rstrip(".")
        if not url.startswith("https://"):
            continue
        if url in seen:
            continue
        seen.add(url)
        links.append({"label": _label_for(url), "url": url})
    links.sort(key=lambda link: LABEL_PRIORITY[link["label"]])  # 같은 순위끼리는 원래 순서 유지
    return links[:max_links]


def clean_kev_entry(raw):
    """KEV 항목 한 건을 정리한다. 쓸 수 없는 항목이면 None을 돌려준다."""
    if not isinstance(raw, dict):
        return None

    cve_id = _text(raw.get("cveID")).upper()
    if not CVE_ID_PATTERN.match(cve_id):
        return None

    added_on = _parse_date(raw.get("dateAdded"))
    if added_on is None:
        return None

    due_date = _parse_date(raw.get("dueDate"))
    cwes = raw.get("cwes")
    if not isinstance(cwes, list):
        cwes = []

    return {
        "cveId": cve_id,
        "vendor": _text(raw.get("vendorProject")),
        "product": _text(raw.get("product")),
        "name": _text(raw.get("vulnerabilityName")),
        "description": _text(raw.get("shortDescription")),
        "addedOn": added_on.isoformat(),
        "dueDate": due_date.isoformat() if due_date else None,
        "requiredAction": _text(raw.get("requiredAction")),
        "ransomwareUse": _text(raw.get("knownRansomwareCampaignUse")).lower() == "known",
        "cwes": [_text(c) for c in cwes if _text(c)],
        "links": extract_links(raw.get("notes")),
    }


def clean_kev_catalog(raw):
    """KEV 전체 데이터를 정리한다. (정리된 항목 목록, 건너뛴 항목 수)를 돌려준다."""
    entries = raw.get("vulnerabilities") if isinstance(raw, dict) else None
    if not isinstance(entries, list):
        return [], 0

    cleaned = []
    seen_ids = set()
    skipped = 0
    for entry in entries:
        item = clean_kev_entry(entry)
        if item is None or item["cveId"] in seen_ids:
            skipped += 1
            continue
        seen_ids.add(item["cveId"])
        cleaned.append(item)
    return cleaned, skipped
