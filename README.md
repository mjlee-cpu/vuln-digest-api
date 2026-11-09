# vuln-digest-api

공개된 취약점 데이터를 수집해서 정제하고 API로 제공하는 학습용 앱입니다.
CI/CD(Buildkite) 파이프라인을 연습하기 위해 단계별로 키워 갑니다.

## 데이터 흐름 (계획)

```
공개 취약점 데이터(CISA KEV 등) → 수집 → 정제 → PostgreSQL 저장 → API로 제공
```

## 현재 단계: v1 (정제 로직)

| 파일 | 설명 |
|---|---|
| `app/cleaner.py` | CISA KEV 원본 데이터를 앱 내부 형식으로 정리 (외부 호출 없음) |
| `tests/test_cleaner.py` | 정제 규칙 단위 테스트 |

이 단계에는 외부 라이브러리가 필요하지 않습니다.

## 테스트 실행

프로젝트 폴더(이 파일이 있는 곳)에서 실행합니다.

```bash
python3 -m unittest discover -s tests -t . -v
```

## 단계별 계획

| 버전 | 내용 |
|---|---|
| v1 | 정제 로직 + 단위 테스트 |
| v2 | PostgreSQL 저장 + 통합 테스트 |
| v3 | API (`/health`, `/vulnerabilities/recent`, `/vulnerabilities/{cve_id}`) + Docker 이미지 빌드 |
| v4 | 실제 KEV 수집기 |
| v5 | staging 배포 → 승인 → prod 배포 |
