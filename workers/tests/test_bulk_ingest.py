import pytest
from unittest.mock import patch, MagicMock
from tasks.bulk_ingest import bulk_ingest


def test_bulk_ingest_retries_on_500():
    events = [{
        "event_type": "subdomain",
        "severity": "info",
        "source_type": "subfinder",
        "source_name": "subfinder",
        "target_domain": "example.com",
        "payload": {},
    }]
    with patch("tasks.bulk_ingest.time") as mock_time, \
         patch("tasks.bulk_ingest.httpx.Client") as mock_client_cls:
        mock_time.sleep = MagicMock()  # не ждём реально

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.json.return_value = {"status": "error"}
        mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_resp

        result = bulk_ingest(events, "http://localhost:8765", "secret")

    # После всех ретраев и fallback — должны быть errors
    assert result.get("errors", 0) >= 1


def test_bulk_ingest_no_retry_on_422():
    events = [{
        "event_type": "bad_type",
        "severity": "info",
        "source_type": "subfinder",
        "source_name": "subfinder",
        "target_domain": "example.com",
        "payload": {},
    }]
    with patch("tasks.bulk_ingest.httpx.Client") as mock_client_cls:
        mock_resp = MagicMock()
        mock_resp.status_code = 422
        mock_resp.json.return_value = {"detail": "Validation error"}
        mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_resp

        result = bulk_ingest(events, "http://localhost:8765", "secret")

    # 422 — не ретраим, сразу errors
    assert result.get("sent", 0) == 0
    assert result.get("errors", 0) >= 1
