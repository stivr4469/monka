"""
Тесты воркера gitleaks.

Покрывает:
  - install_gitleaks: успех, бинарник уже существует, ошибка API, нет нужного asset
  - _mask_secret: маскировка секретов разной длины
  - _clone_repo: успех, таймаут, ошибка git
  - scan_github_repo: находки, пустой репо, ошибка клонирования, ошибка gitleaks
  - _classify_secret_type: классификация по rule_id
  - scan_github_results: нет репозиториев, несколько репозиториев
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# conftest.py добавляет workers в sys.path — импортируем напрямую
from tasks.gitleaks import (
    GITLEAKS_BIN_PATH,
    _classify_secret_type,
    _mask_secret,
    _clone_repo,
    _CloneError,
    _send_findings,
    install_gitleaks,
    scan_github_repo,
    scan_github_results,
)


# ─── Вспомогательные фабрики ────────────────────────────────────────────────

def _make_finding(
    rule_id: str = "generic-api-key",
    secret: str = "supersecretvalue123",
    file: str = "config/settings.py",
    start_line: int = 42,
    commit: str = "abc123",
    author: str = "developer",
) -> dict:
    """Возвращает одну находку в формате gitleaks JSON."""
    return {
        "RuleID": rule_id,
        "Secret": secret,
        "File": file,
        "StartLine": start_line,
        "Commit": commit,
        "Author": author,
        "Date": "2024-01-01T00:00:00Z",
        "Match": f"api_key = {secret}",
    }


def _make_http_response(status_code: int = 200, body: dict | None = None) -> MagicMock:
    """Возвращает замоканный httpx.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body or {}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = Exception(f"HTTP {status_code}")
    return resp


# ─── Тесты _mask_secret ───────────────────────────────────────────────────────

class TestMaskSecret:
    def test_маскирует_длинный_секрет(self):
        """Первые 4 символа видны, остальное — звёздочки."""
        result = _mask_secret("supersecretvalue")
        assert result == "supe***"
        assert "supersecretvalue" not in result

    def test_маскирует_короткий_секрет(self):
        """Секрет короче 4 символов → полная маскировка."""
        assert _mask_secret("abc") == "***"
        assert _mask_secret("ab") == "***"

    def test_пустой_секрет_возвращает_звёздочки(self):
        assert _mask_secret("") == "***"

    def test_ровно_4_символа_возвращают_звёздочки(self):
        """Ровно 4 символа — показываем только первые, но <= prefix → звёздочки."""
        # visible_prefix=4, len=4: len <= visible_prefix → "***"
        assert _mask_secret("abcd") == "***"

    def test_5_символов_маскирует_правильно(self):
        result = _mask_secret("abcde")
        assert result == "abcd***"
        assert "e" not in result


# ─── Тесты _classify_secret_type ─────────────────────────────────────────────

class TestClassifySecretType:
    @pytest.mark.parametrize("rule_id,expected", [
        ("aws-access-token", "aws_credentials"),
        ("github-pat", "github_token"),
        ("google-api-key", "google_api_key"),
        ("stripe-secret-key", "stripe_key"),
        ("slack-bot-token", "slack_token"),
        ("jwt-secret", "jwt_token"),
        ("private-key-rsa", "private_key"),
        ("password-in-url", "password"),
        ("generic-api-key", "api_key"),
        ("unknown-rule", "generic_secret"),
    ])
    def test_классификация_по_rule_id(self, rule_id: str, expected: str):
        assert _classify_secret_type(rule_id) == expected


# ─── Тесты install_gitleaks ───────────────────────────────────────────────────

class TestInstallGitleaks:
    def test_возвращает_путь_если_бинарник_существует(self, tmp_path):
        """Если /tmp/gitleaks существует и исполняемый — возвращаем путь без скачивания."""
        fake_bin = tmp_path / "gitleaks"
        fake_bin.write_text("#!/bin/sh\necho ok")
        fake_bin.chmod(0o755)

        with patch("tasks.gitleaks.GITLEAKS_BIN_PATH", fake_bin), \
             patch("tasks.gitleaks._worker_settings") as mock_settings:
            mock_settings.GITLEAKS_BIN = str(tmp_path / "nonexistent")
            result = install_gitleaks()

        assert result == str(fake_bin)

    def test_возвращает_none_при_ошибке_github_api(self):
        """Если GitHub API недоступен — возвращаем None."""
        with patch("tasks.gitleaks.GITLEAKS_BIN_PATH", Path("/tmp/nonexistent_gitleaks_test")), \
             patch("tasks.gitleaks._worker_settings") as mock_settings, \
             patch("httpx.get", side_effect=Exception("connection refused")):
            mock_settings.GITLEAKS_BIN = "/nonexistent/path"
            result = install_gitleaks()

        assert result is None

    def test_возвращает_none_если_нет_нужного_asset(self):
        """Если в релизе нет linux_x64 asset — возвращаем None."""
        release_data = {
            "tag_name": "v8.18.0",
            "assets": [
                {"name": "gitleaks_darwin_arm64.tar.gz", "browser_download_url": "https://example.com/darwin.tar.gz"},
            ],
        }
        with patch("tasks.gitleaks.GITLEAKS_BIN_PATH", Path("/tmp/nonexistent_gitleaks_test")), \
             patch("tasks.gitleaks._worker_settings") as mock_settings, \
             patch("httpx.get", return_value=_make_http_response(200, release_data)):
            mock_settings.GITLEAKS_BIN = "/nonexistent/path"
            result = install_gitleaks()

        assert result is None

    def test_успешная_установка(self, tmp_path):
        """Полный путь: скачиваем, распаковываем, устанавливаем."""
        fake_bin_path = tmp_path / "gitleaks"
        release_data = {
            "tag_name": "v8.18.0",
            "assets": [
                {
                    "name": "gitleaks_8.18.0_linux_x64.tar.gz",
                    "browser_download_url": "https://example.com/gitleaks.tar.gz",
                },
            ],
        }

        # Мокаем httpx.get для API-запроса
        api_response = _make_http_response(200, release_data)

        # Мокаем httpx.stream для скачивания
        mock_stream_ctx = MagicMock()
        mock_stream_ctx.__enter__ = MagicMock(return_value=mock_stream_ctx)
        mock_stream_ctx.__exit__ = MagicMock(return_value=False)
        mock_stream_ctx.raise_for_status = MagicMock()
        mock_stream_ctx.iter_bytes = MagicMock(return_value=iter([b"fake-tar-content"]))

        # Мокаем tarfile чтобы не работать с реальным архивом
        mock_tar = MagicMock()
        mock_member = MagicMock()
        mock_member.name = "gitleaks"
        mock_member.isdir.return_value = False
        mock_tar.getmembers.return_value = [mock_member]
        mock_tar.__enter__ = MagicMock(return_value=mock_tar)
        mock_tar.__exit__ = MagicMock(return_value=False)
        # При extract создаём файл в fake_bin_path вместо /tmp
        def _fake_extract(member, path, **kw):
            fake_bin_path.write_bytes(b"#!/bin/sh\necho gitleaks")
        mock_tar.extract.side_effect = _fake_extract

        with patch("tasks.gitleaks.GITLEAKS_BIN_PATH", fake_bin_path), \
             patch("tasks.gitleaks._worker_settings") as mock_settings, \
             patch("httpx.get", return_value=api_response), \
             patch("httpx.stream", return_value=mock_stream_ctx), \
             patch("tarfile.open", return_value=mock_tar):
            mock_settings.GITLEAKS_BIN = "/nonexistent/path"
            result = install_gitleaks()

        # Бинарник должен быть создан
        assert result == str(fake_bin_path)
        assert fake_bin_path.exists()


# ─── Тесты _clone_repo ────────────────────────────────────────────────────────

class TestCloneRepo:
    def test_успешное_клонирование(self, tmp_path):
        """При успехе git clone директория создаётся."""
        target = tmp_path / "repo"

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            _clone_repo("https://github.com/test/repo.git", target)

    def test_ошибка_клонирования_ненулевой_код(self, tmp_path):
        """Если git вернул ненулевой код — бросаем _CloneError."""
        target = tmp_path / "repo"

        mock_result = MagicMock()
        mock_result.returncode = 128
        mock_result.stderr = "remote: Repository not found"

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(_CloneError, match="git clone вернул код 128"):
                _clone_repo("https://github.com/test/nonexistent.git", target)

    def test_таймаут_клонирования(self, tmp_path):
        """При таймауте бросаем _CloneError с понятным сообщением."""
        target = tmp_path / "repo"

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("git", 60)):
            with pytest.raises(_CloneError, match="Таймаут"):
                _clone_repo("https://github.com/test/slow.git", target)

    def test_git_не_установлен(self, tmp_path):
        """Если git не найден — бросаем _CloneError."""
        target = tmp_path / "repo"

        with patch("subprocess.run", side_effect=FileNotFoundError("git not found")):
            with pytest.raises(_CloneError, match="git не установлен"):
                _clone_repo("https://github.com/test/repo.git", target)


# ─── Тесты scan_github_repo ───────────────────────────────────────────────────

class TestScanGithubRepo:
    def test_нашёл_секреты_отправил_события(self, tmp_path):
        """При наличии находок отправляем события в Core API."""
        findings = [_make_finding("aws-access-token", "AKIA1234567890ABCDEF")]
        report_json = json.dumps(findings)

        # Директория для клонирования должна существовать
        clone_dir = tmp_path / "test_repo"
        clone_dir.mkdir()

        def _mock_subprocess(cmd, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stderr = ""
            result.stdout = ""
            # Gitleaks создаёт файл отчёта во временной директории
            if any("gitleaks" in str(c) for c in cmd):
                for arg in cmd:
                    arg_str = str(arg)
                    if "--report-path=" in arg_str:
                        report_p = Path(arg_str.split("=", 1)[1])
                        report_p.parent.mkdir(parents=True, exist_ok=True)
                        report_p.write_text(report_json)
                        break
            return result

        mock_ingest = _make_http_response(200, {"status": "accepted"})

        with patch("subprocess.run", side_effect=_mock_subprocess), \
             patch("httpx.post", return_value=mock_ingest), \
             patch("shutil.rmtree"), \
             patch("tasks.gitleaks.CLONE_BASE", tmp_path):
            result = scan_github_repo(
                repo_url="https://github.com/test/repo",
                domain="example.com",
                core_api_url="http://localhost:8000",
                internal_secret="test-secret",
                gitleaks_bin="/tmp/gitleaks",
            )

        assert result["secrets_found"] == 1
        assert result["sent"] == 1
        assert result["repo"] == "https://github.com/test/repo"

    def test_пустой_репозиторий_без_секретов(self, tmp_path):
        """Если gitleaks не создал отчёт — возвращаем нули."""
        def _mock_subprocess(cmd, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stderr = ""
            result.stdout = ""
            # gitleaks не создаёт файл (нет секретов)
            return result

        with patch("subprocess.run", side_effect=_mock_subprocess), \
             patch("shutil.rmtree"), \
             patch("tasks.gitleaks.CLONE_BASE", tmp_path):
            result = scan_github_repo(
                repo_url="https://github.com/clean/repo",
                domain="clean.com",
                core_api_url="http://localhost:8000",
                internal_secret="secret",
                gitleaks_bin="/tmp/gitleaks",
            )

        assert result["secrets_found"] == 0
        assert result["sent"] == 0

    def test_ошибка_клонирования(self, tmp_path):
        """При ошибке git clone возвращаем словарь с ошибкой."""
        def _mock_subprocess_fail(cmd, **kwargs):
            result = MagicMock()
            result.returncode = 128
            result.stderr = "Repository not found"
            return result

        with patch("subprocess.run", side_effect=_mock_subprocess_fail), \
             patch("shutil.rmtree"), \
             patch("tasks.gitleaks.CLONE_BASE", tmp_path):
            result = scan_github_repo(
                repo_url="https://github.com/nonexistent/repo",
                domain="example.com",
                core_api_url="http://localhost:8000",
                internal_secret="secret",
                gitleaks_bin="/tmp/gitleaks",
            )

        assert result["secrets_found"] == 0
        assert result["sent"] == 0
        assert "error" in result

    def test_gitleaks_недоступен(self):
        """Если gitleaks не установлен — возвращаем ошибку без краша."""
        with patch("tasks.gitleaks.install_gitleaks", return_value=None):
            result = scan_github_repo(
                repo_url="https://github.com/test/repo",
                domain="example.com",
                core_api_url="http://localhost:8000",
                internal_secret="secret",
                gitleaks_bin=None,
            )

        assert result["secrets_found"] == 0
        assert result["sent"] == 0
        assert "error" in result

    def test_невалидный_json_в_отчёте(self, tmp_path):
        """Если отчёт gitleaks повреждён — не крашимся."""
        def _mock_subprocess_broken_json(cmd, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stderr = ""
            result.stdout = ""
            if any("gitleaks" in str(c) for c in cmd):
                for arg in cmd:
                    arg_str = str(arg)
                    if "--report-path=" in arg_str:
                        report_p = Path(arg_str.split("=", 1)[1])
                        report_p.parent.mkdir(parents=True, exist_ok=True)
                        report_p.write_text("не JSON!")
                        break
            return result

        with patch("subprocess.run", side_effect=_mock_subprocess_broken_json), \
             patch("shutil.rmtree"), \
             patch("tasks.gitleaks.CLONE_BASE", tmp_path):
            result = scan_github_repo(
                repo_url="https://github.com/test/broken",
                domain="example.com",
                core_api_url="http://localhost:8000",
                internal_secret="secret",
                gitleaks_bin="/tmp/gitleaks",
            )

        # Не крашимся при плохом JSON
        assert result["secrets_found"] == 0
        assert result["sent"] == 0

    def test_временная_директория_всегда_удаляется(self, tmp_path):
        """КРИТИЧНО: try/finally гарантирует очистку даже при ошибке."""
        clone_dir = tmp_path / "test_repo"

        call_count = {"clone": 0, "gitleaks": 0}

        def _mock_subprocess(cmd, **kwargs):
            cmd_str = str(cmd)
            if "clone" in cmd_str:
                call_count["clone"] += 1
                # Физически создаём директорию чтобы finally сработал
                clone_dir.mkdir(exist_ok=True)
                result = MagicMock()
                result.returncode = 0
                result.stderr = ""
                return result
            # Gitleaks симулирует OSError
            raise OSError("gitleaks crashed unexpectedly")

        rmtree_was_called = []

        original_rmtree = __import__("shutil").rmtree

        def _spy_rmtree(path, **kwargs):
            rmtree_was_called.append(str(path))
            # Реально удаляем чтобы не оставлять мусор
            if Path(path).exists():
                original_rmtree(path)

        with patch("subprocess.run", side_effect=_mock_subprocess), \
             patch("shutil.rmtree", side_effect=_spy_rmtree), \
             patch("tasks.gitleaks.CLONE_BASE", tmp_path):
            scan_github_repo(
                repo_url="https://github.com/test/repo",
                domain="example.com",
                core_api_url="http://localhost:8000",
                internal_secret="secret",
                gitleaks_bin="/tmp/gitleaks",
            )

        # finally сработал — clone_dir не должна существовать
        assert not clone_dir.exists()


# ─── Тесты scan_github_results ────────────────────────────────────────────────

class TestScanGithubResults:
    def test_нет_репозиториев(self):
        """Если поиск ничего не нашёл — возвращаем нули."""
        with patch("tasks.gitleaks.install_gitleaks", return_value="/tmp/gitleaks"), \
             patch("tasks.gitleaks._collect_repos_from_search", return_value=set()):
            result = scan_github_results(
                domain="clean.com",
                github_token="token",
                core_api_url="http://localhost:8000",
                internal_secret="secret",
            )

        assert result["repos_scanned"] == 0
        assert result["total_secrets"] == 0
        assert result["sent"] == 0

    def test_несколько_репозиториев(self):
        """Сканируем каждый найденный репозиторий."""
        repos = {
            "https://github.com/org/repo1",
            "https://github.com/org/repo2",
        }

        scan_results = [
            {"repo": "https://github.com/org/repo1", "secrets_found": 2, "sent": 2},
            {"repo": "https://github.com/org/repo2", "secrets_found": 1, "sent": 1},
        ]
        scan_iter = iter(scan_results)

        with patch("tasks.gitleaks.install_gitleaks", return_value="/tmp/gitleaks"), \
             patch("tasks.gitleaks._collect_repos_from_search", return_value=repos), \
             patch("tasks.gitleaks.scan_github_repo", side_effect=lambda **kw: next(scan_iter)):
            result = scan_github_results(
                domain="example.com",
                github_token="token",
                core_api_url="http://localhost:8000",
                internal_secret="secret",
            )

        assert result["repos_scanned"] == 2
        assert result["total_secrets"] == 3
        assert result["sent"] == 3

    def test_gitleaks_недоступен_возвращает_ошибку(self):
        """Если gitleaks не удалось установить — возвращаем ошибку."""
        with patch("tasks.gitleaks.install_gitleaks", return_value=None):
            result = scan_github_results(
                domain="example.com",
                github_token="token",
                core_api_url="http://localhost:8000",
                internal_secret="secret",
            )

        assert result["repos_scanned"] == 0
        assert "error" in result


# ─── Тесты _send_findings ─────────────────────────────────────────────────────

class TestSendFindings:
    def test_отправляет_события_успешно(self):
        """Каждая находка генерирует POST в Core API."""
        findings = [
            _make_finding("aws-access-token", "AKIA1234567890ABCDEF"),
            _make_finding("github-pat", "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345"),
        ]
        mock_resp = _make_http_response(200, {"status": "accepted"})

        with patch("httpx.post", return_value=mock_resp) as mock_post:
            sent = _send_findings(
                findings=findings,
                repo_url="https://github.com/test/repo",
                domain="example.com",
                core_api_url="http://localhost:8000",
                internal_secret="secret",
            )

        assert sent == 2
        assert mock_post.call_count == 2

        # Проверяем что raw secret НЕ попал в payload
        call_kwargs = mock_post.call_args_list[0].kwargs
        payload = call_kwargs["json"]["payload"]
        assert "AKIA1234567890ABCDEF" not in str(payload)
        assert "***" in payload["secret_masked"]

    def test_дубликат_тоже_считается_как_sent(self):
        """Статус duplicate тоже засчитывается (событие уже принято раньше)."""
        findings = [_make_finding()]
        mock_resp = _make_http_response(200, {"status": "duplicate"})

        with patch("httpx.post", return_value=mock_resp):
            sent = _send_findings(
                findings=findings,
                repo_url="https://github.com/test/repo",
                domain="example.com",
                core_api_url="http://localhost:8000",
                internal_secret="secret",
            )

        assert sent == 1

    def test_ошибка_сети_не_крашит(self):
        """При сетевой ошибке продолжаем обработку остальных находок."""
        findings = [_make_finding(), _make_finding()]

        with patch("httpx.post", side_effect=Exception("network error")):
            sent = _send_findings(
                findings=findings,
                repo_url="https://github.com/test/repo",
                domain="example.com",
                core_api_url="http://localhost:8000",
                internal_secret="secret",
            )

        assert sent == 0  # ни одно не отправлено, но краша нет
