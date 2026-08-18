"""
Code Fetcher Service
Downloads source code from GitHub repositories or extracts uploaded ZIP archives
with security protections (ZIP bomb detection, path traversal prevention, file size limits).
"""
import os
import shutil
import requests
import zipfile
from dataclasses import dataclass, field


@dataclass
class CodeFile:
    path: str
    language: str
    content: str
    size_bytes: int


@dataclass
class CodeIndex:
    scan_id: str
    source: str
    repo_url: str | None
    branch: str | None
    files: list[CodeFile]
    total_files: int
    total_bytes: int
    languages: dict[str, int] = field(default_factory=dict)


# Safe file extensions for static analysis
ALLOWED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".go", ".rb", ".cs",
    ".json", ".yml", ".yaml", ".env", ".toml", ".xml", ".html", ".css", ".md", ".mdx", ".txt", ".rst", ".dockerfile", ".ini", ".cfg", ".sh", ".bash", ".bat", ".ps1", ".csv"
}

# Directories we should never scan
IGNORED_DIRECTORIES = {
    "node_modules", "vendor", "__pycache__", ".git", "build", "dist", "venv", ".venv"
}

# 500KB per file limit to prevent OOM
MAX_FILE_SIZE = 500 * 1024

# Temp directory base for extracted code (relative to backend root)
DEFAULT_EXTRACTION_BASE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "temp_scans", "extracted_code"
)


class CodeFetcher:
    def __init__(self, extraction_base_path: str | None = None):
        self.extraction_base_path = extraction_base_path or DEFAULT_EXTRACTION_BASE
        os.makedirs(self.extraction_base_path, exist_ok=True)

    def _is_safe_file(self, filename: str) -> bool:
        """Check if file has an allowed extension and is not in an ignored directory."""
        path_parts = filename.replace("\\", "/").split("/")

        # Check ignored directories
        if any(part in IGNORED_DIRECTORIES for part in path_parts):
            return False

        # Allow files without extensions like 'Dockerfile'
        basename = os.path.basename(filename)
        if basename.lower() in ["dockerfile", "makefile"]:
            return True

        _, ext = os.path.splitext(basename)
        return ext.lower() in ALLOWED_EXTENSIONS

    def _determine_language(self, filename: str) -> str:
        """Map extension to a simple language string."""
        basename = os.path.basename(filename).lower()
        if basename == "dockerfile":
            return "dockerfile"

        ext = os.path.splitext(basename)[1].lower()
        mapping = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".java": "java",
            ".php": "php",
            ".go": "go",
            ".rb": "ruby",
            ".cs": "csharp",
            ".html": "html",
            ".json": "json",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".env": "env",
            ".md": "markdown",
            ".mdx": "markdown",
            ".txt": "text",
            ".rst": "text",
            ".sh": "shell",
            ".bash": "shell",
            ".bat": "batch",
            ".ps1": "powershell",
            ".csv": "csv",
        }
        return mapping.get(ext, "unknown")

    def fetch_from_github(self, scan_id: str, installation_token: str, owner: str, repo: str, branch: str = "main") -> CodeIndex:
        """
        Fetch the entire source tree from GitHub API recursively and save it to the extraction path.
        Returns a CodeIndex containing all fetched files and metadata.
        """
        temp_dir = os.path.join(self.extraction_base_path, scan_id)
        os.makedirs(temp_dir, exist_ok=True)

        headers = {
            "Authorization": f"Bearer {installation_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        # 1. Get the latest commit SHA for the branch to get the tree
        branch_resp = requests.get(f"https://api.github.com/repos/{owner}/{repo}/branches/{branch}", headers=headers)
        if branch_resp.status_code != 200:
            raise Exception(f"Failed to fetch branch {branch}: {branch_resp.text}")

        tree_sha = branch_resp.json()["commit"]["sha"]

        # 2. Get the full tree recursively
        tree_resp = requests.get(f"https://api.github.com/repos/{owner}/{repo}/git/trees/{tree_sha}?recursive=1", headers=headers)
        if tree_resp.status_code != 200:
            raise Exception(f"Failed to fetch repository tree: {tree_resp.text}")

        tree = tree_resp.json().get("tree", [])

        code_files = []
        total_bytes = 0
        languages = {}

        for item in tree:
            if item["type"] != "blob":
                continue

            file_path = item["path"]
            file_size = item.get("size", 0)

            # Security filters
            if not self._is_safe_file(file_path):
                continue
            if file_size > MAX_FILE_SIZE:
                print(f"Skipping {file_path} - exceeds max file size of 500KB")
                continue

            # Download the raw file content
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"
            file_resp = requests.get(raw_url, headers=headers)

            if file_resp.status_code == 200:
                content = file_resp.text

                # Save to disk
                local_path = os.path.join(temp_dir, file_path)
                os.makedirs(os.path.dirname(local_path), exist_ok=True)
                with open(local_path, "w", encoding="utf-8") as f:
                    f.write(content)

                lang = self._determine_language(file_path)
                languages[lang] = languages.get(lang, 0) + 1

                code_files.append(CodeFile(
                    path=local_path,
                    language=lang,
                    content=content,
                    size_bytes=len(content)
                ))
                total_bytes += len(content)

        return CodeIndex(
            scan_id=scan_id,
            source="github",
            repo_url=f"https://github.com/{owner}/{repo}",
            branch=branch,
            files=code_files,
            total_files=len(code_files),
            total_bytes=total_bytes,
            languages=languages
        )

    def extract_from_zip(self, scan_id: str, zip_file_path: str) -> CodeIndex:
        """
        Extract uploaded ZIP file securely, guarding against ZIP bombs and path traversal.
        """
        temp_dir = os.path.join(self.extraction_base_path, scan_id)
        os.makedirs(temp_dir, exist_ok=True)

        code_files = []
        total_bytes = 0
        languages = {}

        with zipfile.ZipFile(zip_file_path, "r") as z:
            # ZIP Bomb protection (check sizes before extraction)
            total_uncompressed_size = sum(info.file_size for info in z.infolist())
            if total_uncompressed_size > 200 * 1024 * 1024:  # 200MB Limit
                raise ValueError("ZIP bomb detected: Uncompressed size exceeds 200MB limit.")

            if len(z.infolist()) > 5000:
                raise ValueError("ZIP contains too many files (max 5000).")

            for info in z.infolist():
                if info.is_dir():
                    continue

                # Path Traversal protection
                if ".." in info.filename or info.filename.startswith("/"):
                    print(f"Skipping {info.filename} - Invalid path (path traversal defense)")
                    continue

                if not self._is_safe_file(info.filename):
                    continue

                if info.file_size > MAX_FILE_SIZE:
                    continue

                # Read safely
                with z.open(info) as f:
                    try:
                        content = f.read().decode("utf-8")

                        # Save to disk
                        local_path = os.path.join(temp_dir, info.filename)
                        os.makedirs(os.path.dirname(local_path), exist_ok=True)
                        with open(local_path, "w", encoding="utf-8") as out_f:
                            out_f.write(content)

                        lang = self._determine_language(info.filename)
                        languages[lang] = languages.get(lang, 0) + 1

                        code_files.append(CodeFile(
                            path=local_path,
                            language=lang,
                            content=content,
                            size_bytes=len(content)
                        ))
                        total_bytes += len(content)

                    except UnicodeDecodeError:
                        print(f"Skipping {info.filename} - Not a valid UTF-8 text file")

        return CodeIndex(
            scan_id=scan_id,
            source="zip",
            repo_url=None,
            branch=None,
            files=code_files,
            total_files=len(code_files),
            total_bytes=total_bytes,
            languages=languages
        )

    def cleanup(self, scan_id: str):
        """Remove extracted code for a completed scan."""
        target_dir = os.path.join(self.extraction_base_path, scan_id)
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir, ignore_errors=True)
