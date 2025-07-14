import os
import json
import logging
import time
import difflib
import hashlib
import subprocess
import shutil
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

import argparse

try:
    import google.generativeai as genai
except ImportError as e:
    raise RuntimeError("google-generativeai package is required: pip install google-generativeai") from e

from langgraph.graph import StateGraph, END

GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
if not GEMINI_API_KEY:
    print("ERROR: No Gemini API key provided. Set the GEMINI_API_KEY environment variable.")
    import sys
    sys.exit(1)

MODEL_NAME = "gemini-2.5-flash"

MODULE_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(MODULE_DIR, os.pardir))
REVIEW_REPORT_PATH = os.path.join(PROJECT_ROOT, "review-caller", "review_report.json")
MODIFICATIONS_LOG_PATH = os.path.join(MODULE_DIR, "modifications.json")

DEFAULT_BRANCH_NAME = "auto/remediation-%s" % datetime.utcnow().strftime("%Y%m%d%H%M%S")
GIT_REMOTE = os.environ.get("MCP_GIT_REMOTE", "origin")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s | %(message)s")
logger = logging.getLogger("auto-remediator")

genai.configure(api_key=GEMINI_API_KEY)

class GeminiFixer:
    """Wrapper around Gemini Flash with basic retry/backoff handling."""

    def __init__(self, model_name: str = MODEL_NAME, max_retries: int = 6, base_delay: int = 20):
        self.model = genai.GenerativeModel(model_name)
        self.max_retries = max_retries
        self.base_delay = base_delay

    def generate_fixed_file(self, file_content: str, issue_description: str, mitigation: str = "") -> Optional[str]:
        prompt = (
            "You are an autonomous code-remediation agent. Fix the following problem in the given Python file.\n"
            f"PROBLEM:\n{issue_description}\n{('Mitigation guidance: ' + mitigation) if mitigation else ''}\n\n"
            "Return ONLY the full corrected file content (valid Python). Do NOT wrap in markdown fences "
            "or add extra commentary."
        )
        payload = f"{prompt}\n\n# ORIGINAL FILE BEGINS\n{file_content}\n# ORIGINAL FILE ENDS"

        for attempt in range(self.max_retries):
            try:
                response = self.model.generate_content(payload)
                text = getattr(response, "text", "").strip() if response else ""
                if text and text != file_content:
                    return text
                logger.info("Gemini returned identical content or empty response – skipping patch.")
                return None
            except Exception as e:
                if self._is_rate_limited(e):
                    delay = self.base_delay * (2 ** attempt)
                    logger.warning(
                        "Rate-limit from Gemini (attempt %s/%s). Sleeping %s seconds…",
                        attempt + 1,
                        self.max_retries,
                        delay,
                    )
                    time.sleep(delay)
                    continue
                logger.error("Gemini error: %s", e, exc_info=True)
                break
        return None

    @staticmethod
    def _is_rate_limited(err: Exception) -> bool:
        msg = str(err).lower()
        return "quota" in msg or "rate" in msg or "429" in msg


class ModificationLogger:
    def __init__(self, path: str = MODIFICATIONS_LOG_PATH):
        self.path = path
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                try:
                    self.data = json.load(fh)
                except json.JSONDecodeError:
                    self.data = []
        else:
            self.data = []
    def record(self, file_path: str, diff: str, issue: Dict[str, Any]):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "file": file_path,
            "issue_id": issue.get("id"),
            "issue_title": issue.get("title") or issue.get("vulnerability_type"),
            "issue_description": issue.get("description"),
            "diff": diff,
        }
        self.data.append(entry)
    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2)
        logger.info("Modifications log written to %s", self.path)


class GitOperator:
    def __init__(self, repo_root: str, branch_name: str = DEFAULT_BRANCH_NAME):
        self.repo_root = repo_root
        self.branch = branch_name
    def _run(self, *cmd, check: bool = True):
        logger.debug("Running git command: %s", " ".join(cmd))
        return subprocess.run(cmd, cwd=self.repo_root, capture_output=True, text=True, check=check)
    def create_branch_and_commit(self, message: str = "Apply automated remediations"):
        try:
            self._run("git", "checkout", "-b", self.branch)
        except subprocess.CalledProcessError as e:
            if "already exists" in e.stderr:
                logger.info("Branch already exists – switching to it.")
                self._run("git", "checkout", self.branch)
            else:
                raise
        self._run("git", "add", ".")
        self._run("git", "commit", "-m", message)
        try:
            self._run("git", "push", "-u", GIT_REMOTE, self.branch)
        except subprocess.CalledProcessError as e:
            logger.error("Could not push branch: %s", e.stderr)
    def open_pull_request(self, title: str = "Auto remediations via MCP", body: str = "This PR was generated automatically."):
        if shutil.which("gh"):
            subprocess.run(["gh", "pr", "create", "--title", title, "--body", body], cwd=self.repo_root)
        elif shutil.which("hub"):
            subprocess.run(["hub", "pull-request", "-m", f"{title}\n\n{body}"], cwd=self.repo_root)
        else:
            logger.info("No GitHub CLI found – skipping automatic PR creation.")

@dataclass
class RemediationState:
    issues: List[Dict[str, Any]] = field(default_factory=list)
    issue_index: int = 0
    current_issue: Optional[Dict[str, Any]] = None

    files: List[str] = field(default_factory=list)
    file_index: int = 0
    current_file: Optional[str] = None

    original_content: Optional[str] = None
    fixed_content: Optional[str] = None

    diffs: List[Dict[str, Any]] = field(default_factory=list)

    completed: bool = False

    def add_diff(self, entry: Dict[str, Any]):
        self.diffs.append(entry)

class AutoRemediator:
    def __init__(self, review_report_path: str = REVIEW_REPORT_PATH, project_root: Optional[str] = None):
        self.review_report_path = review_report_path
        self.project_root = project_root or PROJECT_ROOT
        self.review_report = self._load_review_report()
        self.fixer = GeminiFixer()
        self.mod_log = ModificationLogger()
        self.state = RemediationState()
    def _load_review_report(self) -> Dict[str, Any]:
        if not os.path.exists(self.review_report_path):
            raise FileNotFoundError(f"Review report not found: {self.review_report_path}")
        with open(self.review_report_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    def _affected_files_for_issue(self, issue: Dict[str, Any]) -> List[str]:
        if issue.get("file_path") and issue["file_path"] != "multiple":
            return [issue["file_path"]]
        if issue.get("affected_files"):
            return issue["affected_files"]
        return []
    def _normalize_to_workspace(self, path: str) -> Optional[str]:
        if not path:
            return None
        path = path.replace("\\", os.sep)
        if os.path.exists(os.path.join(self.project_root, path)):
            return os.path.join(self.project_root, path)
        basename = os.path.basename(path)
        for root, _dirs, files in os.walk(self.project_root):
            if basename in files:
                candidate = os.path.join(root, basename)
                if os.path.exists(candidate):
                    return candidate
        return None
    def _compute_diff(self, old: str, new: str) -> str:
        diff_lines = difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile="original",
            tofile="remediated",
        )
        return "".join(diff_lines)
    def remediate(self):

        def load_issues(state: RemediationState):
            state.issues = []
            state.issues.extend(self.review_report.get("issues", []))
            state.issues.extend(self.review_report.get("security_findings", []))
            return state

        def select_issue(state: RemediationState):
            if state.issue_index >= len(state.issues):
                state.completed = True
                return state
            state.current_issue = state.issues[state.issue_index]
            state.files = self._affected_files_for_issue(state.current_issue)
            state.file_index = 0
            state.issue_index += 1
            return state

        def select_file(state: RemediationState):
            while state.file_index < len(state.files):
                path = state.files[state.file_index]
                workspace_path = self._normalize_to_workspace(path)
                state.file_index += 1
                if workspace_path and os.path.exists(workspace_path):
                    state.current_file = workspace_path
                    return state
                logger.warning("File %s not found – skipping", path)
            state.current_file = None
            return state

        def retrieve_content(state: RemediationState):
            if not state.current_file:
                return state
            with open(state.current_file, "r", encoding="utf-8") as fh:
                state.original_content = fh.read()
            return state

        def generate_fix(state: RemediationState):
            if not state.original_content:
                return state
            state.fixed_content = self.fixer.generate_fixed_file(
                state.original_content,
                state.current_issue.get("description", "No description"),
                state.current_issue.get("mitigation", ""),
            )
            return state

        def apply_fix(state: RemediationState):
            if not state.fixed_content or state.fixed_content == state.original_content:
                return state
            with open(state.current_file, "w", encoding="utf-8") as fh:
                fh.write(state.fixed_content)
            logger.info("Applied remediation to %s", state.current_file)
            diff_text = self._compute_diff(state.original_content, state.fixed_content)
            entry = {
                "file": os.path.relpath(state.current_file, self.project_root),
                "diff": diff_text,
                "issue_id": state.current_issue.get("id"),
            }
            state.add_diff(entry)
            return state

        g = StateGraph(RemediationState)
        g.add_node("load_issues", load_issues)
        g.add_node("select_issue", select_issue)
        g.add_node("select_file", select_file)
        g.add_node("retrieve_content", retrieve_content)
        g.add_node("generate_fix", generate_fix)
        g.add_node("apply_fix", apply_fix)

        g.set_entry("load_issues")
        g.add_edge("load_issues", "select_issue")

        g.add_conditional_edges(
            "select_issue",
            lambda s: "done" if s.completed else "have_issue",
            {
                "done": END,
                "have_issue": "select_file",
            },
        )

        g.add_conditional_edges(
            "select_file",
            lambda s: "next_issue" if s.current_file is None else "process_file",
            {
                "next_issue": "select_issue",
                "process_file": "retrieve_content",
            },
        )

        g.add_edge("retrieve_content", "generate_fix")
        g.add_edge("generate_fix", "apply_fix")
        g.add_edge("apply_fix", "select_file")

        engine = g.compile()
        engine.invoke(self.state)

        for diff_entry in self.state.diffs:
            self.mod_log.record(diff_entry["file"], diff_entry["diff"], {"id": diff_entry["issue_id"]})

        self.mod_log.save()

        try:
            git = GitOperator(self.project_root)
            git.create_branch_and_commit()
            git.open_pull_request()
        except Exception as e:
            logger.warning("Git operation failed: %s", e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auto-Remediator for MCP")
    parser.add_argument("--project-dir", dest="project_dir", help="Path to the target project directory (git repo)")
    parser.add_argument("--review-report", dest="report_path", default=REVIEW_REPORT_PATH, help="Path to review_report.json")
    args = parser.parse_args()

    try:
        remediator = AutoRemediator(review_report_path=args.report_path, project_root=args.project_dir or PROJECT_ROOT)
        remediator.remediate()
    except KeyboardInterrupt:
        logger.warning("Interrupted by user – exiting.")
    except Exception as exc:
        logger.exception("Fatal error in Auto-Remediator: %s", exc)