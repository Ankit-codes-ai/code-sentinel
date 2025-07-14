import os
import ast
import re
import json
import hashlib
import logging
from pathlib import Path
import fnmatch
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
import google.generativeai as genai
from collections import defaultdict
import tiktoken
from langgraph.graph import StateGraph, END
import time
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
if not GEMINI_API_KEY:
    print("ERROR: No Gemini API key provided. Set the GEMINI_API_KEY environment variable.")
    import sys
    sys.exit(1)
else:
    genai.configure(api_key=GEMINI_API_KEY)

class FileType(Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CPP = "cpp"
    C = "c"
    CSHARP = "csharp"
    GO = "go"
    RUST = "rust"
    PHP = "php"
    RUBY = "ruby"
    JSON = "json"
    YAML = "yaml"
    XML = "xml"
    HTML = "html"
    CSS = "css"
    MARKDOWN = "markdown"
    TEXT = "text"
    CONFIG = "config"
    OTHER = "other"
    SHELL = "shell"
    BATCH = "batch"
    MAKEFILE = "makefile"
    AUTOCONF = "autoconf"
    M4 = "m4"
    PERL = "perl"
    LUA = "lua"
    DOCKER = "docker"
    SQL = "sql"
    SCHEME = "scheme"
    ASM = "asm"
    H = "header"
    S_ASM = "s_asm"
    MD = "machinedesc"
    DEF = "def"
    OPT = "opt"
    LEX = "lex"
    YACC = "yacc"
    TEXINFO = "texinfo"
    INFO = "info"
    FORTRAN = "fortran"
    COBOL = "cobol"
    PASCAL = "pascal"
    ADA = "ada"
    LISP = "lisp"
    ERLANG = "erlang"

@dataclass
class CodeElement:
    """Represents a code element (function, class, variable, etc.)"""
    name: str
    type: str
    line_start: int
    line_end: int
    content: str
    docstring: Optional[str] = None
    dependencies: List[str] = None
    complexity: int = 0
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []

@dataclass
class FileNode:
    """Represents a file in the project tree"""
    path: str
    name: str
    file_type: FileType
    size: int
    raw_content: str
    cleaned_content: str
    elements: List[CodeElement]
    imports: List[str]
    dependencies: List[str]
    hash: str
    last_modified: float
    
    def __post_init__(self):
        if not self.hash:
            self.hash = self._generate_hash()
    
    def _generate_hash(self) -> str:
        """Generate hash for the file content"""
        return hashlib.md5(self.cleaned_content.encode()).hexdigest()

@dataclass
class DirectoryNode:
    """Represents a directory in the project tree"""
    path: str
    name: str
    files: List[FileNode]
    subdirectories: List['DirectoryNode']
    total_size: int = 0
    
    def __post_init__(self):
        self.total_size = self._calculate_total_size()
    
    def _calculate_total_size(self) -> int:
        """Calculate total size of directory including subdirectories"""
        size = sum(file.size for file in self.files)
        size += sum(subdir.total_size for subdir in self.subdirectories)
        return size

@dataclass
class Subtree:
    """Represents a semantic chunk of the codebase"""
    id: str
    nodes: List[FileNode]
    total_tokens: int
    semantic_summary: str
    dependencies: List[str]
    hash: str
    metadata: Dict[str, Any]
    
    def __post_init__(self):
        if not self.hash:
            content = "".join(node.cleaned_content for node in self.nodes)
            self.hash = hashlib.md5(content.encode()).hexdigest()

class FileCrawler:
    """Crawls project directory and identifies files"""
    
    SUPPORTED_EXTENSIONS = {
        '.py': FileType.PYTHON,
        '.js': FileType.JAVASCRIPT,
        '.ts': FileType.TYPESCRIPT,
        '.tsx': FileType.TYPESCRIPT,
        '.jsx': FileType.JAVASCRIPT,
        '.java': FileType.JAVA,
        '.cpp': FileType.CPP,
        '.cc': FileType.CPP,
        '.cxx': FileType.CPP,
        '.c': FileType.C,
        '.cs': FileType.CSHARP,
        '.go': FileType.GO,
        '.rs': FileType.RUST,
        '.php': FileType.PHP,
        '.rb': FileType.RUBY,
        '.json': FileType.JSON,
        '.yaml': FileType.YAML,
        '.yml': FileType.YAML,
        '.xml': FileType.XML,
        '.html': FileType.HTML,
        '.htm': FileType.HTML,
        '.css': FileType.CSS,
        '.md': FileType.MARKDOWN,
        '.txt': FileType.TEXT,
        '.cfg': FileType.CONFIG,
        '.conf': FileType.CONFIG,
        '.ini': FileType.CONFIG,
        '.sh': FileType.SHELL,
        '.bash': FileType.SHELL,
        '.zsh': FileType.SHELL,
        '.ksh': FileType.SHELL,
        '.bat': FileType.BATCH,
        '.cmd': FileType.BATCH,
        '.ps1': FileType.BATCH,
        '.pl': FileType.PERL,
        '.pm': FileType.PERL,
        '.m4': FileType.M4,
        '.am': FileType.AUTOCONF,
        '.in': FileType.AUTOCONF,
        '.mk': FileType.MAKEFILE,
        '.lua': FileType.LUA,
        '.sql': FileType.SQL,
        '.scm': FileType.SCHEME,
        '.s': FileType.ASM,
        '.asm': FileType.ASM,
        'Dockerfile': FileType.DOCKER,
        'Makefile': FileType.MAKEFILE,
        'makefile': FileType.MAKEFILE,
        'configure': FileType.AUTOCONF,
        'CMakeLists.txt': FileType.CONFIG,
        '.h': FileType.H,
        '.S': FileType.S_ASM,
        '.md': FileType.MD,
        '.def': FileType.DEF,
        '.opt': FileType.OPT,
        '.l': FileType.LEX,
        '.y': FileType.YACC,
        '.texi': FileType.TEXINFO,
        '.info': FileType.INFO,
        '.f': FileType.FORTRAN,
        '.for': FileType.FORTRAN,
        '.f90': FileType.FORTRAN,
        '.f95': FileType.FORTRAN,
        '.f03': FileType.FORTRAN,
        '.f08': FileType.FORTRAN,
        '.cob': FileType.COBOL,
        '.cbl': FileType.COBOL,
        '.pas': FileType.PASCAL,
        '.p': FileType.PASCAL,
        '.ada': FileType.ADA,
        '.adb': FileType.ADA,
        '.ads': FileType.ADA,
        '.lisp': FileType.LISP,
        '.lsp': FileType.LISP,
        '.erl': FileType.ERLANG,
        '.hrl': FileType.ERLANG,
    }
    
    IGNORE_PATTERNS = {
        '__pycache__', '.git', '.svn', 'node_modules', '.venv', 'venv',
        '.env', 'dist', 'build', '.pytest_cache', '.mypy_cache',
        '.DS_Store', 'Thumbs.db', '*.pyc', '*.pyo', '*.pyd',
        '.hg', '.idea', '.vscode', '.coverage', '.nvm', '.cache',
        'bower_components', 'jspm_packages', '.parcel-cache', '.yarn',
        '.next', '.nuxt', '.expo', '.expo-shared', '.turbo', '.output',
        '.svelte-kit', '.vercel', '.firebase', '.tmp', '.temp', '.history',
        '.log', 'logs', 'coverage', 'out', 'tmp', 'temp', 'test-output',
        'cypress', 'storybook-static', 'public', 'static', 'builds', 'reports',
        'android', 'ios', 'web-build', 'www', 'platforms', 'plugins',
        'Pods', 'DerivedData', 'build.gradle', 'gradle', '.gradle',
        'target', 'bin', 'obj', 'release', 'debug', 'cmake-build-debug',
        'cmake-build-release', 'cmake-build-relwithdebinfo', 'cmake-build-minsizerel',
        'cmake-build-type', 'cmake-build', 'cmake', 'bazel-bin', 'bazel-out',
        'bazel-testlogs', 'bazel-workspace', 'bazel-execroot', 'bazel-genfiles',
        'bazel-bin', 'bazel-out', 'bazel-testlogs', 'bazel-workspace',
        'bazel-execroot', 'bazel-genfiles',
    }
    IGNORE_FILES = {'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json'}
    
    def __init__(self, root_path: str):
        self.root_path = Path(root_path)
        if not self.root_path.exists():
            raise ValueError(f"Root path does not exist: {root_path}")
        self.gitignore_patterns = self._load_gitignore_patterns()
    
    def crawl(self) -> DirectoryNode:
        """Crawl the directory tree and return structured representation"""
        logger.info(f"Starting crawl of {self.root_path}")
        return self._crawl_directory(self.root_path)
    
    def _crawl_directory(self, dir_path: Path) -> DirectoryNode:
        """Recursively crawl directory"""
        files = []
        subdirectories = []
        
        try:
            for item in dir_path.iterdir():
                if self._should_ignore(item):
                    continue
                
                if item.is_file():
                    file_node = self._process_file(item)
                    if file_node:
                        files.append(file_node)
                elif item.is_dir():
                    subdir = self._crawl_directory(item)
                    subdirectories.append(subdir)
        except PermissionError:
            logger.warning(f"Permission denied accessing {dir_path}")
        
        return DirectoryNode(
            path=str(dir_path),
            name=dir_path.name,
            files=files,
            subdirectories=subdirectories
        )
    
    def _should_ignore(self, path: Path) -> bool:
        """Check if path should be ignored"""
        if path.name in self.IGNORE_PATTERNS or path.name.startswith('.'):
            return True
        if path.is_file() and path.name in self.IGNORE_FILES:
            return True
        rel_path = path.relative_to(self.root_path).as_posix()
        for patt in self.gitignore_patterns:
            if patt.endswith('/'):
                if path.is_dir() and fnmatch.fnmatch(rel_path + '/', patt):
                    return True
            if fnmatch.fnmatch(rel_path, patt):
                return True
        return False

    def _load_gitignore_patterns(self) -> List[str]:
        """Read .gitignore file in root and return list of ignore patterns.

        This is a lightweight implementation that supports the most common
        glob-style patterns. It ignores blank lines, comments (#), and negation
        patterns (!)."""
        gitignore_path = self.root_path / '.gitignore'
        patterns: List[str] = []
        if gitignore_path.exists():
            try:
                with open(gitignore_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#') or line.startswith('!'):
                            continue
                        patterns.append(line)
            except Exception as e:
                logger.warning(f"Failed to read .gitignore: {e}")
        return patterns
    
    def _process_file(self, file_path: Path) -> Optional[FileNode]:
        """Process individual file"""
        try:
            file_type = self._get_file_type(file_path)
            if file_type == FileType.OTHER:
                return None
            
            encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
            content = None
            
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        content = f.read()
                    break
                except UnicodeDecodeError:
                    continue
            
            if content is None:
                with open(file_path, 'rb') as f:
                    binary_content = f.read()
                    content = binary_content.decode('utf-8', errors='replace')
            
            stat = file_path.stat()
            
            return FileNode(
                path=str(file_path),
                name=file_path.name,
                file_type=file_type,
                size=len(content),
                raw_content=content,
                cleaned_content="",
                elements=[],
                imports=[],
                dependencies=[],
                hash="",
                last_modified=stat.st_mtime
            )
        except Exception as e:
            logger.warning(f"Error processing file {file_path}: {e}")
            return None
    
    def _get_file_type(self, file_path: Path) -> FileType:
        return self.SUPPORTED_EXTENSIONS.get(file_path.suffix.lower(), FileType.OTHER)

class InputCleaner:
    """Cleans and processes file content"""
    
    def __init__(self):
        self.comment_patterns = {
            FileType.PYTHON: [r'#.*$', r'"""[\s\S]*?"""', r"'''[\s\S]*?'''"],
            FileType.JAVASCRIPT: [r'//.*$', r'/\*[\s\S]*?\*/'],
            FileType.TYPESCRIPT: [r'//.*$', r'/\*[\s\S]*?\*/'],
            FileType.JAVA: [r'//.*$', r'/\*[\s\S]*?\*/'],
            FileType.CPP: [r'//.*$', r'/\*[\s\S]*?\*/'],
            FileType.C: [r'//.*$', r'/\*[\s\S]*?\*/'],
            FileType.CSHARP: [r'//.*$', r'/\*[\s\S]*?\*/'],
            FileType.GO: [r'//.*$', r'/\*[\s\S]*?\*/'],
            FileType.RUST: [r'//.*$', r'/\*[\s\S]*?\*/'],
            FileType.PHP: [r'//.*$', r'/\*[\s\S]*?\*/', r'#.*$'],
            FileType.RUBY: [r'#.*$', r'=begin[\s\S]*?=end']
        }
        self.comment_patterns.update({
            FileType.SHELL: [r'#.*$'],
            FileType.BATCH: [r'::.*$', r'REM.*$'],
            FileType.PERL: [r'#.*$', r'=pod[\s\S]*?=cut'],
            FileType.MAKEFILE: [r'#.*$'],
            FileType.AUTOCONF: [r'#.*$'],
            FileType.M4: [r'dnl.*$'],
            FileType.LUA: [r'--.*$', r'--\[\[[\s\S]*?\]\]'],
            FileType.SQL: [r'--.*$', r'/\*[\s\S]*?\*/'],
            FileType.ASM: [r';.*$', r'#.*$'],
            FileType.FORTRAN: [r'!.*$'],
            FileType.COBOL: [r'\*.*$'],
            FileType.PASCAL: [r'\{[\s\S]*?\}', r'\(\*[\s\S]*?\*\)', r'//.*$'],
            FileType.ADA: [r'--.*$'],
            FileType.LISP: [r';.*$'],
            FileType.ERLANG: [r'%.*$'],
        })
    
    def clean_file(self, file_node: FileNode) -> FileNode:
        """Clean file content and extract elements"""
        logger.info(f"Cleaning file: {file_node.name}")
        
        cleaned_content = self._remove_comments(file_node.raw_content, file_node.file_type)
        cleaned_content = self._remove_empty_lines(cleaned_content)
        file_node.cleaned_content = cleaned_content
        
        if file_node.file_type == FileType.PYTHON:
            self._extract_python_elements(file_node)
        elif file_node.file_type in [FileType.JAVASCRIPT, FileType.TYPESCRIPT]:
            self._extract_js_elements(file_node)
        
        file_node.hash = file_node._generate_hash()
        
        return file_node
    
    def _remove_comments(self, content: str, file_type: FileType) -> str:
        """Remove comments from code"""
        if file_type not in self.comment_patterns:
            return content
        
        for pattern in self.comment_patterns[file_type]:
            content = re.sub(pattern, '', content, flags=re.MULTILINE)
        
        return content
    
    def _remove_empty_lines(self, content: str) -> str:
        """Remove excessive empty lines"""
        content = re.sub(r'\n\s*\n\s*\n', '\n\n', content)
        return content.strip()
    
    def _extract_python_elements(self, file_node: FileNode):
        """Extract Python code elements using AST"""
        try:
            tree = ast.parse(file_node.raw_content)
            visitor = PythonElementVisitor()
            visitor.visit(tree)
            
            file_node.elements = visitor.elements
            file_node.imports = visitor.imports
            file_node.dependencies = visitor.dependencies
        except SyntaxError as e:
            logger.warning(f"Syntax error in {file_node.name}: {e}")
            try:
                import_pattern = r'^(?:from\s+(\S+)\s+import|import\s+([^,]+)(?:,\s*)?)'
                imports = []
                
                for line in file_node.raw_content.splitlines():
                    line = line.strip()
                    match = re.match(import_pattern, line)
                    if match:
                        module = match.group(1) or match.group(2)
                        if module:
                            module = module.strip()
                            imports.append(module)
                
                file_node.imports = imports
                file_node.dependencies = imports
            except Exception:
                pass
        except Exception as e:
            logger.warning(f"Error extracting Python elements from {file_node.name}: {e}")
    
    def _extract_js_elements(self, file_node: FileNode):
        """Extract JavaScript/TypeScript elements (basic regex-based)"""
        content = file_node.cleaned_content
        elements = []
        imports = []
        
        func_pattern = r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>))'
        for match in re.finditer(func_pattern, content):
            func_name = match.group(1) or match.group(2)
            line_num = content[:match.start()].count('\n') + 1
            elements.append(CodeElement(
                name=func_name,
                type="function",
                line_start=line_num,
                line_end=line_num,
                content=match.group(0)
            ))
        
        import_pattern = r'import\s+.*?from\s+[\'"]([^\'"]+)[\'"]'
        for match in re.finditer(import_pattern, content):
            imports.append(match.group(1))
        
        file_node.elements = elements
        file_node.imports = imports
        file_node.dependencies = imports

class PythonElementVisitor(ast.NodeVisitor):
    """AST visitor for extracting Python code elements"""
    
    def __init__(self):
        self.elements = []
        self.imports = []
        self.dependencies = []
    
    def visit_FunctionDef(self, node):
        """Visit function definitions"""
        docstring = ast.get_docstring(node)
        self.elements.append(CodeElement(
            name=node.name,
            type="function",
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            content=ast.unparse(node) if hasattr(ast, 'unparse') else '',
            docstring=docstring,
            complexity=self._calculate_complexity(node)
        ))
        self.generic_visit(node)
    
    def visit_ClassDef(self, node):
        """Visit class definitions"""
        docstring = ast.get_docstring(node)
        self.elements.append(CodeElement(
            name=node.name,
            type="class",
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            content=ast.unparse(node) if hasattr(ast, 'unparse') else '',
            docstring=docstring
        ))
        self.generic_visit(node)
    
    def visit_Import(self, node):
        """Visit import statements"""
        for alias in node.names:
            self.imports.append(alias.name)
            self.dependencies.append(alias.name)
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node):
        """Visit from...import statements"""
        if node.module:
            self.imports.append(node.module)
            self.dependencies.append(node.module)
        self.generic_visit(node)
    
    def _calculate_complexity(self, node) -> int:
        """Calculate cyclomatic complexity"""
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.Try, ast.With)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity

class TreeBuilder:
    """Builds composite tree data structure"""
    
    def __init__(self, crawler: FileCrawler, cleaner: InputCleaner):
        self.crawler = crawler
        self.cleaner = cleaner
    
    def build_tree(self) -> DirectoryNode:
        """Build complete project tree"""
        logger.info("Building project tree")
        
        root_node = self.crawler.crawl()
        
        self._clean_directory_node(root_node)
        
        return root_node
    
    def _clean_directory_node(self, dir_node: DirectoryNode):
        """Recursively clean all files in directory tree"""
        for i, file_node in enumerate(dir_node.files):
            dir_node.files[i] = self.cleaner.clean_file(file_node)
        
        for subdir in dir_node.subdirectories:
            self._clean_directory_node(subdir)

class SemanticChunker:
    """Chunks code into semantic subtrees using Gemini"""
    
    def __init__(self):
        self.model = genai.GenerativeModel('gemini-2.5-flash')
        self.max_context_length = self._get_context_window_length()
        self.tokenizer = tiktoken.get_encoding("cl100k_base")
    
    def _get_context_window_length(self) -> int:
        """Get context window length for Gemini 2.5 Flash"""
        return 900000
    
    def chunk_tree(self, root_node: DirectoryNode) -> List[Subtree]:
        """Chunk directory tree into semantic subtrees"""
        logger.info("Starting semantic chunking")
        
        all_files = self._get_all_files(root_node)
        
        semantic_groups = self._group_files_semantically(all_files)
        
        subtrees = []
        for group in semantic_groups:
            subtrees.extend(self._create_subtrees_from_group(group))
        
        logger.info(f"Created {len(subtrees)} subtrees")
        return subtrees
    
    def _get_all_files(self, node: DirectoryNode) -> List[FileNode]:
        """Recursively collect all files from directory tree"""
        files = node.files.copy()
        for subdir in node.subdirectories:
            files.extend(self._get_all_files(subdir))
        return files
    
    def _group_files_semantically(self, files: List[FileNode]) -> List[List[FileNode]]:
        """Group files by semantic similarity using Gemini, batching if needed for large projects"""
        if not files:
            return []

        batches = []
        current_batch = []
        current_tokens = 0
        for file in files:
            file_tokens = 100 + len(file.elements) * 10 + len(file.imports) * 5
            file_tokens += len(self.tokenizer.encode(file.cleaned_content))
            if current_tokens + file_tokens > self.max_context_length and current_batch:
                batches.append(current_batch)
                current_batch = []
                current_tokens = 0
            current_batch.append(file)
            current_tokens += file_tokens
        if current_batch:
            batches.append(current_batch)

        all_groups = []
        used_files = set()
        for batch in batches:
            file_summaries = []
            for file in batch:
                summary = {
                    'path': file.path,
                    'name': file.name,
                    'type': file.file_type.value,
                    'elements': [{'name': el.name, 'type': el.type} for el in file.elements[:5]],
                    'imports': file.imports[:10],
                    'size': file.size
                }
                file_summaries.append(summary)
            prompt = (
                "Analyze the following code files and group them by semantic similarity and functional relationships.\n"
                "Consider factors like:\n"
                "- Import dependencies between files\n"
                "- Similar functionality or purpose\n"
                "- Related data structures or classes\n"
                "- Files that work together to implement features\n\n"
                "Files to analyze (as a JSON array):\n"
                f"{json.dumps(file_summaries, indent=2)}\n\n"
                "INSTRUCTION: For each group, write a direct, content-based summary using only the information you have. Do not mention missing information, do not speculate, do not say 'based on the filename', 'without knowing', 'please provide', or anything similar. If you do not know, simply summarize what is present.\n"
                "Return ONLY a valid JSON array (no markdown, no code block, no explanation, no comments). Each element should be a list of file paths that should be grouped together. Ensure no file appears in multiple groups."
            )
            max_retries = 100
            for attempt in range(max_retries):
                try:
                    response = self.model.generate_content(prompt)
                    cleaned_response = self._clean_gemini_json_response(response.text)
                    groups_data = json.loads(cleaned_response)
                    path_to_file = {file.path: file for file in batch}
                    for group_paths in groups_data:
                        group_files = []
                        for path in group_paths:
                            if path in path_to_file and path not in used_files:
                                group_files.append(path_to_file[path])
                                used_files.add(path)
                        if group_files:
                            all_groups.append(group_files)
                    break
                except KeyboardInterrupt:
                    logger.warning("Interrupted by user during Gemini API retry loop.")
                    raise
                except Exception as e:
                    err_str = str(e)
                    logger.warning(f"Exception type: {type(e).__name__}, message: {err_str}")
                    if '429' in err_str or 'quota' in err_str.lower() or 'rate limit' in err_str.lower():
                        logger.warning(f"429/Rate limit hit, sleeping for 60 seconds before retrying batch (attempt {attempt+1}/{max_retries})...")
                        import sys; sys.stdout.flush(); sys.stderr.flush()
                        try:
                            time.sleep(60)
                        except KeyboardInterrupt:
                            logger.warning("Interrupted by user during sleep for rate limit.")
                            raise
                        logger.warning("Woke up from sleep, retrying now.")
                        continue
                    else:
                        logger.warning(f"Error in semantic grouping batch: {e}. Sleeping 2 seconds before fallback.")
                        import sys; sys.stdout.flush(); sys.stderr.flush()
                        time.sleep(2)
                        dir_groups = defaultdict(list)
                        for file in batch:
                            dir_path = str(Path(file.path).parent)
                            dir_groups[dir_path].append(file)
                        all_groups.extend(list(dir_groups.values()))
                        break
            else:
                logger.warning(f"All {max_retries} retries exhausted for Gemini semantic grouping batch. Falling back to directory grouping.")
                dir_groups = defaultdict(list)
                for file in batch:
                    dir_path = str(Path(file.path).parent)
                    dir_groups[dir_path].append(file)
                all_groups.extend(list(dir_groups.values()))

        for file in files:
            if file.path not in used_files:
                all_groups.append([file])
        return all_groups

    def _create_subtrees_from_group(self, group: List[FileNode]) -> List[Subtree]:
        """Create subtrees from a group of files, respecting token limits"""
        subtrees = []
        current_files = []
        current_tokens = 0
        
        for file in group:
            file_tokens = len(self.tokenizer.encode(file.cleaned_content))
            
            if current_tokens + file_tokens > self.max_context_length and current_files:
                subtrees.append(self._create_subtree(current_files))
                current_files = [file]
                current_tokens = file_tokens
            else:
                current_files.append(file)
                current_tokens += file_tokens
        
        if current_files:
            subtrees.append(self._create_subtree(current_files))
        
        return subtrees
    
    def _create_subtree(self, files: List[FileNode]) -> Subtree:
        """Create a subtree from a list of files"""
        summary = self._generate_summary(files)
        
        all_deps = set()
        for file in files:
            all_deps.update(file.dependencies)
        
        total_content = "".join(file.cleaned_content for file in files)
        total_tokens = len(self.tokenizer.encode(total_content))
        
        subtree_id = hashlib.md5(total_content.encode()).hexdigest()[:8]
        
        return Subtree(
            id=subtree_id,
            nodes=files,
            total_tokens=total_tokens,
            semantic_summary=summary,
            dependencies=list(all_deps),
            hash="",
            metadata={
                'file_count': len(files),
                'primary_language': max([f.file_type.value for f in files], key=[f.file_type.value for f in files].count),
                'total_lines': sum(f.cleaned_content.count('\n') for f in files)
            }
        )
    
    def _generate_summary(self, files: List[FileNode]) -> str:
        """Generate semantic summary for a group of files, batching if needed for large groups"""
        MAX_FILES_PER_SUMMARY = 20
        summaries = []
        max_retries = 1000
        
        for i in range(0, len(files), MAX_FILES_PER_SUMMARY):
            batch = files[i:i+MAX_FILES_PER_SUMMARY]
            files_info = []
            for file in batch:
                info = f"File: {file.name}\n"
                info += f"Elements: {', '.join([f'{el.name}({el.type})' for el in file.elements[:5]])}\n"
                if file.imports:
                    info += f"Imports: {', '.join(file.imports[:5])}\n"
                files_info.append(info)
            
            prompt = f"""
            You have full access to the content of all files listed below. Do not say you lack access. Summarize only based on the content provided. Do not speculate or mention missing information.
            Provide a concise semantic summary (2-3 sentences) of what this group of files does together:

            {chr(10).join(files_info)}
            """

            for attempt in range(max_retries):
                try:
                    response = self.model.generate_content(prompt)
                    summaries.append(response.text.strip())
                    break
                except KeyboardInterrupt:
                    logger.warning("Interrupted by user during Gemini API retry loop in summary generation.")
                    raise
                except Exception as e:
                    err_str = str(e)
                    logger.warning(f"Exception type: {type(e).__name__}, message: {err_str}")
                    
                    if '429' in err_str or 'quota' in err_str.lower() or 'rate limit' in err_str.lower():
                        logger.warning(f"429/Rate limit hit during summary generation, sleeping for 60 seconds before retrying (attempt {attempt+1}/{max_retries})...")
                        import sys; sys.stdout.flush(); sys.stderr.flush()
                        try:
                            time.sleep(60)
                        except KeyboardInterrupt:
                            logger.warning("Interrupted by user during sleep for rate limit in summary generation.")
                            raise
                        logger.warning("Woke up from sleep, retrying summary generation now.")
                        continue
                    else:
                        logger.warning(f"Error generating summary batch: {e}")
                        summaries.append(f"Group of {len(batch)} files including {', '.join([f.name for f in batch[:3]])}")
                        break
            else:
                logger.warning(f"All {max_retries} retries exhausted for summary generation. Using fallback summary.")
                summaries.append(f"Group of {len(batch)} files including {', '.join([f.name for f in batch[:3]])}")
        
        if len(summaries) == 1:
            return summaries[0]
        else:
            combine_prompt = f"""
            You have full access to the content of all summaries below. Do not say you lack access. Summarize only based on the content provided. Do not speculate or mention missing information.
            The following are summaries of code file groups. Please provide a single concise summary (2-3 sentences) that describes what all these groups do together as a whole:\n\n{chr(10).join(summaries)}"""
            
            for attempt in range(max_retries):
                try:
                    response = self.model.generate_content(combine_prompt)
                    return response.text.strip()
                except KeyboardInterrupt:
                    logger.warning("Interrupted by user during Gemini API retry loop in summary combination.")
                    raise
                except Exception as e:
                    err_str = str(e)
                    logger.warning(f"Exception type: {type(e).__name__}, message: {err_str}")
                    
                    if '429' in err_str or 'quota' in err_str.lower() or 'rate limit' in err_str.lower():
                        logger.warning(f"429/Rate limit hit during summary combination, sleeping for 60 seconds before retrying (attempt {attempt+1}/{max_retries})...")
                        import sys; sys.stdout.flush(); sys.stderr.flush()
                        try:
                            time.sleep(60)
                        except KeyboardInterrupt:
                            logger.warning("Interrupted by user during sleep for rate limit in summary combination.")
                            raise
                        logger.warning("Woke up from sleep, retrying summary combination now.")
                        continue
                    else:
                        logger.warning(f"Error combining summaries: {e}")
                        return " ".join(summaries)
            else:
                logger.warning(f"All {max_retries} retries exhausted for summary combination. Using joined summaries.")
                return " ".join(summaries)

    def _clean_gemini_json_response(self, text: str) -> str:
        """Cleans Gemini response to extract a valid JSON array string."""
        text = text.strip()
        if text.startswith('```json'):
            text = text[7:]
        if text.startswith('```'):
            text = text[3:]
        if text.endswith('```'):
            text = text[:-3]
        text = text.strip()
        start = text.find('[')
        end = text.rfind(']')
        if start != -1 and end != -1:
            text = text[start:end+1]
        return text

class HashMapBuilder:
    """Builds hash map for lazy loading"""
    
    @staticmethod
    def build_hash_map(subtrees: List[Subtree]) -> Dict[str, Dict[str, Any]]:
        """Build hash map for lazy loading of subtrees"""
        hash_map = {}
        
        for subtree in subtrees:
            hash_map[subtree.id] = {
                'hash': subtree.hash,
                'total_tokens': subtree.total_tokens,
                'semantic_summary': subtree.semantic_summary,
                'file_paths': [node.path for node in subtree.nodes],
                'dependencies': subtree.dependencies,
                'metadata': subtree.metadata,
                'last_accessed': None,
                'access_count': 0
            }
        
        return hash_map

class CodePackager:
    """Main orchestrator for the Code Packager module"""
    
    def __init__(self, root_path: str):
        self.root_path = root_path
        self.crawler = FileCrawler(root_path)
        self.cleaner = InputCleaner()
        self.tree_builder = TreeBuilder(self.crawler, self.cleaner)
        self.semantic_chunker = SemanticChunker()
        self.hash_map_builder = HashMapBuilder()
    
    def package_code(self) -> Tuple[List[Subtree], Dict[str, Dict[str, Any]]]:
        """Main entry point for code packaging"""
        logger.info(f"Starting code packaging for {self.root_path}")
        
        project_tree = self.tree_builder.build_tree()
        
        subtrees = self.semantic_chunker.chunk_tree(project_tree)
        
        hash_map = self.hash_map_builder.build_hash_map(subtrees)
        
        logger.info(f"Code packaging complete. Generated {len(subtrees)} subtrees")
        return subtrees, hash_map
    
    def save_results(self, subtrees: List[Subtree], hash_map: Dict[str, Dict[str, Any]], output_dir: str):
        """Save results to disk (extended with supplementary outputs)"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        subtrees_data = [asdict(subtree) for subtree in subtrees]
        with open(output_path / 'subtrees.json', 'w') as f:
            json.dump(subtrees_data, f, indent=2, default=str)
        
        with open(output_path / 'hash_map.json', 'w') as f:
            json.dump(hash_map, f, indent=2, default=str)
        
        try:
            root_node = self.tree_builder.build_tree()
            project_structure = self._directory_to_dict(root_node)
            project_tree = self._generate_project_tree(subtrees)
            hashmap_details = self._generate_hashmap_details(project_tree, subtrees)
            ui_flow = self._analyze_ui_flow(root_node)

            with open(output_path / '1_project_structure.json', 'w') as f:
                json.dump(project_structure, f, indent=2, default=str)
            with open(output_path / '2_project_tree.json', 'w') as f:
                json.dump(project_tree, f, indent=2, default=str)
            with open(output_path / '3_hashmap_details.json', 'w') as f:
                json.dump(hashmap_details, f, indent=2, default=str)
            with open(output_path / '4_ui_flow_analysis.json', 'w') as f:
                json.dump(ui_flow, f, indent=2, default=str)
        except Exception as e:
            logger.warning(f"Supplementary result generation failed: {e}")
        
        logger.info(f"Results saved to {output_dir}")

    def _directory_to_dict(self, dir_node: DirectoryNode) -> Dict[str, Any]:
        """Convert DirectoryNode tree to serialisable dict structure."""
        node_dict = {
            "name": dir_node.name,
            "path": dir_node.path,
            "type": "directory",
            "children": []
        }
        for subdir in dir_node.subdirectories:
            node_dict["children"].append(self._directory_to_dict(subdir))
        for file in dir_node.files:
            node_dict["children"].append({
                "name": file.name,
                "path": file.path,
                "type": "file",
                "language": file.file_type.value,
                "size": file.size
            })
        return node_dict

    def _generate_project_tree(self, subtrees: List[Subtree]) -> Dict[str, Any]:
        """Create a lightweight semantic project tree from subtrees."""
        tree = {
            "project_tree": {
                "root": {
                    "id": "root",
                    "name": "Project Root",
                    "type": "module",
                    "children": [st.id for st in subtrees],
                    "metadata": {}
                }
            },
            "nodes": {}
        }
        for st in subtrees:
            tree["nodes"][st.id] = {
                "id": st.id,
                "name": f"Subtree {st.id}",
                "type": "subtree",
                "dependencies": st.dependencies,
                "provides": [],
                "entry_point": False,
                "metadata": st.metadata
            }
        return tree

    def _generate_hashmap_details(self, project_tree: Dict[str, Any], subtrees: List[Subtree]) -> Dict[str, Any]:
        """Generate detailed hashmap similar to visualizer/packer.py implementation."""
        hashmap = {}
        subtree_lookup = {st.id: st for st in subtrees}
        for node_id, node_info in project_tree.get("nodes", {}).items():
            st = subtree_lookup.get(node_id)
            hashmap[node_id] = {
                "id": node_id,
                "name": node_info.get("name", "unknown"),
                "type": node_info.get("type", "unknown"),
                "hash": st.hash if st else hashlib.md5(node_id.encode()).hexdigest(),
                "dependencies": node_info.get("dependencies", []),
                "provides": node_info.get("provides", []),
                "chunks": [file.path for file in st.nodes] if st else [],
                "metadata": node_info.get("metadata", {}),
                "created_at": datetime.now().isoformat()
            }
        return hashmap

    def _gather_all_files(self, dir_node: DirectoryNode) -> List[FileNode]:
        """Flatten DirectoryNode tree into list of FileNodes."""
        files: List[FileNode] = list(dir_node.files)
        for subdir in dir_node.subdirectories:
            files.extend(self._gather_all_files(subdir))
        return files

    def _analyze_ui_flow(self, root_node: DirectoryNode) -> Dict[str, Any]:
        """Very lightweight UI flow analysis based on presence of UI related files."""
        all_files = self._gather_all_files(root_node)
        ui_files = [f for f in all_files if f.file_type in {FileType.HTML, FileType.JAVASCRIPT, FileType.TYPESCRIPT}]

        if not ui_files:
            return {"ui_flow": {"message": "No UI components found in the project"}}

        entry_points = [{
            "component": f.name,
            "path": f.path,
            "description": "UI component detected by file type",
            "user_actions": ["view"]
        } for f in ui_files[:10]]

        ui_flow = {
            "ui_flow": {
                "entry_points": entry_points,
                "navigation_flow": [],
                "user_journey": {
                    "steps": [
                        {
                            "step": 1,
                            "component": entry_points[0]["component"] if entry_points else "",
                            "user_action": "Load application",
                            "system_response": "Display UI",
                            "functions_called": []
                        }
                    ] if entry_points else []
                },
                "data_flow": [],
                "api_integrations": []
            },
            "overall_purpose": "Automatically generated UI flow (heuristic)",
            "key_features": ["UI Interface"],
            "technology_stack": list({f.file_type.value for f in ui_files})
        }
        return ui_flow

def crawl_node(state):
    try:
        crawler = FileCrawler(state["project_path"])
        cleaner = InputCleaner()
        tree_builder = TreeBuilder(crawler, cleaner)
        project_tree = tree_builder.build_tree()
        return {**state, "project_tree": project_tree, "error": None}
    except Exception as e:
        logger.error(f"Crawling error: {e}")
        return {**state, "error": f"Crawling error: {e}"}

def chunk_node(state):
    if state.get("error"):
        return state
    try:
        chunker = SemanticChunker()
        subtrees = chunker.chunk_tree(state["project_tree"])
        return {**state, "subtrees": subtrees, "error": None}
    except Exception as e:
        logger.error(f"Chunking error: {e}")
        return {**state, "error": f"Chunking error: {e}"}

def hash_node(state):
    if state.get("error"):
        return state
    try:
        hash_map = HashMapBuilder.build_hash_map(state["subtrees"])
        return {**state, "hash_map": hash_map, "error": None}
    except Exception as e:
        logger.error(f"Hash map error: {e}")
        return {**state, "error": f"Hash map error: {e}"}

def save_node(state):
    if state.get("error"):
        return state
    try:
        packager = CodePackager(state["project_path"])
        packager.save_results(state["subtrees"], state["hash_map"], state["output_dir"])
        return {**state, "error": None}
    except Exception as e:
        logger.error(f"Save error: {e}")
        return {**state, "error": f"Save error: {e}"}

def build_packager_workflow():
    graph = StateGraph(dict)
    graph.add_node('crawl', crawl_node)
    graph.add_node('chunk', chunk_node)
    graph.add_node('hash', hash_node)
    graph.add_node('save', save_node)
    graph.add_edge('__start__', 'crawl')
    graph.add_edge('crawl', 'chunk')
    graph.add_edge('chunk', 'hash')
    graph.add_edge('hash', 'save')
    graph.add_edge('save', END)
    return graph

def run_packager(project_path, output_dir='./code-packager/output'):
    """Run the code packager workflow programmatically."""
    if not project_path:
        print("Project path is required.")
        return {"error": "Project path is required."}
    state = {"project_path": project_path, "output_dir": output_dir}
    workflow = build_packager_workflow()
    compiled = workflow.compile()
    result_state = compiled.invoke(state)
    if result_state.get("error"):
        print(f"Workflow failed: {result_state['error']}")
    else:
        subtrees = result_state.get("subtrees", [])
        print(f"Successfully packaged code with {len(subtrees)} subtrees")
        print(f"Total context window usage: {sum(st.total_tokens for st in subtrees):,} tokens")
        print(f"Results saved to {output_dir}")
    return result_state

def main():
    print("Code Packager Module (LangGraph workflow)")
    print("This script is now callable via run_packager(project_path, output_dir)")
    project_path = input("Enter the path to the project directory: ").strip()
    if not project_path:
        print("Project path is required.")
        return
    output_dir ='./code-packager/output'
    run_packager(project_path, output_dir)

if __name__ == "__main__":
    main()