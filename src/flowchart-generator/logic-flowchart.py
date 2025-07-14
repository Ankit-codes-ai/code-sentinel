import os
import json
import re
import time
import google.generativeai as genai
from pathlib import Path
from typing import List, Dict, Any


API_KEY = os.environ.get('GEMINI_API_KEY', '')
SUBTREES_PATH = os.path.join(os.path.dirname(__file__), '../code-packager/output/subtrees.json')
HASH_MAP_PATH = os.path.join(os.path.dirname(__file__), '../code-packager/output/hash_map.json')
OUTPUT_MERMAID_PATH = os.path.join(os.path.dirname(__file__), 'logic_flowchart.mmd')
MAX_CHARS_PER_FILE = 40000
MAX_NODES_PER_CHUNK = 50
MAX_CONNECTIONS_PER_NODE = 10

try:
    import google.generativeai as genai
    if not API_KEY:
        raise ValueError("No Gemini API key provided. Set the GEMINI_API_KEY environment variable.")
    genai.configure(api_key=API_KEY)
    MODEL_NAME = 'gemini-2.5-flash'
    def get_gemini_model():
        return genai.GenerativeModel(MODEL_NAME)
except Exception as e:
    print(f"Error importing or configuring google.generativeai: {e}")
    genai = None
    def get_gemini_model():
        raise RuntimeError("google-generativeai is not available or failed to configure.")

def load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def clean_mermaid_code(mermaid_code):
    """Clean and validate Mermaid code"""
    if not mermaid_code:
        return ""
    
    lines = mermaid_code.strip().splitlines()
    cleaned_lines = []
    
    for line in lines:
        line = line.strip()
        if line.startswith('```') or not line:
            continue
        if re.match(r'^\s*[\[\{][^\[\]{}]*[\]\}]\s*$', line):
            continue
        cleaned_lines.append(line)
    
    return '\n'.join(cleaned_lines)

def fix_mermaid_syntax(mermaid_code):
    """Fix common Mermaid syntax issues"""
    if not mermaid_code:
        return ""
    
    lines = mermaid_code.strip().splitlines()
    fixed_lines = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        line = re.sub(r'(\w+)-->\[([^\]]+)\]', r'\1-->\2', line)
        line = re.sub(r'\[([^\]]+)\]-->\[([^\]]+)\]', r'\1-->\2', line)
        line = re.sub(r'\[([^\]]+)\]-->(\w+)', r'\1-->\2', line)
        line = re.sub(r'[^\w\s\-\>\[\]\{\}\?\|\(\):]', '_', line)
        if '{' in line and '}' in line:
            def _sanitize_label(match):
                label_text = match.group(1)
                label_text = label_text.replace('_', ' ').replace('(', ' ').replace(')', ' ')
                label_text = re.sub(r'[^A-Za-z0-9\?\> ]+', ' ', label_text)
                label_text = re.sub(r'\s{2,}', ' ', label_text).strip()
                if len(label_text) > 50:
                    label_text = label_text[:47] + "..."
                return '{' + label_text + '}'
            line = re.sub(r'\{([^{}]+)\}', _sanitize_label, line)
        if len(line) > 200:
            line = line[:197] + "..."
        
        fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)

def extract_flowchart_content(mermaid_code):
    """Extract content from flowchart, removing the header"""
    if not mermaid_code:
        return ""
    
    lines = mermaid_code.strip().splitlines()
    content_lines = []
    found_flowchart = False
    
    for line in lines:
        if line.strip().startswith('flowchart '):
            found_flowchart = True
            continue
        if found_flowchart:
            content_lines.append(line)
    
    return '\n'.join(content_lines) if content_lines else mermaid_code

def count_connections(mermaid_code):
    """Count the number of connections in mermaid code"""
    if not mermaid_code:
        return 0
    return mermaid_code.count('-->')

def truncate_mermaid_code(mermaid_code, max_connections=MAX_CONNECTIONS_PER_NODE):
    """Truncate mermaid code if it has too many connections"""
    if not mermaid_code:
        return ""
    
    lines = mermaid_code.strip().splitlines()
    connection_count = 0
    truncated_lines = []
    
    for line in lines:
        if '-->' in line:
            connection_count += 1
            if connection_count > max_connections:
                truncated_lines.append("    %% ... (truncated for size)")
                break
        truncated_lines.append(line)
    
    return '\n'.join(truncated_lines)

def estimate_text_size(mermaid_codes):
    """Estimate the total text size of mermaid codes"""
    total_size = 0
    for code in mermaid_codes:
        if code:
            total_size += len(code)
    return total_size

def write_mermaid_to_file(mermaid_codes, output_path):
    """Write Mermaid content to one or more .mmd files, managing size limits"""
    if not mermaid_codes:
        print("No Mermaid code to write.")
        return []

    header = ["flowchart TD"]
    
    chunks: List[List[str]] = []
    current_chunk: List[str] = header.copy()
    current_len = sum(len(l) + 1 for l in current_chunk)
    current_node_count = 0

    for i, code in enumerate(mermaid_codes, 1):
        if not code:
            continue
            
        cleaned_code = clean_mermaid_code(code)
        fixed_code = fix_mermaid_syntax(cleaned_code)
        content = extract_flowchart_content(fixed_code)
        
        if not content.strip():
            continue
        content = truncate_mermaid_code(content)
        
        section_header = f"    %% Section {i}"
        lines_to_add = [section_header] + ["    " + ln.strip() for ln in content.splitlines() if ln.strip()]
        addition_size = sum(len(ln) + 1 for ln in lines_to_add)
        if ((current_len + addition_size > MAX_CHARS_PER_FILE) or 
            (current_node_count >= MAX_NODES_PER_CHUNK)) and len(current_chunk) > 1:
            chunks.append(current_chunk.copy())
            current_chunk = header.copy()
            current_len = sum(len(l) + 1 for l in current_chunk)
            current_node_count = 0
        current_chunk.extend(lines_to_add)
        current_len += addition_size
        current_node_count += 1
    if len(current_chunk) > 1 or not chunks:
        chunks.append(current_chunk)
    written_paths = []
    base_path = Path(output_path)
    
    for idx, chunk in enumerate(chunks, 1):
        if idx == 1:
            out_path = base_path
        else:
            out_path = base_path.with_stem(f"{base_path.stem}_part{idx}")
        
        try:
            Path(out_path).write_text("\n".join(chunk), encoding='utf-8')
            written_paths.append(str(out_path))
            file_size = len("\n".join(chunk))
            node_count = sum(1 for line in chunk if '-->' in line)
            print(f"  Part {idx}: {file_size} chars, ~{node_count} connections -> {out_path}")
            
        except Exception as e:
            print(f"Error writing file {out_path}: {e}")

    total_size = sum(len("\n".join(chunk)) for chunk in chunks)
    print(f"Combined Mermaid flowchart saved to: {', '.join(written_paths)}")
    print(f"Total size: {total_size} chars across {len(chunks)} file(s)")
    
    return written_paths

def generate_flowchart_mermaid_with_retry(code, node_name="", max_retries=3, base_delay=15):
    """Generate Mermaid flowchart with retry logic and size constraints"""
    for attempt in range(max_retries):
        try:
            model = get_gemini_model()
            if len(code) > 5000:
                code = code[:4900] + "\n... (truncated for processing)"
            
            prompt = (
                f"Create a CONCISE Mermaid flowchart for this code{' from ' + node_name if node_name else ''}. "
                "IMPORTANT: Keep it simple and under 10 connections. Follow these EXACT rules:\n\n"
                "CORRECT format examples:\n"
                "Start-->ProcessData\n"
                "ProcessData-->CheckValid{Is Valid?}\n"
                "CheckValid-->SaveFile\n"
                "CheckValid-->ShowError\n"
                "SaveFile-->End\n\n"
                "WRONG formats (DO NOT USE):\n"
                "Start-->[ProcessData]  ❌ NEVER put brackets after arrow\n"
                "[Start]-->ProcessData  ❌ NEVER start with bracketed node\n"
                "Start --> ProcessData  ❌ NEVER use spaces around arrows\n\n"
                "Rules:\n"
                "1. Use: NodeA-->NodeB (simple connection)\n"
                "2. Use: NodeA-->NodeB{Question?} (for decisions)\n"
                "3. NO brackets after arrows: -->NodeB NOT -->[NodeB]\n"
                "4. NO spaces around arrows: --> NOT -- >\n"
                "5. Start with simple node name, no brackets\n"
                "6. Only output the connections, no 'flowchart TD'\n"
                "7. One connection per line\n"
                "8. MAXIMUM 10 connections to keep diagram manageable\n"
                "9. Use short, clear node names (max 15 chars)\n"
                "10. Focus on main logic flow only\n\n"
                f"Generate CONCISE flowchart for:\n{code}"
            )
            
            response = model.generate_content(prompt)
            
            if hasattr(response, 'text'):
                result = response.text.strip()
            elif hasattr(response, 'candidates') and response.candidates:
                result = response.candidates[0].text.strip()
            else:
                print("Error: Unexpected API response format.")
                return None
            if count_connections(result) > MAX_CONNECTIONS_PER_NODE:
                result = truncate_mermaid_code(result, MAX_CONNECTIONS_PER_NODE)
            
            return result
                
        except Exception as e:
            error_msg = str(e)
            if "429" in error_msg or "quota" in error_msg.lower():
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    print(f"Rate limit exceeded for {node_name}. Retrying in {delay} seconds... (attempt {attempt + 1}/{max_retries})")
                    time.sleep(delay)
                    continue
                else:
                    print(f"Max retries exceeded for {node_name}. Skipping...")
                    return None
            else:
                print(f"Error generating flowchart with Gemini for {node_name}: {e}")
                return None
                
    return None

def generate_flowchart_mermaid(code, node_name=""):
    return generate_flowchart_mermaid_with_retry(code, node_name)

def filter_and_prioritize_nodes(subtrees, max_nodes=50):
    """Filter and prioritize nodes to process based on importance"""
    all_nodes = []
    
    for subtree_idx, subtree in enumerate(subtrees):
        for node in subtree.get('nodes', []):
            node_name = node.get('name', f'node_{subtree_idx}')
            code = node.get('cleaned_content') or node.get('raw_content')
            
            if not code or not code.strip():
                continue
            priority = 0
            code_lower = code.lower()
            if any(keyword in code_lower for keyword in ['main', 'init', 'setup', 'config']):
                priority += 10
            if any(keyword in code_lower for keyword in ['def ', 'function', 'class ']):
                priority += 5
            if any(keyword in code_lower for keyword in ['if ', 'for ', 'while ', 'try:']):
                priority += 3
            if len(code) < 1000:
                priority += 2
            elif len(code) > 5000:
                priority -= 2
            
            all_nodes.append({
                'node': node,
                'name': node_name,
                'code': code,
                'priority': priority,
                'subtree_idx': subtree_idx
            })
    all_nodes.sort(key=lambda x: x['priority'], reverse=True)
    return all_nodes[:max_nodes]

def main():
    if not API_KEY:
        print("ERROR: No Gemini API key provided. Set the GEMINI_API_KEY environment variable.")
        return

    try:
        subtrees = load_json(SUBTREES_PATH)
        hash_map = load_json(HASH_MAP_PATH)
        
        print(f"Loaded {len(subtrees)} subtrees")
        priority_nodes = filter_and_prioritize_nodes(subtrees, max_nodes=50)
        print(f"Selected {len(priority_nodes)} nodes for processing")
        
        all_mermaid = []
        failed_nodes = []
        
        for i, node_info in enumerate(priority_nodes):
            node_name = node_info['name']
            code = node_info['code']
            
            print(f"Processing {i+1}/{len(priority_nodes)}: {node_name}")
            
            mermaid_code = generate_flowchart_mermaid(code, node_name)
            
            if mermaid_code and mermaid_code.strip():
                all_mermaid.append(mermaid_code)
                print(f"  [OK] Generated flowchart ({len(mermaid_code)} chars)")
            else:
                failed_nodes.append(node_name)
                print(f"  [FAILED] No valid Mermaid code generated")
        if all_mermaid:
            written_files = write_mermaid_to_file(all_mermaid, OUTPUT_MERMAID_PATH)
            print(f"\nSUCCESS: Generated flowchart with {len(all_mermaid)} sections")
            print(f"Files created: {len(written_files)}")
            
            if failed_nodes:
                print(f"Failed nodes ({len(failed_nodes)}): {', '.join(failed_nodes[:10])}")
                if len(failed_nodes) > 10:
                    print(f"... and {len(failed_nodes) - 10} more")
        else:
            with open(OUTPUT_MERMAID_PATH, 'w', encoding='utf-8') as f:
                f.write('flowchart TD\n    Start-->End\n    %% Empty logical flowchart - all nodes failed to generate')
            print("WARNING: No Mermaid code generated; wrote empty flowchart placeholder.")
            
    except FileNotFoundError as e:
        print(f"File not found: {e}")
        print("Make sure the code-packager has been run first to generate the required JSON files.")
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON file: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
