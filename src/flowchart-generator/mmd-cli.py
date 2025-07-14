import subprocess
import os
import sys
import shutil
import argparse
import re
import json
from typing import List, Tuple, Set


def clean_node_name(name: str) -> str:
    """Clean node name to be valid Mermaid syntax"""
    if not name:
        return "EmptyNode"
    
    name = re.sub(r'[^\w\-]', '_', name)
    
    name = re.sub(r'_{2,}', '_', name)
    
    name = name.strip('_')
    
    if not name or not name[0].isalpha():
        name = f"Node_{name}" if name else "Node"
    
    if len(name) > 30:
        name = name[:27] + "..."
    
    return name


def extract_node_names(line: str) -> List[str]:
    """Extract node names from a mermaid line"""
    nodes = []
    
    decision_pattern = r'(\w+)\{([^}]+)\}'
    for match in re.finditer(decision_pattern, line):
        nodes.append(match.group(1))
    
    connection_pattern = r'(\w+)-->'
    for match in re.finditer(connection_pattern, line):
        nodes.append(match.group(1))
    
    target_pattern = r'-->(\w+)'
    for match in re.finditer(target_pattern, line):
        nodes.append(match.group(1))
    
    return nodes


def fix_mermaid_syntax(content: str) -> Tuple[str, List[str]]:
    """Fix Mermaid syntax issues and return fixed content and issues found"""
    lines = content.split('\n')
    fixed_lines = []
    issues = []
    node_mapping = {}
    
    for line_num, line in enumerate(lines, 1):
        original_line = line
        line = line.strip()
        
        if not line or line.startswith('%%') or line.startswith('flowchart'):
            fixed_lines.append(original_line)
            continue
        
        if 'age-->Get today_s da' in line:
            issues.append(f"Line {line_num}: Suspicious node name pattern detected")
        
        try:
            if '-->' in line:
                parts = line.split('-->')
                if len(parts) >= 2:
                    source = parts[0].strip()
                    target = parts[1].strip()
                    
                    if source:
                        clean_source = clean_node_name(source)
                        if clean_source != source:
                            node_mapping[source] = clean_source
                            issues.append(f"Line {line_num}: Cleaned source node '{source}' -> '{clean_source}'")
                    
                    if target:
                        decision_match = re.match(r'^(\w+)\{([^}]+)\}$', target)
                        if decision_match:
                            node_name = decision_match.group(1)
                            decision_text = decision_match.group(2)
                            clean_node = clean_node_name(node_name)
                            clean_text = re.sub(r'[^\w\s\?]', '', decision_text)[:30]
                            target = f"{clean_node}{{{clean_text}}}"
                        else:
                            clean_target = clean_node_name(target)
                            if clean_target != target:
                                node_mapping[target] = clean_target
                                issues.append(f"Line {line_num}: Cleaned target node '{target}' -> '{clean_target}'")
                                target = clean_target
                    
                    line = f"{clean_source if source else 'Start'}-->{target if target else 'End'}"
            
            if '-->' not in line and ' ' in line:
                token_parts = line.split()
                if len(token_parts) >= 2:
                    src_token = token_parts[0]
                    tgt_token = ''.join(token_parts[1:])
                    clean_src = clean_node_name(src_token)
                    tgt_has_brace = '{' in tgt_token and '}' in tgt_token
                    if tgt_has_brace:
                        m = re.match(r'^(\w+)\{([^}]+)\}$', tgt_token)
                        if m:
                            tgt_name = clean_node_name(m.group(1))
                            tgt_text = re.sub(r'[^\w\s\?]', '', m.group(2))[:30]
                            tgt_token = f"{tgt_name}{{{tgt_text}}}"
                    else:
                        tgt_token = clean_node_name(tgt_token)
                    line = f"{clean_src}-->{tgt_token}"

            line = re.sub(r'\s+', ' ', line)
            line = re.sub(r'[^\w\s\-\>\{\}\?\.]', '_', line)
            
            if '-->' in line:
                if line.count('-->') != len(re.findall(r'-->', line)):
                    issues.append(f"Line {line_num}: Arrow count mismatch")
                
                nodes = extract_node_names(line)
                for node in nodes:
                    if not re.match(r'^[a-zA-Z]\w*$', node):
                        issues.append(f"Line {line_num}: Invalid node name '{node}'")
            
        except Exception as e:
            issues.append(f"Line {line_num}: Error processing line: {e}")
            line = f"%% Error on line {line_num}: {original_line.strip()}"
        
        fixed_lines.append(line)
    
    return '\n'.join(fixed_lines), issues


def validate_and_fix_mermaid_file(file_path: str, auto_fix: bool = True) -> bool:
    """Validate and optionally fix a Mermaid file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        print(f"Validating file: {file_path}")
        print(f"Original size: {len(content)} characters")
        
        fixed_content, issues = fix_mermaid_syntax(content)
        
        if issues:
            print(f"\nFound {len(issues)} syntax issues:")
            for issue in issues[:10]:
                print(f"  - {issue}")
            if len(issues) > 10:
                print(f"  ... and {len(issues) - 10} more issues")
            
            if auto_fix:
                backup_path = file_path + '.backup'
                with open(backup_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"\nBackup created: {backup_path}")
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(fixed_content)
                
                print(f"Fixed file written: {file_path}")
                print(f"New size: {len(fixed_content)} characters")
                return True
            else:
                print("\nUse --fix flag to automatically fix these issues")
                return False
        else:
            print("No syntax issues found")
            return True
        
    except Exception as e:
        print(f"Error processing file: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Render Mermaid .mmd file to SVG using mermaid-cli with adaptive maxEdges and syntax validation.")
    parser.add_argument('-i', '--input', help='Path to input .mmd file', default=None)
    parser.add_argument('-o', '--output', help='Path to output .svg file', default=None)
    parser.add_argument('--max-text-size', type=int, help='Override maximum text size limit', default=None)
    parser.add_argument('--split-large', action='store_true', help='Split large diagrams into multiple files')
    parser.add_argument('--fix', action='store_true', help='Automatically fix syntax issues')
    parser.add_argument('--validate-only', action='store_true', help='Only validate syntax, don\'t render')
    parser.add_argument('--skip-validation', action='store_true', help='Skip syntax validation')
    args = parser.parse_args()

    default_mmd = os.path.join(os.path.dirname(__file__), 'project_flowchart.mmd')
    mmd_path = args.input if args.input else default_mmd

    if args.output:
        svg_path = args.output
    else:
        stem, _ = os.path.splitext(mmd_path)
        svg_path = f"{stem}.svg"

    if not os.path.exists(mmd_path):
        print(f"Mermaid file not found at {mmd_path}. Run the generator first.")
        sys.exit(1)

    if not args.skip_validation:
        print("=== Syntax Validation ===")
        validation_success = validate_and_fix_mermaid_file(mmd_path, args.fix)
        
        if not validation_success and not args.fix:
            print("Syntax validation failed. Use --fix to automatically fix issues or --skip-validation to proceed anyway.")
            sys.exit(1)
        
        if args.validate_only:
            print("Validation complete. Use without --validate-only to render the diagram.")
            return

    edge_count = 0
    try:
        with open(mmd_path, 'r', encoding='utf-8') as mmd_file:
            for line in mmd_file:
                stripped = line.strip()
                if not stripped or stripped.startswith('%%'):
                    continue
                if '-->' in stripped:
                    edge_count += 1
    except Exception as e:
        print(f"Error reading mermaid file: {e}")
        sys.exit(1)

    try:
        with open(mmd_path, 'r', encoding='utf-8') as f:
            content = f.read()
            char_count = len(content)
            line_count = content.count('\n')
            word_count = len(content.split())
    except Exception as e:
        print(f"Error analyzing file: {e}")
        sys.exit(1)

    print(f"\n=== File Metrics ===")
    print(f"Characters: {char_count}, Lines: {line_count}, Words: {word_count}, Edges: {edge_count}")

    if char_count > 100000 and args.split_large:
        print("Large diagram detected. Attempting to split...")
        if split_diagram(mmd_path, svg_path):
            return
        else:
            print("Split failed, continuing with single large diagram...")

    buffer = max(int(edge_count * 0.2), 50)
    max_edges_value = edge_count + buffer

    config_path = os.path.join(os.path.dirname(__file__), 'mermaid_config.json')
    try:
        if args.max_text_size:
            max_text_size = args.max_text_size
        else:
            base_size = max(char_count * 2, 100000)
            complexity_multiplier = 1 + (edge_count / 1000)
            max_text_size = int(base_size * complexity_multiplier)
            
            max_text_size = min(max_text_size, 10 * 1024 * 1024)
        
        config = {
            "maxEdges": max_edges_value,
            "maxTextSize": max_text_size,
            "securityLevel": "loose",
            "flowchart": {
                "htmlLabels": False,
                "curve": "linear"
            }
        }
        
        with open(config_path, 'w', encoding='utf-8') as cfg:
            json.dump(config, cfg, indent=2)
            
        print(f"Config: maxEdges={max_edges_value}, maxTextSize={max_text_size}")
        
    except Exception as e:
        print(f"Failed to write Mermaid config: {e}")
        sys.exit(1)

    npx_cmd = 'npx.cmd' if os.name == 'nt' else 'npx'
    if not shutil.which(npx_cmd):
        print("Error: 'npx' (Node.js) is not installed or not in your PATH. Please install Node.js and ensure 'npx' is available.")
        sys.exit(1)

    cmd_svg = [
        npx_cmd, 'mmdc',
        '-i', mmd_path,
        '-o', svg_path,
        '-c', config_path
    ]
    
    try:
        print(f"\n=== Rendering SVG ===")
        print(f"Running: {' '.join(cmd_svg)}")
        result_svg = subprocess.run(cmd_svg, capture_output=True, text=True, check=True)
        
        if os.path.exists(svg_path):
            file_size = os.path.getsize(svg_path)
            print(f"SUCCESS: Vector SVG successfully generated at {svg_path} ({file_size} bytes)")
        else:
            print("WARNING: Mermaid-CLI reported success but the SVG was not generated.")
            print("This often means there was a syntax error in the .mmd file.")
            sys.exit(1)

        if result_svg.stdout:
            print("STDOUT:", result_svg.stdout)
        if result_svg.stderr:
            print("STDERR:", result_svg.stderr)
            
    except subprocess.CalledProcessError as e:
        print("ERROR: Error running mermaid-cli:")
        print(f"Return code: {e.returncode}")
        print(f"STDERR: {e.stderr}")
        print(f"STDOUT: {e.stdout}")
        
        if "text size" in e.stderr.lower() or "too large" in e.stderr.lower():
            print("\nSuggestions:")
            print("1. Try with --split-large flag to split the diagram")
            print("2. Use --max-text-size with a larger value (e.g., --max-text-size 5000000)")
            print("3. Reduce the complexity of your flowchart generator")
        elif "syntax" in e.stderr.lower() or "parse" in e.stderr.lower():
            print("\nSuggestions:")
            print("1. Run with --fix flag to automatically fix syntax issues")
            print("2. Use --validate-only to check for syntax issues without rendering")
        
        sys.exit(1)


def split_diagram(input_path, output_path):
    """Split a large Mermaid diagram into smaller chunks"""
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        sections = []
        current_section = []
        header_line = None
        
        for line in lines:
            if line.strip().startswith('flowchart'):
                header_line = line
                continue
            elif line.strip().startswith('%%') and 'Section' in line:
                if current_section:
                    sections.append(current_section)
                    current_section = []
            else:
                current_section.append(line)
        
        if current_section:
            sections.append(current_section)
        
        if len(sections) <= 1:
            print("Cannot split: diagram has only one section")
            return False
        
        base_path = os.path.splitext(output_path)[0]
        success_count = 0
        
        for i, section in enumerate(sections, 1):
            section_input = f"{os.path.splitext(input_path)[0]}_part{i}.mmd"
            section_output = f"{base_path}_part{i}.svg"
            
            with open(section_input, 'w', encoding='utf-8') as f:
                if header_line:
                    f.write(header_line)
                f.writelines(section)
            
            cmd = [
                'npx.cmd' if os.name == 'nt' else 'npx', 'mmdc',
                '-i', section_input,
                '-o', section_output
            ]
            
            try:
                subprocess.run(cmd, check=True, capture_output=True)
                print(f"Generated part {i}: {section_output}")
                success_count += 1
            except subprocess.CalledProcessError as e:
                print(f"Failed to generate part {i}: {e}")
            
            try:
                os.remove(section_input)
            except:
                pass
        
        print(f"Successfully split diagram into {success_count} parts")
        return success_count > 0
        
    except Exception as e:
        print(f"Error splitting diagram: {e}")
        return False


if __name__ == "__main__":
    main()