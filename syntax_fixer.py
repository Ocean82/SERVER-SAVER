#!/usr/bin/env python3
"""
Node.js/Express Syntax Error Diagnostic and Fix Tool
Scans for common syntax errors and provides fixes
"""

import os
import re
import json
import sys
from pathlib import Path
from typing import List, Dict, Tuple
from dataclasses import dataclass
from enum import Enum


class ErrorType(Enum):
    MISSING_CLOSING_BRACE = "missing_closing_brace"
    MISSING_CLOSING_PAREN = "missing_closing_paren"
    MISSING_CLOSING_BRACKET = "missing_closing_bracket"
    MISSING_RES_JSON = "missing_res_json"
    MISSING_RES_STATUS = "missing_res_status"
    MISSING_ASYNC_CLOSING = "missing_async_closing"
    DUPLICATE_CLOSING = "duplicate_closing"
    UNMATCHED_BRACES = "unmatched_braces"


@dataclass
class SyntaxError:
    file_path: str
    line_number: int
    error_type: str
    description: str
    suggested_fix: str
    severity: str  # critical, high, medium, low


class NodeJSSyntaxFixer:
    """Diagnostic and fix tool for Node.js/Express syntax errors"""
    
    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir)
        self.errors: List[SyntaxError] = []
        self.js_files: List[Path] = []
        
    def find_js_files(self) -> List[Path]:
        """Find all JavaScript/TypeScript files"""
        patterns = ['**/*.js', '**/*.jsx', '**/*.ts', '**/*.tsx']
        js_files = []
        
        for pattern in patterns:
            js_files.extend(self.root_dir.glob(pattern))
        
        # Exclude node_modules and common build directories
        js_files = [
            f for f in js_files 
            if 'node_modules' not in str(f) and 
               '.next' not in str(f) and
               'dist' not in str(f) and
               'build' not in str(f)
        ]
        
        self.js_files = js_files
        return js_files
    
    def count_braces(self, content: str) -> Tuple[int, int, int, int]:
        """Count opening and closing braces, parentheses, brackets"""
        open_braces = content.count('{')
        close_braces = content.count('}')
        open_parens = content.count('(')
        close_parens = content.count(')')
        open_brackets = content.count('[')
        close_brackets = content.count(']')
        
        return (open_braces, close_braces, open_parens, close_parens, open_brackets, close_brackets)
    
    def check_missing_closings(self, file_path: Path) -> List[SyntaxError]:
        """Check for missing closing braces, parentheses, brackets"""
        errors = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            return [SyntaxError(
                file_path=str(file_path),
                line_number=0,
                error_type="file_read_error",
                description=f"Could not read file: {e}",
                suggested_fix="Check file permissions",
                severity="high"
            )]
        
        open_braces, close_braces, open_parens, close_parens, open_brackets, close_brackets = self.count_braces(content)
        
        # Check for mismatches
        if open_braces > close_braces:
            diff = open_braces - close_braces
            errors.append(SyntaxError(
                file_path=str(file_path),
                line_number=len(lines),
                error_type=ErrorType.MISSING_CLOSING_BRACE.value,
                description=f"Missing {diff} closing brace(s)",
                suggested_fix=f"Add {diff} closing brace(s) at end of file or appropriate location",
                severity="critical"
            ))
        
        if open_parens > close_parens:
            diff = open_parens - close_parens
            errors.append(SyntaxError(
                file_path=str(file_path),
                line_number=len(lines),
                error_type=ErrorType.MISSING_CLOSING_PAREN.value,
                description=f"Missing {diff} closing parenthesis/parentheses",
                suggested_fix=f"Add {diff} closing parenthesis/parentheses",
                severity="critical"
            ))
        
        if open_brackets > close_brackets:
            diff = open_brackets - close_brackets
            errors.append(SyntaxError(
                file_path=str(file_path),
                line_number=len(lines),
                error_type=ErrorType.MISSING_CLOSING_BRACKET.value,
                description=f"Missing {diff} closing bracket(s)",
                suggested_fix=f"Add {diff} closing bracket(s)",
                severity="critical"
            ))
        
        return errors
    
    def check_res_json_patterns(self, file_path: Path) -> List[SyntaxError]:
        """Check for incomplete res.json() or res.status().json() calls"""
        errors = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception:
            return []
        
        # Pattern for res.json( or res.status().json( without closing
        patterns = [
            (r'res\.json\s*\([^)]*$', 'res.json()', 'missing closing parenthesis for res.json()'),
            (r'res\.status\s*\([^)]*\)\s*\.json\s*\([^)]*$', 'res.status().json()', 'missing closing parenthesis for res.status().json()'),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, method_name, description in patterns:
                if re.search(pattern, line):
                    # Check if it's actually incomplete (not just a multi-line call)
                    # Simple check: if next few lines don't have closing paren
                    next_lines = '\n'.join(lines[line_num:min(line_num+5, len(lines))])
                    if ')' not in next_lines[:200]:  # Check next 200 chars
                        errors.append(SyntaxError(
                            file_path=str(file_path),
                            line_number=line_num,
                            error_type=ErrorType.MISSING_RES_JSON.value,
                            description=description,
                            suggested_fix=f"Complete the {method_name} call with proper closing parenthesis and data",
                            severity="high"
                        ))
        
        return errors
    
    def check_async_functions(self, file_path: Path) -> List[SyntaxError]:
        """Check for incomplete async function definitions"""
        errors = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception:
            return []
        
        # Find async function declarations
        async_pattern = r'async\s+(function\s*\(|\([^)]*\)\s*=>|function\s+\w+\s*\()'
        
        for line_num, line in enumerate(lines, 1):
            if re.search(async_pattern, line):
                # Check if function is properly closed
                # This is a simplified check - would need AST for full validation
                brace_count = 0
                found_open = False
                
                for check_line in lines[line_num-1:]:
                    brace_count += check_line.count('{') - check_line.count('}')
                    if '{' in check_line:
                        found_open = True
                    if found_open and brace_count == 0 and '}' in check_line:
                        break
                else:
                    # Function might not be closed
                    if brace_count > 0:
                        errors.append(SyntaxError(
                            file_path=str(file_path),
                            line_number=line_num,
                            error_type=ErrorType.MISSING_ASYNC_CLOSING.value,
                            description="Async function may be missing closing brace",
                            suggested_fix="Ensure async function has proper closing brace",
                            severity="high"
                        ))
        
        return errors
    
    def check_duplicate_closings(self, file_path: Path) -> List[SyntaxError]:
        """Check for duplicate closing braces/parentheses (already fixed, but verify)"""
        errors = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception:
            return []
        
        # Look for patterns like }}, )), ]]
        for line_num, line in enumerate(lines, 1):
            if re.search(r'}\s*}', line) and line.strip() == '}}':
                errors.append(SyntaxError(
                    file_path=str(file_path),
                    line_number=line_num,
                    error_type=ErrorType.DUPLICATE_CLOSING.value,
                    description="Possible duplicate closing brace",
                    suggested_fix="Review if both braces are needed",
                    severity="medium"
                ))
        
        return errors
    
    def analyze_file(self, file_path: Path) -> List[SyntaxError]:
        """Run all checks on a file"""
        errors = []
        errors.extend(self.check_missing_closings(file_path))
        errors.extend(self.check_res_json_patterns(file_path))
        errors.extend(self.check_async_functions(file_path))
        errors.extend(self.check_duplicate_closings(file_path))
        return errors
    
    def scan_all(self) -> List[SyntaxError]:
        """Scan all JavaScript files"""
        self.find_js_files()
        all_errors = []
        
        print(f"Scanning {len(self.js_files)} JavaScript/TypeScript files...")
        
        for js_file in self.js_files:
            errors = self.analyze_file(js_file)
            all_errors.extend(errors)
            if errors:
                print(f"  Found {len(errors)} issue(s) in {js_file.name}")
        
        self.errors = all_errors
        return all_errors
    
    def generate_report(self, output_file: str = None) -> str:
        """Generate diagnostic report"""
        if not self.errors:
            report = "✅ No syntax errors detected!\n"
        else:
            report = f"\n{'='*80}\n"
            report += f"NODE.JS SYNTAX ERROR DIAGNOSTIC REPORT\n"
            report += f"Scanned: {len(self.js_files)} files\n"
            report += f"Total Issues: {len(self.errors)}\n"
            report += f"{'='*80}\n\n"
            
            # Group by severity
            by_severity = {}
            for error in self.errors:
                if error.severity not in by_severity:
                    by_severity[error.severity] = []
                by_severity[error.severity].append(error)
            
            for severity in ['critical', 'high', 'medium', 'low']:
                if severity in by_severity:
                    report += f"\n[{severity.upper()}] Issues ({len(by_severity[severity])}):\n"
                    report += "-" * 80 + "\n"
                    
                    for error in by_severity[severity]:
                        report += f"\nFile: {error.file_path}\n"
                        report += f"Line: {error.line_number}\n"
                        report += f"Type: {error.error_type}\n"
                        report += f"Description: {error.description}\n"
                        report += f"Fix: {error.suggested_fix}\n"
                        report += "\n"
            
            # Summary by error type
            report += "\n" + "="*80 + "\n"
            report += "SUMMARY BY ERROR TYPE:\n"
            report += "="*80 + "\n"
            
            by_type = {}
            for error in self.errors:
                if error.error_type not in by_type:
                    by_type[error.error_type] = 0
                by_type[error.error_type] += 1
            
            for error_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
                report += f"  {error_type}: {count}\n"
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"\nReport saved to {output_file}")
        
        return report
    
    def export_json(self, output_file: str):
        """Export errors as JSON"""
        errors_dict = [{
            'file_path': e.file_path,
            'line_number': e.line_number,
            'error_type': e.error_type,
            'description': e.description,
            'suggested_fix': e.suggested_fix,
            'severity': e.severity
        } for e in self.errors]
        
        with open(output_file, 'w') as f:
            json.dump({
                'total_files_scanned': len(self.js_files),
                'total_errors': len(self.errors),
                'errors': errors_dict
            }, f, indent=2)
        
        print(f"JSON report saved to {output_file}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Node.js/Express Syntax Error Diagnostic Tool'
    )
    parser.add_argument(
        'directory',
        nargs='?',
        default='.',
        help='Directory to scan (default: current directory)'
    )
    parser.add_argument(
        '--output',
        help='Output file for report'
    )
    parser.add_argument(
        '--json',
        help='Output JSON report to file'
    )
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"Error: {args.directory} is not a valid directory")
        sys.exit(1)
    
    fixer = NodeJSSyntaxFixer(args.directory)
    errors = fixer.scan_all()
    
    report = fixer.generate_report(output_file=args.output)
    print(report)
    
    if args.json:
        fixer.export_json(args.json)
    
    # Exit with error code if critical errors found
    critical_count = sum(1 for e in errors if e.severity == 'critical')
    sys.exit(1 if critical_count > 0 else 0)


if __name__ == '__main__':
    main()

