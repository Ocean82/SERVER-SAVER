#!/usr/bin/env python3
import sys

with open(sys.argv[1], 'r') as f:
    content = f.read()

open_braces = content.count('{')
close_braces = content.count('}')
open_parens = content.count('(')
close_parens = content.count(')')
open_brackets = content.count('[')
close_brackets = content.count(']')

print(f"Braces: {open_braces} open, {close_braces} close, diff: {open_braces - close_braces}")
print(f"Parens: {open_parens} open, {close_parens} close, diff: {open_parens - close_parens}")
print(f"Brackets: {open_brackets} open, {close_brackets} close, diff: {open_brackets - close_brackets}")

