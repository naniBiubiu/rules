#!/usr/bin/env python3
"""
list2singbox.py

Convert a Surge-style (or Clash classic-style) .list rule file into
sing-box's rule-set *source format* (version 5, sing-box >= 1.14.0).

Reference:
  https://sing-box.sagernet.org/configuration/rule-set/source-format/#rules
  https://sing-box.sagernet.org/configuration/rule-set/headless-rule/

Supported Surge/Clash line types
---------------------------------
  DOMAIN,example.com                 -> domain
  DOMAIN-SUFFIX,example.com          -> domain_suffix
  DOMAIN-KEYWORD,keyword             -> domain_keyword
  DOMAIN-REGEX,^stun\\..+            -> domain_regex   (passed through as-is)
  DOMAIN-WILDCARD,*.example.*.com    -> domain_regex   (glob converted to regex)
  IP-CIDR,1.2.3.0/24[,no-resolve]    -> ip_cidr
  IP-CIDR6,2000::/3[,no-resolve]     -> ip_cidr
  IP-ASN,12345                       -> NOT SUPPORTED, skipped with a warning
  GEOIP,CN                           -> NOT SUPPORTED, skipped with a warning
                                         (sing-box headless rules can't
                                          reference geoip/geosite databases;
                                          that only works at the DNS/Route
                                          rule level, not inside a rule-set)
  DOMAIN-SET,https://...             -> NOT SUPPORTED, skipped with a warning
  USER-AGENT,...                     -> NOT SUPPORTED, skipped with a warning
  URL-REGEX,...                      -> NOT SUPPORTED, skipped with a warning
  PROCESS-NAME,curl                  -> process_name
  FINAL / MATCH,...                  -> ignored (no equivalent, doesn't
                                         belong inside a rule-set anyway)
  # comment / blank lines            -> ignored

Output
------
A single JSON file following sing-box's source-format:

    {
      "version": 5,
      "rules": [
        {
          "domain": [...],
          "domain_suffix": [...],
          "domain_keyword": [...],
          "domain_regex": [...],
          "ip_cidr": [...],
          "process_name": [...]
        }
      ]
    }

Empty fields are omitted. All matched items of the same type are merged
into ONE rule object (this is how public rule-sets like geosite/geoip are
structured) rather than emitting one rule object per line, which keeps
the file small and fast to compile.

Usage
-----
    python3 list2singbox.py input.list -o output.json
    python3 list2singbox.py input.list            # writes input.json next to it

Then compile to the binary format sing-box actually loads at runtime:
    sing-box rule-set compile output.json --output output.srs
"""

import argparse
import json
import re
import sys
from collections import OrderedDict

# Surge/Clash line types we can translate 1:1 into a headless-rule field.
SUPPORTED_MAP = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "DOMAIN-REGEX": "domain_regex",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr",
    "PROCESS-NAME": "process_name",
}

# Types we recognise but can't (or shouldn't) translate into a rule-set.
UNSUPPORTED_TYPES = {
    "GEOIP",
    "IP-ASN",
    "DOMAIN-SET",
    "USER-AGENT",
    "URL-REGEX",
    "RULE-SET",
    "SCRIPT",
    "CELLULAR-RADIO",
}

# Types that are meaningless outside a policy file and are silently dropped
# (no warning needed).
IGNORED_TYPES = {"FINAL", "MATCH"}


def glob_to_regex(pattern: str) -> str:
    """Best-effort conversion of DOMAIN-WILDCARD glob syntax to a regex.

    Surge's DOMAIN-WILDCARD uses '*' (any run of characters, no dots
    implied) and '?' (single character). This is a simple, conservative
    translation -- always sanity-check the result before shipping it.
    """
    escaped = re.escape(pattern)
    escaped = escaped.replace(r"\*", ".*").replace(r"\?", ".")
    return "^" + escaped + "$"


def parse_line(raw_line: str, line_no: int, warnings: list):
    line = raw_line.strip()
    if not line or line.startswith("#") or line.startswith("//"):
        return None

    # Clash classic-style lines are sometimes prefixed with a leading
    # comma-less "no scheme", but the vast majority follow TYPE,VALUE[,opts]
    parts = [p.strip() for p in line.split(",")]
    if len(parts) < 2:
        warnings.append(f"[line {line_no}] 无法解析,跳过: {raw_line!r}")
        return None

    rule_type = parts[0].upper()
    value = parts[1]

    if rule_type in IGNORED_TYPES:
        return None

    if rule_type == "DOMAIN-WILDCARD":
        return ("domain_regex", glob_to_regex(value))

    if rule_type in UNSUPPORTED_TYPES:
        warnings.append(
            f"[line {line_no}] {rule_type} 在 sing-box rule-set 里没有对应字段,已跳过: {raw_line!r}"
        )
        return None

    if rule_type in SUPPORTED_MAP:
        return (SUPPORTED_MAP[rule_type], value)

    warnings.append(f"[line {line_no}] 未识别的规则类型 '{rule_type}',已跳过: {raw_line!r}")
    return None


def convert(input_path: str):
    buckets = OrderedDict([
        ("domain", []),
        ("domain_suffix", []),
        ("domain_keyword", []),
        ("domain_regex", []),
        ("ip_cidr", []),
        ("process_name", []),
    ])
    warnings = []
    seen = set()

    with open(input_path, encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            result = parse_line(raw_line, line_no, warnings)
            if result is None:
                continue
            field, val = result
            key = (field, val)
            if key in seen:
                continue
            seen.add(key)
            buckets[field].append(val)

    rule_obj = OrderedDict()
    for field, values in buckets.items():
        if values:
            rule_obj[field] = values

    source = OrderedDict([
        ("version", 5),
        ("rules", [rule_obj] if rule_obj else []),
    ])

    return source, warnings, buckets


def main():
    parser = argparse.ArgumentParser(
        description="Convert a Surge/Clash .list rule file to sing-box rule-set source format (version 5)."
    )
    parser.add_argument("input", help="Path to the input .list file")
    parser.add_argument(
        "-o", "--output", help="Path to the output .json file (default: same name as input, .json extension)"
    )
    args = parser.parse_args()

    output_path = args.output
    if not output_path:
        if args.input.lower().endswith(".list"):
            output_path = args.input[: -len(".list")] + ".json"
        else:
            output_path = args.input + ".json"

    source, warnings, buckets = convert(args.input)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(source, f, ensure_ascii=False, indent=2)
        f.write("\n")

    total = sum(len(v) for v in buckets.values())
    print(f"✅ 已生成: {output_path}")
    print(f"   共转换 {total} 条规则:")
    for field, values in buckets.items():
        if values:
            print(f"     - {field}: {len(values)} 条")

    if warnings:
        print(f"\n⚠️  有 {len(warnings)} 行未能转换,详情如下:")
        for w in warnings:
            print("   " + w)
    else:
        print("\n没有发现无法转换的行。")

    print(
        "\n下一步(可选,编译成 sing-box 实际加载的二进制格式):\n"
        f"  sing-box rule-set compile {output_path} --output "
        f"{output_path[:-5] if output_path.endswith('.json') else output_path}.srs"
    )


if __name__ == "__main__":
    main()
