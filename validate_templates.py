#!/usr/bin/env python3
import sys
import re
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from bs4 import BeautifulSoup


AUTOFIX_RULES = {
    r'ng-if="[^"]+"': '',
    r'ng-repeat="[^"]+"': '',
    r'\.length': '|length',
    r'\|\s*json': '| tojson',
    r'===': '==',
}

EXIT_FAIL = 2


def fake_context():
    return {
        "artifact": {
            "id": "TEST",
            "status": "Success",
            "data": "example.com",
            "report": {
                "full": {},
                "errorMessage": "Error"
            }
        }
    }


def autofix(content: str) -> str:
    rules = {
        r'ng-if="[^"]+"': '',
        r'ng-repeat="[^"]+"': '',
        r'<tbody[^>]*ng-repeat="[^"]+"[^>]*>': '<tbody>',
        r'\.length': '|length',
        r'\|\s*json': '| tojson',
        r'===': '==',
        r'{{\s*artifact\s*}}': '{{ artifact | string }}',
    }

    fixed = content
    for pattern, replacement in rules.items():
        fixed = re.sub(pattern, replacement, fixed)

    return fixed


def validate_html(rendered: str):
    soup = BeautifulSoup(rendered, "lxml")

    # ---- <tr> fuori da <table>
    for tr in soup.find_all("tr"):
        if not tr.find_parent("table"):
            raise Exception("<tr> outside <table>")

    # ---- bilanciamento div (best effort)
    if rendered.count("<div") != rendered.count("</div>"):
        raise Exception("Unbalanced <div> tags")

    # ---- Bootstrap tabs
    panes = soup.select(".tab-pane")
    tabs = soup.select("[data-bs-toggle='tab']")
    if panes and not tabs:
        raise Exception("tab-pane without nav-tabs")

    # ---- Bootstrap accordion
    for acc in soup.select(".accordion-collapse"):
        if not acc.get("id"):
            raise Exception("accordion-collapse missing id")


def validate_template(env, path: Path):
    raw = path.read_text(encoding="utf-8")

    try:
        tpl = env.from_string(raw)
        rendered = tpl.render(**fake_context())
    except Exception as e:
        raise Exception(f"Jinja error: {e}")

    validate_html(rendered)


def backup_file(path: Path):
    backup = path.with_suffix(path.suffix + ".backup")
    if not backup.exists():
        backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    return backup


def main():
    if len(sys.argv) != 2:
        print("Usage: validate_templates.py <template_dir>")
        sys.exit(EXIT_FAIL)

    base = Path(sys.argv[1])
    if not base.is_dir():
        print("Invalid directory")
        sys.exit(EXIT_FAIL)

    env = Environment(
        loader=FileSystemLoader(str(base)),
        undefined=StrictUndefined,
        autoescape=True
    )

    errors = 0
    fixed = 0

    print(f"\n🔍 Validating templates in {base}\n")

    for tpl in sorted(base.glob("*.html")):
        try:
            validate_template(env, tpl)
            print(f"✅ OK     {tpl.name}")
        except Exception as e:
            errors += 1
            print(f"❌ FAIL   {tpl.name}")
            print(f"   ↳ {e}")

            # ---- BACKUP
            #backup = backup_file(tpl)
            #print(f"   📦 Backup saved as {backup.name}")

            # ---- AUTOFIX (overwrite original)
            #fixed_content = autofix(tpl.read_text(encoding="utf-8"))
            #tpl.write_text(fixed_content, encoding="utf-8")
            #print(f"   🔧 Autofixed in-place")

            #fixed += 1

    print("\n📊 Summary")
    print(f"   Errors detected : {errors}")
    #print(f"   Files fixed     : {fixed}")

    sys.exit(EXIT_FAIL if errors else 0)


if __name__ == "__main__":
    main()
