import re

with open("security_scanner.html", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Remove TopoJSON and Globe.gl scripts
content = content.replace('<script src="https://unpkg.com/topojson-client@3"></script>\n  <script src="https://unpkg.com/globe.gl"></script>', '')
content = content.replace('<script src="https://unpkg.com/topojson-client@3"></script>', '')
content = content.replace('<script src="https://unpkg.com/globe.gl"></script>', '')

# 2. Replace DOM container with Kaspersky iframe
start_dom = content.find('<div class="h-[400px]')
end_dom = content.find('</div>\n            </div>', start_dom) + 25

if start_dom != -1 and end_dom != -1:
    new_dom = """<div class="h-[450px] w-full mt-4 rounded-lg relative overflow-hidden bg-white" style="border:1px solid rgba(0,0,0,0.06)">
              <iframe width="100%" height="100%" src="https://cybermap.kaspersky.com/tr/widget/dynamic/light" frameborder="0" style="width: 100%; height: 100%; position: absolute; top: 0; left: 0;"></iframe>
            </div>"""
    content = content[:start_dom] + new_dom + content[end_dom:]

# 3. Remove JS logic
start_js = content.find('(function initThreatMap() {')
end_js = content.find('})();', start_js) + 5

if start_js != -1 and end_js != -1:
    content = content[:start_js] + content[end_js:]

# Clean up empty lines where JS used to be
content = re.sub(r'\n\s*\n\s*\n', '\n\n', content)

with open("security_scanner.html", "w", encoding="utf-8") as f:
    f.write(content)
print("Kaspersky map added successfully")
