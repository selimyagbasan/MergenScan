import re

with open("security_scanner.html", "r", encoding="utf-8") as f:
    content = f.read()

# Find and replace the continent data + drawContinents function
old_start = "// Simplified continent outlines"
old_end = "/* \u2500\u2500 City Nodes"

start_idx = content.find(old_start)
end_idx = content.find(old_end)

if start_idx == -1 or end_idx == -1:
    print(f"Could not find markers. start={start_idx}, end={end_idx}")
    # Try alternative
    old_start = "continent"
    for i, line in enumerate(content.split('\n')):
        if 'continent' in line.lower():
            print(f"Line {i}: {line.strip()[:80]}")
else:
    new_code = """// World map data (loaded from TopoJSON)
      let worldFeatures = null;
      fetch('https://unpkg.com/world-atlas@2/countries-110m.json')
        .then(r => r.json())
        .then(world => {
          worldFeatures = topojson.feature(world, world.objects.countries).features;
        })
        .catch(() => { worldFeatures = []; });

      function drawContinents() {
        if (!worldFeatures) return;
        ctx.strokeStyle = 'rgba(0,0,0,0.08)';
        ctx.fillStyle = 'rgba(0,0,0,0.04)';
        ctx.lineWidth = 0.4;
        for (const feature of worldFeatures) {
          const geom = feature.geometry;
          const polys = geom.type === 'Polygon' ? [geom.coordinates] : geom.coordinates;
          for (const poly of polys) {
            for (const ring of poly) {
              ctx.beginPath();
              for (let i = 0; i < ring.length; i++) {
                const p = geoToXY(ring[i][1], ring[i][0]);
                if (i === 0) ctx.moveTo(p.x, p.y);
                else ctx.lineTo(p.x, p.y);
              }
              ctx.closePath();
              ctx.fill();
              ctx.stroke();
            }
          }
        }
      }

      """
    
    content = content[:start_idx] + new_code + content[end_idx:]
    
    with open("security_scanner.html", "w", encoding="utf-8") as f:
        f.write(content)
    
    print("Successfully replaced continent code with TopoJSON world map!")
