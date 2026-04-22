import re

with open("security_scanner.html", "r", encoding="utf-8") as f:
    content = f.read()

# Add globe.gl script if not there
if "globe.gl" not in content:
    content = content.replace(
        '<script src="https://unpkg.com/topojson-client@3"></script>',
        '<script src="https://unpkg.com/topojson-client@3"></script>\n  <script src="https://unpkg.com/globe.gl"></script>'
    )

# Replace DOM container
old_dom = """            <div class="h-52 w-full mt-4 rounded-lg relative overflow-hidden bg-surface-container" style="border:1px solid rgba(0,0,0,0.06)">
              <canvas id="threatMapCanvas" class="w-full h-full" style="display:block;"></canvas>
              <!-- Legend -->
              <div class="absolute bottom-2 left-3 flex items-center gap-4 z-10">
                <div class="flex items-center gap-1.5">
                  <span class="w-1.5 h-1.5 rounded-full" style="background:#ba1a1a"></span>
                  <span class="text-[9px] text-on-surface-variant/50 uppercase tracking-wider font-medium">Saldırı</span>
                </div>
                <div class="flex items-center gap-1.5">
                  <span class="w-1.5 h-1.5 rounded-full" style="background:#00855d"></span>
                  <span class="text-[9px] text-on-surface-variant/50 uppercase tracking-wider font-medium">Savunma</span>
                </div>
                <div class="flex items-center gap-1.5">
                  <span class="w-1.5 h-1.5 rounded-full" style="background:#8a5c00"></span>
                  <span class="text-[9px] text-on-surface-variant/50 uppercase tracking-wider font-medium">İzleme</span>
                </div>
              </div>
            </div>"""

new_dom = """            <div class="h-[400px] w-full mt-4 rounded-lg relative overflow-hidden bg-[#050505]" style="border:1px solid rgba(0,0,0,0.1); box-shadow: inset 0 0 40px rgba(0,0,0,0.8);">
              <div id="globeViz" class="w-full h-full cursor-move"></div>
              <!-- Legend -->
              <div class="absolute bottom-2 left-3 flex items-center gap-4 z-10 bg-black/40 backdrop-blur-md px-3 py-1.5 rounded-full border border-white/10">
                <div class="flex items-center gap-1.5">
                  <span class="w-1.5 h-1.5 rounded-full" style="background:#ff3333; box-shadow: 0 0 8px #ff3333;"></span>
                  <span class="text-[9px] text-white/80 uppercase tracking-wider font-medium">Saldırı</span>
                </div>
                <div class="flex items-center gap-1.5">
                  <span class="w-1.5 h-1.5 rounded-full" style="background:#00e676; box-shadow: 0 0 8px #00e676;"></span>
                  <span class="text-[9px] text-white/80 uppercase tracking-wider font-medium">Savunma</span>
                </div>
                <div class="flex items-center gap-1.5">
                  <span class="w-1.5 h-1.5 rounded-full" style="background:#ff9100; box-shadow: 0 0 8px #ff9100;"></span>
                  <span class="text-[9px] text-white/80 uppercase tracking-wider font-medium">İzleme</span>
                </div>
              </div>
            </div>"""

content = content.replace(old_dom, new_dom)

# Replace JS logic
start_idx = content.find("(function initThreatMap() {")
end_idx = content.find("})();", start_idx) + 5

if start_idx != -1 and end_idx != -1:
    new_js = """(function initThreatMap() {
      const container = document.getElementById('globeViz');
      if (!container) return;

      const N = 15;
      const arcsData = [];
      const cities = [
        { lat: 41.01, lng: 28.98, name: 'İstanbul', type: 'defense', color: '#00e676' },
        { lat: 39.92, lng: 32.85, name: 'Ankara', type: 'defense', color: '#00e676' },
        { lat: 51.50, lng: -0.12, name: 'Londra', type: 'monitor', color: '#ff9100' },
        { lat: 48.85, lng: 2.35, name: 'Paris', type: 'monitor', color: '#ff9100' },
        { lat: 40.71, lng: -74.0, name: 'New York', type: 'monitor', color: '#ff9100' },
        { lat: 37.77, lng: -122.4, name: 'San Francisco', type: 'defense', color: '#00e676' },
        { lat: 35.68, lng: 139.69, name: 'Tokyo', type: 'monitor', color: '#ff9100' },
        { lat: 55.75, lng: 37.61, name: 'Moskova', type: 'attack', color: '#ff3333' },
        { lat: 39.90, lng: 116.40, name: 'Pekin', type: 'attack', color: '#ff3333' },
        { lat: 1.35, lng: 103.82, name: 'Singapur', type: 'defense', color: '#00e676' },
        { lat: -33.86, lng: 151.20, name: 'Sidney', type: 'monitor', color: '#ff9100' },
        { lat: 19.43, lng: -99.13, name: 'Mexico City', type: 'attack', color: '#ff3333' },
        { lat: 52.52, lng: 13.40, name: 'Berlin', type: 'monitor', color: '#ff9100' },
        { lat: 25.20, lng: 55.27, name: 'Dubai', type: 'defense', color: '#00e676' }
      ];

      function genArc() {
        const attackCities = cities.filter(c => c.type === 'attack' || Math.random() > 0.7);
        const defenseCities = cities.filter(c => c.type === 'defense' || c.type === 'monitor');
        const from = attackCities[Math.floor(Math.random() * attackCities.length)];
        const to = defenseCities[Math.floor(Math.random() * defenseCities.length)];
        if (from === to) return null;
        return {
          startLat: from.lat,
          startLng: from.lng,
          endLat: to.lat,
          endLng: to.lng,
          color: [from.color, to.color]
        };
      }

      for (let i = 0; i < N; i++) {
        const arc = genArc();
        if(arc) arcsData.push(arc);
      }

      const world = Globe()(container)
        .globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg')
        .backgroundColor('#050505')
        .pointsData(cities)
        .pointLat('lat')
        .pointLng('lng')
        .pointColor('color')
        .pointAltitude(0.05)
        .pointRadius(0.8)
        .arcsData(arcsData)
        .arcColor('color')
        .arcDashLength(0.4)
        .arcDashGap(0.2)
        .arcDashInitialGap(() => Math.random())
        .arcDashAnimateTime(1500)
        .arcStroke(0.8);

      world.controls().autoRotate = true;
      world.controls().autoRotateSpeed = 1.0;

      // Ensure proper sizing
      const resizeOb = new ResizeObserver(() => {
        if(container.parentElement) {
            world.width(container.parentElement.clientWidth);
            world.height(container.parentElement.clientHeight);
        }
      });
      resizeOb.observe(container.parentElement);

      let threatCount = parseInt(document.getElementById('threatCounter')?.innerText.replace(/\D/g, '') || '1061');
      const threatEl = document.getElementById('threatCounter');
      setInterval(() => {
        threatCount += Math.floor(Math.random() * 3);
        if (threatEl) threatEl.innerText = threatCount.toLocaleString('tr-TR');
        // dynamically add new arcs
        if(Math.random() > 0.4) {
            const arc = genArc();
            if(arc) {
                const currentArcs = world.arcsData();
                world.arcsData([...currentArcs.slice(-25), arc]); // keep max 25 arcs
            }
        }
      }, 2000);

    })();"""
    content = content[:start_idx] + new_js + content[end_idx:]
else:
    print("Could not find initThreatMap block")

with open("security_scanner.html", "w", encoding="utf-8") as f:
    f.write(content)
print("Updated successfully")
