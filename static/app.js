/* ── XSS Protection ── */
    function escapeHTML(str) {
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    function safeWebURL(value) {
      try {
        const parsed = new URL(String(value));
        if (['http:', 'https:'].includes(parsed.protocol) && !parsed.username && !parsed.password) return parsed.href;
      } catch (_) {}
      return '';
    }

    function scanFetch(path, options = {}) {
      const headers = new Headers(options.headers || {});
      const key = document.getElementById('apiKey').value;
      if (key) headers.set('X-API-Key', key);
      return fetch(path, { ...options, headers, credentials: 'same-origin' });
    }

    async function loadScanConfig() {
      try {
        const response = await fetch('/api/config');
        if (!response.ok) throw new Error('config unavailable');
        const config = await response.json();
        document.getElementById('scanAvailability').textContent = !config.scan_available
          ? 'Tarama şu anda kullanılamıyor: sunucu yöneticisi erişim anahtarını yapılandırmalı.'
          : config.auth_required ? 'Tarama için erişim bölümüne API anahtarınızı girin.' : '';
        document.getElementById('btnScan').disabled = !config.scan_available;
      } catch (_) {
        document.getElementById('scanAvailability').textContent = 'Erişim bilgisi alınamadı. Tarama başlatırken sunucu yanıtı kontrol edilir.';
      }
    }

    /* ── Module List ── */
    const modules = [
      { id: 'sqli',      name: 'SQL Injection',    icon: 'database' },
      { id: 'xss',       name: 'XSS',              icon: 'code' },
      { id: 'csrf',      name: 'CSRF',              icon: 'token' },
      { id: 'headers',   name: 'HTTP Headers',      icon: 'shield' },
      { id: 'traversal', name: 'Path Traversal',    icon: 'folder_open' },
      { id: 'files',     name: 'Hassas Dosyalar',   icon: 'lock_open' },
      { id: 'redirect',  name: 'Open Redirect',     icon: 'open_in_new' },
      { id: 'cmdi',      name: 'Cmd Injection',     icon: 'terminal' },
      { id: 'cors',      name: 'CORS',              icon: 'public' },
      { id: 'ssl',       name: 'SSL/TLS',           icon: 'https' },
      { id: 'waf',       name: 'WAF Tespiti',       icon: 'security' },
      { id: 'cookies',   name: 'Cookie Bayrakları', icon: 'cookie' },
      { id: 'methods',   name: 'HTTP Metodları', icon: 'http' },
      { id: 'clickjack', name: 'Clickjacking', icon: 'web' },
      { id: 'ratelimit', name: 'Rate Limiting', icon: 'speed' },
      { id: 'tech',      name: 'Teknoloji Tespiti', icon: 'memory' },
      { id: 'ports',     name: 'Port Taraması', icon: 'lan' },
      { id: 'robots',    name: 'Robots/Sitemap',    icon: 'smart_toy' },
    ];

    let currentScanId = null;
    let lastScanResult = null;
    let scannedUrl = '';

    /* ── Build Module Toggles on Load ── */
    document.addEventListener('DOMContentLoaded', () => {
      const grid = document.getElementById('modulesGrid');
      grid.innerHTML = modules.map(mod => `
        <label class="module-item active flex items-center gap-3 bg-surface-container-low border border-surface-container-high rounded-lg p-3 cursor-pointer hover:bg-surface-container-high transition-colors" data-module="${mod.id}">
          <input type="checkbox" checked class="hidden" />
          <div class="toggle-track"></div>
          <span class="material-symbols-outlined text-base text-on-surface-variant">${mod.icon}</span>
          <span class="font-label text-sm font-medium">${mod.name}</span>
        </label>
      `).join('');

      grid.addEventListener('click', e => {
        const item = e.target.closest('.module-item');
        if (!item) return;
        e.preventDefault();
        item.classList.toggle('active');
        const cb = item.querySelector('input[type="checkbox"]');
        if (cb) cb.checked = item.classList.contains('active');
        updateModuleCount();
      });

      document.getElementById('focusTarget').addEventListener('click', () => {
        document.getElementById('targetUrl').focus();
        document.getElementById('targetUrl').scrollIntoView({behavior: 'smooth', block: 'center'});
      });
      document.getElementById('targetUrl').addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });
      document.getElementById('btnScan').addEventListener('click', startScan);
      document.getElementById('btnModules').addEventListener('click', () => document.getElementById('moduleDropdown').classList.toggle('active'));
      document.getElementById('closeModules').addEventListener('click', () => document.getElementById('moduleDropdown').classList.remove('active'));
      document.getElementById('toggleAllModules').addEventListener('click', toggleAllModules);
      document.getElementById('cancelScan').addEventListener('click', cancelCurrentScan);
      document.getElementById('newScan').addEventListener('click', () => location.reload());
      document.getElementById('findingsList').addEventListener('click', e => {
        const header = e.target.closest('.finding-header');
        if (header) header.parentElement.classList.toggle('open');
      });
      updateModuleCount();
      loadNews();
      loadScanConfig();

      // Close dropdown when clicking outside
      document.addEventListener('click', e => {
        const dropdown = document.getElementById('moduleDropdown');
        const btn = document.getElementById('btnModules');
        if (!dropdown.contains(e.target) && !btn.contains(e.target)) {
          dropdown.classList.remove('active');
        }
      });
    });

    function updateModuleCount() {
      const total = modules.length;
      const selected = document.querySelectorAll('.module-item.active').length;
      document.getElementById('moduleCount').textContent = `${selected} / ${total} seçili`;
    }

    function toggleAllModules() {
      const items = document.querySelectorAll('.module-item');
      const allActive = [...items].every(i => i.classList.contains('active'));
      items.forEach(item => {
        if (allActive) {
          item.classList.remove('active');
          item.querySelector('input').checked = false;
        } else {
          item.classList.add('active');
          item.querySelector('input').checked = true;
        }
      });
      updateModuleCount();
    }

    /* ── Get Selected Modules ── */
    function getSelectedModules() {
      return [...document.querySelectorAll('.module-item.active')]
        .map(el => el.dataset.module)
        .filter(Boolean);
    }

    /* ── Load News from API ── */
    async function loadNews() {
      try {
        const res = await fetch('/api/news');
        if (!res.ok) throw new Error('Hata');
        const data = await res.json();
        const fallbackImg = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='400' height='200'%3E%3Crect width='400' height='200' fill='%23eeeeee'/%3E%3Ctext x='50%25' y='50%25' dominant-baseline='middle' text-anchor='middle' font-family='Inter,sans-serif' font-size='14' fill='%23777777'%3EGörsel Yok%3C/text%3E%3C/svg%3E";

        document.getElementById('newsGrid').innerHTML = data.articles.filter(a => safeWebURL(a.link)).map(a => `
          <a href="${escapeHTML(safeWebURL(a.link))}" target="_blank" rel="noopener noreferrer"
             class="group bg-surface-container-lowest rounded-lg overflow-hidden ambient-shadow flex flex-col cursor-pointer hover:-translate-y-1 transition-transform duration-300">
            <div class="h-56 overflow-hidden relative">
              <img alt="${escapeHTML(a.title)}"
                   class="object-cover w-full h-full group-hover:scale-105 transition-transform duration-700"
                   src="${escapeHTML(safeWebURL(a.image)) || fallbackImg}"
                   loading="lazy"
                   data-fallback="true" />
            </div>
            <div class="p-6 flex flex-col flex-1">
              <h3 class="font-headline text-lg font-bold text-on-surface mb-3 group-hover:text-primary transition-colors line-clamp-2">
                ${escapeHTML(a.title)}
              </h3>
              <div class="mt-auto pt-4 border-t border-surface-container-low flex justify-between items-center">
                <span class="font-label text-xs font-bold uppercase tracking-widest text-primary">DETAYLI İNCELE</span>
                <span class="material-symbols-outlined text-primary group-hover:translate-x-1 transition-transform">arrow_right_alt</span>
              </div>
            </div>
          </a>
        `).join('');
      } catch (e) {
        document.getElementById('newsGrid').innerHTML = `
          <div class="col-span-full text-center py-12">
            <span class="material-symbols-outlined text-4xl text-on-surface-variant/40 mb-3 block">cloud_off</span>
            <p class="font-label text-sm text-on-surface-variant">Haberler yüklenemedi.</p>
          </div>`;
      }
    }

    /* ── Start Scan ── */
    async function startScan() {
      const url = document.getElementById('targetUrl').value.trim();
      if (!url) return alert('Lütfen URL girin.');

      const selectedModules = getSelectedModules();
      if (selectedModules.length === 0) return alert('Lütfen en az bir modül seçin.');

      scannedUrl = url;

      /* UI: Switch to progress mode */
      document.getElementById('mainContent').style.display = 'none';
      document.getElementById('bentoGrid').style.display = 'none';
      document.getElementById('trustMetrics')?.closest && (document.getElementById('trustMetrics').style.display = 'none');
      document.getElementById('progressSection').style.display = 'flex';
      document.getElementById('resultsSection').style.display = 'none';
      document.getElementById('btnScan').disabled = true;

      try {
        const res = await scanFetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: url, modules: selectedModules })
        });

        if (!res.ok) {
          let errMsg = `Sunucu Hatası (${res.status}).`;
          try { const errData = await res.json(); errMsg = errData.error || errMsg; } catch (e) { }
          throw new Error(errMsg);
        }

        const data = await res.json();
        currentScanId = data.scan_id;

        let polling = false;
        const pollInterval = setInterval(async () => {
          if (polling) return;
          polling = true;
          try {
            const statusRes = await scanFetch('/api/status/' + currentScanId);
            if (!statusRes.ok) throw new Error(`Tarama durumu alınamadı (${statusRes.status}).`);
            const statusData = await statusRes.json();

            if (statusData.status === 'error') {
              clearInterval(pollInterval);
              document.getElementById('spinnerSub').textContent = '// Hata: ' + statusData.msg;
              return;
            }

            for (const msg of (statusData.messages || [])) {
              if (msg === '__DONE__') {
                clearInterval(pollInterval);
                await new Promise(resolve => setTimeout(resolve, 300));
                const resultRes = await scanFetch('/api/results/' + currentScanId);
                if (resultRes.status === 202) {
                  await new Promise(resolve => setTimeout(resolve, 500));
                  const retryRes = await scanFetch('/api/results/' + currentScanId);
                  if (retryRes.status === 202 || !retryRes.ok) throw new Error('Sonuç alınamadı.');
                  showResults(await retryRes.json());
                } else if (!resultRes.ok) {
                  throw new Error('Sonuç alınamadı.');
                } else {
                  showResults(await resultRes.json());
                }
              } else if (msg.startsWith('__PROGRESS__:')) {
                const pct = msg.split(':')[1];
                document.getElementById('progressFill').style.width = pct + '%';
              } else {
                document.getElementById('spinnerSub').textContent = '// ' + msg;
              }
            }
          } catch (e) {
            console.error('Polling hatası:', e);
            clearInterval(pollInterval);
            document.getElementById('spinnerText').textContent = 'Tarama Başarısız';
            document.getElementById('spinnerSub').textContent = '// ' + e.message;
            document.getElementById('progressFill').style.background = '#a51c1c';
          } finally {
            polling = false;
          }
        }, 500);

      } catch (err) {
        alert('Hata: ' + err.message);
        document.getElementById('btnScan').disabled = false;
        document.getElementById('mainContent').style.display = 'flex';
        document.getElementById('bentoGrid').style.display = 'grid';
        document.getElementById('progressSection').style.display = 'none';
      }
    }

    /* ── Cancel Scan ── */
    async function cancelCurrentScan() {
      if (currentScanId) {
        try { await scanFetch('/api/cancel/' + currentScanId, { method: 'POST' }); } catch(e) {}
      }
      location.reload();
    }

    /* ── Show Results ── */
    function showResults(result) {
      document.getElementById('btnScan').disabled = false;
      lastScanResult = result;
      document.getElementById('progressSection').style.display = 'none';
      document.getElementById('resultsSection').style.display = 'flex';
      document.getElementById('bentoGrid').style.display = 'none';

      const { findings = [], counts = {}, score = null } = result;
      const complete = result.status === 'completed';
      const statusLabels = {error: 'Tarama başarısız', cancelled: 'Tarama iptal edildi', timeout: 'Tarama zaman aşımına uğradı'};
      const statusLabel = statusLabels[result.status] || 'Tarama tamamlanmadı';

      document.getElementById('resultUrlLabel').textContent = scannedUrl;

      document.getElementById('summaryGrid').innerHTML = `
        <div class="bg-surface-container-lowest rounded-lg p-6 ambient-shadow text-center fade-in-up" style="animation-delay:0s">
          <span class="font-headline text-3xl font-bold tracking-tighter text-sev-high">${counts.HIGH || 0}</span>
          <p class="font-label text-[0.6875rem] uppercase tracking-widest text-on-surface-variant mt-2">YÜKSEK</p>
        </div>
        <div class="bg-surface-container-lowest rounded-lg p-6 ambient-shadow text-center fade-in-up" style="animation-delay:0.05s">
          <span class="font-headline text-3xl font-bold tracking-tighter text-sev-medium">${counts.MEDIUM || 0}</span>
          <p class="font-label text-[0.6875rem] uppercase tracking-widest text-on-surface-variant mt-2">ORTA</p>
        </div>
        <div class="bg-surface-container-lowest rounded-lg p-6 ambient-shadow text-center fade-in-up" style="animation-delay:0.1s">
          <span class="font-headline text-3xl font-bold tracking-tighter text-sev-low">${counts.LOW || 0}</span>
          <p class="font-label text-[0.6875rem] uppercase tracking-widest text-on-surface-variant mt-2">DÜŞÜK</p>
        </div>
        <div class="bg-primary rounded-lg p-6 shadow-lg text-center fade-in-up" style="animation-delay:0.15s">
          <span class="font-headline text-3xl font-bold tracking-tighter text-on-primary">${complete && score !== null ? score : '—'}</span>
          <p class="font-label text-[0.6875rem] uppercase tracking-widest text-on-primary/70 mt-2">ÖN KONTROL PUANI</p>
        </div>`;

      const checks = Array.isArray(result.checks) ? result.checks : [];
      const observations = Array.isArray(result.observations) ? result.observations : [];
      document.getElementById('scanNotes').innerHTML =
        `<p>Puan, seçili kontrollerdeki bulguların özetidir; güvenlik garantisi değildir.</p>` +
        (checks.length ? `<p>Tamamlanan kontrol: ${checks.filter(c => c.status === 'completed').length} / ${checks.length}</p>` : '') +
        checks.filter(c => c.status !== 'completed').map(c => `<p class="text-sev-high">${escapeHTML(c.module)}: ${escapeHTML(c.detail || 'Çalıştırılmadı')}</p>`).join('') +
        observations.map(o => `<p><strong>${escapeHTML(o.module)}:</strong> ${escapeHTML(o.detail)}</p>`).join('');
      const list = document.getElementById('findingsList');
      const incompleteNotice = complete ? '' : `<div class="p-5 text-sev-high font-bold">${escapeHTML(statusLabel)}. Güvenlik skoru hesaplanmadı; bulgular eksik olabilir.</div>`;
      if (!complete && findings.length === 0) {
        list.innerHTML = incompleteNotice;
        return;
      }
      if (findings.length === 0) {
        list.innerHTML = `
          <div class="bg-surface-container-lowest rounded-lg p-8 ambient-shadow text-center fade-in-up">
            <span class="material-symbols-outlined text-4xl text-sev-pass mb-3 block" style="font-variation-settings: 'FILL' 1;">verified</span>
            <p class="font-headline text-lg font-bold text-sev-pass">Açık bulunamadı</p>
            <p class="font-body text-sm text-on-surface-variant mt-1">Seçilen kontrollerde bulgu tespit edilmedi; bu sonuç güvenlik garantisi değildir.</p>
          </div>`;
        return;
      }

      const sevOrder = { HIGH: 0, MEDIUM: 1, LOW: 2 };
      const sorted = [...findings].sort((a, b) => (sevOrder[a.severity] ?? 3) - (sevOrder[b.severity] ?? 3));

      list.innerHTML = incompleteNotice + sorted.map((f, i) => {
        const sev = (f.severity || 'low').toLowerCase();
        const sevColors = {
          high: 'bg-sev-high-bg text-sev-high border-sev-high/20',
          medium: 'bg-sev-medium-bg text-sev-medium border-sev-medium/20',
          low: 'bg-sev-low-bg text-sev-low border-sev-low/20',
        };
        const dotColors = { high: 'bg-sev-high', medium: 'bg-sev-medium', low: 'bg-sev-low' };
        return `
          <div class="finding-card bg-surface-container-lowest rounded-lg ambient-shadow overflow-hidden fade-in-up" style="animation-delay:${0.05 * i}s">
            <div class="finding-header flex items-center gap-4 p-5 cursor-pointer select-none hover:bg-surface-container-low transition-colors"
>
              <div class="w-2 h-2 rounded-full flex-shrink-0 ${dotColors[sev] || 'bg-outline'}"></div>
              <span class="font-body text-sm font-semibold flex-1">${escapeHTML(f.title)}</span>
              <span class="font-label text-[0.6875rem] font-bold uppercase tracking-wider px-3 py-1 rounded-sm border ${sevColors[sev] || ''}">${escapeHTML(f.severity)}</span>
              <span class="material-symbols-outlined text-on-surface-variant finding-chevron">expand_more</span>
            </div>
            <div class="finding-body border-t border-surface-container-low">
              <div class="p-5">
                <div class="bg-surface rounded-lg p-4 mb-4">
                  <p class="font-label text-xs uppercase tracking-widest text-on-surface-variant mb-2">DETAY</p>
                  <p class="font-body text-sm text-on-surface leading-relaxed">${escapeHTML(f.detail)}</p><p class="text-xs mt-2">Kanıt türü: ${escapeHTML(({differential: "Karşılaştırmalı yanıt", contextual: "HTML bağlamı", heuristic: "Sezgisel kontrol"})[f.confidence] || "Sezgisel kontrol")}</p>
                </div>
                <div>
                  <p class="font-label text-xs uppercase tracking-widest text-on-surface-variant mb-2">ÇÖZÜM ÖNERİSİ</p>
                  <p class="font-body text-sm text-on-surface-variant leading-relaxed">${escapeHTML(f.fix)}</p>
                </div>
              </div>
            </div>
          </div>`;
      }).join('');
    }

    /* ─── End of page logic ─── */
