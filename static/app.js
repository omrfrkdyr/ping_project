/* ═══════════════════════════════════════════════════
   AntiGravity — app.js
   Vanilla JS: API calls, SSE, device cards, animations
   ═══════════════════════════════════════════════════ */

'use strict';

// ─── Toast Notification System ──────────────────────────────────────
function showToast(msg, type = 'info', duration = 3500) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.style.cssText = 'position:fixed;top:70px;right:20px;z-index:999;display:flex;flex-direction:column;gap:8px;pointer-events:none;';
    document.body.appendChild(container);
  }
  const toast = document.createElement('div');
  const colors = { info: '#00d4ff', error: '#f85149', success: '#3fb950', warn: '#d29922' };
  const borderColor = colors[type] || colors.info;
  toast.style.cssText = `
    padding:10px 18px; border-radius:8px; font-size:12px; font-family:'Inter',sans-serif;
    background:rgba(22,27,34,0.95); color:#e6edf3; border:1px solid ${borderColor};
    backdrop-filter:blur(12px); pointer-events:auto; max-width:340px;
    animation:toast-in .25s ease; box-shadow:0 4px 24px rgba(0,0,0,.5);
  `;
  toast.textContent = msg;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    toast.style.transition = 'all .25s ease';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// Toast animasyonu için CSS inject
(function() {
  const style = document.createElement('style');
  style.textContent = '@keyframes toast-in { from{opacity:0;transform:translateX(20px)} to{opacity:1;transform:none} }';
  document.head.appendChild(style);
})();

// ─── State ──────────────────────────────────────────────────────────
let currentMode  = 'basic';
let scanInterval = null;
let gatewayIp    = null;
let _patchTimer  = null;    // isim-polling timer
let _patchStopAt = 0;       // durdurma zamanı (ms)
let _knownNames  = {};      // {ip: friendly_name} — değişimi algılamak için

const DEVICE_ICONS = {
  phone:   '📱',
  laptop:  '💻',
  router:  '🌐',
  tv:      '📺',
  iot:     '⚡',
  unknown: '📡',
};

const BADGE_CLASS = {
  phone:   'badge-phone',
  laptop:  'badge-laptop',
  router:  'badge-router',
  tv:      'badge-tv',
  iot:     'badge-iot',
  unknown: 'badge-unknown',
};

// ─── Mode Switch ─────────────────────────────────────────────────────
function setMode(mode) {
  currentMode = mode;
  document.querySelectorAll('.mode-tab').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + mode).classList.add('active');
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById('view-' + mode).classList.add('active');

  if (mode === 'expert') {
    loadStatus();
    loadCache();
  }
}

// ─── Status Bar ──────────────────────────────────────────────────────
async function loadStatus() {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    gatewayIp = d.gateway_ip;

    const pill  = document.getElementById('status-pill');
    const dot   = pill.querySelector('.dot');
    const text  = document.getElementById('status-text');
    const ipInfo = document.getElementById('ip-info');

    ipInfo.textContent = `${d.local_ip} | ${d.local_v6 && d.local_v6.length > 20 ? d.local_v6.slice(0,20)+'…' : (d.local_v6||'—')}`;

    const isolated = d.isolated || [];
    if (isolated.length > 0) {
      dot.className = 'dot red';
      text.textContent = `${isolated.length} cihaz izole`;
      document.getElementById('isolation-bar').style.display = 'flex';
      document.getElementById('iso-count').textContent = `${isolated.length} cihaz izole edildi`;
      document.getElementById('restore-all-btn').style.display = 'inline-flex';
    } else {
      dot.className = 'dot green';
      text.textContent = 'Hazır';
      document.getElementById('isolation-bar').style.display = 'none';
      document.getElementById('restore-all-btn').style.display = 'none';
    }

    // Expert status
    const body = document.getElementById('expert-status-body');
    if (body) {
      body.innerHTML = `
        <div class="status-row"><span>Yerel IPv4</span><span>${escHtml(d.local_ip)}</span></div>
        <div class="status-row"><span>Yerel IPv6</span><span style="font-size:10px">${escHtml(d.local_v6||'—')}</span></div>
        <div class="status-row"><span>Gateway</span><span>${escHtml(d.gateway_ip||'—')}</span></div>
        <div class="status-row"><span>Keşfedilen Cihaz</span><span>${escHtml(String(d.device_count))}</span></div>
        <div class="status-row"><span>Aktif İzolasyon</span><span style="color:${isolated.length?'var(--red)':'var(--green)'}">${escHtml(String(isolated.length))}</span></div>
        <div class="status-row"><span>Flow Control</span><span style="color:${d.flow_active?'var(--cyan)':'var(--fg3)'}">${d.flow_active ? escHtml(d.flow_mode.toUpperCase()) : 'Kapalı'}</span></div>
      `;
    }
  } catch (e) {
    showToast('Durum bilgisi alınamadı.', 'warn');
  }
}

// ─── Neighbor Cache ───────────────────────────────────────────────────
async function loadCache() {
  try {
    const r = await fetch('/api/neighbor-cache');
    const d = await r.json();
    const el = document.getElementById('cache-output');
    if (el) el.textContent = d.lines ? d.lines.join('\n') : 'Veri yok.';
  } catch (e) {
    showToast('Neighbor cache alınamadı.', 'warn');
  }
}

// ─── Scan ─────────────────────────────────────────────────────────────
async function startScan() {
  const btn   = document.getElementById('scan-btn');
  const net   = document.getElementById('network-input').value.trim() || null;
  const wrap  = document.getElementById('progress-wrap');
  const bar   = document.getElementById('progress-bar');
  const label = document.getElementById('progress-label');
  const sub   = document.getElementById('scan-sub');

  btn.disabled = true;
  btn.innerHTML = '<span class="btn-icon">⟳</span> Taranıyor...';
  wrap.style.display = 'block';
  bar.style.width = '5%';
  label.textContent = 'Tarama başlatılıyor...';

  try {
    await fetch('/api/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ network: net, timeout: 3 })
    });
  } catch (e) {
    showToast('Tarama başlatılamadı. Sunucu bağlantısını kontrol edin.', 'error');
    btn.disabled = false;
    btn.innerHTML = '<span class="btn-icon">⊕</span> Ağı Tara';
    wrap.style.display = 'none';
    return;
  }

  // Poll scan progress
  if (scanInterval) clearInterval(scanInterval);
  scanInterval = setInterval(async () => {
    try {
      const r = await fetch('/api/scan/status');
      const d = await r.json();
      bar.style.width  = d.progress + '%';
      label.textContent = `Taranıyor... ${d.count} cihaz`;

      if (!d.scanning) {
        clearInterval(scanInterval);
        btn.disabled = false;
        btn.innerHTML = '<span class="btn-icon">⊕</span> Yeniden Tara';
        wrap.style.display = 'none';
        sub.textContent = `Son tarama: ${d.count} cihaz bulundu.`;
        await renderDevices();
        loadStatus();
      }
    } catch (e) {
      showToast('Tarama durumu alınamadı.', 'warn');
    }
  }, 600);
}

// ─── Device Cards ─────────────────────────────────────────────────────
async function renderDevices() {
  try {
    const r = await fetch('/api/devices');
    const devices = await r.json();
    const grid = document.getElementById('devices-grid');

    if (!devices.length) {
      grid.innerHTML = `<div class="empty-state" id="empty-state">
        <div class="empty-icon">⬡</div>
        <p>Cihaz bulunamadı. Tekrar tarayın.</p></div>`;
      return;
    }

    // Her render'da isim hafizasını sıfırla (yeni tarama sonrası)
    _knownNames = {};
    grid.innerHTML = '';
    devices.forEach((dev, i) => {
      // Mevcut isimleri hafizaya al
      _knownNames[dev.ip] = dev.friendly_name || '';
      const card = buildDeviceCard(dev, i);
      grid.appendChild(card);
    });

    loadStatus();
    // Sniffer'dan gelen yeni isimler için polling başlat
    startNamePolling();
  } catch (e) {
    showToast('Cihaz listesi alınamadı.', 'error');
  }
}

function buildDeviceCard(dev, index) {
  const isGateway  = dev.ip === gatewayIp;
  const icon       = DEVICE_ICONS[dev.type] || '📡';
  const badgeClass = BADGE_CLASS[dev.type]  || 'badge-unknown';
  const card       = document.createElement('div');

  card.className   = 'device-card' + (dev.isolated ? ' isolated' : '');
  card.id          = 'card-' + dev.ip.replace(/\./g, '-');
  card.style.animationDelay = (index * 40) + 'ms';

  let btnHtml;
  if (isGateway) {
    btnHtml = `<button class="isolate-btn gateway" disabled>🌐 Gateway</button>`;
  } else if (dev.isolated) {
    btnHtml = `<div class="pkt-counter" style="display:block" id="pkt-${dev.ip.replace(/\./g,'-')}">
                 ● ${dev.pkt_count || 0} paket gönderildi
               </div>
               <button class="isolate-btn restore" onclick="restoreDevice('${dev.ip}', this)">
                 ✓ Bağlantıyı Geri Ver
               </button>`;
  } else {
    btnHtml = `<button class="isolate-btn cut" onclick="isolateDevice('${dev.ip}','${dev.mac}',this)" aria-label="${escHtml(dev.ip)} cihazının internetini kes">
                 ■ İnterneti Kes
               </button>`;
  }

  // Monitör butonu (gateway değilse, asla 'Bilinmiyor' etiketi kullanma)
  const cardLabel = dev.friendly_name || (dev.vendor && dev.vendor !== 'Bilinmiyor' ? dev.vendor : '') || dev.ip;
  const monitorBtn = !isGateway
    ? `<button class="monitor-btn" id="monbtn-${dev.ip.replace(/\./g,'-')}" onclick="startMonitor('${dev.ip}','${escHtml(cardLabel)}')" aria-label="${escHtml(cardLabel)} cihazını izle">👁 Monitör Et</button>`
    : '';

  // ── Katman 1: Cihaz Adı (friendly_name > vendor > type) ──
  const deviceName = dev.friendly_name
    ? escHtml(dev.friendly_name)
    : (dev.vendor && dev.vendor !== 'Bilinmiyor' ? escHtml(dev.vendor) : '');

  // ── Katman 2: Sahip Adı ──
  const ownerLine = dev.owner_name
    ? `<div class="device-owner-name"><span class="owner-avatar">👤</span>${escHtml(dev.owner_name)}</div>`
    : '';

  // ── Fallback: ham hostname (sadece friendly_name yoksa) ──
  const hostnameHint = (!dev.friendly_name && dev.hostname && dev.hostname !== dev.ip && dev.hostname !== 'N/A')
    ? `<div class="device-hostname">${escHtml(dev.hostname)}</div>`
    : '';

  card.innerHTML = `
    <div class="device-type-badge ${badgeClass}">${dev.vendor || dev.type}</div>
    <div class="device-icon">${icon}</div>
    ${deviceName ? `<div class="device-name-label">${deviceName}</div>` : ''}
    ${ownerLine}
    <div class="device-ip">${dev.ip}</div>
    <div class="device-mac">${dev.mac}</div>
    ${hostnameHint}
    ${btnHtml}
    ${monitorBtn}
  `;
  return card;
}

// ─── Isolate / Restore ────────────────────────────────────────────────
async function isolateDevice(ip, mac, btn) {
  btn.className = 'isolate-btn loading';
  btn.textContent = '⟳ İzole ediliyor...';

  try {
    await fetch('/api/isolate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ ip, mac })
    });

    // 1.5s sonra kartı güncelle (arka planda işlem devam ediyor)
    setTimeout(renderDevices, 1500);
    setTimeout(loadStatus, 1600);
  } catch (e) {
    btn.className = 'isolate-btn cut';
    btn.textContent = '■ İnterneti Kes';
  }
}

async function restoreDevice(ip, btn) {
  btn.className = 'isolate-btn loading';
  btn.textContent = '⟳ Onarılıyor...';

  try {
    await fetch('/api/restore', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ ip })
    });
    setTimeout(renderDevices, 1500);
    setTimeout(loadStatus, 1600);
  } catch (e) {
    btn.className = 'isolate-btn restore';
    btn.textContent = '✓ Bağlantıyı Geri Ver';
  }
}

async function restoreAll() {
  try {
    await fetch('/api/restore-all', { method: 'POST' });
    setTimeout(renderDevices, 1500);
    setTimeout(loadStatus, 1600);
  } catch (e) {}
}

// ─── Expert Actions ───────────────────────────────────────────────────
async function expertArpStart() {
  const target = document.getElementById('ex-arp-target').value.trim();
  const gw     = document.getElementById('ex-arp-gw').value.trim();
  const fwd    = document.getElementById('ex-fwd').checked;
  const st     = document.getElementById('arp-status');

  if (!target || !gw) { setStatus(st, 'Hedef ve Gateway IP gerekli!', 'error'); return; }
  setStatus(st, 'Başlatılıyor...', '');

  const r = await api('/api/expert/arp-start', { target_ip: target, gateway_ip: gw, forwarding: fwd });
  setStatus(st, r.ok ? `AKTİF → ${target}` : (r.error || 'Hata'), r.ok ? 'active' : 'error');
}

async function expertArpStop() {
  const target = document.getElementById('ex-arp-target').value.trim();
  const st     = document.getElementById('arp-status');
  const r      = await api('/api/expert/arp-stop', { target_ip: target });
  setStatus(st, r.ok ? 'Durduruldu + ARP Onarıldı.' : (r.error || 'Hata'), r.ok ? 'ok' : 'error');
}

async function expertNdpStart() {
  const t6   = document.getElementById('ex-ndp-target').value.trim();
  const r6   = document.getElementById('ex-ndp-router').value.trim();
  const tmac = document.getElementById('ex-ndp-tmac').value.trim();
  const st   = document.getElementById('ndp-status');

  if (!t6 || !r6) { setStatus(st, 'Hedef ve Router IPv6 gerekli!', 'error'); return; }
  setStatus(st, 'Başlatılıyor...', '');

  const r = await api('/api/expert/ndp-start', { target_v6: t6, router_v6: r6, target_mac: tmac || null });
  setStatus(st, r.ok ? `AKTİF → ${t6.slice(0,24)}` : (r.error || 'Hata'), r.ok ? 'active' : 'error');
}

async function expertNdpStop() {
  const t6 = document.getElementById('ex-ndp-target').value.trim();
  const st = document.getElementById('ndp-status');
  const r  = await api('/api/expert/ndp-stop', { target_v6: t6 });
  setStatus(st, r.ok ? 'Durduruldu + Cache Onarıldı.' : (r.error || 'Hata'), r.ok ? 'ok' : 'error');
}

async function expertFlowStart() {
  const mode = document.querySelector('input[name="flow-mode"]:checked')?.value || 'FORWARD';
  const bpf  = document.getElementById('ex-bpf').value.trim();
  const kbps = parseFloat(document.getElementById('ex-kbps').value) || 512;
  const st   = document.getElementById('flow-status');

  setStatus(st, 'Başlatılıyor...', '');
  const r = await api('/api/expert/flow-start', { mode, bpf: bpf || '', kbps });
  setStatus(st, r.ok ? `AKTİF (${mode})` : (r.error || 'Hata'), r.ok ? 'active' : 'error');
}

async function expertFlowStop() {
  const st = document.getElementById('flow-status');
  const r  = await api('/api/expert/flow-stop', {});
  setStatus(st, r.ok ? 'Durduruldu.' : (r.error || 'Hata'), r.ok ? 'ok' : 'error');
}

async function convMac() {
  const mac = document.getElementById('ex-mac-conv').value.trim();
  if (!mac) return;
  const r   = await fetch(`/api/mac-to-ipv6?mac=${encodeURIComponent(mac)}`);
  const d   = await r.json();
  document.getElementById('mac-conv-result').textContent = `EUI-64: ${d.ipv6}`;

  // Otomatik doldur
  document.getElementById('ex-ndp-target').value = d.ipv6;
}

// ─── Log ────────────────────────────────────────────────────────────
let logOpen = false;

function toggleLog() {
  const tray = document.getElementById('log-tray');
  logOpen = !logOpen;
  if (logOpen) {
    tray.classList.add('open');
  } else {
    tray.classList.remove('open');
    tray.style.display = 'none';
    setTimeout(() => {
      if (!logOpen) tray.style.display = '';
    }, 300);
  }
}

function clearLog() {
  document.getElementById('basic-log').innerHTML   = '';
  document.getElementById('expert-log').innerHTML  = '';
}

function appendLog(entry) {
  if (entry.level === 'ping') return;
  const line = document.createElement('div');
  line.className = `log-line ${entry.level}`;
  line.innerHTML = `<span class="log-ts">${entry.ts}</span><span class="log-msg">${escHtml(entry.msg)}</span>`;

  ['basic-log', 'expert-log'].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    const clone = line.cloneNode(true);
    el.appendChild(clone);
    el.scrollTop = el.scrollHeight;
    // Max 200 satır
    while (el.children.length > 200) el.removeChild(el.firstChild);
  });
}

// ─── SSE ─────────────────────────────────────────────────────────────
let _mainSSE = null;

function connectSSE() {
  if (_mainSSE) {
    try { _mainSSE.close(); } catch (_) {}
    _mainSSE = null;
  }
  const es = new EventSource('/api/stream');
  _mainSSE = es;

  es.onmessage = e => {
    try {
      const entry = JSON.parse(e.data);
      appendLog(entry);
    } catch (_) {}
  };

  es.onerror = () => {
    // Sadece bağlantı tamamen kapandıysa yeniden oluştur, açık/bağlanıyor durumunda tarayıcı zaten dener
    if (es.readyState === EventSource.CLOSED) {
      setTimeout(() => {
        if (_mainSSE === es) connectSSE();
      }, 3000);
    }
  };
}

// ─── Akıllı Kart Güncelleme (İsimler gelince anlık yazar) ────────────────
// Pasif sniffer arka planda isim buldukça bu fonksiyon kart DOM'unu
// tam yeniden render etmeden sadece değişen alanları günceller.

function _patchDeviceCards(devs) {
  devs.forEach(dev => {
    const cardId = 'card-' + dev.ip.replace(/\./g, '-');
    const card   = document.getElementById(cardId);
    if (!card) return;

    // ── Paket sayacı (izole cihazlar) ──────────────────────────────
    if (dev.isolated) {
      const pktEl = document.getElementById('pkt-' + dev.ip.replace(/\./g, '-'));
      if (pktEl) pktEl.textContent = `● ${dev.pkt_count || 0} paket gönderildi`;
    }

    // ── İsim veya vendor değişti mi? ──────────────────────────────
    const prevName   = _knownNames[dev.ip] || '';
    const newName    = dev.friendly_name || '';
    const badgeEl    = card.querySelector('.device-type-badge');
    const badgeText  = badgeEl ? badgeEl.textContent.trim() : '';
    const vendorDiff = dev.vendor && dev.vendor !== badgeText;

    if (newName === prevName && !vendorDiff) return;
    _knownNames[dev.ip] = newName;

    // ── Badge (vendor etiketi) ───────────────────────────────────────
    const badge = card.querySelector('.device-type-badge');
    if (badge && dev.vendor && dev.vendor !== 'Bilinmiyor') {
      badge.textContent = dev.vendor;
      // Yeni badge sınıfı
      const BADGE_MAP = {phone:'badge-phone', laptop:'badge-laptop', router:'badge-router',
                         tv:'badge-tv', iot:'badge-iot', unknown:'badge-unknown'};
      badge.className = 'device-type-badge ' + (BADGE_MAP[dev.type] || 'badge-unknown');
    }

    // ── Cihaz ikonu ─────────────────────────────────────────────────
    const iconEl = card.querySelector('.device-icon');
    if (iconEl) {
      const ICONS = {phone:'📱', laptop:'💻', router:'🌐', tv:'📺', iot:'⚡', unknown:'📡'};
      iconEl.textContent = ICONS[dev.type] || '📡';
    }

    // ── Cihaz adı (device-name-label) ──────────────────────────────
    let nameEl = card.querySelector('.device-name-label');
    const displayName = dev.friendly_name
      ? escHtml(dev.friendly_name)
      : (dev.vendor && dev.vendor !== 'Bilinmiyor' ? escHtml(dev.vendor) : '');

    if (displayName) {
      if (!nameEl) {
        // Yeni element oluştur — ikonun hemen altına ekle
        nameEl = document.createElement('div');
        nameEl.className = 'device-name-label name-reveal';
        const icon = card.querySelector('.device-icon');
        if (icon && icon.nextSibling) {
          card.insertBefore(nameEl, icon.nextSibling);
        } else {
          card.appendChild(nameEl);
        }
      }
      if (nameEl.innerHTML !== displayName) {
        nameEl.innerHTML = displayName;
        nameEl.classList.add('name-reveal');
        setTimeout(() => nameEl.classList.remove('name-reveal'), 800);
      }
    }

    // ── Sahip adı (device-owner-name) ───────────────────────────────
    let ownerEl = card.querySelector('.device-owner-name');
    if (dev.owner_name) {
      if (!ownerEl) {
        ownerEl = document.createElement('div');
        ownerEl.className = 'device-owner-name name-reveal';
        const ipEl = card.querySelector('.device-ip');
        if (ipEl) card.insertBefore(ownerEl, ipEl);
        else card.appendChild(ownerEl);
      }
      const ownerHtml = `<span class="owner-avatar">👤</span>${escHtml(dev.owner_name)}`;
      if (ownerEl.innerHTML !== ownerHtml) {
        ownerEl.innerHTML = ownerHtml;
        ownerEl.classList.add('name-reveal');
        setTimeout(() => ownerEl.classList.remove('name-reveal'), 800);
      }
    }

    // ── Monitör butonunu ve açık paneli güncelle ───────────────────
    const monBtn = card.querySelector('.monitor-btn');
    const bestName = dev.friendly_name || (dev.vendor && dev.vendor !== 'Bilinmiyor' ? dev.vendor : '') || dev.ip;
    if (monBtn) {
      monBtn.setAttribute('onclick', `startMonitor('${dev.ip}','${escHtml(bestName)}')`);
      monBtn.setAttribute('aria-label', `${escHtml(bestName)} cihazını izle`);
    }

    if (_monitorIp === dev.ip) {
      const titleEl = document.getElementById('monitor-title');
      if (titleEl && bestName && bestName !== 'Bilinmiyor') {
        titleEl.textContent = bestName;
      }
    }
  });
}

function startNamePolling() {
  if (_patchTimer) clearInterval(_patchTimer);
  _patchStopAt = Date.now() + 10 * 60 * 1000;  // 10 dakika
  // Yenile butonunu gizle (polling aktif)
  const refreshBtn = document.getElementById('refresh-names-btn');
  if (refreshBtn) refreshBtn.style.display = 'none';

  _patchTimer  = setInterval(async () => {
    try {
      const r    = await fetch('/api/devices');
      const devs = await r.json();
      _patchDeviceCards(devs);
      if (Date.now() > _patchStopAt) {
        clearInterval(_patchTimer);
        _patchTimer = null;
        // Yenile butonunu göster
        if (refreshBtn) refreshBtn.style.display = 'inline-flex';
        showToast('İsim arama tamamlandı. Yenilemek için butona tıklayın.', 'info');
      }
    } catch (_) {}
  }, 3000);  // 3 saniye aralık
}

async function refreshNames() {
  const btn = document.getElementById('refresh-names-btn');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '⟳ Yenileniyor...';
  }

  try {
    const r = await fetch('/api/refresh-names', { method: 'POST' });
    const d = await r.json();
    if (d.ok) {
      showToast(`${d.count} cihaz için isim arama yeniden başlatıldı.`, 'success');
      startNamePolling();
    } else {
      showToast(d.error || 'İsim yenileme başarısız.', 'error');
    }
  } catch (e) {
    showToast('Sunucuya bağlanılamadı.', 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '⟳ İsimleri Yenile';
    }
  }
}

// ─── Background Canvas ────────────────────────────────────────────────
function initCanvas() {
  const canvas = document.getElementById('bg-canvas');
  const ctx    = canvas.getContext('2d');
  let W, H, nodes = [];

  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }

  function makeNodes() {
    nodes = Array.from({length: 40}, () => ({
      x:  Math.random() * W,
      y:  Math.random() * H,
      vx: (Math.random() - .5) * .4,
      vy: (Math.random() - .5) * .4,
      r:  Math.random() * 2 + 1,
    }));
  }

  function animate() {
    ctx.clearRect(0, 0, W, H);

    nodes.forEach(n => {
      n.x += n.vx; n.y += n.vy;
      if (n.x < 0 || n.x > W) n.vx *= -1;
      if (n.y < 0 || n.y > H) n.vy *= -1;

      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(0,212,255,.5)';
      ctx.fill();
    });

    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const d  = Math.sqrt(dx*dx + dy*dy);
        if (d < 130) {
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(nodes[j].x, nodes[j].y);
          ctx.strokeStyle = `rgba(0,212,255,${(1 - d/130) * .15})`;
          ctx.lineWidth = .6;
          ctx.stroke();
        }
      }
    }

    requestAnimationFrame(animate);
  }

  resize();
  makeNodes();
  animate();
  window.addEventListener('resize', () => { resize(); makeNodes(); });
}

// ─── Website Monitor Panel ───────────────────────────────────────────
let _monitorIp     = null;   // Şu an izlenen IP
let _monitorSSE    = null;   // EventSource
let _monDnsCount   = 0;
let _monHttpsCount = 0;
let _monTotal      = 0;

function getBestDeviceLabel(ip, fallbackLabel) {
  // 1. Parametre olarak gelen ve 'Bilinmiyor' olmayan isim
  if (fallbackLabel && fallbackLabel !== 'Bilinmiyor' && fallbackLabel !== ip) {
    return fallbackLabel;
  }
  // 2. Hafızadaki en güncel friendly_name
  if (_knownNames[ip] && _knownNames[ip] !== 'Bilinmiyor') {
    return _knownNames[ip];
  }
  // 3. DOM kartındaki güncel etiketler
  const card = document.getElementById('card-' + ip.replace(/\./g, '-'));
  if (card) {
    const nameEl = card.querySelector('.device-name-label');
    if (nameEl && nameEl.textContent.trim() && nameEl.textContent.trim() !== 'Bilinmiyor') {
      return nameEl.textContent.trim();
    }
    const ownerEl = card.querySelector('.device-owner-name');
    if (ownerEl && ownerEl.textContent.trim()) {
      return ownerEl.textContent.replace('👤', '').trim();
    }
    const badgeEl = card.querySelector('.device-type-badge');
    if (badgeEl && badgeEl.textContent.trim() && badgeEl.textContent.trim() !== 'Bilinmiyor') {
      return badgeEl.textContent.trim();
    }
  }
  // 4. Eğer fallbackLabel en azından boş veya Bilinmiyor değilse
  if (fallbackLabel && fallbackLabel !== 'Bilinmiyor') {
    return fallbackLabel;
  }
  // 5. Son çare IP adresi
  return ip;
}

async function startMonitor(ip, label) {
  // Zaten açıksa kapat
  if (_monitorIp && _monitorIp !== ip) {
    await stopMonitor(false);
  }
  _monitorIp = ip;

  // İstatistikleri sıfırla
  _monDnsCount = _monHttpsCount = _monTotal = 0;
  _updateMonStats();

  // Panel başlığını en güncel cihaz adıyla belirle (asla 'Bilinmiyor' göstermez)
  const displayTitle = getBestDeviceLabel(ip, label);
  document.getElementById('monitor-title').textContent    = displayTitle;
  document.getElementById('monitor-subtitle').textContent = ip;
  document.getElementById('monitor-empty').style.display  = 'flex';
  document.getElementById('mon-live-dot').className       = 'monitor-live-dot blink';
  document.getElementById('mon-live-txt').textContent     = 'Başlatılıyor...';

  // Domain listesini temizle (eski cihazın verilerini sil)
  _clearMonitorEntries();

  // Paneli aç
  document.getElementById('monitor-panel').classList.add('open');
  document.getElementById('monitor-overlay').classList.add('open');

  // Backend'de monitor'ü başlat
  try {
    await fetch('/api/monitor/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });
  } catch (e) {
    showToast('Monitor başlatılamadı.', 'error');
  }

  // SSE bağlantısı kur
  _connectMonitorSSE(ip);
}

function _connectMonitorSSE(ip) {
  if (_monitorSSE) _monitorSSE.close();

  _monitorSSE = new EventSource(`/api/monitor/stream/${ip}`);

  _monitorSSE.onopen = () => {
    document.getElementById('mon-live-dot').className = 'monitor-live-dot active';
    document.getElementById('mon-live-txt').textContent = 'Aktif — İzleniyor';
  };

  _monitorSSE.onmessage = e => {
    try {
      const data = JSON.parse(e.data);
      if (data.type === 'ping') return;
      if (data.type === 'stopped') {
        document.getElementById('mon-live-dot').className = 'monitor-live-dot';
        document.getElementById('mon-live-txt').textContent = 'Durduruldu';
        _monitorSSE.close();
        return;
      }
      _addMonitorEntry(data);
    } catch (_) {}
  };

  _monitorSSE.onerror = () => {
    document.getElementById('mon-live-dot').className = 'monitor-live-dot error';
    document.getElementById('mon-live-txt').textContent = 'Bağlantı kesildi';
    setTimeout(() => {
      if (_monitorIp === ip) _connectMonitorSSE(ip);
    }, 3000);
  };
}

function _addMonitorEntry(entry) {
  const list    = document.getElementById('monitor-list');
  const emptyEl = document.getElementById('monitor-empty');

  // İlk giriş gelince empty state'i gizle
  emptyEl.style.display = 'none';

  // Sayaçlar
  _monTotal++;
  if (entry.proto === 'DNS')   _monDnsCount++;
  if (entry.proto === 'HTTPS') _monHttpsCount++;
  _updateMonStats();

  const isHttps = entry.proto === 'HTTPS';
  const el      = document.createElement('div');
  el.className  = 'monitor-entry monitor-entry-new';
  el.innerHTML  = `
    <span class="mon-proto ${isHttps ? 'https' : 'dns'}">${entry.proto}</span>
    <span class="mon-domain">${escHtml(entry.domain)}</span>
    <span class="mon-ts">${escHtml(entry.ts)}</span>
  `;

  // Yeni girişler en üste
  list.insertBefore(el, emptyEl.nextSibling);

  // Max 200 satır
  const entries = list.querySelectorAll('.monitor-entry');
  if (entries.length > 200) entries[entries.length - 1].remove();

  // Animasyon sonrası sınıfı kaldır
  setTimeout(() => el.classList.remove('monitor-entry-new'), 600);
}

function _updateMonStats() {
  document.getElementById('mon-count').textContent       = _monTotal;
  document.getElementById('mon-dns-count').textContent   = _monDnsCount;
  document.getElementById('mon-https-count').textContent = _monHttpsCount;
}

function _clearMonitorEntries() {
  const list    = document.getElementById('monitor-list');
  const entries = list.querySelectorAll('.monitor-entry');
  entries.forEach(e => e.remove());
}

function clearMonitorList() {
  _clearMonitorEntries();
  _monDnsCount = _monHttpsCount = _monTotal = 0;
  _updateMonStats();
  document.getElementById('monitor-empty').style.display = 'flex';
}

function copyMonitorList() {
  const entries = document.querySelectorAll('.monitor-entry .mon-domain');
  const text    = Array.from(entries).map(e => e.textContent).join('\n');
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.querySelector('.monitor-tool-btn[onclick*="copy"]');
    if (btn) { btn.textContent = '✓ Kopyalandı!'; setTimeout(() => btn.textContent = '📋 Kopyala', 1500); }
  }).catch(() => {});
}

async function stopMonitor(closePanelToo = true) {
  const ip = _monitorIp;
  if (!ip) return;

  if (_monitorSSE) { _monitorSSE.close(); _monitorSSE = null; }
  _monitorIp = null;

  try {
    await fetch('/api/monitor/stop', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });
  } catch (e) {
    showToast('Monitor durdurulurken hata oluştu.', 'warn');
  }

  // Monitör butonunu sıfırla
  const btnId = 'monbtn-' + ip.replace(/\./g, '-');
  const btn   = document.getElementById(btnId);
  if (btn) {
    btn.textContent = '👁 Monitör Et';
    btn.classList.remove('monitoring');
  }

  if (closePanelToo) closeMonitor();
}

function closeMonitor() {
  document.getElementById('monitor-panel').classList.remove('open');
  document.getElementById('monitor-overlay').classList.remove('open');
  if (_monitorIp) stopMonitor(false);
}

// ─── Helpers ──────────────────────────────────────────────────────────
async function api(url, body) {
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    return await r.json();
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function setStatus(el, msg, cls) {
  el.textContent = msg;
  el.className   = 'mini-status ' + (cls || '');
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;');
}

// ─── Init ─────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  initCanvas();
  connectSSE();
  loadStatus();

  // 10s'de bir durum yenile
  setInterval(loadStatus, 10000);

  // Network input'a varsayılan değer
  fetch('/api/status').then(r => r.json()).then(d => {
    const netRange = d.network_range || null;
    const ip = d.local_ip || '192.168.1.67';
    if (netRange) {
      document.getElementById('network-input').placeholder = netRange;
      document.getElementById('network-input').value = netRange;
    } else {
      const parts = ip.split('.');
      if (parts.length === 4) {
        document.getElementById('network-input').placeholder =
          `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
        document.getElementById('network-input').value =
          `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
      }
    }
    // Expert gateway otomatik doldur
    const gwEl = document.getElementById('ex-arp-gw');
    if (gwEl && d.gateway_ip) gwEl.value = d.gateway_ip;
  }).catch(() => {
    showToast('Sunucuya bağlanılamadı.', 'error');
  });
});
