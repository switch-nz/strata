const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const IS_MAC = /mac|iphone|ipad/i.test(
  (navigator.userAgentData && navigator.userAgentData.platform) ||
  navigator.platform || navigator.userAgent || '');
const MOD_KEY = IS_MAC ? '⌘' : 'Ctrl';
const MOD_LABEL = k => IS_MAC ? MOD_KEY + k : MOD_KEY + '+' + k;

const api = {
  async get(path, params = {}) {
    const q = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v !== undefined && v !== null));
    const r = await fetch(`/api/${path}?${q}`);
    return r.json();
  },
  async post(path, body = {}) {
    const r = await fetch(`/api/${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return r.json();
  },
};

const S = {
  open: false,
  image: null,
  volumes: null,
  caseInfo: null,
  scope: { part: null, size: 0, label: '' },
  cursor: 0,
  selection: null,
  marks: [],
  carveHits: [],
  carveTypes: null,
  findHits: [],
  timeline: null,
  profile: null,
  volmap: null,
  selectedNode: null,
  structures: [],
  focusField: null,
  structToken: null,
  fileHits: [],
  tags: [],
  tagCounts: {},
  suggestedTags: [],
  savedSearches: [],
  hashSets: [],
  tz: null,
  registry: [],
  tzCandidates: [],
  archive: null,
  hashRows: [],
  indexState: null,
  lastEntry: null,
  lastSearchPart: null,
  prefs: {},
  markCats: [],
};

const fmt = {
  hex(n, pad = 8) { return n.toString(16).toUpperCase().padStart(pad, '0'); },
  bytes(n) {
    if (n === null || n === undefined) return '—';
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0, v = n;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v : v.toFixed(v < 10 ? 2 : 1)) + ' ' + u[i];
  },
  time(t) {
    if (!t) return '—';
    // Recorded with no zone (FAT, DOS times, exFAT without an offset): shown
    // as-is, neither labelled UTC nor converted to the display zone.
    if (!hasZone(t)) return t.replace('T', ' ');
    const utc = t.replace('T', ' ').replace('Z', '');
    if (!S.tz || timeDisplay === 'utc') return utc + ' UTC';
    const local = fmt.localOf(t);
    if (!local) return utc + ' UTC';
    const label = tzLabelAt(t);
    if (timeDisplay === 'local' && label) return `${local} ${label}`;
    return `${local} ${label} · ${utc} UTC`;
  },
  count(n) { return Number(n || 0).toLocaleString(); },
  localOf(t) {
    if (!S.tz || !t || !hasZone(t)) return null;
    const d = new Date(t.endsWith('Z') ? t : t + 'Z');
    if (isNaN(d)) return null;
    const shifted = new Date(d.getTime() + tzOffsetAt(S.tz, d) * 60000);
    return shifted.toISOString().replace('T', ' ').replace(/\.\d+Z$|Z$/, '');
  },
};

function hasZone(t) {
  return /(Z|[+-]\d\d:\d\d)$/.test(String(t));
}

const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

function daysInMonth(year, month) {
  if (month === 2 && ((year % 4 === 0 && year % 100 !== 0) || year % 400 === 0)) {
    return 29;
  }
  return DAYS_IN_MONTH[month - 1];
}

function ruleFiresAt(rule, year) {
  if (!rule || !rule.month) return null;
  let day;
  if (rule.year) {
    day = rule.week || 1;
    year = rule.year;
  } else {
    const first = new Date(Date.UTC(year, rule.month - 1, 1)).getUTCDay();
    const delta = (rule.dow - first + 7) % 7;
    day = 1 + delta + (rule.week - 1) * 7;
    const last = daysInMonth(year, rule.month);
    while (day > last) day -= 7;
  }
  return Date.UTC(year, rule.month - 1, day, rule.hour || 0, rule.minute || 0);
}

function tzOffsetAt(tz, when) {
  const tr = tz && tz.dst_transitions;
  if (!tr || !tr.daylight || !tr.standard || !when) {
    return (tz && tz.offset_minutes) || 0;
  }
  const stdMinutes = -(tr.bias + tr.standard_bias);
  const dstMinutes = -(tr.bias + tr.daylight_bias);
  const local = when.getTime() + stdMinutes * 60000;
  const year = new Date(local).getUTCFullYear();
  const start = ruleFiresAt(tr.daylight, year);
  const end = ruleFiresAt(tr.standard, year);
  if (start == null || end == null) return stdMinutes;
  const inDst = start < end
    ? (local >= start && local < end)
    : (local >= start || local < end);
  return inDst ? dstMinutes : stdMinutes;
}

function tzLabelAt(t) {
  if (!S.tz) return '';
  if (!S.tz.dst_transitions) return S.tz.label;
  const d = new Date(String(t).endsWith('Z') ? t : t + 'Z');
  if (isNaN(d)) return S.tz.label;
  return tzLabel(tzOffsetAt(S.tz, d));
}

const HL_FILL = {
  mark:       'rgba(224,161,74,.18)',
  'field-a':  'rgba(94,148,214,.15)',
  'field-b':  'rgba(96,178,142,.15)',
  'field-on': 'rgba(224,161,74,.34)',
};

let fieldIndex = [];

function buildFieldIndex(structs) {
  const flat = [];
  structs.forEach(s => s.fields.forEach((f, i) => flat.push({
    start: f.offset, end: f.offset + f.size, i,
    field: f, struct: s,
  })));
  flat.sort((a, b) => a.start - b.start || a.end - b.end);
  fieldIndex = flat;
}

function fieldAt(off) {
  let lo = 0, hi = fieldIndex.length - 1, best = null;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const e = fieldIndex[mid];
    if (off < e.start) hi = mid - 1;
    else if (off >= e.end) lo = mid + 1;
    else { best = e; break; }
  }
  return best;
}

async function loadStructures() {
  const part = S.scope.part;
  const token = Symbol();
  S.structToken = token;
  S.structures = [];
  fieldIndex = [];
  S.focusField = null;
  const r = await api.get('structure', { part });
  if (S.structToken !== token) return;
  S.structures = r.structures || [];
  buildFieldIndex(S.structures);
  renderStructures();
  hex.draw();
}

function renderStructures() {
  const box = $('#structs');
  if (!box) return;
  const n = S.structures.length;
  $('#struct-count').textContent = n ? String(n) : '';
  if (!n) {
    box.innerHTML = `<p class="empty">${txt('ui.templated_structures_scope')}</p>`;
    return;
  }
  box.innerHTML = S.structures.map((s, si) => `
    <div class="struct" data-s="${si}">
      <div class="struct-head">
        <span class="nm">${esc(s.name)}</span>
        <span class="at">0x${fmt.hex(s.offset, 8)}</span>
      </div>
      <div class="struct-fields">
        ${s.fields.map((f, fi) => `
          <div class="fld" data-s="${si}" data-f="${fi}"
               title="${esc(f.note || '')}">
            <span class="fnm">${esc(f.name)}</span>
            <span class="fval">${esc(String(f.value))}</span>
            ${f.meaning ? `<span class="fmean">${esc(f.meaning)}</span>` : ''}
            <span class="foff">+${f.offset - s.offset} · ${f.size}B</span>
          </div>`).join('')}
      </div>
    </div>`).join('');

  $$('#structs .fld').forEach(el => el.addEventListener('click', () => {
    const s = S.structures[+el.dataset.s];
    const f = s.fields[+el.dataset.f];
    S.cursor = f.offset;
    S.selection = { start: f.offset, length: f.size };
    S.focusField = fieldAt(f.offset);
    $$('#structs .fld.is-on').forEach(n => n.classList.remove('is-on'));
    el.classList.add('is-on');
    hex.reveal(f.offset);
    hex.draw();
    updateStatus();
  }));
}

const HEX_GROUP = 8;

class HexView {
  constructor(canvas, secondary = false) {
    this.c = canvas;
    this.secondary = secondary;
    this._cur = 0;
    this._sel = null;
    this.ctx = canvas.getContext('2d');
    this.bpr = 16;
    this.top = 0;
    this.cache = { off: -1, data: new Uint8Array(0) };
    this.pending = null;
    this.dpr = 1;

    canvas.addEventListener('wheel', e => this.onWheel(e), { passive: false });
    canvas.addEventListener('mousedown', e => this.onDown(e));
    canvas.addEventListener('mousemove', e => this.onMove(e));
    window.addEventListener('mouseup', () => { this.dragging = false; });
    canvas.addEventListener('keydown', e => this.onKey(e));
    if (!secondary) {
      canvas.addEventListener('contextmenu', e => {
        e.preventDefault();
        hexMenu(e);
      });
    }
    canvas.addEventListener('touchstart', e => this.onTouch(e), { passive: true });
    canvas.addEventListener('touchmove', e => this.onTouchMove(e), { passive: false });

    new ResizeObserver(() => this.resize()).observe(canvas.parentElement);
  }

  get size() { return S.scope.size || 0; }
  get headH() { return this.rowH || 0; }
  get rows() {
    return Math.max(1, Math.floor((this.h - this.headH) / this.rowH));
  }
  get span() { return this.rows * this.bpr; }

  get cur() { return this.secondary ? this._cur : S.cursor; }
  set cur(v) { if (this.secondary) this._cur = v; else S.cursor = v; }

  get sel() { return this.secondary ? this._sel : S.selection; }
  set sel(v) { if (this.secondary) this._sel = v; else S.selection = v; }

  announce() {
    if (!this.secondary) return updateStatus();
    const box = $('#hex-b-at');
    if (box) {
      box.textContent = '0x' + fmt.hex(this.cur, 10)
        + (this.sel ? ` · ${this.sel.length} B` : '');
    }
  }

  resize() {
    const box = this.c.getBoundingClientRect();
    if (!box.width || !box.height) return;
    this.dpr = window.devicePixelRatio || 1;
    this.w = box.width; this.h = box.height;
    const cw = Math.floor(box.width * this.dpr);
    const ch = Math.floor(box.height * this.dpr);
    if (this.c.width !== cw) this.c.width = cw;
    if (this.c.height !== ch) this.c.height = ch;
    const ctx = this.ctx;
    ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    this.fontSize = box.width < 560 ? 11 : 12.5;
    ctx.font = `${this.fontSize}px ${getComputedStyle(document.body).fontFamily}`;
    this.charW = ctx.measureText('0').width;
    this.rowH = Math.round(this.fontSize * 1.55);

    const offCols = 12;
    for (const n of [64, 48, 32, 24, 16, 8]) {
      const cols = offCols + 2 + n * 3 + Math.floor(n / 8) + 2 + n;
      if (cols * this.charW + 24 <= box.width) { this.bpr = n; break; }
      this.bpr = 8;
    }
    this.load(true);
  }

  clamp(v) { return Math.max(0, Math.min(v, Math.max(0, this.size - 1))); }

  scrollTo(offset, { center = false } = {}) {
    if (!Number.isFinite(offset)) { this.draw(); return; }
    let top = center ? offset - Math.floor(this.rows / 2) * this.bpr : offset;
    top = Math.max(0, top - (top % this.bpr));
    const maxTop = Math.max(0, Math.ceil(this.size / this.bpr) * this.bpr
      - this.span);
    this.top = Math.min(top, maxTop);
    this.load();
    if (!this.secondary) core?.draw();
  }

  reveal(offset) {
    if (offset < this.top || offset >= this.top + this.span) {
      this.scrollTo(offset, { center: true });
    } else { this.draw(); }
  }

  async load(force = false) {
    if (!S.open) { this.draw(); return; }
    const margin = this.span * 2;
    const want = Math.max(0, this.top - margin);
    const len = Math.min(this.span + margin * 2, this.size - want);
    const have = this.cache;
    if (!force && have.off >= 0 && want >= have.off &&
        want + len <= have.off + have.data.length) { this.draw(); return; }
    const token = Symbol();
    this.pending = token;
    const r = await api.get('hex', { offset: want, length: len,
                                     part: S.scope.part,
                                     entry: S.scope.entry
                                       ? JSON.stringify(S.scope.entry)
                                       : undefined,
                                     stream: S.scope.stream || undefined });
    if (this.pending !== token) return;
    const bin = atob(r.data || '');
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    this.cache = { off: want, data: arr };
    this.draw();
  }

  byteAt(off) {
    const i = off - this.cache.off;
    if (!Number.isInteger(i) || i < 0 || i >= this.cache.data.length) {
      return null;
    }
    const b = this.cache.data[i];
    return typeof b === 'number' ? b : null;
  }

  highlightFor(off) {
    const sel = this.sel;
    if (sel && off >= sel.start && off < sel.start + sel.length) return 'sel';
    for (const m of marksHere()) {
      const s = m.offset - (S.scope.file ? 0 : (S.scope.part || 0));
      if (off >= s && off < s + Math.max(1, m.length)) {
        const c = markColour(m);
        return c ? { fill: c + '30' } : 'mark';
      }
    }
    const f = fieldAt(off);
    if (f) return f === S.focusField ? 'field-on' : (f.i % 2 ? 'field-b' : 'field-a');
    return null;
  }

  draw() {
    const ctx = this.ctx;
    const css = getComputedStyle(document.documentElement);
    const col = n => css.getPropertyValue(n).trim();
    ctx.fillStyle = col('--ink');
    ctx.fillRect(0, 0, this.w, this.h);
    if (!S.open) {
      ctx.fillStyle = col('--dimmer');
      ctx.textBaseline = 'middle';
      ctx.fillText(txt('help.inspect.no_evidence_open'), 16, this.h / 2);
      return;
    }
    if (!this.size) {
      ctx.fillStyle = col('--dimmer');
      ctx.textBaseline = 'middle';
      ctx.font = `${this.fontSize}px ${getComputedStyle(document.body).fontFamily}`;
      ctx.fillText(txt('help.inspect.no_bytes_here'), 16, this.h / 2);
      return;
    }
    ctx.font = `${this.fontSize}px ${getComputedStyle(document.body).fontFamily}`;
    ctx.textBaseline = 'top';

    const cw = this.charW;
    const padX = 12;
    const offW = 12 * cw;
    const hexX = padX + offW + cw * 2;
    const asciiX = hexX + this.bpr * 3 * cw
                 + Math.floor(this.bpr / HEX_GROUP) * cw + cw * 2;

    const cText = col('--text'), cDim = col('--dim'), cDimmer = col('--dimmer');
    const cAmber = col('--amber'), cSel = col('--select'), cGood = col('--good');

    const twoWays = twoOffsetReadings();
    ctx.fillStyle = (twoWays && effectiveMode() === 'physical') ? cAmber : cDimmer;
    ctx.fillText(!twoWays ? 'Offset'
                 : effectiveMode() === 'physical' ? 'Offset ⌖phys'
                 : S.scope.file ? 'Offset ⌖file' : 'Offset ⌖vol',
                 padX, 3);
    const curCol = this.cur % this.bpr;
    for (let i = 0; i < this.bpr; i++) {
      const gx = hexX + (i * 3 + Math.floor(i / HEX_GROUP)) * cw;
      ctx.fillStyle = i === curCol ? cAmber : cDim;
      ctx.fillText(i.toString(16).toUpperCase().padStart(2, '0'), gx, 3);
    }
    ctx.fillStyle = cDimmer;
    ctx.fillText('ASCII', asciiX, 3);
    ctx.strokeStyle = col('--line-soft');
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(0, this.headH - 0.5);
    ctx.lineTo(this.w, this.headH - 0.5);
    ctx.stroke();

    for (let r = 0; r < this.rows; r++) {
      const rowOff = this.top + r * this.bpr;
      if (rowOff >= this.size) break;
      const y = this.headH + r * this.rowH + 3;

      if ((rowOff / this.bpr) % 8 < 4) {
        ctx.fillStyle = col('--panel');
        ctx.globalAlpha = 0.35;
        ctx.fillRect(0, y - 3, this.w, this.rowH);
        ctx.globalAlpha = 1;
      }

      ctx.fillStyle = cDimmer;
      let label;
      if (S.scope.file && effectiveMode() === 'physical' && twoOffsetReadings()) {
        const dev = deviceOffset(rowOff);
        label = dev == null ? '—'.repeat(11) : fmt.hex(dev, 11);
      } else {
        label = fmt.hex(rowOff + offsetBase(), 11);
      }
      ctx.fillText(label, padX, y);

      let ascii = '';
      for (let i = 0; i < this.bpr; i++) {
        const off = rowOff + i;
        if (off >= this.size) break;
        const b = this.byteAt(off);
        const gx = hexX + (i * 3 + Math.floor(i / HEX_GROUP)) * cw;
        const hl = this.highlightFor(off);
        if (hl) {
          ctx.fillStyle = hl === 'sel' ? cSel
            : (hl.fill ? hl.fill : HL_FILL[hl]);
          ctx.fillRect(gx - cw * 0.25, y - 2, cw * 2.5, this.rowH - 1);
          ctx.fillRect(asciiX + i * cw - 1, y - 2, cw + 2, this.rowH - 1);
        }
        if (typeof b !== 'number') {
          ctx.fillStyle = cDimmer;
          ctx.fillText('··', gx, y);
          ascii += ' ';
          continue;
        }
        ctx.fillStyle = b === 0 ? cDimmer
          : (b >= 32 && b < 127) ? cText
          : b === 255 ? cDim : cGood;
        ctx.fillText(b.toString(16).toUpperCase().padStart(2, '0'), gx, y);
        ascii += (b >= 32 && b < 127) ? String.fromCharCode(b) : '·';
      }

      ctx.fillStyle = cDim;
      for (let i = 0; i < ascii.length; i++) {
        const ch = ascii[i];
        ctx.fillStyle = ch === '·' || ch === ' ' ? cDimmer : cText;
        ctx.fillText(ch, asciiX + i * cw, y);
      }

      if (this.cur >= rowOff && this.cur < rowOff + this.bpr) {
        const i = this.cur - rowOff;
        const gx = hexX + (i * 3 + Math.floor(i / HEX_GROUP)) * cw;
        ctx.strokeStyle = cAmber;
        ctx.lineWidth = 1;
        ctx.strokeRect(gx - cw * 0.3 + .5, y - 2.5, cw * 2.6, this.rowH - 1);
      }
    }

    this.geom = { padX, offW, hexX, asciiX, cw };
    core.draw();
  }

  hitTest(x, y) {
    if (!this.geom) return null;
    const r = Math.floor((y - this.headH) / this.rowH);
    if (r < 0) return null;
    const { hexX, asciiX, cw } = this.geom;
    let i = -1;
    if (x >= asciiX) i = Math.floor((x - asciiX) / cw);
    else if (x >= hexX) {
      const rel = (x - hexX) / cw;
      const span = HEX_GROUP * 3 + 1;
      const g = Math.floor(rel / span);
      const within = rel - g * span;
      i = g * HEX_GROUP + Math.min(HEX_GROUP - 1, Math.floor(within / 3));
      i = Math.min(i, this.bpr - 1);
    }
    if (i < 0 || i >= this.bpr) return null;
    const off = this.top + r * this.bpr + i;
    return off < this.size ? off : null;
  }

  onDown(e) {
    if (e.button !== 0) return;
    this.c.focus();
    const b = this.c.getBoundingClientRect();
    const x = e.clientX - b.left, y = e.clientY - b.top;
    if (this.geom && x < this.geom.hexX && !this.secondary
        && twoOffsetReadings()) {
      setOffsetMode(effectiveMode() === 'physical' ? 'logical' : 'physical');
      return;
    }
    const off = this.hitTest(x, y);
    if (off === null) return;
    this.cur = off;
    this.anchor = off;
    this.dragging = true;
    this.sel = null;
    this.draw();
    this.announce();
  }

  onMove(e) {
    if (!this.dragging) {
      const b = this.c.getBoundingClientRect();
      const over = this.geom && (e.clientX - b.left) < this.geom.hexX
                   && !this.secondary && twoOffsetReadings();
      this.c.style.cursor = over ? 'pointer' : '';
      this.c.title = !over ? ''
        : S.scope.file ? txt('messages.click_switch_file_physical_offsets')
        : txt('messages.click_switch_between_offsets_volume_offsets_start');
      return;
    }
    const b = this.c.getBoundingClientRect();
    const off = this.hitTest(e.clientX - b.left, e.clientY - b.top);
    if (off === null) return;
    this.cur = off;
    this.sel = { start: Math.min(this.anchor, off),
                    length: Math.abs(off - this.anchor) + 1 };
    this.draw();
    this.announce();
  }

  onWheel(e) {
    e.preventDefault();
    const rows = Math.sign(e.deltaY) * Math.max(1, Math.round(Math.abs(e.deltaY) / 32));
    this.scrollTo(this.top + rows * 3 * this.bpr);
  }

  onTouch(e) { this.tY = e.touches[0].clientY; this.tTop = this.top; }
  onTouchMove(e) {
    e.preventDefault();
    const dy = this.tY - e.touches[0].clientY;
    this.scrollTo(this.tTop + Math.round(dy / this.rowH) * this.bpr);
  }

  onKey(e) {
    const k = e.key;
    const moves = {
      ArrowDown: this.bpr, ArrowUp: -this.bpr, ArrowRight: 1, ArrowLeft: -1,
      PageDown: this.span, PageUp: -this.span,
    };
    if (k in moves) {
      e.preventDefault();
      this.cur = this.clamp(this.cur + moves[k]);
      this.sel = null;
      this.reveal(this.cur);
      this.announce();
    } else if (k === 'Home') {
      e.preventDefault(); this.cur = 0; this.scrollTo(0); this.announce();
    } else if (k === 'End') {
      e.preventDefault(); this.cur = this.clamp(this.size - 1);
      this.scrollTo(this.size, { center: true }); this.announce();
    }
  }
}

const CLASS_COLOURS = ['--c-zero', '--c-text', '--c-struct', '--c-dense',
                       '--c-crypt', '--c-ff'];

const CLASS_LABELS = ['zero', 'text', 'struct', 'dense', 'entropy', 'FF'];

class CoreSample {
  constructor(canvas) {
    this.c = canvas;
    this.ctx = canvas.getContext('2d');
    let dragging = false;
    const jump = e => {
      const b = this.c.getBoundingClientRect();
      const y = ('touches' in e ? e.touches[0].clientY : e.clientY) - b.top;
      const frac = Math.max(0, Math.min(1, y / b.height));
      hex.scrollTo(Math.floor(frac * S.scope.size), { center: true });
      S.cursor = Math.floor(frac * S.scope.size);
      updateStatus();
    };
    canvas.addEventListener('mousedown', e => { dragging = true; jump(e); });
    canvas.addEventListener('mousemove', e => { if (dragging) jump(e); });
    window.addEventListener('mouseup', () => { dragging = false; });
    canvas.addEventListener('touchstart', jump, { passive: true });
    canvas.addEventListener('touchmove', e => { e.preventDefault(); jump(e); },
                            { passive: false });
    new ResizeObserver(() => this.draw()).observe(canvas.parentElement);
    this.initGrip();
  }

  initGrip() {
    const grip = $('#core-grip');
    if (!grip) return;
    const body = $('.hex-body');
    let dragging = false;

    const setW = px => {
      const max = Math.max(60, body.getBoundingClientRect().width - 220);
      const w = Math.max(24, Math.min(px, max));
      body.style.setProperty('--core-w', w + 'px');
      hex.resize();
      this.draw();
      return w;
    };
    this.setWidth = setW;

    grip.addEventListener('mousedown', e => {
      dragging = true;
      grip.classList.add('is-dragging');
      e.preventDefault();
    });
    window.addEventListener('mousemove', e => {
      if (!dragging) return;
      setW(body.getBoundingClientRect().right - e.clientX);
    });
    window.addEventListener('mouseup', () => {
      dragging = false;
      grip.classList.remove('is-dragging');
    });
    grip.addEventListener('dblclick', () => {
      const cur = $('#core').getBoundingClientRect().width;
      setW(cur > 90 ? 46 : 240);
    });
    grip.addEventListener('keydown', e => {
      const d = { ArrowLeft: 20, ArrowRight: -20 }[e.key];
      if (!d) return;
      e.preventDefault();
      setW($('#core').getBoundingClientRect().width + d);
    });
  }

  draw() {
    const box = this.c.getBoundingClientRect();
    if (!box.height) return;
    const dpr = window.devicePixelRatio || 1;
    const w = Math.floor(box.width * dpr), h = Math.floor(box.height * dpr);
    if (this.c.width !== w) this.c.width = w;
    if (this.c.height !== h) this.c.height = h;
    const ctx = this.ctx;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const css = getComputedStyle(document.documentElement);
    const col = n => css.getPropertyValue(n).trim();
    const W = box.width, H = box.height;

    ctx.fillStyle = col('--panel');
    ctx.fillRect(0, 0, W, H);
    if (!S.open) return;

    const buckets = S.profile ? S.profile.buckets : null;
    if (buckets) {
      const bh = H / buckets.length;
      for (let i = 0; i < buckets.length; i++) {
        ctx.fillStyle = col(CLASS_COLOURS[buckets[i][0]] || '--c-zero');
        ctx.fillRect(0, i * bh, W - 10, Math.max(bh, 0.6));
      }
    } else {
      ctx.fillStyle = col('--raise');
      ctx.fillRect(0, 0, W - 10, H);
      ctx.save();
      ctx.translate(W / 2 - 5, H / 2);
      ctx.rotate(-Math.PI / 2);
      ctx.fillStyle = col('--dimmer');
      ctx.font = '9px ' + getComputedStyle(document.body).fontFamily;
      ctx.textAlign = 'center';
      ctx.fillText('PROFILE PENDING', 0, 3);
      ctx.restore();
    }

    if (S.volumes && S.scope.part === null) {
      ctx.strokeStyle = col('--line');
      for (const p of S.volumes.partitions) {
        const y = (p.offset / S.scope.size) * H;
        ctx.beginPath(); ctx.moveTo(0, y + .5); ctx.lineTo(W - 10, y + .5);
        ctx.stroke();
      }
    }

    const vmap = (!S.scope.file && S.scope.part !== null && S.volmap
                  && S.volmap.covered) ? S.volmap.spans : null;
    if (vmap && S.scope.size) {
      for (const sp of vmap) {
        const y = (sp.offset / S.scope.size) * H;
        if (y < 0 || y > H) continue;
        const h = Math.max(1.5, ((sp.length || 0) / S.scope.size) * H);
        const c = col(SPAN_COLOURS[sp.kind] || '--c-struct');
        ctx.globalAlpha = 0.55;
        ctx.fillStyle = c;
        ctx.fillRect(0, y, W - 10, Math.min(h, H - y));
        ctx.globalAlpha = 1;
        ctx.fillRect(0, Math.round(y), 4, 1.5);
      }
    }

    for (const m of marksHere()) {
      const rel = m.offset - (S.scope.file ? 0 : (S.scope.part || 0));
      if (rel < 0 || rel > S.scope.size) continue;
      ctx.fillStyle = markColour(m) || col('--good');
      ctx.fillRect(W - 8, (rel / S.scope.size) * H, 6, 2);
    }

    const MIN_MARK = 6;
    const vy = (hex.top / S.scope.size) * H;
    const vh = Math.max(MIN_MARK, (hex.span / S.scope.size) * H);
    const vtop = Math.min(vy, Math.max(0, H - vh));
    ctx.fillStyle = 'rgba(224,161,74,.18)';
    ctx.fillRect(0, vtop, W - 10, vh);
    ctx.strokeStyle = col('--amber');
    ctx.lineWidth = 1;
    ctx.strokeRect(-1, vtop - .5, W - 8, vh);

    if (W >= 96) this.annotate(ctx, col, W, H);
  }

  annotate(ctx, col, W, H) {
    const size = S.scope.size || 0;
    if (!size) return;
    ctx.font = `9px ${getComputedStyle(document.body).fontFamily}`;
    ctx.textBaseline = 'middle';

    const ticks = Math.max(2, Math.min(16, Math.floor(H / 46)));
    ctx.strokeStyle = col('--line');
    for (let i = 0; i <= ticks; i++) {
      const y = (i / ticks) * H;
      const off = Math.floor((i / ticks) * size);
      ctx.beginPath();
      ctx.moveTo(0, Math.round(y) + .5);
      ctx.lineTo(5, Math.round(y) + .5);
      ctx.stroke();
      ctx.fillStyle = col('--dimmer');
      const label = W >= 150 ? `0x${fmt.hex(off, 8)}` : fmt.bytes(off);
      ctx.fillText(label, 8, Math.min(H - 5, Math.max(5, y)));
    }

    if (S.volumes && S.scope.part === null && W >= 130) {
      for (const p of S.volumes.partitions) {
        const y = (p.offset / size) * H;
        if (y < 0 || y > H) continue;
        ctx.fillStyle = p.allocated === false ? col('--dimmer') : col('--text');
        const nm = p.allocated === false ? 'gap' : (p.detected || p.type || '');
        ctx.fillText(nm.slice(0, 18), 8, Math.min(H - 5, Math.max(12, y + 9)));
      }
    }

    if (S.volmap && S.volmap.covered && S.scope.part !== null
        && !S.scope.file && W >= 130) {
      let lastY = -99, hidden = 0;
      for (const sp of S.volmap.spans) {
        const y = (sp.offset / size) * H;
        if (y < 0 || y > H) continue;
        if (y - lastY < 11) { hidden++; continue; }
        lastY = y;
        ctx.fillStyle = col(SPAN_COLOURS[sp.kind] || '--c-struct');
        ctx.fillText(String(sp.name).slice(0, 18), 8,
                     Math.min(H - 16, Math.max(12, y + 9)));
      }
      if (hidden) {
        ctx.fillStyle = col('--dimmer');
        ctx.fillText(`+${hidden} more`, 8, Math.min(H - 16, lastY + 20));
      }
    }

    if (W >= 170) {
      const cur = hex.top;
      ctx.fillStyle = col('--amber');
      ctx.fillText(`${fmt.bytes(cur)} of ${fmt.bytes(size)}`, 8, H - 6);
    }
  }
}

const EPOCH_1601 = -11644473600000;

function fmtDate(ms) {
  if (!Number.isFinite(ms) || ms < -62135596800000 || ms > 253402300799999) {
    return null;
  }
  return new Date(ms).toISOString()
    .replace('T', ' ')
    .replace(/\.000Z$/, ' UTC')
    .replace(/\.(\d{3})Z$/, '.$1 UTC');
}

function dosDateTime(v) {
  const time = v & 0xFFFF, date = (v >>> 16) & 0xFFFF;
  const y = ((date >> 9) & 0x7F) + 1980, mo = (date >> 5) & 0x0F, d = date & 0x1F;
  const h = (time >> 11) & 0x1F, mi = (time >> 5) & 0x3F, s = (time & 0x1F) * 2;
  if (!mo || mo > 12 || !d || d > 31 || h > 23 || mi > 59 || s > 59) return null;
  return `${y}-${String(mo).padStart(2,'0')}-${String(d).padStart(2,'0')} ` +
         `${String(h).padStart(2,'0')}:${String(mi).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
}

function guidFrom(b) {
  const h = [...b].map(x => x.toString(16).padStart(2, '0'));
  const j = (a, z) => h.slice(a, z).join('');
  return `${h[3]}${h[2]}${h[1]}${h[0]}-${h[5]}${h[4]}-${h[7]}${h[6]}-` +
         `${j(8,10)}-${j(10,16)}`;
}

function renderInterp() {
  const box = $('#interp');
  if (!box) return;
  if (!S.open) {
    $('#interp-at').textContent = '';
    box.innerHTML = `<p class="empty">${txt('help.inspect.click_hex_view')}</p>`;
    return;
  }
  const at = S.selection ? S.selection.start : S.cursor;
  const n = 8;
  const b = new Uint8Array(n);
  let have = 0;
  for (let i = 0; i < n; i++) {
    const v = hex.byteAt(at + i);
    if (v === null) break;
    b[i] = v; have++;
  }
  $('#interp-at').textContent = `0x${fmt.hex(at, 8)}`;
  if (!have) {
    box.innerHTML = `<p class="empty">${txt('ui.bytes_loaded_cursor')}</p>`;
    return;
  }
  const dv = new DataView(b.buffer);
  const u64 = have >= 8 ? dv.getBigUint64(0, true) : null;
  const u64be = have >= 8 ? dv.getBigUint64(0, false) : null;

  const ft = u64 !== null && u64 > 0n && u64 < 0x8000000000000000n
    ? fmtDate(Number(u64 / 10000n) + EPOCH_1601) : null;
  const unix32 = have >= 4 ? fmtDate(dv.getUint32(0, true) * 1000) : null;
  const dos = have >= 4 ? dosDateTime(dv.getUint32(0, true)) : null;

  const rows = [
    ['int8',    have >= 1 && `${dv.getInt8(0)}`,  have >= 1 && `${dv.getUint8(0)}`],
    ['int16',   have >= 2 && `${dv.getInt16(0, true)}`,  have >= 2 && `${dv.getInt16(0, false)}`],
    ['uint16',  have >= 2 && `${dv.getUint16(0, true)}`, have >= 2 && `${dv.getUint16(0, false)}`],
    ['int32',   have >= 4 && `${dv.getInt32(0, true)}`,  have >= 4 && `${dv.getInt32(0, false)}`],
    ['uint32',  have >= 4 && `${dv.getUint32(0, true)}`, have >= 4 && `${dv.getUint32(0, false)}`],
    ['int64',   have >= 8 && `${dv.getBigInt64(0, true)}`,  have >= 8 && `${dv.getBigInt64(0, false)}`],
    ['uint64',  have >= 8 && `${u64}`, have >= 8 && `${u64be}`],
    ['float32', have >= 4 && `${+dv.getFloat32(0, true).toPrecision(9)}`,
                have >= 4 && `${+dv.getFloat32(0, false).toPrecision(9)}`],
    ['float64', have >= 8 && `${+dv.getFloat64(0, true).toPrecision(17)}`,
                have >= 8 && `${+dv.getFloat64(0, false).toPrecision(17)}`],
  ];

  const dual = `<table class="interp-t">
    <thead><tr><th></th><th>${txt('ui.little_endian')}</th><th>${txt('ui.big_endian')}</th></tr></thead>
    <tbody>${rows.map(([k, le, be]) => le === false ? '' : `<tr>
      <td class="k">${k}</td><td class="v">${esc(le)}</td>
      <td class="v">${esc(be === false ? '—' : be)}</td></tr>`).join('')}
    </tbody></table>`;

  const single = [
    ['binary', have >= 1 && b[0].toString(2).padStart(8, '0')],
    ['octal', have >= 1 && '0o' + b[0].toString(8)],
    ['FILETIME', ft],
    ['Unix (32-bit)', unix32],
    ['DOS date/time', dos],
    ['GUID', have >= 8 ? (hexBytes(at, 16)?.length === 16
                          ? guidFrom(hexBytes(at, 16)) : null) : null],
    ['ASCII', asciiRun(at, 24)],
    ['UTF-16LE', utf16Run(at, 24)],
  ].filter(([, v]) => v);

  box.innerHTML = dual + `<dl class="kv interp-kv">${single.map(([k, v]) =>
    `<dt>${k}</dt><dd class="num">${esc(String(v))}</dd>`).join('')}</dl>` +
    (S.focusField ? `<div class="interp-field">
       <span class="fnm">${esc(S.focusField.field.name)}</span>
       <span class="fsrc">${esc(S.focusField.struct.name)}</span>
       ${S.focusField.field.note
         ? `<p class="hint">${esc(S.focusField.field.note)}</p>` : ''}
     </div>` : '');
}

function hexBytes(at, n) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    const v = hex.byteAt(at + i);
    if (v === null) return null;
    out[i] = v;
  }
  return out;
}

function asciiRun(at, n) {
  let s = '';
  for (let i = 0; i < n; i++) {
    const v = hex.byteAt(at + i);
    if (v === null || v === 0) break;
    if (v < 32 || v > 126) break;
    s += String.fromCharCode(v);
  }
  return s.length >= 2 ? s : null;
}

function utf16Run(at, n) {
  let s = '';
  for (let i = 0; i < n * 2; i += 2) {
    const lo = hex.byteAt(at + i), hi = hex.byteAt(at + i + 1);
    if (lo === null || hi === null) break;
    const c = lo | (hi << 8);
    if (!c) break;
    if (c < 32 || c > 0xD7FF) break;
    s += String.fromCharCode(c);
  }
  return s.length >= 2 ? s : null;
}

let offsetMode = 'physical';

let timeDisplay = 'both';

function deviceOffset(fileOff) {
  const ch = S.scope.chunks;
  if (ch && ch.size && ch.offsets && ch.offsets.length) {
    const n = Math.floor(fileOff / ch.size);
    return n < ch.offsets.length ? ch.offsets[n] : null;
  }
  const ex = S.scope.extents;
  if (!ex || !ex.length) return null;
  for (const r of ex) {
    if (fileOff >= r.at && fileOff < r.at + r.length) {
      return r.media == null ? null : r.media + (fileOff - r.at);
    }
  }
  return null;
}

function marksHere() {
  if (!S.scope.file) return S.marks.filter(m => (m.frame || 'media') !== 'file');
  const e = S.scope.entry;
  if (!e) return [];
  const node = String(e.oid ?? e.mft ?? e.inode ?? e.start_cluster ?? e.path ?? '');
  const stream = S.scope.stream || null;
  return S.marks.filter(m => m.frame === 'file'
    && String(m.node ?? '') === node
    && (m.part ?? null) === (S.scope.part ?? null)
    && (m.stream || null) === stream);
}

function twoOffsetReadings() {
  if (!S.open) return false;
  if (S.scope.file) {
    return !!(S.scope.extents || []).length;
  }
  return !!S.scope.part;
}

function effectiveMode() {
  return offsetMode;
}

function offsetBase() {
  if (S.scope.file) return 0;
  return effectiveMode() === 'physical' ? (S.scope.part || 0) : 0;
}

function setTimeDisplay(mode) {
  timeDisplay = ['utc', 'local'].includes(mode) ? mode : 'both';
  savePref('time_display', timeDisplay);
  if (dirView.entries.length) renderDirView();
  if (inspecting && inspecting.entry) {
    showEntry(inspecting.entry, inspecting.part, inspecting.from,
              inspecting.stream);
  }
  updateStatus();
}

function setOffsetMode(mode) {
  offsetMode = mode === 'physical' ? 'physical' : 'logical';
  savePref('offset_mode', offsetMode);
  hex.draw();
  updateStatus();
  const where = S.scope.file
    ? (effectiveMode() === 'physical'
       ? txt('messages.offsets_now_count_start_image')
       : txt('messages.offsets_now_count_start_file'))
    : S.scope.part
    ? (effectiveMode() === 'physical'
        ? txt('messages.offsets_now_count_start_image')
        : txt('messages.offsets_now_count_start_volume'))
    : txt('messages.whole_image_scope_two_readings_same');
  toast(where);
}

function updateStatus() {
  if (!S.open) return;
  const abs = S.cursor + (S.scope.part || 0);
  if (S.scope.empty) {
    $('#stat-offset').textContent = '';
    $('#stat-value').textContent = '';
    $('#stat-context').textContent = txt('messages.no_bytes_for_this_selection');
    return;
  }
  const dev = S.scope.file ? deviceOffset(S.cursor) : null;
  $('#stat-offset').textContent = S.scope.file
    ? (dev != null
        ? (S.scope.chunks
            ? `0x${fmt.hex(S.cursor, 8)} in file · 0x${fmt.hex(dev, 8)} in image`
            : effectiveMode() === 'physical'
            ? `0x${fmt.hex(dev, 8)} phys · 0x${fmt.hex(S.cursor, 8)} in file`
            : `0x${fmt.hex(S.cursor, 8)} in file · phys 0x${fmt.hex(dev, 8)}`)
        : `0x${fmt.hex(S.cursor, 8)} in file`)
    : !S.scope.part
    ? `0x${fmt.hex(S.cursor, 8)}`
    : (effectiveMode() === 'physical'
        ? `0x${fmt.hex(abs, 8)} phys · 0x${fmt.hex(S.cursor, 8)} in volume`
        : `0x${fmt.hex(S.cursor, 8)} · phys 0x${fmt.hex(abs, 8)}`);
  const b = hex.byteAt(S.cursor);
  if (b === null) { $('#stat-value').textContent = ''; }
  else {
    const ch = (b >= 32 && b < 127) ? String.fromCharCode(b) : '·';
    $('#stat-value').textContent = `${b} · 0x${b.toString(16).toUpperCase()
      .padStart(2, '0')} · ${b.toString(2).padStart(8, '0')} · '${ch}'`;
  }
  const sel = S.selection;
  const f = fieldAt(S.cursor);
  S.focusField = f;
  const vs = f ? null : spanAt(S.cursor);
  $('#stat-context').textContent = f
    ? `${f.struct.name} · ${f.field.name}${f.field.meaning
        ? ` — ${f.field.meaning}` : ''}`
    : vs
    ? `${vs.name}${vs.note ? ` — ${vs.note}` : ''}`
    : sel
    ? txt('ui.sel_bytes_selected_0x_start', { sel: sel.length, start: fmt.hex(sel.start, 8) })
    : (S.scope.label || '');
  renderInterp();
}

function spanAt(off) {
  const m = S.volmap;
  if (!m || !m.covered || S.scope.file || S.scope.part === null) return null;
  for (const sp of m.spans) {
    if (!sp.length) continue;
    if (off >= sp.offset && off < sp.offset + sp.length) return sp;
  }
  return null;
}

const dirCache = new Map();
const dirKey = (part, node, ev) =>
  `${ev ?? S.activeId ?? '?'}:${part}:${node ?? 'root'}`;

const walkCache = new Map();
const walkKey = (part, node) =>
  dirKey(partOffset(part), node, part && part.ev_id);

async function fetchDir(part, nodeId, path, ev) {
  const key = dirKey(part, nodeId, ev);
  const hit = dirCache.get(key);
  if (hit) return hit;

  let r = await api.get('dir', { part, node: nodeId, path, types: 1,
                                 ev: ev ?? undefined });
  if (r.building) {
    const done = await awaitTask(r.task, 'Indexing MFT', {
      modal: {
        title: txt('ui.indexing_master_file_table'),
        detail: txt('help.strata_reads_directory_tree_file_name_parent'),
      },
    });
    if (!done) return { error: txt('messages.indexing_interrupted') };
    r = await api.get('dir', { part, node: nodeId, path, types: 1,
                               ev: ev ?? undefined });
  }
  if (!r.error) dirCache.set(key, r);
  return r;
}

let selectedRow = null;
function selectRow(el) {
  if (selectedRow === el) return;
  selectedRow?.classList.remove('is-on');
  selectedRow = el;
  el.classList.add('is-on');
}

function node({ label, tag, meta = null, cls = '', depth = 0,
                expandable = false, onClick, onMenu = null, expand = null,
                data = null, onPick = null, picked = false,
                pickTitle = '' }) {
  const el = document.createElement('div');
  el.className = 'node ' + cls + (meta ? ' has-meta' : '');
  if (data) for (const [k, v] of Object.entries(data)) el.dataset[k] = v;
  el.style.paddingLeft = (8 + depth * 14) + 'px';
  el.innerHTML = `<span class="twist">${expandable ? '▸' : ''}</span>${
    onPick ? `<input type="checkbox" class="pick"${picked ? ' checked' : ''}
                data-own-title="${esc(pickTitle)}"
                title="${esc(pickTitle)}" aria-label="${esc(pickTitle)}">` : ''}
    <span class="stack">
      <span class="label"></span>
      ${meta ? '<span class="meta"></span>' : ''}
    </span>${tag ? `<span class="tag">${tag}</span>` : ''}`;
  $('.label', el).textContent = label;
  if (meta) $('.meta', el).textContent = meta;

  if (onPick) {
    const box = $('.pick', el);
    box.addEventListener('click', ev => ev.stopPropagation());
    box.addEventListener('change', () => onPick(box.checked, el));
  }

  let kids = null, loaded = false, busy = false;
  el.isOpen = false;

  el.toggle = async function (want) {
    if (!expandable || busy) return;
    const open = want === undefined ? !el.isOpen : want;
    if (open === el.isOpen && loaded) return;
    el.isOpen = open;
    el.classList.toggle('is-open', open);
    if (!kids) {
      kids = document.createElement('div');
      kids.className = 'kids';
      el.after(kids);
    }
    kids.hidden = !open;
    if (open && !loaded) {
      busy = true;
      el.classList.add('is-busy');
      try {
        loaded = (await expand(kids, depth + 1)) !== false;
      } finally {
        busy = false;
        el.classList.remove('is-busy');
      }
    }
    $('.twist', el).textContent = el.isOpen ? '▾' : '▸';
  };

  $('.twist', el).addEventListener('click', ev => {
    ev.stopPropagation();
    el.toggle();
  });
  el.addEventListener('click', ev => {
    ev.stopPropagation();
    selectRow(el);
    onClick(el);
    if (expandable && !el.isOpen) el.toggle(true);
  });
  if (onMenu) {
    el.addEventListener('contextmenu', ev => {
      ev.preventDefault();
      ev.stopPropagation();
      onMenu(ev, el);
    });
  }
  return el;
}

function partNumber(p, parts) {
  if (!p || p.allocated === false) return null;
  const list = parts || S.volumes?.partitions || [];
  let n = 0;
  for (const x of list) {
    if (x.allocated === false) continue;
    n += 1;
    if (x.offset === p.offset) return n;
  }
  return null;
}

const logicalRegion = p => !!(p && p.logical);

function partName(p, parts) {
  if (!p) return txt('ui.whole_image');
  if (p.allocated === false) return txt('ui.unpartitioned_space');
  if (logicalRegion(p)) return p.slot;
  const n = partNumber(p, parts);
  return `Partition ${n === null ? '?' : n}${p.label ? ` “${p.label}”` : ''}`;
}

function partDetail(p) {
  if (p.allocated === false) return fmt.bytes(p.size);
  return `${fmt.bytes(p.size)} · ${p.detected || p.type || 'unrecognised'}`;
}

function partLabel(p, parts) {
  if (p.allocated === false) {
    return txt('ui.unpartitioned_space_size_0x_offset', { size: fmt.bytes(p.size), offset: fmt.hex(p.offset, 10) });
  }
  const fs = p.detected || p.type || 'unrecognised';
  return `${partName(p, parts)} (${fmt.bytes(p.size)} · ${fs}) · `
       + `0x${fmt.hex(p.offset, 10)}`;
}

function partLines(p, parts) {
  return { label: partName(p, parts), meta: partDetail(p) };
}

function renderTree() {
  const t = $('#tree');
  t.innerHTML = '';
  selectedRow = null;
  if (!S.open) {
    t.innerHTML = `<p class="empty">${txt('ui.open_image_see_volume_structure')}</p>`;
    return;
  }

  const items = (S.exhibits && S.exhibits.length)
    ? S.exhibits
    : [{ evidence_id: S.evidenceId ?? null, label: S.image.segments[0],
         path: S.image.segments[0], size: S.image.size,
         format: S.image.format, volumes: S.volumes }];

  const head = document.createElement('div');
  head.className = 'group-head';
  head.textContent = items.length === 1
    ? `${S.volumes.scheme} · ${fmt.bytes(S.image.size)}`
    : `${items.length} exhibits`;
  t.appendChild(head);

  for (const ev of items) {
    const active = ev.evidence_id === S.activeId;
    const vols = (ev.volumes || {});
    const parts = vols.partitions || [];

    const root = node({
      label: ev.label || ev.path,
      meta: `${ev.format || ''} · ${fmt.bytes(ev.size)}`.replace(/^ · /, ''),
      cls: 'exhibit-root' + (active ? ' is-active' : ''),
      data: { ev: ev.evidence_id ?? '' },
      depth: 0,
      expandable: true,
      onClick: async () => {
        if (!await useExhibit(ev)) return;
        const only = parts.length === 1 ? parts[0] : null;
        if (only && logicalRegion(only)) {
          setScope(only.offset, only.size, ev.label || ev.path, only);
          return previewRoot(only);
        }
        setScope(null, S.image.size, ev.label || ev.path, S.image);
        showLayout(ev);
      },
      onMenu: (mev, row) => exhibitMenu(mev, ev, items.length, row),
      expand: async (holder, depth) => {
        const only = parts.length === 1 ? parts[0] : null;
        if (only && logicalRegion(only)) {
          if (!await useExhibit(ev)) return;
          return listInto(holder, only, null, depth, '/', ev.label || '/');
        }
        for (const part of parts) {
          holder.appendChild(partitionNode(ev, part, parts, depth));
        }
      },
    });
    t.appendChild(root);
    if (active) root.toggle(true);
  }
  markListScope();
}

function showLayout(ev) {
  const vols = ev.volumes || {};
  const parts = vols.partitions || [];
  dirView.entries = [];
  dirView.trail = [];
  dirView.id = undefined;
  dirView.self = null;
  dirView.name = ev.label || ev.path;

  const live = parts.filter(p => p.allocated !== false).length;
  const gaps = parts.length - live;
  const rows = parts.map(p => {
    const cls = p.allocated === false ? 'gap' : '';
    return `<div class="layout-row ${cls}" data-off="${p.offset}">
      <span class="nm">${esc(partLabel(p, parts))}</span>
      <span class="sl">${esc(p.slot || '')}</span>
    </div>`;
  }).join('');

  dirSet(ev.label || ev.path,
         `${vols.scheme || 'layout'} · ${txt('ui.count.partitions',
           { count: live })}${gaps ? ` · ${txt('ui.count.gaps',
           { count: gaps })}` : ''}`,
         rows || `<p class="empty">${txt('ui.volume_layout_could_read')}</p>`);

  $$('#dirlist .layout-row').forEach(el => el.addEventListener('click', () => {
    const p = parts.find(x => x.offset === +el.dataset.off);
    if (!p) return;
    $$('#dirlist .layout-row').forEach(r => r.classList.remove('is-on'));
    el.classList.add('is-on');
    selectPartition(ev, p);
  }));
}

async function selectPartition(ev, p) {
  if (!await useExhibit(ev)) return;
  S.lastPick = { kind: 'partition', ev, p };
  setScope(p.offset, p.size, partLabel(p, S.volumes?.partitions), p);
  if (p.allocated === false) {
    return previewNone(txt('messages.unpartitioned_space_filesystem_list'));
  }
  if (await maybeUnlock(p)) return;
  previewRoot(p);
}

function partitionMenu(mev, ev, p, row) {
  const mountable = p.allocated !== false && !!p.detected;
  openMenu(mev.clientX, mev.clientY, [
    { label: txt('ui.hash_every_file_volume'),
      hint: mountable ? 'MD5, SHA-1 and SHA-256' : '',
      disabled: !mountable,
      why: p.allocated === false
        ? txt('help.unpartitioned_space_holds_files_hash_carve_instead')
        : txt('messages.filesystem_identified_here_files_walk'),
      action: async () => {
        if (!await useExhibit(ev)) return;
        hashScope(p.offset, 'all', null, partName(p, partsOf(ev)));
      } },
    (on => ({
      label: on ? txt('ui.list_only_this_volume')
                : txt('ui.list_all_in_volume'),
      disabled: !mountable,
      why: txt('messages.recurse_needs_filesystem'),
      action: async () => {
        if (!await useExhibit(ev)) return;
        toggleListAll(!on, p, null, ev);
      },
    }))(isListScope(p, null)),
    { label: txt('ui.verify_file_types'),
      disabled: !mountable,
      why: txt('messages.filesystem_identified_here'),
      action: async () => {
        if (!await useExhibit(ev)) return;
        setScope(p.offset, p.size, partLabel(p, partsOf(ev)), p);
        $('#btn-filetypes')?.click();
      } },
  ], row);
}

function partsOf(ev) {
  return (ev.volumes || {}).partitions || S.volumes?.partitions || [];
}

function partitionNode(ev, p, parts, depth) {
  const { label, meta } = partLines(p, parts);
  return node({
    label,
    meta,
    onMenu: (mev, row) => partitionMenu(mev, ev, p, row),
    onPick: p.allocated !== false && p.detected
      ? on => toggleListAll(on, p, null, ev) : null,
    picked: isListScope(p, null),
    pickTitle: txt('ui.tree.list_volume'),
    tag: p.slot,
    cls: p.allocated === false ? 'gap' : '',
    depth,
    data: { part: p.offset, ev: ev.evidence_id ?? '' },
    expandable: p.allocated !== false,
    onClick: () => selectPartition(ev, p),
    expand: async (holder, d) => {
      if (!await useExhibit(ev)) {
        holder.innerHTML = `<div class="empty" style="padding-left:${
          8 + d * 14}px">${txt('ui.could_switch_exhibit')}</div>`;
        return;
      }
      return listInto(holder, p, null, d, '/', partName(p, parts) + ' · /');
    },
  });
}

function markActiveExhibit() {
  $$('#tree .exhibit-root').forEach(el => {
    el.classList.toggle('is-active',
                        +el.dataset.ev === S.activeId);
  });
}

async function useExhibit(ev) {
  if (ev.evidence_id == null || ev.evidence_id === S.activeId) return true;
  const r = await api.post('evidence/select', { evidence_id: ev.evidence_id });
  if (r.error) { toast(r.error); return false; }
  switchTo(r, { keepTree: true });
  return true;
}

function exhibitMenu(mev, ev, total, row) {
  if (ev.evidence_id == null) return;
  const name = ev.label || ev.path;
  openMenu(mev.clientX, mev.clientY, [
    { label: txt('ui.verify_acquisition_hashes'),
      hint: txt('ui.reads_whole_image'),
      action: async () => {
        if (!await useExhibit(ev)) return;
        runVerify();
      } },
    null,
    { label: txt('ui.remove_name_case', { name: name }),
      hint: txt('ui.deletes_work'),
      action: () => removeExhibit(ev) },
  ], row);
}

const HOLDING_KEYS = {
  bookmarks: 'ui.holdings.bookmarks',
  tagged_items: 'ui.holdings.tagged_items',
  saved_searches: 'ui.holdings.saved_searches',
  file_hashes: 'ui.holdings.file_hashes',
  artefacts: 'ui.holdings.artefacts',
  attack_tags: 'ui.holdings.attack_tags',
  type_mismatches: 'ui.holdings.type_mismatches',
  content_index: 'ui.holdings.content_index',
};

async function removeExhibit(ev) {
  const got = await api.post('evidence/holdings',
                             { evidence_id: ev.evidence_id });
  if (got.error) return toast(got.error);

  const lines = Object.entries(got.holdings || {}).map(([k, n]) =>
    (HOLDING_KEYS[k]
      ? txt(HOLDING_KEYS[k], { count: n, n: n.toLocaleString() })
      : `${n.toLocaleString()} ${k}`));

  $('#remove-what').textContent = got.label || got.path;
  $('#remove-path').textContent = got.path;
  $('#remove-holdings').innerHTML = lines.length
    ? `<p>${txt('ui.deletes_permanently')}</p><ul>${
        lines.map(l => `<li>${esc(l)}</li>`).join('')}</ul>`
    : `<p>${txt('help.nothing_been_recorded_against_exhibit_yet_nothing')}</p>`;
  const dlg = $('#dlg-remove');
  dlg.dataset.ev = ev.evidence_id;
  dlg.returnValue = '';
  dlg.showModal();
}

$('#dlg-remove')?.addEventListener('close', async () => {
  const dlg = $('#dlg-remove');
  if (dlg.returnValue !== 'ok') return;
  const id = +dlg.dataset.ev;
  const r = await api.post('evidence/remove', { evidence_id: id });
  if (r.error) return toast(r.error);
  toast(txt('help.exhibit_removed_case_evidence_file_itself_untouched', { exhibit: r.removed?.label || 'The exhibit' }));
  clearTimelinePanel();
  switchTo(r);
});

async function listInto(holder, part, nodeId, depth, path, dirName) {
  const r = await fetchDir(part.offset, nodeId, path, part.ev_id);
  if (r.error) {
    const pad = `padding-left:${8 + depth * 14}px`;
    if (r.encrypted) {
      holder.innerHTML = `<div class="empty locked" style="${pad}">${
        esc(r.error)} <button class="linkish" type="button">${txt('ui.list_into.unlock')}</button></div>`;
      holder.querySelector('button')?.addEventListener('click', async ev => {
        ev.stopPropagation();
        if (await maybeUnlock(part)) return;
        renderTree();
      });
      return;
    }
    holder.innerHTML = `<div class="empty" style="${pad}">${esc(r.error)}</div>`;
    return false;
  }

  const frag = document.createDocumentFragment();
  for (const e of r.entries) {
    const childId = e.mft ?? e.inode ?? e.oid ?? e.start_cluster;
    frag.appendChild(node({
      label: e.tree_label || e.name,
      meta: e.tree_label
        ? ([e.source_size != null ? fmt.bytes(e.source_size)
                                  : e.source_size_text,
            e.filesystem].filter(Boolean).join(' \u00b7 ') || null)
        : null,
      tag: e.tree_slot !== undefined ? e.tree_slot
           : (e.is_dir ? '' : fmt.bytes(e.size)),
      cls: (e.deleted ? 'deleted ' : '') + (e.system ? 'system' : ''),
      depth,
      data: { node: childId == null ? '' : String(childId) },
      expandable: !!e.is_dir,
      onClick: () => showEntry(e, part,
                               { entries: r.entries, name: dirName, id: nodeId }),
      onMenu: (ev, row) =>
        openMenu(ev.clientX, ev.clientY, entryMenu(e, part), row),
      onPick: e.is_dir ? on => toggleListAll(on, part, e) : null,
      picked: e.is_dir && isListScope(part, childId),
      pickTitle: txt('ui.tree.list_below'),
      expand: (sub, d) => listInto(sub, part, childId, d, e.path, e.name),
    }));
  }
  if (!r.entries.length) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.style.paddingLeft = (8 + depth * 14) + 'px';
    empty.textContent = txt('messages.empty_directory');
    frag.appendChild(empty);
  }
  holder.appendChild(frag);
  markListScope();
}

function isListScope(part, nodeId) {
  return !!dirView.recursive && sameVolume(part, dirView.part)
         && String(nodeId ?? '') === String(dirView.id ?? '');
}

function markListScope() {
  const tree = $('#tree');
  if (!tree) return;
  tree.classList.toggle('is-scoped', !!dirView.recursive);
  $$('#tree .node.is-scope').forEach(el => el.classList.remove('is-scope'));
  $$('#tree .pick').forEach(box => {
    box.checked = false;
    box.disabled = false;
    const own = box.dataset.ownTitle || '';
    box.title = own;
    box.setAttribute('aria-label', own);
  });
  if (!dirView.recursive) return;
  const sel = dirView.id === null || dirView.id === undefined
    ? `#tree .node[data-part="${partOffset(dirView.part)}"]`
    : `#tree .node[data-node="${dirView.id}"]`;
  for (const row of $$(sel)) {
    row.classList.add('is-scope');
    const box = $('.pick', row);
    if (box) box.checked = true;
    const kids = row.nextElementSibling;
    if (!kids || !kids.classList.contains('kids')) continue;
    for (const b of $$('.pick', kids)) {
      b.checked = true;
      b.disabled = true;
      const why = txt('ui.tree.included_in_scope');
      b.title = why;
      b.setAttribute('aria-label', why);
    }
  }
}

function toggleListAll(on, part, e, ev = null) {
  if (on) return listAllBelow(part, e);
  if (e) return showEntry(e, part);
  return ev ? selectPartition(ev, part) : previewRoot(part);
}

function activeView() {
  return document.querySelector('.view.is-on')?.dataset.view || null;
}

function clearViewer() {
  setEmptyScope(txt('ui.viewer.no_selection'), null);
  $('#inspect').innerHTML =
    `<p class="empty">${txt('ui.viewer.select_item')}</p>`;
  previewNone(txt('ui.viewer.select_item'));
  S.scopeView = null;
}

function setScope(part, size, label, meta) {
  S.scope = { part, size, label, entry: null, stream: null,
              extents: null, chunks: null, ev: S.activeId };
  S.scopeView = activeView();
  S.profile = profileCache.get(profileKey(part)) || null;
  S.cursor = 0;
  S.selection = null;
  hex.cache = { off: -1, data: new Uint8Array(0) };
  $('#hex-scope').textContent = label;
  hex.scrollTo(0);
  updateStatus();
  loadStructures();
  loadVolumeMap();
  if (meta) showPartition(meta);
  if (S.profile) { renderLegend(); core.draw(); } else runProfile();
}

function scopedTo(part) {
  return S.scope.part === partOffset(part) && S.scope.ev === S.activeId
         && !S.scope.file && !S.scope.empty;
}

async function revealInTree(part, nodeId) {
  const tree = $('#tree');
  if (!tree) return;

  const kidsOf = el => (el && el.nextElementSibling &&
    el.nextElementSibling.classList.contains('kids'))
    ? el.nextElementSibling : null;

  const root = $(`#tree .exhibit-root[data-ev="${S.activeId}"]`);
  if (!root) return;
  if (!root.isOpen) await root.toggle(true);

  let holder = kidsOf(root);
  if (!holder) return;

  const want = partOffset(part);
  const prow = [...holder.children].find(
    el => el.dataset && el.dataset.part === String(want));
  if (prow) {
    if (!prow.isOpen) await prow.toggle(true);
    holder = kidsOf(prow);
    if (!holder) return;
  }

  const chain = [...(dirView.trail || []).map(t => t.id), nodeId]
    .filter(id => id !== null && id !== undefined);
  let last = prow || root;
  for (const id of chain) {
    const row = [...holder.children].find(
      el => el.dataset && el.dataset.node === String(id));
    if (!row) break;
    last = row;
    if (!row.isOpen) await row.toggle(true);
    const next = kidsOf(row);
    if (!next) break;
    holder = next;
  }
  if (last && last !== root) {
    selectRow(last);
    last.scrollIntoView({ block: 'nearest' });
  }
}

function setEmptyScope(label, part) {
  S.scope = { part: partOffset(part), size: 0, label, entry: null,
              stream: null, extents: null, chunks: null, empty: true,
              ev: S.activeId };
  S.scopeView = activeView();
  S.profile = null;
  S.cursor = 0;
  S.selection = null;
  hex.cache = { off: -1, data: new Uint8Array(0) };
  $('#hex-scope').textContent = label;
  hex.scrollTo(0);
  S.structures = [];
  fieldIndex = [];
  S.focusField = null;
  S.volmap = null;
  updateStatus();
  core.draw();
}

function setFileScope(entry, part, size, label, stream = null,
                     extents = null, chunks = null) {
  S.scope = { part: partOffset(part), size: size || 0, label,
              entry, stream, file: true, extents: extents || null,
              chunks: chunks || null, ev: S.activeId };
  S.scopeView = activeView();
  S.profile = profileCache.get(profileKey(partOffset(part), S.scope)) || null;
  S.cursor = 0;
  S.selection = null;
  hex.cache = { off: -1, data: new Uint8Array(0) };
  $('#hex-scope').textContent = label;
  hex.scrollTo(0);
  S.structures = [];
  fieldIndex = [];
  S.focusField = null;
  S.volmap = null;
  updateStatus();
  if (S.profile) { renderLegend(); core.draw(); } else runProfile();
}

function kv(pairs) {
  return `<dl class="kv">${pairs.filter(Boolean).map(([k, v, num]) =>
    `<dt>${k}</dt><dd class="${num ? 'num' : ''}">${v}</dd>`).join('')}</dl>`;
}

function showPartition(p) {
  const i = $('#inspect');
  if (p === S.image || p.format) {
    const a = S.image.acquisition || {};
    i.innerHTML = `
      <div class="title">${S.image.segments[0]}</div>
      <div class="subtitle">${S.image.format}</div>
      ${kv([
        [txt('ui.kv.size'), fmt.bytes(S.image.size), true],
        [txt('ui.kv.sectors'), (S.image.sector_count || 0).toLocaleString()],
        [txt('ui.kv.sector_size'), (S.image.bytes_per_sector || 512) + ' B'],
        S.image.chunk_count && [txt('ui.kv.chunks'), S.image.chunk_count.toLocaleString()],
        S.image.segments.length > 1 && [txt('ui.kv.segments'), S.image.segments.length],
      ])}
      <h3>${txt('ui.show_partition.acquisition')}</h3>
      ${kv([
        a.case_number && [txt('ui.kv.case'), a.case_number],
        a.evidence_number && [txt('ui.kv.evidence'), a.evidence_number],
        a.examiner && [txt('ui.kv.examiner'), a.examiner],
        a.acquisition_date && [txt('ui.kv.acquired'), a.acquisition_date],
        a.acquiry_software && [txt('ui.kv.tool'), a.acquiry_software],
      ])}
      <h3>${txt('ui.stored_hashes')}</h3>
      ${kv([
        [txt('ui.kv.md5'), S.image.stored_md5 || 'not stored'],
        [txt('ui.kv.sha_1'), S.image.stored_sha1 || 'not stored'],
      ])}
      ${(S.image.findings || []).length ? `<div class="notice bad">
        <strong>${S.image.findings.length} structural finding(s)</strong><br>
        ${S.image.findings.slice(0, 6).join('<br>')}</div>` : ''}
      <div class="actions">
        <button class="ghost" id="btn-verify">${txt('ui.verify_hashes')}</button>
      </div>`;
    $('#btn-verify')?.addEventListener('click', runVerify);
    return;
  }
  i.innerHTML = `
    <div class="title">${esc(partName(p))}</div>
    <div class="subtitle">${esc(p.detected || p.type || '')} · ${p.slot}${
      p.name ? ' · ' + esc(p.name) : ''}</div>
    ${kv([
                                                                     
                                                                         
                                                                        
                              
      [txt('ui.kv.volume_name'), p.label ? esc(p.label) : 'none'],
      [txt('ui.kv.offset'), `0x${fmt.hex(p.offset, 10)}`, true],
      [txt('ui.kv.size'), fmt.bytes(p.size), true],
      [txt('ui.kv.start_sector'), (p.start_sector || 0).toLocaleString()],
      [txt('ui.kv.sectors'), (p.sector_count || 0).toLocaleString()],
      [txt('ui.kv.table_type'), p.type_id],
    ])}
    ${p.note ? `<div class="notice">${esc(p.note)}</div>` : ''}
    ${p.allocated === false ? `<div class="notice">Not claimed by any
      partition. Unpartitioned space is not visible to the operating system
      and is worth carving.</div>` : ''}`;
}

function entryOffset(st) {
  const base = st.partition_offset || 0;
  const first = (st.runs || []).find(r => !r.sparse && r.offset != null);
  if (first) return first.absolute ?? (first.offset + base);
  for (const k of ['record_offset', 'inode_offset']) {
    if (st[k] != null) return st[k] + base;
  }
  if (st.slack?.offset != null) return st.slack.absolute ?? (st.slack.offset + base);
  return null;
}

function runExtents(st, part) {
  const runs = st && st.runs;
  if (!runs || !runs.length) return null;
  if (st.runs_compressed) return null;
  const base = st.partition_offset != null
    ? st.partition_offset : partOffset(part);
  const out = [];
  let at = 0;
  for (const r of runs) {
    const len = r.length || 0;
    if (!len) continue;
    const media = (r.sparse || r.offset == null) ? null
      : (r.absolute != null ? r.absolute : r.offset + base);
    out.push({ at, media, length: len });
    at += len;
  }
  return out.length ? out : null;
}

function gotoEntry(st, part = null, entry = null, stream = null) {
  const abs = entryOffset(st);
  if (entry && !entry.source) {
    const bytes = stream ? stream.size
      : (st.size != null ? st.size
         : (entry.size != null ? entry.size : null));
    if (bytes) {
      const chunkMap = st.chunk_map && st.chunk_map.length
        ? { size: st.chunk_size, offsets: st.chunk_map,
            truncated: !!st.chunk_map_truncated } : null;
      setFileScope(entry, part, bytes,
                   `${entry.name}${stream ? ':' + stream.name : ''}`
                   + ` \u00b7 file offsets`,
                   stream ? stream.name : null,
                   runExtents(st, part), chunkMap);
      revealViewer();
      return true;
    }
  }
  if (entry && entry.source) {
    setEmptyScope(entry.name || 'source', part);
    return true;
  }

  if (abs == null) return false;
  const want = part && part.offset != null ? part.offset : S.scope.part;
  if (want !== S.scope.part || S.scope.ev !== S.activeId) {
    const p = S.volumes?.partitions?.find(x => x.offset === want);
    setScope(want, p ? p.size : S.image.size,
             p ? partLabel(p, S.volumes?.partitions) : txt('ui.whole_image'), null);
  }
  const rel = abs - (S.scope.part || 0);
  if (rel < 0 || rel >= S.scope.size) return false;
  revealViewer();
  S.cursor = hex.clamp(rel);
  S.selection = null;
  hex.reveal(S.cursor);
  updateStatus();
  return true;
}

let inspecting = { entry: null, part: null, from: null };

async function useOwner(part) {
  const id = part && part.ev_id;
  if (id == null || id === S.activeId) return true;
  const ev = S.exhibits.find(x => x.evidence_id === id);
  return ev ? useExhibit(ev) : true;
}

function scopeLabel(part) {
  if (!part || part === S.image) return (S.image.segments || [''])[0];
  if (logicalRegion(part)) {
    const ev = S.exhibits.find(x => x.evidence_id === part.ev_id);
    return (ev && (ev.label || ev.path)) || (S.image.segments || [''])[0];
  }
  return partLabel(part, S.volumes?.partitions);
}

async function showEntry(e, part, from = null, stream = null) {
  S.lastPick = { kind: 'entry', e, part, from, stream };
  if (!await useOwner(part)) return;

  if (part && !scopedTo(part)) {
    setScope(partOffset(part), part.size ?? S.image.size, scopeLabel(part),
             part);
  }

  S.lastEntry = e;
  inspecting = { entry: e, part, from, stream };
  previewEntry(e, part, from, stream);
  const i = $('#inspect');
  i.innerHTML = `<div class="title">${esc(e.name)}</div>
    <div class="subtitle">${txt('ui.show_entry.reading')}</div>`;
  const st = await api.get('stat', { part: partOffset(part),
                                    entry: JSON.stringify(e),
                                    stream: stream ? stream.name : undefined });

  if (!st || st.error) {
    i.innerHTML = `<div class="title">${esc(e.name)}</div>
      <div class="subtitle">${esc(e.path || '')}</div>
      <div class="notice bad">${esc((st && st.error)
        || 'The record could not be read.')}</div>
      <p class="hint">${txt('help.nothing_shown_below_because_nothing_returned_empty')}</p>`;
    return;
  }

  const fileBytes = stream ? stream.size
    : (st.size != null ? st.size : (e.size != null ? e.size : null));

  const runs = (st.runs || []).map((r, n) => r.sparse
    ? `<div class="runbar sparse"><span>${txt('ui.show_entry.sparse')}</span>
        <span class="len">${fmt.bytes(r.length)}</span></div>`
    : r.initialised === false
    ? `<div class="runbar slack" data-off="${r.offset}">
        <span>run ${n + 1} · uninitialised · 0x${fmt.hex(r.offset, 10)}</span>
        <span class="len">${fmt.bytes(r.length)}</span></div>`
    : `<div class="runbar" data-off="${r.offset}">
        <span>run ${n + 1} · 0x${fmt.hex(r.offset, 10)}</span>
        <span class="len">${fmt.bytes(r.length)}</span></div>`).join('');

  const jr = st.journal_recovery ? `<h3>${txt('ui.recovered_journal')}</h3>
    <div class="notice">${st.recovery}</div>
    ${kv([
      [txt('ui.kv.transaction'), jr_seq(st)],
      [txt('ui.kv.committed'), st.journal_recovery.committed ? 'yes' : 'no'],
      [txt('ui.kv.size_then'), fmt.bytes(st.journal_recovery.size)],
      [txt('ui.kv.modified_then'), fmt.time(st.journal_recovery.modified)],
      [txt('ui.kv.images_in_journal'), st.journal_recovery.versions_found],
    ])}` : '';

  const slack = st.slack ? `<h3>${txt('ui.show_entry.slack')}</h3>
    <div class="runbar slack" data-off="${st.slack.offset}">
      <span>0x${fmt.hex(st.slack.offset, 10)}</span>
      <span class="len">${st.slack.length} B</span></div>
    <p class="hint">${txt('help.bytes_after_end_file_inside_final_cluster')}</p>` : '';

  const stList = st.streams || (e.streams || []).map(x => ({ ...x }));
  const here = stream ? stream.name : '';
  const streams = !stList.length ? '' : `<h3>${txt('ui.data_streams')}</h3>
    ${stList.map(x => `
      <div class="runbar stream${x.name === here ? ' is-on' : ''}"
           data-stream="${esc(x.name)}">
        <span>${x.default ? '(unnamed \u2014 the file itself)' : esc(x.name)}${
          x.resident ? ' \u00b7 resident' : ''}${
          x.compressed ? ' \u00b7 compressed' : ''}${
          x.encrypted ? ' \u00b7 encrypted' : ''}</span>
        <span class="len">${fmt.bytes(x.size)}</span>
      </div>`).join('')}
    ${stList.length > 1 ? `<p class="hint">Named streams do not appear in a
      directory listing and are not counted in the file's size. Select one to
      read it.</p>` : ''}`;

  const xattrList = st.xattrs || [];
  const xattrs = !xattrList.length ? '' : `<h3>${txt('ui.extended_attributes')}</h3>
    ${xattrList.map(a => {
      const bytes = Uint8Array.from(atob(a.value || ''), c => c.charCodeAt(0));
      const preview = looksTextual(bytes)
        ? esc(decodeText(bytes).slice(0, 200))
        : Array.from(bytes.slice(0, 32))
            .map(b => b.toString(16).padStart(2, '0')).join(' ')
          + (bytes.length > 32 ? '…' : '');
      return `<div class="runbar">
          <span>${esc(a.name)}${a.truncated ? ' · truncated' : ''}</span>
          <span class="len">${fmt.bytes(a.size)}</span>
        </div>
        <div class="hint mono">${preview}</div>`;
    }).join('')}`;

  const ent = st.entropy && st.entropy.entropy !== null ? `<h3>${txt('ui.show_entry.entropy')}</h3>
    ${kv([
      [txt('ui.kv.bits_per_byte'), `${st.entropy.entropy.toFixed(3)} / 8`, true],
      [txt('ui.kv.reads_as'), st.entropy.band],
      [txt('ui.kv.measured_over'), fmt.bytes(st.entropy.bytes)
        + (st.entropy.sampled ? ' (sample)' : ' (whole file)')],
    ])}
    <p class="hint">${esc(st.entropy.note)}</p>` : '';

  const hb = st.hashes;
  const hashRows = !hb ? '' : kv([
    [txt('ui.kv.md5'), `<span class="mono">${esc(hb.md5 || '')}</span>`],
    [txt('ui.kv.sha_1'), `<span class="mono">${esc(hb.sha1 || '')}</span>`],
    [txt('ui.kv.sha_256'), `<span class="mono">${esc(hb.sha256 || '')}</span>`],
    [txt('ui.kv.computed'), fmt.time(hb.computed_at)],
    hb.partial && [txt('ui.hashed_over'), `${fmt.bytes(hb.read_bytes)} of ${
      fmt.bytes(hb.claimed_size)}`],
  ].filter(Boolean));

  const partialNote = !hb ? ''
    : hb.partial ? `<div class="notice bad">${txt('help.only_read_bytes_claimed_size_could_read', { read_bytes: fmt.bytes(hb.read_bytes), claimed_size: fmt.bytes(hb.claimed_size) })}</div>`
    : hb.read_unknown ? `<div class="notice">${txt('help.hash_recorded_before_tool_stored_how_much')}</div>`
    : '';

  const hits = (hb && hb.matches || []);
  const matchNote = !hits.length ? '' : `<div class="notice ${
    hits.some(m => m.kind === 'known_bad') ? 'bad' : ''}">${
    hits.map(m => `In <strong>${esc(m.set)}</strong> (${
      esc((m.kind || '').replace('_', ' '))})${
      m.label ? ` — ${esc(m.label)}` : ''}`).join('<br>')}</div>`;

  const hashBlock = stream ? '' : `<h3>${txt('ui.show_entry.hashes')}</h3>${hb
    ? hashRows + partialNote + matchNote
    : `<p class="hint">Not hashed. Nothing here has been read for a digest
       yet — this is an absence of work, not a property of the file.</p>`}`;

  const x = st.exif;
  const gps = x && x.coordinates;
  const exifBlock = !x ? '' : `<h3>${txt('ui.camera_metadata')}</h3>
    ${kv([
      x.summary.device && [txt('ui.kv.device'), x.summary.device, true],
      x.summary.serial && [txt('ui.kv.body_serial'), x.summary.serial],
      x.summary.owner && [txt('ui.kv.owner'), x.summary.owner],
      x.summary.lens && [txt('ui.kv.lens'), x.summary.lens],
      x.summary.software && [txt('ui.kv.software'), x.summary.software],
      x.summary.taken && [txt('ui.kv.taken'), x.summary.taken],
      [txt('ui.kv.byte_order'), x.byte_order],
    ].filter(Boolean))}
    <p class="hint">${esc(x.summary.note)}</p>
    ${!gps ? '' : gps.decoded ? `<h3>Location</h3>
      ${kv([
        [txt('ui.kv.latitude'), gps.latitude.toFixed(6), true],
        [txt('ui.kv.longitude'), gps.longitude.toFixed(6), true],
        gps.altitude_m !== undefined && [txt('ui.kv.altitude'), `${gps.altitude_m} m`],
        gps.fix_utc && [txt('ui.kv.gps_fix_utc'), gps.fix_utc],
      ].filter(Boolean))}
      ${gps.note ? `<div class="notice">${esc(gps.note)}</div>` : ''}
      ${gps.fix_note ? `<p class="hint">${esc(gps.fix_note)}</p>` : ''}`
      : `<div class="notice bad">${esc(gps.note)}</div>`}
    ${(x.thumbnail && Object.keys(x.thumbnail).length && x.thumbnail.DateTime
       && x.thumbnail.DateTime !== (x.image || {}).DateTime)
      ? `<div class="notice">The embedded thumbnail carries a different
          timestamp (${esc(x.thumbnail.DateTime)}) from the image itself.
          Thumbnails are not always rewritten when an image is edited.</div>`
      : ''}`;

  const missing = st.stream_missing ? `<div class="notice bad">${txt('help.record_stream_named_here_may_been_renamed', { here: esc(here) })}</div>` : '';

  i.innerHTML = `
    <div class="title">${esc(e.name)}${stream
      ? `<span class="stream-name">:${esc(stream.name)}</span>` : ''}</div>
    <div class="subtitle">${esc(e.path || '')}</div>
    ${missing}
    ${e.deleted && !st.journal_recovery
      ? `<div class="notice">${esc(st.recovery || 'Entry is marked deleted.')}</div>`
      : ''}
    ${kv([
      [txt('ui.kv.size'), fmt.bytes(stream ? stream.size : e.size), true],
      stream && [txt('ui.kv.file_size'), fmt.bytes(e.size)],
      e.short_name && [txt('ui.kv.short_name'), e.short_name],
      e.mft !== undefined && [txt('ui.kv.mft_record'), e.mft],
      e.inode !== undefined && [txt('ui.kv.inode'), e.inode],
      e.oid !== undefined && [txt('ui.kv.object_id'), e.oid],
      e.mode && [txt('ui.kv.mode'), e.mode],
      (e.uid !== undefined && e.uid !== null) && [txt('ui.kv.owner'), e.uid + ':' + e.gid],
      e.contiguous !== undefined && [txt('ui.kv.allocation'),
        e.contiguous ? 'contiguous (no FAT chain)' : 'FAT chain'],
      (e.valid_size !== undefined && e.valid_size !== e.size)
        && [txt('ui.kv.valid_data'), fmt.bytes(e.valid_size)],
      st.sequence !== undefined && [txt('ui.kv.sequence'), st.sequence],
      [txt('ui.kv.created'), fmt.time(e.created)],
      [txt('ui.kv.modified'), fmt.time(e.modified)],
      [txt('ui.kv.accessed'), fmt.time(e.accessed)],
      e.mft_modified && [txt('ui.kv.mft_changed'), fmt.time(e.mft_modified)],
    ])}
    ${streams}
    ${xattrs}
    ${exifBlock}
    ${ent}
    ${hashBlock}
    ${st.note ? `<div class="notice">${esc(st.note)}</div>` : ''}
    ${runs ? `<h3>Data runs</h3>${runs}`
      : (st.filesystem === 'AD1' || !e.size) ? ''
                                                                             
                                                                              
                                                                            
                                                                            
                                                                          
                                                                  
      : `<div class="notice">${e.inline
        ? 'Content is inline — stored inside the inode, with no blocks allocated.'
        : 'Content is resident — stored inside the MFT record itself, with no '
          + 'clusters allocated.'}</div>`}
    ${jr}
    ${slack}
    <div class="actions">
      ${                                                                 
                                                                              
                                                                            
                        ''}
      <button class="ghost" id="btn-goto-file"${
        entryOffset(st) == null && !fileBytes ? ' disabled' : ''
      }>${txt('ui.show_bytes')}</button>
      ${                                                                
                                                                       
                           ''}
      <button class="ghost" id="btn-export">${txt('ui.show_entry.export')}</button>
      <button class="ghost" id="btn-tag">${txt('ui.show_entry.tag')}</button>
      ${stream ? '' : `<button class="ghost" id="btn-hash-one">${
        hb ? 'Rehash' : 'Hash'}</button>`}
    </div>
    <div id="tag-strip" class="tag-strip"></div>`;

  $$('.runbar[data-stream]', i).forEach(el => el.addEventListener('click', () => {
    const name = el.dataset.stream;
    const want = stList.find(x => x.name === name) || null;
    showEntry(e, part, from, want && want.name ? want : null);
  }));

  $$('.runbar[data-off]', i).forEach(el => el.addEventListener('click', () => {
    S.cursor = +el.dataset.off;
    hex.reveal(S.cursor);
    updateStatus();
  }));
  $('#btn-goto-file')?.addEventListener('click',
    () => gotoEntry(st, part, e, stream));

  gotoEntry(st, part, e, stream);
  $('#btn-tag')?.addEventListener('click', () => tagDialog(e, part));
  renderTagStrip(e);
  $('#btn-export')?.addEventListener('click',
    () => exportEntryAs(e, part, stream ? stream.name : ''));
  $('#btn-hash-one')?.addEventListener('click',
    () => hashScope(partOffset(part), 'item', e, e.name));
}

async function exportEntryAs(e, part, stream = '', { addExhibit = false } = {}) {
  if (e.is_dir) {
    return toast(txt('messages.toast.folder_file_export_export_items'));
  }
  const label = stream ? `${e.name}:${stream}` : (e.name || 'file');
  const suggested = stream
    ? `${e.name || 'file'}.stream-${stream.replace(/[^\w.-]/g, '_')}`
    : (e.name || '');
  const dest = await pickPath({ mode: 'save', title: 'Export ' + label,
                                file: suggested });
  if (dest === null) {
    return exportEntry(e, part, null, stream, { addExhibit });
  }
  if (dest === '') return;
  return exportEntry(e, part, dest, stream, { addExhibit });
}

async function exportEntry(e, part, dest = null, stream = '',
                           { addExhibit = false } = {}) {
  if (e.is_dir) {
    return toast(txt('messages.toast.folder_file_export_export_items'));
  }
  const r = await api.post('export/file', {
    part: partOffset(part), entry: e,
    node: e.mft ?? e.inode ?? e.oid ?? e.start_cluster,
    name: e.name, path: e.path, size: e.size, dest, stream,
    add_exhibit: addExhibit });
  if (r.error) return toast(r.error);
  if (r.exhibit) {
    if (r.exhibit.added) {
      adoptOpened(r.exhibit.state);
      renderCases();
      const kind = r.exhibit.as === 'image'
        ? txt('ui.exhibit_kind.image') : txt('ui.exhibit_kind.logical');
      return toast(txt('messages.export.added_as_exhibit',
                       { name: e.name, path: r.path, kind }));
    }
    return toast(txt('messages.export.exhibit_not_added',
                     { name: e.name, path: r.path, error: r.exhibit.error }));
  }
  toast(`Exported ${stream ? `${e.name}:${stream}` : e.name} to ${r.path} · `
      + `SHA-256 ${r.sha256.slice(0, 16)}…`);
}

const COPY_MAX = 1 << 20;

async function rangeBytes(start, length) {
  const r = S.scope.entry
    ? await api.get('hex', { offset: start, length, part: S.scope.part,
                             entry: JSON.stringify(S.scope.entry),
                             stream: S.scope.stream || undefined })
    : await api.get('hex', { offset: start + (S.scope.part || 0),
                             length, part: null });
  if (r.error) throw new Error(r.error);
  return b64ToBytes(r.data);
}

const hexOf = bytes => [...bytes]
  .map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' ');

const textOf = bytes => [...bytes]
  .map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('');

async function toClipboard(text, what) {
  if (await writeClipboard(text)) {
    toast(txt('messages.toast.copied_characters', { what: what, characters: text.length.toLocaleString() }), 'action');
  } else {
    showCopyFallback(text, what);
  }
}

async function writeClipboard(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {                                                    }

  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.top = '-1000px';
  document.body.appendChild(ta);
  ta.select();
  ta.setSelectionRange(0, text.length);
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch { ok = false; }
  ta.remove();
  return ok;
}

function showCopyFallback(text, what) {
  let dlg = $('#dlg-copy');
  if (!dlg) {
    dlg = document.createElement('dialog');
    dlg.id = 'dlg-copy';
    dlg.innerHTML = `
      <form method="dialog" class="dlg">
        <h2 id="copy-what">${txt('ui.show_copy_fallback.copy')}</h2>
        <p class="hint">${txt('help.browser_would_write_clipboard_own_usually_needs')}</p>
        <textarea id="copy-text" rows="6" readonly
                  style="width:100%;font-family:var(--mono, monospace);
                         font-size:12px"></textarea>
        <menu><button value="ok" class="solid">${txt('ui.show_copy_fallback.done')}</button></menu>
      </form>`;
    document.body.appendChild(dlg);
  }
  $('#copy-what', dlg).textContent = what;
  const ta = $('#copy-text', dlg);
  ta.value = text;
  dlg.showModal();
  ta.focus();
  ta.select();
}

async function copyRange(start, length, as) {
  if (length > COPY_MAX) {
    return toast(txt('help.selection_value_copying_limited_copy_max_export', { value: fmt.bytes(length), COPY_MAX: fmt.bytes(COPY_MAX) }));
  }
  let bytes;
  try {
    bytes = await rangeBytes(start, length);
  } catch (e) {
    return toast(txt('messages.toast.could_read_those_bytes_message', { message: e.message }));
  }
  if (bytes.length < length) {
    toast(txt('messages.only_value_value2_could_read_copying', { value: fmt.bytes(bytes.length), value2: fmt.bytes(length) }));
  }
  return toClipboard(as === 'hex' ? hexOf(bytes) : textOf(bytes),
                     as === 'hex' ? 'Hex' : 'Text');
}

function hexMenu(ev) {
  const b = hex.c.getBoundingClientRect();
  const clicked = hex.hitTest(ev.clientX - b.left, ev.clientY - b.top);

  let sel = S.selection;
  const inSel = sel && sel.length > 0 && clicked !== null
             && clicked >= sel.start && clicked < sel.start + sel.length;
  if (!inSel && clicked !== null) {
    sel = { start: clicked, length: 1 };
    S.cursor = clicked;
    S.selection = sel;
    hex.draw();
    updateStatus();
  }
  const has = sel && sel.length > 0;
  const why = txt('help.click_did_land_byte_right_click_values');

  openMenu(ev.clientX, ev.clientY, [
    { label: txt('ui.copy_selection_hex'),
      hint: has ? fmt.bytes(sel.length) : '',
      disabled: !has,
      why,
      action: () => copyRange(sel.start, sel.length, 'hex') },
    { label: txt('ui.copy_selection_text'),
      hint: has ? fmt.bytes(sel.length) : '',
      disabled: !has,
      why,
      action: () => copyRange(sel.start, sel.length, 'text') },
  ]);
}

const PV_MAX = 1 << 20;

function printableRuns(bytes, min = 4, cap = 200) {
  const out = [];
  let cur = '';
  for (const c of bytes) {
    if (c >= 32 && c < 127) { cur += String.fromCharCode(c); }
    else { if (cur.length >= min) out.push(cur); cur = ''; }
    if (out.length >= cap) return out;
  }
  if (cur.length >= min) out.push(cur);
  return out;
}

const ascii = s => [...s].map(c => c.charCodeAt(0));

const MAGIC = [
  { ext: 'png',  mime: 'image/png',  raster: true, kind: 'image', sig: [0x89, 0x50, 0x4E, 0x47] },
  { ext: 'jpeg', mime: 'image/jpeg', raster: true, kind: 'image', sig: [0xFF, 0xD8, 0xFF] },
  { ext: 'gif',  mime: 'image/gif',  raster: true, kind: 'image', sig: [0x47, 0x49, 0x46, 0x38] },
  { ext: 'bmp',  mime: 'image/bmp',  raster: true, kind: 'image', sig: [0x42, 0x4D] },
  { ext: 'ico',  mime: 'image/x-icon', raster: true, kind: 'image', sig: [0x00, 0x00, 0x01, 0x00] },
  { ext: 'tiff', mime: 'image/tiff', kind: 'image', sig: [0x49, 0x49, 0x2A, 0x00] },
  { ext: 'tiff', mime: 'image/tiff', kind: 'image', sig: [0x4D, 0x4D, 0x00, 0x2A] },
  { ext: 'psd',  kind: 'image', sig: ascii('8BPS') },

  { ext: 'pdf',  mime: 'application/pdf', kind: 'doc', sig: ascii('%PDF') },
  { ext: 'rtf',  kind: 'doc', sig: ascii('{\\rtf') },

  { ext: 'ole2', kind: 'office', label: 'Office (OLE2) document',
    sig: [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] },

  { ext: 'sqlite', kind: 'db', label: txt('ui.sqlite_database'),
    sig: ascii(txt('ui.sqlite_format_3')) },
  { ext: 'esedb', kind: 'db', label: txt('ui.ese_database'), at: 4,
    sig: [0xEF, 0xCD, 0xAB, 0x89] },
  { ext: 'regf', kind: 'registry', label: txt('ui.windows_registry_hive'), sig: ascii('regf') },
  { ext: 'evtx', kind: 'log', label: txt('ui.windows_event_log'), sig: ascii('ElfFile') },
  { ext: 'lnk',  kind: 'meta', label: txt('ui.windows_shortcut'),
    sig: [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00] },
  { ext: 'pf',   kind: 'meta', label: 'Prefetch (compressed)', sig: ascii('MAM\x04') },

  { ext: 'zip',  kind: 'archive', sig: [0x50, 0x4B, 0x03, 0x04] },
  { ext: 'gzip', kind: 'archive', sig: [0x1F, 0x8B] },
  { ext: 'rar',  kind: 'archive', sig: ascii('Rar!') },
  { ext: '7z',   kind: 'archive', sig: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] },
  { ext: 'cab',  kind: 'archive', sig: ascii('MSCF') },
  { ext: 'xz',   kind: 'archive', sig: [0xFD, 0x37, 0x7A, 0x58, 0x5A] },

  { ext: 'exe',  kind: 'exec', label: txt('ui.windows_executable'), sig: [0x4D, 0x5A] },
  { ext: 'elf',  kind: 'exec', label: 'ELF binary', sig: [0x7F, 0x45, 0x4C, 0x46] },

  { ext: 'mp3',  kind: 'audio', sig: ascii('ID3') },
  { ext: 'flac', kind: 'audio', sig: ascii('fLaC') },
  { ext: 'ogg',  kind: 'audio', sig: ascii('OggS') },
  { ext: 'mkv',  mime: 'video/webm', kind: 'video', sig: [0x1A, 0x45, 0xDF, 0xA3] },
];

const OOXML = [
  [/^word\//, txt('ui.word_document_docx')],
  [/^ppt\//, txt('ui.powerpoint_presentation_pptx')],
  [/^xl\//, txt('ui.excel_workbook_xlsx')],
  [/^mimetypeapplication\/vnd\.oasis/, txt('ui.opendocument_file')],
];

function sniffZip(b) {
  if (b.length < 32) return null;
  const n = b[26] | (b[27] << 8);
  const name = String.fromCharCode(...b.slice(30, Math.min(30 + n, b.length)));
  const probe = name + String.fromCharCode(...b.slice(30, 120)).replace(/[^\x20-\x7e]/g, '');
  for (const [re, label] of OOXML) {
    if (re.test(name) || re.test(probe)) {
      return { ext: 'ooxml', kind: 'office', label };
    }
  }
  return null;
}

function sniffIsoBmff(b) {
  if (b.length < 12 || String.fromCharCode(...b.slice(4, 8)) !== 'ftyp') return null;
  const brand = String.fromCharCode(...b.slice(8, 12)).trim();
  const heic = ['heic', 'heix', 'hevc', 'mif1'].includes(brand);
  return {
    ext: brand.toLowerCase(),
    kind: heic ? 'image' : 'video',
    mime: heic ? 'image/heic' : (brand === 'qt' ? 'video/quicktime' : 'video/mp4'),
    label: heic ? 'HEIF/HEIC image'
         : brand.startsWith('qt') ? txt('ui.quicktime_video_mov')
         : txt('ui.mp4_family_video_brand') + brand + '")',
  };
}

function sniff(b) {
  const iso = sniffIsoBmff(b);
  if (iso) return iso;
  if (b.length >= 12 && String.fromCharCode(...b.slice(0, 4)) === 'RIFF') {
    const form = String.fromCharCode(...b.slice(8, 12));
    if (form === 'WEBP') return { ext: 'webp', mime: 'image/webp', raster: true, kind: 'image' };
    if (form === 'AVI ') return { ext: 'avi', kind: 'video', label: 'AVI video' };
    if (form === 'WAVE') return { ext: 'wav', kind: 'audio', label: 'WAV audio' };
  }
  for (const m of MAGIC) {
    const at = m.at || 0;
    if (b.length >= at + m.sig.length &&
        m.sig.every((v, i) => b[at + i] === v)) {
      return (m.ext === 'zip' && sniffZip(b)) || m;
    }
  }
  return null;
}

function looksTextual(b) {
  const n = Math.min(b.length, 4096);
  if (!n) return false;
  let odd = 0;
  for (let i = 0; i < n; i++) {
    const c = b[i];
    if (c === 9 || c === 10 || c === 13) continue;
    if (c < 32 || c === 0) odd++;
  }
  return odd / n < 0.05;
}

function decodeText(b) {
  if (b.length >= 2 && b[0] === 0xFF && b[1] === 0xFE) {
    return new TextDecoder('utf-16le').decode(b.slice(2));
  }
  if (b.length >= 2 && b[0] === 0xFE && b[1] === 0xFF) {
    return new TextDecoder('utf-16be').decode(b.slice(2));
  }
  const s = b.length >= 3 && b[0] === 0xEF && b[1] === 0xBB && b[2] === 0xBF
    ? b.slice(3) : b;
  return new TextDecoder('utf-8', { fatal: false }).decode(s);
}

function b64ToBytes(s) {
  const bin = atob(s || '');
  const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  return a;
}

const KIND_GLYPH = {
  image: '▤', video: '▶', audio: '♪', doc: '▦', office: '▦', archive: '▩',
  exec: '⚙', db: '▤', registry: '▨', log: '≡', meta: '◈', binary: '▪',
};

const KIND_WHY = {
  doc: txt('messages.rendering_would_need_pdf_engine_tool_embed'),
  office: txt('messages.container_format_text_lives_compressed_parts_inside'),
  archive: txt('messages.contents_compressed_nothing_readable_sits_top_level'),
  video: txt('messages.browser_could_decode_container_codec'),
  audio: txt('messages.browser_could_decode_container_codec'),
  exec: txt('messages.nothing_meaningful_render_binary'),
  db: txt('messages.structured_storage_tables_inside_surface'),
  registry: txt('messages.open_registry_tab_browse_keys_values'),
  log: txt('messages.structured_binary_log_records_plain_text'),
  meta: txt('messages.small_binary_metadata_record'),
};

function typedCard(kind, e, truncated) {
  const label = kind.label
    || (kind.ext ? kind.ext.toUpperCase() + ' file' : txt('ui.unrecognised_binary'));
  const glyph = KIND_GLYPH[kind.kind] || KIND_GLYPH.binary;
  const why = truncated
    ? txt('messages.only_first_pv_max_read_cannot_rendered', { PV_MAX: fmt.bytes(PV_MAX) })
    : (KIND_WHY[kind.kind] || txt('messages.inline_viewer_format'));
  return `<div class="pv-card">
    <span class="pv-glyph">${glyph}</span>
    <div>
      <strong>${esc(label)}</strong>
      <span class="pv-meta">${fmt.bytes(e.size)}${
        kind.ext ? ' · ' + esc(kind.ext) : ''}</span>
      <p class="hint">${txt('help.why_bytes_intact_shown_below_export_writes', { why: esc(why) })}</p>
    </div>
  </div>`;
}

function fileURL(entry, part) {
  const q = new URLSearchParams({ part: part.offset, entry: JSON.stringify(entry) });
  return `/api/file?${q}`;
}

function thumbnailURL(entry, part) {
  const q = new URLSearchParams({ part: part.offset, entry: JSON.stringify(entry) });
  return `/api/thumbnail?${q}`;
}

function dirSet(name, meta, html) {
  $('#dir-name').textContent = name;
  $('#dir-meta').textContent = meta || '';
  $('#dirlist').innerHTML = html;
}

function pvSet(title, kind, html) {
  $('#preview-title').textContent = title;
  $('#preview-kind').textContent = kind || '';
  $('#preview-body').innerHTML = html;
}

function setViewerPane(name) {
  const v = $('#viewer');
  if (!v || (name !== 'hex' && name !== 'preview')) return;
  v.dataset.pane = name;
  $$('.viewer-tabs .tab').forEach(t => {
    const on = t.dataset.pane === name;
    t.classList.toggle('is-on', on);
    t.setAttribute('aria-selected', String(on));
  });
  if (name === 'hex') hex.resize();
}

const GLYPH = { dir: '▣', img: '▤', txt: '≡', bin: '▪' };

const IMG_RE = /\.(png|jpe?g|gif|bmp|webp|ico|tiff?|heic|avif)$/i;

let hashMap = { ev: null, part: null, map: {} };

async function loadHashMap(part, force = false) {
  if (!force && hashMap.part === part && hashMap.ev === S.activeId) return;
  const r = await api.get('hashmap', { part }).catch(() => null);
  hashMap = { ev: S.activeId, part, map: (r && r.map) || {} };
}

const nodeOf = e => String(e.mft ?? e.inode ?? e.oid ?? e.start_cluster ?? '');

const PAGE_ROWS = 400;

const PAGE_AHEAD = 600;

function folderOf(e) {
  const p = e.path || '';
  const cut = p.lastIndexOf('/');
  const dir = cut > 0 ? p.slice(0, cut) : (cut === 0 ? '/' : '');
  const root = dirView.rootPath;
  if (!root || root === '/') return dir;
  if (dir === root) return '/';
  return dir.startsWith(root + '/') ? dir.slice(root.length) : dir;
}

const dirView = {
  mode: 'list',
  sort: 'name',
  desc: false,
  filter: '',
  recursive: false,
  shown: PAGE_ROWS,
  rootPath: null,
  truncated: false,
  budget: 0,
  entries: [], name: '', part: null, id: undefined,
  self: null,
  trail: [],
};

function resetDirView() {
  dirView.mode = 'list';
  dirView.sort = 'name';
  dirView.desc = false;
  dirView.filter = '';
  dirView.shown = PAGE_ROWS;
  dirView.entries = [];
  dirView.name = '';
  dirView.part = null;
  dirView.id = undefined;
  dirView.self = null;
  dirView.trail = [];
  dirView.recursive = false;
  dirView.rootPath = null;
  dirView.truncated = false;
  dirView.budget = 0;
  lastPulse = null;
  walkCache.clear();
  markListScope();
}

function enterCase(next) {
  if ((next || null) === (S.casePath || null)) return;
  resetDirView();
}

function hashOf(e, which = 'sha256') {
  const h = hashMap.map[nodeOf(e)];
  return h ? h[which] : null;
}

function matchOf(e) {
  const h = hashMap.map[nodeOf(e)];
  return h ? h.match_kind : null;
}

function glyphFor(e) {
  return e.is_dir ? GLYPH.dir
    : IMG_RE.test(e.name) ? GLYPH.img
    : /\.(txt|log|csv|xml|json|ini|cfg|md)$/i.test(e.name) ? GLYPH.txt
    : GLYPH.bin;
}

function sortEntries(list) {
  const k = dirView.sort;
  const val = e => k === 'name' ? (e.name || '').toLowerCase()
    : k === 'size' ? (e.size || 0)
    : (e[k] || '');
  const dir = dirView.desc ? -1 : 1;
  return [...list].sort((a, b) => {
    if (!dirView.recursive && !!a.is_dir !== !!b.is_dir) {
      return a.is_dir ? -1 : 1;
    }
    const x = val(a), y = val(b);
    return (x < y ? -1 : x > y ? 1 : 0) * dir;
  });
}

function navEntries() {
  if (dirView.recursive) return [];
  const out = [];
  if (dirView.self) {
    out.push({ ...dirView.self, name: '.', _nav: 'self',
               _label: dirView.self.name || txt('ui.folder') });
  }
  if (dirView.self || (dirView.trail || []).length) {
    const up = (dirView.trail || []).at(-1);
    out.push({ is_dir: true, name: '..', _nav: 'up',
               _label: up ? (up.name || 'up') : txt('ui.volume_root') });
  }
  return out;
}

function visibleEntries() {
  const q = dirView.filter.trim().toLowerCase();
  const base = q ? dirView.entries.filter(e =>
    (e.name || '').toLowerCase().includes(q)) : dirView.entries;
  return sortEntries(base);
}

async function previewDir(entries, name, part, id = undefined, self = null,
                          parent = null, scope = null) {
  await loadHashMap(partOffset(part));
  if (scope) {
    dirView.trail = [];
  } else if (!parent) {
    dirView.trail = [];
  } else if (sameVolume(part, dirView.part)
             && parent.id === dirView.id && dirView.id !== id) {
    dirView.trail = [...(dirView.trail || []),
                     { id: dirView.id, name: dirView.name, self: dirView.self }];
  } else if (parent.id !== id) {
    dirView.trail = [{ id: parent.id, name: parent.name,
                       self: parent.self || null }];
  }
  dirView.entries = entries;
  dirView.name = name;
  dirView.part = part;
  dirView.id = id;
  dirView.self = self;
  dirView.shown = PAGE_ROWS;
  dirView.recursive = !!(scope && scope.recursive);
  dirView.rootPath = scope ? scope.rootPath : null;
  dirView.truncated = !!(scope && scope.truncated);
  dirView.budget = scope ? scope.budget || 0 : 0;
  renderDirView();
  markListScope();
  revealInTree(part, id);
}

async function dirUp() {
  const part = dirView.part;
  const trail = dirView.trail || [];
  if (!trail.length) {
    const p = (S.volumes?.partitions || [])
      .find(x => x.offset === partOffset(part)) || part;
    return previewRoot(p);
  }
  const back = trail[trail.length - 1];
  dirView.trail = trail.slice(0, -1);
  const r = await fetchDir(partOffset(part), back.id, back.self?.path || "/");
  if (r.error) return toast(r.error);
  dirView.entries = r.entries;
  dirView.name = back.name;
  dirView.id = back.id;
  dirView.self = back.self;
  await loadHashMap(partOffset(part));
  renderDirView();
  revealInTree(part, back.id);
}

async function listAllBelow(part, e = null) {
  if (!await useOwner(part)) return;
  const node = e ? (e.mft ?? e.inode ?? e.oid ?? e.start_cluster) : null;
  const root = e ? (e.path || '/') : '/';
  const label = e ? (e.name || root) : txt('ui.dir.at_root');
  const scopeName = txt('ui.dir.scope_below', { name: label });

  const key = walkKey(part, node);
  const kept = walkCache.get(key);
  if (kept) {
    return previewDir(kept.entries, scopeName, part, node, e, null,
                      { recursive: true, rootPath: kept.root_path,
                        truncated: kept.truncated, budget: kept.budget });
  }

  const ask = () => api.post('dir/recurse', {
    part: partOffset(part), ev: part.ev_id ?? undefined,
    node: node ?? undefined, path: root, name: label });

  let t = await ask();
  if (t.building) {
    const done = await awaitTask(t.task, 'Indexing MFT', {
      modal: { title: txt('ui.indexing_master_file_table'),
               detail: txt('help.strata_reads_directory_tree_file_name_parent') },
    });
    if (!done) return toast(txt('messages.indexing_interrupted'));
    t = await ask();
  }
  if (t.error) return toast(t.error);

  const r = await awaitTask(t, scopeName, {
    indeterminate: true,
    modal: { title: scopeName, detail: t.detail },
  });
  if (!r) return;
  if (r.error) return toast(r.error);
  walkCache.set(key, r);

  await previewDir(r.entries, scopeName, part, node, e, null,
                   { recursive: true, rootPath: r.root_path,
                     truncated: r.truncated, budget: r.budget });
}

function renderDirView() {
  const { name, part } = dirView;
  const nav = navEntries();
  const matched = visibleEntries();
  const entries = nav.concat(matched);
  const dirs = dirView.entries.filter(e => e.is_dir).length;
  const del = dirView.entries.filter(e => e.deleted).length;
  const imgs = dirView.entries.filter(e => !e.is_dir && IMG_RE.test(e.name));

  const bar = `
    <div class="dv-bar">
      <div class="dv-modes">
        ${['list', 'gallery'].map(m =>
          `<button class="dv-mode ${dirView.mode === m ? 'is-on' : ''}"
             data-mode="${m}">${m}</button>`).join('')}
      </div>
      <input type="text" class="dv-filter" id="dv-filter" placeholder="${txt('ui.filter_placeholder')}"
             value="${esc(dirView.filter)}">
      <span class="dv-count">${fmt.count(matched.length)}/${
        fmt.count(dirView.entries.length)}</span>
    </div>`;

  const wide = dirView.recursive;

  const rowsHTML = (from, to) => entries.slice(from, to).map((e, n) => {
    const i = from + n;
    const t = e.type_check;
    const bad = t && t.mismatch;
    const mk = matchOf(e);
    return `
        <tr data-i="${i}" class="${e._nav ? 'is-nav ' : ''}${
      e.deleted ? 'is-del' : ''}${bad ? ' is-typemis' : ''}${
      mk ? ' is-match-' + mk : ''}">
          <td class="nm"><span class="g">${e._nav ? '▲' : glyphFor(e)}</span>${
      esc(e.name)}${e._nav ? ` <span class="mis">${esc(e._label)}</span>` : ''}${
      bad ? ` <span class="mis" title="${esc(t.why)}">renamed?</span>` : ''}${
      mk ? ` <span class="hash-flag ${esc(mk)}">${esc(mk.replace('_', ' '))}</span>` : ''}</td>
          ${wide ? `<td class="c-path" title="${esc(e.path || '')}">${
        esc(folderOf(e))}</td>` : ''}
          <td class="sz">${e.is_dir ? '—' : fmt.bytes(e.size)}</td>
          <td class="ty2 c-ty">${esc(t ? (t.extension_says || '—') : '')}</td>
          <td class="ty2 c-ty${bad ? ' bad' : ''}">${esc(t ? (t.content_is
        || (t.verdict === 'no signature' ? 'no signature' : '—')) : '')}</td>
          <td class="dt">${fmt.time(e.created)}</td>
          <td class="dt">${fmt.time(e.modified)}</td>
          <td class="dt">${fmt.time(e.accessed)}</td>
          <td class="ty2 mono c-hash" title="${esc(hashOf(e, 'md5') || '')}">${
      e.is_dir ? '' : (hashOf(e, 'md5')
        ? esc(hashOf(e, 'md5').slice(0, 12)) + '…' : '')}</td>
          <td class="ty2 mono c-hash" title="${esc(hashOf(e) || '')}">${
      e.is_dir ? '' : (hashOf(e) ? esc(hashOf(e).slice(0, 12)) + '…' : '')}</td>
        </tr>`;
  }).join('');

  const shots = entries.map((e, i) => [e, i])
                       .filter(([e]) => !e.is_dir && IMG_RE.test(e.name));
  const shotsHTML = (from, to) => shots.slice(from, to).map(([e, i]) => `
        <figure class="dv-shot" data-i="${i}">
          <img loading="lazy" alt="" src="${thumbnailURL(e, part)}"
               data-full="${esc(fileURL(e, part))}">
          <figcaption class="${e.deleted ? 'is-del' : ''}"
            title="${esc(e.name)}">${esc(e.name)}</figcaption>
        </figure>`).join('');

  const total = dirView.mode === 'gallery' ? shots.length : entries.length;
  const shown = Math.min(dirView.shown || PAGE_ROWS, total);

  let body;
  if (!entries.length) {
    body = `<p class="empty">${txt('messages.empty_directory')}</p>`;
  } else if (dirView.mode === 'gallery') {
    body = shots.length
      ? `<div class="dv-gallery">${shotsHTML(0, shown)}</div>`
      : `<p class="empty">${txt('ui.images_folder')}</p>`;
  } else {
    const th = (k, label, cls = '', title = '') =>
      `<th data-sort="${k}" class="${cls ? cls + ' ' : ''}${
        dirView.sort === k ? 'is-on ' + (dirView.desc ? 'desc' : 'asc') : ''
      }"${title ? ` title="${esc(title)}"` : ''}>${label}</th>`;
    body = `<table class="dv-list${wide ? ' is-flat' : ''}">
      <thead><tr>${th('name', txt('ui.col.name'))}${
        wide ? th('path', txt('ui.col.path'), 'c-path',
                  txt('ui.dir.title_path')) : ''}${th('size', txt('ui.kv.size'))}
        <th class="c-ty" title="${txt('ui.dir.title_extension')}">${txt('ui.render_dir_view.extension')}</th>
        <th class="c-ty" title="${txt('ui.dir.title_signature')}">${txt('ui.render_dir_view.signature')}</th>
        ${th('created', txt('ui.kv.created'))}${th('modified', txt('ui.kv.modified'))}
        ${th('accessed', txt('ui.kv.accessed'))}
        <th class="c-hash" title="${txt('ui.dir.title_md5')}">${txt('ui.render_dir_view.md5')}</th>
        <th class="c-hash" title="${txt('ui.dir.title_sha256')}"
          >${txt('ui.render_dir_view.sha')}</th></tr></thead>
      <tbody>${rowsHTML(0, shown)}</tbody></table>`;
    if (!dirView.entries.length) {
      body += `<p class="empty">${txt('messages.empty_directory')}</p>`;
    }
  }

  let note = '';
  if (dirView.truncated) {
    note += `<p class="dv-note is-warn">${txt('messages.recurse_truncated',
      { budget: fmt.count(dirView.budget) })}</p>`;
  }

  $('#dir-name').textContent = name;
  $('#dir-meta').textContent = `${fmt.count(dirView.entries.length)} items · ${
    fmt.count(dirs)} folders${del ? ` · ${fmt.count(del)} deleted` : ''}${
    imgs.length ? ` · ${fmt.count(imgs.length)} images` : ''}`;
  const tail = shown < total
    ? `<p class="dv-more">${txt('messages.list_showing_some',
        { shown: fmt.count(shown), total: fmt.count(total) })}</p>`
    : '';

  $('#dirlist').innerHTML =
    `<div class="pv-dir">${bar}${note}<div class="dv-body">${body}${tail}</div></div>`;

  const open = i => {
    const e = entries[i];
    if (!e) return;
    if (e._nav === 'up') return dirUp();
    showEntry(e, part, { entries: dirView.entries, name: dirView.name,
                         id: dirView.id, self: dirView.self });
  };
  const menu = (el, ev) => {
    ev.preventDefault();
    const e = entries[+el.dataset.i];
    if (!e || e._nav === 'up') return;
    openMenu(ev.clientX, ev.clientY, entryMenu(e, part), el);
  };
  const bodyEl = $('#dirlist .dv-body');
  const rowUnder = t => t.closest?.('tr[data-i], .dv-shot[data-i]') || null;
  bodyEl?.addEventListener('click', ev => {
    const el = rowUnder(ev.target);
    if (el) open(+el.dataset.i);
  });
  bodyEl?.addEventListener('contextmenu', ev => {
    const el = rowUnder(ev.target);
    if (el) menu(el, ev);
  });
  // Thumbnails try the (much cheaper) embedded EXIF thumbnail first; img
  // error events don't bubble, so this listens on the capture phase to
  // catch them from any <img> under bodyEl, including ones grow() adds
  // later. data-retried guards against looping if the full image 404s too.
  bodyEl?.addEventListener('error', ev => {
    const img = ev.target;
    if (img.tagName === 'IMG' && img.dataset.full && !img.dataset.retried) {
      img.dataset.retried = '1';
      img.src = img.dataset.full;
    }
  }, true);

  if (bodyEl && shown < total) {
    let drawn = shown;
    let adding = false;
    const grow = () => {
      if (adding || drawn >= total) return;
      if (bodyEl.scrollTop + bodyEl.clientHeight
          < bodyEl.scrollHeight - PAGE_AHEAD) return;
      adding = true;
      const next = Math.min(drawn + PAGE_ROWS, total);
      const holder = dirView.mode === 'gallery'
        ? $('#dirlist .dv-gallery') : $('#dirlist .dv-list tbody');
      holder?.insertAdjacentHTML('beforeend',
        dirView.mode === 'gallery' ? shotsHTML(drawn, next)
                                   : rowsHTML(drawn, next));
      drawn = next;
      dirView.shown = drawn;
      const more = $('#dirlist .dv-more');
      if (drawn >= total) more?.remove();
      else if (more) {
        more.textContent = txt('messages.list_showing_some',
          { shown: fmt.count(drawn), total: fmt.count(total) });
      }
      adding = false;
      grow();
    };
    bodyEl.addEventListener('scroll', grow, { passive: true });
    grow();
  }
  $$('#dirlist .dv-mode').forEach(el => el.addEventListener('click', () => {
    dirView.mode = el.dataset.mode;
    dirView.shown = PAGE_ROWS;
    renderDirView();
  }));
  $$('#dirlist .dv-list th[data-sort]').forEach(el =>
    el.addEventListener('click', () => {
      const k = el.dataset.sort;
      dirView.desc = dirView.sort === k ? !dirView.desc : false;
      dirView.sort = k;
      dirView.shown = PAGE_ROWS;
      renderDirView();
    }));
  const f = $('#dv-filter');
  if (f) {
    f.addEventListener('input', () => {
      dirView.filter = f.value;
      dirView.shown = PAGE_ROWS;
      const at = f.selectionStart;
      renderDirView();
      const nf = $('#dv-filter');
      nf.focus();
      nf.setSelectionRange(at, at);
    });
  }
}

let pvToken = null;

async function previewEntry(e, part, from = null, stream = null) {
  if ($('#panel-hex-off')) return;
  const token = Symbol();
  pvToken = token;

  if (from && !e.is_dir && dirView.id !== from.id) {
    previewDir(from.entries, from.name, part, from.id, from.self || null);
  }

  if (e.is_dir) {
    pvSet(e.name || txt('ui.preview.preview_title'), '',
          `<p class="empty">${txt('messages.folder_has_a_listing_not_a_preview')}</p>`);
    const nodeId = e.mft ?? e.inode ?? e.oid ?? e.start_cluster;
    if (!dirCache.has(dirKey(part.offset, nodeId, part.ev_id))) {
      dirSet(e.name, 'reading…', `<p class="empty">${txt('ui.reading_directory')}</p>`);
    }
    const r = await fetchDir(part.offset, nodeId, e.path, part.ev_id);
    if (pvToken !== token) return;
    if (r.error) return dirSet(e.name, 'error', `<p class="empty">${esc(r.error)}</p>`);
    return previewDir(r.entries, e.name, part, nodeId, e, from);
  }

  const label = stream ? `${e.name}:${stream.name}` : e.name;
  const size = stream ? stream.size : e.size;

  if (!size) {
    return pvSet(label, 'empty', stream
      ? `<p class="pv-note">${txt('help.stream_present_record_holds_bytes_empty_stream')}</p>`
      : `<p class="pv-note">${txt('ui.file_content')}</p>`);
  }

  pvSet(label, 'reading…', `<p class="empty">${txt('ui.preview_entry.reading')}</p>`);
  const want = Math.min(size, PV_MAX);
  const r = await api.get('preview', { part: part.offset,
                                       entry: JSON.stringify(e), length: want,
                                       stream: stream ? stream.name : undefined });
  if (pvToken !== token) return;
  if (r.error) return pvSet(label, 'error', `<p class="empty">${esc(r.error)}</p>`);

  const bytes = b64ToBytes(r.data);
  if (!bytes.length) {
    return pvSet(label, 'no data',
      `<p class="pv-note">${txt('help.readable_content_clusters_may_unallocated_overwritten')}</p>`);
  }
  const truncated = size > bytes.length;
  const kind = sniff(bytes);

  if (stream) {
    const head = kind ? `${kind.ext} · ` : '';
    if (looksTextual(bytes)) {
      const text = decodeText(bytes);
      const cut = text.length > 20000 ? text.slice(0, 20000) : text;
      return pvSet(label, `${head}stream${truncated ? ' · truncated' : ''}`,
        `<pre class="pv-text">${escText(cut)}</pre>`);
    }
    const strs = printableRuns(bytes);
    return pvSet(label, `${head}stream · strings`,
      (strs.length ? `<pre class="pv-text">${escText(strs.join('\n'))}</pre>` : '')
      + `<p class="pv-note">${strs.length
          ? txt('ui.stream.note', { size: fmt.bytes(size) })
          : txt('ui.stream.note_no_strings', { size: fmt.bytes(size) })}</p>`);
  }

  if (kind?.ext === 'regf') return openRegistry(e, part);
  if (kind?.ext === 'evtx') return openEventLog(e, part);
  if (kind?.ext === 'sqlite') return openSqlite(e, part);
  if (kind?.ext === 'esedb') return openEse(e, part);
  if (/\.(ldb|sst)$/i.test(e.name) ||
      (/\.log$/i.test(e.name) &&
       /(Local|Session) Storage|IndexedDB|Sync Data|leveldb/i.test(e.path || ''))) {
    return openLevelDb(e, part);
  }

  const streamURL = fileURL(e, part);

  if (kind?.raster || (kind?.kind === 'image' && kind.mime)) {
    return pvSet(e.name, kind.ext,
      `<div class="pv-image"><img alt="" src="${streamURL}"></div>`);
  }

  if (kind?.kind === 'office') return openDocument(e, part);
  if (kind?.ext === 'zip' || (kind?.kind === 'archive' && kind.ext === 'zip')) {
    return openArchive(e, part);
  }
  if (kind?.ext === 'pdf') return openPdf(e, part);
  const markup = markupKind(bytes, e.name);
  if (markup) return openMarkup(e, part, markup);

  if (kind?.kind === 'video' || kind?.kind === 'audio') {
    const tag = kind.kind === 'video' ? 'video' : 'audio';
    return pvSet(e.name, kind.ext, `
      <div class="pv-media">
        <${tag} controls preload="metadata" src="${streamURL}"></${tag}>
        <p class="hint">${txt('help.ext_size_decoded_browser_play_codec_inside', { ext: esc(kind.label || kind.ext.toUpperCase()), size: fmt.bytes(e.size) })}</p>
      </div>`);
  }

  if (kind && !looksTextual(bytes)) {
    return pvSet(e.name, kind.ext, typedCard(kind, e, truncated));
  }

  if (looksTextual(bytes)) {
    const text = decodeText(bytes);
    const cut = text.length > 20000 ? text.slice(0, 20000) : text;
    return pvSet(e.name, [kind?.ext, 'text', truncated && 'truncated']
      .filter(Boolean).join(' · '), `<pre class="pv-text">${escText(cut)}</pre>`);
  }

  const strs = printableRuns(bytes);
  pvSet(e.name, 'binary · strings',
    strs.length ? `<pre class="pv-text">${escText(strs.join('\n'))}</pre>`
      : `<p class="pv-note">${txt('ui.binary_size_printable_strings_first_value', { size: fmt.bytes(e.size), value: fmt.bytes(bytes.length) })}</p>`);
}

const COLS_KEY = 'strata.columns';
let colWidths = {};
try { colWidths = JSON.parse(localStorage.getItem(COLS_KEY) || '{}'); } catch {}

function tableKey(t) {
  if (t.dataset.rzKey) return t.dataset.rzKey;
  const heads = [...t.querySelectorAll(txt('ui.thead_th'))]
    .map(th => th.textContent.trim().slice(0, 12)).join('|');
  return `${t.className.trim().split(/\s+/).join('.')}#${heads}`;
}

function makeResizable(t) {
  if (t.dataset.rz) return;
  const ths = [...t.querySelectorAll(txt('ui.thead_th'))];
  if (ths.length < 2) return;
  t.dataset.rz = '1';
  const key = tableKey(t);
  const saved = colWidths[key] || {};

  const measured = ths.map(th => Math.round(th.getBoundingClientRect().width));
  ths.forEach((th, i) => {
    const w = saved[i] || measured[i];
    if (w) th.style.width = w + 'px';
    th.classList.add('rz-th');
    if (i === ths.length - 1) return;
    const grip = document.createElement('span');
    grip.className = 'colgrip';
    grip.title = txt('ui.drag_resize_double_click_reset');
    th.appendChild(grip);
    grip.addEventListener('mousedown', ev => beginResize(ev, t, th, i, key));
    grip.addEventListener('dblclick', ev => {
      ev.preventDefault();
      ev.stopPropagation();
      th.style.width = '';
      delete (colWidths[key] || {})[i];
      saveCols();
    });
  });
  t.classList.add('is-rz');
}

function beginResize(ev, table, th, index, key) {
  ev.preventDefault();
  ev.stopPropagation();
  const startX = ev.clientX;
  const startW = th.getBoundingClientRect().width;
  document.body.classList.add('is-colresize');

  const move = e => {
    const w = Math.max(32, Math.round(startW + (e.clientX - startX)));
    th.style.width = w + 'px';
  };
  const up = () => {
    window.removeEventListener('mousemove', move);
    window.removeEventListener('mouseup', up);
    document.body.classList.remove('is-colresize');
    colWidths[key] = colWidths[key] || {};
    colWidths[key][index] = Math.round(th.getBoundingClientRect().width);
    saveCols();
  };
  window.addEventListener('mousemove', move);
  window.addEventListener('mouseup', up);
}

function saveCols() {
  try { localStorage.setItem(COLS_KEY, JSON.stringify(colWidths)); } catch {}
}

function scanForTables(root = document) {
  root.querySelectorAll?.('table:not([data-rz])').forEach(t => {
    if (t.querySelector(txt('ui.thead_th'))) makeResizable(t);
  });
}

function initColumnResize() {
  scanForTables();
  let pending = null;
  const obs = new MutationObserver(() => {
    clearTimeout(pending);
    pending = setTimeout(() => scanForTables(), 30);
  });
  obs.observe(document.body, { childList: true, subtree: true });
}

async function loadTriage() {
  const box = $('#triage-results');
  box.hidden = false;
  $('#art-results').hidden = true;
  artPick = null;
  renderArtTree();
  box.innerHTML = `<p class="empty">${txt('ui.load_triage.gathering')}</p>`;
  let r;
  try { r = await api.get('triage'); } catch { r = null; }
  if (!r || r.error) {
    box.innerHTML = `<p class="empty">${esc(r?.error || 'Nothing to show.')}</p>`;
    return;
  }
  const f = r.findings || [];
  tabCount('triage', f.filter(x => x.severity === 'high').length);
  if (!f.length) {
    box.innerHTML = `<p class="empty">${txt('ui.nothing_flag')}</p>`;
    return;
  }
  box.innerHTML = f.map((x, i) => `
    <div class="tri tri-${x.severity}${x.not_run ? ' is-unrun' : ''}" data-i="${i}">
      <div class="tri-head">
        <span class="tri-dot"></span>
        <span class="tri-title">${esc(x.title)}</span>
        ${x.not_run ? '<span class="tri-unrun">not looked for</span>' : ''}
      </div>
      <div class="tri-detail">${esc(x.detail)}</div>
      ${x.items && x.items.length ? `<div class="tri-items">${
        x.items.slice(0, 40).map(it => triageItem(x.kind, it)).join('')}${
        x.items.length > 40 ? `<div class="tri-more">and ${
          x.items.length - 40} more</div>` : ''}</div>` : ''}
      ${x.action ? `<button class="linkish" data-act="${x.action}"${
        x.part === undefined || x.part === null ? '' : ` data-part="${x.part}"`}
        >${actionLabel(x.action, x.not_run)}</button>` : ''}
    </div>`).join('') +
    `<p class="hint">${esc(r.note)}</p>`;

  $$('#triage-results [data-act]').forEach(el =>
    el.addEventListener('click', () => triageAction(
      el.dataset.act,
      el.dataset.part === undefined ? undefined : +el.dataset.part)));
  $$('#triage-results .tri-item[data-path]').forEach(el =>
    el.addEventListener('click', () => openTriageItem(el.dataset)));
}

function triageItem(kind, it) {
  if (kind === 'encrypted') {
    return `<div class="tri-item"><b>${esc(it.exhibit)}</b> ${esc(it.slot)} ·
      ${esc(it.type)} <span class="${it.unlocked ? 'ok' : 'warn'}">${
      it.unlocked ? 'unlocked' : 'locked'}</span></div>`;
  }
  if (kind === 'unreadable') {
    return `<div class="tri-item"><b>${esc(it.exhibit)}</b> ${esc(it.slot)}
      <span class="tri-note">${esc((it.note || '').slice(0, 120))}</span></div>`;
  }
  if (kind === 'registry') {
    return `<div class="tri-item">
      <span class="tri-name">${esc(it.section)}</span>
      <span class="tri-says">${esc(it.hive || '')}${
        it.exhibit ? ' · ' + esc(it.exhibit) : ''} — <b>${it.count}</b></span>
      </div>`;
  }
  if (kind === 'filetype') {
    return `<div class="tri-item ${it.severity === 'high' ? 'is-high' : ''}"
        data-path="${esc(it.path || '')}" data-part="${it.part ?? ''}"
        data-node="${esc(String(it.node ?? ''))}" data-name="${esc(it.name || '')}"
        data-size="${it.size ?? 0}" data-deleted="${it.deleted ? 1 : 0}">
      <span class="tri-name">${esc(it.name)}</span>
      <span class="tri-says">.${esc(it.extension || '')} says ${
        esc(it.extension_says || '?')} → <b>${esc(it.content_is || '?')}</b></span>
      <span class="tri-path">${esc(it.path || '')}</span></div>`;
  }
  return '';
}

function actionLabel(act, unrun) {
  return { filetypes: unrun ? txt('ui.verify_file_types_now') : txt('ui.re_verify_file_types'),
           registry: unrun ? txt('ui.read_registry_now') : txt('ui.re_read_registry'),
           usn: unrun ? txt('ui.read_change_journal') : txt('ui.show_change_journal'),
           unlock: txt('ui.go_volume'), index: txt('ui.build_index'),
           hashes: txt('ui.import_hash_set'), tags: txt('ui.show_tagged_items') }[act] || act;
}

function triageAction(act, part) {
  if (act === 'filetypes') return runFileTypes();
  if (act === 'registry') return runRegistry();
  if (act === 'usn') {
    $('.tab[data-view="triage"]')?.click();
    const sel = $('#art-scope');
    if (sel && part !== undefined && part !== null) sel.value = String(part);
    artMode = 'usn';
    $$('.dv-mode[data-art]').forEach(b =>
      b.classList.toggle('is-on', b.dataset.art === 'usn'));
    return doArtifacts();
  }
  if (act === 'index' || act === 'hashes') {
    $(`.tab[data-view="${act === 'index' ? 'find' : 'hash'}"]`)?.click();
    return;
  }
  if (act === 'tags') return $('.tab[data-view="tags"]')?.click();
  if (act === 'unlock') return $('.tab[data-view="sources"]')?.click();
}

function nodeEntry(fsName, n) {
  const fs = (fsName || '').toUpperCase();
  if (fs.startsWith('NTFS')) return { mft: n };
  if (fs.startsWith('EXT')) return { inode: n };
  if (fs.startsWith('HFS')) return { cnid: n };
  if (fs.startsWith('APFS') || fs === 'AD1' || fs.startsWith('LOGICAL')) {
    return { oid: n };
  }
  return { start_cluster: n };
}

function openTriageItem(d) {
  const part = d.part === '' ? S.scope.part : +d.part;
  const p = partIn(d.evidence, part);
  if (!p) return toast(txt('messages.toast.partition_open_exhibit'));
  const entry = { name: d.name, path: d.path, size: +d.size,
                  is_dir: false, deleted: d.deleted === '1' };
  const n = d.node === '' || d.node === 'None' ? null : Number(d.node);
  const fsName = (p.detected || '').toUpperCase();
  Object.assign(entry, nodeEntry(fsName, n));
  showEntry(entry, p);
}

async function runFileTypes() {
  const all = $('#ft-all')?.checked;
  const t = await api.post('filetypes/scan', { all_evidence: !!all });
  const r = await awaitTask(t, txt('ui.verifying_file_types'), {
    modal: { title: txt('ui.verifying_file_types'),
             detail: txt('help.reading_first_few_hundred_bytes_every_file') },
  });
  if (!r) return;
  if (r.error) return toast(r.error);
  const checked = (r.scans || []).reduce((n, x) => n + (x.checked || 0), 0);
  const mis = (r.scans || []).reduce((n, x) => n + (x.mismatches || 0), 0);
  const high = (r.scans || []).reduce((n, x) => n + (x.high || 0), 0);
  toast(txt('messages.filetypes.checked',
          { checked: checked.toLocaleString(), count: mis, high }));
  dirCache.clear();
  walkCache.clear();
  loadTriage();
}

async function runRegistry() {
  const all = $('#ft-all')?.checked;
  const t = await api.post('registry/report', { all_evidence: !!all });
  const r = await awaitTask(t, txt('ui.reading_registry'), {
    modal: { title: txt('ui.reading_well_known_registry_keys'),
             detail: txt('help.machine_identity_usb_storage_attached_networks_joined') },
  });
  if (!r) return;
  if (r.error) return toast(r.error);
  S.registry = r.hives || [];
  const blank = S.registry.filter(h => h.unreadable && h.empty).length;
  const bad = S.registry.filter(h => h.unreadable && !h.empty).length;
  const ok = S.registry.length - blank - bad;
  toast(txt('messages.registry.read_hives', { count: ok })
      + (bad ? txt('messages.registry.would_not_parse', { count: bad })
             : '')
      + (blank ? txt('messages.registry.never_written', { count: blank })
               : '') + '.');
  loadTriage();
  renderRegistryReport();
}

function renderRegistryReport() {
  const hives = S.registry || [];
  if (!hives.length) return;
  const owner = h => {
    if (h.kind !== 'NTUSER' && h.kind !== 'USRCLASS') return h.kind;
    const parts = (h.hive || '').replace(/\\/g, '/').split('/').filter(Boolean);
    const i = parts.findIndex(p => ['users', 'serviceprofiles',
                                   txt('ui.documents_settings')]
                                   .includes(p.toLowerCase()));
    return i >= 0 && parts[i + 1] ? `${h.kind} (${parts[i + 1]})` : h.kind;
  };
  const body = hives.map(h => `
    <div class="regrep">
      <div class="regrep-head">${esc(owner(h)
        || (h.empty ? 'never written' : 'would not parse'))}
        <span class="regrep-src">${esc(h.exhibit || '')} · ${esc(h.hive || '')}</span></div>
      ${h.unreadable
        ? `<p class="hint${h.empty ? '' : ' warn'}">${esc(h.note)}</p>` : ''}
      ${(h.sections || []).map(sec => `
        <details class="regsec"${sec.count ? ' open' : ''}>
          <summary>${esc(sec.title)} <span class="dq">${sec.count || 0}</span></summary>
          ${sec.error ? `<p class="hint warn">${esc(sec.error)}</p>` : ''}
          ${sec.note && !sec.count ? `<p class="hint">${esc(sec.note)}</p>` : ''}
          ${sec.rows && sec.rows.length ? `<table class="reg-vals"><thead><tr>${
            Object.keys(sec.rows[0]).map(k => `<th>${esc(k)}</th>`).join('')
          }</tr></thead><tbody>${sec.rows.map(row => `<tr>${
            Object.values(row).map(v => `<td class="dv">${esc(v ?? '')}</td>`).join('')
          }</tr>`).join('')}</tbody></table>` : ''}
        </details>`).join('')}
    </div>`).join('');
  pvSet(txt('ui.registry_well_known_keys'),
        txt('ui.count.hives', { count: hives.length }), body);
}

function switchTo(state, { keepTree = false } = {}) {
  dirCache.clear();
  walkCache.clear();
  artCache.clear();
  S.fileHits = [];
  if (S.timeline?.scope !== 'tagged') clearTimelinePanel();
  S.findHits = [];
  const staleFind = $('#find-results');
  if (staleFind) staleFind.innerHTML = '';
  S.structures = [];
  S.lastEntry = null;
  applyOpened(state, { tree: !keepTree });
  if (!state.open) return;
  if (keepTree) {
    markActiveExhibit();
    S.marks = [];
    fieldIndex = [];
    S.focusField = null;
    loadMarks();
    refreshIndexState();
    renderStructures();
    core.draw();
    hex.draw();
    return;
  }
  previewNone(txt('messages.select_partition_file'));
  loadMarks();
  refreshIndexState();
  loadTimezone(false);
  const now = (state.evidence || [])
    .find(e => e.evidence_id === state.active_id);
  if (now) toast(txt('messages.toast.now_showing_label', { label: now.label }));
}

async function writeReport() {
  const r = await api.post('report/write', {});
  if (r.error) return toast(r.error);
  toast(txt('help.report_written_path_r_open_browser_print', { path: r.path, r: fmt.bytes(r.bytes) }));
}

function tzLabel(mins) {
  const s = mins < 0 ? '-' : '+';
  return `${s}${String(Math.floor(Math.abs(mins) / 60)).padStart(2, '0')}:${
    String(Math.abs(mins) % 60).padStart(2, '0')}`;
}

async function loadTimezone(prompt = false) {
  let r;
  try { r = await api.get('timezone'); } catch { return; }
  if (r.applied) {
    S.tz = { ...r.applied, label: tzLabel(r.applied.offset_minutes) };
  }
  S.tzCandidates = r.candidates || [];
  renderTzStat();
  if (r.applied) return;

  if (!r.detected) {
    const t = await api.post('timezone/detect', {});
    const got = await awaitTask(t, txt('ui.tz.time_zone'));
    if (!got) return;
    S.tzCandidates = got.candidates || [];
    renderTzStat();
  }
  if (prompt && S.tzCandidates.length) tzDialog();
}

function renderTzStat() {
  const el = $('#stat-tz');
  if (!el) return;
  if (!S.tz) {
    el.textContent = S.tzCandidates?.length
      ? txt('ui.utc_tzcandidates_zone_found', { tzCandidates: S.tzCandidates.length }) : 'UTC';
    el.classList.remove('is-on');
  } else {
    el.textContent = `${S.tz.name || 'offset'} ${S.tz.label}`;
    el.classList.add('is-on');
  }
  el.title = S.tz
    ? txt('help.dates_show_local_time_utc_click_change')
    : txt('help.dates_show_utc_click_apply_local_offset');
}

function tzDialog() {
  const dlg = $('#dlg-tz');
  const cands = S.tzCandidates || [];
  const opts = [];
  cands.forEach((c, i) => {
    const choices = c.resolves_transitions
      ? [{ m: c.offset_minutes,
           why: c.observes_dst
             ? txt('ui.daylight_saving_resolved_per_timestamp')
             : txt('ui.zone_observe_daylight_saving') }]
      : [
        c.standard_offset_minutes != null
          ? { m: c.standard_offset_minutes, why: txt('ui.standard_time') } : null,
        c.daylight_offset_minutes != null
         && c.daylight_offset_minutes !== c.standard_offset_minutes
          ? { m: c.daylight_offset_minutes, why: txt('ui.daylight_saving') } : null,
        c.active_offset_minutes != null
          ? { m: c.active_offset_minutes, why: txt('ui.force_machine_last_wrote') }
          : null,
      ].filter(Boolean);
    const seen = new Set();
    opts.push(`<div class="tzc">
      <div class="tzc-head">${esc(c.name || 'Unnamed zone')}
        <span class="tzc-src">${esc(c.partition || '')} · ${esc(c.filesystem || '')}</span></div>
      <div class="tzc-from">${esc(c.source || '')}</div>
      ${c.transition_note ? `<div class="tzc-note">${esc(c.transition_note)}</div>` : ''}
      <div class="tzc-opts">${choices.filter(x => {
        if (seen.has(x.m)) return false; seen.add(x.m); return true;
      }).map(x => `<label class="tzc-opt">
        <input type="radio" name="tzpick" value="${x.m}"
          data-name="${esc(c.name || '')}" data-source="${esc(c.source || '')}"
          data-confidence="${esc(c.confidence || '')}"
          data-transitions="${c.dst_transitions
            ? esc(JSON.stringify(c.dst_transitions)) : ''}">
        <b>${tzLabel(x.m)}</b> <span>${esc(x.why)}</span></label>`).join('')}</div>
    </div>`);
  });

  $('#tz-list').innerHTML = opts.join('') ||
    `<p class="empty">${txt('help.nothing_image_states_time_zone_set_hand')}</p>`;
  $('#tz-manual').value = '';
  $('#tz-note').textContent =
    txt('help.fat_exfat_volumes_record_local_time_already');
  dlg.returnValue = '';
  dlg.showModal();

  dlg.addEventListener('close', async function done() {
    dlg.removeEventListener('close', done);
    if (dlg.returnValue !== 'ok') return;
    const picked = $('#tz-list input[name="tzpick"]:checked');
    const manual = $('#tz-manual').value.trim();
    let tz = null;
    if (manual !== '' && !isNaN(+manual)) {
      tz = { offset_minutes: +manual, name: `manual ${tzLabel(+manual)}`,
             source: txt('ui.set_examiner'), confidence: 'manual' };
    } else if (picked) {
      tz = { offset_minutes: +picked.value, name: picked.dataset.name,
             source: picked.dataset.source,
             confidence: picked.dataset.confidence };
      if (picked.dataset.transitions) {
        try { tz.dst_transitions = JSON.parse(picked.dataset.transitions); }
        catch {                                                          }
      }
    }
    if (!tz) return;
    const r = await api.post('timezone/apply', { timezone: tz });
    if (r.error) return toast(r.error);
    S.tz = { ...tz, label: tzLabel(tz.offset_minutes) };
    renderTzStat();
    redrawDates();
    toast(tz.dst_transitions
      ? txt('messages.dates_now_show_name_alongside_utc_daylight', { name: tz.name })
      : txt('messages.dates_now_show_name_label_alongside_utc', { name: tz.name, label: S.tz.label }));
  }, { once: false });
}

function redrawDates() {
  if (S.lastEntry) showEntry(S.lastEntry, partObj(S.scope.part));
  if (S.timeline) redrawTimelineRows();
  if (S.fileHits?.length) renderFileHits(S.fileHits, S.scope.part,
                                         `${S.fileHits.length} hits`);
  renderTags?.();
}

async function openArchive(e, part) {
  const r = await api.get('archive', { part: partOffset(part),
                                      entry: JSON.stringify(e) });
  if (r.error) {
    return pvSet(e.name, 'archive',
      `<p class="empty">${esc(r.error)}</p>` +
      (r.findings || []).map(f => `<p class="hint">${esc(f)}</p>`).join(''));
  }
  S.archive = { part, entry: e, info: r };

  const head = [
    r.container || 'ZIP archive',
    txt('ui.count.files', { count: r.files }),
    fmt.bytes(r.total_size),
    r.encrypted_entries ? `${r.encrypted_entries} encrypted` : null,
    r.read_by === txt('ui.local_header_scan') ? txt('ui.recovered_scan') : null,
  ].filter(Boolean).join(' · ');

  const notes = (r.findings || []).map(f =>
    `<p class="hint${/discrepanc|truncated|overwritten/.test(f) ? ' warn' : ''}">
       ${esc(f)}</p>`).join('');

  const rows = r.items.filter(x => !x.is_dir).map((x, i) => `
    <div class="zrow" data-i="${i}">
      <span class="zname">${esc(x.name)}</span>
      <span class="zsize">${fmt.bytes(x.size)}</span>
      <span class="zmeta">${esc(x.method)}${x.encrypted ? ' · locked' : ''}${
        x.modified ? ' · ' + esc(x.modified.replace('T', ' ')) : ''}</span>
      ${x.findings.length ? `<span class="zwarn">${esc(x.findings[0])}</span>` : ''}
    </div>`).join('');

  pvSet(e.name, head, `
    ${notes}
    <p class="hint">${txt('ui.entry_times_archive_s_own')}<b>${txt('ui.local_time_zone_recorded')}</b>${txt('help.utc_cannot_converted_without_knowing_where_archive')}</p>
    <div class="ziplist">${rows || '<p class="empty">No files inside.</p>'}</div>`);

  $$('#preview .zrow').forEach(el => el.addEventListener('click', () =>
    openArchiveEntry(+el.dataset.i)));
}

async function openArchiveEntry(i) {
  const a = S.archive;
  if (!a) return;
  const item = a.info.items.filter(x => !x.is_dir)[i];
  if (!item) return;
  const r = await api.get('archive', {
    part: a.part, entry: JSON.stringify(a.entry), inner: item.name });
  if (r.error) return toast(r.error);
  const bytes = Uint8Array.from(atob(r.preview || ''), c => c.charCodeAt(0));
  const notes = (r.notes || []).map(n =>
    `<p class="hint warn">${esc(n)}</p>`).join('');
  const back = `<p class="hint"><button class="linkish" id="zip-back">${txt('ui.back_name', { name: esc(a.entry.name) })}</button></p>`;

  const show = (body) => {
    pvSet(`${a.entry.name} › ${item.name}`, `${item.method} · ${fmt.bytes(item.size)}`,
          back + notes + body);
    $('#zip-back')?.addEventListener('click', () => openArchive(a.entry, a.part));
  };

  if (!bytes.length) return show(`<p class="empty">${txt('ui.content_show')}</p>`);
  const kind = sniff(bytes);
  if (kind?.raster || (kind?.kind === 'image' && kind.mime)) {
    const b64 = r.preview;
    return show(`<div class="pv-image"><img alt="" src="data:${
      kind.mime};base64,${b64}"></div>`);
  }
  if (looksTextual(bytes)) {
    return show(`<pre class="pv-text">${escText(decodeText(bytes).slice(0, 20000))}</pre>`);
  }
  show(`<p class="pv-note">${txt('help.binary_size_inline_viewer_type_inside_archive', { Binary: esc(kind?.label || kind?.ext || 'Binary'), size: fmt.bytes(item.size) })}</p>`);
}

function markupKind(bytes, name = '') {
  const head = new TextDecoder('latin1')
    .decode(bytes.slice(0, 1024)).trim().toLowerCase();
  if (head.includes('<svg')) return 'svg';
  if (/\.svg$/i.test(name) && head.includes('<')) return 'svg';
  if (head.startsWith(txt('ui.doctype_html')) || head.startsWith('<html')
      || head.includes('<html') || head.includes('<body')) return 'html';
  if (/\.x?html?$/i.test(name) && head.includes('<')) return 'html';
  return null;
}

const partOffset = p => ((p && typeof p === "object" ? p.offset : p) ?? 0);

const partObj = p => (p && typeof p === "object") ? p
  : (S.volumes?.partitions || []).find(x => x.offset === (p ?? 0)) || null;

const stampExhibit = h =>
  (h && h.evidence == null ? { ...h, evidence: S.activeId } : h);

const sameVolume = (a, b) =>
  partOffset(a) === partOffset(b) &&
  (a && a.ev_id) === (b && b.ev_id);

function partIn(evId, offset) {
  const id = evId == null || evId === '' ? null : Number(evId);
  const ev = Number.isFinite(id)
    ? S.exhibits.find(x => x.evidence_id === id) : null;
  const parts = ev ? partsOf(ev) : (S.volumes?.partitions || []);
  return parts.find(x => x.offset === offset) || null;
}

function renderURL(e, part, as) {
  const q = new URLSearchParams({ part: String(partOffset(part)),
                                  entry: JSON.stringify(e) });
  if (as) q.set('as', as);
  return `/api/render?${q}`;
}

function sanitisedNote(findings, what) {
  if (!findings || !findings.length) {
    return `<p class="hint">${txt('help.nothing_active_found_still_rendered_sanitised_copy', { what: what })}</p>`;
  }
  return `<details class="stripped" open>
      <summary>${txt('ui.things_removed_before_rendering',
                     { count: findings.length })}</summary>
      <ul>${findings.map(f => `<li>${esc(f)}</li>`).join('')}</ul>
      <p class="hint">${txt('help.these_reported_because_evidence_about_file_rendering')}</p>
    </details>`;
}

async function openPdf(e, part) {
  const info = await api.get('render', { part: partOffset(part),
                                         entry: JSON.stringify(e) });
  if (info.error) return pvSet(e.name, 'pdf', `<p class="empty">${esc(info.error)}</p>`);

  const meta = [
    info.pages ? txt('ui.count.pages', { count: info.pages }) : null,
    info.version ? `PDF ${info.version}` : null,
    info.title, info.author, info.producer,
  ].filter(Boolean).map(esc).join(' · ');

  const active = (info.active_content || []).map(a =>
    `<li><code>${esc(a.key)}</code> — ${esc(a.what)}${a.count > 1
      ? ` (x${a.count})` : ''}
      <span class="${a.neutralised ? 'ok' : 'warn'}">${a.neutralised
        ? 'removed' : (a.location === 'object stream'
          ? 'could not be removed' : 'left in place, inert')}</span></li>`).join('');

  const findings = (info.findings || []).map(f =>
    `<p class="hint warn">${esc(f)}</p>`).join('');

  const body = info.renderable
    ? `<iframe class="pv-frame" referrerpolicy="no-referrer"
         src="${renderURL(e, part, 'bytes')}"></iframe>`
    : `<p class="pv-note">${info.encrypted
        ? txt('ui.pdf.not_rendered_encrypted')
        : txt('ui.pdf.not_rendered_active')}</p>
       ${info.text ? `<pre class="pv-text">${escText(info.text.slice(0, 20000))}</pre>`
         : '<p class="hint">No extractable text either.</p>'}`;

  pvSet(e.name, `pdf · ${meta}`, `
    ${findings}
    ${active ? `<details class="stripped"><summary>Active content
      (${info.active_content.length})</summary><ul>${active}</ul></details>` : ''}
    ${body}`);
}

async function openMarkup(e, part, kind) {
  const info = await api.get('render', { part: partOffset(part),
                                         entry: JSON.stringify(e) });
  if (info.error) return pvSet(e.name, kind, `<p class="empty">${esc(info.error)}</p>`);
  if (!info.renderable) {
    return pvSet(e.name, kind,
      `<p class="pv-note">${txt('ui.could_parsed_safely')}</p>
       ${(info.findings || []).map(f => `<p class="hint">${esc(f)}</p>`).join('')}`);
  }
  pvSet(e.name, `${kind} · sanitised`, `
    ${sanitisedNote(info.findings, kind === 'svg' ? 'graphic' : 'page')}
    <iframe class="pv-frame" sandbox referrerpolicy="no-referrer"
      src="${renderURL(e, part, 'bytes')}"></iframe>`);
}

const reg = { part: null, entry: null, path: '', deleted: false };

function regValueText(v) {
  if (v.truncated) return `<${fmt.bytes(v.size)} — too large to inline>`;
  const d = v.value;
  if (d === null || d === undefined) return '';
  if (Array.isArray(d)) return d.join(' · ');
  return String(d);
}

async function openRegistry(entry, part, path = '') {
  const token = Symbol();
  pvToken = token;
  reg.part = part; reg.entry = entry; reg.path = path;
  pvSet(entry.name, txt('ui.registry_hive'), `<p class="empty">${txt('ui.reading_hive')}</p>`);
  const r = await api.get('registry', {
    part: part.offset, entry: JSON.stringify(entry), key: path });
  if (pvToken !== token) return;
  if (r.error) return pvSet(entry.name, 'registry', `<p class="empty">${esc(r.error)}</p>`);
  renderRegistry(r);
}

function renderRegistry(r) {
  const crumbs = reg.path ? reg.path.split('\\').filter(Boolean) : [];
  const trail = crumbs.map((c, i) =>
    `<button class="crumb" data-p="${esc(crumbs.slice(0, i + 1).join('\\'))}">${
      esc(c)}</button>`).join('<span class="sep">\\</span>');

  const keys = r.subkeys.map(k => `
    <div class="reg-key ${k.deleted ? 'is-del' : ''}" data-k="${esc(k.name)}">
      <span class="nm">${esc(k.name)}</span>
      <span class="cnt">${k.subkey_count || ''}</span>
      <span class="ts">${k.modified ? fmt.time(k.modified) : ''}</span>
    </div>`).join('') || `<p class="empty">${txt('ui.render_registry.no_subkeys')}</p>`;

  const vals = r.values.length ? `
    <table class="reg-vals">
      <thead><tr><th>${txt('ui.render_registry.name')}</th><th>${txt('ui.render_registry.type')}</th><th>${txt('ui.render_registry.data')}</th></tr></thead>
      <tbody>${r.values.map(v => `<tr class="${v.deleted ? 'is-del' : ''}">
        <td class="nm">${esc(v.name)}</td>
        <td class="ty">${esc(v.type)}</td>
        <td class="dv"${v.truncated ? '' : ` title="${esc(regValueText(v))}"`}>${
          v.truncated
            ? `<button class="linkish reg-load-value" data-offset="${v.offset}">${
                esc(regValueText(v))} — load</button>`
            : esc(regValueText(v))}</td>
      </tr>`).join('')}</tbody>
    </table>` : `<p class="empty">${txt('ui.values_key')}</p>`;

  const info = r.info;
  const rp = info.replay;
  const state = !rp ? (info.dirty ? ' · dirty' : '')
    : rp.recovered ? txt('ui.recovered_log')
    : txt('ui.dirty_recoverable');
  pvSet(reg.entry.name,
    `${info.version}${state} · ${r.subkeys.length} keys · ${
      r.values.length} values`, `
    <div class="pv-reg">
      <div class="reg-bar">
        <button class="crumb root" data-p="">${esc(info.embedded_name
          || 'ROOT')}</button>
        ${trail ? '<span class="sep">\\</span>' + trail : ''}
        <button class="ghost reg-del" id="reg-del">${txt('ui.render_registry.deleted')}</button>
      </div>
      ${rp ? `<div class="notice${rp.recovered ? ' ok' : ''}">${
        esc(rp.summary || '')}${(rp.findings || []).length
          ? '<br>' + esc(rp.findings[0]) : ''}</div>`
        : info.dirty ? `<div class="notice">${esc(info.findings[0] || '')}</div>` : ''}
      ${r.key?.modified ? `<div class="reg-meta">Key last written
        <strong>${fmt.time(r.key.modified)}</strong> — the registry's only
        timestamp, and it belongs to the key, not to any single value.</div>` : ''}
      <div class="reg-split">
        <div class="reg-keys">${keys}</div>
        <div class="reg-body">${vals}</div>
      </div>
    </div>`);

  $$('#preview-body .reg-key').forEach(el => el.addEventListener('click', () => {
    const next = (reg.path ? reg.path + '\\' : '') + el.dataset.k;
    openRegistry(reg.entry, reg.part, next);
  }));
  $$('#preview-body .crumb').forEach(el => el.addEventListener('click', () =>
    openRegistry(reg.entry, reg.part, el.dataset.p)));
  $('#reg-del')?.addEventListener('click', showRegistryDeleted);
  $$('#preview-body .reg-load-value').forEach(el =>
    el.addEventListener('click', () => loadRegistryValue(el)));
}

async function loadRegistryValue(el) {
  const td = el.closest('td');
  const offset = +el.dataset.offset;
  td.textContent = txt('ui.render_registry.loading_value');
  const v = await api.get('registry/value', {
    part: reg.part.offset, entry: JSON.stringify(reg.entry), offset });
  if (v.error) { td.textContent = v.error; return; }
  const text = regValueText(v);
  td.textContent = text;
  td.title = text;
}

async function showRegistryDeleted() {
  const token = Symbol();
  pvToken = token;
  pvSet(reg.entry.name, 'registry · deleted',
        `<p class="empty">${txt('ui.sweeping_free_cells')}</p>`);
  const r = await api.get('registry/deleted', {
    part: reg.part.offset, entry: JSON.stringify(reg.entry) });
  if (pvToken !== token) return;
  if (r.error) return pvSet(reg.entry.name, 'registry',
                            `<p class="empty">${esc(r.error)}</p>`);
  const keys = r.keys.map(k => `<tr><td class="nm">${esc(k.name)}</td>
    <td class="ty">${txt('ui.show_registry_deleted.key')}</td><td class="dv">${k.modified ? fmt.time(k.modified) : ''}</td></tr>`);
  const vals = r.values.map(v => `<tr><td class="nm">${esc(v.name)}</td>
    <td class="ty">${esc(v.type)}</td><td class="dv">${esc(regValueText(v))}</td></tr>`);
  pvSet(reg.entry.name, `deleted · ${r.keys.length} keys · ${r.values.length} values`, `
    <div class="pv-reg">
      <div class="reg-bar">
        <button class="crumb root" id="reg-back">${txt('ui.back_tree')}</button>
      </div>
      <div class="reg-meta">${txt('help.recovered_free_cells_windows_marks_deleted_key')}</div>
      <div class="reg-body">
        ${keys.length + vals.length ? `<table class="reg-vals is-del">
          <thead><tr><th>Name</th><th>Type</th><th>Data / last written</th></tr></thead>
          <tbody>${keys.join('')}${vals.join('')}</tbody></table>`
          : '<p class="empty">No recoverable deleted records in this hive.</p>'}
      </div>
    </div>`);
  $('#reg-back')?.addEventListener('click', () =>
    openRegistry(reg.entry, reg.part, reg.path));
}

const EVTX_PAGE = 2000;

async function openEventLog(entry, part, offset = 0) {
  const token = Symbol();
  pvToken = token;
  pvSet(entry.name, txt('ui.event_log'),
        `<p class="empty">${txt('ui.decoding_records_progress_task_tray')}</p>`);
  const t = await api.post('evtx', {
    part: part.offset, entry, limit: EVTX_PAGE, offset });
  const r = await awaitTask(t, txt('ui.decoding_events'));
  if (pvToken !== token) return;
  if (!r) return pvSet(entry.name, txt('ui.event_log'),
                       `<p class="empty">${txt('ui.decoding_cancelled')}</p>`);
  r._entry = entry;
  r._part = part;
  r._offset = offset;
  if (r.error) return pvSet(entry.name, txt('ui.event_log'),
                            `<p class="empty">${esc(r.error)}</p>`);

  const recs = r.records || [];
  const undecoded = recs.filter(x => x.unsupported).length;
  const head = r.header || {};
  const notes = [
    head.dirty ? txt('messages.log_closed_cleanly_dirty_flag_set') : null,
    ...(r.findings || []),
  ].filter(Boolean).map(f => `<div class="notice">${esc(f)}</div>`).join('');

  const rows = recs.map((x, i) => `
    <tr data-i="${i}" class="${x.unsupported ? 'is-del' : ''}">
      <td class="dt">${esc((x.written_at || '').replace('T', ' ').slice(0, 19))}</td>
      <td class="sz">${x.event_id ?? '—'}</td>
      <td class="nm">${esc(x.level || '')}</td>
      <td class="nm">${esc(x.provider || '')}</td>
    </tr>`).join('');

  const total = r.total ?? recs.length;
  const from = offset + 1;
  const to = offset + recs.length;
  const pager = total > recs.length || offset > 0 ? `
    <div class="evtx-pager">
      <button class="ghost" id="evtx-prev" ${offset ? '' : 'disabled'}>${txt('ui.open_event_log.newer')}</button>
      <span>${from.toLocaleString()}–${to.toLocaleString()} of
        ${total.toLocaleString()}</span>
      <button class="ghost" id="evtx-next" ${r.more ? '' : 'disabled'}>${txt('ui.open_event_log.older')}</button>
    </div>` : '';

  pvSet(entry.name,
    `${total.toLocaleString()} records · ${r.chunks} chunks · v${
      head.version || '?'}${undecoded ? ` · ${undecoded} undecoded` : ''}`, `
    <div class="pv-dir">
      ${notes}
      ${pager}
      <div class="dv-body">
        <table class="dv-list evtx">
          <thead><tr><th>${txt('ui.open_event_log.written')}</th><th>${txt('ui.open_event_log.event')}</th><th>${txt('ui.open_event_log.level')}</th>
            <th>${txt('ui.open_event_log.provider')}</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div class="evtx-detail" id="evtx-detail">
        <p class="empty">${txt('ui.open_event_log.select_record')}</p>
      </div>
    </div>`);

  $('#evtx-prev')?.addEventListener('click', () =>
    openEventLog(entry, part, Math.max(0, offset - EVTX_PAGE)));
  $('#evtx-next')?.addEventListener('click', () =>
    openEventLog(entry, part, offset + recs.length));

  $$('#preview-body .dv-list.evtx tbody tr').forEach(el =>
    el.addEventListener('click', () => {
      $$('#preview-body .dv-list.evtx tbody tr').forEach(t =>
        t.classList.remove('is-on'));
      el.classList.add('is-on');
      const x = recs[+el.dataset.i];
      const f = x.fields || {};
      $('#evtx-detail').innerHTML = `
        <div class="reg-meta">Record ${x.record_id} · ${
          esc(fmt.time(x.written_at))}${x.computer
            ? ' · ' + esc(x.computer) : ''}</div>
        ${x.unsupported ? `<div class="notice">${esc(x.unsupported)}</div>` : ''}
        <table class="reg-vals"><tbody>${Object.entries(f).map(([k, v]) => `
          <tr><td class="nm">${esc(k.replace(/^Event\//, ''))}</td>
              <td class="dv">${esc(String(v ?? ''))}</td></tr>`).join('')}
        </tbody></table>`;
    }));
}

const sq = { entry: null, part: null, table: null, info: null, tables: [],
             raw: false, last: null };

async function openSqlite(entry, part, table = null, recover = false) {
  const token = Symbol();
  pvToken = token;
  pvSet(entry.name, 'database', `<p class="empty">${txt('ui.reading_pages')}</p>`);
  const t = await api.post('sqlite', {
    part: part.offset, entry, table, recover, limit: 5000 });
  const r = await awaitTask(t, txt('ui.reading_database'));
  if (pvToken !== token) return;
  if (!r) return pvSet(entry.name, 'database',
                       `<p class="empty">${txt('ui.open_sqlite.cancelled')}</p>`);
  if (r.error) return pvSet(entry.name, 'database',
                            `<p class="empty">${esc(r.error)}</p>`);
  sq.entry = entry; sq.part = part; sq.table = table;
  sq.info = r.info; sq.tables = r.tables;
  renderSqlite(r);
}

function renderSqlite(r) {
  sq.last = r;
  const info = r.info || {};
  const notes = (info.findings || []).map(f =>
    `<div class="notice">${esc(f)}</div>`).join('');

  const tabs = (r.tables || []).map(t =>
    `<div class="reg-key ${t.name === sq.table ? 'is-on' : ''}"
       data-t="${esc(t.name)}">
       <span class="nm">${esc(t.name)}</span>
       <span class="cnt">${(t.columns || []).length}</span>
     </div>`).join('') || `<p class="empty">${txt('ui.render_sqlite.no_tables')}</p>`;

  let body;
  if (r.recovered) {
    const recs = r.recovered.records || [];
    const c = r.recovered.counts || {};
    body = `<div class="reg-meta">${txt('help.recovered_free_space_freeblock_deleted_cells_unallocated', { freeblock: c.freeblock || 0, unallocated: c.unallocated || 0, freelist: c.freelist || 0 })}</div>
      ${recs.length ? `<table class="reg-vals"><thead><tr><th>Page</th>
        <th>Recovered from</th><th>Values</th></tr></thead><tbody>
        ${recs.slice(0, 2000).map(x => `<tr class="is-del">
          <td class="ty">${x.page}</td><td class="ty">${esc(x.source)}</td>
          <td class="dv">${esc(x.values.map(v => v === null ? '∅'
            : String(v)).join(' | ').slice(0, 300))}</td></tr>`).join('')}
      </tbody></table>` : '<p class="empty">Nothing recoverable.</p>'}`;
  } else if (r.table) {
    const cols = r.table.columns?.length ? r.table.columns
      : Object.keys(r.table.rows[0] || {}).filter(k => k !== '_rowid');
    const dcol = r.table.decoded_columns || {};
    const dec = r.table.decoded || {};
    const anyDecoded = Object.keys(dcol).length > 0;
    const legend = anyDecoded ? `<p class="hint">${
      txt('ui.sqlite.interpreted', { columns: Object.entries(dcol).map(
        ([c, m]) => `<b>${esc(c)}</b> <span class="dq">${
          esc(m.kind || '')}</span>`).join(', ') })}
      <button class="linkish" id="sq-raw">${sq.raw ? 'show decoded'
        : 'show stored values'}</button>.</p>` : '';

    body = r.table.rows.length ? legend + `<table class="reg-vals">
      <thead><tr>${cols.map(c => `<th>${esc(c)}${
        dcol[c] ? '<span class="dq" title="interpreted for display">*</span>' : ''
        }</th>`).join('')}</tr></thead>
      <tbody>${r.table.rows.slice(0, 2000).map((row, i) => `<tr>${cols.map(c => {
        const stored = String(row[c] ?? '');
        const d = dec[i] && dec[i][c];
        if (d == null || sq.raw) return `<td class="dv">${esc(stored)}</td>`;
        return `<td class="dv is-dec" title="stored: ${esc(stored)}">${
          esc(String(d))}</td>`;
      }).join('')}</tr>`).join('')}</tbody></table>`
      : `<p class="empty">${txt('ui.table_empty')}</p>`;
  } else {
    body = `<p class="empty">${txt('ui.render_sqlite.pick_table')}</p>`;
  }

  pvSet(sq.entry.name,
    `${(r.tables || []).length} tables · ${info.pages} pages · ${
      info.page_size}B${info.wal_mode ? ' · WAL' : ''}${
      r.kind ? ' · ' + r.kind.replace(/_/g, ' ') : ''}`, `
    <div class="pv-dir">
      ${notes}
      <div class="reg-bar">
        <button class="crumb root" id="sq-tables">${txt('ui.render_sqlite.tables_2')}</button>
        <button class="ghost reg-del" id="sq-recover">${txt('ui.deleted_rows')}</button>
      </div>
      <div class="reg-split">
        <div class="reg-keys">${tabs}</div>
        <div class="reg-body">${body}</div>
      </div>
    </div>`);

  $$('#preview-body .reg-key[data-t]').forEach(el =>
    el.addEventListener('click', () =>
      openSqlite(sq.entry, sq.part, el.dataset.t)));
  $('#sq-tables')?.addEventListener('click', () =>
    openSqlite(sq.entry, sq.part, null));
  $('#sq-raw')?.addEventListener('click', () => {
    sq.raw = !sq.raw;
    if (sq.last) renderSqlite(sq.last);
  });
  $('#sq-recover')?.addEventListener('click', () =>
    openSqlite(sq.entry, sq.part, null, true));
}

const eseView = { entry: null, part: null, table: null };

async function openEse(entry, part, table = null) {
  const token = Symbol();
  pvToken = token;
  pvSet(entry.name, 'database', `<p class="empty">${txt('ui.reading_pages')}</p>`);
  const t = await api.post('ese', { part: part.offset, entry, table, limit: 2000 });
  const r = await awaitTask(t, txt('ui.reading_database'));
  if (pvToken !== token) return;
  if (!r) return pvSet(entry.name, 'database',
                       `<p class="empty">${txt('ui.open_sqlite.cancelled')}</p>`);
  if (r.error) return pvSet(entry.name, 'database',
                            `<p class="empty">${esc(r.error)}</p>`);
  eseView.entry = entry; eseView.part = part; eseView.table = table;
  renderEse(r);
}

function eseCell(v) {
  if (v === null || v === undefined) return '';
  return typeof v === 'object' ? JSON.stringify(v) : String(v);
}

function renderEse(r) {
  const info = r.info || {};
  const notes = [...(info.findings || []), ...(r.error_table ? [r.error_table] : [])]
    .map(f => `<div class="notice">${esc(f)}</div>`).join('');

  const tabs = (r.tables || []).map(t =>
    `<div class="reg-key ${t.name === eseView.table ? 'is-on' : ''}"
       data-t="${esc(t.name)}">
       <span class="nm">${esc(t.name)}</span>
       <span class="cnt">${t.columns}</span>
     </div>`).join('') || `<p class="empty">${txt('ui.render_sqlite.no_tables')}</p>`;

  const tb = r.table;
  let body;
  if (tb) {
    const counts = [
      txt('ui.ese.rows_read', { read: tb.read }),
      tb.skipped ? txt('ui.ese.rows_skipped', { skipped: tb.skipped }) : null,
      tb.truncated ? txt('ui.ese.rows_truncated', { limit: tb.limit }) : null,
    ].filter(Boolean).join(' · ');
    body = `<div class="reg-meta">${esc(counts)}</div>`
      + (tb.note ? `<p class="hint">${esc(tb.note)}</p>` : '')
      + (tb.rows.length ? `<table class="reg-vals">
        <thead><tr>${tb.columns.map(c =>
          `<th title="${esc(tb.types?.[c] || '')}">${esc(c)}</th>`).join('')}</tr></thead>
        <tbody>${tb.rows.map(row => `<tr>${tb.columns.map(c =>
          `<td class="dv">${esc(eseCell(row[c]))}</td>`).join('')}</tr>`).join('')}</tbody>
      </table>` : `<p class="empty">${txt('ui.table_empty')}</p>`);
  } else {
    body = `<p class="empty">${txt('ui.render_sqlite.pick_table')}</p>`;
  }

  pvSet(eseView.entry.name, txt('ui.ese.summary', {
    tables: (r.tables || []).length, pages: info.pages,
    page_size: info.page_size, state: info.state || '' }), `
    <div class="pv-dir">
      ${notes}
      <div class="reg-bar">
        <button class="crumb root" id="ese-tables">${txt('ui.render_sqlite.tables_2')}</button>
      </div>
      <div class="reg-split">
        <div class="reg-keys">${tabs}</div>
        <div class="reg-body">${body}</div>
      </div>
    </div>`);

  $$('#preview-body .reg-key[data-t]').forEach(el =>
    el.addEventListener('click', () =>
      openEse(eseView.entry, eseView.part, el.dataset.t)));
  $('#ese-tables')?.addEventListener('click', () =>
    openEse(eseView.entry, eseView.part, null));
}

async function openLevelDb(entry, part) {
  const token = Symbol();
  pvToken = token;
  pvSet(entry.name, 'leveldb', `<p class="empty">${txt('ui.decompressing_blocks')}</p>`);
  const t = await api.post('leveldb', { part: part.offset, entry });
  const r = await awaitTask(t, 'Reading LevelDB');
  if (pvToken !== token) return;
  if (!r) return pvSet(entry.name, 'leveldb', `<p class="empty">${txt('ui.open_sqlite.cancelled')}</p>`);
  if (r.error) return pvSet(entry.name, 'leveldb',
                            `<p class="empty">${esc(r.error)}</p>`);
  const ls = r.local_storage || [];
  const rows = ls.length ? ls : (r.rows || []);
  const isLs = ls.length > 0;
  pvSet(entry.name, `${r.count} entries${isLs ? ' · local storage' : ''}`, `
    <div class="pv-dir">
      ${(r.findings || []).map(f => `<div class="notice">${esc(f)}</div>`).join('')}
      <div class="dv-body">
        <table class="reg-vals">
          <thead><tr>${isLs ? '<th>Origin</th><th>Key</th>'
            : '<th>Key</th>'}<th>${txt('ui.open_level_db.value')}</th></tr></thead>
          <tbody>${rows.slice(0, 3000).map(x => `
            <tr class="${x.deleted ? 'is-del' : ''}">
              ${isLs ? `<td class="nm">${esc(x.origin || '')}</td>` : ''}
              <td class="nm">${esc(x.key || '')}</td>
              <td class="dv">${x.deleted ? '<em>deleted</em>'
                : esc(String(x.value ?? '').slice(0, 300))}</td>
            </tr>`).join('')}</tbody>
        </table>
      </div>
    </div>`);
}

function previewNone(msg) {
  pvToken = Symbol();
  dirView.entries = [];
  dirView.name = '';
  dirView.id = undefined;
  dirSet('—', '', `<p class="empty">${msg}</p>`);
  pvSet(txt('ui.preview.preview_title'), '', `<p class="empty">${msg}</p>`);
}

async function maybeUnlock(part) {
  let enc;
  try {
    enc = await api.get('encryption', { part: part.offset });
  } catch { return false; }
  if (!enc || !enc.encrypted) return false;
  if (enc.unlocked) return false;

  S.encInfo = enc;
  const dlg = $('#dlg-unlock');
  const kinds = enc.accepts || [];
  const isBde = enc.type === 'bitlocker';

  $('#unlock-title').textContent = isBde ? txt('ui.bitlocker_volume') : 'LUKS volume';
  $('#unlock-summary').textContent = [
    part.slot, enc.encryption,
    enc.description || enc.uuid || '', fmt.bytes(part.size),
  ].filter(Boolean).join(' · ');

  $('#unlock-protectors').innerHTML = (enc.protectors || enc.slots || [])
    .map(p => {
      const name = p.type || `Key slot ${p.slot}`;
      const ok = p.usable ?? p.active;
      return `<div class="prot ${ok ? '' : 'is-out'}">
        <span class="dot"></span>
        <span class="pname">${esc(name)}</span>
        <span class="pnote">${esc(p.note || (p.active === false
          ? 'Empty — holds no key.' : ''))}</span></div>`;
    }).join('');

  const canTry = !!enc.recoverable;
  $('#unlock-field').hidden = !canTry;
  $('#unlock-go').hidden = !canTry;
  $('#unlock-label').textContent = kinds.includes('recovery')
    ? (kinds.includes('password') ? txt('ui.unlock.unlock_label') : txt('ui.recovery_key'))
    : 'Password';
  $('#unlock-cancel').textContent = canTry ? 'Not now' : 'Close';
  $('#unlock-note').textContent = (enc.findings || []).join(' ')
    || (canTry ? txt('help.key_held_session_only_never_written_case') : '');
  $('#unlock-error').hidden = true;
  $('#unlock-secret').value = '';
  $('#unlock-secret').type = 'password';
  $('#unlock-show').checked = false;

  previewNone(canTry
    ? txt('help.volume_encrypted_unlock_list_contents')
    : txt('messages.volume_encrypted_cannot_opened_image'));

  dlg.returnValue = '';
  dlg.showModal();
  if (canTry) setTimeout(() => $('#unlock-secret').focus(), 30);

  return await new Promise(resolve => {
    const done = async () => {
      dlg.removeEventListener('close', done);
      if (dlg.returnValue !== 'ok') return resolve(true);
      const secret = $('#unlock-secret').value;
      if (!secret) return resolve(true);
      const t = await api.post('unlock', { part: part.offset, secret });
      const r = await awaitTask(t, 'Unlocking', {
        modal: { title: txt('ui.unlocking_volume'),
                 detail: txt('help.deriving_key_entered_format_specifies_about_million') },
      });
      if (r && r.unlocked) {
        toast(`Unlocked with the ${r.protector || 'key slot ' + r.slot}`
            + `${r.verified ? ' — verified against the volume header' : ''}.`);
        dirCache.clear();
        walkCache.clear();
        S.encInfo = null;
        renderTree();
        previewRoot(part);
        return resolve(true);
      }
      const why = (r && r.reason) || txt('messages.did_open_volume');
      dlg.addEventListener('close', done);
      $('#unlock-error').textContent = why;
      $('#unlock-error').hidden = false;
      $('#unlock-secret').value = '';
      dlg.returnValue = '';
      dlg.showModal();
      setTimeout(() => $('#unlock-secret').focus(), 30);
    };
    dlg.addEventListener('close', done);
  });
}

$('#unlock-show')?.addEventListener('change', e => {
  $('#unlock-secret').type = e.target.checked ? 'text' : 'password';
});

async function previewRoot(part) {
  const token = Symbol();
  pvToken = token;
  const label = partName(part);
  if (!dirCache.has(dirKey(part.offset, null, part.ev_id))) {
    dirSet(label + ' · /', 'reading…',
           `<p class="empty">${txt('ui.reading_root_directory')}</p>`);
  }
  const r = await fetchDir(part.offset, null, '/', part.ev_id);
  if (pvToken !== token) return;
  if (r.error) {
    return dirSet(label + ' · /', 'error', `<p class="empty">${esc(r.error)}</p>`);
  }
  previewDir(r.entries, label + ' · /', part, null, null);
}

function initPreviewPane() {
  const panel = $('.panel-hex');
  const sp = $('#splitter');
  let dragging = false;

  const setH = px => {
    const box = panel.getBoundingClientRect();
    const max = box.height - 150;
    const clamp = v => Math.max(60, Math.min(v, Math.max(60, max)));
    if (panel.classList.contains('mod-mode')) {
      panel.style.setProperty('--viewer-h', clamp(box.bottom - px - 24) + 'px');
    } else {
      panel.style.setProperty('--list-h', clamp(px - box.top) + 'px');
    }
    hex.resize();
  };

  sp.addEventListener('mousedown', e => {
    dragging = true; sp.classList.add('is-dragging');
    e.preventDefault();
  });
  window.addEventListener('mousemove', e => {
    if (!dragging) return;
    setH(e.clientY);
  });
  window.addEventListener('mouseup', () => {
    dragging = false; sp.classList.remove('is-dragging');
  });
  sp.addEventListener('keydown', e => {
    const d = { ArrowUp: -20, ArrowDown: 20 }[e.key];
    if (!d) return;
    e.preventDefault();
    setH($('#splitter').getBoundingClientRect().top + d);
  });

  $$('.viewer-tabs .tab').forEach(t =>
    t.addEventListener('click', () => setViewerPane(t.dataset.pane)));

  $('#btn-maximise').addEventListener('click', () => {
    const on = panel.classList.toggle('full-preview');
    $('#btn-maximise').classList.toggle('is-on', on);
    $('#btn-maximise').setAttribute('aria-pressed', String(on));
    hex.resize();
  });

  setViewerPane('hex');
}

let menuEl = null;

function closeMenu() {
  menuEl?.remove();
  menuEl = null;
  $$('.is-ctx').forEach(el => el.classList.remove('is-ctx'));
}

function markMenuTarget(el) {
  $$('.is-ctx').forEach(n => n.classList.remove('is-ctx'));
  el?.classList.add('is-ctx');
}

function openMenu(x, y, items, anchor = null) {
  closeMenu();
  const live = items.filter(Boolean);
  if (!live.length) return;
  markMenuTarget(anchor);

  const el = document.createElement('div');
  el.className = 'ctx';
  el.setAttribute('role', 'menu');
  for (const it of live) {
    if (it.sep) {
      const hr = document.createElement('div');
      hr.className = 'ctx-sep';
      el.append(hr);
      continue;
    }
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'ctx-item' + (it.danger ? ' is-danger' : '');
    b.setAttribute('role', 'menuitem');
    b.textContent = it.label;
    if (it.hint) {
      const k = document.createElement('span');
      k.className = 'ctx-hint';
      k.textContent = it.hint;
      b.append(k);
    }
    if (it.disabled) {
      b.disabled = true;
      if (it.why) b.title = it.why;
    } else {
      b.addEventListener('click', () => { closeMenu(); it.action(); });
    }
    el.append(b);
  }

  el.style.left = '-9999px';
  el.style.top = '0';
  document.body.append(el);
  const r = el.getBoundingClientRect();
  el.style.left = Math.max(4, Math.min(x, innerWidth - r.width - 4)) + 'px';
  el.style.top = Math.max(4, Math.min(y, innerHeight - r.height - 4)) + 'px';
  menuEl = el;
  el.querySelector('.ctx-item:not([disabled])')?.focus();
}

document.addEventListener('mousedown', e => {
  if (menuEl && !menuEl.contains(e.target)) closeMenu();
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && menuEl) { e.stopPropagation(); closeMenu(); }
});
window.addEventListener('blur', closeMenu);
window.addEventListener('resize', closeMenu);
document.addEventListener('scroll', closeMenu, true);

function entryMenu(e, part) {
  const dir = !!e.is_dir;
  return [
    { label: dir ? 'Open' : txt('ui.show_bytes'), action: () => showEntry(e, part) },
    dir ? null
        : { label: 'Preview',
            action: () => { showEntry(e, part); setViewerPane('preview'); } },
    dir ? (on => ({
            label: on ? txt('ui.list_only_this') : txt('ui.list_all_below'),
            action: () => toggleListAll(!on, part, e),
          }))(isListScope(part, nodeOf(e))) : null,
    { sep: true },
    { label: 'Tag…', action: () => tagDialog(e, part) },
    { label: dir ? txt('ui.hash_everything_here') : 'Hash',
      action: () => hashScope(partOffset(part), dir ? 'folder' : 'item', e,
                              e.name || (dir ? 'folder' : 'file')) },
    dir ? { label: txt('ui.export_folder'), action: () => exportFolder(e, part) }
        : { label: 'Export', action: () => exportEntry(e, part) },
    dir ? null : { label: txt('ui.export'), action: () => exportEntryAs(e, part) },
    dir ? { label: txt('ui.export_folder_and_add'),
            action: () => exportFolder(e, part, { addExhibit: true }) }
        : { label: txt('ui.export_and_add'),
            action: () => exportEntryAs(e, part, '', { addExhibit: true }) },
    { sep: true },
    { label: txt('ui.copy_path'), action: () => copyText(e.path || e.name) },
    { label: txt('ui.copy_name'), action: () => copyText(e.name || '') },
  ];
}

async function exportFolder(e, part, { addExhibit = false } = {}) {
  const dest = await pickPath({ mode: 'dir',
                                title: 'Export ' + (e.name || 'folder') + ' into…' });
  if (dest === '') return;
  const t = await api.post('export/folder', {
    part: partOffset(part), entry: e, dest: dest || null,
    add_exhibit: addExhibit });
  if (t.error) return toast(t.error);
  const r = await awaitTask(t, 'Exporting ' + (e.name || 'folder'), {
    modal: { title: 'Exporting ' + (e.name || 'folder'),
             detail: txt('messages.every_file_beneath_each_hashed_recorded_manifest') },
  });
  if (!r) return;
  if (r.exhibit && r.exhibit.added) {
    adoptOpened(r.exhibit.state);
    renderCases();
    return toast(txt('messages.export.folder_added_as_exhibit',
                     { files: r.files, dir: r.dir }));
  }
  toast(`Exported ${r.files} file(s)${r.failed ? `, ${r.failed} unreadable` : ''}`
        + ` to ${r.dir}`);
}

async function pickPath({ mode = 'open', title = '', dir = '', file = '',
                          kind = 'image' } = {}) {
  const r = await api.post('pick', { mode, title, dir, file, kind })
                     .catch(() => ({ unavailable: txt('messages.engine_did_answer') }));
  if (r.unavailable) { toast(r.unavailable); return null; }
  return r.path || '';
}

function rangeMenu({ offset, length, part = null, label = 'range', ext = '',
                     fragments = null }) {
  const len = Math.max(1, length || 1);
  return [
    { label: txt('ui.show_bytes'), action: () => jumpTo(part, offset, len) },
    { sep: true },
    { label: 'Mark…',
      action: () => saveMark(offset + (part || 0), len, label, 'result') },
    { label: txt('ui.export_bytes'),
      action: () => exportRange({ offset, length: len, part, ext, fragments }) },
    { label: txt('ui.export_bytes_2'),
      action: () => exportRangeAs({ offset, length: len, part, ext, label, fragments }) },
    { sep: true },
    { label: txt('ui.copy_offset'), action: () => copyText('0x' + fmt.hex(offset, 8)) },
  ];
}

async function exportRange({ offset, length, part = null, ext = '', dest = null,
                             fragments = null }) {
  const r = await api.post('export', { part: part ?? undefined, offset, length,
                                       ext: ext || undefined, dest, fragments });
  if (r.error) return toast(r.error);
  toast(txt('messages.toast.exported_with_digest', { size: fmt.bytes(r.bytes), digest: (r.sha256 || '').slice(0, 16) }), 'action');
}

async function exportRangeAs(spec) {
  const name = `${spec.label || 'carved'}-0x${fmt.hex(spec.offset, 8)}`
             + (spec.ext ? '.' + spec.ext : '.bin');
  const dest = await pickPath({ mode: 'save', title: txt('ui.export_bytes'), file: name });
  if (dest === null) return exportRange(spec);
  if (dest === '') return;
  return exportRange({ ...spec, dest });
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied.', 'action');
  } catch {
    toast(txt('messages.toast.browser_refused_clipboard_access'));
  }
}

let attackState = { catalogue: null, tags: [], summary: [], pick: null };

async function loadAttack(suggestFor = null) {
  const r = await api.get('attack', suggestFor ? { suggest: suggestFor } : {})
                    .catch(() => null);
  if (!r || r.error) return null;
  attackState.catalogue = r.catalogue;
  attackState.tags = r.tags || [];
  attackState.summary = r.summary || [];
  return r;
}

function fillAttackPicker(suggested) {
  const sel = $('#tag-attack');
  if (!sel || !attackState.catalogue) return;
  const cat = attackState.catalogue;
  const byTactic = new Map();
  for (const t of cat.techniques) {
    if (!byTactic.has(t.tactic)) byTactic.set(t.tactic, []);
    byTactic.get(t.tactic).push(t);
  }
  const ids = new Set((suggested || []).map(x => x.id));
  let html = `<option value="">${txt('ui.fill_attack_picker.none')}</option>`;
  if (ids.size) {
    html += `<optgroup label="Commonly recorded here — your call">${
      (suggested || []).map(t =>
        `<option value="${esc(t.id)}">${esc(t.id)} · ${esc(t.name)}</option>`)
        .join('')}</optgroup>`;
  }
  for (const [tactic, list] of byTactic) {
    html += `<optgroup label="${esc(list[0].tactic_name || tactic)}">${
      list.map(t => `<option value="${esc(t.id)}">${esc(t.id)} · ${
        esc(t.name)}</option>`).join('')}</optgroup>`;
  }
  sel.innerHTML = html;

  const note = $('#tag-attack-note');
  if (note) {
    note.hidden = false;
    note.textContent = cat.complete
      ? `Catalogue: MITRE ${cat.version || 'imported'}.`
      : txt('help.catalogue_built_subset_version_techniques_disk_image', { version: cat.version });
  }
}

function renderAttackTactics() {
  const box = $('#attack-tactics');
  if (!box) return;
  const cat = attackState.catalogue;
  $('#attack-cat').textContent = cat
    ? (cat.complete ? `MITRE ${cat.version}` : `subset ${cat.version}`) : '';
  $('#attack-cat-note').textContent = cat ? cat.note : '';

  const rows = [];
  const byTactic = new Map();
  for (const t of attackState.summary) {
    if (!byTactic.has(t.tactic)) byTactic.set(t.tactic, []);
    byTactic.get(t.tactic).push(t);
  }
  const tacticName = k => (cat?.tactics || []).find(x => x.id === k)?.name || k;
  for (const [tactic, list] of byTactic) {
    const a = list.reduce((n, t) => n + t.asserted, 0);
    const p = list.reduce((n, t) => n + t.proposed, 0);
    rows.push(`<div class="at-row at-top" data-tactic="${esc(tactic)}"
      >${esc(tacticName(tactic))}<span class="at-n">${a}${
        p ? ` +${p}?` : ''}</span></div>`);
    for (const t of list) {
      const on = attackState.pick === t.technique;
      rows.push(`<div class="at-row at-leaf ${on ? 'is-on' : ''}"
        data-technique="${esc(t.technique)}"
        title="${esc(t.technique_name || '')}">${esc(t.technique)}<span
        class="at-n">${t.asserted}${t.proposed ? ` +${t.proposed}?` : ''}</span></div>`);
    }
  }
  box.innerHTML = rows.length ? rows.join('')
    : `<p class="empty">${txt('help.nothing_attributed_yet_tag_file_mark_give')}</p>`;
  $$('#attack-tactics .at-row[data-technique]').forEach(el =>
    el.addEventListener('click', () => {
      attackState.pick = el.dataset.technique;
      renderAttackTactics();
      renderAttackList();
    }));
}

function renderAttackList() {
  const box = $('#attack-results');
  if (!box) return;
  const pick = attackState.pick;
  const rows = attackState.tags.filter(t => !pick || t.technique === pick);
  if (!rows.length) {
    box.innerHTML = `<p class="empty">${attackState.tags.length
      ? 'Nothing attributed to that technique.'
      : 'No attributions in this case.'}</p>`;
    return;
  }
  const asserted = rows.filter(r => r.asserted).length;
  box.innerHTML = `<div class="results-head">${txt('ui.count.attributions',
      { count: rows.length })} · ${txt('ui.attack.asserted',
      { count: asserted })}${rows.length - asserted
        ? txt('ui.attack.proposed', { count: rows.length - asserted })
        : ''}</div>` +
    rows.map(r => `
      <div class="result ${r.asserted ? '' : 'match-notable'}" data-id="${r.id}">
        <div class="top">
          <span class="kind">${esc(r.technique)}</span>
          <span class="off">${esc(r.target_kind)}</span>
        </div>
        <div class="name">${esc(r.technique_name || '')}</div>
        <div class="path">${esc(r.target_ref)}${r.note ? ' · ' + esc(r.note) : ''}</div>
        <div class="meta">${r.asserted
          ? `asserted by ${esc(r.examiner || 'unattributed')}`
          : `proposed by the tool — not confirmed`} · ${fmt.time(r.created_at)}
          <button class="linkish" data-untag="${r.id}">${txt('ui.render_attack_list.withdraw')}</button></div>
      </div>`).join('');
  $$('#attack-results [data-untag]').forEach(el =>
    el.addEventListener('click', async ev => {
      ev.stopPropagation();
      const r = await api.post('attack/untag', { id: +el.dataset.untag });
      if (r.error) return toast(r.error);
      attackState.tags = r.tags || [];
      attackState.summary = r.summary || [];
      renderAttackTactics();
      renderAttackList();
    }));
}

async function showAttack() {
  await loadAttack();
  renderAttackTactics();
  renderAttackList();
}

$('#btn-attack-refresh')?.addEventListener('click', showAttack);

$('#btn-attack-import')?.addEventListener('click', async () => {
  const path = $('#attack-path').value.trim();
  if (!path) return toast(txt('messages.toast.point_stix_bundle_mitre'));
  const r = await api.post('attack/import',
                           { path, version: $('#attack-version').value.trim() });
  if (r.error) return toast(r.error);
  attackState.catalogue = r.catalogue;
  renderAttackTactics();
  toast(txt('help.techniques_techniques_imported_attributions_already_made_unchanged', { techniques: r.techniques.toLocaleString() }));
});

const nodeIdOf = e => String(e.mft ?? e.inode ?? e.oid ?? e.start_cluster);

function tagsFor(entry) {
  const id = nodeIdOf(entry);
  return (S.tags || []).filter(t => t.node === id);
}

function renderTagStrip(entry) {
  const box = $('#tag-strip');
  if (!box) return;
  const mine = tagsFor(entry);
  box.innerHTML = mine.map(t =>
    `<span class="chip" data-id="${t.id}" title="${esc(t.note || '')}">${
      esc(t.tag)}<button class="x" aria-label="${txt('ui.tags.remove_tag')}">×</button></span>`).join('');
  $$('#tag-strip .chip .x').forEach(el => el.addEventListener('click', async ev => {
    ev.stopPropagation();
    const id = +el.parentElement.dataset.id;
    await api.post('tag/remove', { id });
    await loadTags();
  await loadSavedSearches();
  await loadHashSets();
  await refreshIndexState();
  pollTasks();
    renderTagStrip(entry);
  }));
}

async function tagDialog(entry, part) {
  $('#tag-item').textContent = entry.path || entry.name;
  $('#dlg-tag').dataset.entry = JSON.stringify(entry);
  $('#dlg-tag').dataset.part = part?.offset ?? 0;
  const sel = $('#tag-name');
  sel.innerHTML = (S.suggestedTags || []).map(t =>
    `<option value="${esc(t)}">${esc(t)}</option>`).join('');
  $('#tag-custom').value = '';
  $('#tag-note').value = '';
  $('#tag-attack').value = '';
  const r = await loadAttack(artPick ? artPick.mode : null);
  fillAttackPicker(r && r.suggestions);
  $('#dlg-tag').showModal();
}

async function loadTags() {
  const r = await api.get('tags');
  S.tags = r.items || [];
  S.tagCounts = r.counts || {};
  S.suggestedTags = [...new Set([...(r.suggested || []),
                                 ...Object.keys(S.tagCounts)])];
  renderTags();
  tabCount('tags', S.tags.length);
}

function renderTags() {
  const box = $('#tag-results');
  const filter = $('#tag-filter').value;
  const items = filter ? S.tags.filter(t => t.tag === filter) : S.tags;

  const cur = $('#tag-filter').value;
  $('#tag-filter').innerHTML = `<option value="">${txt('ui.render_tags.all_tags')}</option>` +
    Object.entries(S.tagCounts).map(([t, n]) =>
      `<option value="${esc(t)}">${esc(t)} (${n})</option>`).join('');
  $('#tag-filter').value = cur;

  if (!items.length) {
    box.innerHTML = `<p class="empty">${txt('help.nothing_tagged_yet_select_file_use_tag')}</p>`;
    return;
  }
  box.innerHTML = items.map((t, i) => `
    <div class="result" data-i="${i}">
      <div class="top"><span class="kind">${esc(t.tag)}</span>
        <span class="off">${t.deleted ? 'deleted' : ''}</span></div>
      <div class="name ${t.deleted ? 'is-del' : ''}">${esc(t.name || '')}</div>
      <div class="path">${esc(t.path || '')}</div>
      ${t.note ? `<div class="sub">${esc(t.note)}</div>` : ''}
      <div class="meta">${fmt.bytes(t.size)} · ${esc(t.examiner || '')} ·
        ${fmt.time(t.created_at)}</div>
    </div>`).join('');
  bindResults(box, el => {
    const t = items[+el.dataset.i];
    openTagged(t);
  });
}

async function openTagged(t) {
  const part = partIn(t.evidence_id, t.part);
  if (!part) return toast(txt('messages.toast.partition_evidence'));
  const entry = { name: t.name, path: t.path, size: t.size,
                  is_dir: !!t.is_dir, deleted: !!t.deleted,
                  contiguous: !!t.contiguous };
  const n = t.node === 'null' ? null : Number(t.node);
  const fsName = (part.detected || '').toUpperCase();
  Object.assign(entry, nodeEntry(fsName, n));
  showEntry(entry, part);
}

const tray = { open: false, timer: null, tasks: [] };

async function pollTasks() {
  let running = 0;
  try {
    if (!S.open) {
      tray.tasks = [];
    } else {
      const r = await api.get('tasks');
      tray.tasks = r.tasks || [];
      running = r.running || 0;
    }
    $('#tray-spin').hidden = !running;
    $('#tray-label').textContent = !S.open ? 'No tasks'
      : running ? txt('ui.count.tasks_running', { count: running })
      : (tray.tasks.length ? `${tray.tasks.length} finished` : 'No tasks');
    $('#tray').classList.toggle('is-busy', running > 0);
    if (tray.open) renderTray();
  } catch {
  } finally {
    clearTimeout(tray.timer);
    tray.timer = setTimeout(pollTasks, running ? 700 : (S.open ? 4000 : 10000));
  }
}

function renderTray() {
  const box = $('#tray-list');
  if (!tray.tasks.length) {
    box.innerHTML = `<p class="empty">${S.open ? 'Nothing has run yet.'
      : 'No evidence open.'}</p>`;
    return;
  }
  box.innerHTML = tray.tasks.slice().reverse().map(t => {
    const pct = Math.round((t.progress || 0) * 100);
    return `<div class="tray-task is-${t.state}">
      <div class="tt-top">
        <span class="tt-name">${esc(t.label || t.name)}</span>
        ${t.state === 'running'
          ? `<button class="tt-cancel" data-cancel="${t.id}">Cancel</button>`
          : `<span class="tt-state">${esc(t.state)}</span>`}
      </div>
      ${t.detail ? `<div class="tt-detail">${esc(t.detail)}</div>` : ''}
      <div class="tt-bar"><i style="width:${pct}%"></i></div>
      <div class="tt-meta">${[
        t.state === 'running' ? pct + '%' : null,
        t.elapsed != null ? `${t.elapsed}s` : null,
        t.error ? esc(t.error) : null,
      ].filter(Boolean).join(' · ')}</div>
    </div>`;
  }).join('');
  $$('#tray-list [data-cancel]').forEach(el =>
    el.addEventListener('click', async () => {
      el.disabled = true;
      el.textContent = 'Cancelling…';
      await api.post('task/cancel', { id: el.dataset.cancel });
      pollTasks();
    }));
}

function initTray() {
  $('#tray-toggle').addEventListener('click', () => {
    tray.open = !tray.open;
    $('#tray-panel').hidden = !tray.open;
    $('#tray-toggle').setAttribute('aria-expanded', String(tray.open));
    if (tray.open) {
      renderTray();
      pollTasks();
    }
  });
  $('#tray-clear').addEventListener('click', async () => {
    await api.post('tasks/clear', {});
    pollTasks();
  });
  document.addEventListener('click', e => {
    if (!tray.open) return;
    if (!$('#tray').contains(e.target)) {
      tray.open = false;
      $('#tray-panel').hidden = true;
      $('#tray-toggle').setAttribute('aria-expanded', 'false');
    }
  });
}

const runningTasks = new Map();

function trackTask(id, label, pct) {
  runningTasks.set(id, { label, pct });
  paintTask();
}

function untrackTask(id) {
  runningTasks.delete(id);
  paintTask();
}

function paintTask() {
  const all = [...runningTasks.values()];
  if (!all.length) return setTask('', 0);
  setTask(all.length === 1 ? all[0].label
                          : txt('ui.count.tasks_running',
                                { count: all.length }),
          all.reduce((sum, t) => sum + t.pct, 0) / all.length);
}

function setTask(text, pct) {
  $('#stat-task').innerHTML = text
    ? `${text}<span class="progress"><i style="width:${(pct * 100).toFixed(0)}%">
       </i></span>` : '';
}

const busy = {
  dlg: null,
  taskId: null,
  session: 0,
  open(title, detail, taskId = null) {
    this.dlg = this.dlg || $('#dlg-busy');
    this.taskId = taskId;
    $('#busy-title').textContent = title;
    $('#busy-detail').textContent = detail || '';
    const btn = $('#busy-cancel');
    btn.hidden = !taskId;
    btn.disabled = false;
    btn.textContent = 'Cancel';
    $('#busy-min').title = taskId
      ? txt('messages.minimise_work_keeps_running_watch_task_tray')
      : txt('ui.minimise_work_keeps_running_esc');
    this.set(0);
    if (!this.dlg.open) this.dlg.showModal();
    return ++this.session;
  },
  set(p) {
    $('#busy-fill').classList.remove('is-waiting');
    const pct = Math.max(0, Math.min(1, p || 0));
    $('#busy-fill').style.width = (pct * 100).toFixed(1) + '%';
    $('#busy-pct').textContent = Math.round(pct * 100) + '%';
  },
  waiting(text) {
    $('#busy-fill').classList.add('is-waiting');
    $('#busy-fill').style.width = '35%';
    $('#busy-pct').textContent = text || 'working…';
  },
  close(session = null) {
    if (session !== null && session !== this.session) return;
    this.taskId = null;
    if (this.dlg?.open) this.dlg.close();
  },
};

$('#busy-min').addEventListener('click', () => {
  const tracked = busy.taskId;
  busy.dlg?.close();
  if (tracked) toast(txt('messages.toast.still_running_follow_task_tray'), 'task');
});

$('#busy-cancel').addEventListener('click', async () => {
  if (!busy.taskId) return;
  const btn = $('#busy-cancel');
  btn.disabled = true;
  btn.textContent = 'Cancelling…';
  await api.post('task/cancel', { id: busy.taskId });
  pollTasks();
});

async function awaitTask(task, label, { modal = null, onPartial = null,
                                        indeterminate = false } = {}) {
  if (task.error) { toast(task.error); return null; }
  const mine = modal ? busy.open(modal.title, modal.detail, task.id) : null;
  pollTasks();
  let wait = 30;
  let seen = 0;
  const nameOf = t => (typeof label === 'function' ? label(t) : label);
  try {
    while (true) {
      const t = await api.get('task', onPartial ? { id: task.id, since: seen }
                                                : { id: task.id });
      if (onPartial && t.new && t.new.length) {
        seen += t.new.length;
        onPartial(t.new, t);
      }
      trackTask(task.id, nameOf(t), t.progress || 0);
      if (modal) {
        if (indeterminate && t.state === 'running') {
          busy.waiting(t.found ? txt('ui.recurse.found',
                                     { n: fmt.count(t.found) })
                               : txt('ui.recurse.working'));
        } else {
          busy.set(t.progress || 0);
        }
      }
      if (t.state === 'done') return t.result;
      if (t.state === 'cancelled') { toast(txt('messages.toast.cancelled'), 'task'); return null; }
      if (t.state === 'error') { toast(t.error); return null; }
      await new Promise(r => setTimeout(r, wait));
      wait = Math.min(wait * 1.6, 250);
    }
  } finally {
    untrackTask(task.id);
    if (modal) busy.close(mine);
  }
}

const volmapCache = new Map();

const SPAN_COLOURS = {
  boot: '--amber',
  metadata: '--c-struct',
  journal: '--good',
  bitmap: '--c-text',
  table: '--c-struct',
  data: '--dimmer',
};

const profileCache = new Map();
const profileKey = (part, scope = S.scope) => {
  const base = `${S.activeId ?? '?'}:${part ?? 'image'}`;
  if (!scope || !scope.file || !scope.entry) return base;
  const e = scope.entry;
  const node = e.oid ?? e.mft ?? e.inode ?? e.start_cluster ?? e.path;
  return `${base}:file:${node}${scope.stream ? ':' + scope.stream : ''}`;
};
let profileToken = null;

let volmapToken = null;

async function loadVolumeMap() {
  const part = S.scope.part;
  if (!S.open || S.scope.file || part == null) { S.volmap = null; core.draw(); return; }
  const key = `${S.activeId ?? '?'}:${part}`;
  const hit = volmapCache.get(key);
  if (hit) { S.volmap = hit; core.draw(); return; }
  const token = Symbol();
  volmapToken = token;
  S.volmap = null;
  const r = await api.get('volumemap', { part, ev: S.activeId ?? undefined })
    .catch(() => null);
  if (volmapToken !== token) return;
  if (!r || r.error) { S.volmap = null; return; }
  volmapCache.set(key, r);
  S.volmap = r;
  core.draw();
}

async function runProfile() {
  if (!S.open) return;
  const key = profileKey(S.scope.part);
  const token = Symbol();
  profileToken = token;
  const buckets = S.scope.file
    ? Math.max(1, Math.min(1200, S.scope.size || 1)) : 1200;
  const t = await api.post('profile', {
    part: S.scope.part, buckets,
    entry: S.scope.entry || undefined,
    stream: S.scope.stream || undefined });
  const res = await awaitTask(t, 'Profiling');
  if (profileToken !== token) return;
  if (res) {
    profileCache.set(key, res);
    S.profile = res;
    renderLegend();
    core.draw();
  }
}

function renderLegend() {
  const seen = new Set((S.profile?.buckets || []).map(b => b[0]));
  $('#core-legend').innerHTML = [...seen].sort().map(c =>
    `<span title="${CLASS_LABELS[c]}"><i style="background:var(${
      CLASS_COLOURS[c]})"></i>${CLASS_LABELS[c]}</span>`).join('');
}

async function runVerify() {
  const t = await api.post('verify');
  const r = await awaitTask(t, 'Verifying');
  if (!r) return;
  const badge = $('#integrity');
  badge.hidden = false;
  if (r.md5_match === true) {
    badge.dataset.state = 'verified';
    badge.textContent = txt('ui.hashes_verified');
  } else if (r.stored_md5) {
    badge.dataset.state = 'failed';
    badge.textContent = txt('ui.hash_mismatch');
  } else {
    badge.dataset.state = 'unchecked';
    badge.textContent = txt('ui.stored_hash');
  }
  toast(r.md5_match ? txt('messages.acquisition_hashes_match_media')
    : `Recomputed MD5 ${r.computed_md5}`);
  showPartition(S.image);
}

function scopeOptions() {
  const opts = [`<option value="">${txt('ui.whole_image')}</option>`];
  const parts = S.volumes?.partitions || [];
  parts.forEach(p => {
    opts.push(`<option value="${p.offset}">${esc(partLabel(p, parts))}</option>`);
  });
  $('#carve-scope').innerHTML = opts.join('');
  $('#find-scope').innerHTML = opts.join('');
  const mountable = parts
    .filter(p => p.allocated !== false && p.detected)
    .map(p => `<option value="${p.offset}">${esc(partLabel(p, parts))}</option>`)
    .join('') || `<option value="">${txt('ui.mountable_filesystem')}</option>`;
  $('#hash-scope').innerHTML = mountable;
  $('#art-scope').innerHTML = mountable;
  const wasTagged = $('#time-scope').value === 'tagged';
  $('#time-scope').innerHTML = mountable
    + `<option value="tagged">${txt('ui.timeline.tagged')}</option>`;
  if (wasTagged) $('#time-scope').value = 'tagged';
  const cur = S.scope.part ?? '';
  $('#carve-scope').value = cur;
  $('#find-scope').value = cur;
  if (cur !== '') {
    if ($('#time-scope').value !== 'tagged') $('#time-scope').value = cur;
    $('#hash-scope').value = cur;
  }
}

async function doCarve() {
  const partVal = $('#carve-scope').value;
  const part = partVal === '' ? null : +partVal;
  const pick = carveSelection();
  if (pick.extensions && !pick.extensions.length && !pick.custom.length) {
    return toast(txt('messages.carve.nothing_selected'));
  }
  carveRunning = true;
  $('#btn-carve').disabled = true;
  const t = await api.post('carve', {
    part,
    unallocated_only: $('#carve-unalloc').checked,
    alignment: $('#carve-aligned').checked ? 0 : 1,
    extensions: pick.extensions,
    custom: pick.custom,
  }).catch(() => null);
  if (!t || t.error) {
    carveRunning = false;
    carvePickSummary();
    return toast((t && t.error) || txt('messages.carve.signature_unchecked'));
  }
  S.carveHits = [];
  renderCarve(part);
  const r = await awaitTask(t,
    tk => tk.found ? txt('ui.count.files_located', { count: tk.found })
                   : 'Carving',
    { onPartial: (items) => {
        S.carveHits = S.carveHits.concat(items.map(stampExhibit));
        renderCarve(part);
        tabCount('carve', S.carveHits.length);
      } });
  carveRunning = false;
  carvePickSummary();
  if (!r) return;
  S.carveHits = r.hits.map(stampExhibit);
  renderCarve(part);
  tabCount('carve', r.hits.length);
}

function renderCarve(part) {
  const box = $('#carve-results');
  if (!S.carveHits.length) {
    box.innerHTML = `<p class="empty">${txt('help.nothing_found_these_settings_try_turning_off')}</p>`;
    return;
  }
  box.innerHTML = S.carveHits.map((h, i) => `
    <div class="result" data-i="${i}" data-off="${h.offset}" data-part="${
      part ?? ''}">
      <div class="top">
        <span class="kind">${esc(h.ext.toUpperCase())}</span>
        <span>${fmt.bytes(h.length)}</span>
        ${h.bounded ? '' : `<span class="flag warn">${txt('ui.carve.estimated')}</span>`}
        ${h.fragments ? `<span class="flag warn">${txt('ui.carve.fragmented')}</span>` : ''}
        ${h.custom ? `<span class="flag">${txt('ui.carve.custom_flag')}</span>` : ''}
        <span class="off">0x${fmt.hex(h.offset, 8)}</span>
      </div>
      <div class="sub">${esc(h.type)} · ${esc(carveMethod(h.method))}${
        h.entropy != null ? ` · ${txt('ui.carve.entropy', { e: h.entropy })}` : ''}</div>
    </div>`).join('');
  const carvePart = el => el.dataset.part === '' ? null : +el.dataset.part;
  bindResults(box, (el) => {
    const h = S.carveHits[+el.dataset.i];
    jumpTo(carvePart(el), h.offset, h.length, h.evidence);
    showCarveHit(h, carvePart(el));
  }, el => {
    const h = S.carveHits[+el.dataset.i];
    return h && rangeMenu({ offset: h.offset, length: h.length,
                            part: carvePart(el), ext: h.ext,
                            fragments: h.fragments,
                            label: `Carved ${(h.ext || '').toUpperCase()}` });
  });
  core.draw();
}

function showCarveHit(h, part) {
  $('#inspect').innerHTML = `
    <div class="title">${esc(h.type)}</div>
    <div class="subtitle">${txt('ui.carved_referenced_any_directory_entry')}</div>
    ${kv([
      [txt('ui.kv.offset'), `0x${fmt.hex(h.offset, 10)}`, true],
      [txt('ui.kv.length'), fmt.bytes(h.length), true],
      [txt('ui.kv.extension'), h.ext],
      [txt('ui.kv.length_from'), carveMethod(h.method)],
      h.entropy != null && [txt('ui.kv.entropy'), h.entropy + ' bits/byte'],
      h.gap && [txt('ui.kv.gap'), fmt.bytes(h.gap.length)],
    ])}
    ${h.bounded ? '' : `<div class="notice">${txt('help.carve.estimated_notice')}</div>`}
    ${h.gap ? `<div class="notice">${txt('help.carve.fragmented_notice',
      { bytes: fmt.bytes(h.gap.length) })}</div>` : ''}
    <div class="actions">
      <button class="ghost" id="btn-carve-export">${txt('ui.show_entry.export')}</button>
      <button class="ghost" id="btn-carve-mark">${txt('ui.show_carve_hit.mark')}</button>
    </div>`;
  $('#btn-carve-export').addEventListener('click', async () => {
    const r = await api.post('export', { part, offset: h.offset,
      length: h.length, ext: h.ext, fragments: h.fragments });
    toast(txt('messages.toast.exported_with_digest', { size: fmt.bytes(r.bytes), digest: r.sha256.slice(0, 16) }), 'action');
  });
  $('#btn-carve-mark').addEventListener('click', () =>
    saveMark(h.offset + (part || 0), h.length, `Carved ${h.ext.toUpperCase()}`,
             'carver'));
}

const CARVE_CATEGORY = {
  images: 'ui.carve.category.images', documents: 'ui.carve.category.documents',
  archives: 'ui.carve.category.archives', databases: 'ui.carve.category.databases',
  email: 'ui.carve.category.email', media: 'ui.carve.category.media',
  system: 'ui.carve.category.system', executables: 'ui.carve.category.executables',
};
const CARVE_LENGTH = {
  structure: 'ui.carve.length.structure', footer: 'ui.carve.length.footer',
  estimate: 'ui.carve.length.estimate',
};
const CARVE_METHOD = {
  structure: 'ui.carve.method.structure', footer: 'ui.carve.method.footer',
  next_header: 'ui.carve.method.next_header',
  allocated: 'ui.carve.method.allocated',
  empty_sector: 'ui.carve.method.empty_sector', limit: 'ui.carve.method.limit',
};

let carveRunning = false;

function carveMethod(m) {
  return CARVE_METHOD[m] ? txt(CARVE_METHOD[m]) : m;
}

async function loadCarveTypes() {
  const r = await api.get('carve/types').catch(() => null);
  if (!r || r.error || !Array.isArray(r.types)) return;
  S.carveTypes = r;
  renderCarvePick();
}

function carveOff() { return new Set(S.prefs?.carve_types_off || []); }
function carveSignatures() { return S.prefs?.carve_signatures || []; }

function carveSelection() {
  const types = S.carveTypes?.types;
  const off = carveOff();
  return {
    extensions: types
      ? types.filter(t => !off.has(t.ext)).map(t => t.ext) : undefined,
    custom: carveSignatures().filter(s => s.on !== false),
  };
}

function renderCarvePick() {
  const box = $('#carve-types');
  const r = S.carveTypes;
  if (!box || !r) return;
  const off = carveOff();
  const open = new Set($$('details[open]', box).map(d => d.dataset.cat));
  const groups = r.categories
    .map(cat => [cat, r.types.filter(t => t.category === cat)])
    .filter(([, rows]) => rows.length);
  box.innerHTML = groups.map(([cat, rows]) => {
    const on = rows.filter(t => !off.has(t.ext)).length;
    return `
      <details class="carve-cat" data-cat="${esc(cat)}"${open.has(cat) ? ' open' : ''}>
        <summary>
          <input type="checkbox" data-cat-check="${esc(cat)}"${on ? ' checked' : ''}>
          <span>${esc(CARVE_CATEGORY[cat] ? txt(CARVE_CATEGORY[cat]) : cat)}</span>
          <span class="n">${txt('ui.carve.n_of', { on, total: rows.length })}</span>
        </summary>
        ${rows.map(t => `
          <label class="check carve-type" title="${esc(txt('tooltips.carve.type_headers',
                                                           { headers: t.headers.join(' · ') }))}">
            <input type="checkbox" data-ext="${esc(t.ext)}"${off.has(t.ext) ? '' : ' checked'}>
            <span class="nm">${esc(t.name)}<em>.${esc(t.ext)} · ${
              esc(txt(CARVE_LENGTH[t.length] || CARVE_LENGTH.estimate))}</em></span>
          </label>`).join('')}
      </details>`;
  }).join('');
  for (const [cat, rows] of groups) {
    const on = rows.filter(t => !off.has(t.ext)).length;
    const cb = box.querySelector(`[data-cat-check="${cat}"]`);
    if (cb) cb.indeterminate = on > 0 && on < rows.length;
  }
  renderCarveCustom();
  carvePickSummary();
}

function renderCarveCustom() {
  const box = $('#carve-custom');
  if (!box) return;
  const sigs = carveSignatures();
  box.innerHTML = sigs.length ? sigs.map(s => `
    <div class="carve-sig">
      <label class="check carve-type">
        <input type="checkbox" data-sig="${esc(s.id)}"${s.on === false ? '' : ' checked'}>
        <span class="nm">${esc(s.name)}<em>.${esc(s.ext)}</em></span>
      </label>
      <code>${esc(s.header)}${s.footer ? ` … ${esc(s.footer)}` : ''}</code>
      <div class="acts">
        <button type="button" class="linkish" data-edit="${esc(s.id)}">${txt('ui.carve.edit')}</button>
        <button type="button" class="linkish" data-del="${esc(s.id)}">${txt('ui.carve.remove')}</button>
      </div>
    </div>`).join('')
    : `<p class="hint">${txt('ui.carve.no_custom')}</p>`;
}

function carvePickSummary() {
  const r = S.carveTypes;
  const sel = carveSelection();
  const types = sel.extensions ? sel.extensions.length : 0;
  const custom = sel.custom.length;
  const n = $('#carve-pick-n');
  if (n) {
    n.textContent = !r ? '' : custom
      ? txt('ui.carve.picked_custom', { types, total: r.types.length, custom })
      : txt('ui.carve.picked', { types, total: r.types.length });
  }
  const none = !!r && !types && !custom;
  const btn = $('#btn-carve');
  if (!carveRunning) btn.disabled = none;
  btn.title = none ? txt('tooltips.carve.nothing_selected') : '';
}

function setAllCarve(on) {
  const r = S.carveTypes;
  savePref('carve_types_off', on || !r ? [] : r.types.map(t => t.ext));
  const sigs = carveSignatures();
  if (sigs.length) savePref('carve_signatures', sigs.map(s => ({ ...s, on })));
  renderCarvePick();
}

function sizeText(n) {
  if (!Number.isFinite(n) || n <= 0) return '';
  if (n % 1048576 === 0) return `${n / 1048576} MB`;
  if (n % 1024 === 0) return `${n / 1024} KB`;
  return String(n);
}

function sigFromForm() {
  const num = v => (v === '' ? 0 : Number(v));
  const max = $('#sig-max').value;
  return {
    name: $('#sig-name').value,
    ext: $('#sig-ext').value,
    header: $('#sig-header').value,
    header_offset: num($('#sig-offset').value),
    footer: $('#sig-footer').value,
    footer_mode: $('#sig-footer-mode').value,
    footer_extra: num($('#sig-footer-extra').value),
    missing_footer: $('#sig-missing').value,
    max_size: parseSize(max) ?? max,
    stop_at_allocated: $('#sig-stop-alloc').checked,
    stop_at_zeros: $('#sig-stop-zeros').checked,
  };
}

function listOr(items) {
  try {
    return new Intl.ListFormat(document.documentElement.lang || undefined,
                               { type: 'disjunction' }).format(items);
  } catch {
    return items.join(', ');
  }
}

function explainSignature() {
  const s = sigFromForm();
  const hasFooter = !!s.footer.trim();
  for (const id of ['#sig-footer-mode', '#sig-footer-extra', '#sig-missing']) {
    $(id).disabled = !hasFooter;
  }
  const lines = [];
  if (hasFooter) {
    const extra = s.footer_extra > 0;
    const key = s.footer_mode === 'last'
      ? (extra ? 'ui.carve.explain.footer_last_extra' : 'ui.carve.explain.footer_last')
      : (extra ? 'ui.carve.explain.footer_first_extra' : 'ui.carve.explain.footer_first');
    lines.push(txt(key, { n: fmt.count(s.footer_extra) }));
    lines.push(txt(s.missing_footer === 'estimate'
      ? 'ui.carve.explain.missing_estimate' : 'ui.carve.explain.missing_discard'));
  }
  if (!hasFooter || s.missing_footer === 'estimate') {
    const bounds = [txt('ui.carve.bound.next_header')];
    if (s.stop_at_allocated) bounds.push(txt('ui.carve.bound.allocated'));
    if (s.stop_at_zeros) bounds.push(txt('ui.carve.bound.empty_sector'));
    bounds.push(txt('ui.carve.bound.limit', {
      size: Number.isFinite(s.max_size) ? fmt.bytes(s.max_size) : '?' }));
    lines.push(txt('ui.carve.explain.estimate', { bounds: listOr(bounds) }));
  }
  $('#sig-method').textContent = lines.join(' ');
}

function editCarveSignature(existing) {
  const dlg = $('#dlg-carve-sig');
  const s = existing || {
    header_offset: 0, footer_mode: 'first', footer_extra: 0,
    missing_footer: 'discard', max_size: 8 << 20,
    stop_at_allocated: true, stop_at_zeros: false };
  $('#sig-title').textContent = txt(existing
    ? 'ui.carve.sig.title_edit' : 'ui.carve.sig.title_add');
  $('#sig-name').value = s.name || '';
  $('#sig-ext').value = s.ext || '';
  $('#sig-header').value = s.header || '';
  $('#sig-offset').value = s.header_offset || 0;
  $('#sig-max').value = sizeText(s.max_size);
  $('#sig-footer').value = s.footer || '';
  $('#sig-footer-mode').value = s.footer_mode || 'first';
  $('#sig-footer-extra').value = s.footer_extra || 0;
  $('#sig-missing').value = s.missing_footer || 'discard';
  $('#sig-stop-alloc').checked = s.stop_at_allocated !== false;
  $('#sig-stop-zeros').checked = !!s.stop_at_zeros;
  $('#sig-error').hidden = true;
  explainSignature();
  dlg.returnValue = '';
  dlg.showModal();
  setTimeout(() => $('#sig-name').focus(), 30);

  const done = async () => {
    if (dlg.returnValue !== 'ok') {
      dlg.removeEventListener('close', done);
      return;
    }
    const r = await api.post('carve/signature', { signature: sigFromForm() })
      .catch(() => null);
    if (!r || r.error) {
      $('#sig-error').textContent = (r && r.error)
        || txt('messages.carve.signature_unchecked');
      $('#sig-error').hidden = false;
      dlg.returnValue = '';
      dlg.showModal();
      return;
    }
    dlg.removeEventListener('close', done);
    const id = existing?.id
      || `s${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
    const saved = { ...r.signature, id, on: existing ? existing.on !== false : true };
    const list = carveSignatures();
    savePref('carve_signatures', list.some(x => x.id === id)
      ? list.map(x => (x.id === id ? saved : x)) : [...list, saved]);
    renderCarvePick();
  };
  dlg.addEventListener('close', done);
}

function parseSize(s) {
  const t = (s || '').trim();
  if (!t) return null;
  const m = /^([\d.]+)\s*([kmgt]?)b?$/i.exec(t);
  if (!m) return null;
  const mult = { '': 1, k: 1024, m: 1048576, g: 1073741824, t: 1099511627776 };
  return Math.round(parseFloat(m[1]) * mult[m[2].toLowerCase()]);
}

function currentFilters() {
  const exts = $('#f-ext').value.split(',').map(s => s.trim().replace(/^\./, '')
    .toLowerCase()).filter(Boolean);
  const f = {
    extensions: exts.length ? exts : null,
    min_size: parseSize($('#f-min').value),
    max_size: parseSize($('#f-max').value),
    modified_after: $('#f-mod-after').value || null,
    modified_before: $('#f-mod-before').value
      ? $('#f-mod-before').value + 'T23:59:59Z' : null,
    deleted_only: $('#f-deleted').checked,
    files_only: $('#f-files').checked,
  };
  return Object.fromEntries(Object.entries(f).filter(([, v]) =>
    v !== null && v !== false));
}

async function doFind() {
  const partVal = $('#find-scope').value;
  const part = partVal === '' ? null : +partVal;
  const terms = $('#find-terms').value.split(',').map(s => s.trim()).filter(Boolean);
  if (!terms.length) return toast(txt('messages.toast.enter_something_search'));
  const encodings = [];
  if ($('#enc-ascii').checked) encodings.push('ascii');
  if ($('#enc-u16').checked) encodings.push('utf-16le');
  const mode = $('#find-mode').value;

  if (mode !== 'media') {
    S.lastSearchPart = part;
    if (mode === 'indexed') return doIndexedFind(part, terms);
    return doFileFind(part, terms, encodings, mode);
  }
  S.lastSearchPart = null;

  $('#btn-find').disabled = true;
  const t = await api.post('search', { part, terms, encodings,
                                       regex: $('#find-regex').checked });
  const r = await awaitTask(t, 'Searching');
  $('#btn-find').disabled = false;
  if (!r) return;
  S.findHits = r.hits.map(stampExhibit);
  const box = $('#find-results');
  if (!r.hits.length) {
    box.innerHTML = `<p class="empty">${txt('help.matches_windows_stores_most_text_utf_16le')}</p>`;
    return;
  }
  box.innerHTML = r.hits.map((h, i) => {
    const pre = esc(h.context.slice(0, h.match_at));
    const mid = esc(h.context.slice(h.match_at, h.match_at + h.length));
    const post = esc(h.context.slice(h.match_at + h.length));
    return `<div class="result" data-off="${h.offset}" data-part="${part ?? ''}"
      data-len="${h.length}" data-i="${i}">
      <div class="top"><span class="kind">${h.encoding}</span>
        <span class="off">0x${fmt.hex(h.offset, 8)}</span></div>
      <div class="sub">${pre}<mark>${mid}</mark>${post}</div></div>`;
  }).join('');
  bindResults(box, el => jumpTo(
    el.dataset.part === '' ? null : +el.dataset.part,
    +el.dataset.off, +el.dataset.len,
    (S.findHits[+el.dataset.i] || {}).evidence),
    el => rangeMenu({ offset: +el.dataset.off,
                      length: +(el.dataset.len || 1),
                      part: el.dataset.part === '' ? null : +el.dataset.part,
                      label: txt('ui.search_hit') }));
  tabCount('find', r.hits.length);
}

async function doFileFind(part, terms, encodings, mode) {
  $('#btn-find').disabled = true;
  const scan = $('#f-scan').value;
  const t = await api.post('search/files', {
    part, terms, encodings, mode,
    regex: $('#find-regex').checked,
    case_sensitive: $('#find-case').checked,
    filters: currentFilters(),
    full: scan === 'full',
    scan_bytes: scan === 'full' ? null : +scan,
  });
  const r = await awaitTask(t, txt('ui.searching_files'), {
    modal: { title: txt('ui.searching_files'),
             detail: txt('help.reading_each_allocated_file_turn_deleted_entries') },
  });
  $('#btn-find').disabled = false;
  if (!r) return;
  if (r.error) return toast(r.error);

  S.fileHits = r.hits.map(stampExhibit);
  S.findHits = [];

  const notices = [];
  if (r.partial_files) {
    notices.push(`<div class="notice">${txt('ui.find.partly_read', {
      count: r.partial_files, n: r.partial_files.toLocaleString(),
      bytes: fmt.bytes(r.skipped_bytes) })}${r.partial_examples?.length
        ? '<br>e.g. ' + esc(r.partial_examples.slice(0, 3).join(', ')) : ''}</div>`);
  }
  if (r.partitions_skipped?.length) {
    notices.push(`<div class="notice">${txt('ui.find.not_searched', {
      count: r.partitions_skipped.length,
      volumes: r.partitions_skipped.map(
        p => esc(p.label || ('offset ' + p.part))).join(', ') })}</div>`);
  }
  const coverage = notices.join('');

  const where = r.partitions_searched?.length > 1
    ? `${r.partitions_searched.length} volumes` : null;

  if (!r.hits.length) {
    $('#find-results').innerHTML = coverage + `<p class="empty">${
      txt('ui.find.no_matches', { entries: r.entries.toLocaleString(),
        where: where ? ' across ' + where : '',
        searched: r.searched.toLocaleString(),
        bytes: fmt.bytes(r.bytes_read) })}</p>`;
    $('#find-actions').hidden = true;
    tabCount('find', 0);
    return;
  }
  renderFileHits(r.hits, part, `${r.hits.length} hits${
    where ? ' across ' + where : ''} · ${r.searched} files read`
    + ` · ${fmt.bytes(r.bytes_read)}${r.truncated ? ' · hit limit reached' : ''}`,
    coverage);
}

async function refreshIndexState() {
  const part = $('#find-scope').value === '' ? null : +$('#find-scope').value;
  const r = await api.get('index/status', { part });
  S.indexState = r;
  const el = $('#index-state');
  if (!r.available) {
    el.textContent = 'Index: unavailable (no FTS5)';
    $('#btn-index').disabled = true;
  } else if (r.built) {
    el.textContent = `Index: ${r.documents.toLocaleString()} documents`;
  } else {
    el.textContent = txt('ui.tree.index_state');
  }
  $('#btn-index-clear').hidden = !r.built;
  $('#btn-index').textContent = r.built
    ? txt('ui.rebuild_index') : txt('ui.tree.index');
}

async function buildIndex() {
  const t = await api.post('search/index',
                           { filters: currentFilters(), full: true,
                             whole_disk: true });
  const r = await awaitTask(t, 'Indexing', {
    modal: { title: txt('ui.indexing_whole_disk'),
             detail: txt('help.every_partition_plus_unallocated_space_gaps_runs') },
  });
  if (!r) return;
  if (r.error) return toast(r.error);
  await refreshIndexState();
  pollTasks();
  if (r.whole_disk) return reportDiskIndex(r);
  const pct = Math.round((r.coverage ?? 1) * 100);
  const parts = [
    txt('messages.indexed_indexed_content_files_content_pct', { indexed: r.indexed.toLocaleString(), with_content: r.with_content.toLocaleString(), pct: pct }),
    txt('ui.empty_entries_empty', { empty: r.skip.empty.toLocaleString() }),
    r.skip.unreadable ? `${r.skip.unreadable.toLocaleString()} unreadable` : null,
    r.walk_truncated ? txt('ui.walk_truncated_results_incomplete') : null,
  ].filter(Boolean);
  toast(parts.join(' · ') + '.');
  if (r.walk_truncated) {
    toast(txt('messages.toast.filesystem_walk_hit_limit_index_does_cover'));
  }
}

function reportDiskIndex(r) {
  const fromFiles = r.filesystems.reduce((n, f) => n + (f.indexed || 0), 0);
  const fromRaw = r.regions.reduce((n, x) => n + (x.documents || 0), 0);
  const skipped = r.regions.reduce((n, x) => n + (x.skipped_high_entropy || 0), 0);
  const zeroed = r.regions.reduce((n, x) => n + (x.skipped_zeroed || 0), 0);
  const bits = [
    `${r.documents.toLocaleString()} documents`,
    txt('messages.fromfiles_files_fromraw_raw_regions', { fromFiles: fromFiles.toLocaleString(), fromRaw: fromRaw.toLocaleString() }),
    txt('ui.coverage_media_covered', { coverage: Math.round(r.coverage * 100) }),
    zeroed ? `${fmt.bytes(zeroed)} zeroed` : null,
    skipped ? txt('ui.skipped_skipped_encrypted_compressed', { skipped: fmt.bytes(skipped) }) : null,
  ].filter(Boolean);
  toast(bits.join(' · ') + '.');
  (r.findings || []).forEach(f => toast(f));
}

async function doIndexedFind(part, terms) {
  const r = await api.post('search/indexed', { part, terms, limit: 1000 });
  if (r.error) return toast(r.error);
  S.fileHits = r.hits.map(stampExhibit);
  S.findHits = [];

  const cov = r.coverage || {};
  const note = !cov.summary ? '' :
    `<div class="notice${cov.complete ? ' ok' : ''}">${esc(cov.summary)}${
      cov.complete ? '' :
      ` <button class="ghost" id="btn-sweep-now">Build index of whole disk</button>`
    }</div>`;

  if (!r.hits.length) {
    $('#find-results').innerHTML = note + `<p class="empty">${txt('help.matches_terms_indexed_documents_indexed_documents', { terms: esc(terms.join(', ')), indexed_documents: (r.indexed_documents || 0).toLocaleString() })}</p>`;
    $('#find-actions').hidden = true;
    tabCount('find', 0);
  } else {
    renderFileHits(r.hits, part, `${r.hits.length} hits from ${
      r.indexed_documents.toLocaleString()} indexed documents${
      r.truncated ? ' · truncated' : ''}`, note);
  }

  const sweep = $('#btn-sweep-now');
  if (sweep) sweep.addEventListener('click', buildIndex);
}

async function loadSavedSearches() {
  const r = await api.get('searches');
  S.savedSearches = r.searches || [];
  $('#saved-count').textContent = S.savedSearches.length || '';
  const box = $('#saved-list');
  if (!S.savedSearches.length) {
    box.innerHTML = `<p class="empty">${txt('ui.none_saved')}</p>`;
    return;
  }
  box.innerHTML = S.savedSearches.map(s => `
    <div class="saved" data-id="${s.id}">
      <span class="nm">${esc(s.name)}</span>
      <span class="ct">${s.hit_count}</span>
      <button class="x" data-del="${s.id}" aria-label="${txt('ui.searches.delete')}">×</button>
    </div>`).join('');
  $$('#saved-list .saved .nm').forEach(el => el.addEventListener('click', () =>
    openSavedSearch(+el.parentElement.dataset.id)));
  $$('#saved-list [data-del]').forEach(el => el.addEventListener('click', async ev => {
    ev.stopPropagation();
    await api.post('search/delete', { id: +el.dataset.del });
    loadSavedSearches();
  }));
}

async function openSavedSearch(id) {
  const r = await api.get('search/saved', { id });
  if (r.error) return toast(r.error);
  const part = r.part;
  const hits = r.hits.map(h => ({
    name: h.name, path: h.path, size: h.size, deleted: !!h.deleted,
    is_dir: !!h.is_dir, modified: h.modified, where: h.where_found,
    term: h.term, context: h.context, file_offset: h.file_offset,
    node: h.node, entry: null,
  }));
  S.fileHits = hits.map(stampExhibit);
  renderFileHits(hits, part, `saved "${r.name}" · ${hits.length} hits · ${
    fmt.time(r.created_at)}`);
  $('#find-actions').hidden = true;
}

async function saveCurrentSearch() {
  if (!S.fileHits?.length) return toast(txt('messages.toast.nothing_save'));
  const name = prompt(txt('ui.name_result_set'),
                      $('#find-terms').value.slice(0, 40));
  if (!name) return;
  const r = await api.post('search/save', {
    name,
    part: S.lastSearchPart,
    query: { terms: $('#find-terms').value, mode: $('#find-mode').value },
    hits: S.fileHits,
  });
  if (r.error) return toast(r.error);
  await loadSavedSearches();
  toast(txt('messages.toast.saved_name', { name: name }), 'action');
}

function renderFileHits(hits, part, headline, prefix = '') {
  const box = $('#find-results');
  $('#find-actions').hidden = !hits.length;
  if (!hits.length) {
    box.innerHTML = prefix + `<p class="empty">${txt('ui.render_file_hits.no_matches')}</p>`;
    tabCount('find', 0);
    return;
  }
  box.innerHTML = prefix + `<div class="results-head">${esc(headline)}</div>` +
    hits.map((h, i) => `
      <div class="result ${h.match_kind ? 'match-' + h.match_kind : ''}" data-i="${i}">
        <div class="top">
          <span class="kind">${esc(
            h.kind === 'usn' ? 'change journal'
            : h.raw ? h.kind : (h.where || 'hit'))}${
            h.kind === 'usn'
              ? (h.deleted ? ' · not in the MFT' : ' · still on the volume')
              : (h.deleted && !h.raw ? ' · deleted' : '')}</span>
          <span class="off">${h.raw && h.offset != null
            ? '0x' + fmt.hex(h.offset, 6)
            : h.file_offset != null
            ? '+0x' + fmt.hex(h.file_offset, 6) : ''}</span>
        </div>
        <div class="name ${h.deleted ? 'is-del' : ''}">${esc(h.name || '')}${
          h.match_kind ? ` <span class="hash-flag ${esc(h.match_kind)}">${
            esc(h.match_kind.replace('_', ' '))}</span>` : ''}</div>
        <div class="path">${esc(h.path || '')}</div>
        <div class="sub">${esc(h.context || '')}</div>
        <div class="meta">${fmt.bytes(h.size)} · ${fmt.time(h.modified)}${
          h.more_in_file ? ` · ${h.more_in_file} more in this file` : ''}</div>
      </div>`).join('');
  bindResults(box, el => openHit(hits[+el.dataset.i], part),
    el => {
      const h = hits[+el.dataset.i];
      return h && h.entry ? entryMenu(h.entry, partObj(part)) : null;
    });
  tabCount('find', hits.length);
}

function openHit(h, part) {
  if (!h) return;
  if (h.kind === 'usn' && h.deleted) {
    return toast(txt('help.name_survives_only_change_journal_file_open', { name: h.name, there: h.context || 'recorded there' }));
  }
  const key = h.part != null && h.part !== '' ? Number(h.part) : part;
  if (h.raw && h.offset != null) {
    return jumpTo(key, Math.max(0, h.offset - key), h.size || 512,
                  h.evidence);
  }
  const p = partIn(h.evidence, key);
  if (!p) return toast(txt('messages.toast.partition_evidence'));
  if (h.entry) return showEntry(h.entry, p);
  const entry = { name: h.name, path: h.path, size: h.size,
                  is_dir: !!h.is_dir, deleted: !!h.deleted };
  const n = h.node == null || h.node === 'null' ? null : Number(h.node);
  const fsName = (p.detected || '').toUpperCase();
  Object.assign(entry, nodeEntry(fsName, n));
  showEntry(entry, p);
}

async function doHash() {
  const partVal = $('#hash-scope').value;
  if (partVal === '') return toast(txt('messages.toast.hashing_needs_partition'));
  return hashScope(+partVal, 'all', null);
}

async function hashScope(part, scope, entry, label) {
  const t = await api.post('hash', {
    part, scope, entry,
    filters: scope === 'all' ? currentFilters() : null,
  });
  const r = await awaitTask(t, label ? `Hashing ${label}` : 'Hashing', {
    modal: { title: label ? `Hashing ${label}` : txt('ui.hashing_files'),
             detail: txt('help.md5_sha_1_sha_256_single_pass') },
  });
  if (!r) return;
  S.hashRows = r.rows;
  await loadHashMap(part, true);
  if (dirView.entries.length) renderDirView();
  renderHashes(r, part);
  await loadHashSets();

  const showing = inspecting.entry;
  if (showing && !showing.is_dir && hashOf(showing)) {
    showEntry(showing, inspecting.part, inspecting.from);
  }
}

function renderHashes(r, part) {
  const box = $('#hash-results');
  const rows = r.rows || [];
  if (!rows.length) {
    box.innerHTML = `<p class="empty">${txt('ui.nothing_hashed')}</p>`;
    tabCount('hash', 0);
    return;
  }
  const mc = r.match_counts || {};
  const summary = [
    `${r.hashed.toLocaleString()} files`,
    mc.known_bad ? txt('ui.known_bad_known_bad', { known_bad: mc.known_bad }) : null,
    mc.known_good ? txt('ui.known_good_known_good', { known_good: mc.known_good }) : null,
    mc.notable ? `${mc.notable} notable` : null,
    r.truncated ? txt('ui.list_truncated') : null,
  ].filter(Boolean).join(' · ');

  box.innerHTML = `<div class="results-head">${summary}</div>` +
    rows.map((h, i) => `
      <div class="result ${h.match_kind ? 'match-' + h.match_kind : ''}" data-i="${i}">
        <div class="top">
          <span class="kind">${h.match_kind
            ? esc(h.match_kind.replace('_', ' ')) : 'hashed'}${
            h.partial ? ' · partial' : ''}</span>
          <span class="off">${fmt.bytes(h.size)}</span>
        </div>
        <div class="name ${h.deleted ? 'is-del' : ''}">${esc(h.name || '')}</div>
        <div class="path">${esc(h.path || '')}</div>
        <div class="sub mono">${esc((h.md5 || '').slice(0, 32))}</div>
        ${h.matches ? `<div class="meta">in ${h.matches.map(m =>
          esc(m.set)).join(', ')}</div>` : ''}
      </div>`).join('');
  bindResults(box, el => {
    const h = rows[+el.dataset.i];
    openHit({ ...h, node: h.node }, part);
  });
  tabCount('hash', r.hashed);
}

async function doDuplicates() {
  const box = $('#hash-results');
  box.innerHTML = `<p class="empty">${txt('ui.preview_entry.reading')}</p>`;
  const r = await api.get('hashes/duplicates');
  renderDuplicates(r);
}

function renderDuplicates(r) {
  const box = $('#hash-results');
  const groups = r.groups || [];
  if (!groups.length) {
    box.innerHTML = `<p class="empty">${txt('ui.render_duplicates.none_found')}</p>`;
    tabCount('hash', 0);
    return;
  }
  const totalFiles = groups.reduce((n, g) => n + g.items.length, 0);
  const summary = txt('ui.render_duplicates.summary',
    { sets: groups.length, files: totalFiles });
  box.innerHTML = `<div class="results-head">${esc(summary)}</div>` +
    groups.map(g => `
      <div class="result">
        <div class="top">
          <span class="kind">${txt('ui.render_duplicates.copies',
            { count: g.items.length })}</span>
          <span class="off">${fmt.bytes(g.items[0].size)}</span>
        </div>
        <div class="sub mono">${esc(g.sha256.slice(0, 32))}</div>
        ${g.items.map(it => `<div class="path">${
          esc(it.exhibit || '?')} — ${esc(it.path || it.name || '')}${
          it.deleted ? ' <span class="mis">deleted</span>' : ''}</div>`).join('')}
      </div>`).join('');
  tabCount('hash', totalFiles);
}

async function doSimilar() {
  const box = $('#hash-results');
  box.innerHTML = `<p class="empty">${txt('ui.preview_entry.reading')}</p>`;
  const r = await api.get('hashes/similar');
  renderSimilar(r);
}

function renderSimilar(r) {
  const box = $('#hash-results');
  const pairs = r.pairs || [];
  if (!pairs.length) {
    box.innerHTML = `<p class="empty">${txt('ui.render_similar.none_found')}</p>`;
    tabCount('hash', 0);
    return;
  }
  const summary = txt('ui.render_similar.summary', { pairs: pairs.length });
  box.innerHTML = `<div class="results-head">${esc(summary)}</div>` +
    pairs.map(p => `
      <div class="result">
        <div class="top">
          <span class="kind">${esc(txt('ui.render_similar.score',
            { score: p.score }))}</span>
          <span class="off">${fmt.bytes(p.a.size)}</span>
        </div>
        <div class="path">${esc(p.a.exhibit || '?')} — ${
          esc(p.a.path || p.a.name || '')}${p.a.deleted
            ? ' <span class="mis">deleted</span>' : ''}</div>
        <div class="path">${esc(p.b.exhibit || '?')} — ${
          esc(p.b.path || p.b.name || '')}${p.b.deleted
            ? ' <span class="mis">deleted</span>' : ''}</div>
      </div>`).join('');
  tabCount('hash', pairs.length);
}

async function loadHashSets() {
  const r = await api.get('hashsets');
  S.hashSets = r.sets || [];
  $('#hashset-count').textContent = S.hashSets.length || '';
  const box = $('#hashset-list');
  box.innerHTML = S.hashSets.length ? S.hashSets.map(h => `
    <div class="saved" data-id="${h.id}">
      <span class="nm">${esc(h.name)}<em class="kind ${esc(h.kind)}">${
        esc((h.kind || '').replace('_', ' '))}</em></span>
      <span class="ct">${h.entries.toLocaleString()}</span>
      <button class="x" data-del="${h.id}" aria-label="${txt('ui.hashsets.remove')}">×</button>
    </div>`).join('') : `<p class="empty">${txt('ui.hash_sets_imported')}</p>`;
  $$('#hashset-list [data-del]').forEach(el => el.addEventListener('click', async () => {
    await api.post('hashset/delete', { id: +el.dataset.del });
    loadHashSets();
  }));
}

let artMode = 'recyclebin';

const artCache = new Map();
const artKey = (mode, part) => `${mode}:${part}`;

const ART_RENDER = {
  vss: renderVss, browser: renderBrowser, appcompat: renderAppcompat,
  prefetch: renderPrefetch, shellbags: renderShellbags, mail: renderMail,
  leveldb: renderLevelDbSweep, lnk: renderLnk, recyclebin: renderRecycleBin,
  wallets: renderWallets,
};

const ART_ORDER = ['recyclebin', 'lnk', 'browser', 'appcompat', 'prefetch',
                   'usn', 'shellbags', 'mail', 'leveldb', 'vss', 'wallets'];
const ART_LABEL = {
  recyclebin: 'Recycle Bin', lnk: 'Shortcuts', browser: 'Browsing',
  appcompat: 'Programs', prefetch: 'Execution', usn: txt('ui.change_journal'),
  shellbags: 'Folders', mail: 'Mail', leveldb: 'LevelDB',
  vss: txt('ui.tree.shadow_copies'), wallets: 'Crypto',
};

let artPick = null;

function artCount(mode, r) {
  if (!r || r === true) return null;
  if (mode === 'wallets') {
    return (r.phrases || []).length + (r.files || []).length
         + (r.address_count || 0);
  }
  if (mode === 'browser') {
    return (r.history || []).length + (r.downloads || []).length
         + (r.cookies || []).length;
  }
  if (mode === 'lnk') {
    return (r.items || []).length + (r.jumplists || []).reduce(
      (n, l) => n + (l.entries || []).length, 0);
  }
  for (const k of ['items', 'entries', 'rows', 'hits', 'programs', 'bags',
                   'messages', 'stores', 'copies', 'files']) {
    if (Array.isArray(r[k])) return r[k].length;
  }
  return Array.isArray(r) ? r.length : null;
}

function browserBranches(r) {
  const by = new Map();
  const add = (product, kind, n) => {
    const p = product || txt('ui.unidentified_profile');
    if (!by.has(p)) by.set(p, {});
    by.get(p)[kind] = (by.get(p)[kind] || 0) + n;
  };
  for (const h of r.history || []) add(h.product, h.deleted ? 'Recovered' : 'History', 1);
  for (const d of r.downloads || []) add(d.product, 'Downloads', 1);
  for (const c of r.cookies || []) add(c.product, 'Cookies', 1);
  return [...by.entries()].sort((a, b) => a[0].localeCompare(b[0]));
}

async function loadSavedArtefacts() {
  const r = await api.get('artefacts').catch(() => null);
  if (!r || r.error) return;
  for (const [key, rec] of Object.entries(r.items || {})) {
    artCache.set(key, rec.payload);
  }
  renderArtTree();
  if (r.dropped && r.dropped.length) {
    const names = [...new Set(r.dropped.map(d => ART_LABEL[d.kind] || d.kind))];
    toast(txt('messages.artefacts.dropped',
              { names: names.join(', '), count: names.length }));
  }
}

function renderArtTree() {
  const box = $('#art-tree');
  if (!box) return;
  const partVal = $('#art-scope')?.value;
  if (partVal === '' || partVal == null) { box.innerHTML = ''; return; }
  const part = +partVal;

  const rows = [];
  for (const mode of ART_ORDER) {
    const r = artCache.get(artKey(mode, part));
    if (r === undefined) continue;
    const n = artCount(mode, r);
    const on = artPick && artPick.mode === mode && !artPick.product;
    rows.push(`<div class="at-row at-top ${on ? 'is-on' : ''}"
      data-mode="${mode}">${esc(ART_LABEL[mode] || mode)}${
      n == null ? '' : `<span class="at-n">${n.toLocaleString()}</span>`}</div>`);
    if (mode !== 'browser' || r === true) continue;
    for (const [product, kinds] of browserBranches(r)) {
      rows.push(`<div class="at-row at-mid" data-mode="browser"
        data-product="${esc(product)}">${esc(product)}</div>`);
      for (const [kind, count] of Object.entries(kinds).sort()) {
        const sel = artPick && artPick.mode === 'browser'
                 && artPick.product === product && artPick.kind === kind;
        rows.push(`<div class="at-row at-leaf ${sel ? 'is-on' : ''}"
          data-mode="browser" data-product="${esc(product)}" data-kind="${esc(kind)}"
          >${esc(kind)}<span class="at-n">${count.toLocaleString()}</span></div>`);
      }
    }
  }

  box.innerHTML = rows.length ? rows.join('')
    : `<p class="empty">${txt('ui.nothing_read_yet_pick_artefact_press_examine')}</p>`;
  $$('#art-tree .at-row').forEach(el => el.addEventListener('click', () => {
    artPick = { mode: el.dataset.mode, product: el.dataset.product || null,
                kind: el.dataset.kind || null };
    renderArtTree();
    showArtPick(part);
  }));
}

function showArtPick(part) {
  if (!artPick) return;
  const r = artCache.get(artKey(artPick.mode, part));
  if (r === undefined) return;
  $('#triage-results').hidden = true;
  $('#art-results').hidden = false;
  if (artPick.mode === 'browser' && artPick.product) {
    return renderBrowserSlice(r, part, artPick.product, artPick.kind);
  }
  if (artPick.mode === 'usn') {
    usnPage = 0; usnQuery = ''; usnReason = '';
    return loadUsn(part);
  }
  const draw = ART_RENDER[artPick.mode];
  if (draw) draw(r, part);
}

function renderBrowserSlice(r, part, product, kind) {
  const wanted = h => (h.product || txt('ui.unidentified_profile')) === product;
  const hist = (r.history || []).filter(wanted);
  const dl = (r.downloads || []).filter(wanted);
  const ck = (r.cookies || []).filter(wanted);
  let items, what;
  if (kind === 'Cookies') {
    return drawCookieList($('#art-results'), ck, product);
  }
  if (kind === 'Downloads') {
    items = dl;
    what = txt('ui.browser.downloads', { count: dl.length });
  }
  else if (kind === 'Recovered') {
    items = hist.filter(h => h.deleted);
    what = txt('ui.browser.recovered_urls', { count: items.length });
  } else if (kind === 'History') {
    items = hist.filter(h => !h.deleted);
    what = txt('ui.browser.history_entries', { count: items.length });
  } else { items = hist.concat(dl); what = 'entries'; }
  drawBrowserList($('#art-results'), items, product, what, kind === 'Downloads');
}

function drawCookieList(box, items, product) {
  if (!items.length) {
    box.innerHTML = `<p class="empty">${txt('ui.cookies_product', { product: esc(product) })}</p>`;
    return;
  }
  const enc = items.filter(c => c.encrypted).length;
  box.innerHTML = `<div class="results-head">${esc(product)} · ${
      txt('ui.browser.cookies_from_hosts', {
        count: items.length,
        hosts: new Set(items.map(c => c.host)).size.toLocaleString() })}${
      enc ? ' · ' + txt('ui.browser.values_encrypted', { count: enc })
          : ''}</div>
    <table class="dv-list">
      <thead><tr><th>${txt('ui.draw_cookie_list.host')}</th><th>${txt('ui.render_registry.name')}</th><th>${txt('ui.draw_cookie_list.path')}</th>
        <th>${txt('ui.draw_cookie_list.created')}</th><th>${txt('ui.last_reached')}</th><th>${txt('ui.draw_cookie_list.expires')}</th><th>${txt('ui.draw_cookie_list.flags')}</th></tr></thead>
      <tbody>${items.slice(0, 5000).map(c => `
        <tr>
          <td class="nm">${esc(c.host || '')}</td>
          <td>${esc(c.name || '')}</td>
          <td class="ty2">${esc(c.path || '')}</td>
          <td class="dt">${fmt.time(c.created_at)}</td>
          <td class="dt">${fmt.time(c.last_access)}</td>
          <td class="dt">${fmt.time(c.expires_at)}</td>
          <td class="ty2">${[c.secure && 'secure', c.http_only && 'httpOnly',
                             c.encrypted && 'encrypted value']
                            .filter(Boolean).join(', ')}</td>
        </tr>`).join('')}</tbody></table>`;
}

function drawBrowserList(box, items, product, what, asDownloads) {
  if (!items.length) {
    box.innerHTML = `<p class="empty">${txt('ui.artefacts.none_for', {
      what: what, product: esc(product) })}</p>`;
    return;
  }
  box.innerHTML = `<div class="results-head">${esc(product)} · ${
      items.length.toLocaleString()} ${what}</div>` +
    items.slice(0, 5000).map((h, i) => asDownloads ? `
      <div class="result" data-i="${i}">
        <div class="top">
          <span class="kind">${txt('ui.draw_browser_list.download')}</span>
          <span class="off">${h.total_bytes ? fmt.bytes(h.total_bytes) : ''}</span>
        </div>
        <div class="name">${esc(h.target_path || h.filename || h.url || '')}</div>
        <div class="path">${esc(h.url || '')}</div>
        <div class="meta">${h.started_at ? fmt.time(h.started_at) : 'no timestamp'}${
          h.state ? ' · ' + esc(String(h.state)) : ''}</div>
      </div>` : `
      <div class="result ${h.deleted ? 'match-notable' : ''}" data-i="${i}">
        <div class="top">
          <span class="kind">${esc(h.source || '')}${h.deleted ? ' · recovered' : ''}</span>
          <span class="off">${esc(h.transition || '')}</span>
        </div>
        <div class="name">${esc(h.title || h.url || '')}</div>
        <div class="path">${esc(h.url || '')}</div>
        <div class="meta">${h.visited_at ? fmt.time(h.visited_at) : 'no timestamp'}${
          h.visit_count ? ' · ' + h.visit_count + ' visits' : ''}${
          h.note ? ' · ' + esc(h.note) : ''}</div>
      </div>`).join('');
}

function showCachedArtefact(mode, part) {
  const hit = artCache.get(artKey(mode, part));
  if (!hit) return false;
  if (mode === 'usn') { usnPage = 0; usnQuery = ''; usnReason = ''; loadUsn(part); return true; }
  const draw = ART_RENDER[mode];
  if (!draw) return false;
  draw(hit, part);
  return true;
}

function cacheArtefact(mode, part, r) {
  if (r) {
    artCache.set(artKey(mode, part), r);
    artPick = { mode, product: null, kind: null };
    $('#triage-results').hidden = true;
    $('#art-results').hidden = false;
    renderArtTree();
  }
  return r;
}

async function doArtifacts(force = false) {
  const partVal = $('#art-scope').value;
  if (partVal === '') return toast(txt('messages.toast.pick_filesystem'));
  const part = +partVal;
  const box = $('#art-results');
  $('#triage-results').hidden = true;
  $('#art-results').hidden = false;
  if (!force && showCachedArtefact(artMode, part)) return;
  box.innerHTML = `<p class="empty">${txt('ui.preview_entry.reading')}</p>`;
  if (artMode === 'vss') {
    return renderVss(cacheArtefact('vss', part, await api.get('vss', { part })), part);
  }
  if (artMode === 'browser') {
    const t = await api.post('browser', { part, recover: true });
    const r = await awaitTask(t, txt('ui.browser_history'), {
      modal: { title: txt('ui.collecting_browsing_history'),
               detail: txt('help.finding_every_browser_database_volume_schema_rather') },
    });
    return r ? renderBrowser(cacheArtefact('browser', part, r), part) : null;
  }
  if (artMode === 'appcompat') {
    const t = await api.post('appcompat', { part });
    const r = await awaitTask(t, 'Amcache / ShimCache', {
      modal: { title: txt('ui.reading_amcache_shimcache'),
               detail: txt('help.both_record_programs_machine_knew_about_shimcache') },
    });
    return r ? renderAppcompat(cacheArtefact('appcompat', part, r), part) : null;
  }
  if (artMode === 'prefetch') {
    const t = await api.post('prefetch', { part });
    const r = await awaitTask(t, 'Prefetch', {
      modal: { title: txt('ui.reading_prefetch'),
               detail: txt('help.ran_how_often_files_each_program_opened') },
    });
    return r ? renderPrefetch(cacheArtefact('prefetch', part, r), part) : null;
  }
  if (artMode === 'wallets') {
    const t = await api.post('wallets', { part });
    const r = await awaitTask(t, 'Crypto', {
      modal: { title: txt('ui.looking_wallets_seed_phrases'),
               detail: txt('help.seed_phrases_confirmed_against_their_own_checksum') },
    });
    return r ? renderWallets(cacheArtefact('wallets', part, r), part) : null;
  }
  if (artMode === 'usn') {
    const have = await api.get('usn', { limit: 1 });
    if (have.loaded && have.part === part) {
      usnPage = 0; usnQuery = ''; usnReason = '';
      artCache.set(artKey('usn', part), true);
      return loadUsn(part);
    }
    const t = await api.post('usn', { part });
    const r = await awaitTask(t, txt('ui.change_journal'), {
      modal: { title: txt('ui.reading_change_journal'),
               detail: txt('help.usnjrnl_records_happened_files_rather_creations_renames') },
    });
    if (!r) return null;
    if (!r.present) { $('#art-results').innerHTML =
        `<p class="empty">${esc(r.note)}</p>`; return null; }
    usnPage = 0; usnQuery = ''; usnReason = '';
    artCache.set(artKey('usn', part), true);
    return loadUsn(part);
  }
  if (artMode === 'shellbags') {
    const t = await api.post('shellbags', { part });
    const r = await awaitTask(t, 'Shellbags', {
      modal: { title: txt('ui.reading_shellbags'),
               detail: txt('help.folders_opened_explorer_reconstructed_bagmru_shell_items') },
    });
    return r ? renderShellbags(cacheArtefact('shellbags', part, r), part) : null;
  }
  if (artMode === 'mail') {
    const t = await api.post('mail', { part });
    const r = await awaitTask(t, 'Mail', {
      modal: { title: txt('ui.reading_mail_stores'),
               detail: txt('help.mail_stores_identified_content_rather_extension_msg') },
    });
    return r ? renderMail(cacheArtefact('mail', part, r), part) : null;
  }
  if (artMode === 'leveldb') {
    const t = await api.post('leveldb', { part });
    const r = await awaitTask(t, 'LevelDB', {
      modal: { title: 'Reading LevelDB stores',
               detail: txt('help.local_storage_session_storage_indexeddb_sync_data') },
    });
    return r ? renderLevelDbSweep(cacheArtefact('leveldb', part, r), part) : null;
  }
  if (artMode === 'lnk') {
    busy.open(txt('ui.reading_shortcuts'), txt('ui.sweeping_volume_lnk_files'));
    busy.waiting('parsing…');
    try {
      return renderLnk(cacheArtefact('lnk', part,
                                     await api.get('lnk', { part })), part);
    } finally { busy.close(); }
  }
  renderRecycleBin(cacheArtefact('recyclebin', part,
                                 await api.get('recyclebin', { part })), part);
}

function jumpRows(lists) {
  const rows = [];
  lists.forEach((l, li) => {
    const base = { li, kind: l.kind, source: l.source, name: l.source_name };
    const ents = l.entries || [];
    if (!ents.length) {
      rows.push({ ...base, empty: true,
                  why: (l.findings || [])[0] || l.note || '' });
      return;
    }
    for (const x of ents) {
      if (l.kind === 'automatic') {
        rows.push({ ...base, path: x.path || x.target?.path, when: x.accessed,
                    count: x.access_count, pinned: x.pinned, host: x.hostname,
                    volume: x.target?.volume_serial });
      } else {
        rows.push({ ...base, path: x.target_path, host: x.machine_id,
                    volume: x.volume_serial });
      }
    }
  });
  return rows;
}

function renderLnk(r, part) {
  const box = $('#art-results');
  if (r.error) return box.innerHTML = `<p class="empty">${esc(r.error)}</p>`;
  const items = r.items || [];
  const lists = r.jumplists || [];
  const rows = jumpRows(lists);
  const st = r.stat || {};
  if (!items.length && !lists.length) {
    box.innerHTML = `<p class="empty">${txt('help.readable_shortcuts_seen_entries_seen_empty_empty', { seen: st.seen || 0, empty: st.empty || 0 })}</p>`
      + (st.jumplists ? `<p class="empty">${txt('ui.jumplist.none_readable', { seen: st.jumplists })}</p>` : '');
    tabCount('triage', 0);
    return;
  }
  const machines = [...new Set(items.map(i => i.machine_id).filter(Boolean))];
  const macs = [...new Set(items.map(i => i.mac_address).filter(Boolean))];
  const vols = [...new Set(items.map(i => i.volume_serial).filter(Boolean))];
  const head = [
    txt('ui.items_shortcuts_read', { items: items.length }),
    st.empty ? txt('ui.empty_empty_entries_skipped', { empty: st.empty }) : null,
    st.unparsed ? `${st.unparsed} unreadable` : null,
    machines.length ? `${machines.length} machine(s): ${machines.join(', ')}` : null,
    vols.length ? `volumes ${vols.join(', ')}` : null,
    macs.length ? `MAC ${macs.join(', ')}` : null,
  ].filter(Boolean).join(' · ');

  const shortcuts = items.length ? `<div class="results-head">${esc(head)}</div>` +
    items.map((it, i) => `
      <div class="result ${it.metadata_zeroed ? 'match-notable' : ''}" data-i="${i}">
        <div class="top">
          <span class="kind">${esc(it.drive_type || 'shortcut')}</span>
          <span class="off">${it.target_size ? fmt.bytes(it.target_size) : ''}</span>
        </div>
        <div class="name">${esc(it.target_path || it.source_name || '—')}</div>
        <div class="path">${esc(it.source || '')}</div>
        <div class="meta">${it.target_modified
          ? 'target modified ' + fmt.time(it.target_modified)
          : 'no target timestamps'}${it.machine_id ? ' · ' + esc(it.machine_id) : ''}${
          it.volume_serial ? ' · vol ' + esc(it.volume_serial) : ''}</div>
      </div>`).join('') : '';

  const read = rows.filter(x => !x.empty).length;
  const jumpHead = lists.length || st.jumplists_unparsed
    ? `<div class="results-head">${esc([
        txt('ui.jumplist.heading', { lists: lists.length, entries: read }),
        st.jumplists_unparsed
          ? txt('ui.jumplist.unreadable', { count: st.jumplists_unparsed }) : null,
      ].filter(Boolean).join(' · '))}</div>` : '';
  const notes = lists.filter(l => (l.entries || []).length && (l.findings || []).length)
    .map(l => `<div class="notice">${esc(l.source_name || '')}: ${
      esc(l.findings.join(' '))}</div>`).join('');
  const jumps = rows.map((x, j) => `
      <div class="result" data-j="${j}">
        <div class="top">
          <span class="kind">${esc(x.empty ? txt('ui.jumplist.empty_list')
            : x.kind === 'automatic' ? txt('ui.jumplist.automatic')
            : txt('ui.jumplist.custom'))}</span>
          <span class="off">${x.count ? esc(txt('ui.jumplist.opened_count', { count: x.count })) : ''}</span>
        </div>
        <div class="name">${esc((x.empty ? x.name : x.path) || '—')}</div>
        <div class="path">${esc(x.source || '')}</div>
        <div class="meta">${x.empty ? esc(x.why) : [
          x.when ? txt('ui.jumplist.accessed', { when: fmt.time(x.when) }) : null,
          x.pinned ? esc(txt('ui.jumplist.pinned')) : null,
          x.host ? esc(x.host) : null,
          x.volume ? 'vol ' + esc(x.volume) : null,
        ].filter(Boolean).join(' · ')}</div>
      </div>`).join('');

  box.innerHTML = shortcuts + jumpHead + notes + jumps;
  bindResults(box, el => {
    if (el.dataset.j != null) {
      const l = lists[rows[+el.dataset.j].li];
      if (l?.entry) openHit({ ...l.entry, entry: l.entry }, part);
      return;
    }
    const it = items[+el.dataset.i];
    if (it.entry) openHit({ ...it.entry, entry: it.entry }, part);
  });
  tabCount('triage', items.length + read);
}

function renderRecycleBin(r, part) {
  const box = $('#art-results');
  if (r.error) return box.innerHTML = `<p class="empty">${esc(r.error)}</p>`;
  const items = r.items || [];
  const notes = (r.findings || []).map(f =>
    `<div class="notice">${esc(f)}</div>`).join('');
  if (!items.length) {
    box.innerHTML = notes + `<p class="empty">${r.bins
      ? `${r.bins} recycle bin folder(s) found, but nothing deleted in them.`
      : 'No recycle bin on this volume.'}</p>`;
    tabCount('triage', 0);
    return;
  }
  box.innerHTML = notes + items.map((it, i) => `
    <div class="result ${it.orphan ? 'match-notable' : ''}" data-i="${i}">
      <div class="top">
        <span class="kind">${it.orphan
          ? esc('orphan ' + it.orphan) : (it.source === 'INFO2' ? 'INFO2' : 'deleted')}</span>
        <span class="off">${fmt.bytes(it.size ?? it.recoverable_size)}</span>
      </div>
      <div class="name">${esc(it.original_name || it.r_name || '—')}</div>
      <div class="path">${esc(it.original_path || 'original path unknown')}</div>
      <div class="meta">${it.deleted_at ? 'deleted ' + fmt.time(it.deleted_at)
        : 'deletion time unknown'} · ${esc(it.sid || '')}</div>
    </div>`).join('');
  bindResults(box, el => {
    const it = items[+el.dataset.i];
    if (it.entry) openHit({ ...it.entry, entry: it.entry }, part);
    else toast(txt('messages.toast.content_item_present_volume'));
  });
  tabCount('triage', items.length);
}

function renderVss(r, part) {
  const box = $('#art-results');
  if (r.error) return box.innerHTML = `<p class="empty">${esc(r.error)}</p>`;
  const snaps = r.snapshots || [];
  const notes = (r.findings || []).map(f =>
    `<div class="notice">${esc(f)}</div>`).join('');
  if (!snaps.length) {
    box.innerHTML = notes + `<p class="empty">${esc(r.note
      || 'No shadow copies on this volume.')}</p>`;
    tabCount('triage', 0);
    return;
  }
  box.innerHTML = notes + `<div class="results-head">${txt('ui.snaps_shadow_copies_newest_first', { snaps: snaps.length })}</div>` + snaps.map((s, i) => `
    <div class="result" data-i="${i}">
      <div class="top">
        <span class="kind">${s.unsupported ? 'unreadable' : 'snapshot'}</span>
        <span class="off">${fmt.bytes(s.volume_size)}</span>
      </div>
      <div class="name">${fmt.time(s.created_at)}</div>
      <div class="path">${esc(s.id || '')}</div>
      ${s.unsupported ? `<div class="meta">${esc(s.unsupported)}</div>` : ''}
    </div>`).join('');
  tabCount('triage', snaps.length);
}

function renderBrowser(r, part) {
  const box = $('#art-results');
  const hist = r.history || [];
  const dbs = r.databases || [];
  if (!hist.length) {
    box.innerHTML = `<p class="empty">${txt('ui.browser_history_found_dbs_databases_examined', { dbs: dbs.length })}</p>`;
    tabCount('triage', 0);
    return;
  }
  const products = [...new Set(dbs.map(d => d.product).filter(Boolean))];
  const deleted = hist.filter(h => h.deleted).length;
  box.innerHTML = `<div class="results-head">${txt('ui.browser.summary', {
      count: hist.length, n: hist.length.toLocaleString(),
      databases: dbs.length.toLocaleString() })}${
      products.length ? ' · ' + products.join(', ') : ''}${
      deleted ? ' · ' + deleted + ' recovered from deleted rows' : ''}${
      r.downloads?.length ? ' · ' + r.downloads.length + ' downloads' : ''}</div>` +
    hist.slice(0, 3000).map((h, i) => `
      <div class="result ${h.deleted ? 'match-notable' : ''}" data-i="${i}">
        <div class="top">
          <span class="kind">${esc(h.product || h.source || '')}${
            h.deleted ? ' · deleted' : ''}</span>
          <span class="off">${esc(h.transition || '')}</span>
        </div>
        <div class="name">${esc(h.title || h.url || '')}</div>
        <div class="path">${esc(h.url || '')}</div>
        <div class="meta">${h.visited_at ? fmt.time(h.visited_at)
          : 'no timestamp'}${h.visit_count ? ' · ' + h.visit_count + ' visits' : ''}${
          h.note ? ' · ' + esc(h.note) : ''}</div>
      </div>`).join('');
  tabCount('triage', hist.length);
}

function renderAppcompat(r, part) {
  const box = $('#art-results');
  const am = r.amcache || {};
  const files = am.files || [];
  const progs = am.programs || [];
  const shim = (r.shimcache || []).flatMap(s =>
    (s.entries || []).map(e => ({ ...e, control_set: s.control_set,
                                  format: s.format })));
  const notes = [...(r.findings || []), ...(am.findings || []),
                 ...(r.shimcache || []).flatMap(s => s.findings || [])]
    .map(f => `<div class="notice">${esc(f)}</div>`).join('');

  if (!files.length && !shim.length) {
    box.innerHTML = notes + `<p class="empty">${txt('ui.amcache_shimcache_data')}</p>`;
    tabCount('triage', 0);
    return;
  }
  const head = [
    shim.length ? txt('ui.shim_shimcache_entries_format', { shim: shim.length, format: shim[0].format }) : null,
    files.length ? txt('ui.files_amcache_files', { files: files.length }) : null,
    progs.length ? txt('ui.progs_installed_programs', { progs: progs.length }) : null,
  ].filter(Boolean).join(' · ');

  const rows = shim.map((e, i) => `
    <div class="result" data-k="shim" data-i="${i}">
      <div class="top"><span class="kind">shimcache #${e.order}</span>
        <span class="off">${esc(e.control_set || '')}</span></div>
      <div class="name">${esc((e.path || '').split('\\').pop())}</div>
      <div class="path">${esc(e.path || '')}</div>
      <div class="meta">${e.modified ? 'file modified ' + fmt.time(e.modified)
        : 'no timestamp'}</div>
    </div>`).concat(files.map((f, i) => `
    <div class="result" data-k="am" data-i="${i}">
      <div class="top"><span class="kind">${txt('ui.render_appcompat.amcache')}</span>
        <span class="off">${f.size ? fmt.bytes(f.size) : ''}</span></div>
      <div class="name">${esc(f.name || (f.path || '').split('\\').pop())}</div>
      <div class="path">${esc(f.path || '')}</div>
      <div class="sub mono">${esc(f.sha1 || '')}</div>
      <div class="meta">${esc(f.publisher || '')}${
        f.version ? ' · ' + esc(f.version) : ''}${
        f.linked_at ? ' · linked ' + fmt.time(f.linked_at) : ''}</div>
    </div>`)).join('');

  box.innerHTML = notes + `<div class="results-head">${esc(head)}</div>` + rows;
  tabCount('triage', shim.length + files.length);
}

function renderWallets(r, part) {
  const box = $('#art-results');
  const phrases = r.phrases || [], near = r.near_misses || [];
  const files = r.files || [], addrs = r.addresses || [];
  const notes = [];

  const wl = r.wordlist;
  if (wl && !wl.ok) {
    notes.push(txt('messages.bip_39_wordlist_failed_own_structural_checks')
             + (wl.problems || []).join('; ') + txt('help.seed_phrase_results_run_cannot_relied_upon'));
  }
  if (r.redacted) {
    notes.push(txt('help.restored_case_phrase_text_never_stored_offsets'));
  }
  const head = notes.map(n => `<div class="notice">${esc(n)}</div>`).join('');

  if (!phrases.length && !near.length && !files.length && !addrs.length) {
    box.innerHTML = head + '<p class="empty">No wallets, seed phrases or '
      + 'addresses found on this volume.</p>'
      + `<div class="notice">${txt('help.absence_here_depends_shipped_wordlist_being_correct')}<code>${esc((wl && wl.sha256 || '').slice(0, 16))}…</code>${txt('help.compare_bip_39_s_english_txt_before')}</div>`;
    tabCount('triage', 0);
    return;
  }

  const parts = [];

  if (phrases.length) {
    parts.push(`<div class="results-head">${txt('ui.phrases_seed_phrase_s_checksum_verified', { phrases: phrases.length })}</div>`);
    parts.push(phrases.map((h, i) => `
      <div class="result match-notable" data-w="p" data-i="${i}">
        <div class="top">
          <span class="kind">${txt('ui.words_words_checksum_holds', { words: h.words })}</span>
          <span class="off">0x${fmt.hex(h.offset)}</span>
        </div>
        <div class="name js-phrase">${esc(h.redacted || '')}</div>
        <div class="path">${esc(h.path || h.name || '')}</div>
        <div class="meta">${h.phrase
          ? '<button class="linkish js-reveal">Reveal phrase</button>'
          : 'phrase not stored in the case'}</div>
      </div>`).join(''));
  }

  if (near.length) {
    const nearTotal = r.near_miss_count || near.length;
    parts.push(`<div class="results-head">${txt('ui.wallets.near_miss', {
        count: nearTotal, n: nearTotal.toLocaleString() })}${
        nearTotal > near.length
          ? ` · first ${near.length} kept` : ''}</div>`);
    parts.push(near.map((h, i) => `
      <div class="result" data-w="n" data-i="${i}">
        <div class="top">
          <span class="kind">${txt('ui.words_words_checksum_failed', { words: h.words })}</span>
          <span class="off">0x${fmt.hex(h.offset)}</span>
        </div>
        <div class="name">${esc(h.redacted || '')}</div>
        <div class="path">${esc(h.path || h.name || '')}</div>
      </div>`).join(''));
  }

  if (files.length) {
    parts.push(`<div class="results-head">${txt('ui.files_wallet_file_s', { files: files.length })}</div>`);
    parts.push(files.map((f, i) => `
      <div class="result match-notable" data-w="f" data-i="${i}">
        <div class="top">
          <span class="kind">${esc(f.kind || '')}</span>
          <span class="off">${f.size != null ? fmt.bytes(f.size) : ''}</span>
        </div>
        <div class="name">${esc(f.name || '')}</div>
        <div class="path">${esc(f.path || '')}</div>
        <div class="meta">${esc(f.form || '')}</div>
      </div>`).join(''));
  }

  if (addrs.length) {
    const shown = addrs.slice(0, 500);
    parts.push(`<div class="results-head">${txt('ui.wallets.addresses', {
        count: r.address_count || addrs.length,
        n: (r.address_count || addrs.length).toLocaleString() })}${
        (r.address_count || 0) > shown.length
          ? ` · first ${shown.length} shown` : ''}</div>`);
    parts.push(shown.map((a, i) => `
      <div class="result ${a.secret ? 'match-notable' : ''}"
           data-w="a" data-i="${i}">
        <div class="top">
          <span class="kind">${esc(a.kind || '')}</span>
          <span class="off">0x${fmt.hex(a.offset)}</span>
        </div>
        <div class="name">${esc(a.value || '')}</div>
        <div class="path">${esc(a.path || '')}</div>
        <div class="meta">${esc(a.form || '')}${
          a.unverified ? ' · not verifiable here' : ''}</div>
      </div>`).join(''));
  }

  box.innerHTML = head + parts.join('');

  box.querySelectorAll('.js-reveal').forEach(btn => {
    btn.addEventListener('click', ev => {
      ev.stopPropagation();
      const row = btn.closest('.result');
      const h = phrases[+row.dataset.i];
      row.querySelector('.js-phrase').textContent = h.phrase;
      btn.remove();
    });
  });

  bindResults(box, el => {
    const i = +el.dataset.i;
    if (el.dataset.w === 'f') {
      const f = files[i];
      if (f && f.entry) openHit({ ...f.entry, entry: f.entry }, part);
    }
  });
  tabCount('triage', phrases.length + files.length + (r.address_count || 0));
}

function renderPrefetch(r, part) {
  const box = $('#art-results');
  const items = r.items || [];
  const notes = [];
  if (!r.decompressor) {
    notes.push(txt('help.lzxpress_decompressor_host_compressed_prefetch_files_read'));
  } else if (r.decompressor === 'os') {
    notes.push(txt('help.compressed_prefetch_decoded_using_operating_system_s'));
  }
  if (r.undecoded) notes.push(txt('messages.undecoded_file_s_could_decompressed', { undecoded: r.undecoded }));
  const head = notes.map(n => `<div class="notice">${esc(n)}</div>`).join('');

  if (!items.length) {
    box.innerHTML = head + `<p class="empty">${txt('ui.prefetch_volume')}</p>`;
    tabCount('triage', 0);
    return;
  }
  box.innerHTML = head + `<div class="results-head">${txt('ui.items_programs_sorted_most_recent_run', { items: items.length })}</div>` +
    items.map((p, i) => `
      <div class="result ${p.undecoded ? 'match-notable' : ''}" data-i="${i}">
        <div class="top">
          <span class="kind">${p.run_count != null ? p.run_count + ' run(s)'
            : 'prefetch'}</span>
          <span class="off">${p.file_count ? p.file_count + ' files' : ''}</span>
        </div>
        <div class="name">${esc(p.name || '(unnamed)')}</div>
        <div class="path">${esc(p.source || '')}</div>
        <div class="meta">${p.last_run ? 'last run ' + fmt.time(p.last_run)
          : (p.undecoded ? 'compressed — not decoded' : 'no run time')}${
          p.run_times?.length > 1 ? ` · ${p.run_times.length} recorded runs` : ''}</div>
      </div>`).join('');
  bindResults(box, el => {
    const p = items[+el.dataset.i];
    if (p.entry) openHit({ ...p.entry, entry: p.entry }, part);
  });
  tabCount('triage', items.length);
}

function renderShellbags(r, part) {
  const box = $('#art-results');
  const users = r.users || [];
  const notes = [...(r.findings || []),
                 ...users.flatMap(u => u.findings || [])]
    .map(f => `<div class="notice">${esc(f)}</div>`).join('');
  const all = users.flatMap(u => (u.entries || [])
    .map(e => ({ ...e, user: u.user, hive: u.source })));
  if (!all.length) {
    box.innerHTML = notes + `<p class="empty">${txt('ui.shellbags_found')}</p>`;
    tabCount('triage', 0);
    return;
  }
  all.sort((a, b) => (b.last_opened || '').localeCompare(a.last_opened || ''));
  const who = [...new Set(users.map(u => u.user).filter(Boolean))];
  box.innerHTML = notes + `<div class="results-head">${
    txt('ui.shellbags.summary', { count: all.length,
      n: all.length.toLocaleString(), hives: users.length.toLocaleString() })}${
      who.length ? ' · ' + who.join(', ') : ''}</div>` +
    all.map((e, i) => `
      <div class="result ${e.kind === 'unknown' ? 'match-notable' : ''}" data-i="${i}">
        <div class="top"><span class="kind">${esc(e.kind)}</span>
          <span class="off">depth ${e.depth}</span></div>
        <div class="name">${esc(e.name || '')}</div>
        <div class="path">${esc(e.path || '')}</div>
        <div class="meta">${e.last_opened ? 'last opened ' + fmt.time(e.last_opened)
          : 'no timestamp'}${e.user ? ' · ' + esc(e.user) : ''}</div>
      </div>`).join('');
  tabCount('triage', all.length);
}

function mailAddr(v) {
  // mbox gives a list of addresses; PST gives one already-formatted
  // display string (or nothing). Normalised to a single string either way.
  if (!v) return '';
  return Array.isArray(v) ? v.join(', ') : String(v);
}

function mailBody(m) {
  // What to show for a message's content, in the order this codebase's own
  // rule prefers: decoded plain text, then visible text lifted out of an
  // HTML-only part (never the markup itself, never rendered as HTML), then
  // an honest note that there is nothing readable to show.
  const LIMIT = 20000;
  const cut = s => s.length > LIMIT
    ? s.slice(0, LIMIT) + '\n\n[truncated]' : s;
  if (m.text) return { kind: 'text', text: cut(m.text) };
  if (m.body) return { kind: 'text', text: cut(m.body) };       // PST
  if (m.html_text) return { kind: 'html_text', text: cut(m.html_text) };
  if (m.html_bytes) return { kind: 'html_only', text: null };
  if (m.unparsed) return { kind: 'unparsed', text: null };
  return { kind: 'none', text: null };
}

function mailDetailHtml(m) {
  const rows = [
    ['From', mailAddr(m.from)], ['To', mailAddr(m.to)],
    ['Cc', mailAddr(m.cc)], ['Date', m.date_raw || m.date],
  ].filter(([, v]) => v);
  const body = mailBody(m);
  const bodyHtml = {
    text: `<pre class="mail-body">${escText(body.text)}</pre>`,
    html_text: `<div class="notice">This message has no plain-text part; ` +
      `tags have been stripped from its HTML part to show the text ` +
      `below, which is not rendered as HTML.</div>` +
      `<pre class="mail-body">${escText(body.text)}</pre>`,
    html_only: `<p class="empty">HTML-only message; no readable text ` +
      `could be lifted out of it.</p>`,
    unparsed: `<p class="empty">This message could not be parsed.</p>`,
    none: `<p class="empty">No body text recorded for this message.</p>`,
  }[body.kind];
  const atts = (m.attachments || []).map((a, i) => {
    const label = `${esc(a.filename || a.name || '(unnamed)')}${
      a.content_type ? ' · ' + esc(a.content_type) : ''}${
      (a.bytes ?? a.size) ? ' · ' + fmt.bytes(a.bytes ?? a.size) : ''}`;
    if (a.nid == null) return `<div class="mail-att">${label}</div>`;
    return `<div class="mail-att">
      <button class="linkish mail-load-att" data-i="${i}">${label} — view</button>
    </div>`;
  }).join('');
  return `<div class="mail-detail">
    <div class="mail-headers">${rows.map(([k, v]) =>
      `<div><strong>${k}:</strong> ${esc(v)}</div>`).join('')}</div>
    ${bodyHtml}
    ${atts ? `<div class="mail-attachments">${atts}</div>` : ''}
  </div>`;
}

async function loadMailAttachment(btn, m, part) {
  const a = (m.attachments || [])[+btn.dataset.i];
  const holder = btn.closest('.mail-att');
  btn.disabled = true;
  btn.textContent = txt('ui.render_registry.loading_value');
  const r = await api.get('mail/attachment', {
    part, entry: JSON.stringify(m.store_entry), msg: m.nid, att: a.nid,
  });
  btn.remove();
  if (r.error) {
    holder.insertAdjacentHTML('beforeend',
      `<p class="hint warn">${esc(r.error)}</p>`);
    return;
  }
  const bytes = Uint8Array.from(atob(r.preview || ''), c => c.charCodeAt(0));
  if (!bytes.length) {
    holder.insertAdjacentHTML('beforeend',
      `<p class="empty">${txt('ui.content_show')}</p>`);
    return;
  }
  const kind = sniff(bytes);
  let body;
  if (kind?.raster || (kind?.kind === 'image' && kind.mime)) {
    body = `<div class="pv-image"><img alt="" src="data:${
      kind.mime};base64,${r.preview}"></div>`;
  } else if (looksTextual(bytes)) {
    body = `<pre class="pv-text">${escText(decodeText(bytes).slice(0, 20000))}</pre>`;
  } else {
    body = `<p class="pv-note">${txt('help.mail_attachment_no_inline_viewer', {
      content_type: esc(r.content_type || 'application/octet-stream'),
      size: fmt.bytes(r.bytes) })}${
      r.truncated ? ' (preview truncated)' : ''}</p>`;
  }
  holder.insertAdjacentHTML('beforeend',
    `<div class="mail-att-preview">${body}</div>`);
}

function renderMail(r, part) {
  const box = $('#art-results');
  const msgs = r.messages || [];
  const stores = r.stores || [];
  if (!msgs.length) {
    box.innerHTML = `<p class="empty">${stores.length
      ? txt('help.mail.stores_found_no_messages', {
          count: stores.length,
          kinds: esc([...new Set(stores.map(x => x.kind).filter(Boolean))]
                     .join(', ') || txt('ui.unrecognised_format')) })
      : 'No mail stores on this volume. Stores are identified by content '
        + 'rather than by name, and mbox and PST are both read.'}</p>`;
    tabCount('triage', 0);
    return;
  }
  const deleted = msgs.filter(m => m.deleted_flag).length;
  const head = [`${msgs.length} messages`, `${stores.length} store(s)`,
                deleted ? txt('ui.deleted_flagged_deleted', { deleted: deleted }) : null]
    .filter(Boolean).join(' · ');
  box.innerHTML = `<div class="results-head">${esc(head)}</div>` +
    msgs.map((m, i) => `
      <div class="result ${m.deleted_flag ? 'match-notable' : ''}" data-i="${i}">
        <div class="top">
          <span class="kind">${m.deleted_flag ? 'deleted' : 'message'}${
            m.attachment_count ? ` · ${m.attachment_count} attachment(s)` : ''}</span>
          <span class="off">${fmt.bytes(m.bytes)}</span>
        </div>
        <div class="name">${esc(m.subject || '(no subject)')}</div>
        <div class="path">${esc(mailAddr(m.from))} →
          ${esc(mailAddr(m.to).slice(0, 80))}</div>
        <div class="meta">${esc(m.date || m.date_raw || 'no date')}${
          m.store ? ' · ' + esc(m.store.split('/').pop()) : ''}</div>
      </div>`).join('');
  bindResults(box, (el, ev) => {
    if (ev.target.closest('.mail-detail')) return;
    const open = el.querySelector('.mail-detail');
    if (open) { open.remove(); return; }
    $$('.mail-detail', box).forEach(n => n.remove());
    const m = msgs[+el.dataset.i];
    el.insertAdjacentHTML('beforeend', mailDetailHtml(m));
    $$('.mail-load-att', el).forEach(btn => btn.addEventListener('click', ev2 => {
      ev2.stopPropagation();
      loadMailAttachment(btn, m, part);
    }));
  });
  tabCount('triage', msgs.length);
}

function renderLevelDbSweep(r, part) {
  const box = $('#art-results');
  const rows = r.local_storage || [];
  if (!rows.length) {
    box.innerHTML = `<p class="empty">${txt('ui.leveldb_content_found')}</p>`;
    tabCount('triage', 0);
    return;
  }
  const stores = Object.entries(r.stores || {})
    .map(([k, n]) => `${k} ${n}`).join(' · ');
  const del = rows.filter(x => x.deleted).length;
  box.innerHTML = `<div class="results-head">${r.total.toLocaleString()} keys ·
      ${esc(stores)}${del ? ' · ' + del + ' deleted' : ''}${
      r.unreadable ? ' · ' + r.unreadable + ' unreadable' : ''}</div>` +
    rows.slice(0, 3000).map((x, i) => `
      <div class="result ${x.deleted ? 'match-notable' : ''}" data-i="${i}">
        <div class="top">
          <span class="kind">${esc(x.store || '')}${x.deleted ? ' · deleted' : ''}</span>
        </div>
        <div class="name">${esc(x.origin || '')}</div>
        <div class="path">${esc(x.key || '')}</div>
        <div class="sub">${x.deleted ? '<em>value removed</em>'
          : esc(String(x.value ?? '').slice(0, 160))}</div>
      </div>`).join('');
  tabCount('triage', r.total);
}

const jr_seq = st => st.journal_recovery.sequence;

const esc = s => (s === null || s === undefined ? '' : String(s))
                  .replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;',
                                               '&': '&amp;', '"': '&quot;',
                                               "'": '&#39;' }[c]))
                  .replace(/[\x00-\x1f\x7f]/g, '·');

const escText = s => (s === null || s === undefined ? '' : String(s))
                  .replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;',
                                               '&': '&amp;', '"': '&quot;',
                                               "'": '&#39;' }[c]))
                  .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '·');

function bindResults(box, fn, menuFor = null) {
  $$('.result', box).forEach(el => {
    el.addEventListener('click', ev => {
      $$('.result.is-on', box).forEach(n => n.classList.remove('is-on'));
      el.classList.add('is-on');
      fn(el, ev);
    });
    if (!menuFor) return;
    el.addEventListener('contextmenu', ev => {
      const items = menuFor(el);
      if (!items) return;
      ev.preventDefault();
      openMenu(ev.clientX, ev.clientY, items, el);
    });
  });
}

function tabCount(view, n) {
  const tab = $(`.tab[data-view="${view}"]`);
  const base = { carve: 'Carved', find: 'Search', marks: 'Marks',
                 time: 'Timeline', tags: 'Tagged', hash: 'Hashes',
                 triage: 'Triage', attack: 'ATT&CK' }[view];
  if (!base) return;
  tab.innerHTML = n == null ? base : `${base} <span class="count">${n}</span>`;
}

async function jumpTo(part, offset, length, evId) {
  const p = partIn(evId, part);
  if (p && !await useOwner(p)) return;
  if (part !== S.scope.part || S.scope.ev !== S.activeId) {
    setScope(part, p ? p.size : S.image.size,
             p ? partLabel(p, S.volumes?.partitions) : txt('ui.whole_image'), null);
  }
  revealViewer();
  S.cursor = offset;
  S.selection = { start: offset, length: Math.max(1, length || 1) };
  hex.reveal(offset);
  updateStatus();
}

const TL_PAD = { l: 46, r: 10, t: 8, b: 18 };
const TL_BAR_PX = 3;

function tlStamp(t, span) {
  if (!Number.isFinite(t)) return '—';
  const iso = new Date(t * 1000).toISOString();
  if (span > 2 * 365 * 86400) return iso.slice(0, 7);
  if (span > 3 * 86400) return iso.slice(0, 10);
  if (span > 600) return iso.slice(0, 16).replace('T', ' ');
  return iso.slice(0, 19).replace('T', ' ');
}

function tlTicks(lo, hi, most) {
  const span = hi - lo;
  const DAY = 86400, MONTH = 30.44 * DAY, YEAR = 365.25 * DAY;
  const steps = [
    [1, 's', 1], [5, 's', 5], [15, 's', 15], [30, 's', 30],
    [1, 'm', 60], [5, 'm', 300], [15, 'm', 900], [30, 'm', 1800],
    [1, 'h', 3600], [3, 'h', 10800], [6, 'h', 21600], [12, 'h', 43200],
    [1, 'd', DAY], [2, 'd', 2 * DAY], [7, 'd', 7 * DAY], [14, 'd', 14 * DAY],
    [1, 'M', MONTH], [3, 'M', 3 * MONTH], [6, 'M', 6 * MONTH],
    [1, 'Y', YEAR], [2, 'Y', 2 * YEAR], [5, 'Y', 5 * YEAR],
    [10, 'Y', 10 * YEAR], [25, 'Y', 25 * YEAR], [50, 'Y', 50 * YEAR],
    [100, 'Y', 100 * YEAR],
  ];
  const pick = steps.find(s => span / s[2] <= most) || steps[steps.length - 1];
  const [n, unit, secs] = pick;
  const out = [];
  if (unit === 'M' || unit === 'Y') {
    const d = new Date(lo * 1000);
    let y = d.getUTCFullYear();
    let m = unit === 'Y' ? 0 : Math.floor(d.getUTCMonth() / n) * n;
    if (unit === 'Y') y = Math.floor(y / n) * n;
    for (let g = 0; g < 600; g++) {
      const t = Date.UTC(y, m, 1) / 1000;
      if (t > hi) break;
      if (t >= lo) out.push([t, unit]);
      if (unit === 'Y') y += n;
      else { m += n; y += Math.floor(m / 12); m %= 12; }
    }
  } else {
    for (let t = Math.ceil(lo / secs) * secs, g = 0; t <= hi && g < 600;
         t += secs, g++) {
      out.push([t, unit]);
    }
  }
  return out;
}

function tlTickLabel(t, unit) {
  const iso = new Date(t * 1000).toISOString();
  if ((unit === 'h' || unit === 'm') && iso.slice(11, 16) === '00:00') {
    return iso.slice(5, 10);
  }
  return { Y: iso.slice(0, 4), M: iso.slice(0, 7), d: iso.slice(5, 10),
           h: iso.slice(11, 16), m: iso.slice(11, 16),
           s: iso.slice(11, 19) }[unit];
}

class TimelineGraph {
  constructor(canvas) {
    this.c = canvas;
    this.ctx = canvas.getContext('2d');
    this.hist = null;
    this.view = null;
    this.sel = null;
    this.drag = null;
    this.dragNow = null;
    this.hover = null;
    this.mark = null;
    this.seq = 0;
    this.failed = null;
    this.timer = null;
    this.pan = null;
    this.panTimer = null;
    this.scroll = $('#time-scroll');
    this.thumb = this.scroll ? this.scroll.querySelector('.tl-thumb') : null;

    canvas.addEventListener('mousedown', e => this.down(e));
    window.addEventListener('mousemove', e => this.move(e));
    window.addEventListener('mouseup', () => this.up());
    canvas.addEventListener('mouseleave', () => {
      if (this.hover == null) return;
      this.hover = null;
      this.draw();
    });
    canvas.addEventListener('dblclick', e => {
      e.preventDefault();
      if (this.sel) this.zoomToSelection();
      else this.resetView();
    });
    canvas.addEventListener('wheel', e => {
      const dx = e.deltaX || (e.shiftKey ? e.deltaY : 0);
      if (!dx || !this.pannable()) return;
      e.preventDefault();
      const h = this.hist;
      const lo = this.view ? this.view[0] : h.lo;
      const width = this.view ? this.view[1] - this.view[0] : h.hi - h.lo;
      this.panTo(lo + (dx / this.plot().w) * width, 'soon');
    }, { passive: false });
    if (this.scroll) {
      this.scroll.addEventListener('pointerdown', e => this.scrollDown(e));
      this.scroll.addEventListener('keydown', e => this.scrollKey(e));
      window.addEventListener('pointermove', e => this.scrollMove(e));
      window.addEventListener('pointerup', () => this.scrollUp());
    }
    new ResizeObserver(() => this.resized()).observe(canvas);
  }

  plot() {
    const b = this.c.getBoundingClientRect();
    return { x: TL_PAD.l, y: TL_PAD.t,
             w: Math.max(10, b.width - TL_PAD.l - TL_PAD.r),
             h: Math.max(10, b.height - TL_PAD.t - TL_PAD.b),
             W: b.width, H: b.height, left: b.left, top: b.top };
  }

  bins() {
    return Math.max(20, Math.min(600, Math.floor(this.plot().w / TL_BAR_PX)));
  }

  range() { return this.sel || this.view || null; }

  timeAt(clientX) {
    const p = this.plot(), h = this.hist;
    const f = Math.max(0, Math.min(1, (clientX - p.left - p.x) / p.w));
    return h.lo + f * (h.hi - h.lo);
  }

  xOf(t) {
    const p = this.plot(), h = this.hist;
    return p.x + ((t - h.lo) / (h.hi - h.lo)) * p.w;
  }

  reset() {
    this.hist = null;
    this.failed = null;
    this.view = null;
    this.sel = null;
    this.mark = null;
    this.drag = null;
    this.pan = null;
    this.buttons();
    this.draw();
    this.describe();
    this.syncScroll();
  }

  async load() {
    const tl = S.timeline;
    if (!tl || !this.c.getBoundingClientRect().width) return;
    const seq = ++this.seq;
    const r = await api.get('timeline/histogram', {
      key: tl.key, bins: this.bins(),
      start: this.view ? this.view[0] : undefined,
      end: this.view ? this.view[1] : undefined,
      q: tl.q || undefined, flagged: tl.flagged ? 1 : undefined,
    }).catch(() => null);
    if (seq !== this.seq || S.timeline?.key !== tl.key) return;
    if (!r || r.error || !Array.isArray(r.bins)) {
      this.hist = null;
      this.failed = (r && r.error) || txt('ui.timeline.graph_no_answer');
    } else {
      this.failed = null;
      this.hist = r;
      if (this.view && (this.view[0] !== r.lo || this.view[1] !== r.hi)) {
        this.view = [r.lo, r.hi];
        if (!this.sel && !this.pan) refilterTimeline();
      }
    }
    this.draw();
    this.describe();
    this.syncScroll();
  }

  resized() {
    this.draw();
    this.syncScroll();
    clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      if (!S.timeline || !this.c.getBoundingClientRect().width) return;
      if (!this.hist || this.hist.bins.length !== this.bins()) this.load();
    }, 200);
  }

  inPlot(e) {
    const p = this.plot();
    const x = e.clientX - p.left, y = e.clientY - p.top;
    return x >= p.x && x <= p.x + p.w && y >= 0 && y <= p.H;
  }

  pannable() {
    const h = this.hist;
    return !!(h && h.full && (h.lo > h.full.lo || h.hi < h.full.hi));
  }

  scrollGeom() {
    const h = this.hist;
    const trackW = this.scroll.clientWidth;
    const span = h.full.hi - h.full.lo;
    const width = this.view ? this.view[1] - this.view[0] : h.hi - h.lo;
    const thumbW = Math.min(trackW, Math.max(16, trackW * width / span));
    return { trackW, thumbW, width, room: Math.max(1, trackW - thumbW),
             slack: Math.max(0, span - width) };
  }

  syncScroll() {
    const s = this.scroll, t = this.thumb, h = this.hist;
    if (!s || !t) return;
    const show = this.pannable();
    s.hidden = !show;
    if (!show) return;
    s.style.marginLeft = `${TL_PAD.l}px`;
    s.style.marginRight = `${TL_PAD.r}px`;
    const g = this.pan ? this.pan.g : this.scrollGeom();
    const lo = this.view ? this.view[0] : h.lo;
    const frac = g.slack ? Math.max(0, Math.min(1, (lo - h.full.lo) / g.slack)) : 0;
    t.style.width = `${g.thumbW}px`;
    t.style.left = `${frac * g.room}px`;
    s.setAttribute('aria-valuenow', String(Math.round(frac * 100)));
    s.setAttribute('aria-valuetext',
                   `${tlStamp(lo, g.width)} – ${tlStamp(lo + g.width, g.width)}`);
  }

  panTo(lo, settle) {
    const h = this.hist;
    if (!h || !h.full) return;
    const width = this.view ? this.view[1] - this.view[0] : h.hi - h.lo;
    lo = Math.max(h.full.lo, Math.min(h.full.hi - width, lo));
    this.view = [lo, lo + width];
    if (this.sel) {
      this.sel = null;
      this.describe();
    }
    this.buttons();
    this.syncScroll();
    clearTimeout(this.panTimer);
    if (settle === true) {
      this.settlePan();
      return;
    }
    this.panTimer = setTimeout(() => (settle === 'soon' ? this.settlePan() : this.load()),
                               settle === 'soon' ? 250 : 120);
  }

  settlePan() {
    clearTimeout(this.panTimer);
    refilterTimeline();
    this.load();
  }

  scrollDown(e) {
    if (e.button !== 0 || !this.pannable()) return;
    e.preventDefault();
    this.scroll.focus();
    const h = this.hist;
    const g = this.scrollGeom();
    const lo = this.view ? this.view[0] : h.lo;
    if (e.target === this.thumb) {
      this.pan = { x: e.clientX, lo, g };
      this.thumb.classList.add('is-dragging');
      return;
    }
    const at = this.thumb.getBoundingClientRect();
    this.panTo(lo + (e.clientX < at.left ? -g.width : g.width), true);
  }

  scrollMove(e) {
    if (!this.pan) return;
    const { x, lo, g } = this.pan;
    this.panTo(lo + g.slack * (e.clientX - x) / g.room, false);
  }

  scrollUp() {
    if (!this.pan) return;
    this.pan = null;
    this.thumb.classList.remove('is-dragging');
    this.settlePan();
  }

  scrollKey(e) {
    if (!this.pannable()) return;
    const h = this.hist;
    const width = this.view ? this.view[1] - this.view[0] : h.hi - h.lo;
    const lo = this.view ? this.view[0] : h.lo;
    const step = { ArrowLeft: -width / 10, ArrowRight: width / 10,
                   PageUp: -width, PageDown: width }[e.key];
    const to = step != null ? lo + step
      : e.key === 'Home' ? h.full.lo
      : e.key === 'End' ? h.full.hi - width : null;
    if (to == null) return;
    e.preventDefault();
    this.panTo(to, 'soon');
  }

  down(e) {
    if (e.button !== 0 || !this.hist || !this.inPlot(e)) return;
    e.preventDefault();
    this.drag = e.clientX;
    this.dragNow = e.clientX;
  }

  move(e) {
    if (this.drag != null) {
      this.dragNow = e.clientX;
      this.draw();
      return;
    }
    if (e.target !== this.c || !this.hist) return;
    const x = this.inPlot(e) ? e.clientX - this.plot().left : null;
    if (x === this.hover) return;
    this.hover = x;
    this.draw();
  }

  up() {
    if (this.drag == null) return;
    const a = this.drag, b = this.dragNow ?? a;
    this.drag = null;
    const h = this.hist;
    if (!h) return;
    if (Math.abs(b - a) < 3) {
      const i = Math.floor((this.timeAt(a) - h.lo) / h.width);
      if (i >= 0 && i < h.bins.length && h.bins[i] > 0) {
        this.select(h.lo + i * h.width, h.lo + (i + 1) * h.width);
      } else {
        this.select(null);
      }
      return;
    }
    const t0 = this.timeAt(Math.min(a, b)), t1 = this.timeAt(Math.max(a, b));
    const i0 = Math.max(0, Math.floor((t0 - h.lo) / h.width));
    const i1 = Math.min(h.bins.length, Math.ceil((t1 - h.lo) / h.width));
    this.select(h.lo + i0 * h.width, h.lo + Math.max(i0 + 1, i1) * h.width);
  }

  select(lo, hi) {
    this.sel = lo == null ? null : [lo, hi];
    this.buttons();
    this.draw();
    this.describe();
    refilterTimeline();
  }

  zoomToSelection() {
    if (!this.sel) return;
    this.view = this.sel;
    this.sel = null;
    this.buttons();
    refilterTimeline();
    this.load();
  }

  resetView() {
    if (!this.view && !this.sel) return;
    this.view = null;
    this.sel = null;
    this.buttons();
    refilterTimeline();
    this.load();
  }

  showAll() {
    const h = this.hist;
    if (!h || !h.full) return;
    this.view = [h.full.lo, h.full.hi];
    this.sel = null;
    this.buttons();
    refilterTimeline();
    this.load();
  }

  setMark(t) {
    this.mark = Number.isFinite(t) ? t : null;
    this.draw();
  }

  buttons() {
    const z = $('#time-zoom'), c = $('#time-clear'), o = $('#time-out');
    if (z) z.disabled = !this.sel;
    if (c) c.disabled = !this.sel;
    if (o) o.disabled = !this.view && !this.sel;
  }

  countIn(lo, hi) {
    const h = this.hist;
    let n = 0;
    for (let i = 0; i < h.bins.length; i++) {
      const a = h.lo + i * h.width;
      if (a >= lo - h.width * 1e-6 && a + h.width <= hi + h.width * 1e-6) {
        n += h.bins[i];
      }
    }
    return n;
  }

  describe() {
    const el = $('#time-window');
    if (!el) return;
    const h = this.hist;
    if (!h) { el.textContent = ''; return; }
    const span = h.hi - h.lo;
    const parts = [];
    if (this.sel) {
      parts.push(esc(txt('ui.timeline.selected', {
        from: tlStamp(this.sel[0], span), to: tlStamp(this.sel[1], span),
        n: fmt.count(S.timeline?.matched
                     ?? this.countIn(this.sel[0], this.sel[1])) })));
    } else {
      parts.push(esc(txt('ui.timeline.viewing', {
        from: tlStamp(h.lo, span), to: tlStamp(h.hi, span),
        n: fmt.count(h.bins.reduce((a, b) => a + b, 0)) })));
    }
    if (h.before || h.after) {
      const key = !h.after ? 'ui.timeline.outside_before'
        : !h.before ? 'ui.timeline.outside_after' : 'ui.timeline.outside';
      parts.push(esc(txt(key, {
        before: fmt.count(h.before), after: fmt.count(h.after) }))
        + ` <a href="#" data-act="all">${esc(txt('ui.timeline.show_all'))}</a>`);
    }
    el.innerHTML = parts.join(' · ');
  }

  draw() {
    const box = this.c.getBoundingClientRect();
    if (!box.width || !box.height) return;
    const dpr = window.devicePixelRatio || 1;
    const cw = Math.floor(box.width * dpr), ch = Math.floor(box.height * dpr);
    if (this.c.width !== cw) this.c.width = cw;
    if (this.c.height !== ch) this.c.height = ch;
    const ctx = this.ctx;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const css = getComputedStyle(document.documentElement);
    const col = n => css.getPropertyValue(n).trim();
    const p = this.plot();
    const font = getComputedStyle(document.body).fontFamily;

    ctx.fillStyle = col('--panel');
    ctx.fillRect(0, 0, p.W, p.H);
    ctx.font = `9px ${font}`;

    const say = msg => {
      ctx.fillStyle = col('--dimmer');
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(msg, p.W / 2, p.H / 2);
      ctx.textAlign = 'left';
    };
    const h = this.hist;
    if (!h) {
      return say(this.failed
        ? txt('ui.timeline.graph_failed', { why: this.failed })
        : txt('ui.timeline.graph_pending'));
    }
    const counts = h.bins;
    let peak = 0;
    for (const v of counts) if (v > peak) peak = v;
    if (!peak) return say(txt('ui.timeline.no_activity'));

    const log = !!$('#time-log')?.checked;
    const scale = v => (v <= 0 ? 0
      : log ? Math.log10(v + 1) / Math.log10(peak + 1) : v / peak);

    ctx.fillStyle = col('--well') || col('--ink');
    ctx.fillRect(p.x, p.y, p.w, p.h);

    const bw = p.w / counts.length;
    const sel = this.sel;
    const amber = col('--amber');
    for (let i = 0; i < counts.length; i++) {
      const v = counts[i];
      if (!v) continue;
      const bh = Math.max(1, scale(v) * p.h);
      const a = h.lo + i * h.width;
      const inside = !sel || (a >= sel[0] - h.width * 1e-6
                              && a + h.width <= sel[1] + h.width * 1e-6);
      ctx.globalAlpha = inside ? 1 : 0.3;
      ctx.fillStyle = amber;
      ctx.fillRect(p.x + i * bw, p.y + p.h - bh,
                   Math.max(1, bw > 2 ? bw - 1 : bw), bh);
    }
    ctx.globalAlpha = 1;

    let band = null;
    if (this.drag != null && this.dragNow != null) {
      const x0 = Math.min(this.drag, this.dragNow) - p.left;
      const x1 = Math.max(this.drag, this.dragNow) - p.left;
      band = [Math.max(p.x, x0), Math.min(p.x + p.w, x1)];
    } else if (sel) {
      band = [Math.max(p.x, this.xOf(sel[0])), Math.min(p.x + p.w, this.xOf(sel[1]))];
    }
    if (band && band[1] > band[0]) {
      ctx.fillStyle = 'rgba(224,161,74,.18)';
      ctx.fillRect(band[0], p.y, band[1] - band[0], p.h);
      ctx.strokeStyle = amber;
      ctx.lineWidth = 1;
      ctx.strokeRect(band[0] + 0.5, p.y + 0.5,
                     Math.max(1, band[1] - band[0] - 1), p.h - 1);
    }

    if (this.mark != null && this.mark >= h.lo && this.mark < h.hi) {
      const x = Math.round(this.xOf(this.mark)) + 0.5;
      ctx.strokeStyle = col('--text');
      ctx.beginPath();
      ctx.moveTo(x, p.y);
      ctx.lineTo(x, p.y + p.h);
      ctx.stroke();
    }

    ctx.fillStyle = col('--dimmer');
    ctx.textAlign = 'right';
    ctx.textBaseline = 'top';
    ctx.fillText(fmt.count(peak), p.x - 5, p.y);
    ctx.textBaseline = 'bottom';
    ctx.fillText(log ? 'log' : '0', p.x - 5, p.y + p.h);
    ctx.textAlign = 'left';

    const ticks = tlTicks(h.lo, h.hi, Math.max(2, Math.floor(p.w / 80)));
    ctx.strokeStyle = col('--line');
    ctx.textBaseline = 'top';
    let clear = -Infinity;
    for (const [t, unit] of ticks) {
      const x = Math.round(this.xOf(t)) + 0.5;
      ctx.beginPath();
      ctx.moveTo(x, p.y + p.h);
      ctx.lineTo(x, p.y + p.h + 4);
      ctx.stroke();
      const label = tlTickLabel(t, unit);
      const w = ctx.measureText(label).width;
      const lx = Math.min(p.W - w - 2, Math.max(0, x - w / 2));
      if (lx < clear) continue;
      ctx.fillStyle = col('--dimmer');
      ctx.fillText(label, lx, p.y + p.h + 5);
      clear = lx + w + 8;
    }

    if (this.hover != null && this.drag == null) {
      const i = Math.max(0, Math.min(counts.length - 1,
                                     Math.floor((this.hover - p.x) / bw)));
      const a = h.lo + i * h.width;
      ctx.fillStyle = col('--text');
      ctx.globalAlpha = 0.12;
      ctx.fillRect(p.x + i * bw, p.y, Math.max(1, bw), p.h);
      ctx.globalAlpha = 1;
      const tip = txt('ui.timeline.bar_tip', {
        from: tlStamp(a, h.width), to: tlStamp(a + h.width, h.width),
        n: fmt.count(counts[i]) });
      ctx.font = `10px ${font}`;
      const tw = ctx.measureText(tip).width;
      const tx = this.hover > p.x + p.w / 2
        ? Math.max(p.x + 2, this.hover - tw - 8) : Math.min(p.x + p.w - tw - 2, this.hover + 8);
      ctx.fillStyle = col('--raise');
      ctx.fillRect(tx - 4, p.y + 2, tw + 8, 15);
      ctx.fillStyle = col('--text');
      ctx.textBaseline = 'top';
      ctx.fillText(tip, tx, p.y + 4);
    }
  }
}

function timelineChoice() {
  const v = $('#time-scope').value;
  if (v === 'tagged') return { scope: 'tagged', key: 'tagged' };
  if (v === '' || S.activeId == null) return null;
  return { scope: 'volume', part: +v, ev: S.activeId,
           key: `ev${S.activeId}-p${+v}` };
}

function clearTimelinePanel() {
  S.timeline = null;
  const box = $('#time-results');
  if (box) box.innerHTML = '';
  const sum = $('#time-summary');
  if (sum) sum.hidden = true;
  const bar = $('#time-bar');
  if (bar) bar.hidden = true;
  const graph = $('#time-graph');
  if (graph) graph.hidden = true;
  timelineGraph?.reset();
  tabCount('time', null);
}

async function doTimeline() {
  const k = timelineChoice();
  if (!k) return toast(txt('messages.toast.filesystem_here_build_timeline'));
  $('#btn-timeline').disabled = true;
  try {
    const t = await api.post('timeline', {
      scope: k.scope, part: k.part, ev: k.ev,
      include_accessed: $('#time-accessed').checked });
    const r = await awaitTask(t, x => x.found
      ? txt('ui.timeline.building_n', { n: fmt.count(x.found) })
      : txt('ui.building_timeline'));
    if (!r) return;
    if (r.error) return toast(r.error);
    if (timelineChoice()?.key !== k.key) return;
    await showTimeline(k, r);
  } finally {
    $('#btn-timeline').disabled = false;
  }
}

async function loadStoredTimeline() {
  const k = timelineChoice();
  if (!k) return clearTimelinePanel();
  if (S.timeline?.key === k.key) return;
  const r = await api.get('timeline/summary', { key: k.key }).catch(() => null);
  if (timelineChoice()?.key !== k.key) return;
  if (!r || r.error || !r.exists) {
    clearTimelinePanel();
    $('#time-results').innerHTML =
      `<p class="empty">${txt('ui.timeline.none')}</p>`;
    return;
  }
  await showTimeline(k, r.summary);
}

async function showTimeline(k, summary) {
  timelineGraph.reset();
  S.timeline = { ...k, summary, rows: [], cursor: null, done: false,
                 matched: null, loading: false, range: null,
                 q: $('#time-filter').value.trim(),
                 flagged: $('#time-flagged').checked };
  renderTimelineSummary();
  $('#time-graph').hidden = false;
  const box = $('#time-results');
  box.innerHTML = '';
  box.scrollTop = 0;
  tabCount('time', summary.count);
  timelineGraph.load();
  await loadTimelinePage();
}

function renderTimelineSummary() {
  const r = S.timeline.summary;
  const reason = code => ({
    not_found: txt('ui.timeline.reason.not_found'),
    ambiguous: txt('ui.timeline.reason.ambiguous'),
    exhibit_not_open: txt('ui.timeline.reason.exhibit_not_open'),
    volume_locked: txt('ui.timeline.reason.volume_locked'),
    volume_unreadable: txt('ui.timeline.reason.volume_unreadable'),
  })[code] || code;
  const lines = [
    txt('ui.timeline.summary', { events: fmt.count(r.count),
                                 files: fmt.count(r.files) })
      + (r.deleted_files
         ? ` · ${txt('ui.timeline.deleted', { n: fmt.count(r.deleted_files) })}`
         : ''),
    r.span ? `${esc(r.span.first)} → ${esc(r.span.last)}` : '',
    r.flagged
      ? `<span class="warn">${txt('ui.count.timeline_flagged',
                                  { count: r.flagged })}</span>` : '',
    r.truncated
      ? `<span class="warn">${txt('ui.timeline.truncated',
                                  { n: fmt.count(r.files) })}</span>` : '',
    r.too_deep
      ? `<span class="warn">${txt('ui.timeline.too_deep',
                                  { n: fmt.count(r.too_deep) })}</span>` : '',
    r.resolved_by_name
      ? txt('ui.timeline.by_name', { n: fmt.count(r.resolved_by_name) }) : '',
    txt('ui.timeline.built', { when: fmt.time(r.built_at),
                               who: esc(r.examiner || '—') }),
    esc(r.note || ''),
  ].filter(Boolean);
  const miss = r.unresolved || [];
  const missed = miss.length ? `
    <details class="tl-miss">
      <summary class="warn">${txt('ui.count.timeline_unresolved',
                                  { count: r.unresolved_count || miss.length })}</summary>
      ${miss.map(m => `<div>${esc(m.path || m.name || '')} — ${esc(reason(m.reason))}${
        m.exhibit ? ` · ${esc(m.exhibit)}` : ''}</div>`).join('')}
    </details>` : '';
  const sum = $('#time-summary');
  sum.hidden = false;
  sum.innerHTML = lines.join('<br>') + missed;
  $('#time-bar').hidden = false;
}

async function loadTimelinePage() {
  const tl = S.timeline;
  if (!tl || tl.loading || tl.done) return;
  tl.loading = true;
  try {
    const r = await api.get('timeline/page', {
      key: tl.key, limit: PAGE_ROWS,
      cursor: tl.cursor ? JSON.stringify(tl.cursor) : undefined,
      q: tl.q || undefined, flagged: tl.flagged ? 1 : undefined,
      start: tl.range ? tl.range[0] : undefined,
      end: tl.range ? tl.range[1] : undefined });
    if (S.timeline !== tl) return;
    if (r.error) return toast(r.error);
    if (r.matched != null) tl.matched = r.matched;
    const from = tl.rows.length;
    tl.rows.push(...r.rows);
    tl.cursor = r.cursor;
    tl.done = r.done;
    appendTimelineRows(from);
  } finally {
    tl.loading = false;
  }
  const box = $('#time-results');
  if (S.timeline === tl && !tl.done
      && box.scrollHeight <= box.clientHeight + PAGE_AHEAD) {
    loadTimelinePage();
  }
}

function timelineRowHTML(e, i) {
  const acrossExhibits = S.timeline?.scope === 'tagged';
  return `
    <div class="result ${e.flagged ? 'flagged' : ''}" data-i="${i}">
      <div class="top">
        <span class="when">${esc(e.time.replace('T', ' ').replace('Z', ''))}</span>
        <span class="act ${e.source === '$FILE_NAME' ? 'fn' : ''}">${esc(e.action)}</span>
        ${e.deleted ? `<span class="flag warn">${txt('ui.timeline.deleted_flag')}</span>` : ''}
        ${e.partial ? `<span class="flag">${txt('ui.timeline.from_tag')}</span>` : ''}
        ${acrossExhibits && e.exhibit ? `<span class="flag">${esc(e.exhibit)}</span>` : ''}
      </div>
      <div class="sub">${esc(e.path || e.name || '')}</div>
    </div>`;
}

function appendTimelineRows(from) {
  const tl = S.timeline;
  const box = $('#time-results');
  if (!tl.rows.length) {
    box.innerHTML = `<p class="empty">${txt('ui.timeline.none_match')}</p>`;
  } else {
    box.insertAdjacentHTML('beforeend', tl.rows.slice(from)
      .map((e, j) => timelineRowHTML(e, from + j)).join(''));
  }
  $('#time-count').textContent = txt('ui.timeline.shown', {
    shown: fmt.count(tl.rows.length),
    total: fmt.count(tl.matched ?? tl.summary.count) });
  timelineGraph.describe();
}

function redrawTimelineRows() {
  const tl = S.timeline;
  if (!tl) return;
  const box = $('#time-results');
  const top = box.scrollTop;
  box.innerHTML = '';
  appendTimelineRows(0);
  box.scrollTop = top;
}

let timelineFilterTimer = null;

function refilterTimeline() {
  const tl = S.timeline;
  if (!tl) return;
  S.timeline = { ...tl, rows: [], cursor: null, done: false, matched: null,
                 loading: false, range: timelineGraph.range(),
                 q: $('#time-filter').value.trim(),
                 flagged: $('#time-flagged').checked };
  const box = $('#time-results');
  box.innerHTML = '';
  box.scrollTop = 0;
  loadTimelinePage();
}

function refilterTimelineAndGraph() {
  refilterTimeline();
  timelineGraph.load();
}

$('#time-filter')?.addEventListener('input', () => {
  clearTimeout(timelineFilterTimer);
  timelineFilterTimer = setTimeout(refilterTimelineAndGraph, 250);
});
$('#time-flagged')?.addEventListener('change', refilterTimelineAndGraph);
$('#time-zoom')?.addEventListener('click', () => timelineGraph.zoomToSelection());
$('#time-clear')?.addEventListener('click', () => timelineGraph.select(null));
$('#time-out')?.addEventListener('click', () => timelineGraph.resetView());
$('#time-log')?.addEventListener('change', () => timelineGraph.draw());
$('#time-window')?.addEventListener('click', ev => {
  if (ev.target.closest('[data-act="all"]')) {
    ev.preventDefault();
    timelineGraph.showAll();
  }
});
$('#time-scope')?.addEventListener('change', () => loadStoredTimeline());
$('#btn-viewer-hide')?.addEventListener('click', hideViewer);
$('#time-results')?.addEventListener('scroll', ev => {
  const box = ev.currentTarget;
  if (box.scrollTop + box.clientHeight >= box.scrollHeight - PAGE_AHEAD) {
    loadTimelinePage();
  }
});
$('#time-results')?.addEventListener('click', ev => {
  const row = ev.target.closest('.result[data-i]');
  if (!row || !S.timeline) return;
  $$('#time-results .result.is-on').forEach(n => n.classList.remove('is-on'));
  row.classList.add('is-on');
  const e = S.timeline.rows[+row.dataset.i];
  timelineGraph.setMark(e && e.sort);
  openTimelineEvent(e);
});

async function openTimelineEvent(e) {
  if (!e) return;
  const tl = S.timeline;
  const part = partIn(e.ev, e.part);
  if (part && !await useOwner(part)) return;
  if (S.timeline !== tl) return;
  let flag = null;
  if (e.flagged) {
    const r = await api.get('timeline/flag', {
      key: tl.key, ev: e.ev ?? undefined, part: e.part ?? undefined,
      node: e.node ?? undefined }).catch(() => null);
    flag = r && r.flag;
  }
  const onMedia = !!part && (e.offset != null || e.node != null);
  showTimelineEvent(e, flag, onMedia);
  if (onMedia && $('.panel-hex').classList.contains('viewer-borrowed')) {
    showEventBytes(e);
  }
}

let eventBytesSeq = 0;

async function showEventBytes(e) {
  const part = partIn(e.ev, e.part);
  if (!part) return;
  const seq = ++eventBytesSeq;
  const n = e.node == null || e.node === '' ? null : Number(e.node);
  const entry = { name: e.name || '', path: e.path || '', size: e.size,
                  is_dir: !!e.is_dir, deleted: !!e.deleted,
                  ...nodeEntry(part.detected, n) };
  const st = n == null ? null
    : await api.get('stat', { part: partOffset(part),
                              entry: JSON.stringify(entry) }).catch(() => null);
  if (seq !== eventBytesSeq) return;
  if (!scopedTo(part)) {
    setScope(partOffset(part), part.size ?? S.image.size, scopeLabel(part), null);
  }
  if (st && !st.error && gotoEntry(st, part, entry)) {
    if (!entry.is_dir) previewEntry(entry, part);
    syncBytesButton();
    return;
  }
  if (e.offset != null) await jumpTo(e.part, e.offset - e.part, 1, e.ev);
  syncBytesButton();
}

function showTimelineEvent(e, flag, onMedia = false) {
  if (!S.timeline) return;
  $('#inspect').innerHTML = `
    <div class="title">${esc(e.name || '')}</div>
    <div class="subtitle">${esc(e.path || '')}</div>
    ${kv([
      [txt('ui.kv.when'), e.time],
      [txt('ui.kv.what'), e.action],
      [txt('ui.kv.recorded_in'), e.source === '$FILE_NAME'
        ? '$FILE_NAME (kernel maintained)'
        : 'standard metadata (user writable)'],
      [txt('ui.kv.size'), fmt.bytes(e.size), true],
      e.offset != null && [txt('ui.kv.on_media'), `0x${fmt.hex(e.offset, 10)}`, true],
      [txt('ui.kv.state'), e.deleted ? 'deleted' : 'live'],
      e.exhibit && [txt('ui.timeline.kv_exhibit'), e.exhibit],
      e.tags && [txt('ui.timeline.kv_tags'), e.tags],
    ])}
    ${e.partial ? `<p class="notice">${txt('help.timeline.from_tag')}</p>` : ''}
    ${flag ? `<h3>Timestamp observations</h3>
      ${flag.observations.map(o => `<div class="obs">
        <span class="sev">${o.severity} confidence</span>${o.detail}</div>`)
        .join('')}
      ${kv([
        [txt('ui.kv.created_standard'), fmt.time(flag.created)],
        [txt('ui.kv.created_file_name'), fmt.time(flag.fn_created)],
        [txt('ui.kv.modified_standard'), fmt.time(flag.modified)],
        [txt('ui.kv.modified_file_name'), fmt.time(flag.fn_modified)],
      ])}` : ''}
    <div class="actions">
      ${onMedia ? '<button class="ghost" id="btn-time-bytes"></button>' : ''}
      <button class="ghost" id="btn-time-mark">${txt('ui.mark')}</button>
    </div>`;
  syncBytesButton();
  $('#btn-time-bytes')?.addEventListener('click', () => {
    if ($('.panel-hex').classList.contains('viewer-borrowed')) hideViewer();
    else showEventBytes(e);
  });
  $('#btn-time-mark')?.addEventListener('click', () =>
    saveMark(e.offset ?? e.part, 1,
             `${e.action} · ${e.name}`, 'timeline',
             `${e.time} — ${e.path}`));
}

async function loadMarkCategories() {
  if (S.markCats.length) return S.markCats;
  const r = await api.get('bookmark/categories');
  S.markCats = r.categories || [];
  const sel = $('#mark-filter');
  if (sel) {
    sel.innerHTML = `<option value="">${txt('ui.load_mark_categories.all_categories')}</option>`
      + S.markCats.map(c => `<option value="${esc(c.name)}">${esc(c.name)}</option>`)
                  .join('')
      + `<option value="" data-none="1">${txt('ui.load_mark_categories.no_category')}</option>`;
  }
  return S.markCats;
}

function markColour(m) {
  if (m.colour) return m.colour;
  const c = S.markCats.find(x => x.name === m.category);
  return c ? c.colour : '';
}

function renderMarks() {
  const box = $('#mark-results');
  const sel = $('#mark-filter');
  const cat = sel?.value || '';
  const wantNone = sel?.selectedOptions?.[0]?.dataset.none === '1';
  const rep = $('#mark-report-filter')?.value ?? '';
  let list = S.marks;
  if (wantNone) list = list.filter(m => !m.category);
  else if (cat) list = list.filter(m => m.category === cat);
  if (rep !== '') list = list.filter(m => !!m.in_report === (rep === '1'));

  if (!S.marks.length) {
    box.innerHTML = `<p class="empty">${txt('help.marks_yet_select_bytes_hex_view_press')}</p>`;
    return;
  }
  if (!list.length) {
    box.innerHTML = `<p class="empty">${
      txt('help.marks.none_match_filter', { count: S.marks.length })}</p>`;
    return;
  }
  box.innerHTML = list.map(m => {
    const col = markColour(m);
    return `
      <div class="result mark-row" data-off="${m.offset}" data-len="${m.length}"
           data-id="${m.id}" data-frame="${esc(m.frame || 'media')}"
           data-part="${m.part ?? ''}" data-node="${esc(m.node ?? '')}"
           data-stream="${esc(m.stream || '')}"${
             col ? ` style="--mk:${esc(col)}"` : ''}>
        <div class="top">
          ${col ? '<span class="mk-dot" aria-hidden="true"></span>' : ''}
          <span class="kind">${esc(m.label || 'mark')}</span>
          ${m.category ? `<span class="mk-cat">${esc(m.category)}</span>` : ''}
          ${m.in_report ? '' : '<span class="mk-off-report">not in report</span>'}
          ${                                                            
                                                                        
                                                                  ''}
          <span class="off">0x${fmt.hex(m.offset, 8)}${
            m.frame === 'file' ? ' in file' : ''}</span>
        </div>
        <div class="sub">${esc(m.note || '')} · ${esc(m.created_at)} · ${
          esc(m.examiner)}</div></div>`;
  }).join('');
  bindResults(box, el => openMark(el.dataset),
    el => rangeMenu({ offset: +el.dataset.off, length: +el.dataset.len,
                      part: el.dataset.frame === 'file'
                        ? (el.dataset.part === '' ? null : +el.dataset.part)
                        : null,
                      label: 'Bookmark' }));
}

async function openMark(d) {
  if (!d || d.frame !== 'file') {
    return jumpTo(null, +d.off, +d.len);
  }
  const part = d.part === '' ? null : +d.part;
  const p = partIn(S.activeId, part);
  if (!p) return toast(txt('messages.mark_file_not_in_this_exhibit'));
  const node = d.node;
  const entry = { name: '', path: '' };
  const fsName = (p.detected || '').toUpperCase();
  const n = node === '' ? null : Number(node);
  Object.assign(entry, nodeEntry(fsName, n));
  const st = await api.get('stat', { part: partOffset(p),
                                     entry: JSON.stringify(entry),
                                     stream: d.stream || undefined });
  if (!st || st.error) return toast(txt('messages.mark_file_not_readable'));
  const bytes = st.size != null ? st.size : null;
  if (!bytes) return toast(txt('messages.mark_file_not_readable'));
  const chunkMap = st.chunk_map && st.chunk_map.length
    ? { size: st.chunk_size, offsets: st.chunk_map } : null;
  setFileScope(entry, p, bytes,
               `${st.name || 'file'}${d.stream ? ':' + d.stream : ''}`
               + ` \u00b7 file offsets`,
               d.stream || null, runExtents(st, p), chunkMap);
  revealViewer();
  S.cursor = hex.clamp(+d.off);
  S.selection = { start: +d.off, length: Math.max(1, +d.len || 1) };
  hex.reveal(S.cursor);
  updateStatus();
}

async function loadMarks() {
  await loadMarkCategories();
  const r = await api.get('bookmarks');
  S.marks = Array.isArray(r) ? r : [];
  renderMarks();
  tabCount('marks', S.marks.length);
  core.draw();
  hex.draw();
}

function markFrame() {
  if (!S.scope.file || !S.scope.entry) return { frame: 'media' };
  const e = S.scope.entry;
  return {
    frame: 'file',
    part: S.scope.part,
    node: String(e.oid ?? e.mft ?? e.inode ?? e.start_cluster ?? e.path ?? ''),
    stream: S.scope.stream || null,
    name: e.name || '',
  };
}

async function saveMark(absOffset, length, label, source, note = '',
                        category = '', inReport = true, where = null) {
  const frame = where || { frame: 'media' };
  await api.post('bookmark', {
    offset: absOffset, length, label, note, source, category,
    colour: (S.markCats.find(c => c.name === category) || {}).colour || '',
    in_report: inReport,
    frame: frame.frame,
    part: frame.part ?? null,
    node: frame.node ?? null,
    stream: frame.stream ?? null,
    mark_in: frame.name ?? null,
  });
  await loadMarks();
  toast(inReport ? txt('messages.mark_saved_case')
                 : txt('messages.mark_saved_working_mark_kept_out_report'));
}

async function openDocument(e, part) {
  const token = (pvToken = Symbol());
  pvSet(e.name, 'document', `<p class="empty">${txt('ui.preview_entry.reading')}</p>`);
  const d = await api.get('document', { part: partOffset(part),
                                       entry: JSON.stringify(e) });
  if (pvToken !== token) return;
  if (d.error) return pvSet(e.name, 'document',
    `<div class="notice bad">${esc(d.error)}</div>`);
  if (!d.document) {
    return pvSet(e.name, 'document',
      `<p class="empty">${esc(d.note)}</p>
       <div class="actions">
         <button class="ghost" id="doc-as-zip">${txt('ui.open_archive')}</button>
       </div>`) || bindDocZip(e, part);
  }

  const meta = Object.entries(d.metadata || {});
  const secs = (d.sections || []).map((sec, i) => `
    <details class="docsec"${i === 0 ? ' open' : ''}>
      <summary>${esc(sec.name)} <span class="dq">${
        sec.text.length.toLocaleString()}</span></summary>
      <pre class="doctext">${escText(sec.text)}</pre>
    </details>`).join('');

  pvSet(e.name, d.kind, `
    ${(d.findings || []).map(f =>
        `<div class="notice bad">${esc(f)}</div>`).join('')}
    ${meta.length ? `<h3>Document properties</h3>
      ${kv(meta.map(([k, v]) => [k, String(v)]))}
      <p class="hint">${esc(d.note)}</p>` : ''}
    ${secs || '<p class="empty">The document carries no text.</p>'}
    <div class="actions">
      <button class="ghost" id="doc-as-zip">${txt('ui.open_archive')}</button>
    </div>`);
  bindDocZip(e, part);
}

function bindDocZip(e, part) {
  $('#doc-as-zip')?.addEventListener('click', () => openArchive(e, part));
}

function applyEmptyCase(r) {
  const next = r.case_path || r.case?.path || null;
  enterCase(next);
  S.open = false;
  S.image = null;
  S.volumes = null;
  S.caseInfo = r.case;
  S.casePath = next;
  S.exhibits = [];
  S.activeId = null;
  startPulse();
  const caseFile = S.casePath ? S.casePath.replace(/^.*[\\/]/, '') : null;
  $('#evidence-bar').innerHTML = `
    <span class="name">${esc(caseFile || r.case?.name || 'No case file')}</span>
    <span class="meta">no evidence · ${
      esc(r.case?.examiner || 'unattributed')}</span>
    <button class="ghost" id="btn-add">${txt('ui.apply_empty_case.add_evidence')}</button>
    <button class="ghost" id="btn-case">${txt('ui.app.case')}</button>`;
  $('#btn-add').addEventListener('click', () => openDialog({ add: true }));
  $('#btn-case').addEventListener('click', () => caseDialog());
  $('#btn-audit').hidden = false;
  $('#btn-report').hidden = false;
  $('#integrity').hidden = true;
  if ($('.view[data-view="cases"]')?.classList.contains('is-on')) {
    renderCases();
  }
  $('#tree').innerHTML =
    `<p class="empty">${txt('ui.case_evidence_use')} <strong>Add `
    + 'evidence</strong> to put an image in it — its bookmarks, tags and '
    + 'audit trail are still here.</p>';
  previewNone(txt('messages.case_evidence_yet'));
  setEmptyScope(caseFile || r.case?.name || txt('ui.cases.no_case'), null);
}

function examinerName() {
  const raw = (S.examiner || S.caseInfo?.examiner || "").trim();
  return (!raw || raw.toLowerCase() === "unattributed") ? null : raw;
}

async function loadWho() {
  const r = await api.get('whoami');
  S.examiner = r.name || null;
  const el = $('#who-name');
  if (el) el.textContent = r.name || 'Set name';
  $('#btn-who')?.classList.toggle('is-unset', !r.name);
  return r.name;
}

async function setWho(name) {
  const r = await api.post('whoami', { name });
  if (r.error) return toast(r.error);
  await loadWho();
  toast(txt('messages.toast.work_now_recorded_name', { name: name }));
}

async function openWho() {
  await loadWho();
  $('#who-input').value = S.examiner || '';
  const who = await api.get('analysts');
  const others = (who.analysts || []).filter(a => a.name !== S.examiner);
  const idle = who.unnamed || 0;
  const tail = !idle ? '' :
    `<p class="hint">${txt('help.who.idle_browsers',
                          { count: idle })}</p>`;
  $('#who-others').innerHTML = (!others.length && !idle) ? '' : `
    <h3>${txt('ui.also_working_here')}</h3>
    ${others.length ? kv(others.map(a => [a.name, a.case || 'no case open']))
                    : ''}
    ${tail}
    <p class="hint">${esc(who.note)}</p>`;
  $('#dlg-who').showModal();
  $('#who-input').focus();
}

let pickerRows = [];
const picked = new Set();

const COST_RANK = { instant: 0, quick: 1, minutes: 2, long: 3 };

let pickerPresence = {};

async function openPicker() {
  if (!S.open) return toast(txt('messages.toast.open_evidence_first'));
  const [r, presence] = await Promise.all([
    api.get('artifacts'), api.get('artifacts/presence')]);
  pickerRows = r.artifacts || [];
  pickerPresence = presence || {};
  if (!picked.size) {
    const ok = new Set(pickerRows.filter(a => a.available !== false)
                                 .map(a => a.id));
    (r.triage || []).filter(id => ok.has(id)).forEach(id => picked.add(id));
  }
  renderPicker();
  $('#dlg-picker').showModal();
}

function presenceHint(id) {
  const p = pickerPresence;
  if (id === 'recyclebin' && p.recyclebin?.found) {
    return txt('ui.presence.recyclebin_found', { count: p.recyclebin.count });
  }
  if (id === 'prefetch' && p.prefetch?.found) {
    return txt('ui.presence.prefetch_found', { count: p.prefetch.count });
  }
  if (id === 'browser' && p.browser?.found) {
    return txt('ui.presence.browser_found', { count: p.browser.profiles.length });
  }
  return null;
}

function renderPicker() {
  const groups = {};
  for (const a of pickerRows) (groups[a.cost] = groups[a.cost] || []).push(a);
  const order = Object.keys(groups).sort((x, y) => COST_RANK[x] - COST_RANK[y]);

  $('#picker-list').innerHTML = order.map(cost => `
    <div class="pick-group">
      <div class="pick-cost">${esc(cost)}
        <span class="pick-costnote">${esc(groups[cost][0].cost_note)}</span></div>
      ${groups[cost].map(a => {
        const off = a.available === false;
        const hint = !off && presenceHint(a.id);
        return `
        <label class="pick${off ? ' is-off' : ''}">
          <input type="checkbox" data-id="${esc(a.id)}"
                 ${picked.has(a.id) && !off ? 'checked' : ''}
                 ${off ? 'disabled' : ''}>
          <span class="pick-body">
            <span class="pick-label">${esc(a.label)}</span>
            <span class="pick-answers">${esc(a.answers)}</span>
            ${hint ? `<span class="pick-presence">${esc(hint)}</span>` : ''}
            ${off ? `<span class="pick-why">${
              esc(a.unavailable_because || 'Not available for this image.')
            }</span>` : ''}
          </span>
        </label>`;
      }).join('')}
    </div>`).join('');

  $$('#picker-list input[type=checkbox]').forEach(el =>
    el.addEventListener('change', () => {
      el.checked ? picked.add(el.dataset.id) : picked.delete(el.dataset.id);
      updateSelection();
    }));
  updateSelection();
}

function updateSelection() {
  const runnable = new Set(pickerRows.filter(a => a.available !== false)
                                     .map(a => a.id));
  const n = [...picked].filter(id => runnable.has(id)).length;
  $('#pick-run').disabled = n === 0;
  $('#pick-run').textContent = n ? `Run ${n} selected` : 'Run selected';
}

async function runSelection(ids) {
  const rows = pickerRows.filter(a => ids.includes(a.id) && a.available !== false);
  rows.sort((a, b) => COST_RANK[a.cost] - COST_RANK[b.cost]);
  const parts = (S.volumes?.partitions || [])
    .filter(p => p.allocated && p.detected);

  let ran = 0, failed = 0, skipped = 0;

  const jobs = [];
  for (const a of rows) {
    if (!a.route) { skipped++; continue; }
    for (const p of (a.per_volume ? parts : [null])) jobs.push({ a, p });
  }

  const RUN_AT_ONCE = 4;
  let next = 0;

  async function worker() {
    while (next < jobs.length) {
      const { a, p } = jobs[next++];
      const body = p ? { part: p.offset } : {};
      try {
        let r;
        if (a.method === 'GET') {
          r = await api.get(a.route, body);
        } else {
          r = await api.post(a.route, body);
          if (r && r.id && r.state) r = await awaitTask(r, a.label);
        }
        if (r && r.error) { failed++; } else { ran++; }
      } catch (err) {
        failed++;
      }
      pollTasks();
    }
  }

  await Promise.all(Array.from({ length: Math.min(RUN_AT_ONCE, jobs.length) },
                               worker));
  await loadTriage();
  toast(txt('messages.artefacts.runs_finished', { count: ran })
        + (failed ? `, ${failed} failed` : '')
        + (skipped ? txt('ui.skipped_already_known', { skipped: skipped }) : '') + '.');
}

function initPlatformKeys() {
  const pal = $('#btn-palette');
  if (pal) {
    pal.textContent = MOD_LABEL('K');
    pal.title = 'Commands — ' + MOD_LABEL('K');
  }
  $$('kbd.mod').forEach(k => { k.textContent = MOD_KEY; });
}

const NO_CLOSE_BUTTON = ['dlg-busy', 'dlg-palette'];

function initDialogClose() {
  $$('dialog').forEach(dlg => {
    if (NO_CLOSE_BUTTON.includes(dlg.id)) return;
    if (dlg.querySelector(':scope > .dlg-x, :scope > * > .dlg-x')) return;
    const x = document.createElement('button');
    x.type = 'button';
    x.className = 'dlg-x';
    x.title = 'Close (Esc)';
    x.setAttribute('aria-label', 'Close');
    x.innerHTML = '&times;';
    x.addEventListener('click', () => dlg.close('cancel'));
    (dlg.querySelector(':scope > .dlg') || dlg).prepend(x);
  });
}

function initPicker() {
  $('#btn-picker')?.addEventListener('click', openPicker);
  $('#pick-triage')?.addEventListener('click', () => {
    picked.clear();
    pickerRows.filter(a => a.in_triage && a.available !== false)
              .forEach(a => picked.add(a.id));
    renderPicker();
  });
  $('#pick-all')?.addEventListener('click', () => {
    picked.clear();
    pickerRows.filter(a => a.available !== false).forEach(a => picked.add(a.id));
    renderPicker();
  });
  $('#pick-none')?.addEventListener('click', () => {
    picked.clear();
    renderPicker();
  });
  $('#dlg-picker')?.addEventListener('close', () => {
    const dlg = $('#dlg-picker');
    const go = dlg.returnValue === 'ok' && picked.size;
    dlg.returnValue = '';
    if (go) {
      runSelection([...picked]);
    }
  });
}

let usnPage = 0, usnQuery = '', usnReason = '';
const USN_PER_PAGE = 200;

async function loadUsn(part) {
  const r = await api.get('usn', {
    offset: usnPage * USN_PER_PAGE, limit: USN_PER_PAGE,
    q: usnQuery || undefined, reason: usnReason || undefined,
  });
  if (!r.loaded) {
    $('#art-results').innerHTML =
      `<p class="empty">${txt('ui.change_journal_been_read_yet')}</p>`;
    return;
  }
  renderUsn(r, part);
}

function renderUsn(r, part) {
  const st = r.stats || {}, j = r.journal || {};
  const pages = Math.max(1, Math.ceil(r.total / USN_PER_PAGE));
  const notes = [];
  if (st.resyncs) {
    notes.push(`<p class="notice bad">${txt('help.resyncs_point_s_journal_could_followed_skipped', { resyncs: st.resyncs.toLocaleString(), resync_bytes: st.resync_bytes.toLocaleString() })}</p>`);
  }
  if (st.sparse_skipped) {
    notes.push(`<p class="notice">${txt('help.sparse_skipped_stream_unallocated_windows_purges_head', { sparse_skipped: fmt.bytes(st.sparse_skipped) })}</p>`);
  }
  if (j.readable) {
    notes.push(`<p class="hint">${txt('help.journal_journal_id_cap_max_size_lowest', { journal_id: esc(j.journal_id), max_size: fmt.bytes(j.max_size), lowest_valid_usn: (j.lowest_valid_usn || 0).toLocaleString() })}</p>`);
  }

  const rows = (r.records || []).map(x => `
    <tr data-mft="${x.mft ?? ''}">
      <td class="dv">${esc(fmt.time(x.timestamp))}</td>
      <td class="dv">${esc(x.name || '—')}</td>
      <td class="dv">${esc((x.reasons || []).join(', '))}</td>
      <td class="dv">${x.is_dir ? 'dir' : 'file'}</td>
      <td class="dv">${x.mft ?? '—'}</td>
      <td class="dv">${x.parent_mft ?? '—'}</td>
      <td class="dv">${(x.usn ?? 0).toLocaleString()}</td>
    </tr>`).join('');

  $('#art-results').innerHTML = `
    ${notes.join('')}
    <div class="runbar">
      <input type="text" id="usn-q" class="dv-filter" placeholder="${txt('ui.name_placeholder')}"
             value="${esc(usnQuery)}">
      <select id="usn-reason">
        <option value="">${txt('ui.every_change')}</option>
        ${(r.reasons || []).map(x =>
          `<option value="${esc(x)}"${x === usnReason ? ' selected' : ''}>${esc(x)}</option>`
        ).join('')}
      </select>
      <button class="ghost" id="usn-prev"${usnPage ? '' : ' disabled'}>${txt('ui.render_usn.prev')}</button>
      <span class="len">${txt('ui.render_usn.pager', {
        page: (usnPage + 1).toLocaleString(),
        pages: pages.toLocaleString(),
        count: r.total, n: r.total.toLocaleString() })}</span>
      <button class="ghost" id="usn-next"${
        usnPage + 1 >= pages ? ' disabled' : ''}>${txt('ui.render_usn.next')}</button>
    </div>
    <table class="dv-list">
      <thead><tr><th>${txt('ui.render_usn.when')}</th><th>${txt('ui.render_registry.name')}</th><th>${txt('ui.happened')}</th><th>${txt('ui.render_usn.kind')}</th>
        <th>${txt('ui.render_usn.mft')}</th><th>${txt('ui.render_usn.parent')}</th><th>${txt('ui.render_usn.usn')}</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;

  $('#usn-prev').addEventListener('click', () => {
    if (usnPage) { usnPage--; loadUsn(part); }
  });
  $('#usn-next').addEventListener('click', () => {
    if (usnPage + 1 < pages) { usnPage++; loadUsn(part); }
  });
  $('#usn-reason').addEventListener('change', e => {
    usnReason = e.target.value; usnPage = 0; loadUsn(part);
  });
  let t;
  $('#usn-q').addEventListener('input', e => {
    clearTimeout(t);
    const v = e.target.value;
    t = setTimeout(() => { usnQuery = v; usnPage = 0; loadUsn(part); }, 250);
  });
  initColumnResize();
}

let toastTimer;
function noticeWanted(channel) {
  if (!channel || channel === 'problem') return true;
  const set = (S.prefs && S.prefs.notify) || {};
  return set[channel] !== false;
}

function toast(msg, channel = 'problem') {
  if (!noticeWanted(channel)) return;
  const el = $('#stat-context');
  el.textContent = msg;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(updateStatus, 6000);
}

const OPEN_STAGES = [
  ['bookmarks…', () => loadMarks()],
  [txt('ui.tagged_items_2'), () => loadTags()],
  [txt('ui.saved_searches_2'), () => loadSavedSearches()],
  [txt('ui.hash_sets'), () => loadHashSets()],
  [txt('ui.index_state'), () => refreshIndexState()],
];

function adoptOpened(state) {
  dirCache.clear();
  walkCache.clear();
  artCache.clear();
  profileCache.clear();
  volmapCache.clear();
  applyOpened(state);
}

async function openImage(path, examiner, casePath,
                         { add = false, kind = 'image' } = {}) {
  busy.open(add ? txt('ui.adding_evidence') : txt('ui.opening_evidence'), path);
  busy.waiting(txt('ui.reading_container'));
  let r;
  try {
    r = await api.post('open', { path, examiner, case: casePath, add, kind });
    if (r.error) return toast(r.error);
    busy.waiting(txt('ui.reading_volume_layout'));
    adoptOpened(r);
    for (const [label, fn] of OPEN_STAGES) {
      busy.waiting(label);
      await fn();
    }
  } finally {
    busy.close();
  }
  pollTasks();
  loadSavedArtefacts();
  if (r.index_reset) {
    toast(txt('messages.toast.content_index_reset_schema_update_needs_rebuilding'));
  }
  loadTimezone(true);
  if (add) {
    toast(txt('messages.added_path_exhibits_exhibits_case', { path: path.replace(/^.*[\\/]/, ''), exhibits: S.exhibits.length }));
  }
}

function applyOpened(r, { tree = true } = {}) {
  if (!r.open) return applyEmptyCase(r);
  enterCase(r.case_path || null);
  S.open = true;
  S.image = r.image;
  S.volumes = r.volumes;
  S.caseInfo = r.case;
  S.casePath = r.case_path || null;
  S.exhibits = r.evidence || [];
  S.activeId = r.active_id ?? null;
  S.evidenceId = r.evidence_id ?? null;
  startPulse();
  relocateIndex(r.index_pending);

  for (const ex of S.exhibits) {
    for (const p of (ex.volumes || {}).partitions || []) {
      p.ev_id = ex.evidence_id;
    }
  }
  for (const p of (S.volumes || {}).partitions || []) p.ev_id = S.activeId;

  const caseFile = S.casePath ? S.casePath.replace(/^.*[\\/]/, '') : null;
  const exhibits = S.exhibits.length;
  $('#evidence-bar').innerHTML = `
    <span class="name">${esc(caseFile || r.case?.name || 'No case file')}</span>
    <span class="meta">${exhibits
        ? txt('ui.count.exhibits', { count: exhibits }) + ' · ' : ''}${
      esc(r.case?.examiner || txt('ui.unattributed'))}</span>
    <button class="ghost" id="btn-add">${txt('ui.apply_empty_case.add_evidence')}</button>
    <button class="ghost" id="btn-case">${txt('ui.app.case')}</button>`;
  $('#btn-add').addEventListener('click', () => openDialog({ add: true }));
  $('#btn-case').addEventListener('click', () => caseDialog());
  $('#btn-audit').hidden = false;
  $('#btn-report').hidden = false;
  $('#integrity').hidden = false;
  $('#integrity').dataset.state = 'unchecked';
  $('#integrity').textContent = txt('ui.hashes_unchecked');
  scopeOptions();
  if ($('.view[data-view="cases"]')?.classList.contains('is-on')) {
    renderCases();
  }
  if (!tree) return;
  renderTree();
  setScope(null, r.image.size,
           S.exhibits.find(e => e.evidence_id === S.activeId)?.label
           || r.image.segments[0], S.image);
  previewNone(txt('messages.select_file_folder_preview'));
}

async function browse(path, { into = '#browser', target = '#open-path',
                              kind = 'image', onPick = null,
                              onDir = null } = {}) {
  const r = await api.get('browse', { path, for: kind });
  onDir?.(r.path);
  $(into).dataset.at = r.path;
  $(into).innerHTML = `
    <div class="item dir" data-path="${r.parent}" data-dir="1">.. </div>
    ${r.items.map(i => `<div class="item ${i.dir ? 'dir' : ''}${
         i.case ? ' is-case' : ''}"
       data-path="${esc(i.path)}" data-dir="${i.dir ? 1 : 0}">
       ${i.dir ? '▸' : (i.case ? '▣' : ' ')} ${esc(i.name)}
       <span class="sz">${i.dir || i.case ? '' : fmt.bytes(i.size)}</span></div>`).join('')}`;
  $$(into + ' .item').forEach(el => el.addEventListener('click', () => {
    if (el.dataset.dir === '1') {
      browse(el.dataset.path, { into, target, kind, onPick, onDir });
    } else { $(target).value = el.dataset.path; onPick?.(el.dataset.path); }
  }));
}

function openDialog({ add = false, kind = 'image' } = {}) {
  const dlg = $('#dlg-open');
  dlg.dataset.add = add ? '1' : '';
  const known = examinerName();
  $('#open-examiner').value = known || '';
  $('#open-examiner-field').hidden = add && !!known;
  $('#open-title').textContent = add ? 'Add evidence' : txt('ui.app.open');
  $('#open-confirm').textContent = add ? 'Add' : 'Open';
  $('#open-case-field').hidden = add;
  $('#open-add-note').hidden = !add;
  if (add && S.casePath) {
    $('#open-add-note').textContent =
      txt('messages.added_alongside_exhibits_already_open_casepath', { exhibits: S.exhibits.length, casePath: S.casePath.replace(/^.*[\\/]/, '') })
      + (known ? txt('messages.recorded_known', { known: known })
               : txt('help.nobody_recorded_examining_case_yet'));
  }
  setOpenKind(kind);
  dlg.showModal();
}

const OPEN_KINDS = ['image', 'file', 'folder'];
const openKind = () => $('#dlg-open')?.dataset.kind || 'image';

function setOpenKind(kind) {
  const k = OPEN_KINDS.includes(kind) ? kind : 'image';
  $('#dlg-open').dataset.kind = k;
  $$('#open-kinds .open-kind').forEach(b => {
    const on = b.dataset.kind === k;
    b.classList.toggle('is-on', on);
    b.setAttribute('aria-checked', String(on));
  });
  openKindChanged();
}

function openKindChanged() {
  const kind = openKind();
  const hints = { image: txt('help.open.point_strata_at_e01_ex01_raw'),
                  file: txt('help.open.kind_file'),
                  folder: txt('help.open.kind_folder') };
  const places = { image: txt('tooltips.tag.path_image_e01'),
                   file: txt('tooltips.open.path_file'),
                   folder: txt('tooltips.open.path_folder') };
  $('#open-hint').textContent = hints[kind];
  $('#open-path').placeholder = places[kind];
  $('#open-usedir').hidden = kind !== 'folder';
  browse($('#open-path').value || '/',
         { kind: kind === 'image' ? 'image' : 'any' });
}

$$('#open-kinds .open-kind').forEach(b =>
  b.addEventListener('click', () => setOpenKind(b.dataset.kind)));

$('#open-usedir')?.addEventListener('click', () => {
  const at = $('#browser')?.dataset.at;
  if (at) $('#open-path').value = at;
});

(async () => {
  const btn = $('#open-browse');
  if (!btn) return;
  const r = await api.post('pick', { mode: 'probe' }).catch(() => ({ ok: false }));
  btn.hidden = !r.ok;
  if (!r.ok && r.unavailable) btn.title = r.unavailable;
})();

$('#open-browse')?.addEventListener('click', async () => {
  const kind = openKind();
  const chosen = await pickPath({ title: txt('ui.app.open'),
                                  mode: kind === 'folder' ? 'dir' : 'open',
                                  kind: kind === 'image' ? 'image' : 'any',
                                  dir: $('#open-path').value || '' });
  if (!chosen) return;
  $('#open-path').value = chosen;
  browse(chosen, { kind: kind === 'image' ? 'image' : 'any' });
});

async function peekCase(path) {
  const box = $('#case-peek');
  if (!path) { box.innerHTML = ''; return; }
  const r = await api.get('case/peek', { path });
  if (r.error) { box.innerHTML = `<p class="empty">${esc(r.error)}</p>`; return; }
  const ev = r.evidence?.[0];
  box.innerHTML = `
    ${kv([
      [txt('ui.kv.case'), r.name],
      [txt('ui.kv.created'), fmt.time(r.created_at)],
      [txt('ui.kv.by'), r.created_by],
      [txt('ui.kv.evidence'), ev ? ev.label || ev.path : '—'],
      [txt('ui.kv.bookmarks'), r.bookmark_count],
      [txt('ui.kv.audit_entries'), r.audit_entries],
    ])}
    <div class="notice ${r.audit_integrity?.intact ? '' : 'bad'}">
      ${r.audit_integrity?.intact
        ? 'Audit chain intact.'
        : `Audit chain broken at entry ${r.audit_integrity?.broken_at}.`}
    </div>`;
}

function caseDialog() {
  $('#case-peek').innerHTML = '';
  $('#dlg-case').showModal();
  browse($('#case-path').value || '/', {
    into: '#case-browser', target: '#case-path', kind: 'case',
    onPick: peekCase,
  });
}

async function openCase(path, examiner) {
  busy.open(txt('ui.opening_case'), path);
  busy.waiting(txt('ui.reading_case'));
  let r;
  try {
    r = await api.post('case/open', { path, examiner });
    if (r.error) return toast(r.error);
    dirCache.clear();
    walkCache.clear();
    artCache.clear();
    profileCache.clear();
    volmapCache.clear();
    busy.waiting(txt('ui.reading_volume_layout'));
    applyOpened(r);
    for (const [label, fn] of OPEN_STAGES) {
      busy.waiting(label);
      await fn();
    }
  } finally {
    busy.close();
  }
  pollTasks();
  if (r.index_reset) {
    toast(txt('messages.toast.content_index_reset_schema_update_needs_rebuilding'));
  }
  loadTimezone(true);
}

let recentCases = [];

async function loadRecents() {
  const r = await api.get('case/recent').catch(() => null);
  recentCases = r?.cases || [];
  return recentCases;
}

function recentFlag(c) {
  if (c.exists === false) return `<span class="flag warn">${txt('ui.cases.missing')}</span>`;
  if (c.exists === null || c.exists === undefined) {
    return `<span class="flag warn">${txt('ui.cases.unreachable')}</span>`;
  }
  return '';
}

function evidenceRow(e, openIds) {
  const isActive = e.id === S.activeId;
  const isOpen = openIds.has(e.id);
  const verified = e.verified_at
    ? `<span class="flag">${txt('ui.cases.verified')}</span>` : '';
  const state = isActive
    ? `<span class="flag">${txt('ui.cases.active')}</span>`
    : (isOpen ? '' : `<span class="flag warn">${txt('ui.cases.not_open')}</span>`);
  return `
    <div class="result ${isActive ? 'is-on' : ''}" data-ev="${e.id}"
         data-open="${isOpen ? 1 : 0}" data-path="${esc(e.path)}">
      <div class="top">
        <span class="kind">${esc(e.format || '—')}</span>
        <span>${esc(e.label || e.path)}</span>
        ${state}${verified}
        <span class="off">${fmt.bytes(e.size)}</span>
      </div>
      <div class="sub">${esc(e.path)}</div>
      <button class="linkish" data-remove="${e.id}">${txt('ui.cases.remove')}</button>
    </div>`;
}

function caseCard(c) {
  return `
    <div class="case-card">
      <div class="top">
        <span class="case-name">${esc(c.name || '—')}</span>
        <span class="off">${txt('ui.cases.open_now')}</span>
      </div>
      <code class="dim">${esc(c.path || '')}</code>
      ${kv([
        [txt('ui.cases.examiner'), esc(c.examiner || txt('ui.unattributed'))],
        [txt('ui.cases.created'), fmt.time(c.created_at)],
        [txt('ui.cases.created_by'), esc(c.created_by || txt('ui.unattributed'))],
        [txt('ui.cases.bookmarks'), (c.bookmark_count || 0).toLocaleString(), true],
        [txt('ui.cases.tagged'), (c.tagged_count || 0).toLocaleString(), true],
        [txt('ui.cases.audit'), (c.audit_entries || 0).toLocaleString(), true],
      ])}
    </div>`;
}

async function renderCases() {
  const box = $('#cases-results');
  if (!box) return;
  const c = S.caseInfo;
  const openIds = new Set((S.exhibits || []).map(e => e.evidence_id));
  const ev = c?.evidence || [];

  box.innerHTML = `
    ${c ? caseCard(c) : `<p class="empty">${txt('help.cases.none_open')}</p>`}
    ${c ? `<h3 class="case-sec">${txt('ui.cases.evidence')}</h3>
      ${ev.length ? ev.map(e => evidenceRow(e, openIds)).join('')
                  : `<p class="empty">${txt('help.cases.no_evidence')}</p>`}` : ''}
    <h3 class="case-sec">${txt('ui.cases.recent')}</h3>
    <div id="cases-recent"><p class="empty">${txt('ui.cases.reading')}</p></div>`;

  $$('#cases-results [data-remove]').forEach(el =>
    el.addEventListener('click', bit => {
      bit.stopPropagation();
      removeExhibit({ evidence_id: +el.dataset.remove });
    }));
  $$('#cases-results .result[data-ev]').forEach(el =>
    el.addEventListener('click', () => pickExhibit(el)));

  await loadRecents();
  const list = $('#cases-recent');
  if (!list) return;
  const here = S.casePath ? S.casePath.toLowerCase() : null;
  const rows = recentCases.filter(x => (x.path || '').toLowerCase() !== here);
  list.innerHTML = rows.length ? rows.map(x => `
    <div class="result" data-case="${esc(x.path)}"
         data-there="${x.exists === true ? 1 : 0}">
      <div class="top">
        <span>${esc(x.name || '—')}</span>
        ${recentFlag(x)}
        <span class="off">${fmt.time(x.opened_at)}</span>
      </div>
      <div class="sub">${esc(x.path)}</div>
      <button class="linkish" data-forget="${esc(x.path)}">${
        txt('ui.cases.forget')}</button>
    </div>`).join('')
    : `<p class="empty">${recentCases.length ? txt('help.cases.only_this')
                                             : txt('help.cases.no_recent')}</p>`;

  $$('#cases-recent [data-forget]').forEach(el =>
    el.addEventListener('click', async bit => {
      bit.stopPropagation();
      const r = await api.post('case/forget', { path: el.dataset.forget });
      if (r.error) return toast(r.error);
      toast(txt('messages.cases.forgotten'));
      renderCases();
    }));
  $$('#cases-recent .result[data-case]').forEach(el =>
    el.addEventListener('click', () => {
      if (el.dataset.there !== '1') {
        return toast(txt('messages.cases.gone', { path: el.dataset.case }));
      }
      openCase(el.dataset.case, examinerName() || undefined);
    }));
}

async function pickExhibit(el) {
  const id = +el.dataset.ev;
  if (el.dataset.open === '1') {
    const r = await api.post('evidence/select', { evidence_id: id });
    if (r.error) return toast(r.error);
    switchTo(r);
    setModule('sources');
    return;
  }
  const r = await api.post('open', { path: el.dataset.path, add: true,
                                     case: S.casePath,
                                     examiner: examinerName() || undefined });
  if (r.error) return toast(r.error);
  applyOpened(r);
  renderCases();
}

function newCaseDialog() {
  const dlg = $('#dlg-new-case');
  if (!dlg) return;
  $('#newcase-name').value = '';
  $('#newcase-examiner').value = examinerName() || '';
  $('#newcase-path').value = '';
  $('#newcase-where').textContent = txt('help.newcase.pick_folder');
  dlg.returnValue = '';
  dlg.showModal();
  browse($('#newcase-path').value || '/', {
    into: '#newcase-browser', target: '#newcase-path', kind: 'case',
    onPick: pathHint,
    onDir: where => { $('#newcase-path').value = where; pathHint(); },
  });
  $('#newcase-name').focus();
}

function pathHint() {
  const where = $('#newcase-path').value.trim();
  const name = $('#newcase-name').value.trim();
  const el = $('#newcase-where');
  if (!el) return;
  if (!where) { el.textContent = txt('help.newcase.pick_folder'); return; }
  el.textContent = txt('messages.newcase.will_write', { path: caseFilePath() });
}

function caseFilePath() {
  let where = $('#newcase-path').value.trim();
  const name = $('#newcase-name').value.trim();
  if (!where) return '';
  if (/\.strata$/i.test(where)) return where;
  const sep = where.includes('\\') ? '\\' : '/';
  const leaf = (name || 'case').replace(/[\\/:*?"<>|]+/g, '-').trim() || 'case';
  return where.replace(/[\\/]+$/, '') + sep + leaf + '.strata';
}

async function createCase() {
  const path = caseFilePath();
  if (!path) return toast(txt('messages.newcase.need_folder'));
  const r = await api.post('case/new', {
    path,
    name: $('#newcase-name').value.trim() || undefined,
    examiner: $('#newcase-examiner').value.trim() || undefined,
  });
  if (r.error) return toast(r.error);
  dirCache.clear();
  walkCache.clear();
  artCache.clear();
  profileCache.clear();
  volmapCache.clear();
  applyOpened(r);
  renderCases();
  toast(txt('messages.newcase.made', { path }));
}

function closeCaseDialog() {
  if (!S.casePath) return toast(txt('messages.cases.none_open'));
  const dlg = $('#dlg-close-case');
  if (!dlg) return;
  $('#closecase-what').textContent = S.caseInfo?.name || '';
  $('#closecase-path').textContent = S.casePath;
  const n = (S.exhibits || []).length;
  $('#closecase-holds').textContent = n
    ? txt('messages.closecase.holds', { count: n, n: n.toLocaleString() })
    : txt('messages.closecase.holds_none');
  dlg.returnValue = '';
  dlg.showModal();
}

async function closeCase() {
  const r = await api.post('case/close', {});
  if (r.error) {
    return toast(r.tasks?.length ? `${r.error} ${r.advice}` : r.error);
  }
  dirCache.clear();
  walkCache.clear();
  artCache.clear();
  profileCache.clear();
  volmapCache.clear();
  applyNoCase();
  setModule('cases');
  renderCases();
  toast(txt('messages.cases.closed', { name: r.closed_case || '' }));
}

function applyNoCase() {
  enterCase(null);
  stopPulse();
  S.open = false;
  S.image = null;
  S.volumes = null;
  S.caseInfo = null;
  S.casePath = null;
  S.exhibits = [];
  S.activeId = null;
  S.evidenceId = null;
  S.scope = null;
  S.marks = [];
  S.tags = [];
  $('#evidence-bar').innerHTML = `
    <button class="ghost" id="btn-open">${txt('ui.app.open')}</button>
    <button class="ghost" id="btn-case">${txt('ui.app.case')}</button>`;
  $('#btn-open').addEventListener('click', () => openDialog());
  $('#btn-case').addEventListener('click', () => caseDialog());
  $('#btn-audit').hidden = true;
  $('#btn-report').hidden = true;
  $('#integrity').hidden = true;
  $('#tree').innerHTML = `<p class="empty">${txt('help.cases.none_open')}</p>`;
  $('#inspect').innerHTML = '';
  previewNone(txt('help.cases.none_open'));
  setEmptyScope(txt('ui.cases.no_case'), null);
}

$('#btn-new-case')?.addEventListener('click', newCaseDialog);
$('#btn-open-case')?.addEventListener('click', () => caseDialog());
$('#btn-case-add')?.addEventListener('click', () => openDialog({ add: !!S.casePath }));
$('#btn-close-case')?.addEventListener('click', closeCaseDialog);
$('#newcase-name')?.addEventListener('input', pathHint);
$('#newcase-path')?.addEventListener('input', pathHint);
$('#dlg-new-case')?.addEventListener('close', () => {
  if ($('#dlg-new-case').returnValue === 'ok') createCase();
});
$('#dlg-close-case')?.addEventListener('close', () => {
  if ($('#dlg-close-case').returnValue === 'ok') closeCase();
});

let prefTimer = null;
const prefQueue = {};

function savePref(key, value) {
  prefQueue[key] = value;
  S.prefs[key] = value;
  clearTimeout(prefTimer);
  prefTimer = setTimeout(() => {
    const send = { ...prefQueue };
    for (const k of Object.keys(prefQueue)) delete prefQueue[k];
    api.post('prefs', send).catch(() => {});
  }, 400);
}

const THEMES = ['dark', 'light', 'midnight', 'sepia', 'contrast', 'paper'];

function toggleTheme() {
  applyTheme(['light', 'paper'].includes(document.documentElement.dataset.theme)
    ? 'dark' : 'light');
}

function applyTheme(name, { save = true } = {}) {
  const theme = THEMES.includes(name) ? name : 'dark';
  document.documentElement.dataset.theme = theme;
  const btn = $('#btn-theme');
  if (btn) btn.textContent = txt('ui.settings.theme_' + theme);
  if ($('#dlg-theme')?.open) renderThemeList();
  hex.draw();
  core.draw();
  timelineGraph?.draw();
  if (save) savePref('theme', theme);
}

function renderThemeList() {
  const box = $('#theme-list');
  const current = document.documentElement.dataset.theme;
  box.innerHTML = THEMES.map(id => `
    <div class="theme-item${id === current ? ' is-on' : ''}" data-theme-id="${id}"
         role="option" aria-selected="${id === current}" tabindex="0">
      <span class="theme-swatch" data-swatch="${id}" aria-hidden="true"></span>
      <span class="theme-name">${esc(txt('ui.settings.theme_' + id))}</span>
      <span class="theme-check" aria-hidden="true">${id === current ? '✓' : ''}</span>
    </div>`).join('');
  $$('.theme-item', box).forEach(el => {
    el.addEventListener('click', () => {
      applyTheme(el.dataset.themeId);
      $('#dlg-theme').close();
    });
    el.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        applyTheme(el.dataset.themeId);
        $('#dlg-theme').close();
      }
    });
  });
}

function openThemeDialog() {
  const dlg = $('#dlg-theme');
  renderThemeList();
  dlg.showModal();
  $(`.theme-item.is-on`, dlg)?.focus();
}

function settingsDialog() {
  const dlg = $('#dlg-settings');
  const notify = (S.prefs && S.prefs.notify) || {};
  for (const ch of ['action', 'task', 'colleague']) {
    const box = $('#set-notify-' + ch);
    if (box) box.checked = notify[ch] !== false;
  }
  const theme = $('#set-theme');
  if (theme) theme.value = document.documentElement.dataset.theme || 'dark';
  const off = $('#set-offsets');
  if (off) off.value = offsetMode;
  const when = $('#set-time');
  if (when) when.value = timeDisplay;

  if (!dlg.dataset.wired) {
    dlg.dataset.wired = '1';
    for (const ch of ['action', 'task', 'colleague']) {
      $('#set-notify-' + ch)?.addEventListener('change', ev => {
        const now = { ...((S.prefs && S.prefs.notify) || {}),
                      [ch]: ev.target.checked };
        savePref('notify', now);
      });
    }
    $('#set-theme')?.addEventListener('change', ev =>
      applyTheme(ev.target.value));
    $('#set-offsets')?.addEventListener('change', ev =>
      setOffsetMode(ev.target.value));
    $('#set-time')?.addEventListener('change', ev =>
      setTimeDisplay(ev.target.value));
  }
  dlg.showModal();
}

function applyLayout(p) {
  const ws = $('#workspace');
  if (p.tree_width) ws.style.setProperty('--tree-w', p.tree_width + 'px');
  if (p.inspect_width) ws.style.setProperty('--inspect-w', p.inspect_width + 'px');
  if (p.preview_split) {
    $('.panel-hex').style.setProperty('--list-h', p.preview_split + 'px');
  }
  hex.resize();
  core.draw();
}

function initWorkspaceResize() {
  const ws = $('#workspace');
  [['tree', '--tree-w', 'tree_width', 1],
   ['inspect', '--inspect-w', 'inspect_width', -1]].forEach(
    ([which, varName, prefKey, sign]) => {
      const grip = document.createElement('div');
      grip.className = txt('ui.col_grip_col_grip', { which: which });
      grip.setAttribute('role', 'separator');
      grip.setAttribute('aria-orientation', 'vertical');
      grip.tabIndex = 0;
      grip.title = txt('ui.drag_resize_arrow_keys_also_work');
      $(`.panel-${which}`).appendChild(grip);

      const setW = px => {
        const clamped = Math.max(160, Math.min(720, Math.round(px)));
        ws.style.setProperty(varName, clamped + 'px');
        hex.resize();
        core.draw();
        savePref(prefKey, clamped);
      };
      let on = false;
      grip.addEventListener('mousedown', e => {
        on = true; grip.classList.add('is-dragging'); e.preventDefault();
      });
      window.addEventListener('mousemove', e => {
        if (!on) return;
        const box = ws.getBoundingClientRect();
        setW(sign > 0 ? e.clientX - box.left : box.right - e.clientX);
      });
      window.addEventListener('mouseup', () => {
        on = false; grip.classList.remove('is-dragging');
      });
      grip.addEventListener('keydown', e => {
        const d = { ArrowLeft: -20, ArrowRight: 20 }[e.key];
        if (!d) return;
        e.preventDefault();
        const cur = parseInt(
          getComputedStyle(ws).getPropertyValue(varName), 10) || 300;
        setW(cur + d * sign);
      });
    });
}

const PULSE_MS = 15000;
let pulseTimer = null;
let lastPulse = null;

function markPulse(p) {
  if (p) lastPulse = { bookmarks: p.bookmarks, tags: p.tags, audit: p.audit };
}

async function pulse() {
  if (!S.casePath) return;
  const p = await api.get('case/pulse').catch(() => null);
  if (!p || !p.open) return;
  const changed = !lastPulse
    || p.bookmarks !== lastPulse.bookmarks
    || p.tags !== lastPulse.tags
    || p.audit !== lastPulse.audit;
  if (!changed) return;

  const first = lastPulse === null;
  const added = first ? 0
    : (p.bookmarks - lastPulse.bookmarks) + (p.tags - lastPulse.tags);
  markPulse(p);
  if (first) return;

  await loadTags();
  await loadMarks();

  const mine = (examinerName() || '').toLowerCase();
  const who = (p.latest || '').trim();
  if (!who || who.toLowerCase() === mine) return;
  if (added > 0) {
    toast(txt('messages.colleague_added', { who, count: added }), 'colleague');
  }
}

function startPulse() {
  clearInterval(pulseTimer);
  lastPulse = null;
  pulse();
  pulseTimer = setInterval(pulse, PULSE_MS);
}

function stopPulse() {
  clearInterval(pulseTimer);
  pulseTimer = null;
  lastPulse = null;
}

async function relocateIndex(pending) {
  if (!pending) return;
  const t = await api.post('index/relocate', {}).catch(() => null);
  if (!t || t.error || t.nothing_to_do) return;
  const r = await awaitTask(t, txt('ui.index.moving'));
  if (r && r.moved) {
    toast(txt('messages.index_moved', { count: r.moved }), 'task');
  }
}

async function loadVersion() {
  const el = $('#app-version');
  if (!el) return;
  const r = await api.get('version').catch(() => null);
  if (!r || !r.version) return;
  el.textContent = r.version;
  el.title = txt('tooltips.app.version', { label: r.label });
  el.classList.toggle('stale', !!r.stale);
  if (r.stale) {
    el.textContent = txt('ui.version.stale', { version: r.version });
    el.title = txt('tooltips.app.version_stale');
    toast(txt('messages.version.stale'));
  }
}

async function loadPrefs() {
  let p = {};
  try {
    const r = await api.get('prefs');
    p = r.prefs || {};
  } catch {                                                         }
  S.prefs = p;
  offsetMode = p.offset_mode === 'logical' ? 'logical' : 'physical';
  timeDisplay = ['utc', 'local'].includes(p.time_display)
    ? p.time_display : 'both';
  const wants = p.theme
    || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  applyTheme(wants, { save: false });
  applyLayout(p);
  return p;
}

function commands() {
  const out = [];
  const tabName = t => t.textContent.trim().replace(/\s+\d+$/, '');
  const digits = $$('.modules .tab').filter(t => t.dataset.view !== 'cases');
  $$('.tab').forEach((t, i) => out.push({
    title: `Go to ${tabName(t)}`,
    hint: t.dataset.view === 'cases' ? 'Alt+0'
      : (digits.indexOf(t) >= 0 && digits.indexOf(t) < 9
          ? `Alt+${digits.indexOf(t) + 1}` : ''),
    keys: txt('ui.tab_view_panel_view', { view: t.dataset.view }),
    run: () => t.click(),
  }));

  out.push({
    title: `Switch to the ${
      ['light', 'paper'].includes(document.documentElement.dataset.theme)
        ? 'dark' : 'light'
    } theme`,
    keys: txt('messages.theme_dark_light_colour_color_appearance_contrast'),
    run: toggleTheme,
  });

  const has = sel => { const el = $(sel); return el && !el.hidden && !el.disabled; };
  const click = (sel, title, keys, hint) => {
    if (has(sel)) out.push({ title, keys, hint, run: () => $(sel).click() });
  };

  click('#btn-open', txt('ui.app.open'), txt('ui.open_image_e01_evidence'));
  click('#btn-add', txt('ui.add_another_exhibit_case'),
        txt('ui.add_evidence_exhibit_second_image_alongside'));
  click('#btn-case', txt('ui.open_saved_case'), txt('ui.case_open_load'));
  if (twoOffsetReadings()) {
    out.push({
      title: effectiveMode() === 'physical'
        ? (S.scope.file ? txt('ui.show_offsets_start_file')
                        : txt('ui.show_offsets_start_volume'))
        : txt('ui.show_offsets_start_image'),
      keys: txt('messages.offset_physical_logical_absolute_relative_volume_partition'),
      run: () => setOffsetMode(effectiveMode() === 'physical' ? 'logical' : 'physical'),
    });
  }
  click('#btn-report', txt('ui.write_examination_report'), txt('ui.report_write_export_html'));
  click('#btn-audit', txt('ui.show_audit_log'), txt('ui.audit_log_chain_integrity'));
  click('#btn-triage', txt('ui.refresh_triage_findings'), txt('ui.triage_findings_refresh'));
  click('#btn-filetypes', txt('ui.verify_file_types'), txt('messages.file_type_verify_mismatch_extension_signature'));
  click('#btn-registry', txt('ui.read_well_known_registry_keys'),
        txt('messages.registry_hive_usb_network_autorun_account_software'));
  click('#btn-index', txt('ui.build_content_index'), txt('ui.index_search_fts_content_build'));
  click('#btn-hash', txt('ui.hash_files'), txt('ui.hash_md5_sha1_sha256'));
  click('#stat-tz', txt('ui.timezone_time_display'), txt('ui.timezone_tz_utc_local_offset'));

  if (S.open) {
    out.push({
      title: 'Go to offset…',
      hint: 'Ctrl+G',
      keys: txt('ui.offset_goto_jump_address_seek_hex'),
      run: () => { $('#goto').focus(); $('#goto').select(); },
    });
    out.push({
      title: txt('ui.copy_current_offset'),
      keys: txt('ui.copy_offset_clipboard_address'),
      run: async () => {
        const v = '0x' + fmt.hex(S.cursor, 10);
        try {
          await navigator.clipboard.writeText(v);
          toast(txt('messages.toast.copied_v', { value: v }));
        } catch { toast(txt('messages.toast.current_offset_v', { offset: v })); }
      },
    });
    out.push({
      title: txt('ui.compare_second_offset_split_hex_view'),
      keys: txt('messages.split_compare_two_panes_side_side_diff'),
      run: () => toggleSplit(),
    });
  }

  out.push({
    title: txt('ui.show_keyboard_shortcuts'),
    hint: '?',
    keys: txt('ui.help_keyboard_shortcuts_keys_bindings'),
    run: () => $('#dlg-keys').showModal(),
  });
  out.push({
    title: txt('ui.reset_saved_layout_preferences'),
    keys: txt('ui.reset_preferences_layout_default_theme_width'),
    run: async () => {
      await api.post('prefs/reset', {});
      S.prefs = {};
      $('#workspace').style.removeProperty('--tree-w');
      $('#workspace').style.removeProperty('--inspect-w');
      applyTheme(matchMedia('(prefers-color-scheme: light)').matches
                 ? 'light' : 'dark', { save: false });
      toast(txt('messages.toast.layout_preferences_reset'));
    },
  });
  return out;
}

function substringScore(hay, q, base) {
  const at = hay.indexOf(q);
  if (at < 0) return 0;
  const wordStart = at === 0 || hay[at - 1] === ' ';
  return base + (wordStart ? 2000 : 0) + (at === 0 ? 500 : 0) - hay.length;
}

function paletteScore(cmd, q) {
  if (!q) return 1;
  const title = cmd.title.toLowerCase();
  const hay = title + ' ' + (cmd.keys || '').toLowerCase();

  const words = q.split(/\s+/).filter(Boolean);
  if (words.length > 1) {
    let total = 0;
    for (const w of words) {
      const s = substringScore(title, w, 20000)
             || substringScore(hay, w, 8000);
      if (!s) return 0;
      total += s;
    }
    return total;
  }

  const direct = substringScore(title, q, 200000)
              || substringScore(hay, q, 100000);
  if (direct) return direct;

  let i = 0, score = 0, prev = -1;
  for (const ch of q) {
    const at = hay.indexOf(ch, i);
    if (at < 0) return 0;
    if (at === 0 || hay[at - 1] === ' ') score += 6;
    else if (at === prev + 1) score += 3;
    else score += 1;
    prev = at;
    i = at + 1;
  }
  return score * 200 - hay.length;
}

let palItems = [], palAt = 0;

function palRender(q) {
  const box = $('#palette-list');
  palItems = commands()
    .map(c => ({ c, s: paletteScore(c, q.toLowerCase().trim()) }))
    .filter(x => x.s > 0)
    .sort((a, b) => b.s - a.s)
    .slice(0, 40)
    .map(x => x.c);
  palAt = 0;
  if (!palItems.length) {
    box.innerHTML = `<div class="pal-empty">${txt('ui.nothing_matches')}</div>`;
    return;
  }
  box.innerHTML = palItems.map((c, i) => `
    <div class="pal-item${i === 0 ? ' is-on' : ''}" data-i="${i}">
      <span class="pal-title">${esc(c.title)}</span>
      ${c.hint ? `<span class="pal-hint">${esc(c.hint)}</span>` : ''}
    </div>`).join('');
  $$('.pal-item', box).forEach(el => {
    el.addEventListener('mouseenter', () => palMove(+el.dataset.i, true));
    el.addEventListener('click', () => palRun());
  });
}

function palMove(to, absolute = false) {
  if (!palItems.length) return;
  palAt = absolute ? to
    : (palAt + to + palItems.length) % palItems.length;
  $$('.pal-item').forEach((el, i) => el.classList.toggle('is-on', i === palAt));
  $$('.pal-item')[palAt]?.scrollIntoView({ block: 'nearest' });
}

function palRun() {
  const cmd = palItems[palAt];
  if (!cmd) return;
  closePalette();
  setTimeout(() => cmd.run(), 0);
}

function openPalette() {
  const dlg = $('#dlg-palette');
  if (dlg.open) return;
  $('#palette-q').value = '';
  palRender('');
  dlg.showModal();
  $('#palette-q').focus();
}

function closePalette() {
  const dlg = $('#dlg-palette');
  if (dlg.open) dlg.close();
}

function initPalette() {
  $('#palette-q').addEventListener('input', e => palRender(e.target.value));
  $('#palette-q').addEventListener('keydown', e => {
    if (e.key === 'ArrowDown') { e.preventDefault(); palMove(1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); palMove(-1); }
    else if (e.key === 'Enter') { e.preventDefault(); palRun(); }
  });
}

function typing() {
  const el = document.activeElement;
  if (!el) return false;
  return el.matches('input, textarea, select, [contenteditable="true"]');
}

function initKeys() {
  window.addEventListener('keydown', e => {
    const mod = e.ctrlKey || e.metaKey;

    if (mod && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      return $('#dlg-palette').open ? closePalette() : openPalette();
    }
    if (mod && e.shiftKey && e.key.toLowerCase() === 'p') {
      e.preventDefault();
      return openPalette();
    }
    if (mod && e.key.toLowerCase() === 'g' && S.open) {
      e.preventDefault();
      $('#goto').focus(); $('#goto').select();
      return;
    }
    if (e.altKey && !mod && /^[0-9]$/.test(e.key)) {
      const tabs = $$('.modules .tab');
      const tab = e.key === '0'
        ? tabs.find(t => t.dataset.view === 'cases')
        : tabs.filter(t => t.dataset.view !== 'cases')[+e.key - 1];
      if (tab) { e.preventDefault(); tab.click(); tab.focus(); }
      return;
    }
    if (e.key === 'Escape' && !$('#dlg-palette').open) {
      if (document.activeElement === $('#goto')) $('#goto').blur();
      return;
    }
    if (typing() || mod || e.altKey) return;

    if (e.key === '?') { e.preventDefault(); $('#dlg-keys').showModal(); }
    else if (e.key === '/') {
      e.preventDefault();
      $('.tab[data-view="find"]')?.click();
      $('#find-terms')?.focus();
    }
  });
}

let hexB = null;

function toggleSplit(want) {
  const panel = $('.panel-hex');
  const on = want === undefined ? !panel.classList.contains('is-split') : want;
  panel.classList.toggle('is-split', on);
  $('#btn-split')?.classList.toggle('is-on', on);
  $('#btn-split')?.setAttribute('aria-pressed', String(on));
  if (on && !hexB) {
    hexB = new HexView($('#hex-b'), true);
    hexB.cur = S.cursor;
    hexB.scrollTo(S.cursor, { center: true });
    $('#btn-hex-b-here')?.addEventListener('click', () => {
      hexB.cur = S.cursor;
      hexB.scrollTo(S.cursor, { center: true });
      hexB.announce();
    });
    $('#btn-hex-b-swap')?.addEventListener('click', () => {
      const a = S.cursor;
      S.cursor = hexB.cur;
      hexB.cur = a;
      hex.reveal(S.cursor);
      hexB.scrollTo(hexB.cur, { center: true });
      updateStatus();
      hexB.announce();
    });
  }
  hex.resize();
  if (hexB) { hexB.resize(); hexB.announce(); }
  savePref('split_hex', on);
  return on;
}

const hex = new HexView($('#hex'));
const core = new CoreSample($('#core-canvas'));
const timelineGraph = new TimelineGraph($('#time-canvas'));

initPreviewPane();
initTray();
initColumnResize();
initWorkspaceResize();
initPalette();
initKeys();
initPicker();
initPlatformKeys();
initDialogClose();
$('#btn-who')?.addEventListener('click', openWho);
$('#dlg-who')?.addEventListener('close', () => {
  if ($('#dlg-who').returnValue !== 'ok') return;
  const n = $('#who-input').value.trim();
  if (n) setWho(n);
});
$('#btn-theme').addEventListener('click', openThemeDialog);
$('#btn-settings')?.addEventListener('click', () => settingsDialog());
$('#btn-palette').addEventListener('click', openPalette);
$('#btn-split').addEventListener('click', () => toggleSplit());
$('#stat-tz')?.addEventListener('click', () => tzDialog());
$('#btn-report')?.addEventListener('click', writeReport);
$('#btn-triage')?.addEventListener('click', loadTriage);
$('#btn-filetypes')?.addEventListener('click', runFileTypes);
$('#btn-registry')?.addEventListener('click', runRegistry);

$('#btn-open').addEventListener('click', () => openDialog());

$('#dlg-open').addEventListener('close', e => {
  const dlg = $('#dlg-open');
  const add = dlg.dataset.add === '1';
  dlg.dataset.add = '';
  if (dlg.returnValue !== 'ok') return;
  const p = $('#open-path').value.trim();
  const kind = openKind();
  const who = $('#open-examiner').value.trim() || examinerName() || '';
  if (who && who !== S.examiner) setWho(who);
  if (!p) return;
  openImage(p, who, add ? undefined : ($('#open-case').value.trim() || undefined),
            { add, kind });
});

$('#dlg-tag').addEventListener('close', async () => {
  if ($('#dlg-tag').returnValue !== 'ok') return;
  const entry = JSON.parse($('#dlg-tag').dataset.entry);
  const tag = $('#tag-custom').value.trim() || $('#tag-name').value;
  if (!tag) return toast(txt('messages.toast.tag_needs_name'));
  const r = await api.post('tag', { item: entry, tag,
                                    note: $('#tag-note').value.trim(),
                                    part: +$('#dlg-tag').dataset.part });
  if (r.error) return toast(r.error);

  const tech = $('#tag-attack')?.value || '';
  let attributed = null;
  if (tech) {
    const t = (attackState.catalogue?.techniques || [])
      .find(x => x.id === tech);
    const a = await api.post('attack/tag', {
      part: +$('#dlg-tag').dataset.part,
      target_kind: 'file',
      target_ref: String(entry.mft ?? entry.inode ?? entry.oid
                         ?? entry.start_cluster ?? entry.path ?? entry.name),
      technique: tech, technique_name: t?.name, tactic: t?.tactic,
      note: $('#tag-note').value.trim(), asserted: true,
      catalogue: attackState.catalogue?.version,
    });
    if (a.error) toast(a.error);
    else {
      attackState.tags = a.tags || [];
      attackState.summary = a.summary || [];
      attributed = tech;
      renderAttackTactics();
      renderAttackList();
    }
  }

  await loadTags();
  await loadSavedSearches();
  await loadHashSets();
  await refreshIndexState();
  pollTasks();
  renderTagStrip(entry);
  toast(`Tagged "${entry.name}" as ${tag}`
        + (attributed ? txt('messages.attributed_attributed', { attributed: attributed }) : '.'));
});

$('#tag-filter').addEventListener('change', renderTags);

$('#btn-index').addEventListener('click', buildIndex);
$('#btn-index-clear').addEventListener('click', async () => {
  const partVal = $('#find-scope').value;
  await api.post('index/clear', { part: partVal === '' ? null : +partVal });
  await refreshIndexState();
  pollTasks();
  toast(txt('messages.index_cleared'));
});
$('#find-scope').addEventListener('change', refreshIndexState);
$('#btn-save-search').addEventListener('click', saveCurrentSearch);
$('#btn-hash').addEventListener('click', doHash);
$('#btn-duplicates').addEventListener('click', doDuplicates);
$('#btn-similar').addEventListener('click', doSimilar);
$('#btn-artifacts').addEventListener('click', () => doArtifacts(true));
$('#art-scope')?.addEventListener('change', () => { artPick = null; renderArtTree(); });

$$('.dv-mode[data-art]').forEach(el => el.addEventListener('click', () => {
  artMode = el.dataset.art;
  $$('.dv-mode[data-art]').forEach(b => b.classList.toggle('is-on', b === el));
  const partVal = $('#art-scope').value;
  if (partVal !== '' && showCachedArtefact(artMode, +partVal)) return;
  $('#art-results').innerHTML = `<p class="empty">${txt('ui.core.press_examine')}</p>`;
}));

$('#btn-hs-import').addEventListener('click', async () => {
  const path = $('#hs-path').value.trim();
  if (!path) return toast(txt('messages.point_hash_list_file'));
  const r = await api.post('hashset/import', {
    path, name: $('#hs-name').value.trim() || null, kind: $('#hs-kind').value });
  if (r.error) return toast(r.error);
  await loadHashSets();
  toast(txt('messages.imported_entries_hashes_name', { entries: r.entries.toLocaleString(), name: r.name }));
});

$('#btn-tag-export').addEventListener('click', async () => {
  const filter = $('#tag-filter').value;
  const items = filter ? S.tags.filter(t => t.tag === filter) : S.tags;
  if (!items.length) return toast(txt('messages.toast.nothing_tagged_export'));
  let ok = 0, failed = 0;
  busy.open(txt('ui.exporting_tagged_items'), `${items.length} item(s)`);
  try {
    for (let i = 0; i < items.length; i++) {
      busy.set(i / items.length);
      const t = items[i];
      if (t.is_dir) continue;
      const r = await api.post('export/file', { part: t.part, node: t.node,
                                                name: t.name, path: t.path,
                                                size: t.size, deleted: !!t.deleted,
                                                contiguous: !!t.contiguous,
                                                modified: t.modified,
                                                accessed: t.accessed,
                                                created: t.file_created });
      if (r.error) failed++; else ok++;
    }
  } finally { busy.close(); }
  toast(`Exported ${ok} item(s)${failed ? `, ${failed} failed` : ''}.`);
});

$('#btn-case').addEventListener('click', caseDialog);
$('#dlg-case').addEventListener('close', () => {
  if ($('#dlg-case').returnValue !== 'ok') return;
  const p = $('#case-path').value.trim();
  if (p) openCase(p, $('#case-examiner').value.trim());
});
$('#case-path').addEventListener('change', () => peekCase($('#case-path').value.trim()));

$('#btn-carve').addEventListener('click', doCarve);
$('#carve-types')?.addEventListener('change', ev => {
  const el = ev.target;
  const off = carveOff();
  if (el.dataset.ext) {
    if (el.checked) off.delete(el.dataset.ext); else off.add(el.dataset.ext);
  } else if (el.dataset.catCheck && S.carveTypes) {
    for (const t of S.carveTypes.types) {
      if (t.category !== el.dataset.catCheck) continue;
      if (el.checked) off.delete(t.ext); else off.add(t.ext);
    }
  } else {
    return;
  }
  savePref('carve_types_off', [...off].sort());
  renderCarvePick();
});
$('#carve-all')?.addEventListener('click', () => setAllCarve(true));
$('#carve-none')?.addEventListener('click', () => setAllCarve(false));
$('#carve-add-sig')?.addEventListener('click', () => editCarveSignature(null));
$('#carve-custom')?.addEventListener('change', ev => {
  const id = ev.target.dataset.sig;
  if (!id) return;
  savePref('carve_signatures', carveSignatures().map(s =>
    (s.id === id ? { ...s, on: ev.target.checked } : s)));
  carvePickSummary();
});
$('#carve-custom')?.addEventListener('click', ev => {
  const edit = ev.target.closest('[data-edit]');
  const del = ev.target.closest('[data-del]');
  if (edit) {
    const s = carveSignatures().find(x => x.id === edit.dataset.edit);
    if (s) editCarveSignature(s);
  } else if (del) {
    const s = carveSignatures().find(x => x.id === del.dataset.del);
    if (!s) return;
    savePref('carve_signatures', carveSignatures().filter(x => x.id !== s.id));
    renderCarvePick();
    toast(txt('messages.carve.signature_removed', { name: s.name }), 'action');
  }
});
{
  const form = $('#dlg-carve-sig form');
  form?.addEventListener('input', explainSignature);
  form?.addEventListener('change', explainSignature);
}
$('#btn-timeline').addEventListener('click', doTimeline);
$('#btn-find').addEventListener('click', doFind);
$('#find-terms').addEventListener('keydown', e => {
  if (e.key === 'Enter') { e.preventDefault(); doFind(); }
});

$('#goto').addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  e.preventDefault();
  const v = $('#goto').value.trim();
  const n = /^0x/i.test(v) ? parseInt(v, 16)
    : /^[0-9a-f]+$/i.test(v) && /[a-f]/i.test(v) ? parseInt(v, 16) : parseInt(v, 10);
  if (Number.isFinite(n)) {
    S.cursor = hex.clamp(n);
    hex.reveal(S.cursor);
    updateStatus();
  }
});

let markCat = '';

function renderMarkCats() {
  const box = $('#mark-cats');
  box.innerHTML = S.markCats.map(c => `
    <button type="button" class="cat${c.name === markCat ? ' is-on' : ''}"
            data-cat="${esc(c.name)}" style="--mk:${esc(c.colour)}">
      <span class="mk-dot" aria-hidden="true"></span>${esc(c.name)}
    </button>`).join('')
    + `<button type="button" class="cat${markCat ? '' : ' is-on'}"
               data-cat="">${txt('ui.fill_attack_picker.none')}</button>`;
  $$('.cat', box).forEach(el => el.addEventListener('click', () => {
    markCat = el.dataset.cat;
    renderMarkCats();
  }));
}

$('#btn-mark').addEventListener('click', async () => {
  if (!S.open) return;
  const sel = S.selection || { start: S.cursor, length: 1 };
  $('#mark-range').textContent =
    `0x${fmt.hex(sel.start, 10)} · ${sel.length} byte(s)`;
  await loadMarkCategories();
  renderMarkCats();
  $('#dlg-mark').showModal();
  $('#dlg-mark').dataset.sel = JSON.stringify(sel);
});

$('#dlg-mark').addEventListener('close', () => {
  if ($('#dlg-mark').returnValue !== 'ok') return;
  const sel = JSON.parse($('#dlg-mark').dataset.sel);
  saveMark(S.scope.file ? sel.start : sel.start + (S.scope.part || 0),
           sel.length,
           $('#mark-label').value || 'mark', 'manual', $('#mark-note').value,
           markCat, $('#mark-in-report').checked, markFrame());
  $('#mark-label').value = ''; $('#mark-note').value = '';
  $('#mark-in-report').checked = true;
  markCat = '';
});

$('#mark-filter').addEventListener('change', renderMarks);
$('#mark-report-filter').addEventListener('change', renderMarks);

$('#btn-audit').addEventListener('click', async () => {
  const r = await api.get('audit');
  $('#audit-state').innerHTML = r.integrity.intact
    ? txt('messages.hash_chain_intact_across_all_entries')
    : `<strong style="color:var(--alarm)">${txt('ui.chain_broken_entry_broken', { broken_at: r.integrity.broken_at })}</strong> The log has been altered since it
        was written.`;
  $('#audit-body').innerHTML = r.entries.map(e => `
    <div class="entry">
      <span class="when">${e.at}</span>
      <span class="what">${e.action}</span>
      <span class="detail">${esc(e.detail || '')}</span>
    </div>`).join('');
  $('#dlg-audit').showModal();
});

const VIEW_HOME = new WeakMap();

function revealViewer() {
  const panel = $('.panel-hex');
  if (!panel.classList.contains('no-viewer')) return;
  panel.classList.remove('no-viewer');
  panel.classList.add('viewer-borrowed');
  hex.resize();
  syncBytesButton();
}

function hideViewer() {
  const panel = $('.panel-hex');
  if (!panel.classList.contains('viewer-borrowed')) return;
  panel.classList.remove('viewer-borrowed');
  panel.classList.add('no-viewer');
  syncBytesButton();
}

function syncBytesButton() {
  const b = $('#btn-time-bytes');
  if (!b) return;
  b.textContent = txt($('.panel-hex').classList.contains('viewer-borrowed')
    ? 'ui.timeline.back_to_timeline' : 'ui.timeline.show_bytes');
}

function setModule(view) {
  const tab = $(`.modules .tab[data-view="${view}"]`);
  const el = $(`.view[data-view="${view}"]`);
  if (!tab || !el) return;

  $$('.modules .tab').forEach(t => {
    const on = t.dataset.view === view;
    t.classList.toggle('is-on', on);
    t.setAttribute('aria-selected', String(on));
  });

  const host = $('#mod-main');
  const mine = el.querySelector(':scope > .view-main')
    || $$('#mod-main > .view-main').find(m => VIEW_HOME.get(m) === el)
    || null;
  $$('#mod-main > .view-main').forEach(m => {
    if (m === mine) return;
    const home = VIEW_HOME.get(m);
    if (home) home.append(m);
  });
  if (mine) {
    if (!VIEW_HOME.has(mine)) VIEW_HOME.set(mine, mine.parentElement);
    if (mine.parentElement !== host) host.append(mine);
  }
  host.hidden = !mine;

  $('#filelist').hidden = view !== 'sources';
  $('.panel-hex').classList.toggle('mod-mode', view !== 'sources');
  $('.panel-hex').classList.toggle('no-viewer', tab.hasAttribute('data-no-viewer'));
  $('.panel-hex').classList.remove('viewer-borrowed');
  syncBytesButton();

  $$('.view').forEach(v => v.classList.remove('is-on'));
  el.classList.add('is-on');

  if (S.scopeView !== view) {
    if (view === 'sources' && S.lastPick) {
      const pick = S.lastPick;
      if (pick.kind === 'partition') selectPartition(pick.ev, pick.p);
      else showEntry(pick.e, pick.part, pick.from, pick.stream);
    } else if (S.scopeView) {
      clearViewer();
    }
  }

  if (view === 'sources') core.draw();
  if (view === 'cases') renderCases();
  if (view === 'time') loadStoredTimeline();
  hex.resize();
}

$$('.modules .tab').forEach(tab =>
  tab.addEventListener('click', () => setModule(tab.dataset.view)));

(async function init() {
  const p = await loadPrefs();
  loadVersion();
  loadCarveTypes();
  hex.resize();
  loadWho();
  const st = await api.get('state');
  if (st.open) {
    applyOpened(st);
    if (p.split_hex) toggleSplit(true);
    await loadMarks();
    await loadTags();
    await loadSavedSearches();
    await loadHashSets();
    await refreshIndexState();
    pollTasks();
  } else if (st.case) {
    applyEmptyCase(st);
    await loadWho();
  } else {
    renderTree();
    setModule('cases');
  }
})();
