(function () {
  function esc(v) {
    return String(v ?? '').replace(/[&<>"']/g, c => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }

  function spiro(cx, cy, R, r, d, n = 600) {
    const k = (R + r) / r;
    let p = '';
    for (let i = 0; i <= n; i++) {
      const t = (i / n) * Math.PI * 2;
      const x = cx + (R + r) * Math.cos(t) - d * Math.cos(k * t);
      const y = cy + (R + r) * Math.sin(t) - d * Math.sin(k * t);
      p += (i ? 'L' : 'M') + x.toFixed(2) + ',' + y.toFixed(2);
    }
    return p + 'Z';
  }

  function rosetteSVG(size, stroke, gradId) {
    const c = size / 2, s = size;
    const paths = [
      spiro(c, c, s * 0.30, s * 0.05, s * 0.13),
      spiro(c, c, s * 0.25, s * 0.043, s * 0.16),
      spiro(c, c, s * 0.17, s * 0.036, s * 0.11),
      spiro(c, c, s * 0.09, s * 0.024, s * 0.06),
    ];
    const grad = gradId
      ? `<defs><linearGradient id="${gradId}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#34d399"/><stop offset=".5" stop-color="#60a5fa"/><stop offset="1" stop-color="#eab308"/></linearGradient></defs>`
      : '';
    return `<svg viewBox="0 0 ${s} ${s}" width="100%" height="100%">${grad}${paths
      .map((p, i) => `<path d="${p}" fill="none" stroke="${gradId ? `url(#${gradId})` : stroke}" stroke-width="${i === 0 ? 0.25 : 0.18}" opacity="${0.48 - i * 0.08}"/>`)
      .join('')}</svg>`;
  }

  /** Soft, light pastel security wave background — gentle tint that keeps text razor sharp */
  function guillocheBG(seed) {
    const W = 188, H = 250;
    let p = '';
    for (let i = 0; i < 34; i++) {
      const y0 = 6 + i * 7.2, ph = i * 0.55 + (seed % 7), A = 1.8 + (i % 3) * 0.35;
      let d = '';
      for (let x = 0; x <= W; x += 2) {
        d += (x ? 'L' : 'M') + x.toFixed(1) + ',' + (y0 + A * Math.sin(x / 11 + ph) + 0.8 * Math.sin(x / 4.2 + ph * 2)).toFixed(2);
      }
      p += `<path d="${d}" fill="none" stroke="#34d399" stroke-width="0.09" opacity="0.16"/>`;
    }
    for (let i = 0; i < 28; i++) {
      const x0 = 4 + i * 6.8, ph = i * 0.65 + (seed % 5);
      let d = '';
      for (let y = 0; y <= H; y += 2.5) {
        d += (y ? 'L' : 'M') + (x0 + 1.4 * Math.sin(y / 13 + ph)).toFixed(2) + ',' + y.toFixed(1);
      }
      p += `<path d="${d}" fill="none" stroke="#eab308" stroke-width="0.07" opacity="0.13"/>`;
    }
    return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" width="100%" height="100%">${p}</svg>`;
  }

  function sealSVG(docId, labelText) {
    const topLabel = labelText || 'RESULTSNIPER BD • DIGITALLY VERIFIED • QR AUTHENTIC •';
    const uid = 'seal_' + Math.random().toString(36).slice(2, 7);
    return `<svg viewBox="0 0 120 120" width="27mm" height="27mm">
      <defs><path id="${uid}" d="M60,60 m-44,0 a44,44 0 1,1 88,0 a44,44 0 1,1 -88,0"/></defs>
      <circle cx="60" cy="60" r="57" fill="rgba(236,253,245,0.6)" stroke="#065f46" stroke-width="1.4"/>
      <circle cx="60" cy="60" r="52.5" fill="none" stroke="#d97706" stroke-width="0.5" stroke-dasharray="1.5 1.2"/>
      <text font-size="7.1" font-weight="800" letter-spacing="1.25" fill="#065f46" font-family="Inter,Arial"><textPath href="#${uid}">${esc(topLabel)}</textPath></text>
      <g transform="translate(26,26)">${rosetteSVG(68, '#10b981').replace('<svg ', '<svg width="68" height="68" ')}</g>
      <circle cx="60" cy="60" r="21" fill="#fffefa" stroke="#065f46" stroke-width="0.7"/>
      <text x="60" y="57" text-anchor="middle" font-size="8.2" font-weight="900" fill="#065f46" font-family="Inter,Arial">VERIFIED</text>
      <text x="60" y="66" text-anchor="middle" font-size="5" font-weight="700" fill="#b45309" font-family="JetBrains Mono,monospace">${esc(docId)}</text>
    </svg>`;
  }

  function qrSVG(text) {
    try {
      const q = qrcode(0, 'M');
      q.addData(text);
      q.make();
      return q.createSvgTag({ cellSize: 2, margin: 1, scalable: true });
    } catch (e) {
      return '<div style="font-size:8px">QR error</div>';
    }
  }

  window.RS_ART = { esc, rosetteSVG, guillocheBG, sealSVG, qrSVG };
})();
