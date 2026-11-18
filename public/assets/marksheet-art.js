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

  /** Soft pastel security wave background; palette 'verify' shifts from emerald to slate/teal */
  function guillocheBG(seed, palette) {
    const W = 188, H = 250;
    const c1 = palette === 'verify' ? '#0ea5e9' : '#34d399';
    const c2 = palette === 'verify' ? '#14b8a6' : '#eab308';
    const op1 = palette === 'verify' ? '0.11' : '0.16';
    const op2 = palette === 'verify' ? '0.10' : '0.13';
    let p = '';
    for (let i = 0; i < 34; i++) {
      const y0 = 6 + i * 7.2, ph = i * 0.55 + (seed % 7), A = 1.8 + (i % 3) * 0.35;
      let d = '';
      for (let x = 0; x <= W; x += 2) {
        d += (x ? 'L' : 'M') + x.toFixed(1) + ',' + (y0 + A * Math.sin(x / 11 + ph) + 0.8 * Math.sin(x / 4.2 + ph * 2)).toFixed(2);
      }
      p += `<path d="${d}" fill="none" stroke="${c1}" stroke-width="0.09" opacity="${op1}"/>`;
    }
    for (let i = 0; i < 28; i++) {
      const x0 = 4 + i * 6.8, ph = i * 0.65 + (seed % 5);
      let d = '';
      for (let y = 0; y <= H; y += 2.5) {
        d += (y ? 'L' : 'M') + (x0 + 1.4 * Math.sin(y / 13 + ph)).toFixed(2) + ',' + y.toFixed(1);
      }
      p += `<path d="${d}" fill="none" stroke="${c2}" stroke-width="0.07" opacity="${op2}"/>`;
    }
    return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" width="100%" height="100%">${p}</svg>`;
  }

  function sealSVG(docId, labelText, centerText, accentColor) {
    const topLabel = labelText || 'RESULTSNIPER BD ★ DIGITALLY VERIFIED ★ AUTHENTIC RECORD ★';
    const midWord = centerText || 'VERIFIED';
    const ink = accentColor || '#065f46';
    const fillBg = accentColor ? 'rgba(240,253,250,0.75)' : 'rgba(236,253,245,0.65)';
    const uid = 'seal_' + Math.random().toString(36).slice(2, 7);
    return `<svg viewBox="0 0 120 120" width="25mm" height="25mm" style="display:block;margin:0 auto">
      <defs><path id="${uid}" d="M60,16 a44,44 0 1,1 -0.1,0"/></defs>
      <circle cx="60" cy="60" r="57" fill="${fillBg}" stroke="#065f46" stroke-width="1.35" style="stroke:${ink}"/>
      <circle cx="60" cy="60" r="52.5" fill="none" stroke="#d97706" stroke-width="0.55" stroke-dasharray="1.6 1.2"/>
      <text font-size="6.5" font-weight="800" fill="${ink}" font-family="Inter,Arial"><textPath href="#${uid}" textLength="264" lengthAdjust="spacing">${esc(topLabel)}</textPath></text>
      <g transform="translate(26,26)">${rosetteSVG(68, accentColor ? '#0d9488' : '#10b981').replace('<svg ', '<svg width="68" height="68" ')}</g>
      <circle cx="60" cy="60" r="21" fill="#fffefa" stroke="${ink}" stroke-width="0.75"/>
      <text x="60" y="57.5" text-anchor="middle" font-size="7.6" font-weight="900" fill="${ink}" font-family="Inter,Arial">${esc(midWord)}</text>
      <text x="60" y="66.5" text-anchor="middle" font-size="4.8" font-weight="700" fill="#b45309" font-family="JetBrains Mono,monospace">${esc(docId)}</text>
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
