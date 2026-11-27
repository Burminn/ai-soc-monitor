/* linechart.js — minimalny wykres liniowy na <canvas>.
 * Zastępuje Chart.js ładowany z CDN bez przypiętej wersji i bez SRI:
 * na pulpicie bezpieczeństwa nie powinno być zewnętrznego kodu JS,
 * a dzięki temu CSP może blokować wszystkie obce skrypty. */
(function () {
  'use strict';

  var MONO = '10px "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';

  function niceMax(v) {
    if (v <= 5) return 5;
    var p = Math.pow(10, Math.floor(Math.log10(v)));
    var f = v / p;
    return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
  }

  function curve(ctx, pts, top, bottom) {
    var k = 0.35 / 3;
    var clampY = function (y) { return Math.min(Math.max(y, top), bottom); };
    ctx.moveTo(pts[0].x, pts[0].y);
    for (var i = 0; i < pts.length - 1; i++) {
      var p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
      ctx.bezierCurveTo(
        p1.x + (p2.x - p0.x) * k, clampY(p1.y + (p2.y - p0.y) * k),
        p2.x - (p3.x - p1.x) * k, clampY(p2.y - (p3.y - p1.y) * k),
        p2.x, p2.y
      );
    }
  }

  function draw(canvas, labels, values, opts) {
    opts = opts || {};
    var dpr = window.devicePixelRatio || 1;
    var height = 140;
    canvas.style.width = '100%';
    canvas.style.height = height + 'px';
    var width = canvas.getBoundingClientRect().width || 300;
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);

    var ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);

    var left = 34, right = 8, top = 8, bottom = height - 22;
    var plotW = Math.max(width - left - right, 10), plotH = bottom - top;
    var max = niceMax(Math.max.apply(null, values.concat([1])));

    ctx.font = MONO;
    ctx.fillStyle = '#7c8aa5';
    ctx.strokeStyle = '#1c2740';
    ctx.lineWidth = 1;
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (var t = 0; t <= 4; t++) {
      var y = bottom - plotH * t / 4;
      ctx.beginPath(); ctx.moveTo(left, y + 0.5); ctx.lineTo(width - right, y + 0.5); ctx.stroke();
      ctx.fillText(String(Math.round(max * t / 4)), left - 6, y);
    }

    var n = values.length;
    var pts = values.map(function (v, i) {
      return { x: left + (n === 1 ? plotW / 2 : plotW * i / (n - 1)), y: bottom - plotH * v / max };
    });

    // etykiety osi X (rzadziej, żeby się nie nakładały)
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    var every = Math.max(1, Math.ceil(n / 6));
    for (var i = 0; i < n; i += every) {
      ctx.fillText(String(labels[i]).slice(5), pts[i].x, bottom + 6);
    }

    if (n > 0) {
      ctx.beginPath();
      if (n === 1) { ctx.moveTo(pts[0].x, pts[0].y); ctx.lineTo(pts[0].x, pts[0].y); }
      else { curve(ctx, pts, top, bottom); }
      ctx.strokeStyle = '#22d3ee';
      ctx.lineWidth = 2;
      ctx.stroke();

      if (n > 1) {
        ctx.lineTo(pts[n - 1].x, bottom);
        ctx.lineTo(pts[0].x, bottom);
        ctx.closePath();
        ctx.fillStyle = 'rgba(34,211,238,0.12)';
        ctx.fill();
      }

      ctx.fillStyle = '#22d3ee';
      pts.forEach(function (p) { ctx.beginPath(); ctx.arc(p.x, p.y, 2, 0, Math.PI * 2); ctx.fill(); });
    }

    // tooltip: najbliższy punkt w poziomie
    canvas.__lc = { pts: pts, labels: labels, values: values, onHover: opts.onHover };
    if (!canvas.__lcBound) {
      canvas.__lcBound = true;
      canvas.addEventListener('mousemove', function (e) {
        var s = canvas.__lc;
        if (!s || !s.pts.length || !s.onHover) return;
        var x = e.clientX - canvas.getBoundingClientRect().left, best = 0;
        s.pts.forEach(function (p, i) { if (Math.abs(p.x - x) < Math.abs(s.pts[best].x - x)) best = i; });
        s.onHover(s.labels[best], s.values[best], e);
      });
      canvas.addEventListener('mouseleave', function () {
        var s = canvas.__lc;
        if (s && s.onHover) s.onHover(null, null, null);
      });
    }
  }

  window.LineChart = { draw: draw };
})();
