// Created by: Aman Kumar Panda
// Dashboard charts (Chart.js, loaded locally - works offline).
(function () {
  var data = JSON.parse(document.getElementById('chart-data').textContent);
  var css = getComputedStyle(document.documentElement);
  var v = function (n) { return css.getPropertyValue(n).trim(); };
  var muted = v('--muted'), line = v('--line');
  var still = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  Chart.defaults.color = muted;
  Chart.defaults.borderColor = line;
  Chart.defaults.font.family = v('--sans');
  Chart.defaults.animation = still ? false : { duration: 600 };
  Chart.defaults.plugins.legend.labels.boxWidth = 10;
  Chart.defaults.plugins.legend.labels.usePointStyle = true;

  var SRC = { 'Event Log': v('--src-event-log'), 'Browser': v('--src-browser'), 'USB': v('--src-usb'),
              'File Log': v('--src-file-log'), 'Login Log': v('--src-login-log') };
  var LEVEL = { None: v('--tone-success'), Low: v('--sev-low'), Medium: v('--sev-medium'),
                High: v('--sev-high'), Critical: v('--sev-critical') };

  // risk gauge (half doughnut)
  var g = document.getElementById('gauge');
  if (g) {
    new Chart(g, { type: 'doughnut',
      data: { datasets: [{ data: [data.risk, 100 - data.risk], borderWidth: 0,
                           backgroundColor: [LEVEL[data.level] || v('--cyan'), v('--panel-3')] }] },
      options: { rotation: -90, circumference: 180, cutout: '78%', aspectRatio: 2,
                 plugins: { legend: { display: false }, tooltip: { enabled: false } } } });
  }

  // activity over time, stacked by evidence source
  var a = document.getElementById('activity');
  if (a) {
    new Chart(a, { type: 'bar',
      data: { labels: data.activity.labels,
              datasets: data.activity.datasets.map(function (d) {
                return { label: d.source, data: d.data, backgroundColor: SRC[d.source] || muted, borderRadius: 2, borderSkipped: false };
              }) },
      options: { maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
                 scales: { x: { stacked: true, grid: { display: false }, ticks: { maxRotation: 55, autoSkip: true, maxTicksLimit: 16 } },
                           y: { stacked: true, beginAtZero: true, ticks: { precision: 0 }, title: { display: true, text: 'events' } } },
                 plugins: { legend: { position: 'bottom' } } } });
  }

  // source mix
  var s = document.getElementById('sources');
  if (s) {
    new Chart(s, { type: 'doughnut',
      data: { labels: data.sources.map(function (d) { return d.source; }),
              datasets: [{ data: data.sources.map(function (d) { return d.count; }), borderColor: v('--panel'), borderWidth: 2,
                           backgroundColor: data.sources.map(function (d) { return SRC[d.source] || muted; }) }] },
      options: { maintainAspectRatio: false, cutout: '62%', plugins: { legend: { position: 'right' } } } });
  }

  // events per account
  var u = document.getElementById('users');
  if (u) {
    new Chart(u, { type: 'bar',
      data: { labels: data.users.map(function (d) { return d.user; }),
              datasets: [{ data: data.users.map(function (d) { return d.count; }), backgroundColor: v('--cyan'), borderRadius: 3 }] },
      options: { indexAxis: 'y', maintainAspectRatio: false,
                 scales: { x: { beginAtZero: true, ticks: { precision: 0 } }, y: { grid: { display: false } } },
                 plugins: { legend: { display: false } } } });
  }
})();
