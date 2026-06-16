(function () {
  "use strict";

  const palette = {
    critical: "#D92D20",
    high: "#E35D12",
    medium: "#B7791F",
    low: "#0077B6",
    info: "#6956C7",
    text: "#526079",
    grid: "#D8E1EC",
    cyan: "#0F766E",
    violet: "#6956C7"
  };
  const charts = {};

  function defaults() {
    if (!window.Chart) return;
    Chart.defaults.color = palette.text;
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.borderColor = palette.grid;
    Chart.defaults.plugins.legend.labels.boxWidth = 10;
  }

  function commonOptions() {
    return {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: { labels: { color: palette.text } },
        tooltip: {
          backgroundColor: "#FFFFFF",
          borderColor: palette.grid,
          borderWidth: 1,
          titleColor: "#1E293B",
          bodyColor: palette.text
        }
      },
      scales: {
        x: { ticks: { color: palette.text }, grid: { color: palette.grid } },
        y: { ticks: { color: palette.text }, grid: { color: palette.grid }, beginAtZero: true }
      }
    };
  }

  function initializeCharts() {
    if (!window.Chart || charts.severity) return;
    defaults();
    const severityCanvas = document.getElementById("severity-chart");
    const vulnerabilityCanvas = document.getElementById("vulnerability-chart");
    const trendCanvas = document.getElementById("trend-chart");
    const owaspCanvas = document.getElementById("owasp-chart");
    if (!severityCanvas || !vulnerabilityCanvas || !trendCanvas || !owaspCanvas) return;

    charts.severity = new Chart(severityCanvas, {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low", "Info"],
        datasets: [{
          data: [0, 0, 0, 0, 0],
          backgroundColor: [palette.critical, palette.high, palette.medium, palette.low, palette.info],
          borderColor: "#FFFFFF",
          borderWidth: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "68%",
        animation: false,
        plugins: { legend: { position: "bottom", labels: { color: palette.text, padding: 14, boxWidth: 9 } } }
      }
    });

    const barOptions = commonOptions();
    barOptions.plugins.legend.display = false;
    barOptions.scales.x.ticks.maxRotation = 0;
    charts.vulnerabilities = new Chart(vulnerabilityCanvas, {
      type: "bar",
      data: { labels: [], datasets: [{ data: [], backgroundColor: palette.cyan, hoverBackgroundColor: palette.violet, borderWidth: 0 }] },
      options: barOptions
    });

    const trendOptions = commonOptions();
    trendOptions.plugins.legend.display = false;
    charts.trend = new Chart(trendCanvas, {
      type: "line",
      data: {
        labels: [],
        datasets: [{
          data: [],
          borderColor: palette.cyan,
          backgroundColor: "rgba(15,118,110,0.08)",
          fill: true,
          tension: 0.3,
          pointRadius: 2,
          pointBackgroundColor: palette.cyan
        }]
      },
      options: trendOptions
    });

    const gradient = owaspCanvas.getContext("2d").createLinearGradient(0, 0, owaspCanvas.width || 500, 0);
    gradient.addColorStop(0, palette.violet);
    gradient.addColorStop(1, palette.cyan);
    const owaspOptions = commonOptions();
    owaspOptions.indexAxis = "y";
    owaspOptions.plugins.legend.display = false;
    charts.owasp = new Chart(owaspCanvas, {
      type: "bar",
      data: { labels: [], datasets: [{ data: [], backgroundColor: gradient, borderWidth: 0 }] },
      options: owaspOptions
    });
  }

  function updateCharts(stats) {
    initializeCharts();
    if (!charts.severity) return;
    charts.severity.data.datasets[0].data = [
      stats.critical_count || 0,
      stats.high_count || 0,
      stats.medium_count || 0,
      stats.low_count || 0,
      stats.info_count || 0
    ];
    charts.severity.update("none");

    const top = stats.top_vulnerability_types || [];
    charts.vulnerabilities.data.labels = top.map(item => item.title.length > 28 ? `${item.title.slice(0, 27)}…` : item.title);
    charts.vulnerabilities.data.datasets[0].data = top.map(item => item.count);
    charts.vulnerabilities.update("none");

    const trend = stats.findings_trend || [];
    charts.trend.data.labels = trend.map(item => item.date.slice(5));
    charts.trend.data.datasets[0].data = trend.map(item => item.count);
    charts.trend.update("none");

    const owasp = stats.owasp_breakdown || [];
    charts.owasp.data.labels = owasp.map(item => item.category.split(" ")[0]);
    charts.owasp.data.datasets[0].data = owasp.map(item => item.count);
    charts.owasp.update("none");
  }

  window.BugHunterCharts = { initializeCharts, updateCharts };
})();
