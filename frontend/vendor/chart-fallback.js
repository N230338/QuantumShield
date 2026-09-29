/* Small local canvas-chart fallback used only when the pinned Chart.js CDN is unavailable. */
(() => {
  if (window.Chart) return;

  class LocalChartFallback {
    constructor(canvas, config) {
      this.canvas = canvas;
      this.context = canvas.getContext("2d");
      this.config = config;
      this.render();
    }

    destroy() {
      this.context.clearRect(0, 0, this.canvas.width, this.canvas.height);
    }

    render() {
      const context = this.context;
      const canvas = this.canvas;
      const ratio = window.devicePixelRatio || 1;
      const bounds = canvas.getBoundingClientRect();
      canvas.width = Math.max(300, bounds.width * ratio);
      canvas.height = Math.max(180, bounds.height * ratio);
      context.scale(ratio, ratio);
      const width = canvas.width / ratio;
      const height = canvas.height / ratio;
      const pad = { left: 38, right: 12, top: 12, bottom: 28 };
      const values = this.config.data.datasets.flatMap((dataset) => dataset.data.filter(Number.isFinite));
      const maximum = Math.max(1, ...values);
      const labels = this.config.data.labels || [];
      const chartWidth = width - pad.left - pad.right;
      const chartHeight = height - pad.top - pad.bottom;

      context.font = "11px system-ui";
      context.strokeStyle = "#354345";
      context.fillStyle = "#91a3a2";
      context.lineWidth = 1;
      for (let tick = 0; tick <= 4; tick += 1) {
        const y = pad.top + (chartHeight * tick) / 4;
        context.beginPath();
        context.moveTo(pad.left, y);
        context.lineTo(width - pad.right, y);
        context.stroke();
        context.fillText((maximum * (1 - tick / 4)).toFixed(2), 2, y + 4);
      }
      labels.forEach((label, index) => {
        const x = pad.left + (chartWidth * index) / Math.max(1, labels.length - 1);
        if (index % Math.max(1, Math.ceil(labels.length / 8)) === 0) {
          context.fillText(String(label), x - 5, height - 7);
        }
      });

      this.config.data.datasets.forEach((dataset) => {
        const color = dataset.borderColor || dataset.backgroundColor || "#66d8b0";
        context.strokeStyle = color;
        context.fillStyle = color;
        context.lineWidth = 2;
        context.beginPath();
        let started = false;
        dataset.data.forEach((value, index) => {
          if (!Number.isFinite(value)) {
            started = false;
            return;
          }
          const x = pad.left + (chartWidth * index) / Math.max(1, labels.length - 1);
          const y = pad.top + chartHeight * (1 - value / maximum);
          if (!started) {
            context.moveTo(x, y);
            started = true;
          } else {
            context.lineTo(x, y);
          }
        });
        context.stroke();
      });
    }
  }

  window.Chart = LocalChartFallback;
})();
