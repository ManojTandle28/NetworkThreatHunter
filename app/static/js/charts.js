/**
 * Native, offline-capable responsive SVG charts for NetworkThreatHunter.
 * Zero external CDN or internet dependencies.
 */

const NthCharts = {
  renderTimelineChart: function(containerId, timeBuckets) {
    const container = document.getElementById(containerId);
    if (!container || !timeBuckets || timeBuckets.length === 0) return;

    const width = container.clientWidth || 600;
    const height = container.clientHeight || 200;
    const padding = { top: 20, right: 20, bottom: 35, left: 45 };

    const maxPackets = Math.max(...timeBuckets.map(b => b.packet_count), 1);
    const plotWidth = width - padding.left - padding.right;
    const plotHeight = height - padding.top - padding.bottom;

    const barWidth = Math.max(4, (plotWidth / timeBuckets.length) - 4);

    let barsHtml = '';
    let xLabelsHtml = '';

    timeBuckets.forEach((bucket, i) => {
      const x = padding.left + i * (plotWidth / timeBuckets.length) + 2;
      const barH = (bucket.packet_count / maxPackets) * plotHeight;
      const y = padding.top + (plotHeight - barH);

      barsHtml += `
        <rect class="chart-bar" x="${x}" y="${y}" width="${barWidth}" height="${barH}" rx="2" data-packets="${bucket.packet_count}" data-time="${bucket.bucket_label}">
          <title>${bucket.bucket_label}: ${bucket.packet_count} packets (${bucket.byte_count} bytes)</title>
        </rect>
      `;

      // Label every few bars
      const step = Math.max(1, Math.floor(timeBuckets.length / 6));
      if (i % step === 0 || i === timeBuckets.length - 1) {
        xLabelsHtml += `
          <text class="chart-axis-text" x="${x + barWidth / 2}" y="${height - 10}" text-anchor="middle">${bucket.bucket_label}</text>
        `;
      }
    });

    // Y Axis Grid & Labels
    let yGridHtml = '';
    const yTicks = 4;
    for (let i = 0; i <= yTicks; i++) {
      const val = Math.round((maxPackets / yTicks) * i);
      const y = padding.top + plotHeight - (i / yTicks) * plotHeight;
      yGridHtml += `
        <line class="chart-grid" x1="${padding.left}" y1="${y}" x2="${width - padding.right}" y2="${y}" />
        <text class="chart-axis-text" x="${padding.left - 8}" y="${y + 3}" text-anchor="end">${val}</text>
      `;
    }

    container.innerHTML = `
      <svg class="svg-chart" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
        ${yGridHtml}
        ${barsHtml}
        ${xLabelsHtml}
      </svg>
    `;
  },

  renderProtocolBars: function(containerId, protocolDistribution) {
    const container = document.getElementById(containerId);
    if (!container || !protocolDistribution || protocolDistribution.length === 0) return;

    const protoColors = {
      'TCP': '#0ea5e9',
      'UDP': '#8b5cf6',
      'ICMP': '#f59e0b',
      'ICMPv6': '#f59e0b',
      'DNS': '#10b981',
      'HTTP': '#ec4899',
      'ARP': '#64748b'
    };

    let html = '<div style="display: flex; flex-direction: column; gap: 0.65rem;">';
    protocolDistribution.forEach(p => {
      const color = protoColors[p.protocol] || '#3b82f6';
      html += `
        <div>
          <div style="display: flex; justify-content: space-between; font-size: 0.8rem; margin-bottom: 0.2rem;">
            <span style="font-weight: 600; font-family: monospace;">${p.protocol}</span>
            <span style="color: var(--text-muted);">${p.count.toLocaleString()} pkts (${p.percentage}%)</span>
          </div>
          <div style="width: 100%; height: 8px; background-color: var(--bg-input); border-radius: 9999px; overflow: hidden;">
            <div style="width: ${p.percentage}%; height: 100%; background-color: ${color}; border-radius: 9999px; transition: width 0.4s ease;"></div>
          </div>
        </div>
      `;
    });
    html += '</div>';

    container.innerHTML = html;
  }
};
