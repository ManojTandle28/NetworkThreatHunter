/**
 * Packet Explorer client-side filter and deep inspector logic
 */

let currentPage = 1;
let currentTotalPages = 1;

function fetchPackets(page = 1) {
  currentPage = page;
  const tableBody = document.getElementById('packet-table-body');
  const countEl = document.getElementById('packet-count-display');
  const pageInfoEl = document.getElementById('page-info');
  const prevBtn = document.getElementById('btn-prev');
  const nextBtn = document.getElementById('btn-next');

  if (!tableBody) return;

  const srcIp = document.getElementById('filter-src')?.value || '';
  const dstIp = document.getElementById('filter-dst')?.value || '';
  const proto = document.getElementById('filter-proto')?.value || '';
  const port = document.getElementById('filter-port')?.value || '';
  const search = document.getElementById('filter-search')?.value || '';
  const pageSize = document.getElementById('filter-pagesize')?.value || '50';

  const params = new URLSearchParams({
    page: page,
    page_size: pageSize,
    src_ip: srcIp,
    dst_ip: dstIp,
    protocol: proto,
    port: port,
    search: search
  });

  tableBody.innerHTML = `<tr><td colspan="9" style="text-align: center; padding: 2rem; color: var(--text-muted);">Loading packet data...</td></tr>`;

  fetch(`/api/packets?${params.toString()}`)
    .then(res => res.json())
    .then(data => {
      currentTotalPages = data.total_pages || 1;
      if (countEl) countEl.innerText = `${data.total.toLocaleString()} packets found`;
      if (pageInfoEl) pageInfoEl.innerText = `Page ${data.page} of ${currentTotalPages}`;

      if (prevBtn) prevBtn.disabled = data.page <= 1;
      if (nextBtn) nextBtn.disabled = data.page >= currentTotalPages;

      if (!data.packets || data.packets.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="9" style="text-align: center; padding: 2rem; color: var(--text-dim);">No matching packets found.</td></tr>`;
        return;
      }

      let rowsHtml = '';
      data.packets.forEach(p => {
        const srcPortText = p.src_port ? `:${p.src_port}` : '';
        const dstPortText = p.dst_port ? `:${p.dst_port}` : '';
        const flagsBadge = p.tcp_flags ? `<span style="font-size: 0.72rem; color: #a5b4fc; background: rgba(99, 102, 241, 0.15); padding: 0.1rem 0.35rem; border-radius: 4px;">${p.tcp_flags}</span>` : '';
        const cleartextBadge = p.is_cleartext ? `<span title="Unencrypted Cleartext Protocol" style="color: #fbbf24; font-size: 0.8rem; margin-right: 0.2rem;">🔓</span>` : '';
        const encryptedBadge = p.is_encrypted ? `<span title="TLS / Encrypted Channel" style="color: #34d399; font-size: 0.8rem; margin-right: 0.2rem;">🔒</span>` : '';

        rowsHtml += `
          <tr style="cursor: pointer;" onclick="openPacketDetail(${p.packet_index})">
            <td style="font-family: monospace; font-weight: 600; color: var(--accent-cyan);">${p.packet_index}</td>
            <td style="font-family: monospace; font-size: 0.78rem; color: var(--text-muted);">${p.time_iso.split(' ')[1] || p.time_iso}</td>
            <td style="font-family: monospace; font-size: 0.78rem;">+${p.relative_time.toFixed(4)}s</td>
            <td style="font-family: monospace;">${p.src_ip}${srcPortText}</td>
            <td style="font-family: monospace;">${p.dst_ip}${dstPortText}</td>
            <td><span class="badge badge-proto">${p.protocol}</span></td>
            <td style="font-family: monospace;">${p.length} B</td>
            <td>${flagsBadge}</td>
            <td style="max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
              ${cleartextBadge}${encryptedBadge}${escapeHtml(p.summary || '')}
            </td>
          </tr>
        `;
      });
      tableBody.innerHTML = rowsHtml;
    })
    .catch(err => {
      tableBody.innerHTML = `<tr><td colspan="9" style="text-align: center; padding: 2rem; color: #f87171;">Failed to load packet data.</td></tr>`;
    });
}

function openPacketDetail(packetIndex) {
  const modal = document.getElementById('packet-inspect-modal');
  const modalTitle = document.getElementById('inspect-modal-title');
  const detailsContainer = document.getElementById('inspect-details');

  if (!modal || !detailsContainer) return;

  modalTitle.innerText = `Inspecting Packet #${packetIndex}`;
  detailsContainer.innerHTML = '<p style="color: var(--text-muted);">Fetching decoded layers...</p>';
  modal.classList.add('active');

  fetch(`/api/packets/${packetIndex}`)
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        detailsContainer.innerHTML = `<p style="color: #f87171;">${data.error}</p>`;
        return;
      }
      const pkt = data.packet;
      const layers = pkt.layer_details || {};

      let layersTreeHtml = '<div style="margin-bottom: 1rem;">';
      layersTreeHtml += `<h4 style="font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; margin-bottom: 0.5rem;">Decoded Layer Tree</h4>`;

      for (const [layerName, fields] of Object.entries(layers)) {
        layersTreeHtml += `
          <div style="background: #090e1a; border: 1px solid var(--border-color); border-radius: 6px; padding: 0.6rem 0.8rem; margin-bottom: 0.5rem;">
            <div style="font-weight: 700; color: var(--accent-cyan); font-family: monospace; font-size: 0.85rem; margin-bottom: 0.25rem;">
              Layer: ${layerName}
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.4rem; font-size: 0.8rem; font-family: monospace;">
        `;
        for (const [k, v] of Object.entries(fields)) {
          layersTreeHtml += `<div><span style="color: var(--text-muted);">${k}:</span> <span style="color: var(--text-main);">${escapeHtml(String(v))}</span></div>`;
        }
        layersTreeHtml += `</div></div>`;
      }
      layersTreeHtml += '</div>';

      // Security note
      let encryptionNotice = '';
      if (pkt.is_encrypted) {
        encryptionNotice = `
          <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); color: #34d399; padding: 0.6rem 0.8rem; border-radius: 6px; font-size: 0.8rem; margin-bottom: 1rem;">
            🔒 <strong>Encrypted Transport (TLS / HTTPS):</strong> Application payload is encrypted cryptographically in transit. Plaintext payload decryption is not performed or simulated.
          </div>
        `;
      } else if (pkt.is_cleartext) {
        encryptionNotice = `
          <div style="background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); color: #fbbf24; padding: 0.6rem 0.8rem; border-radius: 6px; font-size: 0.8rem; margin-bottom: 1rem;">
            🔓 <strong>Cleartext Protocol:</strong> Transport headers and payload are unencrypted on the wire.
          </div>
        `;
      }

      // Payload view
      const hexView = pkt.payload_hex ? `
        <div style="margin-top: 1rem;">
          <h4 style="font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; margin-bottom: 0.35rem;">Payload Hex Dump (First ${pkt.payload_hex.split(' ').length} Bytes)</h4>
          <div class="hex-viewer">${pkt.payload_hex}</div>
        </div>
      ` : '<p style="font-size: 0.8rem; color: var(--text-dim); margin-top: 0.75rem;">No raw payload bytes attached to this packet layer.</p>';

      const asciiView = pkt.payload_ascii ? `
        <div style="margin-top: 1rem;">
          <h4 style="font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; margin-bottom: 0.35rem;">Printable ASCII Representation</h4>
          <div class="hex-viewer" style="color: #6ee7b7;">${escapeHtml(pkt.payload_ascii)}</div>
        </div>
      ` : '';

      detailsContainer.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.5rem; background: var(--bg-input); padding: 0.75rem; border-radius: 6px; font-size: 0.8rem; margin-bottom: 1rem;">
          <div><span style="color: var(--text-muted);">Timestamp:</span><br><code>${pkt.time_iso}</code></div>
          <div><span style="color: var(--text-muted);">Length:</span><br><code>${pkt.length} bytes</code></div>
          <div><span style="color: var(--text-muted);">Protocol:</span><br><code>${pkt.protocol}</code></div>
          <div><span style="color: var(--text-muted);">TCP Flags:</span><br><code>${pkt.tcp_flags || 'None'}</code></div>
        </div>
        ${encryptionNotice}
        ${layersTreeHtml}
        ${hexView}
        ${asciiView}
      `;
    })
    .catch(err => {
      detailsContainer.innerHTML = `<p style="color: #f87171;">Failed to fetch packet details.</p>`;
    });
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

document.addEventListener('DOMContentLoaded', () => {
  const filterForm = document.getElementById('packet-filter-form');
  const resetBtn = document.getElementById('btn-reset-filters');
  const prevBtn = document.getElementById('btn-prev');
  const nextBtn = document.getElementById('btn-next');
  const exportCsvBtn = document.getElementById('btn-export-filtered-csv');

  if (filterForm) {
    filterForm.addEventListener('submit', (e) => {
      e.preventDefault();
      fetchPackets(1);
    });
  }

  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      if (document.getElementById('filter-src')) document.getElementById('filter-src').value = '';
      if (document.getElementById('filter-dst')) document.getElementById('filter-dst').value = '';
      if (document.getElementById('filter-proto')) document.getElementById('filter-proto').value = '';
      if (document.getElementById('filter-port')) document.getElementById('filter-port').value = '';
      if (document.getElementById('filter-search')) document.getElementById('filter-search').value = '';
      fetchPackets(1);
    });
  }

  if (prevBtn) {
    prevBtn.addEventListener('click', () => {
      if (currentPage > 1) fetchPackets(currentPage - 1);
    });
  }

  if (nextBtn) {
    nextBtn.addEventListener('click', () => {
      if (currentPage < currentTotalPages) fetchPackets(currentPage + 1);
    });
  }

  if (exportCsvBtn) {
    exportCsvBtn.addEventListener('click', () => {
      const srcIp = document.getElementById('filter-src')?.value || '';
      const dstIp = document.getElementById('filter-dst')?.value || '';
      const proto = document.getElementById('filter-proto')?.value || '';
      const port = document.getElementById('filter-port')?.value || '';
      const search = document.getElementById('filter-search')?.value || '';

      const params = new URLSearchParams({
        src_ip: srcIp,
        dst_ip: dstIp,
        protocol: proto,
        port: port,
        search: search
      });
      window.location.href = `/export/csv?${params.toString()}`;
    });
  }

  // Initial load if on explorer page
  if (document.getElementById('packet-table-body')) {
    fetchPackets(1);
  }
});
