/**
 * Front-end Application Logic for NGAP / NAS Wireshark Diagnostic Analyzer GUI.
 */

let currentReportData = null;
let currentFilter = 'all';
let currentView = 'list'; // Default to vertical formal list layout

document.addEventListener('DOMContentLoaded', () => {
    initDropzone();
    initFilters();
    initSearch();
    initViewToggle();
    initModal();

    document.getElementById('btn-load-sample').addEventListener('click', loadSampleData);
});

function initViewToggle() {
    const btnList = document.getElementById('view-btn-list');
    const btnGrid = document.getElementById('view-btn-grid');

    if (btnList && btnGrid) {
        btnList.addEventListener('click', () => {
            btnList.classList.add('active');
            btnGrid.classList.remove('active');
            currentView = 'list';
            renderUEView();
        });

        btnGrid.addEventListener('click', () => {
            btnGrid.classList.add('active');
            btnList.classList.remove('active');
            currentView = 'grid';
            renderUEView();
        });
    }
}

function initDropzone() {
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('file-input');

    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
    });

    dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('dragover');
    });

    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            uploadFile(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            uploadFile(e.target.files[0]);
        }
    });
}

function showSpinner(text = "Analyzing Capture...") {
    document.getElementById('spinner-text').textContent = text;
    document.getElementById('upload-spinner').classList.remove('hidden');
}

function hideSpinner() {
    document.getElementById('upload-spinner').classList.add('hidden');
}

async function uploadFile(file) {
    showSpinner(`Analyzing ${file.name}...`);

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Server returned status ${response.status}`);
        }

        const data = await response.json();
        if (data.error) {
            alert(`Analysis Error: ${data.error}`);
            return;
        }

        renderReport(data);
    } catch (err) {
        console.error(err);
        alert(`Failed to analyze file: ${err.message}`);
    } finally {
        hideSpinner();
    }
}

async function loadSampleData() {
    showSpinner("Loading Sample 5G Signalling Capture...");
    try {
        const response = await fetch('/api/sample');
        if (!response.ok) throw new Error("Failed to fetch sample data");

        const data = await response.json();
        renderReport(data);
    } catch (err) {
        alert(`Error loading sample: ${err.message}`);
    } finally {
        hideSpinner();
    }
}

function renderReport(data) {
    currentReportData = data;

    // Update Summary Metrics
    document.getElementById('metric-frames').textContent = data.total_frames_analyzed || 0;
    document.getElementById('metric-file').textContent = data.pcap_file || 'Capture File';

    const ues = data.ue_contexts || [];
    document.getElementById('metric-ues').textContent = ues.length;

    let totalFailures = 0;
    let totalIncomplete = 0;
    let totalSuccess = 0;

    ues.forEach(ue => {
        const hasFailures = (ue.explicit_failures && ue.explicit_failures.length > 0) ||
            (ue.procedures && ue.procedures.some(p => p.status === 'Failed'));
        const hasIncomplete = (ue.incomplete_procedures && ue.incomplete_procedures.length > 0) ||
            (ue.procedures && ue.procedures.some(p => p.status === 'Incomplete'));

        if (hasFailures) totalFailures++;
        else if (hasIncomplete) totalIncomplete++;
        else totalSuccess++;
    });

    document.getElementById('metric-failures').textContent = totalFailures;
    document.getElementById('metric-incomplete').textContent = totalIncomplete;

    document.getElementById('count-all').textContent = ues.length;
    document.getElementById('count-failed').textContent = totalFailures;
    document.getElementById('count-incomplete').textContent = totalIncomplete;
    document.getElementById('count-success').textContent = totalSuccess;

    // Show sections
    document.getElementById('metrics-section').classList.remove('hidden');
    document.getElementById('filter-section').classList.remove('hidden');

    renderUEView();
}

function initFilters() {
    const tabs = document.querySelectorAll('.filter-tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            currentFilter = tab.getAttribute('data-filter');
            renderUEView();
        });
    });
}

function initSearch() {
    const input = document.getElementById('search-input');
    input.addEventListener('input', () => {
        renderUEView();
    });
}

function renderUEView() {
    const container = document.getElementById('ue-container');
    container.innerHTML = '';

    if (currentView === 'list') {
        container.className = 'ue-container list-view';
    } else {
        container.className = 'ue-container grid-view';
    }

    if (!currentReportData || !currentReportData.ue_contexts || currentReportData.ue_contexts.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🔍</div>
                <h3>No UE Contexts Found</h3>
                <p>No 5G NGAP/NAS UE contexts were identified in this capture file.</p>
            </div>
        `;
        return;
    }

    const searchQuery = document.getElementById('search-input').value.toLowerCase().trim();

    const filteredUEs = currentReportData.ue_contexts.filter(ue => {
        const hasFailures = (ue.explicit_failures && ue.explicit_failures.length > 0) ||
            (ue.procedures && ue.procedures.some(p => p.status === 'Failed'));
        const hasIncomplete = (ue.incomplete_procedures && ue.incomplete_procedures.length > 0) ||
            (ue.procedures && ue.procedures.some(p => p.status === 'Incomplete'));

        // Filter tab match
        if (currentFilter === 'failed' && !hasFailures) return false;
        if (currentFilter === 'incomplete' && (!hasIncomplete || hasFailures)) return false;
        if (currentFilter === 'success' && (hasFailures || hasIncomplete)) return false;

        // Search query match
        if (searchQuery) {
            const ranStr = String(ue.ran_ue_ngap_id || '');
            const amfStr = String(ue.amf_ue_ngap_id || '');
            const tmsiStr = String(ue.fiveg_s_tmsi || '').toLowerCase();
            const idMatch = ranStr.includes(searchQuery) || amfStr.includes(searchQuery) || tmsiStr.includes(searchQuery);
            if (!idMatch) return false;
        }

        return true;
    });

    if (filteredUEs.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🔎</div>
                <h3>No Matching UE Contexts</h3>
                <p>No UEs match the selected filter criteria or search query.</p>
            </div>
        `;
        return;
    }

    if (currentView === 'list') {
        renderVerticalFormalTable(container, filteredUEs);
    } else {
        filteredUEs.forEach(ue => {
            const card = createUECard(ue);
            container.appendChild(card);
        });
    }
}

function renderVerticalFormalTable(container, ues) {
    const tableWrapper = document.createElement('div');
    tableWrapper.className = 'table-responsive';

    const table = document.createElement('table');
    table.className = 'formal-table';

    table.innerHTML = `
        <thead>
            <tr>
                <th>Outcome Status</th>
                <th>UE Context</th>
                <th>NGAP Identifiers</th>
                <th>Network Endpoints</th>
                <th>Procedures & Diagnostics</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody></tbody>
    `;

    const tbody = table.querySelector('tbody');
    ues.forEach(ue => {
        const row = createUETableRow(ue);
        tbody.appendChild(row);
    });

    tableWrapper.appendChild(table);
    container.appendChild(tableWrapper);
}

function createUETableRow(ue) {
    const tr = document.createElement('tr');

    const hasFailures = (ue.explicit_failures && ue.explicit_failures.length > 0) ||
        (ue.procedures && ue.procedures.some(p => p.status === 'Failed'));
    const hasIncomplete = (ue.incomplete_procedures && ue.incomplete_procedures.length > 0) ||
        (ue.procedures && ue.procedures.some(p => p.status === 'Incomplete'));

    let rowClass = 'table-row-success';
    let pillClass = 'pill-success';
    let pillText = 'Completed 🟢';

    if (hasFailures) {
        rowClass = 'table-row-failed';
        pillClass = 'pill-failed';
        pillText = 'Explicit Failure 🔴';
    } else if (hasIncomplete) {
        rowClass = 'table-row-incomplete';
        pillClass = 'pill-incomplete';
        pillText = 'Incomplete 🟡';
    }

    tr.className = rowClass;

    const ranStr = ue.ran_ue_ngap_id !== null ? `RAN ID: ${ue.ran_ue_ngap_id}` : 'RAN ID: (none)';
    const amfStr = ue.amf_ue_ngap_id !== null ? `AMF ID: ${ue.amf_ue_ngap_id}` : 'AMF ID: (none)';
    const gnbIp = ue.gnb_ip || 'gNB IP';
    const amfIp = ue.amf_ip || 'AMF IP';

    let procsHtml = '';
    if (ue.procedures && ue.procedures.length > 0) {
        procsHtml = ue.procedures.map(p => `<span class="proc-chip">${p.name}: <strong>${p.status}</strong></span>`).join(' ');
    } else {
        procsHtml = '<span class="proc-chip">No procedures</span>';
    }

    let diagSummary = '';
    if (ue.explicit_failures && ue.explicit_failures.length > 0) {
        diagSummary += ue.explicit_failures.map(f => `<div style="color:#fca5a5; font-size:0.8rem; margin-top:0.25rem;">🚨 <strong>${f.procedure}</strong>: ${f.cause}</div>`).join('');
    }
    if (ue.diagnostic_observations && ue.diagnostic_observations.length > 0) {
        diagSummary += `<div style="color:var(--text-muted); font-size:0.78rem; margin-top:0.25rem;">💬 ${ue.diagnostic_observations.join(', ')}</div>`;
    }

    tr.innerHTML = `
        <td><span class="status-pill ${pillClass}">${pillText}</span></td>
        <td class="td-id">
            <div>${ue.context_id || 'UE'}</div>
            ${ue.fiveg_s_tmsi ? `<div style="font-size:0.75rem; color:var(--text-muted); font-weight:normal;">TMSI: ${ue.fiveg_s_tmsi}</div>` : ''}
        </td>
        <td>
            <div class="td-ngap-ids">
                <span class="badge badge-ran">${ranStr}</span>
                <span class="badge badge-amf">${amfStr}</span>
            </div>
        </td>
        <td>
            <div class="td-endpoints">
                <span>📡 gNB: ${gnbIp}</span>
                <span>🏢 AMF: ${amfIp}</span>
            </div>
        </td>
        <td class="td-diagnostics">
            <div>${procsHtml}</div>
            ${diagSummary}
        </td>
        <td>
            <button class="action-btn">Inspect Flow ➔</button>
        </td>
    `;

    tr.addEventListener('click', () => openUEModal(ue));
    return tr;
}

function createUECard(ue) {
    const card = document.createElement('div');
    card.className = 'ue-card';

    const hasFailures = (ue.explicit_failures && ue.explicit_failures.length > 0) ||
        (ue.procedures && ue.procedures.some(p => p.status === 'Failed'));
    const hasIncomplete = (ue.incomplete_procedures && ue.incomplete_procedures.length > 0) ||
        (ue.procedures && ue.procedures.some(p => p.status === 'Incomplete'));

    let pillClass = 'pill-success';
    let pillText = 'Completed';

    if (hasFailures) {
        pillClass = 'pill-failed';
        pillText = 'Explicit Failure 🔴';
    } else if (hasIncomplete) {
        pillClass = 'pill-incomplete';
        pillText = 'Incomplete 🟡';
    }

    const ranStr = ue.ran_ue_ngap_id !== null ? `RAN ID: ${ue.ran_ue_ngap_id}` : 'RAN ID: (none)';
    const amfStr = ue.amf_ue_ngap_id !== null ? `AMF ID: ${ue.amf_ue_ngap_id}` : 'AMF ID: (not assigned)';
    const gnbIp = ue.gnb_ip || 'gNB IP';
    const amfIp = ue.amf_ip || 'AMF IP';

    let procsHtml = '';
    if (ue.procedures && ue.procedures.length > 0) {
        procsHtml = ue.procedures.map(p => `<span class="proc-chip">${p.name}: <strong>${p.status}</strong></span>`).join('');
    } else {
        procsHtml = '<span class="proc-chip">No procedures</span>';
    }

    let failureAlert = '';
    if (ue.explicit_failures && ue.explicit_failures.length > 0) {
        failureAlert = ue.explicit_failures.map(f => `
            <div class="failure-alert-box">
                <strong>🚨 ${f.procedure}</strong>
                <span>Cause: ${f.cause}</span>
            </div>
        `).join('');
    }

    let obsHtml = '';
    if (ue.diagnostic_observations && ue.diagnostic_observations.length > 0) {
        obsHtml = `<div class="obs-box">💬 ${ue.diagnostic_observations.join('<br>💬 ')}</div>`;
    }

    card.innerHTML = `
        <div class="ue-card-header">
            <div>
                <div class="ue-title">${ue.context_id || 'UE'}</div>
                <div class="id-badge-group">
                    <span class="badge badge-ran">${ranStr}</span>
                    <span class="badge badge-amf">${amfStr}</span>
                </div>
                <div class="endpoint-badge-group">
                    <span class="badge badge-ip">📡 gNB: ${gnbIp}</span>
                    <span class="badge badge-ip">🏢 AMF: ${amfIp}</span>
                </div>
            </div>
            <span class="status-pill ${pillClass}">${pillText}</span>
        </div>
        <div class="procedure-list-summary">
            ${procsHtml}
        </div>
        ${failureAlert}
        ${obsHtml}
    `;

    card.addEventListener('click', () => openUEModal(ue));
    return card;
}

function initModal() {
    const modal = document.getElementById('detail-modal');
    const closeBtn = document.getElementById('modal-close');

    closeBtn.addEventListener('click', () => {
        modal.classList.add('hidden');
    });

    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.add('hidden');
        }
    });

    const tabs = document.querySelectorAll('.modal-tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            const target = tab.getAttribute('data-mtab');
            document.querySelectorAll('.mtab-content').forEach(c => c.classList.remove('active'));
            document.getElementById(`mtab-${target}`).classList.add('active');
        });
    });
}

function openUEModal(ue) {
    document.getElementById('modal-ue-title').textContent = `${ue.context_id} Signalling Flow`;

    const badgesContainer = document.getElementById('modal-ue-badges');
    badgesContainer.innerHTML = `
        <span class="badge badge-ran">RAN ID: ${ue.ran_ue_ngap_id}</span>
        <span class="badge badge-amf">AMF ID: ${ue.amf_ue_ngap_id}</span>
        <span class="badge badge-ip">gNB IP: ${ue.gnb_ip}</span>
        <span class="badge badge-ip">AMF IP: ${ue.amf_ip}</span>
    `;

    // Render Sequence Diagram
    const seqContainer = document.getElementById('sequence-diagram');
    seqContainer.innerHTML = '';

    if (ue.timeline && ue.timeline.length > 0) {
        ue.timeline.forEach(event => {
            const item = document.createElement('div');
            item.className = 'seq-item';

            const isGnbToAmf = event.direction.includes('gNB -> AMF');
            const dirClass = isGnbToAmf ? 'dir-gnb-amf' : 'dir-amf-gnb';
            const srcIp = event.src_ip || (isGnbToAmf ? ue.gnb_ip : ue.amf_ip) || 'gNB';
            const dstIp = event.dst_ip || (isGnbToAmf ? ue.amf_ip : ue.gnb_ip) || 'AMF';
            const streamInfo = event.sctp_stream !== null ? ` | Stream #${event.sctp_stream}` : '';

            item.innerHTML = `
                <div class="seq-frame">
                    <span>Frame #${event.frame_number}</span>
                    <span style="font-size:0.7rem; color:var(--text-dim);">${event.timestamp}s</span>
                </div>
                <div class="seq-msg-card">
                    <div>
                        <strong>${event.message_type}</strong>
                        <div class="ip-flow-text">
                            ${srcIp} ➔ ${dstIp} ${streamInfo}
                        </div>
                        ${event.cause_code ? `<div style="color:#fca5a5; font-size:0.75rem; margin-top:0.2rem;">Cause: ${event.cause_code}</div>` : ''}
                    </div>
                    <span class="seq-direction ${dirClass}">${event.direction}</span>
                </div>
            `;
            seqContainer.appendChild(item);
        });
    } else {
        seqContainer.innerHTML = '<p class="text-muted">No timeline events recorded.</p>';
    }

    // Render Procedures List Tab
    const procList = document.getElementById('modal-procedures-list');
    if (ue.procedures && ue.procedures.length > 0) {
        procList.innerHTML = ue.procedures.map(p => `
            <div style="background:rgba(255,255,255,0.04); border:1px solid var(--card-border); padding:0.8rem; border-radius:8px; margin-bottom:0.5rem;">
                <strong>${p.name}</strong> - Status: <span style="color:var(--indigo); font-weight:600;">${p.status}</span>
                ${p.failure_cause ? `<div style="color:#fca5a5; font-size:0.8rem; margin-top:0.3rem;">Failure Cause: ${p.failure_cause}</div>` : ''}
                ${p.observations ? `<div style="color:var(--text-muted); font-size:0.8rem; margin-top:0.3rem;">Observations: ${p.observations.join(', ')}</div>` : ''}
            </div>
        `).join('');
    } else {
        procList.innerHTML = '<p>No procedures recorded.</p>';
    }

    // Render Raw JSON
    document.getElementById('modal-json-view').textContent = JSON.stringify(ue, null, 2);

    document.getElementById('detail-modal').classList.remove('hidden');
}
