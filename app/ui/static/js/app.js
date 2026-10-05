/**
 * NETPHISH — Cybersecurity Operations Client Script
 */

// Application State
const state = {
    currentView: 'dashboard',
    stats: null,
    recentAnalyses: [],
    investigations: [],
    iocs: [],
};

// Application Initialization
function initApp() {
    initNavigation();
    initUrlAnalyzer();
    initPcapAnalyzer();
    initHistoryFilters();
    initIocFilters();
    initInvestigations();
    loadDashboardData();
    loadSamplesList();

    const refreshBtn = document.getElementById('refresh-data-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            loadDashboardData();
        });
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
} else {
    initApp();
}

// Navigation Handling
function initNavigation() {
    const navButtons = document.querySelectorAll('.nav-item');
    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const viewTarget = btn.getAttribute('data-view');
            switchView(viewTarget);
        });
    });
}

function switchView(viewName) {
    state.currentView = viewName;

    // Update active nav item
    document.querySelectorAll('.nav-item').forEach(btn => {
        if (btn.getAttribute('data-view') === viewName) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    // Toggle panels
    document.querySelectorAll('.view-panel').forEach(panel => {
        panel.classList.remove('active');
    });

    const targetPanel = document.getElementById(`view-${viewName}`);
    if (targetPanel) {
        targetPanel.classList.add('active');
    }

    // Update Topbar Title
    const titleMap = {
        'dashboard': 'SOC Dashboard',
        'url-analysis': 'URL Threat Analyzer',
        'pcap-analysis': 'PCAP Flow Analyzer',
        'analyses-history': 'Analyses History',
        'ioc-intelligence': 'IOC Threat Intelligence',
        'investigations': 'Investigation Dossiers',
        'architecture': 'Platform Architecture & Heuristics Reference',
    };
    document.getElementById('current-view-title').innerText = titleMap[viewName] || 'SOC Dashboard';

    // Route-specific data refresh
    if (viewName === 'dashboard') loadDashboardData();
    if (viewName === 'analyses-history') loadHistoryData();
    if (viewName === 'ioc-intelligence') loadIocsData();
    if (viewName === 'investigations') loadInvestigationsData();
}

// 1. Dashboard Logic
async function loadDashboardData() {
    try {
        const statsRes = await fetch('/api/stats');
        if (statsRes.ok) {
            const stats = await statsRes.json();
            state.stats = stats;
            const elTotal = document.getElementById('stat-total-analyses');
            if (elTotal) elTotal.innerText = stats.total_analyses ?? 0;
            const elUrl = document.getElementById('stat-url-analyses');
            if (elUrl) elUrl.innerText = stats.url_analyses ?? 0;
            const elPcap = document.getElementById('stat-pcap-analyses');
            if (elPcap) elPcap.innerText = stats.pcap_analyses ?? 0;
            const elCrit = document.getElementById('stat-critical-detections');
            if (elCrit) elCrit.innerText = stats.critical_detections ?? 0;
            const elIocs = document.getElementById('stat-total-iocs');
            if (elIocs) elIocs.innerText = stats.total_iocs ?? 0;
            const elInvs = document.getElementById('stat-active-investigations');
            if (elInvs) elInvs.innerText = stats.active_investigations ?? 0;

            try { drawSeverityChart(stats); } catch (e) { console.error('Severity chart error:', e); }
            try { drawPostureChart(stats); } catch (e) { console.error('Posture chart error:', e); }
        }
    } catch (err) {
        console.error('Failed to load stats:', err);
    }

    try {
        const analysesRes = await fetch('/api/analyses?limit=6');
        if (analysesRes.ok) {
            const analyses = await analysesRes.json();
            state.recentAnalyses = analyses;
            renderRecentAnalysesTable(analyses);
        } else {
            const tbody = document.querySelector('#dashboard-recent-table tbody');
            if (tbody) {
                tbody.innerHTML = '<tr><td colspan="8" class="text-center">No forensic analyses recorded yet. Run a URL or PCAP assessment.</td></tr>';
            }
        }
    } catch (err) {
        console.error('Failed to load recent analyses:', err);
        const tbody = document.querySelector('#dashboard-recent-table tbody');
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center">No forensic analyses recorded yet. Run a URL or PCAP assessment.</td></tr>';
        }
    }
}

function renderRecentAnalysesTable(analyses) {
    const tbody = document.querySelector('#dashboard-recent-table tbody');
    if (!analyses || analyses.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center">No forensic analyses recorded yet. Run a URL or PCAP assessment.</td></tr>';
        return;
    }

    tbody.innerHTML = analyses.map(a => {
        const dateStr = a.created_at ? new Date(a.created_at).toLocaleString() : 'N/A';
        const sevClass = (a.severity || 'low').toLowerCase();
        return `
            <tr>
                <td>#${a.id}</td>
                <td><span class="badge ${a.analysis_type === 'URL' ? 'medium' : 'low'}">${a.analysis_type}</span></td>
                <td><code title="${escapeHtml(a.target)}">${truncate(a.target, 40)}</code></td>
                <td><strong>${a.risk_score.toFixed(1)}</strong></td>
                <td><span class="badge ${sevClass}">${a.severity}</span></td>
                <td><span style="font-size:12px; color:var(--text-secondary);">${truncate(a.summary || 'Completed', 35)}</span></td>
                <td>${dateStr}</td>
                <td>
                    <button class="btn btn-sm btn-outline" onclick="viewAnalysisDetail(${a.id}, '${a.analysis_type}')">Inspect</button>
                </td>
            </tr>
        `;
    }).join('');
}

// 2. URL Threat Analyzer
function initUrlAnalyzer() {
    const btn = document.getElementById('btn-submit-url');
    const input = document.getElementById('url-input-field');

    const handleAnalyze = async () => {
        const urlVal = input.value.trim();
        if (!urlVal) {
            alert('Please enter a target URL to analyze.');
            return;
        }

        btn.disabled = true;
        btn.innerText = 'Analyzing...';

        try {
            const res = await fetch('/api/url/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: urlVal }),
            });

            if (!res.ok) {
                const errData = await res.json();
                throw new Error(errData.detail || 'Analysis request failed.');
            }

            const data = await res.json();
            renderUrlResults(data);
        } catch (err) {
            alert('Error analyzing URL: ' + err.message);
        } finally {
            btn.disabled = false;
            btn.innerText = '⚡ Analyze Target';
        }
    };

    btn.addEventListener('click', handleAnalyze);
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') handleAnalyze();
    });
}

function loadSampleUrl(url) {
    document.getElementById('url-input-field').value = url;
    document.getElementById('btn-submit-url').click();
}

function renderUrlResults(data) {
    const container = document.getElementById('url-results-container');
    container.classList.remove('hidden');

    // Score Banner
    const scoreVal = data.risk_score;
    const sev = data.severity;
    document.getElementById('url-res-score').innerText = scoreVal.toFixed(0);
    const badge = document.getElementById('url-res-badge');
    badge.innerText = sev;
    badge.className = `score-badge ${sev.toLowerCase()}`;
    document.getElementById('url-res-summary').innerText = data.summary;

    // Features Table
    const featTbody = document.querySelector('#url-features-table tbody');
    const featRows = Object.entries(data.features || {}).map(([key, val]) => {
        let isSuspicious = false;
        if (typeof val === 'boolean' && val === true && key !== 'has_https') isSuspicious = true;
        if (key === 'has_https' && val === false) isSuspicious = true;
        if (key === 'risk_score' || key === 'severity') return '';

        const statusBadge = isSuspicious
            ? '<span class="badge high">Flagged</span>'
            : '<span class="badge low">Baseline</span>';

        return `
            <tr>
                <td><code>${key}</code></td>
                <td>${typeof val === 'object' ? JSON.stringify(val) : String(val)}</td>
                <td>${statusBadge}</td>
            </tr>
        `;
    }).filter(r => r !== '').join('');
    featTbody.innerHTML = featRows;

    // Factors Table
    const factorTbody = document.querySelector('#url-factors-table tbody');
    if (!data.factors || data.factors.length === 0) {
        factorTbody.innerHTML = '<tr><td colspan="3" class="text-center">No malicious heuristic triggers identified.</td></tr>';
    } else {
        factorTbody.innerHTML = data.factors.map(f => `
            <tr>
                <td><strong>${f.name}</strong></td>
                <td><span class="badge ${f.points >= 20 ? 'critical' : 'medium'}">+${f.points.toFixed(0)} pts</span></td>
                <td>${f.reason}</td>
            </tr>
        `).join('');
    }

    // IOCs Table
    const iocTbody = document.querySelector('#url-iocs-table tbody');
    if (!data.iocs || data.iocs.length === 0) {
        iocTbody.innerHTML = '<tr><td colspan="4" class="text-center">No indicators extracted.</td></tr>';
    } else {
        iocTbody.innerHTML = data.iocs.map(i => `
            <tr>
                <td><code>${i.type}</code></td>
                <td><strong>${escapeHtml(i.canonical_value)}</strong></td>
                <td><span class="badge ${i.confidence}">${i.confidence}</span></td>
                <td>${i.classification || '-'}</td>
            </tr>
        `).join('');
    }

    container.scrollIntoView({ behavior: 'smooth' });
}

// 3. PCAP Flow Analyzer
function initPcapAnalyzer() {
    const dropzone = document.getElementById('pcap-dropzone');
    const fileInput = document.getElementById('pcap-file-input');

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
            handlePcapUpload(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            handlePcapUpload(fileInput.files[0]);
        }
    });

    document.getElementById('flow-filter-input').addEventListener('input', (e) => {
        const term = e.target.value.toLowerCase();
        document.querySelectorAll('#pcap-flows-table tbody tr').forEach(row => {
            row.style.display = row.innerText.toLowerCase().includes(term) ? '' : 'none';
        });
    });
}

async function handlePcapUpload(file) {
    const formData = new FormData();
    formData.append('file', file);

    const banner = document.getElementById('pcap-score-banner');
    banner.scrollIntoView({ behavior: 'smooth' });

    try {
        const res = await fetch('/api/pcap/analyze', {
            method: 'POST',
            body: formData,
        });

        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Capture analysis failed.');
        }

        const data = await res.json();
        renderPcapResults(data);
    } catch (err) {
        alert('PCAP analysis error: ' + err.message);
    }
}

function renderPcapResults(data) {
    const container = document.getElementById('pcap-results-container');
    container.classList.remove('hidden');

    // Score Banner
    const scoreVal = data.risk_score;
    const sev = data.severity;
    document.getElementById('pcap-res-score').innerText = scoreVal.toFixed(0);
    const badge = document.getElementById('pcap-res-badge');
    badge.innerText = sev;
    badge.className = `score-badge ${sev.toLowerCase()}`;
    document.getElementById('pcap-res-summary').innerText = data.summary;

    // Metrics Row
    document.getElementById('pcap-res-hash').innerText = data.file_hash;
    document.getElementById('pcap-res-packets').innerText = data.packet_count;
    document.getElementById('pcap-res-flows').innerText = data.flow_count;
    document.getElementById('pcap-res-duration').innerText = `${data.duration_seconds.toFixed(2)}s`;

    // Detections Table
    const detTbody = document.querySelector('#pcap-detections-table tbody');
    if (!data.detections || data.detections.length === 0) {
        detTbody.innerHTML = '<tr><td colspan="6" class="text-center">No anomalous network behaviors triggered. Baseline network posture.</td></tr>';
    } else {
        detTbody.innerHTML = data.detections.map(d => `
            <tr>
                <td><span class="badge ${d.severity.toLowerCase()}">${d.severity}</span></td>
                <td><strong>${d.detection_type}</strong></td>
                <td><code>${d.source || '-'}</code></td>
                <td><code>${d.destination || '-'}</code></td>
                <td>${d.evidence}</td>
                <td><span class="badge ${d.points >= 20 ? 'critical' : 'medium'}">+${d.points.toFixed(0)} pts</span></td>
            </tr>
        `).join('');
    }

    // Flows Table
    const flowTbody = document.querySelector('#pcap-flows-table tbody');
    if (!data.flows || data.flows.length === 0) {
        flowTbody.innerHTML = '<tr><td colspan="7" class="text-center">No aggregated logical flows found.</td></tr>';
    } else {
        flowTbody.innerHTML = data.flows.map(f => `
            <tr>
                <td><code>${f.src_ip}:${f.src_port}</code></td>
                <td><code>${f.dst_ip}:${f.dst_port}</code></td>
                <td><strong>${f.protocol}</strong></td>
                <td>${f.packet_count}</td>
                <td>${formatBytes(f.byte_count)}</td>
                <td>${f.duration.toFixed(2)}s</td>
                <td><span style="font-size:11px; color:var(--text-muted);">${f.tcp_flags || '-'}</span></td>
            </tr>
        `).join('');
    }

    container.scrollIntoView({ behavior: 'smooth' });
}

// 4. Analyses History
function initHistoryFilters() {
    document.getElementById('history-type-filter').addEventListener('change', loadHistoryData);
    document.getElementById('history-severity-filter').addEventListener('change', loadHistoryData);
}

async function loadHistoryData() {
    const type = document.getElementById('history-type-filter').value;
    const sev = document.getElementById('history-severity-filter').value;

    let url = '/api/analyses?limit=100';
    if (type) url += `&analysis_type=${type}`;
    if (sev) url += `&severity=${sev}`;

    try {
        const res = await fetch(url);
        if (res.ok) {
            const analyses = await res.json();
            renderHistoryTable(analyses);
        }
    } catch (err) {
        console.error('Failed to load history:', err);
    }
}

function renderHistoryTable(analyses) {
    const tbody = document.querySelector('#history-table tbody');
    if (!analyses || analyses.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center">No matching analysis records found.</td></tr>';
        return;
    }

    tbody.innerHTML = analyses.map(a => {
        const dateStr = a.created_at ? new Date(a.created_at).toLocaleString() : 'N/A';
        const sevClass = (a.severity || 'low').toLowerCase();
        return `
            <tr>
                <td>#${a.id}</td>
                <td><span class="badge ${a.analysis_type === 'URL' ? 'medium' : 'low'}">${a.analysis_type}</span></td>
                <td><code title="${escapeHtml(a.target)}">${truncate(a.target, 45)}</code></td>
                <td><strong>${a.risk_score.toFixed(1)}</strong></td>
                <td><span class="badge ${sevClass}">${a.severity}</span></td>
                <td><span style="font-size:12px; color:var(--text-secondary);">${truncate(a.summary || 'Analysis Complete', 40)}</span></td>
                <td>${dateStr}</td>
                <td>
                    <button class="btn btn-sm btn-outline" onclick="deleteAnalysis(${a.id})">Delete</button>
                </td>
            </tr>
        `;
    }).join('');
}

async function deleteAnalysis(id) {
    if (!confirm(`Are you sure you want to delete analysis record #${id}?`)) return;
    try {
        const res = await fetch(`/api/analyses/${id}`, { method: 'DELETE' });
        if (res.ok) {
            loadHistoryData();
            loadDashboardData();
        }
    } catch (err) {
        alert('Failed to delete analysis: ' + err.message);
    }
}

// 5. IOC Intelligence
function initIocFilters() {
    document.getElementById('ioc-type-filter').addEventListener('change', loadIocsData);
    document.getElementById('ioc-search-input').addEventListener('input', debounce(loadIocsData, 300));
}

async function loadIocsData() {
    const type = document.getElementById('ioc-type-filter').value;
    const search = document.getElementById('ioc-search-input').value.trim();

    let url = '/api/iocs?limit=200';
    if (type) url += `&ioc_type=${type}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;

    try {
        const res = await fetch(url);
        if (res.ok) {
            const iocs = await res.json();
            renderIocsTable(iocs);
        }
    } catch (err) {
        console.error('Failed to load IOCs:', err);
    }
}

function renderIocsTable(iocs) {
    const tbody = document.querySelector('#iocs-master-table tbody');
    if (!iocs || iocs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center">No Indicators of Compromise matching query.</td></tr>';
        return;
    }

    tbody.innerHTML = iocs.map(i => `
        <tr>
            <td><code>${i.type}</code></td>
            <td><strong>${escapeHtml(i.canonical_value)}</strong></td>
            <td><span class="badge low">${i.source}</span></td>
            <td><span class="badge ${i.confidence}">${i.confidence}</span></td>
            <td>${i.classification || '-'}</td>
            <td>${i.analysis_id ? `#${i.analysis_id}` : '-'}</td>
        </tr>
    `).join('');
}

// 6. Investigations
function initInvestigations() {
    document.getElementById('btn-open-create-inv-modal').addEventListener('click', openCreateInvModal);
    document.getElementById('btn-submit-create-inv').addEventListener('click', submitCreateInvestigation);
}

async function loadInvestigationsData() {
    try {
        const res = await fetch('/api/investigations');
        if (res.ok) {
            const invs = await res.json();
            state.investigations = invs;
            renderInvestigationsTable(invs);
        }
    } catch (err) {
        console.error('Failed to load investigations:', err);
    }
}

function renderInvestigationsTable(invs) {
    const tbody = document.querySelector('#investigations-table tbody');
    if (!invs || invs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="text-center">No investigation dossiers created. Click "New Investigation Case" to correlate analyses.</td></tr>';
        return;
    }

    tbody.innerHTML = invs.map(inv => {
        const dateStr = inv.created_at ? new Date(inv.created_at).toLocaleDateString() : 'N/A';
        const sevClass = (inv.severity || 'low').toLowerCase();
        return `
            <tr>
                <td><strong>${inv.id}</strong></td>
                <td><strong>${escapeHtml(inv.title)}</strong></td>
                <td><span class="badge low">${inv.status}</span></td>
                <td><strong>${inv.risk_score.toFixed(1)}</strong></td>
                <td><span class="badge ${sevClass}">${inv.severity}</span></td>
                <td>${inv.analyses_count}</td>
                <td><span class="badge ${inv.correlations_count > 0 ? 'critical' : 'low'}">${inv.correlations_count}</span></td>
                <td>${dateStr}</td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="viewInvestigationDetail('${inv.id}')">Inspect Dossier</button>
                </td>
            </tr>
        `;
    }).join('');
}

async function viewInvestigationDetail(id) {
    try {
        const res = await fetch(`/api/investigations/${id}`);
        if (!res.ok) throw new Error('Failed to retrieve investigation.');
        const inv = await res.json();

        const container = document.getElementById('investigation-detail-container');
        container.classList.remove('hidden');

        // Banner
        document.getElementById('inv-score').innerText = inv.risk_score.toFixed(0);
        const badge = document.getElementById('inv-badge');
        badge.innerText = inv.severity;
        badge.className = `score-badge ${inv.severity.toLowerCase()}`;
        document.getElementById('inv-detail-title').innerText = `${inv.id}: ${inv.title}`;
        document.getElementById('inv-detail-explanation').innerText = inv.explanation || 'Correlated forensic incident.';

        // Setup Export Buttons
        document.getElementById('btn-export-json').onclick = () => {
            window.open(`/api/reports/${inv.id}/json`, '_blank');
        };
        document.getElementById('btn-export-html').onclick = () => {
            window.open(`/api/reports/${inv.id}/html`, '_blank');
        };

        // Correlations Table
        const corrTbody = document.querySelector('#inv-correlations-table tbody');
        if (!inv.correlations || inv.correlations.length === 0) {
            corrTbody.innerHTML = '<tr><td colspan="6" class="text-center">No cross-source correlations identified across selected analyses.</td></tr>';
        } else {
            corrTbody.innerHTML = inv.correlations.map(c => `
                <tr>
                    <td><strong>${c.correlation_type}</strong></td>
                    <td><code>${escapeHtml(c.ioc_value)}</code></td>
                    <td>${c.source_a} &harr; ${c.source_b}</td>
                    <td>${c.evidence}</td>
                    <td>${c.time_delta_seconds !== null ? `${c.time_delta_seconds.toFixed(1)}s` : 'N/A'}</td>
                    <td><span class="badge critical">+${c.points.toFixed(0)} pts</span></td>
                </tr>
            `).join('');
        }

        // Timeline Stream
        const tlContainer = document.getElementById('inv-timeline-container');
        if (!inv.timeline || inv.timeline.length === 0) {
            tlContainer.innerHTML = '<p style="color:var(--text-muted);">No chronological timeline events recorded.</p>';
        } else {
            tlContainer.innerHTML = inv.timeline.map(t => {
                const tsStr = t.timestamp ? new Date(t.timestamp).toUTCString() : 'N/A';
                return `
                    <div class="timeline-item">
                        <div class="timeline-meta">
                            <span class="ts">${tsStr}</span>
                            <span>${t.event_type}</span>
                        </div>
                        <div class="timeline-body">
                            <h4>${escapeHtml(t.title)}</h4>
                            <p>${escapeHtml(t.details || '')}</p>
                            ${t.ioc_value ? `<div style="margin-top:4px;"><code>IOC: ${escapeHtml(t.ioc_value)}</code></div>` : ''}
                        </div>
                    </div>
                `;
            }).join('');
        }

        // Recommendations List
        const recsList = document.getElementById('inv-recs-list');
        if (!inv.recommendations || inv.recommendations.length === 0) {
            recsList.innerHTML = '<li>Continuous baseline network and DNS monitoring recommended.</li>';
        } else {
            recsList.innerHTML = inv.recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('');
        }

        container.scrollIntoView({ behavior: 'smooth' });
    } catch (err) {
        alert('Error viewing investigation: ' + err.message);
    }
}

async function openCreateInvModal() {
    const modal = document.getElementById('modal-create-investigation');
    modal.classList.remove('hidden');

    const selector = document.getElementById('inv-analyses-selector');
    selector.innerHTML = 'Loading available analyses...';

    try {
        const res = await fetch('/api/analyses?limit=50');
        if (res.ok) {
            const analyses = await res.json();
            if (analyses.length === 0) {
                selector.innerHTML = '<p style="color:var(--text-muted);">No analyses available. Run a URL or PCAP test first.</p>';
                return;
            }

            selector.innerHTML = analyses.map(a => `
                <label class="checkbox-item">
                    <input type="checkbox" name="selected_analyses" value="${a.id}" />
                    <span>#${a.id} [${a.analysis_type}] <strong>${escapeHtml(truncate(a.target, 35))}</strong> (${a.severity})</span>
                </label>
            `).join('');
        }
    } catch (err) {
        selector.innerHTML = 'Failed to load analyses.';
    }
}

function closeCreateInvModal() {
    document.getElementById('modal-create-investigation').classList.add('hidden');
}

async function submitCreateInvestigation() {
    const title = document.getElementById('inv-title-input').value.trim();
    const explanation = document.getElementById('inv-desc-input').value.trim();

    const checked = Array.from(document.querySelectorAll('input[name="selected_analyses"]:checked'))
        .map(cb => parseInt(cb.value));

    if (!title) {
        alert('Please specify an investigation title.');
        return;
    }

    if (checked.length === 0) {
        alert('Please select at least one analysis record to link.');
        return;
    }

    try {
        const res = await fetch('/api/investigations', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                title: title,
                explanation: explanation,
                analysis_ids: checked,
            }),
        });

        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Failed to create investigation.');
        }

        const data = await res.json();
        closeCreateInvModal();
        loadInvestigationsData();
        viewInvestigationDetail(data.id);
    } catch (err) {
        alert('Error creating case: ' + err.message);
    }
}

// 7. Samples Loader
async function loadSamplesList() {
    try {
        const res = await fetch('/api/samples');
        if (res.ok) {
            const data = await res.json();
            const pcapBox = document.getElementById('pcap-samples-buttons');
            if (data.pcap_samples && data.pcap_samples.length > 0) {
                pcapBox.innerHTML = data.pcap_samples.map(p => `
                    <button class="pill-btn ${p.filename.includes('clean') ? 'success' : 'danger'}"
                            onclick="loadSamplePcap('${p.filename}')">
                        ${p.filename}
                    </button>
                `).join('');
            } else {
                pcapBox.innerHTML = '<span style="color:var(--text-muted); font-size:12px;">No preloaded PCAPs found in samples/ directory.</span>';
            }
        }
    } catch (err) {
        console.error('Failed to load sample list:', err);
    }
}

async function loadSamplePcap(filename) {
    alert(`Loading synthetic sample "${filename}". File will be ingested into the Scapy parser.`);
    // Fetch binary from /samples/ or trigger server file ingestion
    try {
        const response = await fetch(`/samples/${filename}`);
        if (!response.ok) {
            // Fallback: create mock upload with file name for demo
            alert(`Direct fetch of sample file '${filename}'. In production, drag and drop the file from the samples folder.`);
            return;
        }
        const blob = await response.blob();
        const file = new File([blob], filename, { type: 'application/vnd.tcpdump.pcap' });
        handlePcapUpload(file);
    } catch (e) {
        alert(`Sample '${filename}' is located in the local samples/ directory. Drag and drop it into the dropzone.`);
    }
}

// Canvas Visualizations (Zero CDN dependencies)
function drawSeverityChart(stats) {
    const canvas = document.getElementById('chart-severity');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const categories = ['Critical', 'High', 'Medium', 'Low'];
    // Derive approximate distribution from stats
    const total = stats.total_detections || 1;
    const critical = stats.critical_detections || 0;
    const high = Math.max(0, Math.floor((total - critical) * 0.4));
    const medium = Math.max(0, Math.floor((total - critical) * 0.4));
    const low = Math.max(0, total - critical - high - medium);

    const values = [critical, high, medium, low];
    const colors = ['#ef4444', '#f97316', '#eab308', '#10b981'];

    const barWidth = 45;
    const gap = 35;
    const startX = 35;
    const maxVal = Math.max(...values, 5);
    const chartHeight = 140;
    const baseY = 160;

    values.forEach((val, idx) => {
        const h = (val / maxVal) * chartHeight;
        const x = startX + idx * (barWidth + gap);
        const y = baseY - h;
        const safeH = Math.max(0, h);

        // Bar
        ctx.fillStyle = colors[idx];
        ctx.beginPath();
        if (typeof ctx.roundRect === 'function' && safeH > 0) {
            ctx.roundRect(x, y, barWidth, safeH, [4, 4, 0, 0]);
        } else {
            ctx.rect(x, y, barWidth, safeH);
        }
        ctx.fill();

        // Label
        ctx.fillStyle = '#94a3b8';
        ctx.font = '10px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(categories[idx], x + barWidth / 2, baseY + 18);

        // Value
        ctx.fillStyle = '#f8fafc';
        ctx.font = 'bold 11px sans-serif';
        ctx.fillText(val, x + barWidth / 2, y - 6);
    });
}

function drawPostureChart(stats) {
    const canvas = document.getElementById('chart-posture');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const urlCount = stats.url_analyses || 0;
    const pcapCount = stats.pcap_analyses || 0;

    const data = [
        { label: 'URL Assessments', value: urlCount, color: '#00e5ff' },
        { label: 'PCAP Ingestions', value: pcapCount, color: '#3b82f6' },
    ];

    const centerX = 100;
    const centerY = 100;
    const radius = 65;

    let totalVal = data.reduce((acc, d) => acc + d.value, 0);
    if (totalVal === 0) {
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, 0, 2 * Math.PI);
        ctx.strokeStyle = '#374151';
        ctx.lineWidth = 14;
        ctx.stroke();

        ctx.fillStyle = '#64748b';
        ctx.font = '11px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('No data yet', centerX, centerY + 4);
        return;
    }

    let startAngle = -Math.PI / 2;

    data.forEach(item => {
        if (item.value <= 0) return;
        const sliceAngle = (item.value / totalVal) * (2 * Math.PI);
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
        ctx.closePath();
        ctx.fillStyle = item.color;
        ctx.fill();
        startAngle += sliceAngle;
    });

    // Donut hole
    ctx.beginPath();
    ctx.arc(centerX, centerY, 38, 0, 2 * Math.PI);
    ctx.fillStyle = '#111827';
    ctx.fill();

    // Legend
    let legendY = 70;
    data.forEach(item => {
        ctx.fillStyle = item.color;
        ctx.fillRect(190, legendY, 12, 12);

        ctx.fillStyle = '#f8fafc';
        ctx.font = '11px sans-serif';
        ctx.textAlign = 'left';
        ctx.fillText(`${item.label} (${item.value})`, 210, legendY + 10);
        legendY += 28;
    });
}

// Utility Helpers
function truncate(str, maxLen) {
    if (!str) return '';
    return str.length > maxLen ? str.slice(0, maxLen) + '...' : str;
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function debounce(func, wait) {
    let timeout;
    return function (...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}
