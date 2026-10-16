/**
 * responder_actions.js - Client-side logic for Responder actions
 * SESSION-BASED VERSION - No username/password required per action
 */

(function() {
    if (window.__responderActionsLoaded) {
        return;
    }
    if (window.ResponderModal) {
        window.__responderActionsLoaded = true;
        return;
    }
    window.__responderActionsLoaded = true;

function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

// ============ Modal Management ============

class ResponderModal {
    constructor() {
        this.modal = null;
        this.currentObservable = null;
        this.currentDataType = null;
        this.currentResponders = [];
        this.init();
    }

    getDefaultTlp() {
        const value = Number(window.FUCO_DEFAULT_TLP);
        if (!Number.isInteger(value) || value < 0 || value > 3) {
            return 1;
        }
        return value;
    }

    getDefaultPap() {
        const value = Number(window.FUCO_DEFAULT_PAP);
        if (!Number.isInteger(value) || value < 0 || value > 3) {
            return 1;
        }
        return value;
    }

    init() {
        if (!document.getElementById('responderModal')) {
            this.createModal();
        }
        this.modal = document.getElementById('responderModal');
    }

    createModal() {
        const modalHTML = `
        <div class="modal fade" id="responderModal" tabindex="-1" role="dialog">
            <div class="modal-dialog modal-lg" role="document">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Execute Responder Action</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <!-- Observable Info -->
                        <div class="alert alert-info">
                            <strong>Observable:</strong> <span id="modalObservable"></span><br>
                            <strong>Type:</strong> <span id="modalDataType"></span>
                        </div>

                        <!-- Responder Selection -->
                        <div class="form-group">
                            <label>Select Responders:</label>
                            <div id="responderSelect"></div>
                        </div>

                        <!-- TLP/PAP -->
                        <div class="row">
                            <div class="col-md-6">
                                <label for="tlpSelect">TLP Level:</label>
                                <select id="tlpSelect" class="form-control">
                                    <option value="0">WHITE (0)</option>
                                    <option value="1">GREEN (1)</option>
                                    <option value="2">AMBER (2)</option>
                                    <option value="3">RED (3)</option>
                                </select>
                            </div>
                            <div class="col-md-6">
                                <label for="papSelect">PAP Level:</label>
                                <select id="papSelect" class="form-control">
                                    <option value="0">WHITE (0)</option>
                                    <option value="1">GREEN (1)</option>
                                    <option value="2">AMBER (2)</option>
                                    <option value="3">RED (3)</option>
                                </select>
                            </div>
                        </div>

                        <!-- Message/Notes -->
                        <div class="form-group mt-3">
                            <label for="responderMessage">Message (optional):</label>
                            <textarea id="responderMessage" class="form-control" rows="2" 
                                      placeholder="Add notes or reason for this action"></textarea>
                        </div>

                        <!-- Status Messages -->
                        <div id="responderStatus" class="mt-3"></div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" id="closeResponderBtn" data-bs-dismiss="modal" style="display:none;">Close</button>
                        <button type="button" class="btn btn-danger" id="executeResponderBtn">
                            <i class="fas fa-bolt"></i> Execute Action
                        </button>
                    </div>
                </div>
            </div>
        </div>
        `;

        document.body.insertAdjacentHTML('beforeend', modalHTML);

        const tlpSelect = document.getElementById('tlpSelect');
        if (tlpSelect) {
            tlpSelect.value = String(this.getDefaultTlp());
        }
        const papSelect = document.getElementById('papSelect');
        if (papSelect) {
            papSelect.value = String(this.getDefaultPap());
        }

        document.getElementById('executeResponderBtn').addEventListener('click', () => {
            this.executeResponders();
        });
    }

    async show(observable, dataType, responders = null) {
        // ============ NEW: Check authentication first ============
        const authStatus = await this.checkAuth();
        if (!authStatus.authenticated) {
            alert('Please login first to execute responder actions.\n\nClick "Login to Cortex" button in the top-right corner.');
            return;
        }

        this.currentObservable = observable;
        this.currentDataType = dataType;

        document.getElementById('modalObservable').textContent = observable;
        document.getElementById('modalDataType').textContent = dataType;

        if (!responders) {
            await this.loadResponders(dataType);
        } else {
            this.populateResponders(responders);
        }

        document.getElementById('responderMessage').value = '';
        document.getElementById('responderStatus').innerHTML = '';
        const closeBtn = document.getElementById('closeResponderBtn');
        if (closeBtn) {
            closeBtn.style.display = 'none';
        }

        $(this.modal).modal('show');
    }

    async checkAuth() {
        try {
            const response = await fetch('/api/auth/status');
            return await response.json();
        } catch (error) {
            console.error('Error checking auth:', error);
            return { authenticated: false };
        }
    }

    async loadResponders(dataType) {
        try {
            const response = await fetch(`/api/responder/for-observable?dataType=${encodeURIComponent(dataType)}`);
            const data = await response.json();

            if (data.success && data.responders.length > 0) {
                this.populateResponders(data.responders);
            } else {
                this.showError('No responders available for this data type');
            }
        } catch (error) {
            console.error('Error loading responders:', error);
            this.showError('Failed to load responders: ' + error.message);
        }
    }

    populateResponders(responders) {
        if (!this.picker) {
            this.picker = new ResponderPicker(document.getElementById('responderSelect'));
        }
        this.picker.setItems(responders.map(resp => ({
            id: resp.id,
            label: `${resp.name} (${resp.version})`,
            title: resp.description || ''
        })));
        this.picker.focusSearch();

        this.currentResponders = responders;
    }

    async executeResponders() {
        const message = document.getElementById('responderMessage').value.trim();
        const tlp = parseInt(document.getElementById('tlpSelect').value);
        const pap = parseInt(document.getElementById('papSelect').value);

        const selectedOptions = this.picker ? this.picker.getSelectedItems() : [];

        if (selectedOptions.length === 0) {
            this.showError('Please select at least one responder');
            return;
        }

        const statusDiv = document.getElementById('responderStatus');
        if (statusDiv) {
            statusDiv.innerHTML = '';
        }

        // Disable button
        const executeBtn = document.getElementById('executeResponderBtn');
        executeBtn.disabled = true;
        executeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Executing...';

        const results = [];

        try {
            // Execute for each selected responder
            for (const option of selectedOptions) {
                const responderId = option.id;
                const responderName = option.label;

                try {
                    this.showInfo(`Executing ${responderName}...`);

                    // ============ MODIFICATO: NO username/password! ============
                    const result = await this.executeResponder({
                        observable: this.currentObservable,
                        dataType: this.currentDataType,
                        responderId: responderId,
                        tlp: tlp,
                        pap: pap,
                        message: message || undefined
                    });

                    results.push({ name: responderName, success: true, data: result });
                    this.showSuccess(`✓ ${responderName}: Job ${result.job_id} started`);

                    try {
                        const jobResult = await this.pollResponderJob(result.job_id);
                        if (jobResult && jobResult.status) {
                            if (jobResult.status === 'Success') {
                                this.showSuccess(`✓ ${responderName}: Completed (Job ${result.job_id})`);
                            } else if (jobResult.status === 'Failure') {
                                this.showError(`✗ ${responderName}: Failed (Job ${result.job_id})`);
                            } else {
                                this.showWarning(`• ${responderName}: ${jobResult.status} (Job ${result.job_id})`);
                            }
                        }
                    } catch (pollError) {
                        this.showWarning(`• ${responderName}: Status check failed (${pollError.message})`);
                    }

                } catch (error) {
                    console.error(`Error executing ${responderName}:`, error);
                    
                    // If 401 error, show login message
                    if (error.message.includes('Authentication required')) {
                        this.showError('Session expired. Please login again.');
                        setTimeout(() => location.reload(), 2000);
                        break;
                    }
                    
                    results.push({ name: responderName, success: false, error: error.message });
                    this.showError(`✗ ${responderName}: ${error.message}`);
                }
            }

            // Show summary
            const successful = results.filter(r => r.success).length;
            const total = results.length;

            if (total > 0) {
                if (successful === total) {
                    this.showSuccess(`All ${total} responder(s) executed successfully!`);
                } else {
                    this.showWarning(`${successful}/${total} responder(s) executed successfully`);
                }
            }
        } finally {
            // Re-enable button
            executeBtn.disabled = false;
            executeBtn.innerHTML = '<i class="fas fa-bolt"></i> Execute Action';
            const closeBtn = document.getElementById('closeResponderBtn');
            if (closeBtn) {
                closeBtn.style.display = 'inline-block';
            }
        }
    }

    async executeResponder(params) {
        const response = await fetch('/api/responder/execute', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify(params)  // NO username/password!
        });
        const contentType = response.headers.get('content-type') || '';

        if (!response.ok) {
            if (contentType.includes('application/json')) {
                const error = await response.json();
                throw new Error(error.error || 'Execution failed');
            }
            if (response.status === 401 || response.status === 403 || response.status === 400) {
                throw new Error('Session expired or invalid CSRF token. Please reload the page and login again.');
            }
            throw new Error('Execution failed. Please reload the page and try again.');
        }

        if (!contentType.includes('application/json')) {
            throw new Error('Unexpected response format. Please reload the page and try again.');
        }

        return await response.json();
    }

    async pollResponderJob(jobId) {
        const response = await fetch(`/api/responder/poll/${encodeURIComponent(jobId)}`);
        const contentType = response.headers.get('content-type') || '';
        if (!response.ok) {
            if (contentType.includes('application/json')) {
                const error = await response.json();
                throw new Error(error.error || 'Status check failed');
            }
            throw new Error('Status check failed');
        }
        if (!contentType.includes('application/json')) {
            throw new Error('Unexpected response format');
        }
        const data = await response.json();
        return data.job;
    }

    showError(message) {
        const statusDiv = document.getElementById('responderStatus');
        statusDiv.innerHTML += `<div class="alert alert-danger alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>`;
    }

    showSuccess(message) {
        const statusDiv = document.getElementById('responderStatus');
        statusDiv.innerHTML += `<div class="alert alert-success alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>`;
    }

    showInfo(message) {
        const statusDiv = document.getElementById('responderStatus');
        statusDiv.innerHTML += `<div class="alert alert-info alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>`;
    }

    showWarning(message) {
        const statusDiv = document.getElementById('responderStatus');
        statusDiv.innerHTML += `<div class="alert alert-warning alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>`;
    }
}

// ============ Quick Action Buttons ============

function addResponderButtons(observable, dataType, containerId) {
    const container = document.getElementById(containerId);
    if (!container) {
        console.error(`Container ${containerId} not found`);
        return;
    }

    const buttonsHTML = `
        <button class="action-btn-header btn-respond responder-action-btn requires-auth"
                data-requires-auth="true"
                data-observable="${observable}"
                data-datatype="${dataType}">
            <i class="fas fa-shield-alt"></i> Respond
        </button>
    `;

    container.innerHTML = buttonsHTML;

    if (typeof window.updateAuthDependentUI === 'function') {
        window.updateAuthDependentUI(!!(window.authState && window.authState.authenticated));
    }

    container.querySelector('.responder-action-btn').addEventListener('click', function() {
        const obs = this.getAttribute('data-observable');
        const dt = this.getAttribute('data-datatype');
        if (window.authState && !window.authState.authenticated) {
            if (typeof window.handleLogin === 'function') {
                window.handleLogin();
            }
            return;
        }
        window.responderModal.show(obs, dt);
    });
}

// ============ Initialization ============

// ============ Searchable checkbox picker (shared by single and bulk) ============

class ResponderPicker {
    constructor(container) {
        this.container = container;
        this.items = [];
        this.selected = new Set();
        this.filter = '';
        this.render();
    }

    render() {
        this.container.innerHTML = `
            <input type="search" class="form-control mb-2" placeholder="Search responders..." autocomplete="off" data-role="search">
            <div class="d-flex justify-content-between align-items-center mb-1 small">
                <span data-role="count" class="text-muted"></span>
                <span>
                    <a href="#" data-role="select-visible">Select visible</a> |
                    <a href="#" data-role="clear-visible">Clear visible</a> |
                    <a href="#" data-role="clear-all">Clear all</a>
                </span>
            </div>
            <div data-role="list" class="border rounded p-2" style="max-height: 220px; overflow-y: auto;"></div>
            <div data-role="chips" class="mt-2"></div>`;
        const q = role => this.container.querySelector(`[data-role="${role}"]`);
        this.searchEl = q('search');
        this.listEl = q('list');
        this.countEl = q('count');
        this.chipsEl = q('chips');

        this.searchEl.addEventListener('input', () => {
            this.filter = this.searchEl.value.trim().toLowerCase();
            this.renderList();
        });
        this.searchEl.addEventListener('keydown', e => {
            if (e.key === 'Enter') e.preventDefault();
        });
        const bind = (role, fn) => q(role).addEventListener('click', e => {
            e.preventDefault();
            fn();
            this.renderList();
            this.renderChips();
        });
        bind('select-visible', () => this.visibleItems().forEach(i => this.selected.add(i.id)));
        bind('clear-visible', () => this.visibleItems().forEach(i => this.selected.delete(i.id)));
        bind('clear-all', () => this.selected.clear());
    }

    setItems(items) {
        this.items = items;
        this.selected.clear();
        this.filter = '';
        this.searchEl.value = '';
        this.renderList();
        this.renderChips();
    }

    visibleItems() {
        return this.items.filter(i => i.label.toLowerCase().includes(this.filter));
    }

    getSelectedIds() {
        return this.items.filter(i => this.selected.has(i.id)).map(i => i.id);
    }

    getSelectedItems() {
        return this.items.filter(i => this.selected.has(i.id));
    }

    focusSearch() {
        this.searchEl.focus();
    }

    renderList() {
        this.listEl.innerHTML = '';
        const visible = this.visibleItems();
        if (visible.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'text-muted small';
            empty.textContent = this.items.length ? 'No responders found' : 'No responders available';
            this.listEl.appendChild(empty);
        }
        visible.forEach(item => {
            const row = document.createElement('div');
            row.className = 'form-check';
            const input = document.createElement('input');
            input.type = 'checkbox';
            input.className = 'form-check-input';
            input.checked = this.selected.has(item.id);
            input.addEventListener('change', () => {
                if (input.checked) this.selected.add(item.id); else this.selected.delete(item.id);
                this.renderChips();
            });
            const label = document.createElement('label');
            label.className = 'form-check-label';
            label.style.cursor = 'pointer';
            label.textContent = item.label;
            label.title = item.title || '';
            label.prepend(input);
            row.appendChild(label);
            this.listEl.appendChild(row);
        });
        this.countEl.textContent = `${visible.length} of ${this.items.length} shown`;
    }

    renderChips() {
        this.chipsEl.innerHTML = '';
        const selected = this.getSelectedItems();
        const summary = document.createElement('div');
        summary.className = 'small text-muted mb-1';
        summary.textContent = `${selected.length} selected`;
        this.chipsEl.appendChild(summary);
        selected.forEach(item => {
            const chip = document.createElement('span');
            chip.className = 'badge bg-secondary badge-secondary me-1 mb-1';
            chip.style.cursor = 'pointer';
            chip.title = 'Click to remove';
            chip.textContent = `${item.label} \u00d7`;
            chip.addEventListener('click', () => {
                this.selected.delete(item.id);
                this.renderList();
                this.renderChips();
            });
            this.chipsEl.appendChild(chip);
        });
    }
}

document.addEventListener('DOMContentLoaded', function() {
    if (!window.responderModal) {
        window.responderModal = new ResponderModal();
        console.log('Responder modal initialized (session-based auth)');
    }
});

// ============ Export ============

window.ResponderModal = ResponderModal;
window.ResponderPicker = ResponderPicker;
window.addResponderButtons = addResponderButtons;

})();
