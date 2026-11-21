(function () {
    const daysSelect = document.getElementById('statisticsDays');
    const userControl = document.getElementById('statisticsUserControl');
    const userSelect = document.getElementById('statisticsUser');
    const errorBox = document.getElementById('statisticsError');
    const loadingBox = document.getElementById('statisticsLoading');
    const emptyBox = document.getElementById('statisticsEmpty');
    const globalContainer = document.getElementById('globalDashboard');
    const individualContainer = document.getElementById('individualDashboard');
    const individualTitle = document.getElementById('individualTitle');
    let requestId = 0;
    let isAdmin = false;

    function escapeHtml(value) {
        return String(value == null ? '' : value).replace(/[&<>"']/g, function (char) {
            return {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#39;'
            }[char];
        });
    }

    function count(value) {
        if (value == null || !Number.isFinite(Number(value))) return '0';
        return Number(value).toLocaleString('it-IT');
    }

    function milliseconds(value) {
        if (value == null || !Number.isFinite(Number(value))) return 'N/D';
        return Math.round(Number(value)).toLocaleString('it-IT') + ' ms';
    }

    function percentage(value) {
        if (value == null || !Number.isFinite(Number(value))) return 'N/D';
        return Number(value).toLocaleString('it-IT', {
            maximumFractionDigits: 1
        }) + '%';
    }

    function metricCard(label, value, note) {
        return '<div class="col-6 col-md-4 col-xl-3"><div class="card metric-card">' +
            '<div class="card-body py-3"><div class="metric-value">' +
            escapeHtml(value) + '</div><div class="metric-label">' +
            escapeHtml(label) + '</div>' +
            (note ? '<small class="text-muted">' + escapeHtml(note) + '</small>' : '') +
            '</div></div></div>';
    }

    function metricsGrid(cards) {
        return '<div class="row g-3">' + cards.join('') + '</div>';
    }

    function renderAi(ai) {
        ai = ai || {};
        const tokens = ai.tokens || {};
        const cards = [
            metricCard('Assessment', count(ai.assessments)),
            metricCard('Chiamate al provider', count(ai.provider_call_count)),
            metricCard('Cache hit', count(ai.cache_hit_count)),
            metricCard('Assessment fresh', count(ai.fresh_count)),
            metricCard('Refresh forzati', count(ai.refresh_count)),
            metricCard('Errori assessment', count(ai.failure_count)),
            metricCard('Latenza mediana provider', milliseconds(ai.latency_median_ms)),
            metricCard('Latenza P95 provider', milliseconds(ai.latency_p95_ms)),
            metricCard('Token input', tokens.input_tokens == null ? 'N/D' : count(tokens.input_tokens)),
            metricCard('Token output', tokens.output_tokens == null ? 'N/D' : count(tokens.output_tokens)),
            metricCard('Token totali', tokens.total_tokens == null ? 'N/D' : count(tokens.total_tokens),
                count(ai.token_events) + ' assessment con token disponibili'),
            metricCard('Indicatori', count(ai.indicators_count)),
            metricCard('Report ricevuti da Cortex', count(ai.reports_count)),
            metricCard('Report passati all’AI', count(ai.ai_input_count))
        ];
        let html = '<h3 class="h5 dashboard-section-title mt-0">Assessment AI</h3>' +
            metricsGrid(cards);

        const daily = ai.daily || [];
        if (!daily.length) {
            html += '<p class="statistics-empty mt-3 mb-0">Nessun assessment nel periodo.</p>';
            return html;
        }

        const maxDaily = Math.max.apply(null, daily.map(function (item) {
            return (item.fresh || 0) + (item.refresh || 0) + (item.cache || 0) || 1;
        }));
        const rows = daily.slice().reverse().map(function (item) {
            const fresh = Number(item.fresh) || 0;
            const refresh = Number(item.refresh) || 0;
            const cache = Number(item.cache) || 0;
            const freshWidth = fresh * 100 / maxDaily;
            const refreshWidth = refresh * 100 / maxDaily;
            const cacheWidth = cache * 100 / maxDaily;
            return '<tr><td>' + escapeHtml(item.date) + '</td><td>' + count(fresh) +
                '</td><td>' + count(refresh) + '</td><td>' + count(cache) +
                '</td><td>' + count(item.failures) + '</td><td><div class="daily-bar" role="img" aria-label="Fresh ' +
                count(fresh) + ', refresh ' + count(refresh) + ', cache ' + count(cache) + '">' +
                '<span class="daily-fresh" style="width:' + freshWidth + '%"></span>' +
                '<span class="daily-refresh" style="width:' + refreshWidth + '%"></span>' +
                '<span class="daily-cache" style="width:' + cacheWidth + '%"></span>' +
                '</div></td></tr>';
        }).join('');
        html += '<h4 class="h6 dashboard-section-title">Assessment nel tempo</h4>' +
            '<div class="table-responsive"><table class="table table-sm table-striped statistics-table">' +
            '<thead><tr><th>Data</th><th>Fresh</th><th>Refresh forzati</th><th>Cache hit</th>' +
            '<th>Errori</th><th>Distribuzione</th></tr></thead><tbody>' + rows +
            '</tbody></table></div>' +
            '<div class="small text-muted"><span class="text-success">■</span> Provider fresh ' +
            '<span class="text-warning ms-2">■</span> Refresh forzato ' +
            '<span class="text-primary ms-2">■</span> Cache hit</div>';
        return html;
    }

    function rankingTable(title, entries) {
        entries = entries || [];
        const rows = entries.map(function (entry) {
            return '<tr><td>' + escapeHtml(entry.name) + '</td><td>' +
                escapeHtml(entry.data_type) + '</td><td>' + count(entry.jobs) +
                '</td><td>' + percentage(entry.success_rate) + '</td></tr>';
        }).join('');
        return '<div class="col-12 col-xl-6"><h5 class="h6 mt-3">' +
            escapeHtml(title) + '</h5>' +
            (rows
                ? '<div class="table-responsive"><table class="table table-sm table-striped statistics-table">' +
                  '<thead><tr><th>Nome</th><th>Tipo</th><th>Job</th><th>Successo</th></tr></thead><tbody>' +
                  rows + '</tbody></table></div>'
                : '<p class="statistics-empty">Dati insufficienti.</p>') +
            '</div>';
    }

    function renderJobs(title, stats, includeIndicators) {
        stats = stats || {};
        const cards = [
            metricCard('Job', count(stats.jobs)),
            metricCard('Successo', count(stats.success_count)),
            metricCard('Fallimento', count(stats.failure_count)),
            metricCard('Deleted', count(stats.deleted_count)),
            metricCard('Timeout', count(stats.timeout_count)),
            metricCard('Esito non osservato', count(stats.unobserved_count),
                'Esclusi dal tasso di successo'),
            metricCard('Tasso di successo', percentage(stats.success_rate),
                count(stats.observed_count) + ' esiti osservati'),
            metricCard('Durata mediana', milliseconds(stats.duration_median_ms)),
            metricCard('Durata P95', milliseconds(stats.duration_p95_ms))
        ];
        if (stats.invalid_data_type_count) {
            cards.splice(5, 0, metricCard('Tipo di dato non valido',
                count(stats.invalid_data_type_count)));
        }
        if (includeIndicators) {
            cards.push(metricCard('Indicatori elaborati',
                count(stats.indicators_processed)));
        }

        const rankings = stats;
        return '<h3 class="h5 dashboard-section-title">' + escapeHtml(title) + '</h3>' +
            metricsGrid(cards) +
            '<div class="row">' +
            rankingTable('Più usati', rankings.most_used) +
            rankingTable('Meno usati', rankings.least_used) +
            rankingTable('Più affidabili', rankings.most_reliable) +
            rankingTable('Meno affidabili', rankings.least_reliable) +
            '</div>';
    }

    function renderDashboard(container, dashboard) {
        dashboard = dashboard || {};
        container.innerHTML = renderAi(dashboard.ai) +
            renderJobs('Analyzer', dashboard.analyzer, false) +
            renderJobs('Responder', dashboard.responder, true);
    }

    function showError(message, loginRequired) {
        errorBox.textContent = message;
        if (loginRequired) {
            const loginButton = document.createElement('button');
            loginButton.type = 'button';
            loginButton.className = 'btn btn-sm btn-outline-danger ms-2';
            loginButton.textContent = 'Accedi';
            loginButton.addEventListener('click', function () {
                if (typeof window.handleLogin === 'function') window.handleLogin();
            });
            errorBox.appendChild(loginButton);
        }
        errorBox.classList.remove('d-none');
    }

    async function requestJson(url) {
        const response = await fetch(url, { credentials: 'same-origin' });
        let body = {};
        try {
            body = await response.json();
        } catch (error) {
            throw new Error('Risposta non valida dal server.');
        }
        return { response: response, body: body };
    }

    async function populateUsers(days, selectedUsername, id) {
        const result = await requestJson('/api/statistics/users?days=' + encodeURIComponent(days));
        if (id !== requestId) return;
        if (!result.response.ok) {
            throw new Error(result.response.status === 503
                ? 'Database statistiche non disponibile.'
                : 'Impossibile caricare l’elenco degli utenti.');
        }

        const users = result.body.users || [];
        userSelect.replaceChildren();
        if (selectedUsername && !users.includes(selectedUsername)) {
            users.unshift(selectedUsername);
        }
        users.forEach(function (username) {
            const option = document.createElement('option');
            option.value = username;
            option.textContent = username;
            userSelect.appendChild(option);
        });
        userSelect.value = selectedUsername || users[0] || '';
        userControl.classList.remove('d-none');
    }

    async function loadDashboard() {
        const id = ++requestId;
        const days = daysSelect.value;
        const selectedUsername = isAdmin ? userSelect.value : '';
        const params = new URLSearchParams({ days: days });
        if (selectedUsername) params.set('username', selectedUsername);

        errorBox.classList.add('d-none');
        errorBox.replaceChildren();
        emptyBox.classList.add('d-none');
        loadingBox.classList.remove('d-none');

        try {
            const result = await requestJson('/api/statistics/aggregate?' + params.toString());
            if (id !== requestId) return;
            if (result.response.status === 401) {
                throw new Error('Accedi per visualizzare le statistiche.');
            }
            if (result.response.status === 503) {
                throw new Error('Statistiche non disponibili: database disabilitato o non raggiungibile.');
            }
            if (!result.response.ok) {
                throw new Error(result.body.error || 'Errore durante il caricamento delle statistiche.');
            }

            const data = result.body;
            isAdmin = data.is_admin;
            if (isAdmin) {
                await populateUsers(days, data.individual_username, id);
                if (id !== requestId) return;
            } else {
                userControl.classList.add('d-none');
            }

            individualTitle.textContent = isAdmin
                ? 'Dati individuali: ' + data.individual_username
                : 'I miei dati';
            renderDashboard(globalContainer, data.dashboard);
            renderDashboard(individualContainer, data.individual_dashboard);

            const ai = data.dashboard && data.dashboard.ai;
            const analyzer = data.dashboard && data.dashboard.analyzer;
            const responder = data.dashboard && data.dashboard.responder;
            const total = (ai ? ai.assessments : 0) +
                (analyzer ? analyzer.jobs : 0) + (responder ? responder.jobs : 0);
            emptyBox.classList.toggle('d-none', total > 0);
        } catch (error) {
            if (id !== requestId) return;
            const loginRequired = error.message.indexOf('Accedi') === 0;
            showError(error.message, loginRequired);
        } finally {
            if (id === requestId) loadingBox.classList.add('d-none');
        }
    }

    daysSelect.addEventListener('change', loadDashboard);
    userSelect.addEventListener('change', function () {
        if (isAdmin) loadDashboard();
    });
    window.addEventListener('fuco-auth-state-changed', function (event) {
        if (event.detail && event.detail.authenticated) {
            loadDashboard();
            return;
        }
        requestId += 1;
        isAdmin = false;
        userControl.classList.add('d-none');
        globalContainer.replaceChildren();
        individualContainer.replaceChildren();
        loadingBox.classList.add('d-none');
        errorBox.replaceChildren();
        showError('Accedi per visualizzare le statistiche.', true);
    });
    loadDashboard();
})();
