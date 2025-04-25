// dane_modal.js - DANE Modal Implementation

/**
 * Create HTML for DANE modal
 * @param {string} modalId - ID for the modal
 * @param {string} domain - Domain name
 * @param {Object} data - DANE validation data
 * @returns {string} - Modal HTML
 */
function createDANEModal(modalId, domain, data) {
    if (!data || !data.results || !data.state) {
        return `
        <div id="${modalId}" class="modal">
            <div class="modal-content">
                <span class="close-modal" onclick="closeModal('${modalId}')">&times;</span>
                <h3>DANE Details - ${domain}</h3>
                <p>No DANE data available for this domain.</p>
            </div>
        </div>`;
    }

    const resultsData = data.results;
    const validationState = data.state;

    // Create tab buttons
    let tabButtons = '';
    let tabContents = '';

    // Determine which tab to make active initially and what data key to use
    let currentDataKey = null;
    if (resultsData.domain_ns) {
        currentDataKey = 'domain_ns';
    } else if (resultsData.domain_mx) {
        currentDataKey = 'domain_mx';
    } else if (resultsData.mailserver_ns) {
        currentDataKey = 'mailserver_ns';
    }

    // Nameserver of Domain tab button
    if (resultsData.domain_ns) {
        const state = validationState['Nameserver of Domain']?.toLowerCase() || 'not-found';
        tabButtons += `
            <button class="tab-button ${currentDataKey === 'domain_ns' ? 'active' : ''}"
                    onclick="showTab('${modalId}-domain-ns')">
                <i class="fas fa-server"></i> Nameserver of Domain
                ${getDANEStatusIcon(state, 'Nameserver of Domain')}
            </button>`;

        // Build Nameserver of Domain tab content
        tabContents += `
            <div id="${modalId}-domain-ns"
                 class="tab-content ${currentDataKey === 'domain_ns' ? 'active' : ''}">
                <table class="validation-table validation-table details-table">
                    <thead>
                    <tr>
                        <th>Server</th>
                        <th>TLSA Records</th>
                        <th>Validation</th>
                    </tr>
                    </thead>
                    <tbody>
                    ${createDANEServerRows(resultsData.domain_ns, 'domain_ns')}
                    </tbody>
                </table>
            </div>`;
    }

    // Mail Server of Domain tab button
    if (resultsData.domain_mx) {
        const state = validationState['Mail Server of Domain']?.toLowerCase() || 'not-found';
        tabButtons += `
            <button class="tab-button ${currentDataKey === 'domain_mx' ? 'active' : ''}"
                    onclick="showTab('${modalId}-domain-mx')">
                <i class="fas fa-envelope"></i> Mail Server of Domain
                ${getDANEStatusIcon(state, 'Mail Server of Domain')}
            </button>`;

        // Build Mail Server of Domain tab content
        tabContents += `
            <div id="${modalId}-domain-mx"
                 class="tab-content ${currentDataKey === 'domain_mx' ? 'active' : ''}">
                <table class="validation-table details-table">
                    <thead>
                    <tr>
                        <th>Server</th>
                        <th>TLSA Records</th>
                        <th>Validation</th>
                    </tr>
                    </thead>
                    <tbody>
                    ${createDANEServerRows(resultsData.domain_mx, 'domain_mx')}
                    </tbody>
                </table>
            </div>`;
    }

    // Nameserver of Mail Server tab button
    if (resultsData.mailserver_ns) {
        const state = validationState['Nameserver of Mail Server']?.toLowerCase() || 'not-found';
        tabButtons += `
            <button class="tab-button ${currentDataKey === 'mailserver_ns' ? 'active' : ''}"
                    onclick="showTab('${modalId}-mailserver-ns')">
                <i class="fas fa-server"></i> Nameserver of Mail Server
                ${getDANEStatusIcon(state, 'Nameserver of Mail Server')}
            </button>`;

        // Build Nameserver of Mail Server tab content
        tabContents += `
            <div id="${modalId}-mailserver-ns"
                 class="tab-content ${currentDataKey === 'mailserver_ns' ? 'active' : ''}">
                <table class="validation-table details-table">
                    <thead>
                    <tr>
                        <th>Server</th>
                        <th>TLSA Records</th>
                        <th>Validation</th>
                    </tr>
                    </thead>
                    <tbody>
                    ${createDANEServerRows(resultsData.mailserver_ns, 'mailserver_ns')}
                    </tbody>
                </table>
            </div>`;
    }

    // Compose the full modal HTML
    return `
    <div id="${modalId}" class="modal">
        <div class="modal-content">
            <span class="close-modal" onclick="closeModal('${modalId}')">&times;</span>
            <h3>DANE Details - ${domain}</h3>

            <div class="tab-container">
                <div class="tab-buttons">
                    ${tabButtons}
                </div>
                ${tabContents}
            </div>
        </div>
    </div>`;
}

/**
 * Get DANE status icon HTML based on state and check type
 * @param {string} state - Validation state
 * @param {string} checkType - Type of check (Nameserver of Domain, etc.)
 * @returns {string} - HTML for status icon
 */
function getDANEStatusIcon(state, checkType) {
    // Special handling for not-valid state in nameserver checks
    if (state === 'not-valid' &&
        (checkType === 'Nameserver of Domain' || checkType === 'Nameserver of Mail Server')) {
        return '<i class="fas fa-question-circle status-not-found"></i>';
    }

    if (state === 'valid') {
        return '<i class="fas fa-check-circle status-valid"></i>';
    } else if (state === 'partially-valid') {
        return '<i class="fas fa-exclamation-triangle status-partially-valid"></i>';
    } else if (state === 'not-found') {
        return '<i class="fas fa-question-circle status-not-found"></i>';
    } else {
        return '<i class="fas fa-times-circle status-not-valid"></i>';
    }
}

/**
 * Helper function to create table rows for DANE server data
 * @param {Object} serverData - Server data from validation results
 * @param {string} dataType - Type of data (domain_ns, domain_mx, mailserver_ns)
 * @returns {string} - HTML for table rows
 */
function createDANEServerRows(serverData, dataType) {
    if (!serverData) return '';

    let rows = '';

    // Iterate through each server
    for (const [server, details] of Object.entries(serverData)) {
        rows += `<tr>
            <td class="server-name">${server}</td>`;

        // TLSA Records column
        rows += '<td>';

        if (details.tlsa_records && details.tlsa_records.length > 0) {
            rows += '<ul class="record-list">';

            // Special handling for domain_mx which has a different structure
            if (dataType === 'domain_mx') {
                details.tlsa_records.forEach(record => {
                    rows += `<li>
                        <span class="ip-address">${record.record}</span>
                        <i class="fas fa-${record.valid ? 'check status-valid' : 'times status-not-valid'}"></i>
                    </li>`;
                });
            } else {
                details.tlsa_records.forEach(record => {
                    rows += `<li><span class="ip-address">${record}</span></li>`;
                });
            }

            rows += '</ul>';
        } else {
            rows += '<span class="status-not-found">No TLSA records found</span>';
        }

        rows += '</td>';

        // Validation column
        rows += '<td>';

        if (details.tlsa_records && details.tlsa_records.length > 0) {
            rows += `<span class="rpki-state ${details.validation ? 'rpki-valid' : 'rpki-invalid'}">
                <i class="fas fa-${details.validation ? 'check-circle' : 'times-circle'}"></i>
                ${details.validation ? 'Valid' : 'Invalid'}
            </span>`;
        } else {
            rows += `<span class="status-not-found">
                <i class="fas fa-question-circle"></i>
                N/A
            </span>`;
        }

        rows += '</td></tr>';
    }

    return rows;
}