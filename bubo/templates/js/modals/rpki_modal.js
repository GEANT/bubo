// rpki_modal.js - RPKI Modal Implementation

/**
 * Create HTML for RPKI modal
 * @param {string} modalId - ID for the modal
 * @param {string} domain - Domain name
 * @param {Object} data - RPKI validation data
 * @returns {string} - Modal HTML
 */
function createRPKIModal(modalId, domain, data) {
    if (!data || !data.results || !data.state) {
        return `
        <div id="${modalId}" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <span class="close-modal" onclick="closeModal('${modalId}')">&times;</span>
                    <h3>RPKI Details - ${domain}</h3>
                </div>
                <p>No RPKI data available for this domain.</p>
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
                ${getRPKIStatusIcon(state)}
            </button>`;

        // Build Nameserver of Domain tab content
        tabContents += `
            <div id="${modalId}-domain-ns"
                 class="tab-content ${currentDataKey === 'domain_ns' ? 'active' : ''}">
                <table class="validation-table details-table">
                    <thead>
                    <tr>
                        <th>Server</th>
                        <th>IPv4</th>
                        <th>IPv6</th>
                        <th>ASN</th>
                        <th>Prefix</th>
                        <th>RPKI State</th>
                    </tr>
                    </thead>
                    <tbody>
                    ${createRPKIServerRows(resultsData.domain_ns)}
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
                ${getRPKIStatusIcon(state)}
            </button>`;

        // Build Mail Server of Domain tab content
        tabContents += `
            <div id="${modalId}-domain-mx"
                 class="tab-content ${currentDataKey === 'domain_mx' ? 'active' : ''}">
                <table class="validation-table details-table">
                    <thead>
                    <tr>
                        <th>Server</th>
                        <th>IPv4</th>
                        <th>IPv6</th>
                        <th>ASN</th>
                        <th>Prefix</th>
                        <th>RPKI State</th>
                    </tr>
                    </thead>
                    <tbody>
                    ${createRPKIServerRows(resultsData.domain_mx)}
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
                ${getRPKIStatusIcon(state)}
            </button>`;

        // Build Nameserver of Mail Server tab content
        tabContents += `
            <div id="${modalId}-mailserver-ns"
                 class="tab-content ${currentDataKey === 'mailserver_ns' ? 'active' : ''}">
                <table class="validation-table details-table">
                    <thead>
                    <tr>
                        <th>Server</th>
                        <th>IPv4</th>
                        <th>IPv6</th>
                        <th>ASN</th>
                        <th>Prefix</th>
                        <th>RPKI State</th>
                    </tr>
                    </thead>
                    <tbody>
                    ${createRPKIServerRows(resultsData.mailserver_ns)}
                    </tbody>
                </table>
            </div>`;
    }

    // Compose the full modal HTML
    return `
    <div id="${modalId}" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <span class="close-modal" onclick="closeModal('${modalId}')">&times;</span>
                <h3>RPKI Details - ${domain}</h3>
            </div>
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
 * Get status icon HTML based on state
 * @param {string} state - Validation state
 * @returns {string} - HTML for status icon
 */
function getRPKIStatusIcon(state) {
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
 * Helper function to create table rows for RPKI server data
 * @param {Object} serverData - Server data from validation results
 * @returns {string} - HTML for table rows
 */
function createRPKIServerRows(serverData) {
    if (!serverData) return '';

    let rows = '';

    // Iterate through each server
    for (const [server, details] of Object.entries(serverData)) {
        if (!details.prefix) continue;

        // Get all prefixes for this server
        const prefixes = Object.entries(details.prefix);
        const prefixCount = prefixes.length;

        // Iterate through each prefix
        prefixes.forEach(([prefix, prefixData], index) => {
            const isFirstRow = index === 0;

            rows += `<tr>`;

            // Server and IP columns only in first row
            if (isFirstRow) {
                // Extract all IPv4 addresses
                const ipv4Addresses = [];
                for (const pd of Object.values(details.prefix)) {
                    if (pd.ipv4) {
                        ipv4Addresses.push(...pd.ipv4);
                    }
                }

                // IPv6 addresses
                const ipv6Addresses = details.ipv6 || [];

                rows += `
                    <td rowspan="${prefixCount}" class="server-name">${server}</td>
                    <td rowspan="${prefixCount}">
                        ${ipv4Addresses.map(ip => `<span class="ip-address">${ip}</span>`).join('')}
                    </td>
                    <td rowspan="${prefixCount}">
                        ${ipv6Addresses.map(ip => {
                    if (ip !== 'No IPv6') {
                        return `<span class="ip-address">${ip}</span>`;
                    } else {
                        return `<span class="status-not-found">${ip}</span>`;
                    }
                }).join('')}
                    </td>`;
            }

            // ASN, Prefix, and RPKI State columns
            const rpkiState = prefixData.rpki_state || 'Not-found';
            const rpkiClassMap = {
                'Valid': 'rpki-valid',
                'Not-found': 'rpki-not-found',
                'Invalid': 'rpki-invalid'
            };

            const rpkiIconMap = {
                'Valid': 'check-circle',
                'Not-found': 'question-circle',
                'Invalid': 'times-circle'
            };

            rows += `
                <td>AS${prefixData.asn}</td>
                <td class="prefix-cell">${prefix}</td>
                <td>
                    <span class="rpki-state ${rpkiClassMap[rpkiState] || 'rpki-not-found'}">
                        <i class="fas fa-${rpkiIconMap[rpkiState] || 'question-circle'}"></i>
                        ${rpkiState}
                    </span>
                </td>
            </tr>`;
        });
    }

    return rows;
}