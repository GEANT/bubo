// dnssec_modal.js - DNSSEC Modal Implementation

/**
 * Create HTML for DNSSEC modal
 * @param {string} modalId - ID for the modal
 * @param {string} domain - Domain name
 * @param {Object} data - DNSSEC validation data
 * @returns {string} - Modal HTML
 */
function createDNSSECModal(modalId, domain, data) {
    if (!data) {
        return `
        <div id="${modalId}" class="modal">
            <div class="modal-content">
                <span class="close-modal" onclick="closeModal('${modalId}')">&times;</span>
                <h3>DNSSEC Details - ${domain}</h3>
                <p>No DNSSEC data available for this domain.</p>
            </div>
        </div>`;
    }

    const check_type = 'Root Domain'; // Default check type

    // Determine which data set to use
    let currentDataKey = null;
    if (data.domain_ns) {
        currentDataKey = 'domain_ns';
    } else if (data.domain_mx) {
        currentDataKey = 'domain_mx';
    } else if (data.mailserver_ns) {
        currentDataKey = 'mailserver_ns';
    }

    // Create the modal HTML
    return `
    <div id="${modalId}" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>
                    <i class="fas fa-shield-alt text-blue-600"></i>
                    DNSSEC Details - ${domain} (${check_type})
                </h3>
                <span class="close-modal" onclick="closeModal('${modalId}')">&times;</span>
            </div>

            <div class="tab-container">
                <div class="tab-buttons">
                    <button class="tab-button active" onclick="showTab('${modalId}-status')">
                        <i class="fas fa-info-circle"></i>
                        Status
                    </button>
                    <button class="tab-button" onclick="showTab('${modalId}-chain')">
                        <i class="fas fa-link"></i>
                        Verification Chain
                    </button>
                </div>

                <div id="${modalId}-status" class="tab-content active">
                    ${createDNSSECStatusTab(data, currentDataKey)}
                </div>

                <div id="${modalId}-chain" class="tab-content">
                    ${createDNSSECChainTab(data, currentDataKey)}
                </div>
            </div>
        </div>
    </div>`;
}

/**
 * Create the status tab content for DNSSEC modal
 * @param {Object} data - DNSSEC validation data
 * @param {string|null} currentDataKey - Key for current data set (domain_ns, domain_mx, mailserver_ns)
 * @returns {string} - HTML for the status tab
 */
function createDNSSECStatusTab(data, currentDataKey) {
    let htmlContent = '';

    if (currentDataKey && data[currentDataKey]) {
        // If we have data for specific servers
        for (const [server, serverData] of Object.entries(data[currentDataKey])) {
            htmlContent += `
            <div class="server-section">
                <div class="server-header">
                    <i class="fas fa-server text-purple-600"></i>
                    <h4>${server} (${serverData.base_domain})</h4>
                </div>
                ${renderDNSSECStatusContent({
                dnssec_status: serverData.dnssec_status,
                verification_chain: serverData.verification_chain,
                summary: serverData.summary
            })}
            </div>`;
        }
    } else {
        // Otherwise use the root data
        htmlContent += renderDNSSECStatusContent({
            dnssec_status: data.dnssec_status,
            verification_chain: data.verification_chain,
            summary: data.summary
        });
    }

    return htmlContent;
}

/**
 * Create the chain tab content for DNSSEC modal
 * @param {Object} data - DNSSEC validation data
 * @param {string|null} currentDataKey - Key for current data set (domain_ns, domain_mx, mailserver_ns)
 * @returns {string} - HTML for the chain tab
 */
function createDNSSECChainTab(data, currentDataKey) {
    let htmlContent = '';

    if (currentDataKey && data[currentDataKey]) {
        // If we have data for specific servers
        for (const [server, serverData] of Object.entries(data[currentDataKey])) {
            htmlContent += `
            <div class="chain-section">
                <div class="chain-header">
                    <i class="fas fa-link text-blue-600"></i>
                    <h4>Chain for ${server} (${serverData.base_domain})</h4>
                </div>
                ${renderDNSSECChainContent({verification_chain: serverData.verification_chain})}
            </div>`;

            // Add separator if not the last item
            const servers = Object.keys(data[currentDataKey]);
            if (server !== servers[servers.length - 1]) {
                htmlContent += '<hr class="chain-separator">';
            }
        }
    } else {
        // Otherwise use the root data
        htmlContent += renderDNSSECChainContent(data);
    }

    return htmlContent;
}

/**
 * Render the DNSSEC status table content
 * @param {Object} resultsData - DNSSEC results data
 * @returns {string} - HTML for status table
 */
function renderDNSSECStatusContent(resultsData) {
    return `
    <table class="validation-table details-table">
        <thead>
        <tr>
            <th><i class="fas fa-cube"></i> Component</th>
            <th><i class="fas fa-info-circle"></i> Status</th>
            <th><i class="fas fa-list-ul"></i> Details</th>
        </tr>
        </thead>
        <tbody>
        <!-- Registrar Section -->
        <tr>
            <td>
                <div class="component-header">
                    <i class="fas fa-building text-blue-600"></i>
                    <span class="ml-2">Registrar</span>
                </div>
            </td>
            <td>
                <div class="status-indicator">
                    ${renderRegistrarStatus(resultsData.dnssec_status)}
                </div>
            </td>
            <td>
                ${renderRegistrarDetails(resultsData.dnssec_status)}
            </td>
        </tr>
        <!-- Nameservers Section -->
        <tr>
            <td>
                <div class="component-header">
                    <i class="fas fa-server text-purple-600"></i>
                    <span class="ml-2">Nameservers</span>
                </div>
            </td>
            <td>
                <div class="status-indicator">
                    ${renderNameserverStatus(resultsData.dnssec_status)}
                </div>
            </td>
            <td>
                ${renderNameserverDetails(resultsData.dnssec_status)}
            </td>
        </tr>
        </tbody>
    </table>`;
}

/**
 * Render the registrar status
 * @param {Object} dnssecStatus - DNSSEC status data
 * @returns {string} - HTML for registrar status
 */
function renderRegistrarStatus(dnssecStatus) {
    if (!dnssecStatus || !dnssecStatus.registrar) {
        return '<span class="status-badge status-invalid"><i class="fas fa-lock-open"></i> Unknown</span>';
    }

    const isValid = dnssecStatus.registrar.status === 'FullySigned';
    return `
    <span class="status-badge ${isValid ? 'status-valid' : 'status-invalid'}">
        <i class="fas fa-${isValid ? 'lock' : 'lock-open'}"></i>
        ${dnssecStatus.registrar.status}
    </span>`;
}

/**
 * Render the registrar details section
 * @param {Object} dnssecStatus - DNSSEC status data
 * @returns {string} - HTML for registrar details
 */
function renderRegistrarDetails(dnssecStatus) {
    if (!dnssecStatus || !dnssecStatus.registrar) {
        return '<div class="no-records">No data available</div>';
    }

    if (dnssecStatus.registrar.ds_records && dnssecStatus.registrar.ds_records.length > 0) {
        let dsRecordsHTML = '';

        dnssecStatus.registrar.ds_records.forEach(record => {
            dsRecordsHTML += `
            <div class="record-item">
                <div class="record-header">
                    <i class="fas fa-key text-yellow-600"></i>
                    <strong>DS Record</strong>
                </div>
                <div class="record-details">
                    <div class="detail-row">
                        <i class="fas fa-tag text-gray-500"></i>
                        <span>Key Tag: ${record.key_tag}</span>
                    </div>
                    <div class="detail-row">
                        <i class="fas fa-cogs text-gray-500"></i>
                        <span>Algorithm: ${record.algorithm}</span>
                        ${record.algorithm_name ? `<span class="text-gray-500 ml-1">(${record.algorithm_name})</span>` : ''}
                    </div>
                    <div class="detail-row">
                        <i class="fas fa-fingerprint text-gray-500"></i>
                        <span>Digest Type: ${record.digest_type}</span>
                    </div>
                    <div class="detail-row digest">
                        <i class="fas fa-hashtag text-gray-500"></i>
                        Digest: <span class="monospace">${record.digest}</span>
                    </div>
                </div>
            </div>`;
        });

        return `<div class="records-container">${dsRecordsHTML}</div>`;
    } else {
        return `
        <div class="no-records">
            <i class="fas fa-exclamation-triangle text-red-600"></i>
            <span>No DS Records Found</span>
            <div class="security-advisory mt-2">
                <p class="text-sm text-red-700 font-medium">Security Impact:</p>
                <ul class="text-xs text-red-700 ml-5 mt-1 list-disc">
                    <li>Trust chain broken - parent zone not authenticating your DNSSEC keys</li>
                    <li>Resolver validation fails even if zone is signed at nameserver level</li>
                    <li>Vulnerable to DNS spoofing and cache poisoning attacks</li>
                    <li>DNSSEC implementation incomplete - "islands of security" configuration</li>
                </ul>
                <p class="text-xs text-gray-700 mt-1 italic">Validation Status: <span class="text-red-600 font-medium">Insecure</span> (RFC8499)</p>
                <p class="text-xs text-gray-700 mt-1"><i class="fas fa-wrench mr-1"> </i> Remediation: Publish DS records at your registrar to complete the chain of trust</p>
            </div>
        </div>`;
    }
}

/**
 * Render the nameserver status
 * @param {Object} dnssecStatus - DNSSEC status data
 * @returns {string} - HTML for nameserver status
 */
function renderNameserverStatus(dnssecStatus) {
    if (!dnssecStatus || !dnssecStatus.nameservers) {
        return '<span class="status-badge status-invalid"><i class="fas fa-lock-open"></i> Unknown</span>';
    }

    const isSigned = dnssecStatus.nameservers.status === 'Signed';
    return `
    <span class="status-badge ${isSigned ? 'status-valid' : 'status-invalid'}">
        <i class="fas fa-${isSigned ? 'lock' : 'lock-open'}"></i>
        ${dnssecStatus.nameservers.status}
    </span>`;
}

/**
 * Render the nameserver details section
 * @param {Object} dnssecStatus - DNSSEC status data
 * @returns {string} - HTML for nameserver details
 */
function renderNameserverDetails(dnssecStatus) {
    if (!dnssecStatus || !dnssecStatus.nameservers) {
        return '<div class="no-records">No data available</div>';
    }

    let htmlContent = '';

    // DNSKEY Records
    if (dnssecStatus.nameservers.dnskey_records && dnssecStatus.nameservers.dnskey_records.length > 0) {
        htmlContent += `
        <div class="records-section">
            <div class="section-header">
                <i class="fas fa-key text-yellow-600"></i>
                <strong>DNSKEY Records</strong>
            </div>
            <div class="records-container">`;

        dnssecStatus.nameservers.dnskey_records.forEach(record => {
            htmlContent += `
            <div class="record-item">
                <div class="record-details">
                    <div class="detail-row">
                        <i class="fas fa-flag text-gray-500"></i>
                        <span>Flag: ${record.flags}</span>
                        ${record.key_type ? `
                            <span class="badge ml-2 ${record.key_type === 'KSK' ? 'bg-orange-500' : 'bg-blue-500'}">
                                ${record.key_type}
                            </span>` : ''}
                    </div>
                    <div class="detail-row">
                        <i class="fas fa-code-branch text-gray-500"></i>
                        <span>Protocol: ${record.protocol}</span>
                    </div>
                    <div class="detail-row">
                        <i class="fas fa-cogs text-gray-500"></i>
                        <span>Algorithm: ${record.algorithm}</span>
                        ${record.algorithm_name ? `<span class="text-gray-500 ml-1">(${record.algorithm_name})</span>` : ''}
                    </div>
                    ${record.ttl !== undefined ? `
                    <div class="detail-row">
                        <i class="fas fa-clock text-gray-500"></i>
                        <span>TTL: ${record.ttl} seconds</span>
                    </div>` : ''}
                    <div class="detail-row key">
                        <i class="fas fa-key text-gray-500"></i>
                        Key: <span class="monospace">${record.key}</span>
                    </div>
                </div>
            </div>`;
        });

        htmlContent += `</div></div>`;
    }

    // RRSIG Records
    if (dnssecStatus.nameservers.rrsig_records && dnssecStatus.nameservers.rrsig_records.length > 0) {
        htmlContent += `
        <div class="records-section">
            <div class="section-header">
                <i class="fas fa-signature text-green-600"></i>
                <strong>RRSIG Records</strong>
            </div>
            <div class="records-container">`;

        dnssecStatus.nameservers.rrsig_records.forEach(record => {
            htmlContent += `
            <div class="record-item">
                <div class="record-details">
                    <div class="detail-row">
                        <i class="fas fa-file-alt text-gray-500"></i>
                        <span>Type: ${record.type_covered}</span>
                    </div>
                    <div class="detail-row">
                        <i class="fas fa-cogs text-gray-500"></i>
                        <span>Algorithm: ${record.algorithm}</span>
                        ${record.algorithm_name ? `<span class="text-gray-500 ml-1">(${record.algorithm_name})</span>` : ''}
                    </div>
                    <div class="detail-row">
                        <i class="fas fa-tag text-gray-500"></i>
                        <span>Key Tag: ${record.key_tag}</span>
                    </div>
                    <div class="detail-row">
                        <i class="fas fa-user-shield text-gray-500"></i>
                        <span>Signer: ${record.signer}</span>
                    </div>
                    <div class="detail-row">
                        <i class="fas fa-calendar-alt text-gray-500"></i>
                        <span>Valid: ${record.inception} - ${record.expiration}</span>
                        ${record.days_until_expiry !== undefined ? `
                        <span class="ml-2 ${record.expiring_soon ? 'text-yellow-600 font-medium' : 'text-green-600'}">
                            (${record.days_until_expiry} days remaining)
                        </span>` : ''}
                    </div>
                    ${record.ttl !== undefined ? `
                    <div class="detail-row">
                        <i class="fas fa-clock text-gray-500"></i>
                        <span>TTL: ${record.ttl} seconds</span>
                    </div>` : ''}
                </div>
            </div>`;
        });

        htmlContent += `</div></div>`;
    } else {
        htmlContent += `
        <div class="no-records">
            <i class="fas fa-exclamation-triangle text-red-600"></i>
            <span>No RRSIG Records Found</span>
            <div class="security-advisory mt-2">
                <p class="text-sm text-red-700 font-medium">Security Impact:</p>
                <ul class="text-xs text-red-700 ml-5 mt-1 list-disc">
                    <li>Zone data not cryptographically signed - integrity not verifiable</li>
                    <li>DNSSEC is not properly implemented on authoritative nameservers</li>
                    <li>DNS records can be tampered with in transit (MitM vulnerability)</li>
                    <li>Potential exploitation vectors: DNS cache poisoning, Kaminsky attacks</li>
                </ul>
                <p class="text-xs text-gray-700 mt-1"><i class="fas fa-wrench mr-1"> </i> Remediation: Configure DNSSEC signing on authoritative nameservers</p>
            </div>
        </div>`;
    }

    return htmlContent;
}

/**
 * Render the verification chain content
 * @param {Object} resultsData - DNSSEC results data
 * @returns {string} - HTML for verification chain
 */
function renderDNSSECChainContent(resultsData) {
    if (!resultsData || !resultsData.verification_chain || !resultsData.verification_chain.length) {
        return '<div class="no-records">No verification chain data available</div>';
    }

    let htmlContent = '<div class="verification-chain">';

    resultsData.verification_chain.forEach((step, index) => {
        htmlContent += `
        <div class="chain-step">
            <div class="step-header">
                <i class="fas fa-link text-blue-600"></i>
                <h4>${step.zone === '.' ? 'Root Zone' : step.zone}</h4>
            </div>
            <div class="step-content">
                <table class="validation-table chain-view-table">
                    <tbody>`;

        // DNSKEY Records
        if (step.dnskey_records && step.dnskey_records.length) {
            htmlContent += `
            <tr>
                <td class="record-type" rowspan="${step.dnskey_records.length}">
                    <i class="fas fa-key text-yellow-600"></i>
                    DNSKEY
                </td>
                <td class="record-content">
                    <div class="record-list">`;

            step.dnskey_records.forEach(record => {
                htmlContent += `<div class="monospace">${record}</div>`;
            });

            htmlContent += `</div></td></tr>`;
        }

        // DS Records
        if (step.ds_records && step.ds_records.length) {
            htmlContent += `
            <tr>
                <td class="record-type" rowspan="${step.ds_records.length}">
                    <i class="fas fa-shield-alt text-green-600"></i>
                    DS Records
                </td>
                <td class="record-content">
                    <div class="record-list">`;

            step.ds_records.forEach(record => {
                htmlContent += `<div class="monospace">${record}</div>`;
            });

            htmlContent += `</div></td></tr>`;
        }

        // RRSIG Info
        if (step.rrsig_info && step.rrsig_info.length) {
            htmlContent += `
            <tr>
                <td class="record-type" rowspan="${step.rrsig_info.length}">
                    <i class="fas fa-signature text-purple-600"></i>
                    RRSIG
                </td>
                <td class="record-content">
                    <div class="record-list">`;

            step.rrsig_info.forEach(info => {
                htmlContent += `<div class="monospace">${info}</div>`;
            });

            htmlContent += `</div></td></tr>`;
        }

        // Nameserver
        if (step.nameserver) {
            htmlContent += `
            <tr>
                <td class="record-type">
                    <i class="fas fa-server text-blue-600"></i>
                    Nameserver
                </td>
                <td class="record-content">
                    <span class="monospace">${step.nameserver}</span>
                </td>
            </tr>`;
        }

        // A Records
        if (step.a_records && step.a_records.length) {
            htmlContent += `
            <tr>
                <td class="record-type" rowspan="${step.a_records.length}">
                    <i class="fas fa-globe text-indigo-600"></i>
                    A Records
                </td>
                <td class="record-content">
                    <div class="record-list">`;

            step.a_records.forEach(record => {
                htmlContent += `<div class="monospace">${record}</div>`;
            });

            htmlContent += `</div></td></tr>`;
        }

        htmlContent += `</tbody></table></div>`;

        // Add connector if not the last step
        if (index < resultsData.verification_chain.length - 1) {
            htmlContent += `
            <div class="chain-connector">
                <i class="fas fa-arrow-down text-gray-500"></i>
            </div>`;
        }
    });

    htmlContent += '</div>';

    return htmlContent;
}