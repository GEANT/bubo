// email_security_modal.js - Email Security Modal Implementation

/**
 * Create HTML for Email Security modal
 * @param {string} modalId - ID for the modal
 * @param {string} domain - Domain name
 * @param {Object} results - Email security validation results
 * @returns {string} - Modal HTML
 */
function createEmailSecurityModal(modalId, domain, results) {
    if (!results) {
        return `
        <div id="${modalId}" class="modal">
            <div class="modal-content">
                <span class="close-modal" onclick="closeModal('${modalId}')">&times;</span>
                <h3>Email Security Details - ${domain}</h3>
                <p>No email security data available for this domain.</p>
            </div>
        </div>`;
    }

    return `
    <div id="${modalId}" class="modal">
        <div class="modal-content">
            <span class="close-modal" onclick="closeModal('${modalId}')">&times;</span>
            <div class="modal-header">
                <h3>
                    <i class="fas fa-envelope-open-text"></i>
                    Email Security Details for domain ${domain}
                </h3>
            </div>

            <div class="tab-container">
                <div class="tab-buttons">
                    <button class="tab-button active" onclick="showTab('${modalId}-spf')">
                        <i class="fas fa-shield-alt"></i> SPF
                        ${getSPFStatusIcon(results.spf)}
                    </button>
                    <button class="tab-button" onclick="showTab('${modalId}-dkim')">
                        <i class="fas fa-signature"></i> DKIM
                        ${getDKIMStatusIcon(results.dkim)}
                    </button>
                    <button class="tab-button" onclick="showTab('${modalId}-dmarc')">
                        <i class="fas fa-lock"></i> DMARC
                        ${getDMARCStatusIcon(results.dmarc)}
                    </button>
                </div>

                <!-- SPF Tab -->
                <div id="${modalId}-spf" class="tab-content active">
                    ${createSPFTabContent(results.spf)}
                </div>

                <!-- DKIM Tab -->
                <div id="${modalId}-dkim" class="tab-content">
                    ${createDKIMTabContent(results.dkim)}
                </div>

                <!-- DMARC Tab -->
                <div id="${modalId}-dmarc" class="tab-content">
                    ${createDMARCTabContent(results.dmarc)}
                </div>
            </div>
        </div>
    </div>
    
    <script>
        /* JavaScript for Collapsible Function */
        function toggleCollapse(element) {
            element.classList.toggle('collapsed');
            const content = element.nextElementSibling;
            if (element.classList.contains('collapsed')) {
                content.style.maxHeight = '0';
                content.style.padding = '0 16px';
                content.style.overflow = 'hidden';
            } else {
                content.style.maxHeight = content.scrollHeight + 'px';
                content.style.padding = '16px';
                content.style.overflow = 'visible';
            }
        }
    </script>`;
}

/**
 * Get SPF status icon HTML
 * @param {Object} spfData - SPF validation data
 * @returns {string} - HTML for status icon
 */
function getSPFStatusIcon(spfData) {
    if (spfData.valid) {
        return '<i class="fas fa-check-circle status-valid"></i>';
    } else if (spfData.has_spf && !spfData.policy_sufficiently_strict) {
        return '<i class="fas fa-exclamation-triangle status-partially-valid"></i>';
    } else {
        return '<i class="fas fa-times-circle status-not-valid"></i>';
    }
}

/**
 * Get DKIM status icon HTML
 * @param {Object} dkimData - DKIM validation data
 * @returns {string} - HTML for status icon
 */
function getDKIMStatusIcon(dkimData) {
    if (dkimData.valid) {
        return '<i class="fas fa-check-circle status-valid"></i>';
    } else {
        return '<i class="fas fa-times-circle status-not-valid"></i>';
    }
}

/**
 * Get DMARC status icon HTML
 * @param {Object} dmarcData - DMARC validation data
 * @returns {string} - HTML for status icon
 */
function getDMARCStatusIcon(dmarcData) {
    if (dmarcData.valid) {
        return '<i class="fas fa-check-circle status-valid"></i>';
    } else if (dmarcData.record_exists && !dmarcData.valid) {
        return '<i class="fas fa-exclamation-triangle status-partially-valid"></i>';
    } else {
        return '<i class="fas fa-times-circle status-not-valid"></i>';
    }
}

/**
 * Create SPF tab content
 * @param {Object} spfData - SPF validation data
 * @returns {string} - HTML for SPF tab
 */
function createSPFTabContent(spfData) {
    let statusBadge;
    if (spfData.valid) {
        statusBadge = `
        <span class="status-badge status-valid">
            <i class="fas fa-check-circle"></i> Valid
        </span>`;
    } else if (spfData.has_spf && !spfData.policy_sufficiently_strict) {
        statusBadge = `
        <span class="status-badge status-warning">
            <i class="fas fa-exclamation-triangle"></i> Record exists but is not sufficiently strict
        </span>`;
    } else {
        statusBadge = `
        <span class="status-badge status-invalid">
            <i class="fas fa-times-circle"></i> Invalid
        </span>`;
    }

    let html = `
    <div class="component-header">
        <h4>SPF Configuration</h4>
        ${statusBadge}
    </div>

    <div class="record-item">
        <div class="record-header">
            <i class="fas fa-search"></i>
            <strong>Record Status:</strong>
        </div>
        <div class="record-details">
            <div class="detail-row">
                <i class="fas ${spfData.has_spf ? 'fa-check-circle status-valid' : 'fa-times-circle status-invalid'}"></i>
                <span>${spfData.has_spf ? '' : 'No'} SPF Record has been found for this domain.</span>
            </div>`;

    if (spfData.has_spf) {
        html += `
            <div class="detail-row">
                <i class="fas ${spfData.policy_sufficiently_strict ? 'fa-check-circle status-valid' : 'fa-exclamation-triangle status-warning'}"></i>
                <span>SPF Policy is ${spfData.policy_sufficiently_strict ? 'sufficiently strict.' : 'not sufficiently strict.'}</span>
            </div>`;
    }

    html += `</div></div>`;

    // SPF Record
    if (spfData.record) {
        html += `
        <div class="record-card">
            <div class="record-card-header">
                <i class="fas fa-file-alt"></i>
                <span>Record</span>
            </div>
            <div class="record-card-body">
                <code class="spf-record">${spfData.record}</code>
            </div>
        </div>`;
    }

    // Redirect Information
    if (spfData.redirect_info) {
        html += `
        <div class="record-card redirect-card">
            <div class="record-card-header collapsible" onclick="toggleCollapse(this)">
                <i class="fas fa-forward"></i>
                <span>Redirect Information (${spfData.redirect_domain})</span>
                <i class="fas fa-chevron-down collapse-icon"></i>
            </div>
            <div class="record-card-body">
                <div class="redirect-record-container">
                    <div class="redirect-section">
                        <div class="section-label">
                            <i class="fas fa-file-alt"></i>
                            <span>Record:</span>
                        </div>
                        <div class="section-content">
                            <code class="spf-record">${spfData.redirect_info.record}</code>
                        </div>
                    </div>

                    <div class="redirect-section">
                        <div class="section-label">
                            <i class="fas fa-shield-alt"></i>
                            <span>Policy:</span>
                        </div>
                        <div class="section-content">
                            <span class="policy-badge ${['~all', '-all'].includes(spfData.redirect_info.policy) ? 'policy-strict' : 'policy-neutral'}">
                                ${spfData.redirect_info.policy}
                            </span>
                        </div>
                    </div>`;

        // Includes
        if (spfData.redirect_info.includes && spfData.redirect_info.includes.length) {
            html += `
                    <div class="redirect-section">
                        <div class="section-label">
                            <i class="fas fa-link"></i>
                            <span>Includes:</span>
                        </div>
                        <div class="section-content">
                            <div class="tag-container">`;

            spfData.redirect_info.includes.forEach(include => {
                html += `<span class="tag include-tag">${include}</span>`;
            });

            html += `</div></div></div>`;
        }

        // A Records
        if (spfData.redirect_info.a_records && spfData.redirect_info.a_records.length) {
            html += `
                    <div class="redirect-section">
                        <div class="section-label">
                            <i class="fas fa-server"></i>
                            <span>A Records:</span>
                        </div>
                        <div class="section-content">
                            <div class="tag-container">`;

            spfData.redirect_info.a_records.forEach(record => {
                html += `<span class="tag a-record-tag">${record}</span>`;
            });

            html += `</div></div></div>`;
        }

        // MX Records
        if (spfData.redirect_info.mx_records && spfData.redirect_info.mx_records.length) {
            html += `
                    <div class="redirect-section">
                        <div class="section-label">
                            <i class="fas fa-mail-bulk"></i>
                            <span>MX Records:</span>
                        </div>
                        <div class="section-content">
                            <div class="tag-container">`;

            spfData.redirect_info.mx_records.forEach(record => {
                html += `<span class="tag mx-record-tag">${record}</span>`;
            });

            html += `</div></div></div>`;
        }

        // PTR Records
        if (spfData.redirect_info.ptr_records && spfData.redirect_info.ptr_records.length) {
            html += `
                    <div class="redirect-section">
                        <div class="section-label">
                            <i class="fas fa-exchange-alt"></i>
                            <span>PTR Records:</span>
                        </div>
                        <div class="section-content">
                            <div class="tag-container">`;

            spfData.redirect_info.ptr_records.forEach(record => {
                html += `<span class="tag ptr-record-tag">${record}</span>`;
            });

            html += `</div></div></div>`;
        }

        html += `</div></div></div>`;
    }

    // Policy
    if (spfData.policy) {
        let policyExplanation = '';
        if (spfData.policy_explanation) {
            if (spfData.policy_sufficiently_strict) {
                policyExplanation = `
                <div class="policy-explanation valid">
                    <i class="fas fa-check-circle"></i>
                    <span>${spfData.policy_explanation}</span>
                </div>`;
            } else {
                policyExplanation = `
                <div class="policy-explanation warning">
                    <i class="fas fa-exclamation-triangle"></i>
                    <span>${spfData.policy_explanation}</span>
                </div>`;
            }
        }

        html += `
        <div class="record-card">
            <div class="record-card-header">
                <i class="fas fa-shield-alt"></i>
                <span>Policy</span>
            </div>
            <div class="record-card-body policy-container">
                <span class="policy-badge ${['~all', '-all'].includes(spfData.policy) ? 'policy-strict' : 'policy-neutral'}">
                    ${spfData.policy}
                </span>
                ${policyExplanation}
            </div>
        </div>`;
    }

    // DNS Lookups
    if (spfData.dns_lookups !== undefined) {
        html += `
        <div class="record-item">
            <div class="record-header">
                <i class="fas fa-search"></i>
                <strong>DNS Lookups:</strong>
            </div>
            <div class="record-details">
                <div class="detail-row">
                    <span>${spfData.dns_lookups} lookup${spfData.dns_lookups !== 1 ? 's' : ''}</span>
                </div>
                <div class="detail-row">
                    <i class="${spfData.exceeds_lookup_limit ? 'fas fa-exclamation-triangle status-warning' : 'fas fa-check-circle status-valid'}"></i>
                    <span>${spfData.exceeds_lookup_limit ? 'Exceeds' : 'Within'} recommended lookup limit (10)</span>
                </div>
            </div>
        </div>`;
    }

    // Included Domains
    if (spfData.includes && spfData.includes.length) {
        html += `
        <div class="record-item">
            <div class="record-header">
                <i class="fas fa-link"></i>
                <strong>Included Domains:</strong>
            </div>
            <ul class="record-list">`;

        spfData.includes.forEach(include => {
            html += `<li>${include}</li>`;
        });

        html += `</ul></div>`;
    }

    // IPv4 Addresses
    if (spfData.record && spfData.record.includes('ip4:')) {
        html += `
        <div class="record-item">
            <div class="record-header">
                <i class="fas fa-network-wired"></i>
                <strong>IPv4 Addresses:</strong>
            </div>
            <ul class="record-list">`;

        const parts = spfData.record.split(' ');
        parts.forEach(part => {
            if (part.startsWith('ip4:')) {
                html += `<li><code class="ip-address">${part.substring(4)}</code></li>`;
            }
        });

        html += `</ul></div>`;
    }

    // IPv6 Addresses
    if (spfData.record && spfData.record.includes('ip6:')) {
        html += `
        <div class="record-item">
            <div class="record-header">
                <i class="fas fa-network-wired"></i>
                <strong>IPv6 Addresses:</strong>
            </div>
            <ul class="record-list">`;

        const parts = spfData.record.split(' ');
        parts.forEach(part => {
            if (part.startsWith('ip6:')) {
                html += `<li><code class="ip-address">${part.substring(4)}</code></li>`;
            }
        });

        html += `</ul></div>`;
    }

    return html;
}

/**
 * Create DKIM tab content
 * @param {Object} dkimData - DKIM validation data
 * @returns {string} - HTML for DKIM tab
 */
function createDKIMTabContent(dkimData) {
    let statusBadge;
    if (dkimData.valid) {
        statusBadge = `
        <span class="status-badge status-valid">
            <i class="fas fa-check-circle"></i> Valid
        </span>`;
    } else {
        statusBadge = `
        <span class="status-badge status-invalid">
            <i class="fas fa-times-circle"></i> Invalid
        </span>`;
    }

    let html = `
    <div class="component-header">
        <h4>DKIM Configuration</h4>
        ${statusBadge}
    </div>`;

    if (dkimData.selectors_found && dkimData.selectors_found.length) {
        // Overall key strength
        if (dkimData.overall_key_strength) {
            const strengthIconMap = {
                'vulnerable': 'fa-exclamation-circle status-invalid',
                'acceptable': 'fa-info-circle status-info',
                'strong': 'fa-check-circle status-valid',
                'future-proof': 'fa-shield-alt status-valid'
            };

            const strengthClassMap = {
                'vulnerable': 'status-invalid',
                'acceptable': 'status-info',
                'strong': 'status-valid',
                'future-proof': 'status-valid'
            };

            const iconClass = strengthIconMap[dkimData.overall_key_strength] || 'fa-question-circle';
            const statusClass = strengthClassMap[dkimData.overall_key_strength] || '';

            html += `
            <div class="record-item">
                <div class="record-header">
                    <i class="fas fa-shield-alt"></i>
                    <strong>Overall Key Strength:</strong>
                </div>
                <div class="record-details">
                    <div class="detail-row">
                        <i class="fas ${iconClass}"></i>
                        <span class="${statusClass}">
                            ${dkimData.overall_key_strength.charAt(0).toUpperCase() + dkimData.overall_key_strength.slice(1)}
                        </span>
                    </div>
                </div>
            </div>`;
        }

        // Selectors
        dkimData.selectors_found.forEach(selector => {
            html += `
            <div class="record-card">
                <div class="record-card-header collapsible" onclick="toggleCollapse(this)">
                    <i class="fas fa-key"></i>
                    <span>Selector: ${selector}</span>
                    <i class="fas fa-chevron-down collapse-icon"></i>
                </div>
                <div class="record-card-body">`;

            if (dkimData.records && dkimData.records[selector] && dkimData.records[selector].key_info) {
                const keyInfo = dkimData.records[selector].key_info;
                html += `
                    <div class="record-section">
                        <h5>Key Information</h5>
                        <div class="detail-row">
                            <i class="fas fa-key"></i>
                            <strong>Type:</strong>
                            <span>${keyInfo.key_type.toUpperCase()}</span>
                        </div>

                        <div class="detail-row">
                            <i class="fas fa-ruler"></i>
                            <strong>Length:</strong>
                            <span>${keyInfo.key_length} bits</span>
                        </div>`;

                if (keyInfo.strength) {
                    const strengthIconMap = {
                        'vulnerable': 'fa-exclamation-circle status-invalid',
                        'acceptable': 'fa-info-circle status-info',
                        'strong': 'fa-check-circle status-valid',
                        'future-proof': 'fa-shield-alt status-valid'
                    };

                    const strengthClassMap = {
                        'vulnerable': 'status-invalid',
                        'acceptable': 'status-info',
                        'strong': 'status-valid',
                        'future-proof': 'status-valid'
                    };

                    const iconClass = strengthIconMap[keyInfo.strength] || 'fa-question-circle';
                    const statusClass = strengthClassMap[keyInfo.strength] || '';

                    html += `
                        <div class="detail-row">
                            <i class="fas ${iconClass}"></i>
                            <strong>Strength:</strong>
                            <span class="${statusClass}">
                                ${keyInfo.strength.charAt(0).toUpperCase() + keyInfo.strength.slice(1)}
                            </span>
                        </div>`;

                    if (keyInfo.strength_description) {
                        html += `
                        <div class="detail-row" style="margin-left: 24px;">
                            <span>${keyInfo.strength_description}</span>
                        </div>`;
                    }
                }

                if (keyInfo.error) {
                    html += `
                        <div class="detail-row">
                            <i class="fas fa-exclamation-triangle status-warning"></i>
                            <span>Error: ${keyInfo.error}</span>
                        </div>`;
                }

                html += `</div>`;
            }

            if (dkimData.records && dkimData.records[selector] && dkimData.records[selector].record) {
                html += `
                    <div class="record-section">
                        <h5>DKIM Record</h5>
                        <code class="monospace dkim-record">${dkimData.records[selector].record}</code>
                    </div>`;
            }

            html += `</div></div>`;
        });
    }

    if (dkimData.error) {
        html += `
        <div class="record-item">
            <div class="detail-row">
                <i class="fas fa-times-circle status-invalid"></i>
                <span>${dkimData.error}</span>
            </div>
        </div>`;
    }

    return html;
}

/**
 * Create DMARC tab content
 * @param {Object} dmarcData - DMARC validation data
 * @returns {string} - HTML for DMARC tab
 */
function createDMARCTabContent(dmarcData) {
    let statusBadge;
    if (dmarcData.valid) {
        statusBadge = `
        <span class="status-badge status-valid">
            <i class="fas fa-check-circle"></i> Valid
        </span>`;
    } else if (dmarcData.record_exists && !dmarcData.valid) {
        statusBadge = `
        <span class="status-badge status-warning">
            <i class="fas fa-exclamation-triangle"></i> Record exists but is not sufficiently strict
        </span>`;
    } else {
        statusBadge = `
        <span class="status-badge status-invalid">
            <i class="fas fa-times-circle"></i> Invalid
        </span>`;
    }

    let html = `
    <div class="component-header">
        <h4>DMARC Configuration</h4>
        ${statusBadge}
    </div>

    <div class="record-item">
        <div class="record-header">
            <i class="fas fa-search"></i>
            <strong>Record Status:</strong>
        </div>
        <div class="record-details">
            <div class="detail-row">
                <i class="fas ${dmarcData.record_exists ? 'fa-check-circle status-valid' : 'fa-times-circle status-invalid'}"></i>
                <span>${dmarcData.record_exists ? '' : 'No'} DMARC Record has been found for this domain.</span>
            </div>`;

    if (dmarcData.record_exists) {
        html += `
            <div class="detail-row">
                <i class="fas ${dmarcData.valid ? 'fa-check-circle status-valid' : 'fa-times-circle status-invalid'}"></i>
                <span>DMARC Record policy is ${dmarcData.valid ? 'sufficiently strict.' : 'not sufficiently strict.'}</span>
            </div>`;
    }

    html += `</div></div>`;

    if (dmarcData.record) {
        html += `
        <div class="record-item">
            <div class="record-header">
                <i class="fas fa-file-alt"></i>
                <strong>Record:</strong>
            </div>
            <code class="monospace">${dmarcData.record}</code>
        </div>

        <div class="record-item">
            <div class="record-details">
                <div class="detail-row">
                    <i class="fas fa-shield-alt"></i>
                    <strong>Policy:</strong>
                    <span class="status-badge ${['quarantine', 'reject'].includes(dmarcData.policy) ? 'status-valid' : 'status-warning'}">
                        ${dmarcData.policy}
                    </span>
                </div>`;

        if (dmarcData.error) {
            html += `
                <div class="detail-row">
                    <i class="fas fa-exclamation-triangle"></i> ${dmarcData.error}
                </div>`;
        }

        if (dmarcData.sub_policy) {
            html += `
                <div class="detail-row">
                    <i class="fas fa-sitemap"></i>
                    <strong>Subdomain Policy:</strong>
                    <span class="status-badge ${['quarantine', 'reject'].includes(dmarcData.sub_policy) ? 'status-valid' : 'status-warning'}">
                        ${dmarcData.sub_policy}
                    </span>
                </div>`;
        }

        if (dmarcData.percentage !== undefined) {
            html += `
                <div class="detail-row">
                    <i class="fas fa-percent"></i>
                    <strong>Enforcement Percentage:</strong>
                    ${dmarcData.percentage}
                </div>`;
        }

        if (dmarcData.rua) {
            html += `
                <div class="detail-row">
                    <i class="fas fa-envelope"></i>
                    <strong>Aggregate Reports (rua):</strong>
                    ${dmarcData.rua}
                </div>`;
        }

        if (dmarcData.ruf) {
            html += `
                <div class="detail-row">
                    <i class="fas fa-file-alt"></i>
                    <strong>Forensic Reports (ruf):</strong>
                    ${dmarcData.ruf}
                </div>`;
        }

        html += `</div></div>`;

        if (dmarcData.warnings && dmarcData.warnings.length) {
            html += `
            <div class="record-item">
                <div class="record-header">
                    <i class="fas fa-exclamation-triangle"></i>
                    <strong>Warnings:</strong>
                </div>
                <div class="record-details">`;

            dmarcData.warnings.forEach(warning => {
                html += `
                    <div class="detail-row">
                        <i class="fas fa-exclamation-triangle status-warning"></i>
                        <span>${warning}</span>
                    </div>`;
            });

            html += `</div></div>`;
        }
    }

    return html;
}