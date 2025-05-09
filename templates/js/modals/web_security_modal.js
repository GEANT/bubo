// web_security_modal.js - Web Security Modal Implementation

/**
 * Create HTML for Web Security modal
 * @param {string} modalId - ID for the modal
 * @param {string} domain - Domain name
 * @param {Object} results - Web security validation results
 * @returns {string} - Modal HTML
 */
function createWebSecurityModal(modalId, domain, results) {
    if (!results) {
        return `
        <div id="${modalId}" class="modal">
            <div class="modal-content">
                <span class="close-modal" onclick="closeModal('${modalId}')">&times;</span>
                <h3>Web Security Details - ${domain}</h3>
                <p>No web security data available for this domain.</p>
            </div>
        </div>`;
    }

    // Calculate status for each tab based on validation results
    let certificateStatus = 'valid';
    let protocolsStatus = 'valid';
    let headersStatus = 'valid';

    if (results.connectivity_error) {
        certificateStatus = 'not-valid';
        protocolsStatus = 'not-valid';
        headersStatus = 'not-valid';
    } else {
        // Certificate status calculation
        if (results.certificate) {
            if (!results.certificate.is_valid || results.certificate.is_self_signed || results.certificate.is_expired) {
                certificateStatus = 'not-valid';
            } else if (!results.certificate.chain_valid || (results.certificate.days_until_expiry < 30)) {
                certificateStatus = 'partially-valid';
            }
        } else {
            certificateStatus = 'not-valid';
        }

        // Protocols status calculation
        if (results.protocol_support) {
            if (results.protocol_support.has_insecure_protocols) {
                if (results.protocol_support.has_secure_protocols) {
                    protocolsStatus = 'partially-valid';
                } else {
                    protocolsStatus = 'not-valid';
                }
            } else if (results.ciphers && results.ciphers.has_weak_ciphers) {
                protocolsStatus = 'partially-valid';
            }
        } else {
            protocolsStatus = 'not-valid';
        }

        // Headers status calculation
        if (results.security_headers) {
            const cspValid = results.security_headers.content_security_policy;
            const xctoValid = results.security_headers.x_content_type_options;
            const xfoValid = results.security_headers.x_frame_options;
            const hstsValid = results.hsts && results.hsts.enabled === true;

            // Calculate total count of valid headers
            let validHeadersCount = 0;
            if (cspValid) validHeadersCount++;
            if (xctoValid) validHeadersCount++;
            if (xfoValid) validHeadersCount++;
            if (hstsValid) validHeadersCount++;

            const totalPossibleHeaders = 4;

            if (validHeadersCount === 0) {
                headersStatus = 'not-valid';
            } else if (validHeadersCount < totalPossibleHeaders) {
                headersStatus = 'partially-valid';
            } else {
                headersStatus = 'valid';
            }
        } else {
            headersStatus = 'not-valid';
        }
    }

    return `
    <div id="${modalId}" class="modal">
        <div class="modal-content">
            <span class="close-modal" onclick="closeModal('${modalId}')">&times;</span>
            <div class="modal-header">
                <h3>
                    <i class="fas fa-lock"></i>
                    Web Security Details for ${domain}
                </h3>
            </div>

            <div class="tab-container">
                <div class="tab-buttons">
                    <button class="tab-button active" onclick="showTab('${modalId}-overview')">
                        <i class="fas fa-chart-pie"></i> Overview
                    </button>
                    <button class="tab-button" onclick="showTab('${modalId}-certificate')">
                        <i class="fas fa-certificate"></i> Certificate
                        <i class="fas fa-${certificateStatus === 'valid' ? 'check-circle status-valid' : certificateStatus === 'partially-valid' ? 'exclamation-triangle status-partially-valid' : 'times-circle status-not-valid'}"></i>
                    </button>
                    <button class="tab-button" onclick="showTab('${modalId}-protocols')">
                        <i class="fas fa-exchange-alt"></i> Protocols & Ciphers
                        <i class="fas fa-${protocolsStatus === 'valid' ? 'check-circle status-valid' : protocolsStatus === 'partially-valid' ? 'exclamation-triangle status-partially-valid' : 'times-circle status-not-valid'}"></i>
                    </button>
                    <button class="tab-button" onclick="showTab('${modalId}-headers')">
                        <i class="fas fa-shield-alt"></i> Security Headers
                        <i class="fas fa-${headersStatus === 'valid' ? 'check-circle status-valid' : headersStatus === 'partially-valid' ? 'exclamation-triangle status-partially-valid' : 'times-circle status-not-valid'}"></i>
                    </button>
                </div>

                <!-- Overview Tab -->
                <div id="${modalId}-overview" class="tab-content active">
                    ${createOverviewTabContent(results)}
                </div>

                <!-- Certificate Tab -->
                <div id="${modalId}-certificate" class="tab-content">
                    ${createCertificateTabContent(results)}
                </div>

                <!-- Protocols & Ciphers Tab -->
                <div id="${modalId}-protocols" class="tab-content">
                    ${createProtocolsTabContent(results)}
                </div>

                <!-- Security Headers Tab -->
                <div id="${modalId}-headers" class="tab-content">
                    ${createHeadersTabContent(results)}
                </div>
            </div>
        </div>
    </div>`;
}

/**
 * Create Overview tab content
 * @param {Object} results - Web security results
 * @returns {string} - HTML for overview tab
 */
function createOverviewTabContent(results) {
    let html = '';

    // Display connectivity error banner if present
    if (results.connectivity_error) {
        html += `
        <div class="error-banner p-4 mb-4 bg-red-100 border-l-4 border-red-500 text-red-700">
            <div class="flex items-center">
                <i class="fas fa-exclamation-circle mr-2"></i>
                <strong>Connection Error:</strong>
                <span class="ml-2">${results.error_message || 'Could not connect to server'}</span>
            </div>
        </div>`;
    }

    // Security Assessment Section
    if (results.security_assessment) {
        const rating = results.security_assessment.rating || 'unknown';
        let ratingIcon = 'times-circle';

        if (rating === 'excellent') {
            ratingIcon = 'star';
        } else if (rating === 'good') {
            ratingIcon = 'check-circle';
        } else if (rating === 'moderate' || rating === 'fair') {
            ratingIcon = 'exclamation-triangle';
        }

        html += `
        <div class="card">
            <div class="card-header">
                <i class="fas fa-info-circle me-2"></i>
                <span>Security Assessment</span>
            </div>
            <div class="card-body">
                <div class="text-center mb-3">
                    <div class="rating-badge rating-${rating.toLowerCase()}">
                        <i class="fas fa-${ratingIcon} me-2"></i>
                        Rating: ${capitalize(rating)}
                    </div>
                </div>

                <div class="mt-3">
                    <div class="d-flex justify-content-center mb-2">
                        <strong>Issues found: ${results.security_assessment.issues_count || 0}</strong>
                    </div>`;

        // Issues list
        if (results.security_assessment.issues && results.security_assessment.issues.length > 0) {
            html += `<div class="issues-list">`;

            results.security_assessment.issues.forEach(issue => {
                html += `
                <div class="issue-item">
                    <i class="fas fa-exclamation-circle text-danger me-2"></i>
                    <span>${issue}</span>
                </div>`;
            });

            html += `</div>`;
        } else {
            html += `
            <div class="d-flex justify-content-center">
                <div class="issue-item good">
                    <i class="fas fa-check-circle text-success me-2"></i>
                    <span>No security issues detected</span>
                </div>
            </div>`;
        }

        html += `
                </div>
            </div>
        </div>`;
    }

    // Status Grid with Certificate and Protocol sections
    html += `<div class="status-grid">`;

    // Certificate Status
    html += `
    <div class="card">
        <div class="card-header">
            <i class="fas fa-certificate me-2"></i>
            <span>Certificate Status</span>
        </div>`;

    if (results.certificate) {
        const isValid = results.certificate.is_valid || false;
        const chainValid = results.certificate.chain_valid || false;
        const isSelfSigned = results.certificate.is_self_signed || false;
        const daysUntilExpiry = results.certificate.days_until_expiry;

        html += `
        <div class="card-body">
            <ul class="status-list">
                <li class="status-item">
                    <i class="fas fa-${isValid ? 'check-circle text-success' : 'times-circle text-danger'} me-2"></i>
                    <strong>Valid Certificate:</strong>
                    <span>${isValid ? 'Yes' : 'No'}</span>
                </li>
                
                <li class="status-item">
                    <i class="fas fa-${chainValid ? 'check-circle text-success' : 'times-circle text-danger'} me-2"></i>
                    <strong>Valid Chain:</strong>
                    <span>${chainValid ? 'Yes' : 'No'}</span>
                </li>
                
                <li class="status-item">
                    <i class="fas fa-${!isSelfSigned ? 'check-circle text-success' : 'exclamation-triangle text-danger'} me-2"></i>
                    <strong>Self-signed:</strong>
                    <span>${!isSelfSigned ? 'No' : 'Yes'}</span>
                </li>`;

        if (daysUntilExpiry !== undefined) {
            let expiryIconClass = '';
            if (daysUntilExpiry > 30) {
                expiryIconClass = 'check-circle text-success';
            } else if (daysUntilExpiry > 7) {
                expiryIconClass = 'exclamation-triangle text-warning';
            } else {
                expiryIconClass = 'times-circle text-danger';
            }

            html += `
            <li class="status-item">
                <i class="fas fa-${expiryIconClass} me-2"></i>
                <strong>Expires in:</strong>
                <span>${daysUntilExpiry} days</span>
            </li>`;
        }

        html += `</ul></div>`;
    } else {
        html += `
        <div class="card-body">
            <div class="error-message">
                <i class="fas fa-exclamation-triangle"></i>
                <span>Certificate information not available</span>
            </div>
        </div>`;
    }

    html += `</div>`;

    // Protocol Security
    html += `
    <div class="card">
        <div class="card-header">
            <i class="fas fa-shield-alt me-2"></i>
            <span>Protocol Security</span>
        </div>
        <div class="card-body">`;

    if (results.protocol_support) {
        const hasSecure = results.protocol_support.has_secure_protocols || false;
        const hasInsecure = results.protocol_support.has_insecure_protocols || false;

        html += `
        <ul class="status-list">
            <li class="status-item">
                <i class="fas fa-${hasSecure ? 'check-circle text-success' : 'times-circle text-danger'} me-2"></i>
                <strong>Secure Protocols:</strong>
                <span>${hasSecure ? 'Yes' : 'No'}</span>
            </li>
            
            <li class="status-item">
                <i class="fas fa-${!hasInsecure ? 'check-circle text-success' : 'exclamation-triangle text-danger'} me-2"></i>
                <strong>Insecure Protocols:</strong>
                <span>${!hasInsecure ? 'No' : 'Yes'}</span>
            </li>`;

        if (results.ciphers) {
            const hasStrong = results.ciphers.has_strong_ciphers || false;
            const hasWeak = results.ciphers.has_weak_ciphers || false;

            html += `
            <li class="status-item">
                <i class="fas fa-${hasStrong ? 'check-circle text-success' : 'times-circle text-danger'} me-2"></i>
                <strong>Strong Ciphers:</strong>
                <span>${hasStrong ? 'Yes' : 'No'}</span>
            </li>
            
            <li class="status-item">
                <i class="fas fa-${!hasWeak ? 'check-circle text-success' : 'exclamation-triangle text-danger'} me-2"></i>
                <strong>Weak Ciphers:</strong>
                <span>${!hasWeak ? 'No' : 'Yes'}</span>
            </li>`;
        }

        html += `</ul>`;
    } else {
        html += `
        <div class="error-message">
            <i class="fas fa-exclamation-triangle"></i>
            <span>Protocol information not available</span>
        </div>`;
    }

    html += `</div></div></div>`;

    // HSTS Configuration
    if (results.hsts) {
        const hstsEnabled = results.hsts.enabled || false;

        html += `
        <div class="card">
            <div class="card-header collapsible" onclick="toggleCollapse(this)">
                <i class="fas fa-chevron-up me-2"></i>
                <span>HSTS Configuration</span>
            </div>
            <div class="card-body">
                <ul class="status-list">
                    <li class="status-item">
                        <i class="fas fa-${hstsEnabled ? 'check-circle text-success' : 'times-circle text-danger'} me-2"></i>
                        <strong>HSTS Enabled:</strong>
                        <span>${hstsEnabled ? 'Yes' : 'No'}</span>
                    </li>`;

        if (hstsEnabled) {
            const maxAgeGood = results.hsts.max_age >= 15768000;
            const maxAgeDays = Math.round(results.hsts.max_age / 86400);
            const includesSubs = results.hsts.include_subdomains || false;
            const preload = results.hsts.preload || false;

            html += `
            <li class="status-item">
                <i class="fas fa-${maxAgeGood ? 'check-circle text-success' : 'exclamation-triangle text-warning'} me-2"></i>
                <strong>Max Age:</strong>
                <span>${results.hsts.max_age} seconds (${maxAgeDays} days)</span>
            </li>
            
            <li class="status-item">
                <i class="fas fa-${includesSubs ? 'check-circle text-success' : 'exclamation-triangle text-warning'} me-2"></i>
                <strong>Include Subdomains:</strong>
                <span>${includesSubs ? 'Yes' : 'No'}</span>
            </li>
            
            <li class="status-item">
                <i class="fas fa-${preload ? 'check-circle text-success' : 'info-circle text-info'} me-2"></i>
                <strong>Preload:</strong>
                <span>${preload ? 'Yes' : 'No'}</span>
            </li>`;

            if (results.hsts.header_value) {
                html += `
                <div class="records-section">
                    <strong>Header Value:</strong>
                    <code class="monospace dkim-record">${results.hsts.header_value}</code>
                </div>`;
            }
        }

        html += `</ul></div></div>`;
    }

    return html;
}

/**
 * Create Certificate tab content
 * @param {Object} results - Web security results
 * @returns {string} - HTML for certificate tab
 */
function createCertificateTabContent(results) {
    let html = `
    <div class="section-header-main">
        <h3>Certificate Details</h3>`;

    if (results.certificate && results.certificate.is_valid) {
        html += `
        <span class="status-tag valid">
            <i class="fas fa-check-circle"></i> Valid
        </span>`;
    } else {
        html += `
        <span class="status-tag invalid">
            <i class="fas fa-times-circle"></i> Invalid
        </span>`;
    }

    html += `</div>`;

    if (results.connectivity_error) {
        html += `
        <div class="error-message">
            <i class="fas fa-exclamation-triangle"></i>
            <span>Certificate information not available due to connection issues</span>
        </div>`;
    } else if (results.certificate) {
        // Subject & Validity Section
        html += `
        <div class="certificate-section">
            <div class="section-header">
                <i class="fas fa-id-card"></i>
                <span>Subject & Validity</span>
            </div>
            <div class="section-content">
                <div class="certificate-row">
                    <div class="key">Subject:</div>
                    <div class="value">${results.certificate.subject || 'Unknown'}</div>
                </div>
                <div class="certificate-row">
                    <div class="key">Issuer:</div>
                    <div class="value">${results.certificate.issuer || 'Unknown'}</div>
                </div>
                <div class="certificate-row">
                    <div class="key">Valid From:</div>
                    <div class="value">${results.certificate.valid_from || 'Unknown'}</div>
                </div>
                <div class="certificate-row">
                    <div class="key">Valid Until:</div>
                    <div class="value">${results.certificate.valid_until || 'Unknown'}</div>
                </div>`;

        if (results.certificate.days_until_expiry !== undefined) {
            const daysUntilExpiry = results.certificate.days_until_expiry;
            let expiryIconClass = '';

            if (daysUntilExpiry > 30) {
                expiryIconClass = 'check-circle text-success';
            } else if (daysUntilExpiry > 7) {
                expiryIconClass = 'exclamation-triangle text-warning';
            } else {
                expiryIconClass = 'times-circle text-danger';
            }

            html += `
            <div class="certificate-row">
                <div class="key with-icon">
                    <i class="fas fa-${expiryIconClass}"></i>
                    Days Until Expiry:
                </div>
                <div class="value">${daysUntilExpiry} days</div>
            </div>`;
        }

        html += `</div></div>`;

        // Key Information Section
        if (results.certificate.key_info) {
            const keyInfo = results.certificate.key_info;
            const keySecure = keyInfo.secure || false;

            html += `
            <div class="certificate-section">
                <div class="section-header">
                    <i class="fas fa-key"></i>
                    <span>Key Information</span>
                </div>
                <div class="section-content">
                    <div class="certificate-row">
                        <div class="key">Key Type:</div>
                        <div class="value">${keyInfo.type || 'Unknown'}</div>
                    </div>
                    <div class="certificate-row">
                        <div class="key">Key Length:</div>
                        <div class="value">${keyInfo.length || 'Unknown'} bits</div>
                    </div>
                    <div class="certificate-row">
                        <div class="key with-icon">
                            <i class="fas fa-${keySecure ? 'check-circle text-success' : 'times-circle text-danger'}"></i>
                            Key Security:
                        </div>
                        <div class="value">${keySecure ? 'Secure' : 'Insecure'}</div>
                    </div>
                </div>
            </div>`;
        }

        // Signature Algorithm Section
        if (results.certificate.signature_algorithm) {
            const sigAlg = results.certificate.signature_algorithm;
            const sigStrong = sigAlg.security === 'strong';

            html += `
            <div class="certificate-section">
                <div class="section-header">
                    <i class="fas fa-signature"></i>
                    <span>Signature Algorithm</span>
                </div>
                <div class="section-content">
                    <div class="certificate-row">
                        <div class="key">Algorithm:</div>
                        <div class="value">${sigAlg.name || 'Unknown'}</div>
                    </div>
                    <div class="certificate-row">
                        <div class="key with-icon">
                            <i class="fas fa-${sigStrong ? 'check-circle text-success' : 'times-circle text-danger'}"></i>
                            Security:
                        </div>
                        <div class="value">${capitalize(sigAlg.security || 'Unknown')}</div>
                    </div>
                </div>
            </div>`;
        }

        // Subject Alternative Names Section
        if (results.certificate.subject_alternative_names) {
            const san = results.certificate.subject_alternative_names;
            const containsDomain = san.contains_domain || false;

            html += `
            <div class="certificate-section">
                <div class="section-header">
                    <i class="fas fa-globe-americas"></i>
                    <span>Subject Alternative Names</span>
                </div>
                <div class="section-content">
                    <div class="certificate-row">
                        <div class="key with-icon">
                            <i class="fas fa-${containsDomain ? 'check-circle text-success' : 'times-circle text-danger'}"></i>
                            Contains Domain:
                        </div>
                        <div class="value">${containsDomain ? 'Yes' : 'No'}</div>
                    </div>`;

            if (san.names && san.names.length > 0) {
                html += `
                <div class="dns-names-container">
                    <div class="key">Names:</div>
                    <div class="dns-names-list">`;

                san.names.forEach(name => {
                    html += `<div class="dns-name">${name}</div>`;
                });

                html += `</div></div>`;
            }

            html += `</div></div>`;
        }

        // Certificate Chain Section
        if (results.certificate.chain_info && results.certificate.chain_info.length > 0) {
            html += `
            <div class="certificate-section">
                <div class="section-header">
                    <i class="fas fa-link"></i>
                    <span>Certificate Chain</span>
                </div>
                <div class="section-content cert-chain">`;

            results.certificate.chain_info.forEach((cert, index) => {
                const isLast = index === results.certificate.chain_info.length - 1;

                html += `
                <div class="cert-item">
                    <div class="cert-subject">
                        <i class="fas fa-certificate"></i>
                        ${cert.subject}
                    </div>
                    
                    <div class="cert-details">
                        <div class="cert-details-left">
                            <div class="certificate-row">
                                <div class="key">Issuer:</div>
                                <div class="value">${cert.issuer}</div>
                            </div>
                            <div class="certificate-row">
                                <div class="key">Key:</div>
                                <div class="value">${cert.key_type} (${cert.key_length} bits)</div>
                            </div>
                            <div class="certificate-row">
                                <div class="key">Signature:</div>
                                <div class="value">${cert.signature_algorithm}</div>
                            </div>`;

                if (cert.signature_security) {
                    const sigSecure = cert.signature_security === 'strong';

                    html += `
                    <div class="certificate-row">
                        <div class="key with-icon">
                            <i class="fas fa-${sigSecure ? 'check-circle text-success' : 'times-circle text-danger'}"></i>
                            Security:
                        </div>
                        <div class="value">${capitalize(cert.signature_security)}</div>
                    </div>`;
                }

                html += `</div>
                        
                        <div class="cert-details-right">
                            <div class="certificate-row">
                                <div class="key">Valid From:</div>
                                <div class="value">${cert.valid_from}</div>
                            </div>
                            <div class="certificate-row">
                                <div class="key">Valid Until:</div>
                                <div class="value">${cert.valid_until}</div>
                            </div>
                            <div class="certificate-row">
                                <div class="key">Serial:</div>
                                <div class="value serial-value">${cert.serial_number}</div>
                            </div>
                        </div>
                    </div>
                </div>`;

                if (!isLast) {
                    html += `
                    <div class="chain-connector">
                        <i class="fas fa-arrow-down"></i>
                    </div>`;
                }
            });

            html += `</div></div>`;
        }
    } else {
        html += `
        <div class="error-message">
            <i class="fas fa-exclamation-triangle"></i>
            <span>Certificate information not available${results.certificate && results.certificate.validation_error ? ': ' + results.certificate.validation_error : ''}</span>
        </div>`;
    }

    return html;
}

/**
 * Create Protocols & Ciphers tab content
 * @param {Object} results - Web security results
 * @returns {string} - HTML for protocols tab
 */
function createProtocolsTabContent(results) {
    if (results.connectivity_error) {
        return `
        <div class="error-message">
            <i class="fas fa-exclamation-triangle"></i>
            <span>Protocol and cipher information not available due to connection issues</span>
        </div>`;
    }

    let html = '';

    // Protocol Support Section
    html += `
    <div class="summary-section">
        <div class="section-header">
            <i class="fas fa-exchange-alt"></i>
            Protocol Support
        </div>`;

    if (results.protocol_support && results.protocol_support.protocols) {
        html += `
        <div class="summary-content">
            <table class="validation-table details-table">
                <thead>
                <tr>
                    <th>Protocol</th>
                    <th>Status</th>
                    <th>Security</th>
                </tr>
                </thead>
                <tbody>`;

        results.protocol_support.protocols.forEach(protocol => {
            html += `
            <tr>
                <td>${protocol.name}</td>
                <td>
                    ${protocol.supported ?
                        `<i class="fas fa-check-circle ${protocol.secure ? 'status-valid' : 'status-not-valid'}"></i> Supported` :
                        `<i class="fas fa-times-circle ${!protocol.secure ? 'status-valid' : 'status-not-valid'}"></i> Not Supported`
                    }
                </td>
                <td>
                    ${protocol.secure ?
                        `Secure` :
                        `Insecure`
                    }
                </td>
            </tr>`;
        });

        html += `</tbody></table></div></div>`;
    } else {
        html += `
        <div class="error-message">
            <i class="fas fa-exclamation-triangle"></i>
            <span>No protocol information available</span>
        </div>
        </div>`;
    }

    // Cipher Suites Section
    html += `
    <div class="summary-section">
        <div class="section-header">
            <i class="fas fa-lock"></i>
            Cipher Suites
        </div>`;

    if (results.ciphers && results.ciphers.by_protocol) {
        const hasStrongCiphers = results.ciphers.has_strong_ciphers || false;
        const hasWeakCiphers = results.ciphers.has_weak_ciphers || false;
        const hasRecommendedCiphers = Object.values(results.ciphers.by_protocol)
            .flat()
            .some(cipher => cipher.recommended);

        html += `
        <div class="summary-content">
            <div class="flex items-center gap-2 mb-4">
                <i class="fas fa-${hasStrongCiphers ? 'check-circle status-valid' : 'times-circle status-not-valid'} me-2"></i>
                <strong>Strong Ciphers:</strong> ${hasStrongCiphers ? 'Yes' : 'No'}
            </div>
            <div class="flex items-center gap-2 mb-4">
                <i class="fas fa-${!hasWeakCiphers ? 'check-circle status-valid' : 'exclamation-triangle status-not-valid'} me-2"></i>
                <strong>Weak Ciphers:</strong> ${!hasWeakCiphers ? 'No' : 'Yes'}
            </div>
            <div class="flex items-center gap-2 mb-4">
                <i class="fas fa-${hasRecommendedCiphers ? 'check-circle status-valid' : 'info-circle'} me-2"></i>
                <strong>IANA Recommended Ciphers:</strong> ${hasRecommendedCiphers ? 'Yes' : 'No'}
            </div>`;

        // Create collapsible sections for each protocol's ciphers
        for (const [protocol, ciphers] of Object.entries(results.ciphers.by_protocol)) {
            if (ciphers.length > 0) {
                html += `
                <div class="record-card mb-4">
                    <div class="record-card-header collapsible" onclick="toggleCollapse(this)">
                        <i class="fas fa-exchange-alt"></i>
                        <span>${protocol} Ciphers (${ciphers.length})</span>
                        <i class="fas fa-chevron-down collapse-icon"></i>
                    </div>
                    <div class="record-card-body">
                        <!-- Add responsive table wrapper -->
                        <div class="table-responsive">
                            <table class="validation-table details-table">
                                <thead>
                                <tr>
                                    <th style="min-width: 180px;">Cipher</th>
                                    <th>Key Exchange</th>
                                    <th>Auth</th>
                                    <th>Encryption</th>
                                    <th>MAC</th>
                                    <th>Bits</th>
                                    <th>Strength</th>
                                    <th>IANA Recommended</th>
                                    <th>DTLS Compatible</th>
                                </tr>
                                </thead>
                                <tbody>`;

                ciphers.forEach(cipher => {
                    html += `
                    <tr>
                        <td class="monospace nowrap" title="${cipher.name}">${cipher.name}</td>
                        <td>${cipher.key_exchange || 'N/A'}</td>
                        <td>${cipher.authentication || 'N/A'}</td>
                        <td>${cipher.encryption || 'N/A'}</td>
                        <td>${cipher.mac || 'N/A'}</td>
                        <td>${cipher.bits || 'N/A'}</td>
                        <td>
                            <span class="status-badge ${cipher.strength === 'strong' ? 'status-valid' : cipher.strength === 'medium' ? 'status-partially-valid' : 'status-not-valid'}">
                                <i class="fas fa-${cipher.strength === 'strong' ? 'shield-alt' : cipher.strength === 'medium' ? 'exclamation-circle' : 'exclamation-triangle'}"></i>
                                ${capitalize(cipher.strength)}
                            </span>
                        </td>
                        <td>
                            <span class="status-badge ${cipher.recommended ? 'status-valid' : ''}">
                                <i class="fas fa-${cipher.recommended ? 'thumbs-up' : 'thumbs-down'}"></i>
                                ${cipher.recommended ? 'Yes' : 'No'}
                            </span>
                        </td>
                        <td>
                            <span class="status-badge ${cipher.dtls_ok ? 'status-valid' : ''}">
                                <i class="fas fa-${cipher.dtls_ok ? 'check' : 'times'}"></i>
                                ${cipher.dtls_ok ? 'Yes' : 'No'}
                            </span>
                        </td>
                    </tr>`;
                });

                html += `</tbody></table></div></div></div>`;
            }
        }

        // Add cipher classification information section
        html += `
        <div class="record-card mb-5">
            <div class="record-card-header collapsible collapsed" onclick="toggleCollapse(this)">
                <i class="fas fa-shield-alt"></i>
                <span>Cipher Classification Information</span>
                <i class="fas fa-chevron-down collapse-icon"></i>
            </div>
            <div class="record-card-body" style="max-height: 0px; padding: 0px 16px; overflow: hidden;">
                <!-- Classification References Section -->
                <div class="cipherinfo-section mb-5">
                    <h4 class="cipherinfo-title mb-3">Classification References</h4>
                    <p class="mb-4">Our cipher strength classification (Strong/Medium/Weak) is based on these authoritative sources:</p>
                    
                    <div class="cipherinfo-ref-container">
                        <div class="cipherinfo-ref-card mb-3 p-3 border rounded">
                            <h5 class="cipherinfo-ref-title">
                                <a href="https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4" target="_blank" class="cipherinfo-link">
                                    <i class="fas fa-external-link-alt me-2"></i>IANA TLS Cipher Suite Registry
                                </a>
                            </h5>
                            <p class="cipherinfo-ref-desc mt-2">
                                Used for the "Recommended" flag and DTLS compatibility status. IANA explicitly notes that if a cipher suite isn't marked as "Recommended," it doesn't necessarily mean it's flawed, but rather that it "has not been through the IETF consensus process, has limited applicability, or is intended only for specific use cases."
                            </p>
                            
                            <h5 class="cipherinfo-ref-title">
                                <a href="https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final" target="_blank" class="cipherinfo-link">
                                    <i class="fas fa-external-link-alt me-2"></i>NIST SP 800-52r2
                                </a>
                            </h5>
                            <p class="cipherinfo-ref-desc mt-2">
                                Provides our baseline for cipher security classification, particularly the recommendation to "prefer ephemeral keys over static keys (i.e., prefer DHE over DH, and prefer ECDHE over ECDH)" for forward secrecy.
                            </p>
                            
                            <h5 class="cipherinfo-ref-title">
                                <a href="https://english.ncsc.nl/publications/publications/2021/january/19/it-security-guidelines-for-transport-layer-security-2.1" target="_blank" class="cipherinfo-link">
                                    <i class="fas fa-external-link-alt me-2"></i>NCSC-NL TLS Guidelines
                                </a>
                            </h5>
                            <p class="cipherinfo-ref-desc mt-2">
                                Our classification framework closely aligns with NCSC's four-tier security level system.
                            </p>
                        </div>
                    </div>
                </div>
        
                
                <!-- Strength Classification Criteria Section -->
                <div class="cipherinfo-section mb-5">
                    <h4 class="cipherinfo-title mb-3">Strength Classification Criteria</h4>
                    <p class="mb-3">Our cipher classification applies these specific rules:</p>
                    
                    <div class="cipherinfo-strength-grid">
                        <div class="cipherinfo-strength-card cipherinfo-strong p-3 border rounded">
                            <h5 class="d-flex align-items-center">
                                <span class="cipherinfo-badge cipherinfo-badge-success me-2 px-2 py-1 rounded">Strong</span>
                            </h5>
                            <p class="mt-2 mb-0">
                                Cipher suites using AEAD encryption (GCM, CCM, CHACHA20-POLY1305), modern key exchange with forward secrecy (ECDHE, DHE), and secure hash functions (SHA-256, SHA-384, SHA-512).
                            </p>
                        </div>
                        
                        <div class="cipherinfo-strength-card cipherinfo-medium p-3 border rounded mt-2">
                            <h5 class="d-flex align-items-center">
                                <span class="cipherinfo-badge cipherinfo-badge-warning me-2 px-2 py-1 rounded">Medium</span>
                            </h5>
                            <p class="mt-2 mb-0">
                                Cipher suites with CBC mode encryption with forward secrecy, or AEAD encryption without forward secrecy.
                            </p>
                        </div>
                        
                        <div class="cipherinfo-strength-card cipherinfo-weak p-3 border rounded mt-2">
                            <h5 class="d-flex align-items-center">
                                <span class="cipherinfo-badge cipherinfo-badge-danger me-2 px-2 py-1 rounded">Weak</span>
                            </h5>
                            <p class="mt-2 mb-0">
                                Cipher suites containing vulnerable components (NULL, RC4, 3DES, EXPORT, anonymous methods, MD5), static key exchange without forward secrecy, or obsolete hash functions (SHA-1).
                            </p>
                        </div>
                        
                        <div class="cipherinfo-strength-card cipherinfo-protocol p-3 border rounded mt-2">
                            <h5 class="d-flex align-items-center">
                                <span class="cipherinfo-badge cipherinfo-badge-info me-2 px-2 py-1 rounded">Protocol Impact</span>
                            </h5>
                            <p class="mt-2 mb-0">
                                TLS 1.3 cipher suites are classified as Strong, while TLS 1.0/1.1 cipher suites are classified no higher than Medium regardless of other components.
                            </p>
                        </div>
                    </div>
                </div>
        
                <!-- Table Column Legend Section -->
                <div class="cipherinfo-section">
                    <h4 class="cipherinfo-title mb-3">Table Column Legend</h4>
                    
                    <div class="cipherinfo-legend-table">
                        <div class="cipherinfo-legend-row">
                            <div class="cipherinfo-legend-cell">
                                <div class="cipherinfo-legend-term">Key Exchange:</div>
                                <div class="cipherinfo-legend-desc">Key exchange algorithm (e.g., ECDHE, DHE, RSA)</div>
                            </div>
                            <div class="cipherinfo-legend-cell">
                                <div class="cipherinfo-legend-term">Auth:</div>
                                <div class="cipherinfo-legend-desc">Authentication method (e.g., RSA, ECDSA)</div>
                            </div>
                            <div class="cipherinfo-legend-cell">
                                <div class="cipherinfo-legend-term">Encryption:</div>
                                <div class="cipherinfo-legend-desc">Bulk encryption algorithm and mode (e.g., AES-GCM)</div>
                            </div>
                        </div>
                        <div class="cipherinfo-legend-row">
                            <div class="cipherinfo-legend-cell">
                                <div class="cipherinfo-legend-term">MAC:</div>
                                <div class="cipherinfo-legend-desc">Message Authentication Code algorithm</div>
                            </div>
                            <div class="cipherinfo-legend-cell">
                                <div class="cipherinfo-legend-term">Bits:</div>
                                <div class="cipherinfo-legend-desc">Encryption key size in bits</div>
                            </div>
                            <div class="cipherinfo-legend-cell">
                                <div class="cipherinfo-legend-term">IANA Recommended:</div>
                                <div class="cipherinfo-legend-desc">Cipher suites officially recommended by IANA</div>
                            </div>
                        </div>
                        <div class="cipherinfo-legend-row">
                            <div class="cipherinfo-legend-cell">
                                <div class="cipherinfo-legend-term">DTLS Compatible:</div>
                                <div class="cipherinfo-legend-desc">Cipher suites compatible with Datagram TLS</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>`
        html += `</div></div>`;
    } else {
        html += `
        <div class="error-message">
            <i class="fas fa-exclamation-triangle"></i>
            <span>No cipher information available</span>
        </div>
        </div>`;
    }

    return html;
}

/**
 * Create Security Headers tab content
 * @param {Object} results - Web security results
 * @returns {string} - HTML for security headers tab
 */
function createHeadersTabContent(results) {
    let html = `
    <div class="summary-section">
        <div class="section-header">
            <i class="fas fa-shield-alt"></i>
            <span>Security Headers</span>
        </div>`;

    if (results.security_headers && !results.connectivity_error) {
        html += `
        <div class="summary-content">
            <table class="validation-table details-table">
                <colgroup>
                    <col style="width: 25%"> <!-- Header column -->
                    <col style="width: 10%"> <!-- Status column -->
                    <col style="width: 65%"> <!-- Value column -->
                </colgroup>
                <thead>
                <tr>
                    <th><i class="fas fa-tag"></i> Header</th>
                    <th><i class="fas fa-info-circle"></i> Status</th>
                    <th><i class="fas fa-list-ul"></i> Value</th>
                </tr>
                </thead>
                <tbody>`;

        // Content-Security-Policy
        const cspPresent = results.security_headers.content_security_policy;
        html += `
        <tr>
            <td>
                <div class="component-header">
                    <i class="fas fa-shield-alt"></i>
                    <span>content-security-policy</span>
                </div>
            </td>
            <td>
                <div class="status-indicator">
                    <span class="status-badge ${cspPresent ? 'status-valid' : 'status-invalid'}">
                        <i class="fas fa-${cspPresent ? 'check-circle' : 'times-circle'}"></i>
                        ${cspPresent ? 'Present' : 'Missing'}
                    </span>
                </div>
            </td>
            <td>
                ${cspPresent ?
                    `<div class="record-details">
                        <div class="code-wrap">${cspPresent}</div>
                    </div>` :
                    `<span class="not-set">N/A</span>`
                }
            </td>
        </tr>`;

        // X-Content-Type-Options
        const xctoPresent = results.security_headers.x_content_type_options;
        html += `
        <tr>
            <td>
                <div class="component-header">
                    <i class="fas fa-file-code"></i>
                    <span>x-content-type-options</span>
                </div>
            </td>
            <td>
                <div class="status-indicator">
                    <span class="status-badge ${xctoPresent ? 'status-valid' : 'status-invalid'}">
                        <i class="fas fa-${xctoPresent ? 'check-circle' : 'times-circle'}"></i>
                        ${xctoPresent ? 'Present' : 'Missing'}
                    </span>
                </div>
            </td>
            <td>
                ${xctoPresent ?
                    `<div class="record-details">
                        <span>${xctoPresent}</span>
                    </div>` :
                    `<span class="not-set">N/A</span>`
                }
            </td>
        </tr>`;

        // X-Frame-Options
        const xfoPresent = results.security_headers.x_frame_options;
        html += `
        <tr>
            <td>
                <div class="component-header">
                    <i class="fas fa-window-maximize"></i>
                    <span>x-frame-options</span>
                </div>
            </td>
            <td>
                <div class="status-indicator">
                    <span class="status-badge ${xfoPresent ? 'status-valid' : 'status-invalid'}">
                        <i class="fas fa-${xfoPresent ? 'check-circle' : 'times-circle'}"></i>
                        ${xfoPresent ? 'Present' : 'Missing'}
                    </span>
                </div>
            </td>
            <td>
                ${xfoPresent ?
                    `<div class="record-details">
                        <span>${xfoPresent}</span>
                    </div>` :
                    `<span class="not-set">N/A</span>`
                }
            </td>
        </tr>`;

        // Referrer-Policy
        const refPolicyPresent = results.security_headers.referrer_policy;
        html += `
        <tr>
            <td>
                <div class="component-header">
                    <i class="fas fa-external-link-alt"></i>
                    <span>referrer-policy</span>
                </div>
            </td>
            <td>
                <div class="status-indicator">
                    <span class="status-badge ${refPolicyPresent ? 'status-valid' : 'status-invalid'}">
                        <i class="fas fa-${refPolicyPresent ? 'check-circle' : 'times-circle'}"></i>
                        ${refPolicyPresent ? 'Present' : 'Missing'}
                    </span>
                </div>
            </td>
            <td>
                ${refPolicyPresent ?
                    `<div class="record-details">
                        <span>${refPolicyPresent}</span>
                    </div>` :
                    `<span class="not-set">N/A</span>`
                }
            </td>
        </tr>`;

        // Strict-Transport-Security (HSTS)
        const hstsEnabled = results.hsts && results.hsts.enabled;
        const hstsValue = hstsEnabled && results.hsts.header_value;
        html += `
        <tr>
            <td>
                <div class="component-header">
                    <i class="fas fa-lock"></i>
                    <span>strict-transport-security</span>
                </div>
            </td>
            <td>
                <div class="status-indicator">
                    <span class="status-badge ${hstsEnabled ? 'status-valid' : 'status-invalid'}">
                        <i class="fas fa-${hstsEnabled ? 'check-circle' : 'times-circle'}"></i>
                        ${hstsEnabled ? 'Present' : 'Missing'}
                    </span>
                </div>
            </td>
            <td>
                ${hstsValue ?
                    `<div class="record-details">
                        <span>${hstsValue}</span>
                    </div>` :
                    `<span class="not-set">N/A</span>`
                }
            </td>
        </tr>`;

        // X-XSS-Protection
        if (results.security_headers.x_xss_protection !== undefined) {
            const xxpPresent = results.security_headers.x_xss_protection;
            html += `
            <tr>
                <td>
                    <div class="component-header">
                        <i class="fas fa-user-shield"></i>
                        <span>x-xss-protection</span>
                    </div>
                </td>
                <td>
                    <div class="status-indicator">
                        <span class="status-badge ${xxpPresent ? 'status-valid' : 'status-invalid'}">
                            <i class="fas fa-${xxpPresent ? 'check-circle' : 'times-circle'}"></i>
                            ${xxpPresent ? 'Present' : 'Missing'}
                        </span>
                    </div>
                </td>
                <td>
                    ${xxpPresent ?
                        `<div class="record-details">
                            <span>${xxpPresent}</span>
                        </div>` :
                        `<span class="not-set">N/A</span>`
                    }
                </td>
            </tr>`;
        }

        // Permissions-Policy
        if (results.security_headers.permissions_policy !== undefined) {
            const ppPresent = results.security_headers.permissions_policy;
            html += `
            <tr>
                <td>
                    <div class="component-header">
                        <i class="fas fa-sliders-h"></i>
                        <span>permissions-policy</span>
                    </div>
                </td>
                <td>
                    <div class="status-indicator">
                        <span class="status-badge ${ppPresent ? 'status-valid' : 'status-invalid'}">
                            <i class="fas fa-${ppPresent ? 'check-circle' : 'times-circle'}"></i>
                            ${ppPresent ? 'Present' : 'Missing'}
                        </span>
                    </div>
                </td>
                <td>
                    ${ppPresent ?
                        `<div class="record-details">
                            <div class="code-wrap">${ppPresent}</div>
                        </div>` :
                        `<span class="not-set">N/A</span>`
                    }
                </td>
            </tr>`;
        }

        html += `</tbody></table>
        
        <div class="headers-info-box">
            <div class="info-icon" style="margin-right: 8px; color: #0263CBFF">
                <i class="fas fa-info-circle"></i>
            </div>
            <div class="info-content">
                <p>Security headers help protect your site against common web vulnerabilities such as XSS, clickjacking, and other attacks. Missing headers may impact your site's security posture.</p>
            </div>
        </div>
        </div>`;
    } else {
        html += `
        <div class="error-message">
            <i class="fas fa-exclamation-triangle"></i>
            <span>Security header information not available${results.connectivity_error ? ' due to connection issues' : ''}</span>
        </div>`;
    }

    html += `</div>`;

    return html;
}

/**
 * Capitalize the first letter of a string
 * @param {string} string - String to capitalize
 * @returns {string} - Capitalized string
 */
function capitalize(string) {
    if (!string) return '';
    return string.charAt(0).toUpperCase() + string.slice(1);
}