// renderers.js - Renders validation table and other components

/**
 * Render the validation table with data
 */
function renderValidationTable() {
    const tableBody = document.getElementById('validation-table-body');
    if (!tableBody) {
        console.error('Table body element not found');
        return;
    }

    // Clear the table body
    tableBody.innerHTML = '';

    // Get domains from RPKI state
    let domains = Object.keys(window.validationData.RPKI.state || {});

    // Check if any domains have country or institution data
    const hasCountryData = domains.some(domain =>
        window.domainMetadata?.[domain]?.country &&
        window.domainMetadata[domain].country.trim() !== '');

    const hasInstitutionData = domains.some(domain =>
        window.domainMetadata?.[domain]?.institution &&
        window.domainMetadata[domain].institution.trim() !== '');

    // Add base columns to header row (before the tooltips.js adds validation columns)
    const headerRow = document.querySelector('#table-headers tr');
    if (headerRow) {
        // Clear existing headers to start fresh
        headerRow.innerHTML = '';

        // Add Country header if needed
        if (hasCountryData) {
            const countryHeader = document.createElement('th');
            countryHeader.textContent = 'Country';
            headerRow.appendChild(countryHeader);
        }

        // Add Institution header if needed
        if (hasInstitutionData) {
            const institutionHeader = document.createElement('th');
            institutionHeader.textContent = 'Institution';
            headerRow.appendChild(institutionHeader);
        }

        // Always add Domain header
        const domainHeader = document.createElement('th');
        domainHeader.textContent = 'Domain';
        headerRow.appendChild(domainHeader);

        // Validation columns will be added by tooltips.js
    }

    // Sort domains appropriately
    if (hasCountryData) {
        domains.sort((a, b) => {
            const countryA = (window.domainMetadata?.[a]?.country || '').toLowerCase();
            const countryB = (window.domainMetadata?.[b]?.country || '').toLowerCase();

            // If countries are the same, sort by domain
            if (countryA === countryB) {
                return a.localeCompare(b);
            }

            return countryA.localeCompare(countryB);
        });
    } else {
        // Sort by domain name if no country data
        domains.sort((a, b) => a.localeCompare(b));
    }

    // Render each domain row
    domains.forEach(domain => {
        const row = createDomainRow(domain, hasCountryData, hasInstitutionData);
        tableBody.appendChild(row);
    });
}

/**
 * Create a table row for a domain
 * @param {string} domain - Domain name
 * @returns {HTMLElement} - Table row element
 */
function createDomainRow(domain, includeCountry, includeInstitution) {
    const row = document.createElement('tr');
    row.className = 'service-row';

    // Country cell (only if data exists)
    if (includeCountry) {
        const countryCell = document.createElement('td');
        countryCell.textContent = window.domainMetadata?.[domain]?.country || '';
        row.appendChild(countryCell);
    }

    // Institution cell (only if data exists)
    if (includeInstitution) {
        const institutionCell = document.createElement('td');
        institutionCell.textContent = window.domainMetadata?.[domain]?.institution || '';
        row.appendChild(institutionCell);
    }

    // Domain cell (always included)
    const domainCell = document.createElement('td');
    domainCell.className = 'server-name';
    domainCell.textContent = domain;
    row.appendChild(domainCell);

    // Add validation status cells (this part remains unchanged)
    CONFIG.COLUMNS.forEach(column => {
        const validationType = column.modalType;

        switch (validationType) {
            case 'RPKI':
            case 'DANE':
                row.appendChild(createRPKIorDANECell(validationType, domain));
                break;
            case 'DNSSEC':
                row.appendChild(createDNSSECCell(domain));
                break;
            case 'EMAIL_SECURITY':
                row.appendChild(createEmailSecurityCell(domain));
                break;
            case 'WEB_SECURITY':
                row.appendChild(createWebSecurityCell(domain));
                break;
            default:
                console.warn(`Unknown validation type: ${validationType}`);
                const emptyCell = document.createElement('td');
                emptyCell.className = 'text-center';
                emptyCell.innerHTML = '<span class="status-not-found">Not Available</span>';
                row.appendChild(emptyCell);
        }
    });

    return row;
}

/**
 * Create a cell for RPKI or DANE validation
 * @param {string} type - Validation type (RPKI or DANE)
 * @param {string} domain - Domain name
 * @returns {HTMLElement} - Table cell element
 */
function createRPKIorDANECell(type, domain) {
    const cell = document.createElement('td');
    cell.className = 'text-center';

    // Check if validation data exists for this domain
    if (!window.validationData[type] ||
        !window.validationData[type].state ||
        !window.validationData[type].state[domain]) {
        cell.innerHTML = '<span class="status-not-found">Not Available</span>';
        return cell;
    }

    if (type === 'RPKI' &&
        window.validationData[type].state[domain].rpki_state === 'unknown' &&
        window.validationData[type].state[domain].message === 'RPKI validator unavailable') {
        cell.innerHTML = '<span class="status-not-found">Not Available</span>';
        return cell;
    }

    // Create button and modal
    const modalId = `${type.toLowerCase()}-${domain.replace(/\./g, '-')}`;
    const button = document.createElement('button');
    button.className = 'status-button';
    button.onclick = function () {
        openModalWithData(
            modalId,
            type,
            domain,
            {
                state: window.validationData[type].state[domain],
                results: window.validationData[type].results[domain]
            }
        );
    };

    // Create status group container
    const statusGroup = document.createElement('div');
    statusGroup.className = 'service-status-group';

    // Create security details container
    const securityDetails = document.createElement('div');
    securityDetails.className = 'service-security-details';

    // Add status details for different check types
    CONFIG.CHECK_TYPES.forEach(checkType => {
        if (window.validationData[type].state[domain][checkType]) {
            const state = window.validationData[type].state[domain][checkType].toLowerCase();
            const statusDetail = document.createElement('div');
            statusDetail.className = 'status-detail';

            // Create icon based on state
            let iconClass = '';
            if (type === 'DANE' && state === 'not-valid' &&
                (checkType === 'Nameserver of Domain' || checkType === 'Nameserver of Mail Server')) {
                iconClass = 'fas fa-question-circle status-not-found';
            } else {
                const status = CONFIG.STATUS_MAPPING[state] ||
                    CONFIG.STATUS_MAPPING['not-found'];
                iconClass = `fas fa-${status.icon} ${status.class}`;
            }

            statusDetail.innerHTML = `
                <i class="${iconClass}"></i>
                <span>${CONFIG.SHORT_NAMES[checkType] || checkType}</span>
            `;

            securityDetails.appendChild(statusDetail);
        }
    });

    statusGroup.appendChild(securityDetails);
    button.appendChild(statusGroup);
    cell.appendChild(button);

    return cell;
}

/**
 * Create a cell for DNSSEC validation
 * @param {string} domain - Domain name
 * @returns {HTMLElement} - Table cell element
 */
function createDNSSECCell(domain) {
    const cell = document.createElement('td');
    cell.className = 'text-center';

    // Check if DNSSEC data exists for this domain
    if (!window.validationData.DNSSEC ||
        !window.validationData.DNSSEC.results ||
        !window.validationData.DNSSEC.results[domain]) {
        cell.innerHTML = '<span class="status-not-found">Not Available</span>';
        return cell;
    }

    const dnssecData = window.validationData.DNSSEC.results[domain];
    const modalId = `dnssec-${domain.replace(/\./g, '-')}`;

    // Create button with appropriate icon and text
    const button = document.createElement('button');
    button.className = 'status-button';
    button.onclick = function () {
        openModalWithData(modalId, 'DNSSEC', domain, dnssecData);
    };

    if (dnssecData.dnssec_status && dnssecData.dnssec_status.is_signed) {
        button.innerHTML = '<i class="fas fa-check-circle status-icon status-valid"></i> Signed';
    } else {
        button.innerHTML = '<i class="fas fa-times-circle status-icon status-not-valid"></i> Unsigned';
    }

    cell.appendChild(button);

    return cell;
}

/**
 * Create a cell for Email Security validation
 * @param {string} domain - Domain name
 * @returns {HTMLElement} - Table cell element
 */
function createEmailSecurityCell(domain) {
    const cell = document.createElement('td');
    cell.className = 'text-center';

    // Check if Email Security data exists for this domain
    if (!window.validationData.EMAIL_SECURITY ||
        !window.validationData.EMAIL_SECURITY.state ||
        !window.validationData.EMAIL_SECURITY.state[domain]) {
        cell.innerHTML = '<span class="status-not-found">Not Available</span>';
        return cell;
    }

    const emailSecurityState = window.validationData.EMAIL_SECURITY.state[domain];
    const emailSecurityResults = window.validationData.EMAIL_SECURITY.results[domain];
    const modalId = `email-security-${domain.replace(/\./g, '-')}`;

    // Create button with appropriate content
    const button = document.createElement('button');
    button.className = 'status-button';
    button.onclick = function () {
        openModalWithData(modalId, 'EMAIL_SECURITY', domain, emailSecurityResults);
    };

    if (emailSecurityState) {
        // Create status group with SPF, DKIM, DMARC indicators
        const statusGroup = document.createElement('div');
        statusGroup.className = 'service-status-group';

        const securityDetails = document.createElement('div');
        securityDetails.className = 'service-security-details';

        // SPF status
        const spfDetail = document.createElement('div');
        spfDetail.className = 'status-detail';
        const spfResults = emailSecurityResults.spf;

        let spfIconClass = '';
        if (spfResults.has_spf && spfResults.policy_sufficiently_strict) {
            spfIconClass = 'fas fa-check-circle status-valid';
        } else if (spfResults.has_spf && !spfResults.policy_sufficiently_strict) {
            spfIconClass = 'fas fa-exclamation-triangle status-partially-valid';
        } else {
            spfIconClass = 'fas fa-times-circle status-not-valid';
        }

        spfDetail.innerHTML = `<i class="${spfIconClass}"></i><span>SPF</span>`;
        securityDetails.appendChild(spfDetail);

        // DKIM status
        const dkimDetail = document.createElement('div');
        dkimDetail.className = 'status-detail';
        const dkimIconClass = emailSecurityState.DKIM === 'valid'
            ? 'fas fa-check-circle status-valid'
            : 'fas fa-times-circle status-not-valid';

        dkimDetail.innerHTML = `<i class="${dkimIconClass}"></i><span>DKIM</span>`;
        securityDetails.appendChild(dkimDetail);

        // DMARC status
        const dmarcDetail = document.createElement('div');
        dmarcDetail.className = 'status-detail';
        const dmarcResults = emailSecurityResults.dmarc;

        let dmarcIconClass = '';
        if (dmarcResults.record_exists && dmarcResults.valid) {
            dmarcIconClass = 'fas fa-check-circle status-valid';
        } else if (dmarcResults.record_exists && !dmarcResults.valid) {
            dmarcIconClass = 'fas fa-exclamation-triangle status-partially-valid';
        } else {
            dmarcIconClass = 'fas fa-times-circle status-not-valid';
        }

        dmarcDetail.innerHTML = `<i class="${dmarcIconClass}"></i><span>DMARC</span>`;
        securityDetails.appendChild(dmarcDetail);

        statusGroup.appendChild(securityDetails);
        button.appendChild(statusGroup);
    } else {
        button.innerHTML = '<i class="fas fa-times-circle status-icon status-not-valid"></i> Not Configured';
    }

    cell.appendChild(button);

    return cell;
}

/**
 * Create a cell for Web Security validation
 * @param {string} domain - Domain name
 * @returns {HTMLElement} - Table cell element
 */
function createWebSecurityCell(domain) {
    const cell = document.createElement('td');
    cell.className = 'text-center';

    // Check if Web Security data exists for this domain
    if (!window.validationData.WEB_SECURITY ||
        !window.validationData.WEB_SECURITY.state ||
        !window.validationData.WEB_SECURITY.state[domain]) {
        cell.innerHTML = '<span class="status-not-found">Not Available</span>';
        return cell;
    }

    const webSecurityState = window.validationData.WEB_SECURITY.state[domain];
    const webSecurityResults = window.validationData.WEB_SECURITY.results[domain];
    const modalId = `web-security-${domain.replace(/\./g, '-')}`;

    // Create button with appropriate icon based on rating
    const button = document.createElement('button');
    button.className = 'status-button';
    button.style.position = 'relative'; // Required for absolute positioning of warning icon
    button.onclick = function () {
        openModalWithData(modalId, 'WEB_SECURITY', domain, webSecurityResults);
    };

    let securityStatusClass = '';
    const rating = webSecurityState.rating?.toLowerCase();

    if (rating === 'excellent') {
        securityStatusClass = 'status-excellent';
    } else if (rating === 'good') {
        securityStatusClass = 'status-good';
    } else if (rating === 'fair') {
        securityStatusClass = 'status-partially-valid';
    } else {
        securityStatusClass = 'status-not-valid';
    }

    // Check for issues using the issues_count from state
    const hasIssues = webSecurityState.issues_count > 0;

    // Build button content
    button.innerHTML = `<i class="fas fa-lock status-icon ${securityStatusClass}"></i> Details`;

    // Add warning icon in top right corner for Excellent/Good ratings that have issues
    if (hasIssues && (rating === 'excellent')) {
        const warningIcon = document.createElement('i');
        warningIcon.className = 'fas fa-info-circle';
        warningIcon.style.cssText = `
            position: absolute;
            top: -2px;
            right: -2px;
            color: #ff8c00;
            font-size: 10px;
            border-radius: 50%;
            padding: 1px;
            box-shadow: 0 0 2px rgba(0,0,0,0.3);
        `;
        warningIcon.title = 'Has identified issue(s)';
        button.appendChild(warningIcon);
    }
    cell.appendChild(button);

    return cell;
}