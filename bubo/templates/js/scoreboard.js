/**
 * Create a status cell with appropriate styling and icon
 */
function createStatusCell(status, type = 'default') {
    const cell = document.createElement('td');
    cell.className = 'status-cell';
    cell.style.textAlign = 'center';

    // Determine status class and icon
    let statusClass, icon;

    if (type === 'web') {
        // Web security uses rating values with differentiated colors
        if (status === 'excellent') {
            statusClass = 'status-web-excellent';
            icon = 'fas fa-check-circle';
        } else if (status === 'good') {
            statusClass = 'status-web-good';
            icon = 'fas fa-check-circle';
        } else if (status === 'fair') {
            statusClass = 'status-web-fair';
            icon = 'fas fa-exclamation-triangle';
        } else {
            statusClass = 'status-web-poor';
            icon = 'fas fa-times-circle';
        }
    } else if (type === 'email' || type === 'dane' || type === 'rpki') {
        // Email, DANE and RPKI use text status values
        if (status === 'valid') {
            statusClass = 'status-valid';
            icon = 'fas fa-check-circle';
        } else if (status === 'partially-valid') {
            statusClass = 'status-partially-valid';
            icon = 'fas fa-exclamation-triangle';
        } else if (status === 'not-found') {
            statusClass = 'status-not-found';
            icon = 'fas fa-question-circle';
        } else {
            statusClass = 'status-not-valid';
            icon = 'fas fa-times-circle';
        }
    } else {
        // Boolean values (for DNSSEC)
        if (status === true) {
            statusClass = 'status-valid';
            icon = 'fas fa-check-circle';
        } else {
            statusClass = 'status-not-valid';
            icon = 'fas fa-times-circle';
        }
    }

    const indicator = document.createElement('i');
    indicator.className = `${icon} ${statusClass}`;

    cell.appendChild(indicator);
    return cell;
}

function getComplianceColor(score) {
    if (score >= 85) return '#15803d'; // excellent - green
    if (score >= 70) return '#65a30d'; // good - light green
    if (score >= 50) return '#ca8a04'; // fair - yellow
    return '#b91c1c'; // poor - red
}

/**
 * Create the scorecard table
 */
function createScorecardTable() {
    const tbody = document.getElementById('scorecard-body');
    if (!tbody) return;

    // Clear existing rows
    tbody.innerHTML = '';

    // Add rows for each domain
    statsData.domain_scores.forEach(([domain, score]) => {
        const row = document.createElement('tr');

        // Domain column
        const domainCell = document.createElement('td');
        domainCell.className = 'domain-col';
        domainCell.textContent = domain;
        row.appendChild(domainCell);

        // Score column
        const scoreCell = document.createElement('td');
        scoreCell.className = 'score-col';
        scoreCell.innerHTML = `
    <div class="compliance-bar-container">
        <div class="compliance-bar" style="width: ${score}%; background-color: ${getComplianceColor(score)}"></div>
        <span class="compliance-value">${score.toFixed(1)}%</span>
    </div>
`;
        row.appendChild(scoreCell);

        // RPKI status - pass the actual status value, not just a boolean
        const rpkiStatus = statsData.rpki_state[domain]?.['Nameserver of Domain'] || 'not-valid';
        const rpkiCell = createStatusCell(rpkiStatus, 'rpki');
        row.appendChild(rpkiCell);

        // DANE status - pass the actual status value, not just a boolean
        const daneStatus = statsData.dane_state[domain]?.['Mail Server of Domain'] || 'not-valid';
        const daneCell = createStatusCell(daneStatus, 'dane');
        row.appendChild(daneCell);

        // DNSSEC status
        const dnssecCell = createStatusCell(statsData.dnssec_state[domain]?.DNSSEC);
        row.appendChild(dnssecCell);

        // SPF status - pass the actual status value, not just a boolean
        const spfStatus = statsData.email_state[domain]?.SPF || 'not-valid';
        const spfCell = createStatusCell(spfStatus, 'email');
        row.appendChild(spfCell);

        // DKIM status - pass the actual status value, not just a boolean
        const dkimStatus = statsData.email_state[domain]?.DKIM || 'not-valid';
        const dkimCell = createStatusCell(dkimStatus, 'email');
        row.appendChild(dkimCell);

        // DMARC status - pass the actual status value, not just a boolean
        const dmarcStatus = statsData.email_state[domain]?.DMARC || 'not-valid';
        const dmarcCell = createStatusCell(dmarcStatus, 'email');
        row.appendChild(dmarcCell);

        // Web Security status using rating for a more nuanced display
        const webRating = statsData.web_state[domain]?.rating || 'poor';
        const webCell = createStatusCell(webRating, 'web');

        // Add tooltip with more details if available
        if (statsData.web_security_issues[domain] && statsData.web_security_issues[domain].length > 0) {
            webCell.title = `Rating: ${webRating.toUpperCase()}\nIssues: ${
                statsData.web_security_issues[domain].join('\n')
            }`;
        } else {
            webCell.title = `Rating: ${webRating.toUpperCase()}`;
        }

        row.appendChild(webCell);
        tbody.appendChild(row);
    });
}

/**
 * Setup domain search functionality
 */
function setupDomainSearch() {
    const searchInput = document.getElementById('domainSearch');
    if (!searchInput) return;

    searchInput.addEventListener('input', function () {
        const searchTerm = this.value.toLowerCase().trim();

        document.querySelectorAll('.scorecard-table tbody tr').forEach(row => {
            const domain = row.querySelector('.domain-col')?.textContent?.toLowerCase() || '';
            
            if (searchTerm === '' || domain.includes(searchTerm)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    });
}

/**
 * Setup table sorting functionality
 */
function setupTableSorting() {
    const sortSelect = document.getElementById('sortOptions');
    if (!sortSelect) return;

    sortSelect.addEventListener('change', function () {
        const sortOption = this.value;

        // Reset column sort icons when using dropdown
        document.querySelectorAll('.scorecard-table th.sortable .sort-icon').forEach(icon => {
            icon.className = 'fas fa-sort sort-icon';
        });

        const tbody = document.querySelector('.scorecard-table tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));

        // Sort rows based on selected option
        rows.sort((a, b) => {
            const domainA = a.querySelector('.domain-col').textContent.trim().toLowerCase();
            const domainB = b.querySelector('.domain-col').textContent.trim().toLowerCase();

            const scoreA = parseFloat(a.querySelector('.compliance-value').textContent);
            const scoreB = parseFloat(b.querySelector('.compliance-value').textContent);

            switch (sortOption) {
                case 'alpha-asc':
                    currentSort = {column: 'domain', direction: 'asc'};
                    return domainA.localeCompare(domainB);
                case 'alpha-desc':
                    currentSort = {column: 'domain', direction: 'desc'};
                    return domainB.localeCompare(domainA);
                case 'score-asc':
                    currentSort = {column: 'score', direction: 'asc'};
                    return scoreA - scoreB;
                case 'score-desc':
                default:
                    currentSort = {column: 'score', direction: 'desc'};
                    return scoreB - scoreA;
            }
        });

        // Remove existing rows
        rows.forEach(row => row.remove());

        // Append sorted rows
        rows.forEach(row => tbody.appendChild(row));
    });
}

/**
 * Setup column header sorting functionality
 */
function setupColumnSorting() {
    const headers = document.querySelectorAll('.scorecard-table th.sortable');

    headers.forEach(header => {
        header.style.cursor = 'pointer';
        header.addEventListener('click', function () {
            const sortType = this.getAttribute('data-sort');

            // Toggle direction if same column, otherwise default to desc for most columns
            if (currentSort.column === sortType) {
                currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
            } else {
                currentSort.direction = (sortType === 'domain') ? 'asc' : 'desc';
            }

            currentSort.column = sortType;

            sortTableByColumn(sortType, currentSort.direction);
            updateSortIcons(this, currentSort.direction);
        });
    });
}

/**
 * Sort table by specific column
 */
function sortTableByColumn(sortType, direction) {
    const tbody = document.querySelector('.scorecard-table tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));

    rows.sort((a, b) => {
        let valueA, valueB;

        switch (sortType) {
            case 'domain':
                valueA = a.querySelector('.domain-col').textContent.trim().toLowerCase();
                valueB = b.querySelector('.domain-col').textContent.trim().toLowerCase();
                return direction === 'asc' ?
                    valueA.localeCompare(valueB) :
                    valueB.localeCompare(valueA);

            case 'score':
                valueA = parseFloat(a.querySelector('.compliance-value').textContent);
                valueB = parseFloat(b.querySelector('.compliance-value').textContent);
                return direction === 'asc' ? valueA - valueB : valueB - valueA;

            case 'rpki':
                valueA = getStatusSortValue(a, 2, 'rpki');
                valueB = getStatusSortValue(b, 2, 'rpki');
                break;

            case 'dane':
                valueA = getStatusSortValue(a, 3, 'dane');
                valueB = getStatusSortValue(b, 3, 'dane');
                break;

            case 'dnssec':
                valueA = getStatusSortValue(a, 4, 'dnssec');
                valueB = getStatusSortValue(b, 4, 'dnssec');
                break;

            case 'spf':
                valueA = getStatusSortValue(a, 5, 'email');
                valueB = getStatusSortValue(b, 5, 'email');
                break;

            case 'dkim':
                valueA = getStatusSortValue(a, 6, 'email');
                valueB = getStatusSortValue(b, 6, 'email');
                break;

            case 'dmarc':
                valueA = getStatusSortValue(a, 7, 'email');
                valueB = getStatusSortValue(b, 7, 'email');
                break;

            case 'web':
                valueA = getStatusSortValue(a, 8, 'web');
                valueB = getStatusSortValue(b, 8, 'web');
                break;

            default:
                return 0;
        }

        return direction === 'asc' ? valueA - valueB : valueB - valueA;
    });

    // Remove existing rows and append sorted rows
    rows.forEach(row => row.remove());
    rows.forEach(row => tbody.appendChild(row));

    // Update dropdown to reflect custom sorting
    const sortSelect = document.getElementById('sortOptions');
    if (sortSelect) {
        sortSelect.value = '';
    }
}

/**
 * Get numeric sort value for status-based columns
 */
function getStatusSortValue(row, columnIndex, type) {
    const domain = row.querySelector('.domain-col').textContent.trim();

    switch (type) {
        case 'rpki':
            const rpkiStatus = statsData.rpki_state[domain]?.['Nameserver of Domain'] || 'not-valid';
            return getStatusValue(rpkiStatus);

        case 'dane':
            const daneStatus = statsData.dane_state[domain]?.['Mail Server of Domain'] || 'not-valid';
            return getStatusValue(daneStatus);

        case 'dnssec':
            const dnssecStatus = statsData.dnssec_state[domain]?.DNSSEC || false;
            return dnssecStatus ? 1 : 0;

        case 'email':
            // Determine which email field based on column index
            let emailField;
            if (columnIndex === 5) emailField = 'SPF';
            else if (columnIndex === 6) emailField = 'DKIM';
            else if (columnIndex === 7) emailField = 'DMARC';

            const emailStatus = statsData.email_state[domain]?.[emailField] || 'not-valid';
            return getStatusValue(emailStatus);

        case 'web':
            const webRating = statsData.web_state[domain]?.rating || 'poor';
            return getWebRatingValue(webRating);

        default:
            return 0;
    }
}

/**
 * Convert status string to numeric value for sorting
 */
function getStatusValue(status) {
    const statusMap = {
        'valid': 3,
        'partially-valid': 2,
        'not-valid': 1,
        'not-found': 0
    };
    return statusMap[status] || 0;
}

/**
 * Convert web rating to numeric value for sorting
 */
function getWebRatingValue(rating) {
    const ratingMap = {
        'excellent': 4,
        'good': 3,
        'fair': 2,
        'poor': 1
    };
    return ratingMap[rating] || 0;
}

/**
 * Update sort icons to show current sort direction
 */
function updateSortIcons(activeHeader, direction) {
    // Reset all icons
    document.querySelectorAll('.scorecard-table th.sortable .sort-icon').forEach(icon => {
        icon.className = 'fas fa-sort sort-icon';
    });

    // Update active header icon
    const icon = activeHeader.querySelector('.sort-icon');
    if (icon) {
        icon.className = direction === 'asc' ?
            'fas fa-sort-up sort-icon active' :
            'fas fa-sort-down sort-icon active';
    }
}