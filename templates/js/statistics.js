/**
 * Initialize the dashboard with data
 */
function initializeDashboard() {
    configureChartDefaults();

    // Check if data was properly embedded
    if (!statsData) {
        console.error('Statistics data not available');
        alert('Failed to load statistics data. Please check the console for details.');
        return;
    }

    // Set basic information
    setBasicInfo();

    // Populate domain dropdowns for comparison
    populateDomainDropdowns();

    // Create the scorecard table
    createScorecardTable();

    // Initialize all charts
    initCharts();

    // Set component metrics
    setComponentMetrics();

    // Create component charts
    createComponentChartsForTabs();

    // Setup interactive elements
    setupInteractiveElements();
}

/**
 * Set basic information on the dashboard
 */
function setBasicInfo() {
    // Set timestamp
    document.getElementById('reportTimestamp').textContent = statsData.timestamp || 'N/A';

    // Set domain count
    const domainCount = statsData.domain_count || 0;
    document.getElementById('domain-count').textContent = domainCount;

    // Set DNSSEC percentage
    const dnssecPercent = (statsData.dnssec_stats?.compliant / domainCount * 100).toFixed(1);
    document.getElementById('dnssec-percent').textContent = `${dnssecPercent}%`;

    // Set Email compliance percentage
    const emailPercent = (statsData.email_stats?.fully_compliant / domainCount * 100).toFixed(1);
    document.getElementById('email-percent').textContent = `${emailPercent}%`;

    // Set Web compliance percentage
    const webPercent = (statsData.web_stats?.compliant / domainCount * 100).toFixed(1);
    document.getElementById('web-percent').textContent = `${webPercent}%`;

    // Set top domain and score
    document.getElementById('top-domain').textContent = statsData.top_domain || 'N/A';
    document.getElementById('top-score').textContent = (statsData.top_domain_score || 0).toFixed(1);

    // Set footer year
    document.getElementById('footer-year').textContent = statsData.year || new Date().getFullYear();

    // Set web rating counts and percentages
    const webRatingCounts = statsData.web_rating_counts || {excellent: 0, good: 0, fair: 0, poor: 0};
    document.getElementById('excellent-count').textContent = webRatingCounts.excellent || 0;
    document.getElementById('good-count').textContent = webRatingCounts.good || 0;
    document.getElementById('fair-count').textContent = webRatingCounts.fair || 0;
    document.getElementById('poor-count').textContent = webRatingCounts.poor || 0;

    document.getElementById('excellent-percent').textContent =
        `${((webRatingCounts.excellent || 0) / domainCount * 100).toFixed(1)}%`;
    document.getElementById('good-percent').textContent =
        `${((webRatingCounts.good || 0) / domainCount * 100).toFixed(1)}%`;
    document.getElementById('fair-percent').textContent =
        `${((webRatingCounts.fair || 0) / domainCount * 100).toFixed(1)}%`;
    document.getElementById('poor-percent').textContent =
        `${((webRatingCounts.poor || 0) / domainCount * 100).toFixed(1)}%`;

    // Component metrics
    // DANE
    document.getElementById('dane-mx-valid').textContent = statsData.dane_mx_stats?.valid || 0;
    document.getElementById('dane-mx-partial').textContent = statsData.dane_mx_stats?.partially_valid || 0;
    document.getElementById('dane-mx-invalid').textContent = statsData.dane_mx_stats?.not_valid || 0;

    document.getElementById('dane-ns-valid').textContent = statsData.dane_ns_stats?.valid || 0;
    document.getElementById('dane-ns-partial').textContent = statsData.dane_ns_stats?.partially_valid || 0;
    document.getElementById('dane-ns-invalid').textContent = statsData.dane_ns_stats?.not_valid || 0;

    document.getElementById('dane-ms-ns-valid').textContent = statsData.dane_mailserver_ns_stats?.valid || 0;
    document.getElementById('dane-ms-ns-partial').textContent = statsData.dane_mailserver_ns_stats?.partially_valid || 0;
    document.getElementById('dane-ms-ns-invalid').textContent = statsData.dane_mailserver_ns_stats?.not_valid || 0;

    // RPKI
    document.getElementById('rpki-mx-valid').textContent = statsData.rpki_mx_stats?.valid || 0;
    document.getElementById('rpki-mx-partial').textContent = statsData.rpki_mx_stats?.partially_valid || 0;
    document.getElementById('rpki-mx-invalid').textContent = statsData.rpki_mx_stats?.not_valid || 0;

    document.getElementById('rpki-ns-valid').textContent = statsData.rpki_ns_stats?.valid || 0;
    document.getElementById('rpki-ns-partial').textContent = statsData.rpki_ns_stats?.partially_valid || 0;
    document.getElementById('rpki-ns-invalid').textContent = statsData.rpki_ns_stats?.not_valid || 0;

    document.getElementById('rpki-ms-ns-valid').textContent = statsData.rpki_mailserver_ns_stats?.valid || 0;
    document.getElementById('rpki-ms-ns-partial').textContent = statsData.rpki_mailserver_ns_stats?.partially_valid || 0;
    document.getElementById('rpki-ms-ns-invalid').textContent = statsData.rpki_mailserver_ns_stats?.not_valid || 0;

    // Email
    document.getElementById('spf-valid').textContent = statsData.email_spf_stats?.valid || 0;
    document.getElementById('spf-partial').textContent = statsData.email_spf_stats?.partially_valid || 0;
    document.getElementById('spf-invalid').textContent = statsData.email_spf_stats?.not_valid || 0;

    document.getElementById('dkim-valid').textContent = statsData.email_dkim_stats?.valid || 0;
    document.getElementById('dkim-invalid').textContent = statsData.email_dkim_stats?.not_valid || 0;

    document.getElementById('dmarc-valid').textContent = statsData.email_dmarc_stats?.valid || 0;
    document.getElementById('dmarc-partial').textContent = statsData.email_dmarc_stats?.partially_valid || 0;
    document.getElementById('dmarc-invalid').textContent = statsData.email_dmarc_stats?.not_valid || 0;
}

/**
 * Populate domain dropdowns for comparison
 */
function populateDomainDropdowns() {
    const domainDropdowns = document.querySelectorAll('.domain-select');
    const domains = statsData.domain_scores.map(item => item[0]);

    domainDropdowns.forEach((dropdown, index) => {
        domains.forEach((domain, i) => {
            const option = document.createElement('option');
            option.value = domain;
            option.textContent = domain;

            // Select different domains by default in the two dropdowns
            if ((index === 0 && i === 0) || (index === 1 && i === 1)) {
                option.selected = true;
            }

            dropdown.appendChild(option);
        });
    });
}

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
        // Web security uses rating values
        if (['excellent', 'good'].includes(status)) {
            statusClass = 'status-valid';
            icon = 'fas fa-check-circle';
        } else if (status === 'fair') {
            statusClass = 'status-partially-valid';
            icon = 'fas fa-exclamation-triangle';
        } else {
            statusClass = 'status-not-valid';
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
                <div class="compliance-bar" style="width: ${score}%"></div>
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
 * Initialize all charts
 */
function initCharts() {
    createComplianceScoresChart();
    createStandardsAdoptionChart();
    createEmailComplianceChart();
    createWebComplianceRatingChart();
    createDaneImplementationChart();
    createRpkiValidationChart();
    createSpfPolicyChart();
    createDmarcPolicyChart();
    createTlsProtocolChart();
    createWebComplianceRatingDistributionChart();
    createComplianceIssuesChart();

    // Initialize comparison chart but don't populate yet
    initializeComparisonChart();
}

/**
 * Setup interactive elements
 */
function setupInteractiveElements() {
    setupTabSwitching();
    setupDomainSearch();
    setupTableSorting();
    setupComparisonButton();
}

/**
 * Setup tab switching functionality
 */
function setupTabSwitching() {
    const tabs = document.querySelectorAll('.tab');

    tabs.forEach(tab => {
        tab.addEventListener('click', function () {
            // Remove active class from all tabs
            tabs.forEach(t => t.classList.remove('active'));

            // Add active class to clicked tab
            this.classList.add('active');

            // Hide all tab content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });

            // Show the corresponding tab content
            const targetId = this.getAttribute('data-target');
            document.getElementById(targetId).classList.add('active');
        });
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
            const domain = row.querySelector('.domain-col').textContent.toLowerCase();

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
                    return domainA.localeCompare(domainB);
                case 'alpha-desc':
                    return domainB.localeCompare(domainA);
                case 'score-asc':
                    return scoreA - scoreB;
                case 'score-desc':
                default:
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
 * Set component metrics values from statsData
 */
function setComponentMetrics() {
    // DANE metrics
    document.getElementById('dane-mx-valid').textContent = statsData.dane_mx_stats.valid || 0;
    document.getElementById('dane-mx-partial').textContent = statsData.dane_mx_stats.partially_valid || 0;
    document.getElementById('dane-mx-invalid').textContent = statsData.dane_mx_stats.not_valid || 0;

    document.getElementById('dane-ns-valid').textContent = statsData.dane_ns_stats.valid || 0;
    document.getElementById('dane-ns-partial').textContent = statsData.dane_ns_stats.partially_valid || 0;
    document.getElementById('dane-ns-invalid').textContent = statsData.dane_ns_stats.not_valid || 0;

    document.getElementById('dane-ms-ns-valid').textContent = statsData.dane_mailserver_ns_stats.valid || 0;
    document.getElementById('dane-ms-ns-partial').textContent = statsData.dane_mailserver_ns_stats.partially_valid || 0;
    document.getElementById('dane-ms-ns-invalid').textContent = statsData.dane_mailserver_ns_stats.not_valid || 0;

    // RPKI metrics
    document.getElementById('rpki-mx-valid').textContent = statsData.rpki_mx_stats.valid || 0;
    document.getElementById('rpki-mx-partial').textContent = statsData.rpki_mx_stats.partially_valid || 0;
    document.getElementById('rpki-mx-invalid').textContent = statsData.rpki_mx_stats.not_valid || 0;

    document.getElementById('rpki-ns-valid').textContent = statsData.rpki_ns_stats.valid || 0;
    document.getElementById('rpki-ns-partial').textContent = statsData.rpki_ns_stats.partially_valid || 0;
    document.getElementById('rpki-ns-invalid').textContent = statsData.rpki_ns_stats.not_valid || 0;

    document.getElementById('rpki-ms-ns-valid').textContent = statsData.rpki_mailserver_ns_stats.valid || 0;
    document.getElementById('rpki-ms-ns-partial').textContent = statsData.rpki_mailserver_ns_stats.partially_valid || 0;
    document.getElementById('rpki-ms-ns-invalid').textContent = statsData.rpki_mailserver_ns_stats.not_valid || 0;

    // Email metrics
    document.getElementById('spf-valid').textContent = statsData.email_spf_stats.valid || 0;
    document.getElementById('spf-invalid').textContent = statsData.email_spf_stats.not_valid || 0;

    document.getElementById('dkim-valid').textContent = statsData.email_dkim_stats.valid || 0;
    document.getElementById('dkim-invalid').textContent = statsData.email_dkim_stats.not_valid || 0;

    document.getElementById('dmarc-valid').textContent = statsData.email_dmarc_stats.valid || 0;
    document.getElementById('dmarc-invalid').textContent = statsData.email_dmarc_stats.not_valid || 0;
}

/**
 * Setup comparison button functionality
 */
function setupComparisonButton() {
    const compareButton = document.getElementById('compareButton');
    if (!compareButton) return;

    compareButton.addEventListener('click', function () {
        const domain1 = document.getElementById('domain1').value;
        const domain2 = document.getElementById('domain2').value;
        const metric = document.getElementById('comparisonMetric').value;

        updateComparisonChart(domain1, domain2, metric);
    });

    // Initialize with default values
    const domain1 = document.getElementById('domain1').value;
    const domain2 = document.getElementById('domain2').value;
    const metric = document.getElementById('comparisonMetric').value;

    updateComparisonChart(domain1, domain2, metric);
}

/**
 * Create domain compliance scores chart
 */
function createComplianceScoresChart() {
    const ctx = document.getElementById('domainScoresChart');
    if (!ctx) return;

    // Get domain data
    const data = statsData.domain_scores;
    const domains = data.map(item => item[0]);
    const scores = data.map(item => item[1]);
    const colors = scores.map(score => {
        if (score >= 80) return '#28a745'; // success
        if (score >= 60) return '#ffc107'; // warning
        return '#dc3545'; // danger
    });

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: domains,
            datasets: [{
                label: 'Compliance Score',
                data: scores,
                backgroundColor: colors,
                borderColor: colors,
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            return `Compliance Score: ${context.formattedValue}%`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: 'Compliance Score (%)'
                    }
                }
            }
        }
    });
}

/**
 * Create standards adoption chart
 */
function createStandardsAdoptionChart() {
    const ctx = document.getElementById('standardsAdoptionChart');
    if (!ctx) return;

    const domainCount = statsData.domain_count;

    // Calculate weighted percentages for each standard
    // Formula: (100% * valid + 50% * partially_valid) / total * 100

    // DNSSEC weighted score
    const dnssecScore = (
        (statsData.dnssec_stats.compliant * 1.0) +
        (statsData.dnssec_stats.partially_compliant * 0.5)
    ) / domainCount * 100;

    // DANE weighted score
    const daneScore = (
        (statsData.dane_stats.compliant * 1.0) +
        (statsData.dane_stats.partially_compliant * 0.5)
    ) / domainCount * 100;

    // SPF weighted score
    const spfScore = (
        (statsData.email_spf_stats.valid * 1.0) +
        (statsData.email_spf_stats.partially_valid * 0.5)
    ) / domainCount * 100;

    // DKIM weighted score
    const dkimScore = (
        (statsData.email_dkim_stats.valid * 1.0) +
        (statsData.email_dkim_stats.partially_valid * 0.5)
    ) / domainCount * 100;

    // DMARC weighted score
    const dmarcScore = (
        (statsData.email_dmarc_stats.valid * 1.0) +
        (statsData.email_dmarc_stats.partially_valid * 0.5)
    ) / domainCount * 100;

    // RPKI weighted score
    const rpkiScore = (
        (statsData.rpki_stats.compliant * 1.0) +
        (statsData.rpki_stats.partially_compliant * 0.5)
    ) / domainCount * 100;

    // Web security - using the compliant stats
    const webScore = (
        (statsData.web_stats.compliant * 1.0) +
        (statsData.web_stats.partially_compliant * 0.5)
    ) / domainCount * 100;

    const standardsData = [
        Math.round(dnssecScore),
        Math.round(daneScore),
        Math.round(spfScore),
        Math.round(dkimScore),
        Math.round(dmarcScore),
        Math.round(rpkiScore),
        Math.round(webScore)
    ];

    new Chart(ctx, {
        type: 'radar',
        data: {
            labels: ['DNSSEC', 'DANE', 'SPF', 'DKIM', 'DMARC', 'RPKI', 'Web Security'],
            datasets: [{
                label: 'Adoption Rate',
                data: standardsData,
                backgroundColor: 'rgba(0, 98, 204, 0.2)',
                borderColor: 'rgba(0, 98, 204, 1)',
                pointBackgroundColor: 'rgba(0, 98, 204, 1)',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: 'rgba(0, 98, 204, 1)',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                        stepSize: 20,
                        callback: function (value) {
                            return value + '%';
                        }
                    }
                }
            },
            plugins: {
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            return `${context.label}: ${context.formattedValue}%`;
                        }
                    }
                }
            }
        }
    });
}

function createEmailComplianceChart() {
    const ctx = document.getElementById('emailSecurityChart');
    if (!ctx) return;

    // Count logic remains the same
    let allCount = 0;
    let spfDkimCount = 0;
    let spfDmarcCount = 0;
    let dkimDmarcCount = 0;
    let spfOnlyCount = 0;
    let dkimOnlyCount = 0;
    let dmarcOnlyCount = 0;
    let noneCount = 0;

    const domains = Object.keys(statsData.email_state);

    domains.forEach(domain => {
        // Existing counting logic...
        const emailState = statsData.email_state[domain];

        const spfValid = emailState.SPF === 'valid';
        const dkimValid = emailState.DKIM === 'valid';
        const dmarcValid = emailState.DMARC === 'valid';

        if (spfValid && dkimValid && dmarcValid) {
            allCount++;
        } else if (spfValid && dkimValid) {
            spfDkimCount++;
        } else if (spfValid && dmarcValid) {
            spfDmarcCount++;
        } else if (dkimValid && dmarcValid) {
            dkimDmarcCount++;
        } else if (spfValid) {
            spfOnlyCount++;
        } else if (dkimValid) {
            dkimOnlyCount++;
        } else if (dmarcValid) {
            dmarcOnlyCount++;
        } else {
            noneCount++;
        }
    });

    // Create an array of all categories with their counts and colors
    const categories = [
        { label: 'All Standards (SPF, DKIM, DMARC)', count: allCount, color: '#28a745' },
        { label: 'SPF + DKIM only', count: spfDkimCount, color: '#4caf50' },
        { label: 'SPF + DMARC only', count: spfDmarcCount, color: '#8bc34a' },
        { label: 'DKIM + DMARC only', count: dkimDmarcCount, color: '#cddc39' },
        { label: 'SPF only', count: spfOnlyCount, color: '#ffc107' },
        { label: 'DKIM only', count: dkimOnlyCount, color: '#ff9800' },
        { label: 'DMARC only', count: dmarcOnlyCount, color: '#ff5722' },
        { label: 'No Email Protection', count: noneCount, color: '#dc3545' }
    ];

    // Filter categories to only include those with count > 0
    const filteredCategories = categories.filter(category => category.count > 0);

    // Extract labels, data, and colors from filtered categories
    const labels = filteredCategories.map(category => category.label);
    const data = filteredCategories.map(category => category.count);
    const backgroundColor = filteredCategories.map(category => category.color);

    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: backgroundColor,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        font: {
                            size: 11
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const label = context.label || '';
                            const value = context.raw;
                            const percentage = Math.round((value / domains.length) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Create web compliance rating chart
 */
function createWebComplianceRatingChart() {
    const ctx = document.getElementById('webRatingChart');
    if (!ctx) return;

    const ratingCounts = statsData.web_rating_counts;
    const labels = ['Excellent', 'Good', 'Fair', 'Poor'];
    const data = [
        ratingCounts.excellent || 0,
        ratingCounts.good || 0,
        ratingCounts.fair || 0,
        ratingCounts.poor || 0
    ];
    const colors = [
        '#15803d',  // excellent
        '#65a30d',  // good
        '#ca8a04',  // fair
        '#b91c1c'   // poor
    ];

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Domains',
                data: data,
                backgroundColor: colors,
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const value = context.raw;
                            const total = data.reduce((sum, val) => sum + val, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${context.label}: ${value} domains (${percentage}%)`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Number of Domains'
                    }
                }
            }
        }
    });
}

/**
 * Create DANE implementation chart
 */
function createDaneImplementationChart() {
    const ctx = document.getElementById('daneImplementationChart');
    if (!ctx) return;

    const labels = Object.keys(statsData.dane_mail_server_state);
    const data = labels.map(domain => {
        return statsData.dane_mail_server_state[domain] === 'valid' ? 1 : 0;
    });

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'DANE Implementation',
                data: data,
                backgroundColor: data.map(val => val === 1 ? '#28a745' : '#dc3545'),
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const domain = context.label;
                            const state = statsData.dane_mail_server_state[domain];
                            return `DANE: ${state === 'valid' ? 'Valid' : 'Not Valid'}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    max: 1,
                    ticks: {
                        callback: function (value) {
                            return value === 0 ? 'Not Valid' : 'Valid';
                        }
                    }
                }
            }
        }
    });
}

/**
 * Create RPKI validation chart
 */
function createRpkiValidationChart() {
    const ctx = document.getElementById('rpkiValidationChart');
    if (!ctx) return;

    const labels = Object.keys(statsData.rpki_mail_server_state);
    const data = labels.map(domain => {
        const state = statsData.rpki_mail_server_state[domain];
        if (state === 'valid') return 2;
        if (state === 'partially-valid') return 1;
        return 0;
    });

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'RPKI Validation',
                data: data,
                backgroundColor: data.map(val => {
                    if (val === 2) return '#28a745';
                    if (val === 1) return '#ffc107';
                    return '#dc3545';
                }),
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const domain = context.label;
                            const state = statsData.rpki_mail_server_state[domain];
                            return `RPKI: ${state}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    max: 2,
                    ticks: {
                        callback: function (value) {
                            if (value === 0) return 'Not Valid';
                            if (value === 1) return 'Partially Valid';
                            return 'Valid';
                        }
                    }
                }
            }
        }
    });
}

/**
 * Create SPF policy chart
 */
function createSpfPolicyChart() {
    const ctx = document.getElementById('spfPolicyChart');
    if (!ctx) return;

    const spfPolicyCounts = statsData.spf_policy_counts;

    // Create an array of all categories with their counts and colors
    const categories = [
        { label: 'Hard Fail (-all)', count: spfPolicyCounts['-all'] || 0, color: '#28a745' },
        { label: 'Soft Fail (~all)', count: spfPolicyCounts['~all'] || 0, color: '#ffc107' },
        { label: 'Other Policy', count: spfPolicyCounts['other'] || 0, color: '#dc3545' },
        { label: 'No Policy', count: spfPolicyCounts['none'] || 0, color: '#6c757d' }
    ];

    // Filter categories to only include those with count > 0
    const filteredCategories = categories.filter(category => category.count > 0);

    // Extract labels, data, and colors from filtered categories
    const labels = filteredCategories.map(category => category.label);
    const data = filteredCategories.map(category => category.count);
    const backgroundColor = filteredCategories.map(category => category.color);

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: backgroundColor,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const label = context.label || '';
                            const value = context.raw;
                            const total = data.reduce((sum, val) => sum + val, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                },
                legend: {
                    position: 'top',
                    labels: {
                        font: {
                            size: 11
                        }
                    }
                }
            }
        }
    });
}

/**
 * Create DMARC policy chart
 */
function createDmarcPolicyChart() {
    const ctx = document.getElementById('dmarcPolicyChart');
    if (!ctx) return;

    const dmarcPolicyCounts = statsData.dmarc_policy_counts;
    const labels = [
        'Reject',
        'Quarantine',
        'None',
        'No DMARC Record'
    ];
    const data = [
        dmarcPolicyCounts['reject'] || 0,
        dmarcPolicyCounts['quarantine'] || 0,
        dmarcPolicyCounts['none'] || 0,
        dmarcPolicyCounts['no_record'] || 0
    ];
    const colors = [
        '#28a745',  // Reject (strongest)
        '#ffc107',  // Quarantine
        '#ff9800',  // None
        '#dc3545'   // No record
    ];

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const label = context.label || '';
                            const value = context.raw;
                            const total = data.reduce((sum, val) => sum + val, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Create TLS protocol chart
 */
function createTlsProtocolChart() {
    const ctx = document.getElementById('tlsProtocolChart');
    if (!ctx) return;

    // Get protocol stats from statsData
    const tlsProtocolStats = statsData.tls_protocol_stats || {
        'TLSv1.0': {supported: 0, total: 0},
        'TLSv1.1': {supported: 0, total: 0},
        'TLSv1.2': {supported: 0, total: 0},
        'TLSv1.3': {supported: 0, total: 0}
    };

    // Filter out the domain_count property and get protocol names
    const labels = Object.keys(tlsProtocolStats).filter(key => key !== 'domain_count');

    // Use absolute counts of domains that support each protocol
    const data = labels.map(protocol => tlsProtocolStats[protocol].supported);

    // Get total domains for scaling
    const totalDomains = statsData.domain_count;

    // Color code - red for older protocols, green for newer
    const colors = [
        '#dc3545',  // TLSv1.0 (insecure)
        '#ffc107',  // TLSv1.1 (insecure)
        '#28a745',  // TLSv1.2 (secure)
        '#0062cc'   // TLSv1.3 (most secure)
    ];

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Number of Domains',
                data: data,
                backgroundColor: colors,
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const protocol = context.label;
                            const count = context.raw;
                            const percentage = Math.round((count / totalDomains) * 100);
                            return `${count} of ${totalDomains} domains (${percentage}%)`;
                        },
                        afterLabel: function (context) {
                            return `Support ${context.label}`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: totalDomains,
                    title: {
                        display: true,
                        text: 'Number of Domains'
                    },
                    ticks: {
                        // Show total at the top
                        callback: function (value, index, values) {
                            const max = values[values.length - 1];
                            if (value === max.value) {
                                return `${value} (Total)`;
                            }
                            return value;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Create web compliance rating distribution chart
 */
function createWebComplianceRatingDistributionChart() {
    const ctx = document.getElementById('webRatingDistributionChart');
    if (!ctx) return;

    const ratingCounts = statsData.web_rating_counts;
    const labels = ['Excellent', 'Good', 'Fair', 'Poor'];
    const data = [
        ratingCounts.excellent || 0,
        ratingCounts.good || 0,
        ratingCounts.fair || 0,
        ratingCounts.poor || 0
    ];
    const colors = [
        '#15803d',  // excellent
        '#65a30d',  // good
        '#ca8a04',  // fair
        '#b91c1c'   // poor
    ];

    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const label = context.label || '';
                            const value = context.raw;
                            const total = data.reduce((sum, val) => sum + val, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Create component charts for tabs
 */
function createComponentChartsForTabs() {
    createDaneComponentsChart();
    createRpkiComponentsChart();
    createEmailComponentsChart();
}

/**
 * Create DANE components chart
 * Visualizes the DANE implementation status across different component types
 */
function createDaneComponentsChart() {
    const ctx = document.getElementById('daneComponentsChart');
    if (!ctx) return;

    // Define component categories
    const labels = ['Mail Server', 'Nameserver', 'Mail Server Nameservers'];

    // Extract data from stats object
    const validData = [
        statsData.dane_mx_stats.valid || 0,
        statsData.dane_ns_stats.valid || 0,
        statsData.dane_mailserver_ns_stats.valid || 0
    ];

    const partialData = [
        statsData.dane_mx_stats.partially_valid || 0,
        statsData.dane_ns_stats.partially_valid || 0,
        statsData.dane_mailserver_ns_stats.partially_valid || 0
    ];

    const invalidData = [
        statsData.dane_mx_stats.not_valid || 0,
        statsData.dane_ns_stats.not_valid || 0,
        statsData.dane_mailserver_ns_stats.not_valid || 0
    ];

    // Create stacked bar chart
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Valid',
                    data: validData,
                    backgroundColor: '#28a745',
                    borderWidth: 0
                },
                {
                    label: 'Partially Valid',
                    data: partialData,
                    backgroundColor: '#ffc107',
                    borderWidth: 0
                },
                {
                    label: 'Not Valid',
                    data: invalidData,
                    backgroundColor: '#dc3545',
                    borderWidth: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const datasetLabel = context.dataset.label || '';
                            const value = context.raw;
                            const component = context.label;
                            const total = validData[context.dataIndex] +
                                partialData[context.dataIndex] +
                                invalidData[context.dataIndex];
                            const percentage = Math.round((value / total) * 100);
                            return `${component} - ${datasetLabel}: ${value} (${percentage}%)`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    stacked: true
                },
                y: {
                    stacked: true,
                    beginAtZero: true
                }
            }
        }
    });
}

/**
 * Create RPKI components chart
 * Visualizes the RPKI validation status across different component types
 */
function createRpkiComponentsChart() {
    const ctx = document.getElementById('rpkiComponentsChart');
    if (!ctx) return;

    // Define component categories
    const labels = ['Mail Server', 'Nameserver', 'Mail Server Nameservers'];

    // Extract data from stats object
    const validData = [
        statsData.rpki_mx_stats.valid || 0,
        statsData.rpki_ns_stats.valid || 0,
        statsData.rpki_mailserver_ns_stats.valid || 0
    ];

    const partialData = [
        statsData.rpki_mx_stats.partially_valid || 0,
        statsData.rpki_ns_stats.partially_valid || 0,
        statsData.rpki_mailserver_ns_stats.partially_valid || 0
    ];

    const invalidData = [
        statsData.rpki_mx_stats.not_valid || 0,
        statsData.rpki_ns_stats.not_valid || 0,
        statsData.rpki_mailserver_ns_stats.not_valid || 0
    ];

    // Create stacked bar chart
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Valid',
                    data: validData,
                    backgroundColor: '#28a745',
                    borderWidth: 0
                },
                {
                    label: 'Partially Valid',
                    data: partialData,
                    backgroundColor: '#ffc107',
                    borderWidth: 0
                },
                {
                    label: 'Not Valid',
                    data: invalidData,
                    backgroundColor: '#dc3545',
                    borderWidth: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const datasetLabel = context.dataset.label || '';
                            const value = context.raw;
                            const component = context.label;
                            const total = validData[context.dataIndex] +
                                partialData[context.dataIndex] +
                                invalidData[context.dataIndex];
                            const percentage = Math.round((value / total) * 100);
                            return `${component} - ${datasetLabel}: ${value} (${percentage}%)`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    stacked: true
                },
                y: {
                    stacked: true,
                    beginAtZero: true
                }
            }
        }
    });
}

/**
 * Create email components chart
 */
function createEmailComponentsChart() {
    const ctx = document.getElementById('emailComponentsChart');
    if (!ctx) return;

    const labels = ['SPF', 'DKIM', 'DMARC'];
    const validData = [
        statsData.email_spf_stats.valid || 0,
        statsData.email_dkim_stats.valid || 0,
        statsData.email_dmarc_stats.valid || 0
    ];
    const invalidData = [
        statsData.email_spf_stats.not_valid || 0,
        statsData.email_dkim_stats.not_valid || 0,
        statsData.email_dmarc_stats.not_valid || 0
    ];

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Valid',
                    data: validData,
                    backgroundColor: '#28a745',
                    borderWidth: 0
                },
                {
                    label: 'Not Valid',
                    data: invalidData,
                    backgroundColor: '#dc3545',
                    borderWidth: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const datasetLabel = context.dataset.label || '';
                            const value = context.raw;
                            const component = context.label;
                            const total = validData[context.dataIndex] + invalidData[context.dataIndex];
                            const percentage = Math.round((value / total) * 100);
                            return `${component} - ${datasetLabel}: ${value} (${percentage}%)`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    stacked: true
                },
                y: {
                    stacked: true,
                    beginAtZero: true
                }
            }
        }
    });
}

/**
 * Create compliance issues chart
 */
function createComplianceIssuesChart() {
    const ctx = document.getElementById('issuesChart');
    if (!ctx || !statsData.common_issues || statsData.common_issues.length === 0) return;

    // Create chart data
    const issues = statsData.common_issues.map(issue => issue[0]);
    const counts = statsData.common_issues.map(issue => issue[1]);

    // Create chart - keep the color coding for visual distinction but don't label it as severity
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: issues,
            datasets: [{
                label: 'Affected Domains',
                data: counts,
                backgroundColor: '#3498db', // Use a consistent neutral color instead of severity colors
                borderWidth: 0
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            const count = context.raw;
                            const percentage = Math.round((count / statsData.domain_count) * 100);
                            return `${count} domains affected (${percentage}%)`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Number of Affected Domains'
                    }
                }
            }
        }
    });

    // Create modal if it doesn't exist yet
    let modalContainer = document.getElementById('domains-modal-container');
    if (!modalContainer) {
        // Modal creation code remains unchanged
        modalContainer = document.createElement('div');
        modalContainer.id = 'domains-modal-container';
        modalContainer.className = 'modal-container';

        const modal = document.createElement('div');
        modal.className = 'domains-modal';
        modal.innerHTML = `
      <div class="modal-header">
        <h3 class="modal-title">Affected Domains</h3>
        <button class="modal-close">&times;</button>
      </div>
      <div class="modal-content">
        <div id="modal-domains-list"></div>
      </div>
    `;

        modal.querySelector('.modal-close').addEventListener('click', function () {
            modalContainer.style.display = 'none';
        });

        modalContainer.addEventListener('click', function (e) {
            if (e.target === modalContainer) {
                modalContainer.style.display = 'none';
            }
        });

        modalContainer.appendChild(modal);
        document.body.appendChild(modalContainer);
    }

    // Create table header with 3 columns (removed Severity column)
    const issuesTable = document.getElementById('issues-table');
    issuesTable.innerHTML = '';

    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');

    ['Issue', 'Count', 'Domains'].forEach(text => {
        const th = document.createElement('th');
        th.textContent = text;
        headerRow.appendChild(th);
    });

    thead.appendChild(headerRow);
    issuesTable.appendChild(thead);

    // Create table body
    const tbody = document.createElement('tbody');

    // Create table rows for each issue
    statsData.common_issues.forEach((issue) => {
        const [issueName, count, domains] = issue;

        const row = document.createElement('tr');

        // Issue cell
        const issueCell = document.createElement('td');
        issueCell.className = 'issue-cell';
        issueCell.textContent = issueName;
        row.appendChild(issueCell);

        // Count cell
        const countCell = document.createElement('td');
        countCell.className = 'count-cell';

        const countBadge = document.createElement('span');
        countBadge.className = 'domain-count';
        countBadge.textContent = count;
        countCell.appendChild(countBadge);

        row.appendChild(countCell);

        // Domains cell (clickable to show all affected domains)
        const domainsCell = document.createElement('td');
        domainsCell.className = 'domains-cell clickable';

        // Display preview of domains
        const previewDomains = domains.slice(0, 3);
        const previewText = previewDomains.join(', ');
        domainsCell.textContent = domains.length > 3 ? previewText + '...' : previewText;

        // Make the cell clickable to open modal
        if (domains.length > 0) {
            domainsCell.style.cursor = 'pointer';
            domainsCell.addEventListener('click', function () {
                // Update modal content
                document.querySelector('.modal-title').textContent = `Domains Affected by: ${issueName}`;

                const domainsList = document.getElementById('modal-domains-list');
                domainsList.innerHTML = '';

                // Create a grid of domains
                const domainsGrid = document.createElement('div');
                domainsGrid.className = 'domains-grid';

                domains.forEach(domain => {
                    const domainItem = document.createElement('div');
                    domainItem.className = 'domain-item';
                    domainItem.textContent = domain;
                    domainsGrid.appendChild(domainItem);
                });

                domainsList.appendChild(domainsGrid);

                // Show the modal
                modalContainer.style.display = 'flex';
            });
        }

        row.appendChild(domainsCell);

        tbody.appendChild(row);
    });

    issuesTable.appendChild(tbody);
}

/**
 * Initialize comparison chart without data
 */
function initializeComparisonChart() {
    const ctx = document.getElementById('comparisonChart');
    if (!ctx) return;

    // Create empty chart
    window.comparisonChart = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: [],
            datasets: []
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });
}

/**
 * Update comparison chart with domain and metric data
 */
function updateComparisonChart(domain1, domain2, metric) {
    if (!window.comparisonChart) return;

    // Get metrics data based on selected metric
    let labels = [];
    let domain1Data = [];
    let domain2Data = [];

    switch (metric) {
        case 'overall':
            labels = ['Overall Score', 'DNSSEC', 'DANE', 'Email', 'Web', 'RPKI'];

            // Get overall compliance score
            const domain1ComplianceScore = statsData.domain_scores.find(item => item[0] === domain1)[1] || 0;
            const domain2ComplianceScore = statsData.domain_scores.find(item => item[0] === domain2)[1] || 0;

            // Get DNSSEC score
            const domain1Dnssec = statsData.dnssec_state[domain1]?.DNSSEC ? 100 : 0;
            const domain2Dnssec = statsData.dnssec_state[domain2]?.DNSSEC ? 100 : 0;

            // Get DANE score
            const domain1Dane = statsData.dane_state[domain1]?.['Mail Server of Domain'] === 'valid' ? 100 : 0;
            const domain2Dane = statsData.dane_state[domain2]?.['Mail Server of Domain'] === 'valid' ? 100 : 0;

            // Get Email score (average of SPF, DKIM, DMARC)
            const domain1Email = calculateEmailComplianceScore(domain1);
            const domain2Email = calculateEmailComplianceScore(domain2);

            // Get Web score
            const domain1Web = calculateWebComplianceScore(domain1);
            const domain2Web = calculateWebComplianceScore(domain2);

            // Get RPKI score
            const domain1Rpki = statsData.rpki_state[domain1]?.['Nameserver of Domain'] === 'valid' ? 100 : 0;
            const domain2Rpki = statsData.rpki_state[domain2]?.['Nameserver of Domain'] === 'valid' ? 100 : 0;

            domain1Data = [domain1ComplianceScore, domain1Dnssec, domain1Dane, domain1Email, domain1Web, domain1Rpki];
            domain2Data = [domain2ComplianceScore, domain2Dnssec, domain2Dane, domain2Email, domain2Web, domain2Rpki];
            break;

        case 'dnssec':
            labels = ['DNSSEC Enabled', 'DS Records', 'DNSKEY Records', 'RRSIG Records'];

            // Get detailed DNSSEC data (simplified for example)
            const domain1DnssecStatus = statsData.dnssec_state[domain1]?.DNSSEC ? 100 : 0;
            const domain2DnssecStatus = statsData.dnssec_state[domain2]?.DNSSEC ? 100 : 0;

            domain1Data = [domain1DnssecStatus, domain1DnssecStatus, domain1DnssecStatus, domain1DnssecStatus];
            domain2Data = [domain2DnssecStatus, domain2DnssecStatus, domain2DnssecStatus, domain2DnssecStatus];
            break;

        case 'email':
            labels = ['SPF', 'DKIM', 'DMARC', 'Overall Email'];

            const domain1Spf = statsData.email_state[domain1]?.SPF === 'valid' ? 100 :
                (statsData.email_state[domain1]?.SPF === 'partially-valid' ? 50 : 0);
            const domain2Spf = statsData.email_state[domain2]?.SPF === 'valid' ? 100 :
                (statsData.email_state[domain2]?.SPF === 'partially-valid' ? 50 : 0);

            const domain1Dkim = statsData.email_state[domain1]?.DKIM === 'valid' ? 100 :
                (statsData.email_state[domain1]?.DKIM === 'partially-valid' ? 50 : 0);
            const domain2Dkim = statsData.email_state[domain2]?.DKIM === 'valid' ? 100 :
                (statsData.email_state[domain2]?.DKIM === 'partially-valid' ? 50 : 0);

            const domain1Dmarc = statsData.email_state[domain1]?.DMARC === 'valid' ? 100 :
                (statsData.email_state[domain1]?.DMARC === 'partially-valid' ? 50 : 0);
            const domain2Dmarc = statsData.email_state[domain2]?.DMARC === 'valid' ? 100 :
                (statsData.email_state[domain2]?.DMARC === 'partially-valid' ? 50 : 0);

            domain1Data = [domain1Spf, domain1Dkim, domain1Dmarc, calculateEmailComplianceScore(domain1)];
            domain2Data = [domain2Spf, domain2Dkim, domain2Dmarc, calculateEmailComplianceScore(domain2)];
            break;

        case 'web':
            labels = ['TLS Secure', 'Certificate Valid', 'Secure Protocols', 'Security Headers'];

            // Get Web component scores
            const domain1TlsSecure = statsData.web_state[domain1]?.tls_secure ? 100 : 0;
            const domain2TlsSecure = statsData.web_state[domain2]?.tls_secure ? 100 : 0;

            const domain1CertValid = statsData.web_state[domain1]?.cert_valid ? 100 : 0;
            const domain2CertValid = statsData.web_state[domain2]?.cert_valid ? 100 : 0;

            const domain1SecureProtocols = statsData.web_state[domain1]?.uses_secure_protocols ? 100 : 0;
            const domain2SecureProtocols = statsData.web_state[domain2]?.uses_secure_protocols ? 100 : 0;

            // Security headers score based on issues count (inverse)
            const domain1HeadersScore = Math.max(0, 100 - (statsData.web_state[domain1]?.issues_count || 0) * 20);
            const domain2HeadersScore = Math.max(0, 100 - (statsData.web_state[domain2]?.issues_count || 0) * 20);

            domain1Data = [domain1TlsSecure, domain1CertValid, domain1SecureProtocols, domain1HeadersScore];
            domain2Data = [domain2TlsSecure, domain2CertValid, domain2SecureProtocols, domain2HeadersScore];
            break;

        case 'dane':
            labels = ['Mail Server', 'Nameserver', 'Mail Server Nameserver'];

            // Get DANE component scores
            const domain1MxDane = statsData.dane_state[domain1]?.['Mail Server of Domain'] === 'valid' ? 100 : 0;
            const domain2MxDane = statsData.dane_state[domain2]?.['Mail Server of Domain'] === 'valid' ? 100 : 0;

            const domain1NsDane = statsData.dane_state[domain1]?.['Nameserver of Domain'] === 'valid' ? 100 : 0;
            const domain2NsDane = statsData.dane_state[domain2]?.['Nameserver of Domain'] === 'valid' ? 100 : 0;

            const domain1MsNsDane = statsData.dane_state[domain1]?.['Nameserver of Mail Server'] === 'valid' ? 100 : 0;
            const domain2MsNsDane = statsData.dane_state[domain2]?.['Nameserver of Mail Server'] === 'valid' ? 100 : 0;

            domain1Data = [domain1MxDane, domain1NsDane, domain1MsNsDane];
            domain2Data = [domain2MxDane, domain2NsDane, domain2MsNsDane];
            break;

        case 'rpki':
            labels = ['Domain Nameserver', 'Mail Server', 'Mail Server Nameserver'];

            // Get RPKI component scores
            const domain1NsRpki = statsData.rpki_state[domain1]?.['Nameserver of Domain'] === 'valid' ? 100 :
                (statsData.rpki_state[domain1]?.['Nameserver of Domain'] === 'partially-valid' ? 50 : 0);
            const domain2NsRpki = statsData.rpki_state[domain2]?.['Nameserver of Domain'] === 'valid' ? 100 :
                (statsData.rpki_state[domain2]?.['Nameserver of Domain'] === 'partially-valid' ? 50 : 0);

            const domain1MxRpki = statsData.rpki_state[domain1]?.['Mail Server of Domain'] === 'valid' ? 100 :
                (statsData.rpki_state[domain1]?.['Mail Server of Domain'] === 'partially-valid' ? 50 : 0);
            const domain2MxRpki = statsData.rpki_state[domain2]?.['Mail Server of Domain'] === 'valid' ? 100 :
                (statsData.rpki_state[domain2]?.['Mail Server of Domain'] === 'partially-valid' ? 50 : 0);

            const domain1MsNsRpki = statsData.rpki_state[domain1]?.['Nameserver of Mail Server'] === 'valid' ? 100 :
                (statsData.rpki_state[domain1]?.['Nameserver of Mail Server'] === 'partially-valid' ? 50 : 0);
            const domain2MsNsRpki = statsData.rpki_state[domain2]?.['Nameserver of Mail Server'] === 'valid' ? 100 :
                (statsData.rpki_state[domain2]?.['Nameserver of Mail Server'] === 'partially-valid' ? 50 : 0);

            domain1Data = [domain1NsRpki, domain1MxRpki, domain1MsNsRpki];
            domain2Data = [domain2NsRpki, domain2MxRpki, domain2MsNsRpki];
            break;
    }

    // Update chart data
    window.comparisonChart.data.labels = labels;
    window.comparisonChart.data.datasets = [
        {
            label: domain1,
            data: domain1Data,
            backgroundColor: 'rgba(66, 133, 244, 0.2)',
            borderColor: 'rgba(66, 133, 244, 1)',
            pointBackgroundColor: 'rgba(66, 133, 244, 1)',
            pointBorderColor: '#fff',
            pointHoverBackgroundColor: '#fff',
            pointHoverBorderColor: 'rgba(66, 133, 244, 1)'
        },
        {
            label: domain2,
            data: domain2Data,
            backgroundColor: 'rgba(234, 67, 53, 0.2)',
            borderColor: 'rgba(234, 67, 53, 1)',
            pointBackgroundColor: 'rgba(234, 67, 53, 1)',
            pointBorderColor: '#fff',
            pointHoverBackgroundColor: '#fff',
            pointHoverBorderColor: 'rgba(234, 67, 53, 1)'
        }
    ];

    // Update chart scale maximum
    window.comparisonChart.options.scales.r.max = 100;

    // Update chart
    window.comparisonChart.update();
}

/**
 * Helper function to calculate email standards compliance score
 */
function calculateEmailComplianceScore(domain) {
    // Valid = 1.0, partially-valid = 0.5, others = 0
    const spfScore = statsData.email_state[domain]?.SPF === 'valid' ? 1 :
                    (statsData.email_state[domain]?.SPF === 'partially-valid' ? 0.5 : 0);

    const dkimScore = statsData.email_state[domain]?.DKIM === 'valid' ? 1 :
                     (statsData.email_state[domain]?.DKIM === 'partially-valid' ? 0.5 : 0);

    const dmarcScore = statsData.email_state[domain]?.DMARC === 'valid' ? 1 :
                      (statsData.email_state[domain]?.DMARC === 'partially-valid' ? 0.5 : 0);

    // Calculate weighted score (SPF=30%, DKIM=30%, DMARC=40%)
    return Math.round((spfScore * 30 + dkimScore * 30 + dmarcScore * 40));
}

/**
 * Helper function to calculate web standards compliance score
 */
function calculateWebComplianceScore(domain) {
    const webState = statsData.web_state[domain];
    if (!webState) return 0;

    const tlsSecure = webState.tls_secure ? 30 : 0;
    const certValid = webState.cert_valid ? 20 : 0;
    const secureProtocols = webState.uses_secure_protocols ? 20 : 0;

    // Rating-based score
    let ratingScore = 0;
    switch (webState.rating) {
        case 'excellent':
            ratingScore = 30;
            break;
        case 'good':
            ratingScore = 20;
            break;
        case 'fair':
            ratingScore = 10;
            break;
        case 'poor':
            ratingScore = 0;
            break;
    }

    return tlsSecure + certValid + secureProtocols + ratingScore;
}


// Web Security Rating Modal JavaScript

/**
 * Initialize the web security rating modal functionality
 */
function initializeWebSecurityModal() {
    const modal = document.getElementById('webSecurityModal');
    const closeBtn = modal.querySelector('.close-modal');

    // Rating category boxes that will open the modal
    const ratingBoxes = document.querySelectorAll('.rating-group');

    // Close modal when clicking the X
    closeBtn.onclick = function () {
        modal.style.display = 'none';
    };

    // Close modal when clicking outside of it
    window.onclick = function (event) {
        if (event.target == modal) {
            modal.style.display = 'none';
        }
    };

    // Add click handlers to rating boxes
    ratingBoxes.forEach(box => {
        box.addEventListener('click', function () {
            const rating = this.classList[1]; // 'excellent', 'good', 'fair', or 'poor'
            openRatingModal(rating);
        });
    });
}

/**
 * Open the modal with domains for the specified rating
 */
function openRatingModal(rating) {
    // Get rating details from the statsData
    const ratingDetails = statsData.web_rating_details[rating] || [];
    const modal = document.getElementById('webSecurityModal');
    const ratingCategory = document.getElementById('ratingCategory');
    const domainCount = document.getElementById('domainCount');
    const domainListBody = document.getElementById('domainListBody');

    // Set modal title and count
    ratingCategory.textContent = rating.charAt(0).toUpperCase() + rating.slice(1);
    ratingCategory.className = `rating-${rating}`;
    domainCount.textContent = ratingDetails.length;

    // Clear previous domain list
    domainListBody.innerHTML = '';

    // Add domains to the table
    ratingDetails.forEach(domainDetail => {
        const row = document.createElement('tr');
        row.dataset.domain = domainDetail.domain;

        // Add click handler to show domain issues
        row.addEventListener('click', function () {
            // Remove selected class from all rows
            document.querySelectorAll('#domainListBody tr').forEach(r => {
                r.classList.remove('selected');
            });

            // Add selected class to clicked row
            this.classList.add('selected');

            // Show domain issues
            showDomainIssues(domainDetail);
        });

        // Create table cells
        row.innerHTML = `
            <td>${domainDetail.domain}</td>
            <td>${domainDetail.score}/100</td>
            <td>
                <span class="status-indicator ${domainDetail.tls_secure ? 'status-success' : 'status-failure'}"></span>
                ${domainDetail.tls_secure ? 'Secure' : 'Not Secure'}
            </td>
            <td>
                <span class="status-indicator ${domainDetail.cert_valid ? 'status-success' : 'status-failure'}"></span>
                ${domainDetail.cert_valid ? 'Valid' : 'Invalid'}
            </td>
            <td>
                <span class="status-indicator ${domainDetail.uses_secure_protocols ? 'status-success' : 'status-failure'}"></span>
                ${domainDetail.uses_secure_protocols ? 'Yes' : 'No'}
            </td>
        `;

        domainListBody.appendChild(row);
    });

    // Reset domain issues section
    document.getElementById('domainIssues').innerHTML = '<p>Select a domain to view issues</p>';

    // Show the modal
    modal.style.display = 'block';

    // Select the first domain if available
    if (ratingDetails.length > 0) {
        const firstRow = domainListBody.querySelector('tr');
        if (firstRow) {
            firstRow.click();
        }
    }
}

/**
 * Show issues for the selected domain
 */
function showDomainIssues(domainDetail) {
    const domainIssues = document.getElementById('domainIssues');

    // Clear previous content
    domainIssues.innerHTML = '';

    // Add domain name as title
    const issuesTitle = document.createElement('h4');
    issuesTitle.textContent = `Issues for ${domainDetail.domain}:`;
    domainIssues.appendChild(issuesTitle);

    // Check if there are issues
    if (domainDetail.issues && domainDetail.issues.length > 0) {
        // Create issues container
        const issuesContainer = document.createElement('div');
        issuesContainer.className = 'security-issues-container';

        domainDetail.issues.forEach(issue => {
            // Create issue card
            const issueCard = document.createElement('div');
            issueCard.className = 'security-issue-card';

            // Determine issue category and severity
            const issueCategory = categorizeSecurityIssue(issue);

            // Create issue header with icon
            const issueHeader = document.createElement('div');
            issueHeader.className = 'issue-header';

            const issueIcon = document.createElement('span');
            issueIcon.className = `issue-icon ${issueCategory.severity}`;
            issueIcon.innerHTML = getIssueIcon(issueCategory.type);

            const issueTitle = document.createElement('span');
            issueTitle.className = 'issue-title';
            issueTitle.textContent = issue;

            issueHeader.appendChild(issueIcon);
            issueHeader.appendChild(issueTitle);

            // Add description if available
            if (issueCategory.description) {
                const issueDescription = document.createElement('div');
                issueDescription.className = 'issue-description';
                issueDescription.textContent = issueCategory.description;
                issueCard.appendChild(issueHeader);
                issueCard.appendChild(issueDescription);
            } else {
                issueCard.appendChild(issueHeader);
            }

            issuesContainer.appendChild(issueCard);
        });

        domainIssues.appendChild(issuesContainer);
    } else {
        // No issues message
        const noIssues = document.createElement('div');
        noIssues.className = 'no-issues-message';

        const checkIcon = document.createElement('span');
        checkIcon.className = 'issue-icon success';
        checkIcon.innerHTML = '<i class="fas fa-check-circle"></i>';

        const messageText = document.createElement('span');
        messageText.textContent = 'No specific issues identified.';

        noIssues.appendChild(checkIcon);
        noIssues.appendChild(messageText);

        domainIssues.appendChild(noIssues);
    }
}

/**
 * Categorize security issues by type and severity
 */
function categorizeSecurityIssue(issue) {
    const issueLower = issue.toLowerCase();
    let category = {
        type: 'general',
        severity: 'medium',
        description: null
    };

    // Headers
    if (issueLower.includes('header') || issueLower.includes('hsts')) {
        category.type = 'header';
        category.severity = 'medium';

        // Add descriptions for common headers
        if (issueLower.includes('content-security-policy')) {
            category.description = 'Content Security Policy helps prevent XSS attacks by controlling which resources can be loaded.';
        } else if (issueLower.includes('referrer-policy')) {
            category.description = 'Referrer Policy controls how much referrer information is included with requests.';
        } else if (issueLower.includes('hsts')) {
            category.description = 'HTTP Strict Transport Security ensures connections to the site are always via HTTPS.';
        } else if (issueLower.includes('x-frame-options')) {
            category.description = 'X-Frame-Options prevents clickjacking attacks by controlling if a page can be displayed in frames.';
        }
    }
    // TLS/SSL issues
    else if (issueLower.includes('tls') || issueLower.includes('ssl') || issueLower.includes('cipher') || issueLower.includes('protocol')) {
        category.type = 'tls';
        category.severity = 'high';
    }
    // Certificate issues
    else if (issueLower.includes('certificate') || issueLower.includes('cert')) {
        category.type = 'certificate';
        category.severity = 'high';
    }
    // Critical vulnerabilities
    else if (issueLower.includes('vulnerability') || issueLower.includes('exploit') || issueLower.includes('injection')) {
        category.type = 'vulnerability';
        category.severity = 'critical';
    }

    return category;
}

/**
 * Get appropriate icon for issue type
 */
function getIssueIcon(type) {
    switch (type) {
        case 'header':
            return '<i class="fas fa-heading"></i>';
        case 'tls':
            return '<i class="fas fa-lock"></i>';
        case 'certificate':
            return '<i class="fas fa-certificate"></i>';
        case 'vulnerability':
            return '<i class="fas fa-bug"></i>';
        default:
            return '<i class="fas fa-exclamation-triangle"></i>';
    }
}

// Add this to your existing initialization code
document.addEventListener('DOMContentLoaded', function () {
    if (statsData && !modalInitialized) {
        initializeWebSecurityModal();
        modalInitialized = true;
    }
});

function configureChartDefaults() {
    // Set global chart defaults
    Chart.defaults.responsive = true;
    Chart.defaults.maintainAspectRatio = false;

    // Add padding to prevent right-side cutoff
    Chart.defaults.layout = {
        padding: {
            left: 0,
            right: 20,  // Add padding to the right side
            top: 5,
            bottom: 10
        }
    };



    // Add window resize handler to redraw charts
    window.addEventListener('resize', function() {
        // Force redraw of all charts when window is resized
        if (window.Chart && Chart.instances) {
            Object.values(Chart.instances).forEach(chart => {
                try {
                    chart.resize();
                } catch(e) {
                    console.warn('Error resizing chart:', e);
                }
            });
        }
    });
}

// Initialize a flag to track modal initialization
let modalInitialized = false;