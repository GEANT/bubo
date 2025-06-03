// tooltips.js - Manages tooltip functionality

/**
 * Initialize tooltip functionality
 */
function initTooltips() {
    // Add tooltips to table headers
    addColumnHeaders();

    // Add event listener to hide tooltips when clicking outside
    document.addEventListener('click', function(event) {
        if (!event.target.closest('.tooltip-content') &&
            !event.target.closest('.info-icon')) {
            hideAllTooltips();
        }
    });
}

/**
 * Add column headers with tooltips based on CONFIG.COLUMNS
 */
function addColumnHeaders() {
    const headerRow = document.querySelector('#table-headers tr');
    if (!headerRow) return;

    // Add tooltips to column headers
    CONFIG.COLUMNS.forEach(column => {
        headerRow.appendChild(createTooltipHeader(column.title, `${column.id}-tooltip`, column.tooltipData));
    });
}

/**
 * Create a header cell with tooltip
 * @param {string} title - Header title
 * @param {string} tooltipId - Unique ID for the tooltip
 * @param {Object} tooltipData - Structured data for the tooltip content
 * @returns {HTMLElement} - The header cell with tooltip
 */
function createTooltipHeader(title, tooltipId, tooltipData) {
    const headerCell = document.createElement('th');

    const headerContainer = document.createElement('div');
    headerContainer.className = 'header-with-tooltip';

    const headerText = document.createElement('span');
    headerText.textContent = title;

    const infoIcon = document.createElement('span');
    infoIcon.className = 'info-icon';
    infoIcon.innerHTML = '<i class="fas fa-info-circle"></i>';

    const tooltip = document.createElement('div');
    tooltip.className = 'tooltip-content';
    tooltip.id = tooltipId;

    // Build tooltip content from structured data
    let tooltipHtml = '';

    // If tooltipData is a string (for backward compatibility), use it directly
    if (typeof tooltipData === 'string') {
        tooltipHtml = tooltipData;
    }
    // If tooltipData is a structured object, build HTML
    else if (tooltipData && typeof tooltipData === 'object') {
        if (tooltipData.title) {
            tooltipHtml += `<h4>${tooltipData.title}</h4>`;
        }

        if (tooltipData.description) {
            tooltipHtml += `<p>${tooltipData.description}</p>`;
        }

        if (tooltipData.subdescription) {
            tooltipHtml += `<p>${tooltipData.subdescription}</p>`;
        }

        if (tooltipData.bullets && tooltipData.bullets.length) {
            tooltipHtml += '<ul>';
            tooltipData.bullets.forEach(bullet => {
                tooltipHtml += `<li>${bullet}</li>`;
            });
            tooltipHtml += '</ul>';
        }

        if (tooltipData.footer) {
            tooltipHtml += `<p>${tooltipData.footer}</p>`;
        }
    }

    tooltip.innerHTML = tooltipHtml;

    // Add event listeners to show/hide tooltip
    infoIcon.addEventListener('mouseenter', () => showTooltip(tooltipId));
    infoIcon.addEventListener('mouseleave', () => hideTooltip(tooltipId));

    infoIcon.appendChild(tooltip);
    headerContainer.appendChild(headerText);
    headerContainer.appendChild(infoIcon);
    headerCell.appendChild(headerContainer);

    return headerCell;
}

/**
 * Show a tooltip
 * @param {string} tooltipId - ID of the tooltip
 */
function showTooltip(tooltipId) {
    const tooltip = document.getElementById(tooltipId);
    if (!tooltip) return;

    // Hide any other visible tooltips first
    document.querySelectorAll('.tooltip-content.visible').forEach(tip => {
        if (tip.id !== tooltipId) {
            tip.classList.remove('visible');
        }
    });

    // Show this tooltip
    tooltip.classList.add('visible');

    // Position the tooltip
    positionTooltip(tooltip);
}

/**
 * Hide a tooltip
 * @param {string} tooltipId - ID of the tooltip
 */
function hideTooltip(tooltipId) {
    const tooltip = document.getElementById(tooltipId);
    if (tooltip) {
        tooltip.classList.remove('visible');
    }
}

/**
 * Hide all tooltips
 */
function hideAllTooltips() {
    document.querySelectorAll('.tooltip-content.visible').forEach(tooltip => {
        tooltip.classList.remove('visible');
    });
}

/**
 * Position a tooltip to ensure it's visible
 * @param {HTMLElement} tooltip - The tooltip element
 */
function positionTooltip(tooltip) {
    // Reset positioning first
    tooltip.style.left = '';
    tooltip.style.right = '';
    tooltip.style.top = '';
    tooltip.style.bottom = '';

    // Get tooltip position
    const rect = tooltip.getBoundingClientRect();

    // Check if tooltip extends beyond right edge of screen
    if (rect.right > window.innerWidth) {
        tooltip.style.left = 'auto';
        tooltip.style.right = '0';
    }

    // Check if tooltip extends beyond left edge of screen
    if (rect.left < 0) {
        tooltip.style.left = '0';
        tooltip.style.right = 'auto';
    }

    // Make sure tooltip is fully visible in the viewport
    const viewportHeight = window.innerHeight;
    if (rect.bottom > viewportHeight) {
        tooltip.style.top = 'auto';
        tooltip.style.bottom = '100%';
    }
}