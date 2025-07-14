// main.js - Main entry point for the application

/**
 * Initialize the application
 */
function initApp() {

    // Verify that data is available
    if (!window.validationData) {
        showError('Validation data not found. Please check the report generation.');
        return;
    }

    // First render the table with basic headers
    renderValidationTable();

    // Then initialize tooltips to add validation column headers
    initTooltips();

    // Initialize modals
    initModals();
}

/**
 * Show an error message
 * @param {string} message - Error message to display
 */
function showError(message) {
    console.error(message);

    const tableBody = document.getElementById('validation-table-body');
    if (tableBody) {
        const errorRow = document.createElement('tr');
        const errorCell = document.createElement('td');
        errorCell.colSpan = 8; // Adjust based on column count
        errorCell.className = 'error-message';
        errorCell.textContent = message;
        errorRow.appendChild(errorCell);
        tableBody.appendChild(errorRow);
    }
}

// Initialize the application when the DOM is loaded
document.addEventListener('DOMContentLoaded', initApp);