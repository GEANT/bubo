// search.js - Handles search functionality for the validation table

/**
 * Initialize search functionality
 */
function initSearch() {
    const searchInput = document.getElementById('table-search');

    if (!searchInput) {
        console.error('Search input element not found');
        return;
    }

    // Add event listener for the Enter key in the search input
    searchInput.addEventListener('keyup', function(event) {
        if (event.key === 'Enter') {
            searchTable(searchInput.value.trim());
        }
    });

    // Add event listener for real-time searching (as the user types)
    searchInput.addEventListener('input', function() {
        searchTable(searchInput.value.trim());
    });
}


/**
 * Search the validation table
 * @param {string} query - Search query
 */
function searchTable(query) {
    const tableBody = document.getElementById('validation-table-body');
    const rows = tableBody.getElementsByTagName('tr');

    if (query === '') {
        // If the search query is empty, show all rows
        for (let i = 0; i < rows.length; i++) {
            rows[i].style.display = '';
        }
        return;
    }

    const lowerCaseQuery = query.toLowerCase();

    // Check each row
    for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        const cells = row.getElementsByTagName('td');

        // The maximum index to check (only Country, Institution, Domain)
        const maxIndex = Math.min(3, cells.length);
        let matches = false;

        // Check cells up to maxIndex (Country, Institution, Domain)
        for (let j = 0; j < maxIndex; j++) {
            const cellText = cells[j].textContent.toLowerCase();
            if (cellText.includes(lowerCaseQuery)) {
                matches = true;
                break;
            }
        }

        // Show or hide the row based on whether it matches
        row.style.display = matches ? '' : 'none';
    }
}


// Initialize search when the DOM is loaded
document.addEventListener('DOMContentLoaded', initSearch);