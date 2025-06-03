// collapsible.js - Functionality for collapsible sections

/**
 * Toggle a collapsible element
 * @param {HTMLElement} element - The header element to toggle
 */
function toggleCollapse(element) {
    element.classList.toggle('collapsed');
    const content = element.nextElementSibling;

    if (element.classList.contains('collapsed')) {
        // Collapse
        content.style.maxHeight = '0';
        content.style.padding = '0 16px';
        content.style.overflow = 'hidden';
    } else {
        // Expand
        content.style.maxHeight = content.scrollHeight + 'px';
        content.style.padding = '16px';
        content.style.overflow = 'visible';
    }
}

/**
 * Initialize all collapsible elements
 */
function initCollapsible() {
    document.querySelectorAll('.collapsible').forEach(element => {
        element.addEventListener('click', function() {
            toggleCollapse(this);
        });
    });
}

// Initialize collapsible sections when the DOM is loaded
document.addEventListener('DOMContentLoaded', initCollapsible);