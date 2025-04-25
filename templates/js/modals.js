// modals.js - Main modal management functionality

/**
 * Initialize modal functionality
 */
function initModals() {
    // Add event listener to close modals when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target.classList.contains('modal')) {
            event.target.style.display = 'none';
        }
    });
}

/**
 * Create a modal if it doesn't exist yet, and open it
 * @param {string} modalId - ID of the modal
 * @param {string} type - Type of modal (RPKI, DANE, etc.)
 * @param {string} domain - Domain name
 * @param {Object} data - Data for the modal content
 */
function openModalWithData(modalId, type, domain, data) {
    let modal = document.getElementById(modalId);

    // Create the modal if it doesn't exist
    if (!modal) {
        createModal(modalId, type, domain, data);
        modal = document.getElementById(modalId);
    }

    if (!modal) {
        console.error(`Failed to create or find modal with ID ${modalId}`);
        return;
    }

    // Hide all other modals
    document.querySelectorAll('.modal').forEach(m => {
        m.style.display = 'none';
    });

    // Show this modal
    modal.style.display = 'block';

    // Show the first tab if available
    const firstTabContent = modal.querySelector('.tab-content');
    if (firstTabContent) {
        const tabId = firstTabContent.id;
        showTab(tabId);
    }
}

/**
 * Simple wrapper to open an existing modal without creating
 * @param {string} modalId - ID of the modal to open
 */
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) {
        console.error(`Modal with ID ${modalId} not found`);
        return;
    }

    // Hide all other modals first
    document.querySelectorAll('.modal').forEach(m => {
        m.style.display = 'none';
    });

    // Show this modal
    modal.style.display = 'block';

    // Find and show the first tab content
    const firstTabContent = modal.querySelector('.tab-content');
    if (firstTabContent) {
        const tabId = firstTabContent.id;
        showTab(tabId);
    }
}

/**
 * Close a modal
 * @param {string} modalId - ID of the modal to close
 */
function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
    }
}

/**
 * Show a tab within a modal
 * @param {string} tabId - ID of the tab to show
 */
function showTab(tabId) {
    const tabElement = document.getElementById(tabId);
    if (!tabElement) {
        console.error(`Tab with ID ${tabId} not found`);
        return;
    }

    const modal = tabElement.closest('.modal-content');
    if (!modal) {
        console.error('Modal content container not found');
        return;
    }

    // Hide all tab contents in this modal
    modal.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });

    // Remove active class from all tab buttons in this modal
    modal.querySelectorAll('.tab-button').forEach(button => {
        button.classList.remove('active');
    });

    // Show the selected tab
    tabElement.classList.add('active');

    // Activate the corresponding button
    const button = modal.querySelector(`.tab-button[onclick*="${tabId}"]`);
    if (button) {
        button.classList.add('active');
    }

    // Hide any visible tooltips when switching modal tabs
    if (typeof hideAllTooltips === 'function') {
        hideAllTooltips();
    }
}

/**
 * Create a modal and add it to the document
 * @param {string} modalId - ID for the modal
 * @param {string} type - Type of modal (RPKI, DANE, etc.)
 * @param {string} domain - Domain name
 * @param {Object} data - Data for the modal content
 */
function createModal(modalId, type, domain, data) {
    // Get the modal container
    const modalsContainer = document.getElementById('modals-container');
    if (!modalsContainer) {
        console.error('Modals container not found');
        return;
    }

    // Create modal HTML
    let modalHTML = '';

    switch (type.toUpperCase()) {
        case 'RPKI':
            modalHTML = createRPKIModal(modalId, domain, data);
            break;
        case 'DANE':
            modalHTML = createDANEModal(modalId, domain, data);
            break;
        case 'DNSSEC':
            modalHTML = createDNSSECModal(modalId, domain, data);
            break;
        case 'EMAIL_SECURITY':
            modalHTML = createEmailSecurityModal(modalId, domain, data);
            break;
        case 'WEB_SECURITY':
            modalHTML = createWebSecurityModal(modalId, domain, data);
            break;
        default:
            console.error(`Unknown modal type: ${type}`);
            return;
    }

    // Add the modal to the container
    modalsContainer.insertAdjacentHTML('beforeend', modalHTML);

    // Add event listeners
    const modal = document.getElementById(modalId);
    if (modal) {
        // Close button event listener
        const closeButtons = modal.querySelectorAll('.close-modal');
        closeButtons.forEach(button => {
            button.addEventListener('click', function() {
                modal.style.display = 'none';
            });
        });

        // Tab buttons event listeners
        const tabButtons = modal.querySelectorAll('.tab-button');
        tabButtons.forEach(button => {
            button.addEventListener('click', function() {
                // Use the onclick attribute for compatibility with the original code
                const onclickAttr = this.getAttribute('onclick');
                if (onclickAttr) {
                    const match = onclickAttr.match(/showTab\('([^']+)'\)/);
                    if (match && match[1]) {
                        showTab(match[1]);
                    }
                }
            });
        });
    }
}

// These functions will be defined in their respective files
// Just define empty placeholders here to avoid errors if the specific JS files aren't loaded
if (typeof createRPKIModal !== 'function') {
    createRPKIModal = function(modalId, domain, data) {
        console.error('RPKI modal implementation not loaded');
        return `<div id="${modalId}" class="modal"><div class="modal-content"><p>Error: RPKI modal implementation not loaded</p></div></div>`;
    };
}

if (typeof createDANEModal !== 'function') {
    createDANEModal = function(modalId, domain, data) {
        console.error('DANE modal implementation not loaded');
        return `<div id="${modalId}" class="modal"><div class="modal-content"><p>Error: DANE modal implementation not loaded</p></div></div>`;
    };
}

if (typeof createDNSSECModal !== 'function') {
    createDNSSECModal = function(modalId, domain, data) {
        console.error('DNSSEC modal implementation not loaded');
        return `<div id="${modalId}" class="modal"><div class="modal-content"><p>Error: DNSSEC modal implementation not loaded</p></div></div>`;
    };
}

if (typeof createEmailSecurityModal !== 'function') {
    createEmailSecurityModal = function(modalId, domain, data) {
        console.error('Email Security modal implementation not loaded');
        return `<div id="${modalId}" class="modal"><div class="modal-content"><p>Error: Email Security modal implementation not loaded</p></div></div>`;
    };
}

if (typeof createWebSecurityModal !== 'function') {
    createWebSecurityModal = function(modalId, domain, data) {
        console.error('Web Security modal implementation not loaded');
        return `<div id="${modalId}" class="modal"><div class="modal-content"><p>Error: Web Security modal implementation not loaded</p></div></div>`;
    };
}