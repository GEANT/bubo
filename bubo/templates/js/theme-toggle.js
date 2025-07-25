/**
 * Theme toggle functionality for dark/light mode with chart integration
 */
class ThemeToggle {
    constructor() {
        this.theme = this.getStoredTheme() || 'light';
        this.init();
    }

    init() {
        this.applyTheme(this.theme);
        this.createToggleButton();
        this.bindEvents();
    }

    getStoredTheme() {
        return localStorage.getItem('theme');
    }

    setStoredTheme(theme) {
        localStorage.setItem('theme', theme);
    }

    applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        this.theme = theme;
        this.setStoredTheme(theme);
        this.updateToggleIcon();

        // Update charts when theme changes
        this.updateChartsForTheme();

        // Dispatch custom event for other components that might need to update
        const themeChangeEvent = new CustomEvent('themeChanged', {
            detail: {theme: theme}
        });
        document.dispatchEvent(themeChangeEvent);
    }

    toggleTheme() {
        const newTheme = this.theme === 'light' ? 'dark' : 'light';
        this.applyTheme(newTheme);
    }

    createToggleButton() {
        // Check if button already exists
        if (document.querySelector('.theme-toggle')) {
            return;
        }

        const button = document.createElement('button');
        button.className = 'theme-toggle';
        button.setAttribute('aria-label', 'Toggle theme');
        button.setAttribute('title', 'Toggle dark/light theme');

        const icon = document.createElement('i');
        icon.className = this.theme === 'light' ? 'fas fa-moon' : 'fas fa-sun';
        button.appendChild(icon);

        document.body.appendChild(button);
        this.toggleButton = button;
    }

    updateToggleIcon() {
        if (this.toggleButton) {
            const icon = this.toggleButton.querySelector('i');
            if (icon) {
                icon.className = this.theme === 'light' ? 'fas fa-moon' : 'fas fa-sun';
            }
        }
    }

    bindEvents() {
        if (this.toggleButton) {
            this.toggleButton.addEventListener('click', () => {
                this.toggleTheme();
            });
        }

        // Listen for system theme changes
        if (window.matchMedia) {
            const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
            mediaQuery.addEventListener('change', (e) => {
                if (!this.getStoredTheme()) {
                    this.applyTheme(e.matches ? 'dark' : 'light');
                }
            });
        }
    }

    /**
     * Update charts when theme changes - integrates with chart functions
     */
    updateChartsForTheme() {
        // Only update if the chart update function exists
        if (typeof updateChartsForTheme === 'function') {
            // Use setTimeout to ensure DOM has updated with new theme
            setTimeout(() => {
                updateChartsForTheme();
            }, 50);
        }
    }

    // Public method to manually set theme
    setTheme(theme) {
        if (theme === 'light' || theme === 'dark') {
            this.applyTheme(theme);
        }
    }

    // Public method to get current theme
    getCurrentTheme() {
        return this.theme;
    }

    // Public method to force chart updates (useful for manual chart refreshes)
    refreshCharts() {
        this.updateChartsForTheme();
    }
}

// Initialize theme toggle when DOM is loaded
document.addEventListener('DOMContentLoaded', function () {
    window.themeToggle = new ThemeToggle();

    // Also listen for the theme change event (optional, for debugging or other components)
    document.addEventListener('themeChanged', function (event) {
        console.log('Theme changed to:', event.detail.theme);
    });
});

// Also initialize if DOM is already loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
        if (!window.themeToggle) {
            window.themeToggle = new ThemeToggle();
        }
    });
} else {
    if (!window.themeToggle) {
        window.themeToggle = new ThemeToggle();
    }
}

// Export for module usage if needed
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ThemeToggle;
}