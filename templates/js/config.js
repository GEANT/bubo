// config.js - Configuration and constants

const CONFIG = {
    // Column definitions with tooltips
    COLUMNS: [
        {
            id: 'rpki',
            title: 'RPKI',
            tooltipData: {
                title: 'Resource Public Key Infrastructure (RPKI)',
                description: 'RPKI is a security framework that verifies IP address ownership and ensures proper routing.',
                bullets: [
                    'Prevents BGP hijacking and route leaks',
                    'Validates that IP prefixes are announced by authorized networks',
                    'Improves overall internet routing security'
                ]
            },
            modalType: 'RPKI'
        },
        {
            id: 'dane',
            title: 'DANE',
            tooltipData: {
                title: 'DNS-based Authentication of Named Entities (DANE)',
                description: 'DANE binds TLS certificates to domains using DNSSEC, providing an additional layer of validation.',
                bullets: [
                    'Reduces reliance on traditional certificate authorities',
                    'Helps prevent man-in-the-middle attacks',
                    'Enables stronger verification of encrypted connections'
                ]
            },
            modalType: 'DANE'
        },
        {
            id: 'dnssec',
            title: 'DNSSEC',
            tooltipData: {
                title: 'Domain Name System Security Extensions (DNSSEC)',
                description: 'DNSSEC adds cryptographic signatures to DNS records to ensure their authenticity.',
                bullets: [
                    'Protects against DNS cache poisoning',
                    'Verifies DNS responses come from legitimate sources',
                    'Provides a chain of trust from the root zone to subdomains'
                ]
            },
            modalType: 'DNSSEC'
        },
        {
            id: 'email-security',
            title: 'Email Security',
            tooltipData: {
                title: 'Email Security Standards',
                description: 'A combination of protocols that protect email from spoofing and phishing.',
                bullets: [
                    '<strong>SPF:</strong> Specifies which servers can send email from your domain',
                    '<strong>DKIM:</strong> Digitally signs emails to verify they haven\'t been tampered with',
                    '<strong>DMARC:</strong> Policies for handling emails that fail SPF or DKIM checks'
                ]
            },
            modalType: 'EMAIL_SECURITY'
        },
        {
            id: 'web-security',
            title: 'Web Security',
            tooltipData: {
                title: 'WEB Security',
                description: 'Transport Layer Security (TLS) is a protocol that ensures privacy between communicating applications and their users on the Internet.',
                subdescription: 'This check evaluates:',
                bullets: [
                    '<strong>Certificate validity</strong> - Is the SSL/TLS certificate valid and from a trusted authority?',
                    '<strong>Protocol security</strong> - Are only secure TLS versions supported?',
                    '<strong>Cipher strength</strong> - Are strong encryption ciphers used?',
                    '<strong>Security headers</strong> - Are essential security HTTP headers implemented?',
                    '<strong>HSTS</strong> - Is HTTP Strict Transport Security properly configured?'
                ],
                footer: 'The overall rating summarizes the security posture of the site\'s TLS implementation.'
            },
            modalType: 'WEB_SECURITY'
        }
    ],

    STATUS_MAPPING: {
        'valid': {
            icon: 'check-circle',
            class: 'status-valid',
            display: 'Valid'
        },
        'not-valid': {
            icon: 'times-circle',
            class: 'status-not-valid',
            display: 'Not Valid'
        },
        'partially-valid': {
            icon: 'exclamation-triangle',
            class: 'status-partially-valid',
            display: 'Partially Valid'
        },
        'not-found': {
            icon: 'question-circle',
            class: 'status-not-found',
            display: 'Not Found'
        }
    },

    CHECK_TYPES: [
        'Nameserver of Domain',
        'Mail Server of Domain',
        'Nameserver of Mail Server'
    ],

    SHORT_NAMES: {
        'Nameserver of Domain': 'Nameserver',
        'Mail Server of Domain': 'Mailserver',
        'Nameserver of Mail Server': 'Mailserver-NS'
    }
};