class SensitiveDataProxy {
    // Handles masking of sensitive data like credit cards and SSNs
    maskValue(element, value, type) {
        if (!this.validateAccess()) return;

        switch(type) {
            case 'card':
                // Show only last 4 digits of card
                element.textContent = '•••• •••• •••• ' + value.slice(-4);
                break;
            case 'cvv':
                // Completely mask CVV
                element.textContent = '•••';
                break;
            case 'username':
                if (value.includes('@')) {
                    const [username, domain] = value.split('@');
                    element.textContent = '•'.repeat(username.length) + '@' + domain;
                } else {
                    element.textContent = '•'.repeat(value.length);
                }
                break;
            case 'name':
            case 'full_name':
                element.textContent = '•'.repeat(value.length);
                break;
            case 'id':
            case 'identity_number':
            case 'ssn':
            case 'passport':
            case 'license':
                if (type === 'ssn') {
                    element.textContent = '•••-••-' + value.slice(-4);
                } else {
                    element.textContent = '•'.repeat(value.length - 4) + value.slice(-4);
                }
                break;
            case 'identity':
                element.textContent = '•'.repeat(value.length);
                break;
            case 'note':
                element.textContent = '•'.repeat(12); // Fixed length for notes
                break;
            default:
                element.textContent = '•'.repeat(value.length);
        }
    }

    showValue(element, value, type) {
        if (!this.validateAccess()) {
            console.error('Access denied to sensitive data');
            return false;
        }
        
        switch(type) {
            case 'full_name':
                element.textContent = value.trim();
                break;
            case 'ssn':
                if (value.length === 9) {
                    element.textContent = value.slice(0,3) + '-' + value.slice(3,5) + '-' + value.slice(5);
                } else {
                    element.textContent = value;
                }
                break;
            case 'passport':
            case 'drivers_license':
            case 'identity_number':
                element.textContent = value;
                break;
            default:
                element.textContent = value.trim();
        }
        return true;
    }

    validateAccess() {
        // Add security checks here (e.g., session validity)
        return true;
    }
} 