class DashboardManager {
    constructor() {
        this.mediator = new DashboardMediator();
        this.mediator.register('dashboard', this);
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        const container = document.querySelector('.dashboard-container');
        if (container) {
            container.addEventListener('click', (event) => this.handleDashboardClick(event));
        }

        // Register with mediator for all sensitive data operations
        document.querySelectorAll('.masked-data').forEach(element => {
            element.addEventListener('show', () => {
                this.mediator.notify('userActivity');
            });
        });
    }

    handleDashboardClick(event) {
        const button = event.target.closest('button');
        if (!button) return;

        const action = button.dataset.action;
        if (!action) return;

        switch (action) {
            case 'show':
                const itemField = button.closest('.item-field');
                if (!itemField) return;
                const maskedData = itemField.querySelector('.masked-data');
                if (maskedData) {
                    this.handleShowHide(button, maskedData);
                }
                break;

            case 'copy':
                // Handle both masked data and direct value copying
                const value = button.dataset.value || 
                            button.closest('.item-field')?.querySelector('.masked-data')?.dataset.value;
                if (value) {
                    this.handleCopy(button, value);
                }
                break;

            case 'delete':
                const type = button.dataset.type;
                const id = button.dataset.id;
                if (type && id) {
                    this.deleteItem(type, id);
                }
                break;

            case 'navigate':
                const url = button.dataset.url;
                if (url) {
                    window.location.href = url;
                }
                break;
        }
    }

    handleShowHide(button, dataSpan) {
        const data = {
            element: dataSpan,
            value: dataSpan.dataset.value,
            type: dataSpan.dataset.type
        };

        if (button.textContent === 'Show') {
            this.mediator.notify('showSensitiveData', data);
            button.textContent = 'Hide';
            
            // Auto-hide after 30 seconds
            setTimeout(() => {
                this.mediator.notify('hideSensitiveData', data);
                button.textContent = 'Show';
            }, 30000);
        } else {
            this.mediator.notify('hideSensitiveData', data);
            button.textContent = 'Show';
        }
    }

    handleCopy(button, value) {
        this.mediator.notify('copyToClipboard', {
            text: value,
            button: button
        });
    }

    fallbackCopy(text, button) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-9999px';
        document.body.appendChild(textArea);
        
        try {
            textArea.select();
            document.execCommand('copy');
            this.showCopyFeedback(button);
        } catch (err) {
            console.error('Fallback copy failed:', err);
            alert('Copy failed. Please try again.');
        } finally {
            document.body.removeChild(textArea);
        }
    }

    showCopyFeedback(button) {
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        
        // Clear any existing timeout
        if (button.dataset.timeoutId) {
            clearTimeout(Number(button.dataset.timeoutId));
        }
        
        // Set new timeout
        const timeoutId = setTimeout(() => {
            button.textContent = originalText;
        }, 2000);
        
        button.dataset.timeoutId = timeoutId;
    }

    deleteItem(type, id) {
        if (!confirm('Are you sure you want to delete this item? This action cannot be undone.')) {
            return;
        }

        fetch(`/delete_${type}/${id}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'same-origin'
        })
        .then(response => {
            if (response.ok) {
                window.location.reload();
            } else {
                throw new Error('Failed to delete item');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error deleting item. Please try again.');
        });
    }
}

// Initialize the dashboard manager when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new DashboardManager();
}); 