class SessionManager {
    constructor() {
        
        if (SessionManager.instance) {
            return SessionManager.instance;
        }
        this.inactivityTimer = null;
        this.timeoutDuration = 300000; // 5 min timeout
        this.initializeInactivityCheck();
        SessionManager.instance = this;
    }

    initializeInactivityCheck() {
        ['mousemove', 'keypress', 'click', 'scroll'].forEach(event => {
            document.addEventListener(event, () => this.resetTimer());
        });
        this.resetTimer();
    }

    resetTimer() {
        if (this.inactivityTimer) {
            clearTimeout(this.inactivityTimer);
        }
        this.inactivityTimer = setTimeout(() => this.lockVault(), this.timeoutDuration);
    }

    lockVault() {
        
        document.querySelectorAll('.masked-data').forEach(element => {
            const type = element.dataset.type;
            const value = element.dataset.value;
            mediator.notify('hideSensitiveData', { element, value, type });
        });

        
        document.querySelectorAll('.btn-show').forEach(button => {
            button.textContent = 'Show';
        });

       
    }
} 