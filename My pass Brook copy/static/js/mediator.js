class DashboardMediator {
    constructor() {
        this.components = new Map();
        this.dataProxy = new SensitiveDataProxy();
        this.sessionManager = new SessionManager();
        this.clipboardManager = new ClipboardManager();
        
        // Register the clipboard manager
        this.register('clipboard', this.clipboardManager);
    }

    register(name, component) {
        this.components.set(name, component);
    }

    async notify(event, data) {
        switch(event) {
            case 'showSensitiveData':
                this.dataProxy.showValue(data.element, data.value, data.type);
                break;
            case 'hideSensitiveData':
                this.dataProxy.maskValue(data.element, data.value, data.type);
                break;
            case 'copyToClipboard':
                const clipboard = this.components.get('clipboard');
                const success = await clipboard.copy(data.text);
                if (success && data.button) {
                    this.components.get('dashboard').showCopyFeedback(data.button);
                }
                break;
            case 'dismissAlert':
                this.components.get('alerts').dismiss(data);
                break;
            case 'userActivity':
                this.sessionManager.resetTimer();
                break;
        }
    }
} 