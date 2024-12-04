class ClipboardManager {
    constructor() {
        this.fallbackInProgress = false;
    }

    async copy(text) {
        try {
            // Try using the modern Clipboard API first
            await navigator.clipboard.writeText(text);
            return true;
        } catch (err) {
            // Fall back to execCommand if Clipboard API fails
            if (!this.fallbackInProgress) {
                return this.fallbackCopy(text);
            }
            return false;
        }
    }

    fallbackCopy(text) {
        this.fallbackInProgress = true;
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-9999px';
        document.body.appendChild(textArea);
        
        try {
            textArea.select();
            document.execCommand('copy');
            return true;
        } catch (err) {
            console.error('Fallback copy failed:', err);
            return false;
        } finally {
            document.body.removeChild(textArea);
            this.fallbackInProgress = false;
        }
    }
} 