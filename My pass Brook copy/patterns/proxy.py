class SensitiveDataProxy:
    def __init__(self):
        self.masked_char = '•'
    
    def mask_data(self, vault_item):
        # Create a copy of the vault item to avoid modifying the original
        masked_item = type('', (), {})()
        for attr in dir(vault_item):
            if not attr.startswith('_'):  # Skip private attributes
                value = getattr(vault_item, attr)
                setattr(masked_item, attr, value)
        
        # Preserve the original values but mask them for display
        if hasattr(vault_item, 'username'):
            masked_item.username_masked = self.masked_char * len(vault_item.username)
            masked_item.username = vault_item.username  # Keep original for unmasking
            
        if hasattr(vault_item, 'password'):
            masked_item.password_masked = self.masked_char * 8
            masked_item.password = vault_item.password  # Keep original for unmasking
            
        return masked_item
    
    def unmask_data(self, vault_item):
        return vault_item