import random
import string

class PasswordBuilder:
    """Builder pattern for generating complex passwords"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        self._length = 12  # Default length
        self._include_uppercase = False
        self._include_lowercase = True  # Default to at least lowercase
        self._include_numbers = False
        self._include_symbols = False
        self._min_uppercase = 0
        self._min_numbers = 0
        self._min_symbols = 0
        return self
    
    def set_length(self, length: int):
        self._length = max(8, length)  # Minimum 8 characters
        return self
    
    def include_uppercase(self, min_count: int = 1):
        self._include_uppercase = True
        self._min_uppercase = min_count
        return self
    
    def include_lowercase(self, required: bool = True):
        self._include_lowercase = required
        return self
    
    def include_numbers(self, min_count: int = 1):
        self._include_numbers = True
        self._min_numbers = min_count
        return self
    
    def include_symbols(self, min_count: int = 1):
        self._include_symbols = True
        self._min_symbols = min_count
        return self
    
    def build(self) -> str:
        # Ensure at least one character type is selected
        if not any([self._include_lowercase, self._include_uppercase, 
                   self._include_numbers, self._include_symbols]):
            self._include_lowercase = True  # Default to lowercase if nothing selected
        
        # Initialize character pools
        chars = []
        if self._include_lowercase:
            chars.extend(string.ascii_lowercase)
        if self._include_uppercase:
            chars.extend(string.ascii_uppercase)
        if self._include_numbers:
            chars.extend(string.digits)
        if self._include_symbols:
            chars.extend("!@#$%^&*()_+-=[]{}|;:,.<>?")
        
        if not chars:
            raise ValueError("No character types selected for password generation")
        
        # Ensure minimum requirements are met
        password = []
        if self._include_uppercase:
            password.extend(random.choice(string.ascii_uppercase) 
                          for _ in range(self._min_uppercase))
        if self._include_numbers:
            password.extend(random.choice(string.digits) 
                          for _ in range(self._min_numbers))
        if self._include_symbols:
            password.extend(random.choice("!@#$%^&*()_+-=[]{}|;:,.<>?") 
                          for _ in range(self._min_symbols))
            
        # Fill remaining length with random characters
        remaining_length = self._length - len(password)
        password.extend(random.choice(chars) for _ in range(remaining_length))
        
        # Shuffle the password
        random.shuffle(password)
        return ''.join(password) 