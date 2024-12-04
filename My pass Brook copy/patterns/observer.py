from abc import ABC, abstractmethod
from datetime import datetime, timedelta
import re
import json
import uuid

# Main subject that keeps track of all security-related events and observers
class SecuritySubject:
    _instance = None
    _observers = []
    _events = {}  # Stores events by user_id for easy lookup
    
    def __new__(cls):
        # Singleton pattern to ensure only one security subject exists
        if cls._instance is None:
            cls._instance = super(SecuritySubject, cls).__new__(cls)
        return cls._instance
    
    def attach(self, observer):
        if observer not in self._observers:
            self._observers.append(observer)
    
    def detach(self, observer):
        if observer in self._observers:
            self._observers.remove(observer)
    
    def notify(self, event):
        if event.user_id not in self._events:
            self._events[event.user_id] = []
        self._events[event.user_id].append(event)
        
        for observer in self._observers:
            observer.update(event)
    
    def get_events(self, user_id=None):
        if user_id is None:
            return [event for events in self._events.values() for event in events]
        return self._events.get(user_id, [])
    
    def clear_user_events(self, user_id):
        if user_id in self._events:
            del self._events[user_id]
    
    def remove_event(self, event_id, user_id):
        if user_id not in self._events:
            return False
        
        initial_length = len(self._events[user_id])
        self._events[user_id] = [e for e in self._events[user_id] 
                                if str(e.id) != str(event_id)]
        return len(self._events[user_id]) < initial_length

class SecurityEvent:
    def __init__(self, event_type, message, severity, item_id=None, user_id=None):
        self.id = str(uuid.uuid4())
        self.event_type = event_type
        self.message = message
        self.severity = severity
        self.timestamp = datetime.utcnow()
        self.item_id = item_id
        self.user_id = user_id

class SecurityObserver(ABC):
    @abstractmethod
    def update(self, event):
        pass

# Handles password strength checking and notifications
class PasswordStrengthObserver(SecurityObserver):
    def __init__(self):
        self.subject = SecuritySubject()
    
    def update(self, event):
        if event.event_type == 'password_check':
            pass
    
    def check_password(self, password, user_id):
        # Check if password meets all security requirements
        criteria = {
            'length': len(password) >= 12,
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'digit': bool(re.search(r'\d', password)),
            'special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        }
        
        failed_criteria = [k for k, v in criteria.items() if not v]
        
        if failed_criteria:
            message = "Password is weak. Missing: " + ", ".join(failed_criteria)
            self.subject.notify(SecurityEvent(
                'password_check',
                message,
                'high' if len(failed_criteria) > 2 else 'medium',
                user_id=user_id
            ))
            return False
        return True

class ExpirationObserver(SecurityObserver):
    def __init__(self):
        self.subject = SecuritySubject()
    
    def update(self, event):
        if event.event_type == 'expiration_check':
            pass
    
    def check_expiration(self, item_type, expiry_date, item_id, user_id):
        if not expiry_date:
            return
        
        try:
            if isinstance(expiry_date, str):
                expiry_date = datetime.strptime(expiry_date, '%Y-%m-%d')
            
            days_until_expiry = (expiry_date - datetime.utcnow()).days
            
            if days_until_expiry <= 0:
                severity = 'high'
                message = f"Your {item_type} has expired!"
            elif days_until_expiry <= 30:
                severity = 'medium'
                message = f"Your {item_type} will expire in {days_until_expiry} days"
            elif days_until_expiry <= 90:
                severity = 'low'
                message = f"Your {item_type} will expire in {days_until_expiry} days"
            else:
                return
            
            self.subject.notify(SecurityEvent(
                'expiration_check',
                message,
                severity,
                item_id=item_id,
                user_id=user_id
            ))
        except (ValueError, TypeError):
            pass

# Main manager that coordinates security checks and notifications
class SecurityNotificationManager:
    def __init__(self, vault_item_model=None):
        self.subject = SecuritySubject()
        self.password_observer = PasswordStrengthObserver()
        self.expiration_observer = ExpirationObserver()
        self.VaultItem = vault_item_model
        
        self.subject.attach(self.password_observer)
        self.subject.attach(self.expiration_observer)
    
    def check_vault_item(self, vault_item, user_id):
        try:
            data = json.loads(vault_item.data)
            
            # Run appropriate checks based on item type
            if vault_item.type == 'login':
                self.password_observer.check_password(
                    data.get('password', ''), 
                    user_id
                )
            
            elif vault_item.type == 'card':
                self.expiration_observer.check_expiration(
                    'credit card',
                    data.get('expiration'),
                    vault_item.id,
                    user_id
                )
            
            elif vault_item.type == 'identity':
                self.expiration_observer.check_expiration(
                    'identity document',
                    data.get('expiry_date'),
                    vault_item.id,
                    user_id
                )
        except json.JSONDecodeError:
            pass 
    
    def check_expiring_items(self, user_id):
        if not self.VaultItem:
            return []
            
        expiring_items = []
        warning_threshold = timedelta(days=30)
        
        try:
            # Check credit cards
            cards = self.VaultItem.query.filter_by(user_id=user_id, type='card').all()
            for card in cards:
                card_data = json.loads(card.data)
                expiry_date = datetime.strptime(card_data.get('expiry_date', ''), '%Y-%m')
                if self._is_expiring_soon(expiry_date, warning_threshold):
                    expiring_items.append({
                        'title': card.title,
                        'type': 'credit_card',
                        'expiry_date': expiry_date.strftime('%B %Y')
                    })

            # Check identities
            identities = self.VaultItem.query.filter_by(user_id=user_id, type='identity').all()
            for identity in identities:
                identity_data = json.loads(identity.data)
                if identity_data.get('expiry_date'):
                    expiry_date = datetime.strptime(identity_data['expiry_date'], '%Y-%m-%d')
                    if self._is_expiring_soon(expiry_date, warning_threshold):
                        expiring_items.append({
                            'title': identity.title,
                            'type': 'identity',
                            'expiry_date': expiry_date.strftime('%B %d, %Y')
                        })
                        
        except Exception as e:
            print(f"Error checking expiring items: {str(e)}")
            
        return expiring_items
    
    def _is_expiring_soon(self, expiry_date, threshold):
        if not expiry_date:
            return False
        today = datetime.now()
        return expiry_date - today <= threshold and expiry_date > today