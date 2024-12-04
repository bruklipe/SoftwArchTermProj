from abc import ABC, abstractmethod
from flask import flash
from datetime import datetime
from patterns.builder import PasswordBuilder

class UIMediator:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(UIMediator, cls).__new__(cls)
            cls._instance._components = {}
        return cls._instance
    
    def register_component(self, name, component):
        self._components[name] = component
        component.mediator = self
    
    def notify(self, sender, event, data=None):
        if event == "alert_dismissed":
            self._components["alert_manager"].dismiss_alert(data)
        elif event == "data_copied":
            self._components["clipboard_manager"].copy_to_clipboard(data)
        elif event == "data_masked":
            self._components["data_masker"].toggle_mask(data)
        elif event == "flash_message":
            self._components["notification_manager"].show_flash(data)
        elif event == "generate_password":
            self._components["password_generator"].generate_password(data)
        elif event == "password_generated":
            if data.get("success"):
                self._components["notification_manager"].show_flash({
                    "message": "Password generated successfully",
                    "category": "success"
                })
            else:
                self._components["notification_manager"].show_flash({
                    "message": f"Error generating password: {data.get('error')}",
                    "category": "error"
                })

class UIComponent(ABC):
    def __init__(self):
        self.mediator = None
    
    @abstractmethod
    def receive(self, event, data=None):
        pass

class AlertManager(UIComponent):
    def receive(self, event, data=None):
        if event == "alert_dismissed":
            self.dismiss_alert(data)
    
    def dismiss_alert(self, alert_id):
        # Logic to dismiss alert
        self.mediator.notify(self, "flash_message", {
            "message": "Alert dismissed",
            "category": "success"
        })

class ClipboardManager(UIComponent):
    def receive(self, event, data=None):
        if event == "data_copied":
            self.copy_to_clipboard(data)
    
    def copy_to_clipboard(self, data):
        # Logic to copy data
        self.mediator.notify(self, "flash_message", {
            "message": "Data copied to clipboard",
            "category": "info"
        })

class DataMasker(UIComponent):
    def receive(self, event, data=None):
        if event == "data_masked":
            self.toggle_mask(data)
    
    def toggle_mask(self, data):
        element_id = data.get('elementId')
        current_type = data.get('currentType')
        
        # Toggle password visibility
        new_type = 'text' if current_type == 'password' else 'password'
        
        self.mediator.notify(self, "mask_toggled", {
            "elementId": element_id,
            "newType": new_type,
            "buttonText": "Hide" if new_type == 'text' else "Show"
        })

class NotificationManager(UIComponent):
    def receive(self, event, data=None):
        if event == "flash_message":
            self.show_flash(data)
    
    def show_flash(self, data):
        flash(data["message"], data["category"])

class PasswordGenerator(UIComponent):
    def receive(self, event, data=None):
        if event == "generate_password":
            self.generate_password(data)
    
    def generate_password(self, options):
        try:
            builder = PasswordBuilder()
            
            if options.get('length'):
                builder.set_length(options['length'])
            if options.get('uppercase'):
                builder.include_uppercase()
            if options.get('lowercase'):
                builder.include_lowercase()
            if options.get('numbers'):
                builder.include_numbers()
            if options.get('symbols'):
                builder.include_symbols()
                
            password = builder.build()
            self.mediator.notify(self, "password_generated", {
                "success": True,
                "password": password
            })
        except Exception as e:
            self.mediator.notify(self, "password_generated", {
                "success": False,
                "error": str(e)
            }) 