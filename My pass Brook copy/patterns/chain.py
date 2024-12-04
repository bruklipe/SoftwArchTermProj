class PasswordRecoveryChain:
    def __init__(self):
        self.handlers = []
    
    def add_handler(self, handler):
        self.handlers.append(handler)
    
    def process_recovery(self, user, answers):
        for handler in self.handlers:
            if not handler.handle(user, answers):
                return False
        return True

class SecurityQuestionHandler:
    def __init__(self, question_number):
        self.question_number = question_number
    
    def handle(self, user, answers):
        user_answer = getattr(user, f'security_answer{self.question_number}')
        provided_answer = answers.get(f'question{self.question_number}')
        return user_answer.lower() == provided_answer.lower() 