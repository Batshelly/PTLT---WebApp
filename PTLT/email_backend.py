from django.core.mail.backends.base import BaseEmailBackend
import resend
import os


class ResendEmailBackend(BaseEmailBackend):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        resend.api_key = os.environ.get('RESEND_API_KEY', '')
    
    def send_messages(self, email_messages):
        if not email_messages:
            return 0
        
        num_sent = 0
        for message in email_messages:
            try:
                params = {
                    "from": message.from_email,  # ← CHANGED: Use from_email from settings
                    "to": message.to,
                    "subject": message.subject,
                    "reply_to": "tupcptlt@gmail.com",  # Your actual email for replies
                }
                
                # Handle HTML vs plain text
                if hasattr(message, 'content_subtype') and message.content_subtype == 'html':
                    params["html"] = message.body
                else:
                    params["text"] = message.body
                
                resend.Emails.send(params)
                num_sent += 1
            except Exception as e:
                print(f"Resend error: {e}")
                if not self.fail_silently:
                    raise
        
        return num_sent
