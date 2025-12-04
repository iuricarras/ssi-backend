from flask_mail import Mail, Message
from flask import Flask
from typing import Dict

class EmailService:
    """
    Serviço dedicado para enviar emails.
    """
    def __init__(self, mail_service: Mail, config: Dict):
        self.mail_service = mail_service
        self.config = config

    def send_notification_email(self, recipient_email: str, subject: str, content_html: str) -> bool:
        """
        Envia um email genérico de notificação.
        """
        try:
            sender_email = self.config["MAIL_DEFAULT_SENDER"]
            
            msg = Message(
                subject=subject,
                recipients=[recipient_email],
                sender=sender_email,
                reply_to="no-reply@bitsofme.pt"
            )
            msg.html = content_html
            self.mail_service.send(msg)
            return True
        except Exception as e:
            # Em ambiente real, registar o erro no servidor.
            print(f"Erro ao enviar email de notificação para {recipient_email}: {e}")
            return False

    #TODO: Deixar a mensagem de email mais bonita.
    def create_new_request_html(self, user_name: str, requester_name: str, request_type: str) -> str:
        """
        Cria o conteúdo HTML para notificação de nova requisição.
        """
        # Usar um template HTML simples, semelhante ao OTP, mas com foco na notificação.
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: sans-serif; background-color: #f8f9fa; line-height: 1.6; }}
                .container {{ background-color: #ffffff; max-width: 500px; margin: 0px auto; border-radius: 12px; border: 1px solid #e0e0e0; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05); }}
                .header {{ text-align: center; background-color: #295CEA; color: white; padding: 10px; border-radius: 12px 12px 0 0; font-size: 20px; font-weight: 600; }}
                .content {{ padding: 20px; color: #333; font-size: 16px; text-align: left; }}
                .alert {{ background-color: #ffe0b2; color: #e65100; padding: 10px; border-radius: 8px; text-align: center; margin-bottom: 20px; font-weight: 600; }}
                .footer {{ font-size: 13px; color: #888; text-align: center; padding: 10px 20px; border-top: 1px solid #e0e0e0; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>BitsOfMe - Nova Requisição Pendente</h2>
                </div>
                
                <div class="content">
                    <p>Olá, **{user_name}**!</p>
                    <p>**{requester_name}** submeteu uma nova requisição para a sua carteira digital (**{request_type}**).</p>
                    
                    <div class="alert">
                        É necessária a sua ação.
                    </div>

                    <p>Por favor, aceda à sua **área de notificações** na plataforma BitsOfMe para rever e responder a esta requisição.</p>
                    
                    <p>Mantenha o controlo sobre os seus dados!</p>
                    
                    <p>Atenciosamente,<br>A sua Equipa BitsOfMe</p>
                </div>
                <div class="footer">
                    <p>Esta é uma mensagem automática. Por favor, não responda a este e-mail.</p>
                </div>
            </div>
        </body>
        </html>
        """
        return html_template.replace('{user_name}', user_name).replace('{requester_name}', requester_name).replace('{request_type}', request_type)