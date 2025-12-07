from flask_mail import Mail, Message
from typing import Dict
import os

class EmailService:
    """
    Serviço dedicado para enviar emails.
    """
    def __init__(self, mail_service: Mail, config: Dict):
        self.mail_service = mail_service
        self.config = config

        # Caminho base: pasta onde este ficheiro EmailService.py está
        base_dir = os.path.dirname(os.path.abspath(__file__))

        # Caminho completo para /email/template_email.html
        self.template_path = os.path.join(base_dir, "email", "template_email.html")

    def _load_template(self) -> str:
        """
        Carrega o template HTML do email.
        """
        try:
            with open(self.template_path, "r", encoding="utf-8") as file:
                return file.read()
        except Exception as e:
            print(f"Erro ao carregar template de email: {e}")
            return ""

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
            print(f"Erro ao enviar email de notificação para {recipient_email}: {e}")
            return False

    def create_new_request_html(self, user_name: str, requester_name: str, request_type: str) -> str:
        """
        Cria o conteúdo HTML para notificação de nova requisição.
<<<<<<< Updated upstream
        Lê o template e substitui os placeholders.
=======
        O request_type já inclui a informação se é certificado ou verificação.
>>>>>>> Stashed changes
        """
        html = self._load_template()

<<<<<<< Updated upstream
        if not html:
            return ""

        return (
            html
            .replace("{user_name}", user_name)
            .replace("{requester_name}", requester_name)
            .replace("{request_type}", request_type)
        )
=======
                    <p>Por favor, aceda à sua **área de notificações** na plataforma BitsOfMe para rever e responder a esta requisição.</p>
                    
                    <p>Mantenha o controlo sobre os seus dados!</p>
                    
                    <p>Atenciosamente,<br>A sua Equipa BitsOfMe</p>
                </div>
                <div class="footer">
                    <p>Esta é uma mensagem automÃ¡tica. Por favor, nÃ£o responda a este e-mail.</p>
                </div>
            </div>
        </body>
        </html>
        """
        return html_template.replace('{user_name}', user_name).replace('{requester_name}', requester_name).replace('{request_type}', request_type)
>>>>>>> Stashed changes
