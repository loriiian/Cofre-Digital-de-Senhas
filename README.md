# Cofre Digital de Senhas
# Sobre o Projeto
O Cofre Digital de Senhas é uma aplicação web segura, desenvolvida com Flask, projetada para armazenar, gerir e proteger as credenciais dos usuários. O projeto foi construído com um forte foco em segurança, usabilidade e funcionalidades avançadas como importação e exportação de senhas, medidor de segurança de senha e gerador de senha segura.
# Principais Funcionalidades
- Armazenamento Seguro:
    As senhas são encriptadas individualmente por usuário usando o algoritmo AES.
- Recuperação de Conta: 
    Fluxo seguro para redefinição de senha através da verificação da pergunta de segurança.
- Gerador de Senhas:
    Ferramenta integrada para criar senhas fortes e personalizáveis.
- Medidor de Força da Senha:
    Análise em tempo real da força da senha que está a ser criada.
- Copiar com Um Clique:
    Copie facilmente nomes de usuário e senhas para a área de transferência.
- Importação e Exportação:
    Crie backups criptografados das suas senhas e importe-os quando necessário.
- Interface Moderna:
    Tema dark mode com uma barra de navegação lateral e identificação visual dos serviços com os seus logos.
# Tecnologias Utilizadas
# Backend:
- Python
- Flask
- Flask-SQLAlchemy: ORM para interação com o banco de dados.
- Flask-Login: Gestão de sessões de usuário.
- Flask-Bcrypt: Hashing de senhas e respostas de segurança.
- Flask-WTF: Criação de formulários e proteção CSRF.
- Cryptography: Para criptografia AES das senhas guardadas.

# Frontend:
- HTML5
- CSS3
- JavaScript
- Jinja2: Motor de templates para o Flask.
- Banco de Dados: SQLite

# Como Executar o Projeto
Pré-requisitos:

- Python

- pip

# Passos de Instalação

- Crie e ative um ambiente virtual:
Para Windows:
    python -m venv venv
    .\venv\Scripts\activate

Para macOS/Linux:
    python3 -m venv venv
    source venv/bin/activate


- Instale as dependências:
    pip install -r requirements.txt


- Crie o banco de dados:
    Abra um terminal Python na pasta raiz do projeto e execute os seguintes comandos:
from app import app, db

app.app_context().push()

db.create_all()

exit()


- Execute a aplicação:
python run.py


- Acesse a aplicação:
Abra o seu navegador e vá para http://127.0.0.1:5000.
