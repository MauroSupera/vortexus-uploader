# Site de Upload de Arquivos

Um site simples para fazer upload de arquivos e obter links para compartilhamento, com uma área administrativa para gerenciar os arquivos enviados.

## Funcionalidades

- Upload de arquivos com geração automática de links
- Links com extensão do arquivo original preservada
- Área administrativa para:
  - Visualizar todos os arquivos enviados
  - Copiar URLs dos arquivos
  - Visualizar os arquivos
  - Excluir arquivos

## Como usar

### Instalação

1. Instale as dependências:
```
pip install -r requirements.txt
```

2. Execute a aplicação:
```
python app.py
```

3. Acesse o site em seu navegador:
```
http://localhost:5000
```

### Área de Upload

- Na página inicial, clique em "Escolher arquivo" para selecionar um arquivo
- Clique em "Enviar" para fazer o upload
- Após o upload, você receberá um link para o arquivo

### Área Administrativa

- Acesse a área administrativa através do link na página inicial
- Credenciais padrão:
  - Usuário: admin
  - Senha: admin123
- Na área administrativa você pode:
  - Ver todos os arquivos enviados
  - Copiar os links dos arquivos
  - Visualizar os arquivos
  - Excluir arquivos

## Segurança

**Importante:** Para uso em produção, altere as seguintes configurações no arquivo `app.py`:
- Mude a `SECRET_KEY` para uma chave segura
- Altere o nome de usuário e senha administrativos (`ADMIN_USERNAME` e `ADMIN_PASSWORD`)
- Considere implementar um banco de dados para armazenar informações dos arquivos
- Implemente controle de sessão adequado

## Estrutura do Projeto

- `app.py` - Arquivo principal da aplicação Flask
- `templates/` - Contém os arquivos HTML
- `static/css/` - Contém os arquivos CSS
- `uploads/` - Diretório onde os arquivos enviados são armazenados
