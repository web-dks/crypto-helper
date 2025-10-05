## Crypto Helper (WhatsApp Flows)

Microserviço Node.js para decriptar a requisição de Flows (RSA-OAEP + AES-CBC) e reencriptar a resposta no formato esperado.

### Requisitos
- Node.js 18+ (recomendado 18.17+)

### Configuração local
1. Crie um arquivo `.env` e defina `WHATSAPP_RSA_PRIVATE_KEY` com a sua chave privada RSA (PEM). Se estiver em uma única linha, substitua quebras por `\\n`.
   Exemplo:

```bash
PORT=3000
WHATSAPP_RSA_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----"
```

2. Instale dependências:

```bash
npm install
```

3. Inicie em desenvolvimento:

```bash
npm run dev
```

4. Verifique o healthcheck:

```bash
curl http://localhost:3000/health
```

### Endpoints
- `POST /flows-crypto`: recebe `encrypted_flow_data`, `encrypted_aes_key`, `initial_vector` (base64) e, opcionalmente, `reply` (JSON a ser ecoado criptografado).
- `GET /health`: simples verificação de status.

### Deploy no Render
1. Crie um novo Web Service apontando para este repositório.
2. Build Command: (vazio) — não é necessário build.
3. Start Command:

```bash
npm start
```

4. Adicione a variável `WHATSAPP_RSA_PRIVATE_KEY` em Environment → Add Secret.
   - Você pode colar o PEM completo (com múltiplas linhas) ou uma versão com `\n`.

### Notas
- O serviço tenta detectar `\n` no secret e convertê-los para quebras reais antes de usar a chave.
- O algoritmo AES é escolhido conforme o tamanho da chave de sessão decriptada: 16 bytes → `aes-128-cbc`, caso contrário `aes-256-cbc`.


