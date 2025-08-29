# Azure Function - Web API WhatsApp

This Azure Function app exposes several HTTP endpoints used by the chatbot system.

Endpoints
---------

1) `POST /login`
- Description: Simple login endpoint for testing.
- Body (JSON):
  - `username` (string)
  - `password` (string)
- Responses:
  - 200: "Login successful"
  - 401: "Login failed"

Sample responses:

Success (200):
```json
"Login successful"
```

Failure (401):
```json
"Login failed"
```

2) `POST /conversation-mode`
- Description: Cambia el modo de conversación (bot/agente) para un lead específico.
- Body (JSON):
  - `wa_id` (string) - identificador del lead (sin el prefijo `conv_`)
  - `mode` (string) - "bot" o "agente"
- Responses:
  - 200: JSON with success message and timestamp
  - 400: Missing/invalid parameters
  - 404: Conversation not found
  - 500: Internal server error

Sample success response (200):
```json
{
  "success": true,
  "message": "Conversation mode updated successfully",
  "new_mode": "agente",
  "timestamp": "2025-08-28T12:34:56Z"
}
```

3) `POST /send-agent-message`
- Description: Envía un mensaje del agente al lead invocando la función del chatbot.
- Body (JSON):
  - `wa_id` (string)
  - `message` (string)
- Responses:
  - 200: JSON confirming message was sent
  - 400: Missing parameters
  - 500: Error communicating with chatbot

Sample success response (200):
```json
{
  "success": true,
  "message": "Agent message sent successfully",
  "wa_id": "lead_98765",
  "message_sent": "Hola, te contacto desde soporte",
  "conversation_mode": "agente",
  "timestamp": "2025-08-28T12:35:00Z"
}
```

4) `POST /get-conversation`
- Description: Obtiene el estado completo de una conversación. Es de tipo POST y recibe `wa_id` en el body JSON.
- Body (JSON):
  - `wa_id` (string) - identificador del lead (sin el prefijo `conv_`)
- Responses:
  - 200: JSON with conversation details
  - 400: Missing `wa_id` or invalid JSON
  - 404: Conversation not found
  - 500: Internal server error

Sample success response (200):
```json
{
  "wa_id": "lead_98765",
  "conversation_mode": "bot",
  "lead_info": {
    "nombre": "María García López",
    "telefono": "521234567890"
  },
  "messages": [
    {
      "from": "user",
      "text": "Hola",
      "ts": "2025-08-24T18:00:00Z"
    }
  ],
  "completed": false,
  "updated_at": "2025-08-24T18:15:00Z"
}
```

5) `GET /conversations/recent`
- Description: Devuelve las últimas 10 conversaciones ordenadas por `updated_at` desc.
- Responses:
  - 200: JSON array, donde cada elemento tiene la siguiente forma:
    ```json
    {
      "id": "conv_12345",
      "lead_id": "lead_98765",
      "canal": "whatsapp",
      "created_at": "2025-08-24T18:00:00Z",
      "updated_at": "2025-08-24T18:15:00Z",
      "state": {
        "nombre": "María",
        "nombre_completo": "María García López",
        "telefono": "521234567890",
        "completed": false
      },
      "conversation_mode": "agente",
      "asignado_asesor": "asesor_ventas_001"
    }
    ```
  - 500: Internal server error
```

Notes
-----
- Cosmos DB connection is currently hard-coded for local testing in `get_cosmos_container()`; replace with environment variables `COSMOS_CONNECTION_STRING`, `COSMOS_DB_NAME`, and `COSMOS_CONTAINER_NAME` for production.
- The `send-agent-message` function currently uses a hard-coded chatbot URL — switch to environment configuration before deploying.

How to run locally
-------------------
- Install Python requirements from `requirements.txt` into your venv.
- Start the Functions host (VS Code task included): `func host start`.
- Use `test.http` or curl to exercise the endpoints.

