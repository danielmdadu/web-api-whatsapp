# Azure Function - Web API WhatsApp

This Azure Function app exposes several HTTP endpoints used by the chatbot system.

Variables de entorno
---------

```python
# AI BOT AZURE FUNTION
AIBOT_FUNCTION_URL

# AUTH
LOGIN_USER
LOGIN_PASSWORD
JWT_SECRET

# COSMOS
COSMOS_CONNECTION_STRING
COSMOS_DB_NAME
COSMOS_CONTAINER_NAME
```

Endpoints
---------

1) `POST /login`
- Description: Simple login endpoint for testing.
- Body (JSON):
  - `username` (string)
  - `password` (string)
- Responses:
  - 200: JSON with a signed JWT access token
  - 401: "Login failed"

Sample responses:

Success (200):
```json
{
  "message": "Login successful",
  "access_token": "<JWT_TOKEN_HERE>",
  "token_type": "Bearer",
  "expires_in": 28800
}
```

Failure (401):
```json
"Login failed"
```

---

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

---

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

---

4) `GET /leads/recent`
- Description: Devuelve las últimas 10 conversaciones ordenadas por `updated_at` desc e indica si hay más conversaciones en la base de datos con el campo `has_more`.
- Responses:
  - 200: JSON array con una estructura como esta:
    ```json
    {
      "conversations": [
        {
          "id": "conv_12345",
          "lead_id": "lead_98765",
          "canal": "whatsapp",
          "created_at": "2025-08-24T18:00:00Z",
          "updated_at": "2025-08-24T18:15:00Z",
          "state": {
            "nombre": "María García López",
            "telefono": "521234567890",
            "completed": false
          },
          "conversation_mode": "bot",
          "asignado_asesor": "asesor_ventas_001"
        }
      ],
      "has_more": true
    }
    ```
  - 500: Internal server error

---

5) `POST /get-conversation`
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
      "id": "msg_2",
      "sender": "bot",
      "text": "Para brindarte una atención personalizada, ¿podrías decirme tu nombre? Así podré ayudarte mejor con lo que necesitas.",
      "timestamp": "2025-08-29T03:09:47Z",
      "delivered": true,
      "read": false
    },
  ],
  "completed": false,
  "updated_at": "2025-08-24T18:15:00Z"
}
```

---

6) `POST /get-recent-messages`
- Description: Devuelve los últimos mensajes de una conversación específica. Endpoint usado por el polling de la aplicación. Es de tipo POST para permitir enviar en el body JSON `wa_id` y `last_message_id`.
- Body (JSON):
  - `wa_id` (string) - identificador del lead (sin el prefijo `conv_`)
  - `last_message_id` (string) - id del último mensaje que el cliente ya tiene (opcional, si se envía, la respuesta contendrá solo mensajes posteriores)
- Responses:
  - 200: JSON con `conversation_id`, `conversation_mode`, `state` y `messages` (solo los mensajes nuevos desde `last_message_id`)
  - 400: Falta de parámetros o JSON inválido
  - 401: Unauthorized (token JWT faltante, inválido o expirado)
  - 404: Conversación no encontrada
  - 500: Error interno del servidor

Ejemplo de respuesta de éxito (200):
```json
{
  "wa_id": "lead_98765",
  "conversation_mode": "bot",
  "lead_info": {
    "nombre": "María",
    "telefono": "521234567890",
  },
  "messages": [
    {
      "id": "msg_1690000000_1",
      "sender": "lead",
      "text": "Hola otra vez",
      "timestamp": "2025-08-28T12:40:00Z",
      "delivered": true,
      "read": false
    }
  ],
  "completed": false,
  "updated_at": "2025-08-24T18:15:00Z"
}
```

---

7) `POST /next-conversations`
- Description: Devuelve las siguientes 10 conversaciones más recientes después de los IDs proporcionados. Recibe una lista de IDs de conversaciones y devuelve las siguientes 10 basándose en updated_at. Es de tipo POST y recibe `conversation_ids` en el body JSON.
- Body (JSON):
  - `conversation_ids` (array of strings) - lista de IDs de conversaciones
- Responses:
  - 200: JSON with conversation details
  - 400: Missing `conversation_ids` or invalid JSON
  - 404: Conversation not found
  - 500: Internal server error

Sample success response (200):
```json
{
  "conversations": [
    {
      "id": "conv_12345",
      "lead_id": "lead_98765",
      "canal": "whatsapp",
      "created_at": "2025-08-24T18:00:00Z",
      "updated_at": "2025-08-24T18:15:00Z",
      "state": {
        "nombre": "María García López",
        "telefono": "521234567890",
        "completed": false
      },
      "conversation_mode": "bot",
      "asignado_asesor": "asesor_ventas_001"
    }
  ],
  "has_more": true
}
```

Notes
-----
- La conexión a Cosmos DB actualmente está configurada para pruebas locales en `get_cosmos_container()`; reemplázala por las variables de entorno `COSMOS_CONNECTION_STRING`, `COSMOS_DB_NAME` y `COSMOS_CONTAINER_NAME` para producción.
- La función `send-agent-message` actualmente usa una URL de chatbot codificada — cámbiala por una configuración a través de variables de entorno antes de desplegar.
- Autenticación: la Function App ahora emite un JWT al iniciar sesión con éxito. La secret del JWT debe configurarse en App Settings como `JWT_SECRET`.

Autenticación / notas de uso
---------------------------
- Tras un `POST /login` exitoso, la respuesta contiene `access_token` (un JWT). El frontend debe almacenar ese token (por ejemplo en `localStorage`) y enviarlo en las peticiones siguientes en el header `Authorization` así:

```
Authorization: Bearer <token>
```

Ejemplo de uso en cliente (browser JS):

```js
// Tras recibir la respuesta del login en `data`
localStorage.setItem('access_token', data.access_token);

// Más tarde, enviando una petición protegida
fetch('/conversation-mode', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + localStorage.getItem('access_token')
  },
  body: JSON.stringify({ wa_id: 'lead_123', mode: 'agente' })
});
```

Si el JWT falta, es inválido o ha expirado, los endpoints protegidos devolverán 401 Unauthorized.

Cómo ejecutar localmente
-----------------------
- Instala los requisitos de Python listados en `requirements.txt` dentro de tu entorno virtual.
- Inicia el host de Functions (hay una tarea de VS Code incluida): `func host start`.
- Usa `test.http` o `curl` para probar los endpoints.