import azure.functions as func
import logging
import json
import os
import requests
from datetime import datetime, timezone, timedelta
from azure.cosmos import CosmosClient
import jwt

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="login")
def login(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    """
    Handles login request.
    """
    logging.info("login - Start")
    body = req.get_json()
    if not body:
        return func.HttpResponse("Invalid JSON", status_code=400)

    if body.get("username") == os.environ["LOGIN_USER"] and body.get("password") == os.environ["LOGIN_PASSWORD"]:
        # Create JWT
        secret = os.environ["JWT_SECRET"]
        if not secret:
            logging.error("JWT_SECRET not configured in app settings")
            return func.HttpResponse("Server misconfiguration", status_code=500)

        now = datetime.now(timezone.utc)
        payload = {
            "sub": body.get("username"),
            "iat": int(now.timestamp()),
            # token expires in 8 hours
            "exp": int((now + timedelta(hours=8)).timestamp())
        }

        token = jwt.encode(payload, secret, algorithm="HS256")

        response = {
            "message": "Login successful",
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 8 * 3600
        }

        return func.HttpResponse(json.dumps(response), status_code=200, mimetype="application/json")
    else:
        return func.HttpResponse("Login failed", status_code=401)

@app.route(route="conversation-mode", methods=["POST"])
def conversation_mode(req: func.HttpRequest) -> func.HttpResponse:
    """
    Cambia el modo de conversación (bot/agente) para un lead específico.
    """
    logging.info('conversation-mode endpoint called')
    
    try:
        # Verify JWT from Authorization header
        auth_header = req.headers.get('Authorization') or req.headers.get('authorization')
        if not verify_bearer_token(auth_header):
            return func.HttpResponse('Unauthorized', status_code=401)

        body = req.get_json()
        if not body:
            return func.HttpResponse("Invalid JSON", status_code=400)
        
        wa_id = body.get("wa_id")
        mode = body.get("mode")
        
        if not wa_id or not mode:
            return func.HttpResponse("Missing wa_id or mode", status_code=400)
        
        if mode not in ["bot", "agente"]:
            return func.HttpResponse("Invalid mode. Must be 'bot' or 'agente'", status_code=400)
        
        # Obtener estado actual primero
        current_conversation = get_conversation_state(wa_id)
        if not current_conversation:
            return func.HttpResponse("Conversation not found", status_code=404)
        
        # Actualizar modo via Cosmos DB
        success = update_conversation_mode(wa_id, mode)

        if success:

            if mode == "bot":
                startbot_url = os.environ["STARTBOT_FUNCTION_URL"]

                if not startbot_url:
                    return func.HttpResponse("Startbot function URL not configured", status_code=500)

                response = requests.post(startbot_url, json={
                    "wa_id": wa_id
                })
                
                if response.status_code != 200:
                    return func.HttpResponse("Failed to start bot", status_code=500)

                logging.info(f"Bot started successfully for wa_id: {wa_id}")

            response_data = {
                "success": True,
                "message": "Conversation mode updated successfully",
                "new_mode": mode,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            }
            return func.HttpResponse(json.dumps(response_data), status_code=200, mimetype="application/json")
        else:
            return func.HttpResponse("Failed to update conversation mode", status_code=500)
            
    except Exception as e:
        logging.error(f"Error in conversation-mode endpoint: {e}")
        return func.HttpResponse("Internal server error", status_code=500)

def get_cosmos_container():
    """
    Inicializa y retorna el container de Cosmos DB.
    Usa las mismas variables de entorno que la Azure Function principal.
    """
    try:
        cosmos_client = CosmosClient.from_connection_string(os.environ["COSMOS_CONNECTION_STRING"])
        db_name = os.environ["COSMOS_DB_NAME"]
        container_name = os.environ["COSMOS_CONTAINER_NAME"]

        container = cosmos_client.get_database_client(db_name).get_container_client(container_name)
        return container
        
    except Exception as e:
        logging.error(f"Error conectando a Cosmos DB: {e}")
        raise

def save_message_in_db(wa_id: str, message: str, whatsapp_message_id: str, multimedia: str = None) -> bool:
    """
    Guarda un mensaje en la base de datos de Cosmos DB.
    NO guarda todo el estado de la conversación.
    Solo guarda el mensaje actual al final de la lista de mensajes
    """
    try:
        container = get_cosmos_container()

        now = datetime.now(timezone.utc)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        message_id = f"msg_{int(now.timestamp())}_1"  # Simple ID basado en timestamp

        # Crear el nuevo mensaje del agente
        new_message = {
            "id": message_id,
            "whatsapp_message_id": whatsapp_message_id,
            "sender": "agente",
            "text": message,
            "timestamp": now_str,
            "delivered": True,
            "read": False,
            "multimedia": multimedia
        }
        
        # Usar patch operations para agregar el mensaje y actualizar updated_at
        # Esto es más eficiente que cargar todo el documento
        patch_ops = [
            {
                "op": "add",
                "path": "/messages/-",
                "value": new_message
            },
            {
                "op": "replace",
                "path": "/updated_at",
                "value": now_str
            }
        ]
        
        # Ejecutar patch operation
        container.patch_item(
            item=f"conv_{wa_id}",
            partition_key=wa_id,
            patch_operations=patch_ops
        )
        
        logging.info(f"Mensaje de agente guardado exitosamente para wa_id: {wa_id}")
        return message_id
        
    except Exception as e:
        logging.error(f"Error guardando mensaje de agente en DB para wa_id {wa_id}: {e}")
        return None

@app.route(route="send-agent-message", methods=["POST"])
def send_agent_message(req: func.HttpRequest) -> func.HttpResponse:
    """
    Envía un mensaje del agente al lead a través del chatbot Azure Function.
    Guarda el mensaje en la base de datos.
    También se puede usar para enviar un mensaje de plantilla de WhatsApp, pasando el "template_name".
    """
    logging.info('send-agent-message endpoint called')
    
    try:
        # Verify JWT
        auth_header = req.headers.get('Authorization') or req.headers.get('authorization')
        if not verify_bearer_token(auth_header):
            return func.HttpResponse('Unauthorized', status_code=401)

        body = req.get_json()
        if not body:
            return func.HttpResponse("Invalid JSON", status_code=400)
        
        wa_id = body.get("wa_id")
        message = body.get("message")

        # Check if has "template_name"
        template_name = body.get("template_name")

        # Check if has "multimedia"
        multimedia = body.get("multimedia")

        if not wa_id:
            return func.HttpResponse("Missing wa_id", status_code=400)
        
        # Llamar al endpoint agent-message del chatbot Azure Function
        chatbot_url = os.environ["AIBOT_FUNCTION_URL"]

        if not chatbot_url:
            return func.HttpResponse("Chatbot function URL not configured", status_code=500)

        payload = {
            "wa_id": wa_id,
            "message": message
        }
        if multimedia:
            payload["multimedia"] = multimedia
        elif template_name:
            payload["template_name"] = template_name

        logging.info(f"Payload: {payload}")
        response = requests.post(
            chatbot_url,
            json=payload,
            timeout=30
        )
        
        logging.info(f"Response from chatbot function: {response.text}")
        if response.status_code == 200:
            # Acceder al valor de whatsapp_message_id
            whatsapp_message_id = response.text

            message_id = None

            # Los mensajes de plantilla tienen el formato: whatsapp_message_id___message
            if template_name:
                whatsapp_message_id, message = whatsapp_message_id.split("___")
                message = "PLANTILLA: " + message
            # Guardar el mensaje en la base de datos
            message_id = save_message_in_db(wa_id, message, whatsapp_message_id, multimedia)

            response_data = {
                "success": True,
                "message": message,
                "wa_id": wa_id,
                "message_id_sent": message_id,
                "conversation_mode": "agente",
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            }

            return func.HttpResponse(json.dumps(response_data), status_code=200, mimetype="application/json")
        else:
            logging.error(f"Chatbot function returned error: {response.status_code} - {response.text}")
            return func.HttpResponse("Failed to send agent message", status_code=500)
            
    except requests.RequestException as e:
        logging.error(f"Error calling chatbot function: {e}")
        return func.HttpResponse("Error communicating with chatbot service", status_code=500)
    except Exception as e:
        logging.error(f"Error in send-agent-message endpoint: {e}")
        return func.HttpResponse("Internal server error", status_code=500)

def extract_token_from_header(auth_header: str) -> str:
    """Extracts the token string from an Authorization header of the form 'Bearer <token>'"""
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == 'bearer':
        return parts[1]
    return None

def verify_bearer_token(auth_header: str) -> bool:
    """Verifies the JWT using the secret in env var JWT_SECRET. Returns True if valid."""
    token = extract_token_from_header(auth_header)
    if not token:
        logging.warning('No bearer token provided')
        return False

    secret = os.environ['JWT_SECRET']
    if not secret:
        logging.error('JWT_SECRET not configured')
        return False

    try:
        decoded = jwt.decode(token, secret, algorithms=["HS256"])
        logging.debug(f"JWT valid for subject: {decoded.get('sub')}")
        return True
    except jwt.ExpiredSignatureError:
        logging.warning('JWT expired')
        return False
    except jwt.InvalidTokenError as e:
        logging.warning(f'Invalid JWT: {e}')
        return False

def get_conversation_state(wa_id: str) -> dict:
    """
    Obtiene el estado de conversación desde Cosmos DB.
    """
    try:
        container = get_cosmos_container()
        
        # Buscar el documento por wa_id (mismo formato que state_management.py)
        response = container.read_item(item=f"conv_{wa_id}", partition_key=wa_id)
        logging.info(f"Conversación encontrada para wa_id: {wa_id}")
        
        return response
        
    except Exception as e:
        if "Not Found" in str(e):
            logging.info(f"Conversación no encontrada para wa_id: {wa_id}")
            return None
        else:
            logging.error(f"Error obteniendo estado de conversación: {e}")
            return None

def update_conversation_mode(wa_id: str, mode: str) -> bool:
    """
    Actualiza el modo de conversación en Cosmos DB usando patch operations.
    """
    try:
        container = get_cosmos_container()
        
        # Usar patch operation para actualizar solo el campo conversation_mode
        patch_ops = [
            {
                "op": "replace",
                "path": "/conversation_mode",
                "value": mode
            },
            {
                "op": "replace",
                "path": "/updated_at",
                "value": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            }
        ]
        
        container.patch_item(
            item=f"conv_{wa_id}",
            partition_key=wa_id,
            patch_operations=patch_ops
        )
        
        logging.info(f"Modo de conversación actualizado a '{mode}' para wa_id: {wa_id}")
        return True
        
    except Exception as e:
        if "Not Found" in str(e):
            logging.error(f"Conversación no encontrada para actualizar modo: {wa_id}")
        else:
            logging.error(f"Error actualizando modo de conversación: {e}")
        return False

@app.route(route="leads/recent", methods=["GET"])
def get_recent_leads(req: func.HttpRequest) -> func.HttpResponse:
    """
    Devuelve las últimas 10 conversaciones ordenadas por `updated_at` (desc).
    Formato de salida similar al pedido en la descripción del ticket.
    """
    logging.info('get-recent-leads endpoint called')

    try:
        # Verify JWT
        auth_header = req.headers.get('Authorization') or req.headers.get('authorization')
        if not verify_bearer_token(auth_header):
            return func.HttpResponse('Unauthorized', status_code=401)
            
        container = get_cosmos_container()

        # Query para obtener las últimas 11 conversaciones por updated_at descendente
        query = (
            "SELECT TOP 11 c.id, c.lead_id, c.canal, c.created_at, c.updated_at, "
            "c.state, c.conversation_mode, c.asignado_asesor FROM c ORDER BY c.updated_at DESC"
        )

        items_iterable = container.query_items(
            query=query,
            enable_cross_partition_query=True
        )

        # materializar resultados en lista
        items = list(items_iterable)

        # Verificar si hay más conversaciones
        has_more = False
        if len(items) == 11:
            has_more = True

        # Tomar solo las primeras 10 conversaciones
        items = items[:10]

        # Asegurar que cada item tenga las claves esperadas y formatear si es necesario
        results = []
        for it in items:
            raw_state = it.get("state", {}) or {}
            # Keep only the four requested fields in the state
            trimmed_state = {
                "nombre": raw_state.get("nombre", ""),
                "telefono": raw_state.get("telefono", ""),
                "completed": raw_state.get("completed", False)
            }

            formatted = {
                "id": it.get("id"),
                "lead_id": it.get("lead_id"),
                "canal": it.get("canal", ""),
                "created_at": it.get("created_at", ""),
                "updated_at": it.get("updated_at", ""),
                "state": trimmed_state,
                "conversation_mode": it.get("conversation_mode", "bot"),
                "asignado_asesor": it.get("asignado_asesor", "")
            }
            results.append(formatted)

        response_data = {
            "conversations": results,
            "has_more": has_more
        }

        return func.HttpResponse(json.dumps(response_data, ensure_ascii=False), status_code=200, mimetype="application/json")

    except Exception as e:
        logging.error(f"Error in get-recent-conversations endpoint: {e}")
        return func.HttpResponse("Internal server error", status_code=500)

def format_conversation_response(conversation_data: dict, messages: list = None) -> dict:
    """
    Formatea los datos de conversación al formato requerido.
    """
    logging.info(f"conversation_data: {conversation_data}")
    state = conversation_data.get("state", {})

    if messages is None:
        messages = conversation_data.get("messages", [])
    
    formatted_response = {
        "wa_id": conversation_data.get("lead_id"),
        "conversation_mode": conversation_data.get("conversation_mode", "bot"),
        "lead_info": {
            "nombre": state.get("nombre", ""),
            "telefono": state.get("telefono", "")
        },
        "messages": messages,
        "completed": state.get("completed", False),
        "updated_at": conversation_data.get("updated_at", "")
    }
    
    return formatted_response

@app.route(route="get-conversation", methods=["POST"])
def get_conversation(req: func.HttpRequest) -> func.HttpResponse:
    """
    Obtiene el estado completo de una conversación para mostrar en la interfaz web.
    Ahora acepta POST con JSON body que contiene `wa_id`.
    """
    logging.info('get-conversation endpoint called (POST body)')
    
    try:
        # Verify JWT
        auth_header = req.headers.get('Authorization') or req.headers.get('authorization')
        if not verify_bearer_token(auth_header):
            return func.HttpResponse('Unauthorized', status_code=401)

        body = req.get_json()
        if not body:
            return func.HttpResponse("Invalid JSON", status_code=400)

        wa_id = body.get('wa_id')
        if not wa_id:
            return func.HttpResponse("Missing wa_id in request body", status_code=400)

        # Obtener estado de la conversación
        conversation_data = get_conversation_state(wa_id)

        if not conversation_data:
            return func.HttpResponse("Conversation not found", status_code=404)

        # Formatear respuesta según el formato solicitado
        formatted_response = format_conversation_response(conversation_data)

        return func.HttpResponse(
            json.dumps(formatted_response, ensure_ascii=False), 
            status_code=200, 
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error in get-conversation endpoint: {e}")
        return func.HttpResponse("Internal server error", status_code=500)

@app.route(route="get-recent-messages", methods=["POST"])
def get_recent_messages(req: func.HttpRequest) -> func.HttpResponse:
    """
    Devuelve los últimos mensajes de una conversación específica.
    Endpoint usado por el polling de la aplicación.
    Es de tipo POST para permitir el JSON body con el `wa_id` y `last_message_id`.
    """
    logging.info('get-recent-messages endpoint called')

    try:
        # Verify JWT
        auth_header = req.headers.get('Authorization') or req.headers.get('authorization')
        if not verify_bearer_token(auth_header):
            return func.HttpResponse('Unauthorized', status_code=401)

        body = req.get_json()
        if not body:
            return func.HttpResponse("Invalid JSON", status_code=400)

        wa_id = body.get('wa_id')
        last_message_id = body.get('last_message_id')
        if not wa_id or not last_message_id:
            return func.HttpResponse("Missing wa_id or last_message_id in request body", status_code=400)

        container = get_cosmos_container()

        conversation = container.read_item(item=f"conv_{wa_id}", partition_key=wa_id)

        messages = conversation.get("messages", [])

        # Filtrar mensajes nuevos
        new_messages = []
        if last_message_id:
            found_last = False
            for msg in messages:
                if found_last:
                    new_messages.append(msg)
                elif msg["id"] == last_message_id:
                    found_last = True
        
        response = format_conversation_response(conversation, new_messages)

        return func.HttpResponse(json.dumps(response, ensure_ascii=False), status_code=200, mimetype="application/json")

    except Exception as e:
        logging.error(f"Error in get-recent-messages endpoint: {e}")
        return func.HttpResponse("Internal server error", status_code=500)

@app.route(route="next-conversations", methods=["POST"])
def next_conversations(req: func.HttpRequest) -> func.HttpResponse:
    """
    Devuelve las siguientes 10 conversaciones más recientes después de los IDs proporcionados.
    Recibe una lista de IDs de conversaciones y devuelve las siguientes 10 basándose en updated_at.
    """
    logging.info('next-conversations endpoint called')
    
    try:
        # Verify JWT
        auth_header = req.headers.get('Authorization') or req.headers.get('authorization')
        if not verify_bearer_token(auth_header):
            return func.HttpResponse('Unauthorized', status_code=401)

        body = req.get_json()
        if not body:
            return func.HttpResponse("Invalid JSON", status_code=400)

        conversation_ids = body.get('conversation_ids')
        if not conversation_ids or not isinstance(conversation_ids, list):
            return func.HttpResponse("Missing or invalid conversation_ids array", status_code=400)

        container = get_cosmos_container()

        # Si no hay IDs proporcionados, devolver las primeras 10 conversaciones
        if len(conversation_ids) == 0:
            query = (
                "SELECT TOP 11 c.id, c.lead_id, c.canal, c.created_at, c.updated_at, "
                "c.state, c.conversation_mode, c.asignado_asesor FROM c ORDER BY c.updated_at DESC"
            )
        else:
            # Construir la consulta para obtener conversaciones posteriores a los IDs proporcionados
            # Primero obtenemos todas las conversaciones con los IDs proporcionados
            ids_str = "', '".join(conversation_ids)
            ids_query = f"SELECT c.id, c.updated_at FROM c WHERE c.id IN ('{ids_str}')"
            
            # Ejecutar consulta para obtener los IDs y sus updated_at
            ids_results = list(container.query_items(
                query=ids_query,
                enable_cross_partition_query=True
            ))
            
            if not ids_results:
                # Si no se encuentran los IDs, devolver las primeras 10 conversaciones
                query = (
                    "SELECT TOP 11 c.id, c.lead_id, c.canal, c.created_at, c.updated_at, "
                    "c.state, c.conversation_mode, c.asignado_asesor FROM c ORDER BY c.updated_at DESC"
                )
            else:
                # Encontrar el updated_at más antiguo, es decir, el último con el que se tuvo una conversación
                last_updated_at = min(item.get("updated_at", "") for item in ids_results)
                
                # Luego obtenemos las siguientes 10 conversaciones después de esa fecha
                query = (
                    "SELECT TOP 11 c.id, c.lead_id, c.canal, c.created_at, c.updated_at, "
                    "c.state, c.conversation_mode, c.asignado_asesor FROM c "
                    f"WHERE c.updated_at < '{last_updated_at}' "
                    "ORDER BY c.updated_at DESC"
                )

            logging.info(f"Query: {query}")

        items_iterable = container.query_items(
            query=query,
            enable_cross_partition_query=True
        )

        logging.info(f"Items iterable: {items_iterable}")

        # Materializar resultados en lista
        items = list(items_iterable)

        # Verificar si hay más conversaciones
        has_more = False
        if len(items) == 11:
            has_more = True

        # Tomar solo las primeras 10 conversaciones
        items = items[:10]

        # Formatear resultados según el formato requerido
        results = []
        for item in items:
            raw_state = item.get("state", {}) or {}
            # Mantener solo los campos necesarios en el state
            trimmed_state = {
                "nombre": raw_state.get("nombre", ""),
                "telefono": raw_state.get("telefono", ""),
                "completed": raw_state.get("completed", False)
            }

            formatted = {
                "id": item.get("id"),
                "lead_id": item.get("lead_id"),
                "canal": item.get("canal", ""),
                "created_at": item.get("created_at", ""),
                "updated_at": item.get("updated_at", ""),
                "state": trimmed_state,
                "conversation_mode": item.get("conversation_mode", "bot"),
                "asignado_asesor": item.get("asignado_asesor", "")
            }
            results.append(formatted)

        response_data = {
            "conversations": results,
            "has_more": has_more
        }

        return func.HttpResponse(
            json.dumps(response_data, ensure_ascii=False), 
            status_code=200, 
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error in next-conversations endpoint: {e}")
        return func.HttpResponse("Internal server error", status_code=500)

@app.route(route="get-multimedia-whatsapp", methods=["GET"])
def get_multimedia_whatsapp(req: func.HttpRequest) -> func.HttpResponse:
    """
    Obtiene archivos multimedia de WhatsApp usando el multimedia_id.
    Hace dos llamadas a la API de WhatsApp:
    1. Obtiene la información del multimedia (URL, mime_type, etc.)
    2. Descarga el archivo multimedia usando la URL obtenida
    """
    logging.info('get-multimedia-whatsapp endpoint called')
    
    try:
        # Verify JWT
        auth_header = req.headers.get('Authorization') or req.headers.get('authorization')
        # TODO: Mejorar este check con URLs Firmadas (Signed URLs)
        if not auth_header:
            logging.warning('No bearer token provided')
            # return func.HttpResponse('Unauthorized', status_code=401)

        # Get multimedia_id from query parameters
        multimedia_id = req.params.get('id')
        if not multimedia_id:
            return func.HttpResponse("Missing id query parameter", status_code=400)

        # Get WhatsApp access token from environment
        whatsapp_token = os.environ['WHATSAPP_ACCESS_TOKEN']
        if not whatsapp_token:
            logging.error("WHATSAPP_ACCESS_TOKEN not configured in app settings")
            return func.HttpResponse("Server misconfiguration", status_code=500)

        # First API call: Get multimedia information
        media_info_url = f"https://graph.facebook.com/v23.0/{multimedia_id}"
        headers = {
            'Authorization': f'Bearer {whatsapp_token}'
        }
        
        logging.info(f"Fetching media info from: {media_info_url}")
        media_info_response = requests.get(media_info_url, headers=headers, timeout=30)
        
        if media_info_response.status_code != 200:
            logging.error(f"Failed to get media info: {media_info_response.status_code} - {media_info_response.text}")
            return func.HttpResponse("Failed to get multimedia information from WhatsApp API", status_code=500)
        
        media_info = media_info_response.json()
        logging.info(f"Media info received: {media_info}")
        
        # Extract the download URL from the response
        download_url = media_info.get('url')
        if not download_url:
            logging.error("No download URL found in media info response")
            return func.HttpResponse("Invalid multimedia information from WhatsApp API", status_code=500)
        
        # Second API call: Download the actual multimedia file
        logging.info(f"Downloading multimedia file from: {download_url}")
        file_response = requests.get(download_url, headers=headers, timeout=60)
        
        if file_response.status_code != 200:
            logging.error(f"Failed to download file: {file_response.status_code} - {file_response.text}")
            return func.HttpResponse("Failed to download multimedia file from WhatsApp API", status_code=500)
        
        # Get mime type from media info or content-type header
        mime_type = media_info.get('mime_type') or file_response.headers.get('content-type', 'application/octet-stream')
        
        # Return the file with appropriate headers
        return func.HttpResponse(
            file_response.content,
            status_code=200,
            mimetype=mime_type,
            headers={
                'Content-Disposition': f'attachment; filename="whatsapp_media_{multimedia_id}"',
                'Content-Length': str(len(file_response.content))
            }
        )
        
    except requests.RequestException as e:
        logging.error(f"Error calling WhatsApp API: {e}")
        return func.HttpResponse("Error communicating with WhatsApp API", status_code=500)
    except Exception as e:
        logging.error(f"Error in get-multimedia-whatsapp endpoint: {e}")
        return func.HttpResponse("Internal server error", status_code=500)