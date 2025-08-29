import azure.functions as func
import logging
import json
import os
import requests
from datetime import datetime, timezone
from azure.cosmos import CosmosClient

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="login")
def login(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    """
    Handles login request.
    """
    logging.info("login - Start")
    body = req.get_json()
    if body.get("username") == "admin" and body.get("password") == "admin":
        return func.HttpResponse("Login successful", status_code=200)
    else:
        return func.HttpResponse("Login failed", status_code=401)

@app.route(route="conversation-mode", methods=["POST"])
def conversation_mode(req: func.HttpRequest) -> func.HttpResponse:
    """
    Cambia el modo de conversación (bot/agente) para un lead específico.
    """
    logging.info('conversation-mode endpoint called')
    
    try:
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
        
        # Actualizar modo via Cosmos DB (aquí deberías implementar la conexión directa)
        # Por ahora simulamos el éxito
        success = update_conversation_mode(wa_id, mode)
        
        if success:
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

@app.route(route="send-agent-message", methods=["POST"])
def send_agent_message(req: func.HttpRequest) -> func.HttpResponse:
    """
    Envía un mensaje del agente al lead a través del chatbot Azure Function.
    """
    logging.info('send-agent-message endpoint called')
    
    try:
        body = req.get_json()
        if not body:
            return func.HttpResponse("Invalid JSON", status_code=400)
        
        wa_id = body.get("wa_id")
        message = body.get("message")
        
        if not wa_id or not message:
            return func.HttpResponse("Missing wa_id or message", status_code=400)
        
        # Llamar al endpoint agent-message del chatbot Azure Function
        chatbot_url = os.environ["AIBOT_FUNCTION_URL"]

        if not chatbot_url:
            return func.HttpResponse("Chatbot function URL not configured", status_code=500)
        
        payload = {
            "wa_id": wa_id,
            "message": message
        }
        
        response = requests.post(
            chatbot_url,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            response_data = {
                "success": True,
                "message": "Agent message sent successfully",
                "wa_id": wa_id,
                "message_sent": message,
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

@app.route(route="get-conversation", methods=["POST"])
def get_conversation(req: func.HttpRequest) -> func.HttpResponse:
    """
    Obtiene el estado completo de una conversación para mostrar en la interfaz web.
    Ahora acepta POST con JSON body que contiene `wa_id`.
    """
    logging.info('get-conversation endpoint called (POST body)')
    
    try:
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

def format_conversation_response(conversation_data: dict) -> dict:
    """
    Formatea los datos de conversación al formato requerido.
    """
    logging.info(f"conversation_data: {conversation_data}")
    state = conversation_data.get("state", {})
    
    # Determinar nombre (nombre_completo si existe, sino nombre)
    nombre = state.get("nombre_completo") or state.get("nombre", "")
    
    formatted_response = {
        "wa_id": conversation_data.get("lead_id"),
        "conversation_mode": conversation_data.get("conversation_mode", "bot"),
        "lead_info": {
            "nombre": nombre,
            "telefono": state.get("telefono", "")
        },
        "messages": conversation_data.get("messages", []),
        "completed": state.get("completed", False),
        "updated_at": conversation_data.get("updated_at", "")
    }
    
    return formatted_response


@app.route(route="leads/recent", methods=["GET"])
def get_recent_leads(req: func.HttpRequest) -> func.HttpResponse:
    """
    Devuelve las últimas 10 conversaciones ordenadas por `updated_at` (desc).
    Formato de salida similar al pedido en la descripción del ticket.
    """
    logging.info('get-recent-leads endpoint called')

    try:
        container = get_cosmos_container()

        # Query para obtener las últimas 10 conversaciones por updated_at descendente
        query = (
            "SELECT TOP 10 c.id, c.lead_id, c.canal, c.created_at, c.updated_at, "
            "c.state, c.conversation_mode, c.asignado_asesor FROM c ORDER BY c.updated_at DESC"
        )

        items_iterable = container.query_items(
            query=query,
            enable_cross_partition_query=True
        )

        # materializar resultados en lista
        items = list(items_iterable)

        # Asegurar que cada item tenga las claves esperadas y formatear si es necesario
        results = []
        for it in items:
            raw_state = it.get("state", {}) or {}
            # Keep only the four requested fields in the state
            trimmed_state = {
                "nombre": raw_state.get("nombre", ""),
                "nombre_completo": raw_state.get("nombre_completo", ""),
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

        return func.HttpResponse(json.dumps(results, ensure_ascii=False), status_code=200, mimetype="application/json")

    except Exception as e:
        logging.error(f"Error in get-recent-conversations endpoint: {e}")
        return func.HttpResponse("Internal server error", status_code=500)