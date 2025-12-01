from typing import Dict, Any
from fastapi import WebSocket
import json
import logging

logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        # Map user_id -> list of WebSocket connections
        self.user_connections: Dict[str, list[WebSocket]] = {}
        # Map WebSocket -> user_id for reverse lookup
        self.connection_users: Dict[WebSocket, str] = {}

    async def connect(self, websocket: WebSocket, user_id: str):
        """Connect a websocket for a specific user."""
        await websocket.accept()
        if user_id not in self.user_connections:
            self.user_connections[user_id] = []
        self.user_connections[user_id].append(websocket)
        self.connection_users[websocket] = user_id
        logger.info(f"WebSocket client connected for user {user_id}. Total connections: {sum(len(c) for c in self.user_connections.values())}")

    def disconnect(self, websocket: WebSocket):
        """Disconnect a websocket."""
        user_id = self.connection_users.get(websocket)
        if user_id and user_id in self.user_connections:
            if websocket in self.user_connections[user_id]:
                self.user_connections[user_id].remove(websocket)
            if not self.user_connections[user_id]:
                del self.user_connections[user_id]
        if websocket in self.connection_users:
            del self.connection_users[websocket]
        logger.info(f"WebSocket client disconnected. Total connections: {sum(len(c) for c in self.user_connections.values())}")

    async def send_to_user(self, user_id: str, message: Dict[str, Any]):
        """Send a message to all connections for a specific user."""
        connections = self.user_connections.get(user_id, [])
        if not connections:
            return
            
        serialized = json.dumps(message)
        dead_connections = []
        for connection in connections:
            try:
                await connection.send_text(serialized)
            except Exception as e:
                logger.error(f"Error sending message to user {user_id}: {e}")
                dead_connections.append(connection)
        
        # Clean up dead connections
        for conn in dead_connections:
            self.disconnect(conn)

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast to all connected users (use sparingly)."""
        serialized = json.dumps(message)
        for user_id, connections in list(self.user_connections.items()):
            for connection in connections:
                try:
                    await connection.send_text(serialized)
                except Exception as e:
                    logger.error(f"Error broadcasting to user {user_id}: {e}")
                
manager = ConnectionManager()
