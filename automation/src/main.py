"""
Detection & Automation Lab - Main Application
Orchestrates security automation workflows and integrations
"""

import asyncio
import logging
import sys
from contextlib import asynccontextmanager
from typing import Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app, Counter, Histogram, Gauge
import structlog

from core.config import get_settings
from core.logging import setup_logging
from core.database import init_db, close_db
from core.redis_client import init_redis, close_redis
from api.routes import alerts, enrichment, remediation, integrations
from services.alert_processor import AlertProcessor
from services.workflow_engine import WorkflowEngine

# Metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
REQUEST_DURATION = Histogram('http_request_duration_seconds', 'HTTP request duration')
ACTIVE_ALERTS = Gauge('active_alerts_total', 'Number of active alerts')
AUTOMATION_TASKS = Counter('automation_tasks_total', 'Total automation tasks', ['task_type', 'status'])

settings = get_settings()
logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting Detection & Automation Lab")
    
    # Initialize database
    await init_db()
    logger.info("Database initialized")
    
    # Initialize Redis
    await init_redis()
    logger.info("Redis initialized")
    
    # Initialize services
    app.state.alert_processor = AlertProcessor()
    app.state.workflow_engine = WorkflowEngine()
    
    # Start background tasks
    asyncio.create_task(background_alert_processor(app.state.alert_processor))
    asyncio.create_task(background_workflow_engine(app.state.workflow_engine))
    
    logger.info("Application startup complete")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Detection & Automation Lab")
    
    # Close connections
    await close_redis()
    await close_db()
    
    logger.info("Application shutdown complete")


def create_app() -> FastAPI:
    """Create and configure FastAPI application"""
    
    app = FastAPI(
        title="Detection & Automation Lab",
        description="Security Operations Center automation platform",
        version="1.0.0",
        docs_url="/docs" if settings.ENABLE_SWAGGER_UI else None,
        redoc_url="/redoc" if settings.ENABLE_SWAGGER_UI else None,
        lifespan=lifespan
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include routers
    app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["alerts"])
    app.include_router(enrichment.router, prefix="/api/v1/enrichment", tags=["enrichment"])
    app.include_router(remediation.router, prefix="/api/v1/remediation", tags=["remediation"])
    app.include_router(integrations.router, prefix="/api/v1/integrations", tags=["integrations"])
    
    # Metrics endpoint
    if settings.ENABLE_METRICS:
        metrics_app = make_asgi_app()
        app.mount("/metrics", metrics_app)
    
    return app


app = create_app()


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": "2024-01-01T00:00:00Z"
    }


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Detection & Automation Lab API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }


@app.post("/api/v1/webhook/wazuh")
async def wazuh_webhook(
    alert_data: Dict[str, Any],
    background_tasks: BackgroundTasks
):
    """Webhook endpoint for Wazuh alerts"""
    try:
        logger.info("Received Wazuh alert", alert_id=alert_data.get("id"))
        
        # Add to background processing
        background_tasks.add_task(
            process_wazuh_alert,
            alert_data
        )
        
        AUTOMATION_TASKS.labels(task_type="wazuh_alert", status="received").inc()
        
        return {"status": "accepted", "message": "Alert queued for processing"}
        
    except Exception as e:
        logger.error("Error processing Wazuh webhook", error=str(e))
        AUTOMATION_TASKS.labels(task_type="wazuh_alert", status="error").inc()
        raise HTTPException(status_code=500, detail="Internal server error")


async def process_wazuh_alert(alert_data: Dict[str, Any]):
    """Process incoming Wazuh alert"""
    try:
        alert_processor = app.state.alert_processor
        await alert_processor.process_alert(alert_data)
        
        AUTOMATION_TASKS.labels(task_type="wazuh_alert", status="processed").inc()
        logger.info("Wazuh alert processed successfully", alert_id=alert_data.get("id"))
        
    except Exception as e:
        logger.error("Error processing Wazuh alert", error=str(e), alert_data=alert_data)
        AUTOMATION_TASKS.labels(task_type="wazuh_alert", status="failed").inc()


async def background_alert_processor(alert_processor: AlertProcessor):
    """Background task for processing alerts"""
    while True:
        try:
            await alert_processor.process_queue()
            await asyncio.sleep(5)  # Process every 5 seconds
        except Exception as e:
            logger.error("Error in background alert processor", error=str(e))
            await asyncio.sleep(10)  # Wait longer on error


async def background_workflow_engine(workflow_engine: WorkflowEngine):
    """Background task for workflow engine"""
    while True:
        try:
            await workflow_engine.process_workflows()
            await asyncio.sleep(10)  # Process every 10 seconds
        except Exception as e:
            logger.error("Error in background workflow engine", error=str(e))
            await asyncio.sleep(30)  # Wait longer on error


@app.middleware("http")
async def metrics_middleware(request, call_next):
    """Middleware to collect metrics"""
    start_time = asyncio.get_event_loop().time()
    
    response = await call_next(request)
    
    # Record metrics
    duration = asyncio.get_event_loop().time() - start_time
    REQUEST_DURATION.observe(duration)
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code
    ).inc()
    
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    logger.error("Unhandled exception", error=str(exc), path=request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


if __name__ == "__main__":
    # Setup logging
    setup_logging()
    
    # Run the application
    uvicorn.run(
        "main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEVELOPMENT_MODE,
        log_config=None,  # Use our custom logging
        access_log=False  # Disable uvicorn access logs
    )