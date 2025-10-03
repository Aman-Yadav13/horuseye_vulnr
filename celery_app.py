from celery import Celery
import os

# Create a Celery instance.
# The broker URL points to Redis, which will be running in another Docker container.
# The backend is also Redis, used for storing task state (though we are saving results to files).
celery = Celery(
    __name__,
    broker=os.environ.get('CELERY_BROKER_URL', 'redis://redis:6379/0'),
    backend=os.environ.get('CELERY_RESULT_BACKEND', 'redis://redis:6379/0')
)

celery.conf.update(
    task_serializer='json',
    accept_content=['json'],  
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)
