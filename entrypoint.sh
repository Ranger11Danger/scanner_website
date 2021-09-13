#!/bin/bash
echo "Waiting for postgres..."

while ! nc -z db 5432; do
    sleep 0.1
done
echo "PostgreSQL started"

export LC_ALL=C.UTF-8
export LANG=C.UTF-8
python3 manage.py migrate
python3 manage.py shell -c "from hyper.users.models import User; User.objects.create_superuser('admin', 'admin@example.com', 'admin')"
redis-server --daemonize yes
cd /usr/src/app
celery -A hyper.dashboard worker -l info --detach

exec "$@"