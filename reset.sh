#!/bin/bash
set -e  # Exit immediately if a command exits with a non-zero status.
dropdb helios
createdb helios
uv run python manage.py migrate
echo "from helios_auth.models import User; User.objects.create(user_type='google',user_id='rubberdeebugger@gmail.com', info={'name':'Dev Admin'})" | uv run python manage.py shell