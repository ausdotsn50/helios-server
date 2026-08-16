# Helios Server Installation

## Prerequisites

* Install PostgreSQL 12+ - done

* Install RabbitMQ - done
  This is needed for Celery to work, which does background processing such as
  the processing of uploaded list-of-voter CSV files, verification of cast
  votes, and tally computation.

  **RabbitMQ 4.x note.** RabbitMQ 4.0 disallows transient non-exclusive queues
  by default, which Celery's mingle/gossip/pidbox consumers declare on startup.
  Without the setting below the worker fails with
  `INTERNAL_ERROR - Feature 'transient_nonexcl_queues' is deprecated` and
  restarts in a loop. Add to `rabbitmq.conf`
  (Homebrew: `/opt/homebrew/etc/rabbitmq/rabbitmq.conf`) and restart the broker:

```
deprecated_features.permit.transient_nonexcl_queues = true
```

* Download helios-server - done (cloned)

* `cd` into the helios-server directory

## Python Setup

* Install Python 3.13 including dev packages

```
sudo apt install python3 python3-dev
```

* Install uv (modern Python package manager)

```
curl -LsSf https://astral.sh/uv/install.sh | sh
```

* You'll also need Postgres dev libraries. For example on Ubuntu:

```
sudo apt install libpq-dev
```

* Install dependencies (uv creates a virtual environment automatically)

```
uv sync
```

## Database Setup

* Reset database

```
./reset.sh
```

## Running the Server

* Start server

```
uv run python manage.py runserver
```

* Kill server
```
kill -9 $(lsof -t -i:8000)
```

## Run celery worker

```
uv run celery --app helios worker --events --beat --concurrency 1
```

## Google Auth Configuration

To get Google Auth working:

* Go to https://console.developers.google.com

* Create an application

* Set up OAuth2 credentials as a web application, with your origin, e.g. `https://myhelios.example.com`, and your auth callback, which based on our example is `https://myhelios.example.com/auth/after/`

* In the developer console, enable the Google People API

* Set the `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` configuration variables accordingly
