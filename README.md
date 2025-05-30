## Description
This repository contains the app that manages a Prowler scan. It **does not** work for all the providers supported by Prowler though.

This project uses the foundation of the Prowler CLI tool as a library. The scan.py module calls a subset of the functions and classes called by [prowler()](https://github.com/prowler-cloud/prowler/blob/master/prowler/__main__.py#L106)

## Components
This app is made up of the following components:
* The JSON API, which is an API built with Django Rest Framework.
* The Celery worker, which is responsible for executing the background tasks with the prowler library
* SQLite database, which is used to store the data.
* Django channels, a library that extends Django to support Websocket and other protocols.
* Redis database, an in-memory database which is used as a message broker for the Celery workers and Django-channels.

## Deployment
Ensure you have Python and [Redis](https://redis.io/) installed on your computer. Ensure the redis server is up and running on your computer. 

**Note:** This app should not be used in production.

### Environmental Variables
Use the .env.example in the root path as template to set values in a .env file for your environmental variables. This .env file must be created by you. To load variables from your .env file, run this:
```sh
set -a
source .env
```
Ensure you have the correct environmental variables setup

### Dependencies
Install the required dependencies in your computer by executing this in your shell
```sh
pip install -r requirements.txt
```
You execute the above in the root path.

### Apply migrations
Before running this app, you need to run migrations. To do that, run:
```sh
cd src
python manage.py migrate
```

### Run API server and Celery Worker
To successfully use this app to carry out scans, you have to run both the api server and celery worker.

To setup the api server, run this:
```sh
cd src
python manage.py runserver
```

To setup the celery worker, run this:
```sh
cd src
python -m celery -A scanmanager worker -l info
```

Once both are successfully running, you can access the server  in localhost:8000.

## Running and Monitoring Scans
This app gives you the ability to run and monitor multiple scans.

### Running

You can use curl to run a scan. Here's an example:
```sh
curl -X POST -H "Content-Type: application/json" -d '{"provider": "aws", "severities": ["high", "critical"]}' http://localhost:8000/scans/
```
The post json field has the following structure
```json
{
    // Only one of these providers (aws, azure, gcp, m365) is needed. The value is a string.
    "provider": "azure",
    // You can use combinations of these severities (critical, high, medium, low, informational). The value is a list. An empty list signifies that the scan needs to check for all severities.
    "severities": ["low", "medium"]
}
```
Here's an example output after executing the above shell command:
```sh
{
    "url":"http://localhost:8000/scans/1/",
    "id":1,
    "status":"pending",
    "provider":"aws",
    "severities":["high","critical"],
    "start":null,
    "end":null,
    "status_url":"http://localhost:8000/scans/1/status/","checks":[]
}
```
Take note of the id.

### Monitoring
You can monitor a scan via http or websocket. 

#### HTTP
With http, you can check your scan status using curl like this:
```sh
curl -H "Content-Type: application/json"  http://localhost:8000/scans/{scan_id}/status/
```
**{scan_id}** represents the monitored scan id. This is the value of the `id` key in the json response when you run a scan.

The above command will return the status of the scan. The status will either be `pending`, `in_progress`, `completed`, or `failed`.

#### WebSocket
I recommend the use of [wscat](https://github.com/websockets/wscat) to monitor a scan using WebSocket.

To use wscat, ensure the `DJANGO_ALLOWED_HOSTS` environmental variable for the server and celery worker is set to *.

Monitoring using wscat is simple. You just have to run:
```sh
wscat --connect 127.0.0.1:8000/ws/scans/{scan_id}/
```
Again, **{scan_id}** represents the monitored scan id.

Here's an example output:
```sh
{"message": {"status": "pending"}}
< {"message": {"status": "in_progress"}}
< {"message": {"status": "in_progress", "progress": "0.3%"}}
< {"message": {"status": "in_progress", "progress": "0.6%"}}
< {"message": {"status": "in_progress", "progress": "0.9%"}}
< {"message": {"status": "in_progress", "progress": "1.19%"}}
< {"message": {"status": "in_progress", "progress": "1.49%"}}
...others...
< {"message": {"status": "in_progress", "progress": "99.4%"}}
< {"message": {"status": "in_progress", "progress": "99.7%"}}
< {"message": {"status": "in_progress", "progress": "100.0%"}}
< {"message": {"status": "completed"}}
```
## Testing
To run tests, simply execute this:
```sh
cd src
python manage.py test
```

