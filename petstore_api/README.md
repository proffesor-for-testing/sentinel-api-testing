# Petstore API Test Service

A simple FastAPI implementation of the Petstore API for testing the Sentinel platform.

## Features

- Full CRUD operations for pets
- In-memory database (resets on restart)
- CORS enabled for frontend testing
- Interactive API documentation
- Docker support

## Quick Start

### Option 1: Run with the startup script
```bash
chmod +x run.sh
./run.sh
```

### Option 2: Run with Python directly
```bash
pip install -r requirements.txt
python main.py
```

### Option 3: Run with Docker
```bash
docker-compose up --build
```

## API Endpoints

The API will be available at: `http://localhost:8080`

- `GET /` - Welcome message
- `GET /health` - Health check
- `GET /api/v1/pets` - List all pets (supports `?limit=N` query parameter)
- `POST /api/v1/pets` - Create a new pet
- `GET /api/v1/pets/{pet_id}` - Get a specific pet
- `PUT /api/v1/pets/{pet_id}` - Update a pet
- `DELETE /api/v1/pets/{pet_id}` - Delete a pet

## Interactive Documentation

- Swagger UI: `http://localhost:8080/docs`
- ReDoc: `http://localhost:8080/redoc`

## Sample Data

The API comes pre-populated with 5 sample pets:
1. Fluffy (Cat) - $99.99
2. Rex (Dog) - $299.99  
3. Tweety (Bird) - $49.99 (Sold)
4. Nemo (Fish) - $19.99
5. Max (Dog) - $399.99 (Pending)

## Testing with Sentinel

1. Start this API service on port 8080
2. In the Sentinel frontend, go to "Test Runs"
3. Import the `sample-petstore.yaml` specification
4. Set the base URL to `http://localhost:8080/api/v1`
5. Run tests against the API

## Pet Schema

```json
{
  "id": 1,
  "name": "Fluffy",
  "tag": "cute",
  "status": "available|pending|sold",
  "price": 99.99,
  "category": "dog|cat|bird|fish|other"
}
```

## Notes

- The database is in-memory, so all changes are lost when the server restarts
- IDs are auto-generated when creating new pets
- CORS is enabled for all origins to simplify testing