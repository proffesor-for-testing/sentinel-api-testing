from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum
import uvicorn

app = FastAPI(title="Petstore API", version="1.0.0", description="A simple API for managing a pet store")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class PetStatus(str, Enum):
    available = "available"
    pending = "pending"
    sold = "sold"


class PetCategory(str, Enum):
    dog = "dog"
    cat = "cat"
    bird = "bird"
    fish = "fish"
    other = "other"


class Pet(BaseModel):
    id: int
    name: str = Field(..., min_length=1, max_length=100)
    tag: Optional[str] = Field(None, max_length=50)
    status: Optional[PetStatus] = PetStatus.available
    price: Optional[float] = Field(None, ge=0)
    category: Optional[PetCategory] = None


# In-memory database for simplicity
pets_db = {
    1: Pet(id=1, name="Fluffy", tag="cute", status=PetStatus.available, price=99.99, category=PetCategory.cat),
    2: Pet(id=2, name="Rex", tag="loyal", status=PetStatus.available, price=299.99, category=PetCategory.dog),
    3: Pet(id=3, name="Tweety", tag="yellow", status=PetStatus.sold, price=49.99, category=PetCategory.bird),
    4: Pet(id=4, name="Nemo", tag="orange", status=PetStatus.available, price=19.99, category=PetCategory.fish),
    5: Pet(id=5, name="Max", tag="friendly", status=PetStatus.pending, price=399.99, category=PetCategory.dog),
}

next_pet_id = 6


@app.get("/")
async def root():
    return {"message": "Welcome to the Petstore API", "version": "1.0.0"}


@app.get("/api/v1/pets", response_model=List[Pet], tags=["pets"])
async def list_pets(limit: Optional[int] = Query(None, ge=1, le=100)):
    """List all pets with optional limit"""
    pets = list(pets_db.values())
    
    if limit:
        pets = pets[:limit]
    
    return pets


@app.post("/api/v1/pets", response_model=Pet, status_code=201, tags=["pets"])
async def create_pet(pet: Pet):
    """Create a new pet"""
    global next_pet_id
    
    # Override the provided ID with the next available ID
    pet.id = next_pet_id
    pets_db[next_pet_id] = pet
    next_pet_id += 1
    
    return pet


@app.get("/api/v1/pets/{pet_id}", response_model=Pet, tags=["pets"])
async def get_pet_by_id(pet_id: int):
    """Get a specific pet by ID"""
    if pet_id not in pets_db:
        raise HTTPException(status_code=404, detail="Pet not found")
    
    return pets_db[pet_id]


@app.put("/api/v1/pets/{pet_id}", response_model=Pet, tags=["pets"])
async def update_pet(pet_id: int, pet: Pet):
    """Update an existing pet"""
    if pet_id not in pets_db:
        raise HTTPException(status_code=404, detail="Pet not found")
    
    # Ensure the ID matches
    pet.id = pet_id
    pets_db[pet_id] = pet
    
    return pet


@app.delete("/api/v1/pets/{pet_id}", status_code=204, tags=["pets"])
async def delete_pet(pet_id: int):
    """Delete a pet"""
    if pet_id not in pets_db:
        raise HTTPException(status_code=404, detail="Pet not found")
    
    del pets_db[pet_id]
    return None


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "pets_count": len(pets_db)}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)