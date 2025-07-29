# FastAPI Role-Based Project Management API

A RESTful API built with FastAPI featuring JWT authentication and role-based access control (admin/user) for managing projects.

---

## Installation Steps

1. **Clone the repository**

   ```bash
   git clone https://github.com/ABHEY7/restapi.git
   cd fast_api_code
   
2. **Create and activate a virtual environment**
   python -m venv venv
   source venv/bin/activate  //for linux
   .\venv\script\activate    // for windows

4. **Install dependencies**
   pip install -r requirements.txt

5. **Configure environment variables**
  Create a .env file in the project root and set your configuration:
   DATABASE_URL=postgresql://postgres:password@localhost:5432/mydb  **// for postgresql use**
   DATABASE_URL=sqlite:///./test.db     **//for local use**
   SECRET_KEY=abhey_dadwal
   ACCESS_TOKEN_EXPIRE_MINUTES = 30

5.**Run the application**
  uvicorn main:app --reload
  
6. **Access API**
   Open your browser and visit http://127.0.0.1:8000/docs to explore the API documentation.
