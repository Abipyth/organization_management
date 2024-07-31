Organization Management System

## Installation

1. Clone the repository:
    
    git clone the repository
    cd your-repository
    ```

2. Set up a virtual environment:
    
    python -m venv venv
     use `venv\Scripts\activate`
    ```

3. Install the required packages:
    
    pip install -r requirements.txt
    ```

4. Apply migrations:
    python manage.py makemigrations
    python manage.py migrate
    ```

5. Create a superuser (if needed):
    
    python manage.py createsuperuser
    ```

6. Run the development server:
    
    python manage.py runserver
    ```

## Usage

- Visit `http://127.0.0.1:8000/` to view the site.
- Use the admin interface at `http://127.0.0.1:8000/admin` to manage the application.

## Running Tests

To run tests, use:
save the tests report in text file
python manage.py test test_report_final.txt
