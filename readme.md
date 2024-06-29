Phone Number Project


Technologies User : PYTHON , DJANGO , DJANGO REST FRAMEWORK , DRF SWAGGER


### Setup and Running the Project:
To run the project on your local machine, follow these steps:

1. Create a virtual Environment and install all the packages from the requirements.txt
2. Install required dependencies (`Django`, `djangorestframework`, etc.) in a virtual environment.
3. Set up your database configurations in the Django project settings.
4. Populate the database with sample data using scripts 'python3 manage.py populate_data'  i have a provided the script for populating the dummy data at 'myproject/myapp/management/commands/populate_data.py'.
5. Start the development server using `python manage.py runserver`.
6. Test the API endpoints on Swagger or on API testing platforms like Postman.




### Models:
1. **UserRegistration:** Represents registered users with fields like `phone_number`, `name`, `email`, `password`, `is_verified`, `is_registered`, etc.
2. **Contact:** Stores user-specific contacts with `owner`, `name`, and `phone_number`.
3. **SpamReport:** Tracks reported spam numbers with `reporter`, `phone_number`, and `reported_at`.

### Functionalities:

#### Registration and Profile:
- Users register with at least `name` and `phone_number`, optionally adding an `email` and `password`.
- Import of user's phone contacts into the app's database.
- Authentication: Users need to be logged in to access the API endpoints.

#### Spam Reporting:
- Users can mark a number as spam to help other users identify spammers via the global database.
  
#### Search:
- **Search by Name:**
  - Displays results with `name`, `phone_number`, and `spam_likelihood`.
  - Results prioritize names starting with the search query, followed by partial matches.
  
- **Search by Phone Number:**
  - If the number belongs to a registered user, only that result is shown.
  - Otherwise, all matches for that number are displayed (as multiple names can have the same phone number).

#### Display Details:
- Clicking on a search result shows all details along with the `spam_likelihood`.
- Email is displayed only if the user searching is in the person’s contact list and the person is a registered user.
