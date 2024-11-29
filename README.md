
# Flask RBAC App

This is a simple Flask web application that implements **Role-Based Access Control (RBAC)**. The app allows users to register, log in, and access different resources based on their assigned roles, such as **Admin**, **Moderator**, and **User**. The app features authentication, authorization, and role management using Flask, SQLAlchemy, and Flask-Login.

## Features

- **User Authentication**: Secure login system with password hashing.
- **Role-Based Access Control (RBAC)**: Access to specific routes is restricted based on user roles.
- **Admin Role**: Admin can manage users and assign roles.
- **Moderator Role**: Moderator can approve or reject blog posts.
- **User Role**: Regular users can create blog posts but have no access to admin or moderator pages.

## Technologies Used

- **Flask**: Web framework.
- **Flask-SQLAlchemy**: ORM for interacting with the SQLite database.
- **Flask-Login**: User session management.
- **Werkzeug**: Used for password hashing.

## Installation

### 1. Clone this repository:

```bash
git clone https://github.com/AwkwardlyProfessional/flask-rbac-app.git
cd flask-rbac-app
```

### 2. Set up a virtual environment:

```bash
python -m venv venv
```

### 3. Activate the virtual environment:

- **On macOS/Linux**:
  ```bash
  source venv/bin/activate
  ```
- **On Windows**:
  ```bash
  venv\Scripts\activate
  ```

### 4. Install dependencies:

```bash
pip install -r requirements.txt
```

### 5. Run the Flask application:

```bash
python app.py
```

The application will be available at `http://127.0.0.1:5000`.

## Usage

1. **Register**: Create a new user account by providing a username, email, password, and role (Admin, Moderator, or User).
2. **Login**: Log in with your registered credentials.
3. **Access Control**:
   - **Admin**: Can manage users and change their roles.
   - **Moderator**: Can approve or reject blog posts.
   - **User**: Can create blog posts but has no access to admin or moderator features.

### Available Routes:

- `/register` – Registration page for new users.
- `/login` – Login page.
- `/admin_dashboard` – Admin dashboard (only accessible by Admin).
- `/moderator_dashboard` – Moderator dashboard (only accessible by Moderator).
- `/user/dashboard` – User dashboard (only accessible by User).
- `/logout` – Log out the current user.

## Role-Based Access Control (RBAC)

This application implements RBAC using the following roles:

### **Admin**
- Full access to the system.
- Can manage users (create, update, delete) and assign roles.
- Can view all blog posts and approve/reject them.

### **Moderator**
- Can approve or reject blog posts.
- Cannot modify user roles or manage users.

### **User**
- Can create blog posts.
- Cannot access the admin or moderator dashboards.

## Example

1. **Admin**: Logs in and can go to `/admin_dashboard` to manage users.
2. **Moderator**: Logs in and can access `/moderator_dashboard` to approve or reject blog posts.
3. **User**: Logs in and can go to `/user/dashboard` to create blog posts.

## Testing the Application

1. **Create a new user**: Go to the **Register** page (`/register`), provide a username, email, password, and select a role (Admin, Moderator, or User).
2. **Login**: After registration, log in using the **Login** page (`/login`).
3. **Test Role-Based Access**:
   - If you're an **Admin**, you should have access to `/admin_dashboard`.
   - If you're a **Moderator**, you should have access to `/moderator_dashboard`.
   - If you're a **User**, you should be directed to `/user/dashboard`.

## Code Structure

```
/flask-rbac-app
  /app.py              # Main Flask application
  /models.py           # Database models (optional, if separated)
  /templates/          # HTML templates for registration, login, etc.
    /login.html
    /register.html
    /admin_dashboard.html
    /moderator_dashboard.html
    /dashboard.html
  /static/             # Static files (CSS, JS, etc.)
    /css/
      styles.css
  /requirements.txt    # List of dependencies (e.g., Flask, Flask-Login, Flask-SQLAlchemy)
  /README.md           # Project description, installation and usage instructions
```

## Dependencies

This project requires the following Python packages:

- `Flask==2.1.1`
- `Flask-SQLAlchemy==2.5.1`
- `Flask-Login==0.6.2`
- `Werkzeug==2.1.1`

You can install the required dependencies by running:

```bash
pip install -r requirements.txt
```

## Contributing

If you would like to contribute to this project, feel free to fork the repository and create a pull request. Please make sure your code follows the style guide and passes all tests.

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

---

Feel free to replace `your-username` with your actual GitHub username. Also, modify any sections if you add new features or change the structure.
