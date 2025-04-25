GUI Password Manager
===

### Disclaimer: This project is for display and will most likely not work due to Supabase automatically pausing the connection to the database if unused for a certain amount of time. If you do want to try it out, contact me directly.

This is a simple desktop application that allows you to securely manage your account credentials for various services.

Built with **Python**, the app utilizes **PyQt5** for the graphical user interface (GUI), **pycryptodome** for cryptographic operations, and **cryptography** for encryption. The application stores data in a **PostgreSQL** database hosted on **Supabase**, enabling users to access their credentials from any device using their master login (email/password).

It also leverages **Supabase’s built-in logging and monitoring tools** for audit trails and error tracking, reducing the need for manual log handling within the application.

*The project is designed with security and portability in mind, featuring cross-platform support for Windows and Linux.*

### 1. Clone the repository:
```
git clone https://github.com/emiskas/GUI_Password_Manager.git
```

### 2. Create a virtual environment in /GUI_Password_Manager/:
```
python3.12 -m venv .venv
```

### 3. Activate the virtual environment:

- #### For Linux / Mac:
```
source .venv/bin/activate
```

- #### For Windows:
```
.\.venv\Scripts\activate
```

### 4. Install the required packages:
```
(venv) pip install -r requirements.txt
```

Running the Application
===
### Using Python
To start the application, simply run the main_window.py file inside /gui/

```
(venv) python gui/main_window.py
```

### Using the executable
There is an executable each for Windows and Linux in their own folders. You can simply run these. 

*Recommended: If you do use the executable, put it into a seperate folder, because the application will create an additional backup folder*

Running tests (using Python to run the application)
===

In the root directory of the project, run this command
```
(venv) pytest tests.py
```

Or for a more detailed view
```
(venv) pytest tests.py -v
```

Software dependencies
===

### PyQt5
PyQt5 is a set of Python bindings for the Qt application framework. It provides tools to create rich graphical user interfaces (GUIs) and desktop applications. With a range of widgets and a powerful event-driven programming model, PyQt5 offers a robust solution for building cross-platform applications with ease.

### pycryptodome
pycryptodome is a self-contained Python package for cryptographic operations. It includes both high-level cryptographic algorithms (like AES, RSA) and low-level primitives. Ideal for secure encryption, decryption, hashing, and random number generation, pycryptodome is designed to be a drop-in replacement for the older PyCrypto library, providing improved security and performance.

### cryptography
cryptography is a package designed to provide both high-level recipes and low-level cryptographic primitives to Python developers. It’s focused on offering a robust, secure, and easy-to-use API for a variety of cryptographic tasks, including key generation, encryption, and hashing. cryptography is regularly updated to meet the latest standards and security practices in the field.

**For the full list of software dependencies see requirements.txt.**

