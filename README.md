# Blog Web Application

This is a blog web application for CMSC 495.

The focus is to demonstrate working as a team, developing a project plan and executing the plan.

The project itself demonstrates a full stack web application, which incorporates both front end and back end modern technologies.

For the front end, this includes:
* HTML
* CSS
* JavaScript
* BootStrap
* Angular

For the back end, this includes:
* Python - Programming Language
* Flask - Pyhton Web Framework/Library
* SqlAlchemy - Python Database ORM
* PyJWT - Python library for Json Web Tokens (JWT) for Authentication and Authorization
* Bcrypt - Hashing/Cryptography library for securing passwords
* dotenv - Python package/library for loading environment variables via local .env file
* Cloudinary - Online SaaS (Software as a Service) for uploading images

## Team Members
* Ryan Waite
* Matthew Lester
* Brian Oldham
* Michael DeAngelo
* Evan Martin


## Running the Backend

This repository contains only the code for the backend server.

To run the backend, follow the steps below:
* install Python 3.7.6 or above
* open a new terminal instance
* in the terminal, begin installing the needed python packages by running this command: `pip install dotenv flask sqlalchemy pyjwt bcrypt cloudinary`
* run the python file, which can be done many ways. The most typical way is to open a terminal, `cd` (change directory) to the project root folder where the python files are, and run `python app.py`

You should see in the terminal that the server initialized the local database and is listening for requests.

You can test that the API is up by opening this link: <a href="http://127.0.0.1:5000/events">http://127.0.0.1:5000/events</a>

NOTE: if you open the dev tools on that page and run this in the console, you should see the SSE (server-sent events) working:

```javascript
fetch(`/ping`)
```