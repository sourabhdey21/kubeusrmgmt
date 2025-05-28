# Kubernetes User Management Web App

This is a web application that allows you to create Kubernetes users with different access levels (admin and readonly) and generate their kubeconfig files.

## Features

- Create users with admin or readonly access
- Automatically generate kubeconfig files
- Web-based interface for easy user management
- Secure certificate generation for user authentication

## Prerequisites

- Python 3.7+
- Access to a Kubernetes cluster
- Proper RBAC permissions to create ServiceAccounts and RoleBindings

## Installation

1. Clone this repository
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Make sure you have access to your Kubernetes cluster and your kubeconfig is properly set up.

2. Run the application:
   ```bash
   python app.py
   ```

3. Open your web browser and navigate to `http://localhost:5000`

4. Use the web interface to:
   - Enter a username
   - Select a role (admin or readonly)
   - Click "Create User" to generate the kubeconfig file

5. The kubeconfig file will be automatically downloaded. Users can use this file to access the cluster with their assigned permissions.

## Security Considerations

- The application should be run in a secure environment
- Access to the web interface should be restricted
- Generated kubeconfig files should be securely distributed to users
- Consider implementing additional authentication for the web interface

## Deployment

For production deployment, consider:

1. Using a proper WSGI server (e.g., Gunicorn)
2. Setting up HTTPS
3. Implementing authentication for the web interface
4. Running the application in a Kubernetes pod with appropriate RBAC permissions

## License

MIT 