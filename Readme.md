# Authentication Flow Walkthrough

This guide details the steps to obtain an auth token from the `authentication-service` using Postman and a Browser, bypassing the React frontend.

## Prerequisites

- `authentication-service` must be running (default port: `8080`).
- `user-service` must be running (as `authentication-service` depends on it for user creation).
- Database (MySQL/H2) must be accessible.

## Step 1: Register a New User (Postman)

Create a new user to log in with.

- **Method**: `POST`
- **URL**: `http://localhost:8080/auth/register`
- **Headers**: `Content-Type: application/json`
- **Body**:
  ```json
  {
    "userName": "testuser",
    "email": "test@example.com",
    "password": "password123",
    "role": "USER",
    "phoneNumber": "1234567890",
    "department": "IT",
    "officeLocation": "NY"
  }
  ```
- **Expected Response**: `201 Created` with user details.

## Step 2: Initiate Authorization Code Flow (Browser)

Start the OAuth2 login process.

- **Open in Browser**:
  ```
  http://localhost:8080/oauth2/authorize?response_type=code&client_id=oidc-client&scope=openid%20profile&redirect_uri=http://localhost:5173/callback
  ```

## Step 3: Login (Browser)

You will be redirected to the **new custom login page**.

- **Verify UI**: Check that the page has the Cognizant color scheme (Blue/Teal) and looks professional.
- **Username**: `test@example.com`
- **Password**: `password123`
- Click **Sign in**.

## Step 4: Consent (Browser)

You will be asked to approve the requested scopes.

- Select **openid** and **profile**.
- Click **Submit Consent**.

## Step 5: Obtain Authorization Code (Browser)

After consent, you will be redirected to the `redirect_uri`. Since the frontend is not running, the browser might show a "Connection Refused" error, but **look at the URL bar**.

- **URL**: `http://localhost:5173/callback?code=QwErTy...&state=...`
- **Action**: Copy the value of the [code](file:///home/udayan/Projects/game-app/authentication-service/src/main/java/com/cognizant/authentication_service/config/ProjectSecurityConfig.java#142-146) parameter.

## Step 6: Exchange Code for Token (Postman)

Exchange the authorization code for an access token.

- **Method**: `POST`
- **URL**: `http://localhost:8080/oauth2/token`
- **Authorization**: Basic Auth
  - **Username**: `oidc-client`
  - **Password**: `my-client-secret`
- **Body** (`x-www-form-urlencoded`):
  - `grant_type`: `authorization_code`
  - [code](file:///home/udayan/Projects/game-app/authentication-service/src/main/java/com/cognizant/authentication_service/config/ProjectSecurityConfig.java#142-146): `PASTE_YOUR_CODE_HERE`
  - `redirect_uri`: `http://localhost:5173/callback`

- **Expected Response**:
  ```json
  {
    "access_token": "...",
    "refresh_token": "...",
    "scope": "openid profile",
    "id_token": "...",
    "token_type": "Bearer",
    "expires_in": 300
  }
  ```

## Step 7: Use the Token

Use the `access_token` to access protected resources.

- **Header**: `Authorization: Bearer <access_token>`
