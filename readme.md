### Authentication System Flow

Here's a comprehensive flow for implementing an authentication system using Express.js, TypeScript, Prisma, PostgreSQL, and Zod, covering all your requirements:

#### 1. User Registration

- **Input Validation**: When a user registers, validate the input data using Zod. Ensure the username, email, and password meet the specified criteria. The email must belong to specific domains (e.g., gmail.com, yahoo.com, .ac.in, outlook.com).
- **Create User**: If validation passes, create a new user record in the PostgreSQL database using Prisma.
- **Send Verification Email**: After successfully creating the user, send a verification email containing a unique verification link to the user's email address.

#### 2. Email Verification

- **Verification Link Handling**: When the user clicks the verification link, the server should validate the token included in the link.
- **Update User Status**: If the token is valid, update the user's account status to "verified" in the database.

#### 3. User Login

- **Input Validation**: Validate the email and password provided by the user during login.
- **Authentication**: Check the credentials against the database. If they are correct, generate an access token (valid for 5 minutes) and a refresh token (valid for 30 days).
- **Set Refresh Token**: Send the refresh token to the user in a read-only cookie and return the access token in the response.

#### 4. Token Management

- **Access Token Storage**: The user should store the access token in local storage for subsequent requests.
- **Token Expiration Handling**: When the access token expires, the user can request a new access token using the refresh token stored in the cookie.
- **Refresh Token Validation**: Validate the refresh token and, if valid, issue a new access token.

#### 5. Forgot Password

- **Request Handling**: When a user requests a password reset, validate the provided email.
- **Email Verification**: Check if the email exists in the database. If it does, send a password reset email containing a unique reset link.

#### 6. Password Reset

- **Reset Link Handling**: When the user clicks the reset link, validate the token.
- **Update Password**: If the token is valid, present the user with a form to enter a new password and confirm it. Validate the new password against your criteria.
- **Store New Password**: If the new password is valid, hash it using bcrypt and update the user's password in the database.
