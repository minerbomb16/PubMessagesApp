# PubMessagesApp
### Web social app with high level of protection.

### 1. Technologies Used
- .NET Core & ASP.NET Core Identity – Authentication and user management
- Entity Framework Core – ORM for database interactions
- SQLite – Lightweight, encrypted database
- TOTP (Time-based One-Time Password) – Two-factor authentication (2FA)
- RSA & AES Encryption – Secure key management and message signing
- HtmlSanitizer & ImageSharp – Input validation and media sanitization
- Docker & Nginx – Deployment and reverse proxy
- Content-Security-Policy (CSP) – XSS prevention

### 2. Security Features
- User Registration:
  - Email validation on the server side (ViewModel verification).
  - Password requirements enforced using ASP.NET Identity:
  - Minimum 8 characters
  - Upper and lowercase letters
  - At least one number and special character
  - Confirmation link generation (simulated via console output)
  - Passwords are hashed using PBKDF2:
    - HMAC-SHA256, 100,000 iterations
    - 128-bit salt, 256-bit hash
    - Cryptographically secure salt generation using RandomNumberGenerator
  - RSA key pair and secret key are generated randomly:
    - Private key and secret key are encrypted using AES
    - The encryption key is derived from the user password and a unique salt via PBKDF2
    - Randomly generated IV (Initialization Vector) is used for AES encryption
- Login Security
  - 1-second delay for each authentication attempt (protection against brute-force attacks)
  - Account lockout after 4 failed attempts (locked for 5 minutes)
  - TOTP-based 2FA (secret key is shown during the first login for mobile app configuration)
  - 1-second delay when entering the authentication code
- Session Management:
  - Secure HTTP-only cookies for session handling:
    - HttpOnly – Prevents JavaScript access (XSS protection)
    - SecurePolicy – Sent only via HTTPS
    - SameSite – Prevents CSRF attacks
    - IsEssential – Cannot be deleted by the user
    - ExpireTimeSpan – Session expires after 1 hour of inactivity
    - SlidingExpiration – Resets expiration upon user activity
  - Session cookies are assigned upon successful login and removed upon logout or inactivity timeout
- Password Change:
  - Users must enter their current password and confirm the new password twice
  - Password validation follows the same security rules as during registration
  - TOTP validation required before changing the password
  - 1-second delay introduced to mitigate timing attacks
- Messaging & Content Validation:
  - Message text is sanitized using HtmlSanitizer:
    - Allowed tags: \<b>, \<i>, \<br> (bold, italic, line break)
  - Images are validated:
    - File extension verification
    - Header inspection (file structure validation)
    - Metadata removal using ImageSharp
  - Message signing with RSA:
    - The message is converted to a byte array
    - A SHA-256 hash is created
    - The hash is signed with the private RSA key
    - On message retrieval, the signature is verified using the public RSA key
- IP Address Logging:
  - The client’s IP address is sent via a script during login
  - IP validation is performed on the backend to detect tampering
  - Geolocation mapping is done using an external database
  - Login attempts (successful and failed) are logged with timestamps
- Encrypted Database:
  - SQLite is used as the database
  - The database is encrypted, and the password is stored as an environment variable
- CSRF Protection:
  - Global enforcement of AutoValidateAntiforgeryTokenAttribute
  - [ValidateAntiForgeryToken] attribute on all POST methods
  - Anti-forgery tokens are generated in views using @Html.AntiForgeryToken()
  - SameSite cookie settings prevent cross-site request attacks
- Content Security Policy (CSP):
  - Nonce-based security (128-bit random value generated per request) for script/style authorization
  - CSP policy settings:
    - default-src – Only allow resources from the same domain
    - script-src – Restricts scripts to trusted domains; inline scripts require a nonce
    - style-src – Restricts styles to trusted domains; inline styles require a nonce
    - img-src – Allows images only from the same domain
    - connect-src – Allows API requests to localhost and api.ipify.org
    - frame-ancestors – Prevents embedding in \<iframe> (Clickjacking protection)
    - form-action – Restricts form submissions to the same domain
- Deployment (Docker & Nginx):
  - Nginx reverse proxy configured
  - HTTPS enforced (port 443)
  - Database password stored as an environment variable
  - OpenSSL-generated SSL certificates used for secure communication
  - Server headers minimized (Nginx version hidden for security)

### 2. Images
- Registration:
![Registration](https://raw.githubusercontent.com/minerbomb16/Pngs/refs/heads/main/PubMessagesApp/Registration.png)
- Email confirmation:
![Confirmation](https://raw.githubusercontent.com/minerbomb16/Pngs/refs/heads/main/PubMessagesApp/Confirmation.png)
- Login:
![Login](https://raw.githubusercontent.com/minerbomb16/Pngs/refs/heads/main/PubMessagesApp/Login.png)
- Verification:
![Verification](https://raw.githubusercontent.com/minerbomb16/Pngs/refs/heads/main/PubMessagesApp/Verification.png)
- Menu:
![Menu](https://raw.githubusercontent.com/minerbomb16/Pngs/refs/heads/main/PubMessagesApp/Menu.png)
- Login history:
![History](https://raw.githubusercontent.com/minerbomb16/Pngs/refs/heads/main/PubMessagesApp/History.png)
- Add message:
![Add](https://raw.githubusercontent.com/minerbomb16/Pngs/refs/heads/main/PubMessagesApp/Add.png)
- Menu after added message:
![MenuUpdate](https://raw.githubusercontent.com/minerbomb16/Pngs/refs/heads/main/PubMessagesApp/MenuUpdate.png)
- Password change:
![MPasswordChangeenuUpdate](https://raw.githubusercontent.com/minerbomb16/Pngs/refs/heads/main/PubMessagesApp/PasswordChange.png)