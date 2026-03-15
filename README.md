# 🎵 MusicGlow

> A Good platform for listening to Music 🎵🎶

[![Live Demo](https://img.shields.io/badge/Live%20Demo-MusicGlow-brightgreen?style=flat-square)](https://music-glow.vercel.app)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.0+-black?style=flat-square&logo=flask)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

## 📋 Overview

MusicGlow is a full-featured music streaming and sharing platform built with Flask. It allows users to upload, listen, and discover music with features like user authentication, favorites, likes, and recent playback tracking.

## ✨ Features

- 🎧 **Music Streaming** - Upload and play MP3 files
- 👤 **User Authentication** - Secure sign-up and login with password hashing
- 🔐 **Google OAuth Integration** - Quick login with Google
- ❤️ **Like & Favorite** - Mark your favorite songs
- 📜 **Recent Tracks** - Track recently played songs
- 👨‍💼 **Admin Dashboard** - Manage users and content
- 📧 **Email OTP Verification** - Secure email-based authentication
- 🛡️ **Role-Based Access** - Different permission levels for users and admins

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- SQLite3 (comes with Python)
- Gmail account for email notifications

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Abhishekverma3205/MusicGlow.git
   cd MusicGlow
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set environment variables**
   Create a `.env` file in the root directory:
   ```env
   SECRET_KEY=your-secret-key-here
   GOOGLE_CLIENT_ID=your-google-client-id
   GOOGLE_CLIENT_SECRET=your-google-client-secret
   EMAIL_ADDRESS=your-email@gmail.com
   EMAIL_PASSWORD=your-app-password
   ```

5. **Initialize the database**
   ```bash
   python app.py
   ```

6. **Run the application**
   ```bash
   python app.py
   ```
   The app will be available at `http://localhost:5000`

## 📦 Dependencies

- **Flask** - Web framework
- **gunicorn** - WSGI HTTP Server
- **authlib** - OAuth 2.0 authentication library
- **Werkzeug** - Security utilities
- **requests** - HTTP library

See `requirements.txt` for complete dependencies.

## 📁 Project Structure

```
MusicGlow/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── Procfile           # Deployment configuration
├── static/
│   └── uploads/       # User-uploaded music files
├── templates/         # HTML templates
└── Musicglow.db       # SQLite database
```

## 🗄️ Database Schema

### Users Table
- `id` - Primary key
- `username` - Unique username
- `password` - Hashed password
- `role` - User role (user/admin)

### Songs Table
- `id` - Primary key
- `filename` - Song filename
- `uploader` - Username of uploader

### Likes Table
- Tracks which users liked which songs
- Unique constraint on (user, song_id)

### Favorites Table
- Stores user favorite songs
- Unique constraint on (user, song_id)

### Recent Table
- Tracks recently played songs per user

## 🔑 Key Features Explained

### Authentication
- Username/password registration and login
- Google OAuth for quick authentication
- Email OTP verification system
- Secure password hashing with Werkzeug

### Music Management
- Upload MP3 files (stored in `/static/uploads`)
- Display all available songs
- Track upload metadata

### User Interactions
- Like/Unlike songs
- Add/Remove from favorites
- View recent playback history
- Different features for admins and regular users

## 🔐 Security Features

- Password hashing using `werkzeug.security`
- OAuth 2.0 integration via Authlib
- Session-based authentication
- CSRF protection via Flask sessions
- Environment variable configuration for sensitive data

## 🌐 Deployment

The project is configured for deployment on platforms like Heroku using the included `Procfile`.

### Deploy to Heroku
```bash
heroku create your-app-name
git push heroku main
```

## 🛠️ API Routes

Core routes include:
- `/` - Home page (requires login)
- `/login` - User login
- `/register` - User registration
- `/upload` - Upload new music
- `/like` - Like a song
- `/favorite` - Add to favorites
- `/recent` - View recent plays

## 🤝 Contributing

Contributions are welcome! Here's how to contribute:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is open source and available under the MIT License.

## 👨‍💻 Author

**Abhishek Verma**
- GitHub: [@Abhishekverma3205](https://github.com/Abhishekverma3205)

## 🙏 Acknowledgments

- Flask community for the amazing web framework
- Authlib for OAuth integration
- All contributors and users

## 📞 Support

For support, email your concerns or open an issue on the [GitHub repository](https://github.com/Abhishekverma3205/MusicGlow/issues).

---

**[View Live Demo](https://music-glow.vercel.app)** | **[Report Bug](https://github.com/Abhishekverma3205/MusicGlow/issues)** | **[Request Feature](https://github.com/Abhishekverma3205/MusicGlow/issues)**