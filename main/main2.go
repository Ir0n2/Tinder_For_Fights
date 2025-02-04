package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"sync"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

// User struct
type User struct {
	Username string
	Password string
	Email    string
	Image    string // Profile picture path
}

// In-memory storage
var (
	users     = make(map[string]User)
	usersList []User // Slice for swiping
	mu        sync.Mutex
)

// Session store
var store = sessions.NewCookieStore([]byte("super-secret-key"))

// Templates
var templates = template.Must(template.ParseGlob("templates/*.html"))

// Email sender function
func sendEmail(fromUser User, toUser User) error {
	from := "golangbot699@gmail.com"
	password := "here lmao" // Replace with a real App Password

	// SMTP server configuration
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	// Email content
	subject := "You Got a Like from " + fromUser.Username
	body := fmt.Sprintf(
		"Subject: %s\n\n%s liked you!\nEmail: %s\nMessage: Hello World!",
		subject, fromUser.Username, fromUser.Email,
	)

	// Authentication
	auth := smtp.PlainAuth("", from, password, smtpHost)

	// Send email
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{toUser.Email}, []byte(body))
	return err
}

// Signup Handler
func signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		err := r.ParseMultipartForm(10 << 20) // 10MB limit
		if err != nil {
			http.Error(w, "File too large", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")
		email := r.FormValue("email")

		file, handler, err := r.FormFile("profile_pic")
		if err != nil {
			http.Error(w, "Error uploading image", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Save image
		imagePath := filepath.Join("uploads", handler.Filename)
		dst, err := os.Create(imagePath)
		if err != nil {
			http.Error(w, "Error saving file", http.StatusInternalServerError)
			return
		}
		defer dst.Close()
		io.Copy(dst, file)

		// Store user
		mu.Lock()
		newUser := User{Username: username, Password: password, Email: email, Image: imagePath}
		users[username] = newUser
		usersList = append(usersList, newUser)
		mu.Unlock()

		w.WriteHeader(http.StatusCreated)
		fmt.Fprintln(w, "User registered successfully")
	} else {
		templates.ExecuteTemplate(w, "signup.html", nil)
	}
}

// Login Handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var credentials User
		err := json.NewDecoder(r.Body).Decode(&credentials)
		if err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Validate credentials
		mu.Lock()
		user, exists := users[credentials.Username]
		mu.Unlock()

		if !exists || user.Password != credentials.Password {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// Create session
		session, _ := store.Get(r, "session")
		session.Values["authenticated"] = true
		session.Values["user"] = credentials.Username
		session.Save(r, w)

		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Login successful")
	} else {
		templates.ExecuteTemplate(w, "login.html", nil)
	}
}

// Dashboard Handler
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")

	// Check authentication
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	username := session.Values["user"].(string)
	mu.Lock()
	loggedInUser, exists := users[username]
	mu.Unlock()

	if !exists {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	templates.ExecuteTemplate(w, "dashboard.html", struct {
		LoggedInUser User
		Users        []User
	}{
		LoggedInUser: loggedInUser,
		Users:        usersList,
	})
}

// Like Handler
func likeHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")

	// Check authentication
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Get sender & liked user
	fromUsername := session.Values["user"].(string)
	likedUsername := r.URL.Query().Get("username")

	mu.Lock()
	fromUser, fromExists := users[fromUsername]
	likedUser, likedExists := users[likedUsername]
	mu.Unlock()

	if !fromExists || !likedExists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Send email with sender details
	err := sendEmail(fromUser, likedUser)
	if err != nil {
		http.Error(w, "Failed to send email", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Liked user and email sent!")
}

// Logout Handler
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")

	// Destroy session
	session.Options.MaxAge = -1
	session.Save(r, w)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Logged out")
}

func main() {
	// Create uploads directory
	os.Mkdir("uploads", os.ModePerm)

	r := mux.NewRouter()
	r.HandleFunc("/signup", signupHandler)
	r.HandleFunc("/login", loginHandler)
	r.HandleFunc("/dashboard", dashboardHandler)
	r.HandleFunc("/like", likeHandler).Methods("GET")
	r.HandleFunc("/logout", logoutHandler)

	// Serve uploaded images
	r.PathPrefix("/uploads/").Handler(http.StripPrefix("/uploads/", http.FileServer(http.Dir("uploads/"))))

	log.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

