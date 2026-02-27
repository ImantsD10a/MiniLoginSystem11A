import json
import os
import hashlib
import secrets
from datetime import datetime


# ---------- USER CLASS ----------
class User:
    def __init__(self, username, salt, password_hash, created_at=None, last_login=None):
        self.username = username
        self.salt = salt
        self.password_hash = password_hash
        self.created_at = created_at or datetime.now().isoformat()
        self.last_login = last_login

    def to_dict(self):
        return {
            "username": self.username,
            "salt": self.salt,
            "password_hash": self.password_hash,
            "created_at": self.created_at,
            "last_login": self.last_login
        }

    @staticmethod
    def from_dict(data):
        return User(
            data["username"],
            data["salt"],
            data["password_hash"],
            data["created_at"],
            data["last_login"]
        )


# ---------- STORAGE CLASS ----------
class Storage:
    FILE_NAME = "users.json"

    @staticmethod
    def load_users():
        if not os.path.exists(Storage.FILE_NAME):
            return {}
        with open(Storage.FILE_NAME, "r", encoding="utf-8") as f:
            data = json.load(f)
            return {u: User.from_dict(info) for u, info in data.items()}

    @staticmethod
    def save_users(users):
        with open(Storage.FILE_NAME, "w", encoding="utf-8") as f:
            json.dump({u: user.to_dict() for u, user in users.items()}, f, indent=4)


# ---------- AUTH SERVICE ----------
class AuthService:
    def __init__(self):
        self.users = Storage.load_users()

    def _hash_password(self, password, salt):
        return hashlib.sha256((password + salt).encode()).hexdigest()

    def register(self, username, password):
        if username in self.users:
            print("❌ Lietotājs jau eksistē.")
            return

        salt = secrets.token_hex(16)
        password_hash = self._hash_password(password, salt)
        user = User(username, salt, password_hash)
        self.users[username] = user
        Storage.save_users(self.users)
        print("✅ Reģistrācija veiksmīga.")

    def login(self, username, password):
        user = self.users.get(username)
        if not user:
            self._log(username, "FAIL")
            print("❌ Nepareizi dati.")
            return None

        password_hash = self._hash_password(password, user.salt)
        if password_hash == user.password_hash:
            user.last_login = datetime.now().isoformat()
            Storage.save_users(self.users)
            self._log(username, "SUCCESS")
            print("✅ Pieslēgšanās veiksmīga.")
            return user
        else:
            self._log(username, "FAIL")
            print("❌ Nepareizi dati.")
            return None

    def _log(self, username, status):
        with open("auth.log", "a", encoding="utf-8") as f:
            time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{time} | {username} | {status}\n")


# ---------- MAIN MENU ----------
def main():
    auth = AuthService()
    logged_user = None

    while True:
        if not logged_user:
            print("\n=== MINI LOGIN SYSTEM ===")
            print("1. Register")
            print("2. Login")
            print("3. Exit")
            choice = input("Izvēle: ")

            if choice == "1":
                u = input("Username: ")
                p = input("Password: ")
                auth.register(u, p)

            elif choice == "2":
                u = input("Username: ")
                p = input("Password: ")
                logged_user = auth.login(u, p)

            elif choice == "3":
                print("👋 Uz redzēšanos!")
                break

        else:
            print("\n--- PROFILS ---")
            print(f"Username: {logged_user.username}")
            print(f"Izveidots: {logged_user.created_at}")
            print(f"Pēdējā pieslēgšanās: {logged_user.last_login}")
            print("1. Logout")
            if input("Izvēle: ") == "1":
                logged_user = None


if __name__ == "__main__":
    main()
