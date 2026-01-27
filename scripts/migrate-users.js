const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const USERS_PATH = path.join(__dirname, "..", "data", "users.json");

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 120000, 64, "sha512").toString("hex");
}

function migrate() {
  const raw = fs.readFileSync(USERS_PATH, "utf-8");
  const users = JSON.parse(raw);
  let changed = 0;

  for (const user of users) {
    if (user.passwordHash && user.passwordSalt) continue;
    if (!user.password) continue;
    const salt = crypto.randomBytes(16).toString("hex");
    user.passwordSalt = salt;
    user.passwordHash = hashPassword(user.password, salt);
    delete user.password;
    changed += 1;
  }

  if (changed > 0) {
    fs.writeFileSync(USERS_PATH, JSON.stringify(users, null, 2), "utf-8");
  }

  console.log(`Migrated users: ${changed}`);
}

migrate();
