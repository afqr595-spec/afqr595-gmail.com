// ===== server.js: website ka backend =====
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"))); // public folder ke pages dikhao

const SECRET = process.env.JWT_SECRET || "isay-baad-mein-badal-dena";
const DB_FILE = path.join(__dirname, "users.json"); // users yahan save honge

function getUsers() {
  return fs.existsSync(DB_FILE) ? JSON.parse(fs.readFileSync(DB_FILE, "utf8")) : [];
}
function saveUsers(users) {
  fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
}

// Jin users ka OTP abhi verify hona baqi hai (memory mein)
const pending = new Map();

// Step 1: signup ki detail lo, OTP banao
app.post("/api/send-otp", async (req, res) => {
  const { name, email, phone, pass } = req.body;
  if (!name || !email || !phone || !pass) return res.status(400).json({ error: "Saare fields bharna zaroori hain." });
  if (!String(email).includes("@")) return res.status(400).json({ error: "Sahi email likhein." });
  if (!/^[0-9+]{10,14}$/.test(phone)) return res.status(400).json({ error: "Sahi phone number likhein." });
  if (pass.length < 6) return res.status(400).json({ error: "Password kam az kam 6 characters ka ho." });

  const cleanEmail = String(email).trim().toLowerCase();
  if (getUsers().some(u => u.email === cleanEmail)) return res.status(400).json({ error: "Ye email pehle se use ho chuki hai." });

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const passHash = await bcrypt.hash(pass, 10); // password hash ho gaya
  pending.set(cleanEmail, {
    user: { name: name.trim(), email: cleanEmail, phone, passHash, created: new Date().toLocaleDateString() },
    code, expires: Date.now() + 5 * 60 * 1000, tries: 0
  });

  console.log("OTP for", cleanEmail, "=", code);
  // Demo: code wapas bhej rahe hain. Asli website mein yahan SMS bheja jata hai.
  res.json({ demoCode: code, phone });
});

// Step 2: OTP check karo, phir user save karo
app.post("/api/verify-otp", (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const p = pending.get(email);
  if (!p) return res.status(400).json({ error: "Pehle signup karein." });
  if (Date.now() > p.expires) { pending.delete(email); return res.status(400).json({ error: "Code expire ho gaya. Naya code bhejein." }); }
  if (++p.tries > 5) { pending.delete(email); return res.status(429).json({ error: "Bohat koshishein. Dobara signup karein." }); }
  if (String(req.body.code) !== p.code) return res.status(400).json({ error: "Code galat hai." });

  const users = getUsers();
  users.push(p.user);
  saveUsers(users);
  pending.delete(email);
  res.json({ ok: true });
});

// Login
app.post("/api/login", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const user = getUsers().find(u => u.email === email);
  const ok = user && await bcrypt.compare(req.body.pass || "", user.passHash);
  if (!ok) return res.status(401).json({ error: "Email ya password galat hai." });

  const token = jwt.sign({ email }, SECRET, { expiresIn: "7d" });
  const { passHash, ...safeUser } = user; // password hash wapas nahi bhejte
  res.json({ token, user: safeUser });
});

// Dashboard ka data (sirf login user ke liye)
app.get("/api/me", (req, res) => {
  try {
    const token = (req.headers.authorization || "").replace("Bearer ", "");
    const { email } = jwt.verify(token, SECRET);
    const user = getUsers().find(u => u.email === email);
    if (!user) throw new Error("no user");
    const { passHash, ...safeUser } = user;
    res.json({ user: safeUser });
  } catch (e) {
    res.status(401).json({ error: "Dobara login karein." });
  }
});

app.listen(3000, () => console.log("Website chal rahi hai: http://localhost:3000"));
