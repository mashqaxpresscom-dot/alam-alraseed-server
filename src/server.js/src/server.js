
import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { initializeApp, cert } from "firebase-admin/app";
import { getDatabase } from "firebase-admin/database";

const app = express();

app.use(helmet());
app.use(express.json({ limit: "20kb" }));

app.use("/v1/auth", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false
}));

const serviceAccountText = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
const databaseURL = process.env.FIREBASE_DATABASE_URL;
const jwtSecret = process.env.JWT_SECRET;

if (!serviceAccountText || !databaseURL || !jwtSecret || jwtSecret.length < 32) {
  throw new Error("Server environment variables are missing or invalid");
}

const serviceAccount = JSON.parse(serviceAccountText);

initializeApp({
  credential: cert(serviceAccount),
  databaseURL
});

const db = getDatabase();

app.get("/", (req, res) => {
  res.json({
    service: "Alam Alraseed API",
    status: "running"
  });
});

app.post("/v1/auth/register", async (req, res) => {
  try {
    const phone = String(req.body.phone || "").replace(/\D/g, "");
    const password = String(req.body.password || "");

    if (phone.length < 7 || phone.length > 15) {
      return res.status(400).json({ error: "رقم الهاتف غير صحيح" });
    }

    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({ error: "كلمة المرور يجب أن تكون 8 أحرف على الأقل" });
    }

    const userRef = db.ref(`users/${phone}`);
    const existing = await userRef.get();

    if (existing.exists()) {
      return res.status(409).json({ error: "رقم الهاتف مسجل مسبقاً" });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = {
      phone,
      passwordHash,
      role: "customer",
      createdAt: Date.now(),
      active: true
    };

    await db.ref().update({
      [`users/${phone}`]: user,
      [`wallets/${phone}`]: {
        balance: 0,
        currency: "YER",
        updatedAt: Date.now()
      }
    });

    return res.status(201).json({
      message: "تم إنشاء الحساب بنجاح"
    });
  } catch (error) {
    console.error("Register error:", error.message);
    return res.status(500).json({ error: "تعذر إنشاء الحساب" });
  }
});

app.post("/v1/auth/login", async (req, res) => {
  try {
    const phone = String(req.body.phone || "").replace(/\D/g, "");
    const password = String(req.body.password || "");

    if (!phone || !password) {
      return res.status(400).json({ error: "أدخل رقم الهاتف وكلمة المرور" });
    }

    const snapshot = await db.ref(`users/${phone}`).get();

    if (!snapshot.exists()) {
      return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });
    }

    const user = snapshot.val();
    const valid = await bcrypt.compare(password, user.passwordHash);

    if (!valid || user.active === false) {
      return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });
    }

    const token = jwt.sign(
      { phone, role: user.role || "customer" },
      jwtSecret,
      { expiresIn: "7d" }
    );

    return res.json({
      message: "تم تسجيل الدخول",
      token,
      user: {
        phone,
        role: user.role || "customer"
      }
    });
  } catch (error) {
    console.error("Login error:", error.message);
    return res.status(500).json({ error: "تعذر تسجيل الدخول" });
  }
});

const port = process.env.PORT || 3000;

app.listen(port, "0.0.0.0", () => {
  console.log(`Alam Alraseed API listening on ${port}`);
});
