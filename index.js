/**
 * ================================================================
 *  ESPORTS TOURNAMENT BACKEND — PayU Edition
 *  Stack: Node.js + Express + Firebase Admin + Firestore + PayU
 *  Deploy: Vercel / Render / Railway
 * ================================================================
 *
 *  ENV VARS (Vercel Dashboard → Settings → Environment Variables):
 *  ---------------------------------------------------------------
 *  FIREBASE_PROJECT_ID       = e-sports-de5b9
 *  FIREBASE_CLIENT_EMAIL     = firebase-adminsdk-fbsvc@e-sports-de5b9.iam.gserviceaccount.com
 *  FIREBASE_PRIVATE_KEY      = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC9CVebE58nDxVX...\n-----END PRIVATE KEY-----\n"
 *
 *  PAYU_MERCHANT_KEY         = 3yS7S2
 *  PAYU_MERCHANT_SALT        = M7ByaWB1vKr2hcRLzmFCeaEH8BSmLUz1
 *  PAYU_ENV                  = test   (or production)
 *
 *  BACKEND_BASE_URL          = https://your-vercel-app.vercel.app
 *  NODE_ENV                  = production
 * ================================================================
 */

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const admin = require("firebase-admin");
const axios = require("axios");

/* ================================================================
   1) FIREBASE ADMIN INIT
   ================================================================ */
function initFirebase() {
  if (admin.apps.length) return admin.app();

  const projectId = process.env.FIREBASE_PROJECT_ID || "e-sports-de5b9";
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKeyRaw = process.env.FIREBASE_PRIVATE_KEY;

  if (!clientEmail || !privateKeyRaw) {
    console.error(
      "❌ FIREBASE_CLIENT_EMAIL or FIREBASE_PRIVATE_KEY missing in env vars"
    );
    throw new Error("Missing Firebase credentials in environment variables");
  }

  let privateKey = privateKeyRaw.trim();
  if (privateKey.startsWith('"') && privateKey.endsWith('"')) {
    privateKey = privateKey.slice(1, -1);
  }
  privateKey = privateKey.replace(/\\n/g, "\n");

  admin.initializeApp({
    credential: admin.credential.cert({
      projectId,
      clientEmail,
      privateKey,
    }),
  });

  console.log("✅ Firebase Admin initialized →", projectId);
  return admin.app();
}

initFirebase();

const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;

/* ================================================================
   2) EXPRESS APP
   ================================================================ */
const app = express();
app.use(cors({ origin: true }));

// PayU webhook uses form-urlencoded (or JSON). Parse both.
app.use(
  "/webhook/payu",
  express.urlencoded({ extended: true, limit: "2mb" }),
  express.json({ limit: "2mb" })
);

// JSON parser for all other routes
app.use(express.json({ limit: "2mb" }));

/* ================================================================
   3) CONSTANTS
   ================================================================ */
const PAYU_BASE =
  process.env.PAYU_ENV === "production"
    ? "https://secure.payu.in"
    : "https://test.payu.in";

const PAYU_MERCHANT_KEY = process.env.PAYU_MERCHANT_KEY || "";
const PAYU_MERCHANT_SALT = process.env.PAYU_MERCHANT_SALT || "";

const DAILY_REWARD_AMOUNT = Number(process.env.DAILY_REWARD_AMOUNT || 2);
const DAILY_REWARD_COOLDOWN_MS = 24 * 60 * 60 * 1000;

const XP_PER_KILL = 10;
const XP_PER_RANK_BASE = 50;

/* ================================================================
   4) UTILS
   ================================================================ */
const now = () => new Date();
const round2 = (n) => Math.round((Number(n) + Number.EPSILON) * 100) / 100;
const safeStr = (v, max = 500) =>
  typeof v === "string" ? v.trim().slice(0, max) : "";
const isPosNumber = (v) => typeof v === "number" && isFinite(v) && v > 0;

function generateReferralCode(prefix = "APP") {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < 6; i++)
    out += chars[Math.floor(Math.random() * chars.length)];
  return `${prefix}${out}`;
}

/* ================================================================
   5) AUTH MIDDLEWARE
   ================================================================ */
async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const match = header.match(/^Bearer\s+(.+)$/i);
    if (!match) return res.status(401).json({ message: "Missing auth token" });

    const decoded = await admin.auth().verifyIdToken(match[1]);
    req.uid = decoded.uid;
    req.tokenEmail = decoded.email || "";
    next();
  } catch (e) {
    console.error("auth error:", e.message);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

/* ================================================================
   6) PAYU HELPERS
   ================================================================ */
/**
 * PayU forward hash (for creating payment request)
 * Formula:
 * sha512(key|txnid|amount|productinfo|firstname|email|udf1|udf2|udf3|udf4|udf5||||||SALT)
 */
function payuForwardHash({
  key,
  txnid,
  amount,
  productinfo,
  firstname,
  email,
  udf1 = "",
  udf2 = "",
  udf3 = "",
  udf4 = "",
  udf5 = "",
  salt,
}) {
  const str = [
    key,
    txnid,
    amount,
    productinfo,
    firstname,
    email,
    udf1,
    udf2,
    udf3,
    udf4,
    udf5,
    "",
    "",
    "",
    "",
    "",
    salt,
  ].join("|");
  return crypto.createHash("sha512").update(str).digest("hex");
}

/**
 * PayU reverse hash (for verifying callback / webhook)
 * Formula:
 * sha512(SALT|status||||||udf5|udf4|udf3|udf2|udf1|email|firstname|productinfo|amount|txnid|key)
 */
function payuReverseHash({
  status,
  udf5 = "",
  udf4 = "",
  udf3 = "",
  udf2 = "",
  udf1 = "",
  email,
  firstname,
  productinfo,
  amount,
  txnid,
  key,
  salt,
}) {
  const str = [
    salt,
    status,
    "",
    "",
    "",
    "",
    "",
    udf5,
    udf4,
    udf3,
    udf2,
    udf1,
    email,
    firstname,
    productinfo,
    amount,
    txnid,
    key,
  ].join("|");
  return crypto.createHash("sha512").update(str).digest("hex");
}

/**
 * PayU additional charges hash (only if using PayU's charges)
 * We are NOT using additional charges here, but kept for completeness.
 */
function payuVerifyReverseHash(params) {
  const expected = payuReverseHash({
    status: params.status || "",
    udf5: params.udf5 || "",
    udf4: params.udf4 || "",
    udf3: params.udf3 || "",
    udf2: params.udf2 || "",
    udf1: params.udf1 || "",
    email: params.email || "",
    firstname: params.firstname || "",
    productinfo: params.productinfo || "",
    amount: params.amount || "",
    txnid: params.txnid || "",
    key: params.key || PAYU_MERCHANT_KEY,
    salt: PAYU_MERCHANT_SALT,
  });
  return expected === (params.hash || "");
}

/* ================================================================
   7) HEALTH / ROOT
   ================================================================ */
app.get("/", (_req, res) =>
  res.json({
    ok: true,
    service: "esports-backend-payu",
    projectId: "e-sports-de5b9",
    payuEnv: process.env.PAYU_ENV || "test",
    timestamp: new Date().toISOString(),
  })
);

app.get("/healthz", (_req, res) => res.json({ ok: true }));

/* ================================================================
   8) AUTH — SIGNUP
   ================================================================ */
app.post("/auth/signup", requireAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const username = safeStr(req.body.username, 60);
    const email = safeStr(req.body.email || req.tokenEmail, 120);
    const referralCode = safeStr(req.body.referralCode, 20);

    if (!username) return res.status(400).json({ message: "username required" });

    const ref = db.collection("users").doc(uid);
    const snap = await ref.get();
    if (snap.exists) {
      return res.json({ ok: true, alreadyExists: true, user: snap.data() });
    }

    let finalRefCode = null;
    for (let i = 0; i < 5; i++) {
      const candidate = generateReferralCode();
      const q = await db
        .collection("users")
        .where("referralCode", "==", candidate)
        .limit(1)
        .get();
      if (q.empty) {
        finalRefCode = candidate;
        break;
      }
    }
    if (!finalRefCode) finalRefCode = generateReferralCode("X");

    let referredBy = null;
    if (referralCode) {
      const q = await db
        .collection("users")
        .where("referralCode", "==", referralCode)
        .limit(1)
        .get();
      if (!q.empty) referredBy = q.docs[0].id;
    }

    const data = {
      uid,
      username,
      email,
      wallet: 0,
      totalXP: 0,
      joinedMatches: [],
      referralCode: finalRefCode,
      referredBy,
      matchesPlayed: 0,
      totalKills: 0,
      dailyStreak: 0,
      lastDailyRewardAt: null,
      isVIP: false,
      createdAt: now(),
    };
    await ref.set(data);
    return res.json({ ok: true, user: data });
  } catch (e) {
    console.error("signup error:", e);
    return res.status(500).json({ message: "signup failed" });
  }
});

/* ================================================================
   9) WALLET — CREATE PAYU ORDER
   ================================================================ */
app.post("/wallet/createOrder", requireAuth, async (req, res) => {
  try {
    const amount = round2(Number(req.body.amount));
    if (!isPosNumber(amount) || amount < 1 || amount > 100000) {
      return res.status(400).json({ message: "Invalid amount (1–100000)" });
    }

    const userSnap = await db.collection("users").doc(req.uid).get();
    if (!userSnap.exists)
      return res.status(404).json({ message: "User not found" });

    const user = userSnap.data();

    // unique txnid (max 25 chars in PayU, alphanumeric)
    const txnid = `T${Date.now()}${crypto
      .randomBytes(2)
      .toString("hex")}`.slice(0, 25);

    const firstname = safeStr(user.username || "Player", 60);
    const email = safeStr(user.email || "player@example.com", 120);
    const productinfo = `Wallet Topup ₹${amount}`;

    const backendUrl = process.env.BACKEND_BASE_URL || "";
    const surl = `${backendUrl}/wallet/payu/success`;
    const furl = `${backendUrl}/wallet/payu/failure`;

    const hash = payuForwardHash({
      key: PAYU_MERCHANT_KEY,
      txnid,
      amount: String(amount),
      productinfo,
      firstname,
      email,
      udf1: req.uid, // Firebase UID
      udf2: "",      // reserved
      udf3: "",
      udf4: "",
      udf5: "",
      salt: PAYU_MERCHANT_SALT,
    });

    // persist pending transaction — wallet NOT touched
    await db.collection("transactions").doc(txnid).set({
      transactionId: txnid,
      orderId: txnid,
      userId: req.uid,
      type: "DEPOSIT",
      amount,
      status: "PENDING",
      provider: "PAYU",
      createdAt: now(),
      updatedAt: now(),
    });

    // Return PayU params — client will POST these to PAYU_BASE + "/_payment"
    return res.json({
      ok: true,
      txnid,
      amount: String(amount),
      payuUrl: `${PAYU_BASE}/_payment`,
      params: {
        key: PAYU_MERCHANT_KEY,
        txnid,
        amount: String(amount),
        productinfo,
        firstname,
        email,
        phone: "9999999999",
        surl,
        furl,
        hash,
        udf1: req.uid,
        udf2: "",
        udf3: "",
        udf4: "",
        udf5: "",
        service_provider: "payu_paisa",
      },
    });
  } catch (e) {
    console.error("createOrder error:", e?.response?.data || e.message);
    return res
      .status(500)
      .json({ message: "Failed to create order", detail: e.message });
  }
});

/* ================================================================
   10) PAYU — SUCCESS REDIRECT (informational, DOES NOT CREDIT WALLET)
   ================================================================ */
app.post("/wallet/payu/success", express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const params = req.body || {};
    const txnid = safeStr(params.txnid, 60);

    // Even on surl, we do NOT trust client data — wallet is credited ONLY via webhook.
    // We just verify hash (optional informational) and redirect to app.
    return res.redirect(
      `${process.env.BACKEND_BASE_URL || ""}/?payu_status=success&txnid=${encodeURIComponent(txnid)}`
    );
  } catch (e) {
    return res.redirect(
      `${process.env.BACKEND_BASE_URL || ""}/?payu_status=error`
    );
  }
});

/* ================================================================
   11) PAYU — FAILURE REDIRECT (informational)
   ================================================================ */
app.post("/wallet/payu/failure", express.urlencoded({ extended: true }), async (req, res) => {
  const params = req.body || {};
  const txnid = safeStr(params.txnid, 60);
  return res.redirect(
    `${process.env.BACKEND_BASE_URL || ""}/?payu_status=failure&txnid=${encodeURIComponent(txnid)}`
  );
});

/* ================================================================
   12) PAYU WEBHOOK — ONLY PLACE WALLET IS CREDITED
   ================================================================ */
app.post("/webhook/payu", async (req, res) => {
  try {
    const params = req.body || {};
    const txnid = safeStr(params.txnid, 60);
    const status = safeStr(params.status, 30);
    const amount = Number(params.amount);
    const mihpayid = safeStr(params.mihpayid, 60);

    if (!txnid) return res.status(400).json({ message: "Missing txnid" });

    // Verify reverse hash
    if (!payuVerifyReverseHash(params)) {
      console.warn("⚠️ PayU webhook hash verification failed", { txnid });
      return res.status(401).json({ message: "Invalid hash" });
    }

    const txnRef = db.collection("transactions").doc(txnid);

    await db.runTransaction(async (tx) => {
      const txnSnap = await tx.get(txnRef);
      if (!txnSnap.exists) return; // unknown txn — ignore (idempotent)
      const txn = txnSnap.data();

      // idempotency
      if (txn.status === "SUCCESS" || txn.status === "FAILED") return;

      // amount sanity check
      if (Math.abs(Number(txn.amount) - amount) > 0.01) {
        tx.update(txnRef, {
          status: "FAILED",
          reason: "AMOUNT_MISMATCH",
          updatedAt: now(),
        });
        return;
      }

      const success = status === "success" || status === "SUCCESS";

      if (success) {
        const userRef = db.collection("users").doc(txn.userId);
        const userSnap = await tx.get(userRef);
        if (!userSnap.exists) {
          tx.update(txnRef, {
            status: "FAILED",
            reason: "USER_NOT_FOUND",
            updatedAt: now(),
          });
          return;
        }
        const currentWallet = Number(userSnap.data().wallet || 0);
        const newWallet = round2(currentWallet + Number(txn.amount));

        tx.update(userRef, { wallet: newWallet });
        tx.update(txnRef, {
          status: "SUCCESS",
          mihpayid: mihpayid || null,
          updatedAt: now(),
        });
      } else {
        tx.update(txnRef, {
          status: "FAILED",
          reason: status || "UNKNOWN",
          mihpayid: mihpayid || null,
          updatedAt: now(),
        });
      }
    });

    return res.json({ ok: true });
  } catch (e) {
    console.error("webhook error:", e);
    return res.status(500).json({ message: "webhook failed" });
  }
});

/* ================================================================
   13) MATCH — JOIN
   ================================================================ */
app.post("/match/join", requireAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const matchId = safeStr(req.body.matchId, 120);
    const gameUids = Array.isArray(req.body.gameUids) ? req.body.gameUids : [];

    if (!matchId) return res.status(400).json({ message: "matchId required" });
    if (![1, 2, 4].includes(gameUids.length)) {
      return res
        .status(400)
        .json({ message: "gameUids must contain 1, 2, or 4 entries" });
    }

    const cleanedGameUids = [];
    for (const g of gameUids) {
      const s = safeStr(String(g), 40);
      if (!s) return res.status(400).json({ message: "Invalid gameUid" });
      if (cleanedGameUids.includes(s)) {
        return res.status(400).json({ message: "Duplicate gameUid in request" });
      }
      cleanedGameUids.push(s);
    }

    const result = await db.runTransaction(async (tx) => {
      const matchRef = db.collection("matches").doc(matchId);
      const userRef = db.collection("users").doc(uid);

      const [matchSnap, userSnap] = await Promise.all([
        tx.get(matchRef),
        tx.get(userRef),
      ]);

      if (!matchSnap.exists) throw { code: 404, message: "Match not found" };
      if (!userSnap.exists) throw { code: 404, message: "User not found" };

      const match = matchSnap.data();
      const user = userSnap.data();

      if (match.status !== "upcoming")
        throw { code: 409, message: "Match is not open for joining" };

      const mode = match.mode;
      const expectedPlayers =
        mode === "SOLO" ? 1 : mode === "DUO" ? 2 : mode === "SQUAD" ? 4 : null;
      if (!expectedPlayers)
        throw { code: 400, message: "Invalid match mode" };
      if (cleanedGameUids.length !== expectedPlayers) {
        throw {
          code: 400,
          message: `Mode ${mode} requires exactly ${expectedPlayers} gameUid(s)`,
        };
      }

      const maxPlayers = Number(match.maxPlayers || 0);
      const joinedCount = Number(match.joinedCount || 0);
      if (maxPlayers > 0 && joinedCount + expectedPlayers > maxPlayers) {
        throw { code: 409, message: "Not enough slots" };
      }

      const entryFee = Number(match.entryFee || 0);
      const wallet = Number(user.wallet || 0);
      if (wallet < entryFee)
        throw { code: 402, message: "Insufficient wallet balance" };

      const teamRef = matchRef.collection("teams").doc(uid);
      const teamSnap = await tx.get(teamRef);
      if (teamSnap.exists)
        throw { code: 409, message: "You have already joined this match" };

      const teamsSnapTx = await tx.get(matchRef.collection("teams"));
      for (const d of teamsSnapTx.docs) {
        const data = d.data();
        const existing = Array.isArray(data.gameUids) ? data.gameUids : [];
        for (const g of cleanedGameUids) {
          if (existing.includes(g))
            throw { code: 409, message: `gameUid ${g} already registered` };
        }
      }

      const newWallet = round2(wallet - entryFee);
      tx.update(userRef, {
        wallet: newWallet,
        joinedMatches: FieldValue.arrayUnion(matchId),
      });

      tx.set(teamRef, {
        ownerUid: uid,
        ownerUsername: user.username || "Player",
        gameUids: cleanedGameUids,
        mode,
        matchId,
        createdAt: now(),
      });

      tx.update(matchRef, { joinedCount: joinedCount + expectedPlayers });

      const txnRef = db.collection("transactions").doc();
      tx.set(txnRef, {
        transactionId: txnRef.id,
        userId: uid,
        type: "MATCH_JOIN",
        matchId,
        amount: entryFee,
        status: "SUCCESS",
        timestamp: now(),
      });

      return { entryFee, newWallet, matchId };
    });

    return res.json({ ok: true, ...result });
  } catch (e) {
    if (e && e.code && e.message)
      return res.status(e.code).json({ message: e.message });
    console.error("match join error:", e);
    return res.status(500).json({ message: "Failed to join match" });
  }
});

/* ================================================================
   14) REWARDS — DAILY
   ================================================================ */
app.post("/rewards/daily", requireAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const userRef = db.collection("users").doc(uid);

    const result = await db.runTransaction(async (tx) => {
      const snap = await tx.get(userRef);
      if (!snap.exists) throw { code: 404, message: "User not found" };
      const user = snap.data();

      const last = user.lastDailyRewardAt
        ? new Date(user.lastDailyRewardAt).getTime()
        : 0;
      const current = Date.now();
      if (last && current - last < DAILY_REWARD_COOLDOWN_MS) {
        const remaining = DAILY_REWARD_COOLDOWN_MS - (current - last);
        throw {
          code: 429,
          message: `Daily reward not ready. Try again in ${Math.ceil(
            remaining / 60000
          )} min`,
        };
      }

      const newWallet = round2(Number(user.wallet || 0) + DAILY_REWARD_AMOUNT);
      const newStreak = Number(user.dailyStreak || 0) + 1;

      tx.update(userRef, {
        wallet: newWallet,
        dailyStreak: newStreak,
        lastDailyRewardAt: now(),
      });

      const txnRef = db.collection("transactions").doc();
      tx.set(txnRef, {
        transactionId: txnRef.id,
        userId: uid,
        type: "DAILY_REWARD",
        amount: DAILY_REWARD_AMOUNT,
        status: "SUCCESS",
        timestamp: now(),
      });

      return {
        wallet: newWallet,
        dailyStreak: newStreak,
        amount: DAILY_REWARD_AMOUNT,
      };
    });

    return res.json({ ok: true, ...result });
  } catch (e) {
    if (e && e.code && e.message)
      return res.status(e.code).json({ message: e.message });
    console.error("daily reward error:", e);
    return res.status(500).json({ message: "Failed to claim daily reward" });
  }
});

/* ================================================================
   15) WALLET — WITHDRAW
   ================================================================ */
app.post("/wallet/withdraw", requireAuth, async (req, res) => {
  try {
    const uid = req.uid;
    const amount = round2(Number(req.body.amount));
    const upiId = safeStr(req.body.upiId, 80);

    if (!isPosNumber(amount) || amount < 10) {
      return res.status(400).json({ message: "Minimum withdrawal is ₹10" });
    }
    if (!upiId || !/^[\w.\-]+@[\w.\-]+$/.test(upiId)) {
      return res.status(400).json({ message: "Invalid UPI ID" });
    }

    const userRef = db.collection("users").doc(uid);

    const result = await db.runTransaction(async (tx) => {
      const snap = await tx.get(userRef);
      if (!snap.exists) throw { code: 404, message: "User not found" };
      const user = snap.data();

      const wallet = Number(user.wallet || 0);
      if (wallet < amount)
        throw { code: 402, message: "Insufficient wallet balance" };

      const newWallet = round2(wallet - amount);
      tx.update(userRef, { wallet: newWallet });

      const txnRef = db.collection("transactions").doc();
      tx.set(txnRef, {
        transactionId: txnRef.id,
        userId: uid,
        type: "WITHDRAW",
        amount,
        upiId,
        status: "PENDING",
        timestamp: now(),
      });

      return { newWallet, txnId: txnRef.id, amount };
    });

    return res.json({ ok: true, ...result });
  } catch (e) {
    if (e && e.code && e.message)
      return res.status(e.code).json({ message: e.message });
    console.error("withdraw error:", e);
    return res.status(500).json({ message: "Failed to request withdrawal" });
  }
});

/* ================================================================
   16) ADMIN — DISTRIBUTE PRIZE
   ================================================================ */
function calcRankPrize(rankPrizes, rank) {
  if (!rankPrizes || typeof rankPrizes !== "object") return 0;
  return Number(rankPrizes[String(rank)] || 0);
}

app.post("/admin/match/distribute", requireAuth, async (req, res) => {
  try {
    const matchId = safeStr(req.body.matchId, 120);
    const gameUid = safeStr(String(req.body.gameUid || ""), 40);
    const rank = Number(req.body.rank);
    const kills = Number(req.body.kills || 0);

    if (!matchId) return res.status(400).json({ message: "matchId required" });
    if (!gameUid) return res.status(400).json({ message: "gameUid required" });
    if (!Number.isFinite(rank) || rank < 1)
      return res.status(400).json({ message: "rank must be >= 1" });
    if (!Number.isFinite(kills) || kills < 0)
      return res.status(400).json({ message: "kills must be >= 0" });

    const matchRef = db.collection("matches").doc(matchId);

    const result = await db.runTransaction(async (tx) => {
      const matchSnap = await tx.get(matchRef);
      if (!matchSnap.exists) throw { code: 404, message: "Match not found" };
      const match = matchSnap.data();

      const teamsSnap = await tx.get(matchRef.collection("teams"));
      let teamDoc = null;
      for (const d of teamsSnap.docs) {
        const data = d.data();
        if (Array.isArray(data.gameUids) && data.gameUids.includes(gameUid)) {
          teamDoc = { id: d.id, data };
          break;
        }
      }
      if (!teamDoc) throw { code: 404, message: "No team owns this gameUid" };

      const ownerUid = teamDoc.data.ownerUid;
      if (!ownerUid) throw { code: 500, message: "Team missing ownerUid" };

      const distributedMap = match.prizeDistributed || {};
      const key = `${teamDoc.id}:${gameUid}`;
      if (distributedMap[key]) {
        throw {
          code: 409,
          message: "Prize already distributed for this gameUid",
        };
      }

      const perKillRate = Number(match.perKillRate || 0);
      const rankPrize = calcRankPrize(match.rankPrizes, rank);
      const killPrize = perKillRate * kills;
      const totalPrize = round2(killPrize + rankPrize);

      const xp = kills * XP_PER_KILL + Math.max(0, 10 - rank) * XP_PER_RANK_BASE;

      const ownerRef = db.collection("users").doc(ownerUid);
      const ownerSnap = await tx.get(ownerRef);
      if (!ownerSnap.exists)
        throw { code: 404, message: "Team owner not found" };
      const owner = ownerSnap.data();

      const newWallet = round2(Number(owner.wallet || 0) + totalPrize);
      const newXP = Number(owner.totalXP || 0) + xp;
      const newKills = Number(owner.totalKills || 0) + kills;
      const newMatchesPlayed = Number(owner.matchesPlayed || 0) + 1;

      tx.update(ownerRef, {
        wallet: newWallet,
        totalXP: newXP,
        totalKills: newKills,
        matchesPlayed: newMatchesPlayed,
      });

      const update = {};
      update[`prizeDistributed.${key}`] = true;
      tx.update(matchRef, update);

      const txnRef = db.collection("transactions").doc();
      tx.set(txnRef, {
        transactionId: txnRef.id,
        userId: ownerUid,
        type: "PRIZE",
        matchId,
        gameUid,
        rank,
        kills,
        amount: totalPrize,
        xpAwarded: xp,
        status: "SUCCESS",
        timestamp: now(),
      });

      return { ownerUid, totalPrize, xpAwarded: xp, newWallet, newXP };
    });

    return res.json({ ok: true, ...result });
  } catch (e) {
    if (e && e.code && e.message)
      return res.status(e.code).json({ message: e.message });
    console.error("distribute error:", e);
    return res.status(500).json({ message: "Failed to distribute prize" });
  }
});

/* ================================================================
   17) ORDER STATUS (polling)
   ================================================================ */
app.get("/wallet/orderStatus", requireAuth, async (req, res) => {
  try {
    const orderId = safeStr(req.query.orderId, 120);
    if (!orderId) return res.status(400).json({ message: "orderId required" });

    const snap = await db.collection("transactions").doc(orderId).get();
    if (!snap.exists)
      return res.status(404).json({ message: "Order not found" });

    const txn = snap.data();
    if (txn.userId !== req.uid)
      return res.status(403).json({ message: "Forbidden" });

    let status = "pending";
    if (txn.status === "SUCCESS") status = "credited";
    else if (txn.status === "FAILED") status = "failed";

    return res.json({ ok: true, status, amount: txn.amount });
  } catch (e) {
    console.error("orderStatus error:", e);
    return res.status(500).json({ message: "Failed to fetch status" });
  }
});

/* ================================================================
   18) FALLBACK + ERROR HANDLER
   ================================================================ */
app.use((req, res) => res.status(404).json({ message: "Not found" }));

app.use((err, _req, res, _next) => {
  console.error("UNHANDLED:", err);
  res.status(500).json({ message: "Internal server error" });
});

/* ================================================================
   19) EXPORT / LISTEN
   ================================================================ */
module.exports = app;

if (process.env.NODE_ENV !== "production" && !process.env.VERCEL) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
  });
}
