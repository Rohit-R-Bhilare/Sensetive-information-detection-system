/**
 * Chat backend server using Node.js, Express and MongoDB
 * Features:
 * - User registration and login with password hash (bcrypt)
 * - List users
 * - Send and receive messages between users
 * - Sensitive word detection on messages before saving
 * - CORS enabled for cross-origin requests
 */

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { MongoClient, ObjectId } = require("mongodb");

const app = express();
const port = 3000;

// MongoDB URI from user
const mongoUri =
"mongodb+srv://darshanghadge02:EAtY77HpxgJYKf6t@cluster0.rhfhd.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

// Database and collections  
let db;
let usersCollection;
let messagesCollection;

// Sensitive words list (lowercase)
const sensitiveWords = [
  "password",
  "ssn",
  "social security number",
  "credit card",
  "ccv",
  "cvv",
  "bank account",
  "routing number",
  "phone number",
  "address",
  "email",
  "passport",
  "driver license",
  "pin code",
  "secret",
  "confidential",
];

// Utility function to check if text contains sensitive words
function containsSensitive(text) {
  if (!text) return false;
  const lowerText = text.toLowerCase();
  return sensitiveWords.some((word) => lowerText.includes(word));
}

// Middleware
app.use(cors());
app.use(express.json());

// Connect to MongoDB and initialize collections
async function connectDb() {
  const client = new MongoClient(mongoUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
  await client.connect();
  // Use a database named "chatapp"
  db = client.db("chatapp");
  usersCollection = db.collection("users");
  messagesCollection = db.collection("messages");
  console.log("Connected to MongoDB");
}

// User registration endpoint
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password || username.length < 2 || username.length > 20) {
      return res
        .status(400)
        .json({ error: "Invalid username or password length." });
    }
    const existingUser = await usersCollection.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ error: "Username already exists." });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await usersCollection.insertOne({
      username,
      passwordHash: hashedPassword,
      createdAt: new Date(),
    });
    return res.json({
      success: true,
      message: "User registered successfully.",
    });
  } catch (err) {
    console.error("Register error:", err);
    return res
      .status(500)
      .json({ error: "Internal server error during registration." });
  }
});

// User login endpoint
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required." });
    }
    const user = await usersCollection.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: "Invalid username or password." });
    }
    const passwordMatch = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid username or password." });
    }
    return res.json({ success: true, username: user.username });
  } catch (err) {
    console.error("Login error:", err);
    return res
      .status(500)
      .json({ error: "Internal server error during login." });
  }
});

// Get all users endpoint (excluding requester)
app.get("/api/users", async (req, res) => {
  try {
    const { username } = req.query;
    if (!username) {
      return res.status(400).json({ error: "Username query param required." });
    }
    const users = await usersCollection
      .find(
        { username: { $ne: username } },
        { projection: { _id: 0, username: 1 } }
      )
      .toArray();
    const userList = users.map((u) => u.username);
    return res.json({ users: userList });
  } catch (err) {
    console.error("Users error:", err);
    return res
      .status(500)
      .json({ error: "Internal server error fetching users." });
  }
});

// Send message endpoint
app.post("/api/messages", async (req, res) => {
  try {
    const { sender, recipient, text } = req.body;
    if (!sender || !recipient || !text) {
      return res
        .status(400)
        .json({ error: "sender, recipient, and text are required." });
    }
    if (containsSensitive(text)) {
      return res
        .status(400)
        .json({ error: "Message contains sensitive data and cannot be sent." });
    }
    const messageDoc = {
      sender,
      recipient,
      text,
      createdAt: new Date(),
    };
    await messagesCollection.insertOne(messageDoc);
    return res.json({ success: true, message: "Message sent." });
  } catch (err) {
    console.error("Send message error:", err);
    return res
      .status(500)
      .json({ error: "Internal server error sending message." });
  }
});

// Get messages between two users
app.get("/api/messages", async (req, res) => {
  try {
    const { user1, user2 } = req.query;
    if (!user1 || !user2) {
      return res
        .status(400)
        .json({ error: "user1 and user2 query params required." });
    }
    const messages = await messagesCollection
      .find({
        $or: [
          { sender: user1, recipient: user2 },
          { sender: user2, recipient: user1 },
        ],
      })
      .sort({ createdAt: 1 })
      .toArray();
    return res.json({ messages });
  } catch (err) {
    console.error("Get messages error:", err);
    return res
      .status(500)
      .json({ error: "Internal server error getting messages." });
  }
});

// Start server async after DB connection
connectDb()
  .then(() => {
    app.listen(port, () => {
      console.log(`Chat backend server listening at http://localhost:${port}`);
    });
  })
  .catch((err) => {
    console.error("Failed to connect to MongoDB:", err);
    process.exit(1);
  });
