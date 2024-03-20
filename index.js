const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const User = require("./models/User");
const Post = require("./models/Post");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const upload = multer({ dest: "uploads/" });
const fs = require("fs");
const cookieParser = require("cookie-parser");
const env = require("dotenv");
const app = express();

env.config();

app.use(
  cors({
    origin: "https://hamza-blog-teal.vercel.app",
    credentials: true,
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
    "Access-Control-Allow-Headers": "Content-Type, Set-Cookie, Authorization",
  })
);
app.use(express.json());
app.use(cookieParser());
app.use("/uploads", express.static(__dirname + "/uploads"));
// mongoose.connect(process.env.MONGO_URL);
mongoose
  .connect(process.env.MONGO_URL)
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((error) => {
    console.error("Error connecting to MongoDB:", error);
  });

const saltRounds = 10;
const salt = bcrypt.genSaltSync(saltRounds);
const secret = process.env.SECRET;
const PORT = process.env.PORT || 4000;

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.create({
      username,
      password: bcrypt.hashSync(password, salt),
    });
    res.json(userDoc);
  } catch (e) {
    if (e.code === 11000 && e.keyPattern && e.keyValue) {
      res.status(400).json({ error: "Username already exists." });
    } else {
      console.error(e);
      res.status(400).json({ error: "Failed to register user." });
    }
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const userDoc = await User.findOne({ username });
  if (!userDoc) {
    res.status(400).json({ error: "User not found! Please register." });
    return;
  }
  const passOk = bcrypt.compareSync(password, userDoc.password);
  if (!passOk) {
    res.status(400).json({ error: "Incorrect Password!" });
    return;
  }
  if (passOk) {
    jwt.sign(
      { username, id: userDoc._id }, // Payload
      secret,
      { expiresIn: "1d" }, // Options object
      (err, token) => {
        if (err) throw err;
        res.json({ id: userDoc._id, username, token }); // Send the token back
      }
    );
    console.log("Logged in");
  } else {
    res.status(400).json("Wrong Credentials");
  }
});

app.get("/profile", (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1]; // Bearer token

  if (!token) return res.status(401).json("No authorization token provided");

  jwt.verify(token, secret, {}, (err, info) => {
    if (err) throw err;
    res.json(info);
  });
});

app.post("/logout", (req, res) => {
  res.json("Logged out");
  console.log("Logged out");
});

app.post("/post", upload.single("file"), async (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json("No authorization token provided");

  const { originalname, path } = req.file;
  const parts = originalname.split(".");
  const ext = parts[parts.length - 1];
  const newPath = path + "." + ext;
  fs.renameSync(path, newPath);

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) {
      return res.status(403).json("Invalid authorization token");
    }
    const { title, summary, content } = req.body;
    const postDoc = await Post.create({
      title,
      summary,
      content,
      cover: newPath,
      author: info.id,
    });
    res.json(postDoc);
  });
});

app.put("/post", upload.single("file"), async (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json("No authorization token provided");
  let newPath = null;
  if (req.file) {
    const { originalname, path } = req.file;
    const parts = originalname.split(".");
    const ext = parts[parts.length - 1];
    newPath = path + "." + ext;
    fs.renameSync(path, newPath);
  }

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) {
      return res.status(403).json("Invalid authorization token");
    }
    const { id, title, summary, content } = req.body;

    const postDoc = await Post.findById(id);
    const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
    if (!isAuthor) {
      return res.status(400).json("you are not the author");
    }
    await postDoc.updateOne({
      title,
      summary,
      content,
      cover: newPath ? newPath : postDoc.cover,
    });
    res.json(postDoc);
  });
});

app.get("/post", async (req, res) => {
  res.json(
    await Post.find()
      .populate("author", ["username"])
      .sort({ createdAt: -1 })
      .limit(20)
  );
});
app.get("/healthz", (req, res) => {
  res.status(200).json("Systems up & running");
});
app.get("/post/:id", async (req, res) => {
  const { id } = req.params;
  const postDoc = await Post.findById(id).populate("author", ["username"]);
  res.json(postDoc);
});

app.delete("/post/:id", async (req, res) => {
  const { id } = req.params;
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json("No authorization token provided");
  if (!token) {
    return res.status(404).json("You are not logged in");
  }
  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) {
      return res.status(403).json("Invalid authorization token");
    }
    const postDoc = await Post.findById(id);
    const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
    if (!isAuthor) {
      return res.status(400).json("you are not the author");
    }
    await postDoc.deleteOne();
    res.json(postDoc);
  });
});
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
