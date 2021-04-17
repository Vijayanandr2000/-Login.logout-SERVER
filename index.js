const express = require("express");
const mongodb = require("mongodb");
const JWT = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const dotenv = require("dotenv");

const app = express();
app.use(express.json());
app.use(cors());
dotenv.config();

const DBURL =
  "mongodb+srv://vijay:ReTYRSovc9HOye4r@cluster0.5nom1.mongodb.net/myFirstDatabase?retryWrites=true&w=majority";

const mongoClient = mongodb.MongoClient;
const objectId = mongodb.ObjectID;
const DB_URL = DBURL || "mongodb://127.0.0.1:27017";
const PORT = process.env.PORT || 8000;

app.get("/", (req, res) => {
  console.log("SERVER IS RUNNINg");
});

app.post("/register", async (req, res) => {
  try {
    const client = await mongoClient.connect(DB_URL);
    const db = client.db("login");
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(req.body.password, salt);
    const data = {
      name: req.body.name,
      mail: req.body.mail,
      password: hash,
    };
    var mailValid = await db
      .collection("user")
      .findOne({ mail: req.body.mail });
    if (mailValid) {
      res.status(400).json({ message: "Email already exists" });
    } else {
      await db.collection("user").insertOne(data);
    }
    res.status(200).json({ message: "Registered" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  } finally {
    client.close();
  }
});

app.post("/login", async (req, res) => {
  try {
    const client = await mongoClient.connect(DB_URL);
    const db = client.db("login");
    const user = await db.collection("user").findOne({ mail: req.body.mail });
    if (user) {
      var cmp = await bcrypt.compare(req.body.password, user.password);
      if (cmp) {
        var userToken = await JWT.sign({ mail: user.mail }, "loginUser");
        res
          .header("auth", userToken)

          .json({ message: "allow", userToken });
      } else {
        res.status(400).json({ message: "Password Incorrect" });
      }
    } else {
      res.status(400).json({
        message: "Email not found",
      });
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  } finally {
    client.close();
  }
});

const authenticate = (req, res, next) => {
  const token = req.header("auth");
  req.token = token;
  next();
};

app.get("/home", authenticate, async (req, res) => {
  try {
    JWT.verify(req.token, "loginUser", async (e, data) => {
      if (e) {
        res.send(403);
      } else {
        const client = await mongoClient.connect(DB_URL);
        const db = client.db("login");
        data = await db
          .collection("user")
          .find()
          .project({ password: 0 })
          .toArray();
        res.send(data);
      }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  } finally {
    client.close();
  }
});

app.listen(PORT, () => {
  console.log(`App is listening on port ${PORT}`);
});
