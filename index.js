import express from "express";
import { MongoClient } from "mongodb";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";

import { auth } from "./middleware/auth.js";
const app = express();

//connecting mongodb____________________
const MONGO_URL =
  "mongodb+srv://raghutwo:welcome123@cluster0.4gd3qjn.mongodb.net";
const client = new MongoClient(MONGO_URL);
await client.connect();
console.log("mongo connected");
//_______________________________________

const PORT = 4000;
app.use(express.json());
app.use(cors());

app.get("/", (req, res) => {
  res.send("express working successfully");
});

app.get("/who-has-logged-in", auth, async (req, res) => {
  const token = req.header("x-auth-token");
  try {
    const data = await client
      .db("reset-password")
      .collection("users")
      .findOne({ token: token });
    res.send({ userName: data.userName });
  } catch {
    res.status(401).send({ message: "token tampered" });
  }
});

app.post("/sign-up", async (req, res) => {
  const data = req.body;

  //check user name available______
  const usernameCheck = await client
    .db("reset-password")
    .collection("users")
    .findOne({ userName: data.userName });

  console.log(usernameCheck);
  if (usernameCheck) {
    res.status(401).send({ message: "user name already exits try login" });
  } else if (data.password.length < 7) {
    res
      .status(401)
      .send({ message: "password should be at least 8 character" });
  } else {
    //hsah the password
    const password = data.password;
    const NO_OF_ROUNDS = 10;
    const salt = await bcrypt.genSalt(NO_OF_ROUNDS);
    const hashedPassword = await bcrypt.hash(password, salt);
    //____________________

    //get jwt token___________
    const token = jwt.sign({ id: hashedPassword }, "mysecretkey");
    //________________________
    const patchedData = { ...data, token: token, password: hashedPassword };

    const result = await client
      .db("reset-password")
      .collection("users")
      .insertOne(patchedData);

    res.send({ userName: data.userName, token: token });
  }
});

app.post("/log-in", async (req, res) => {
  const data = req.body;

  const checkUser = await client
    .db("reset-password")
    .collection("users")
    .findOne({ userName: data.userName });

  if (!checkUser) {
    res.status(401).send({ message: "invalid username or passworrd" });
  } else {
    const db_password = checkUser.password;
    const checkPass = await bcrypt.compare(data.password, db_password);
    console.log(checkPass);

    if (checkPass) {
      const token = jwt.sign({ id: checkUser._id }, "mysecretkey");

      const updateToken = await client
        .db("reset-password")
        .collection("users")
        .updateOne(
          { userName: checkUser.userName },
          { $set: { token: token } }
        );

      res.send({ userName: checkUser.userName, token: token });
    } else {
      res.status(401).send({ message: "invalid username or password" });
    }
  }
});

app.listen(PORT, () => console.log(`listening to ${PORT}`));
