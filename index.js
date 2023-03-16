import express from "express";
import { MongoClient } from "mongodb";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
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

app.get("/", (req, res) => {
  res.send("express working successfully");
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
    res.send({ message: "user name already exits try login" });
  } else if (data.password.length < 7) {
    res.send({ message: "password should be at least 8 character" });
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
    res.send({ message: "invalid username or passworrd" });
  } else {
    const db_password = checkUser.password;
    const checkPass = await bcrypt.compare(data.password, db_password);
    console.log(checkPass);
  }
});

app.listen(PORT, () => console.log(`listening to ${PORT}`));
