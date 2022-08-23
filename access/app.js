const express = require("express");
const fs = require("fs");
const path = require("path");
const dot = require("dotenv").config();
const { sequelize, User } = require("./model");
const bcrypt = require("bcrypt");
const e = require("express");

const app = express();

app.use(express.urlencoded({ extended: false }));

app.use(express.static(__dirname));

sequelize
  .sync({ force: false })
  .then(() => {
    console.log("DB 연결성공");
  })
  .catch((err) => {
    console.log(err);
  });

app.get("/", (req, res) => {
  fs.readFile("view/loginPage/login.html", "utf-8", (err, data) => {
    res.send(data);
  });
});

app.get("/join", (req, res) => {
  fs.readFile("view/joinPage/joinMember.html", "utf-8", (err, data) => {
    res.send(data);
  });
});

app.post("/emailCheck", (req, res) => {
  const { email } = req.body;
  User.findOne({ where: { email: email } })
    .then((e) => {
      if (e === null) {
        res.send("usable");
      } else res.send("disusable");
    })
    .catch((err) => {
      res.send(err);
    });
});

app.post("/signUpPro", (req, res) => {
  const { email, password, name, phone, birth } = req.body;
  bcrypt.hash(password, 10).then((e) => {
    const create = User.create({
      email: email,
      password: e,
      name: name,
      phone: phone,
      birth: birth,
    });
  });
});

app.listen(3000, () => {
  console.log(3000, "server running");
});
