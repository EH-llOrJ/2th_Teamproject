const express = require("express");
const fs = require("fs");
const path = require("path");
const dot = require("dotenv").config();
const { sequelize, User } = require("./model");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const session = require("express-session");

const app = express();

app.use(express.urlencoded({ extended: false }));

app.use(express.static(__dirname));

app.use(
  session({
    secret: process.env.SESSION_KEY,
    resave: false,
    saveUninitialized: true,
  })
);

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
      } else {
        res.send("disusable");
      }
    })
    .catch((err) => {
      res.send(err);
    });
});

app.post("/signUpPro", (req, res) => {
  const { email, password, name, phone, birth } = req.body;
  bcrypt.hash(password, 10).then((e) => {
    User.create({
      email: email,
      password: e,
      name: name,
      phone: phone,
      birth: birth,
    });
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  User.findOne({ where: { email: email } })
    .then((e) => {
      if (e) {
        bcrypt.compare(password, e?.password, (err, same) => {
          if (same) {
            const accessToken = jwt.sign(
              {
                email: email,
              },
              process.env.ACCESS_TOKEN,
              {
                expiresIn: "5s",
                issuer: "ksh",
              }
            );

            const refreshToken = jwt.sign(
              {
                email: email,
              },
              process.env.REFRESH_TOKEN,
              {
                expiresIn: "10s",
                issuer: "ksh",
              }
            );

            User.update({ refresh: refreshToken }, { where: { email: email } });

            req.session.access_token = accessToken;
            req.session.refresh_token = refreshToken;
            res.send({ access: accessToken, refresh: refreshToken });
          } else {
            res.send("비밀번호를 확인해 주세요");
          }
        });
      } else {
        res.send("해당 email이 없습니다. 다시 확인해주세요.");
      }
    })
    .catch((err) => {
      res.send(err);
    });
});

const middleware = (req, res, next) => {
  const { access_token, refresh_token } = req.session;

  jwt.verify(access_token, process.env.ACCESS_TOKEN, (err, acc_decoded) => {
    if (err) {
      jwt.verify(
        refresh_token,
        process.env.REFRESH_TOKEN,
        (err, ref_decoded) => {
          if (err) {
            res.send("refesh token이 만료되었습니다. 다시 로그인해주세요");
          } else {
            User.findOne({ where: { email: ref_decoded.email } })
              .then((e) => {
                if (e?.refresh == refresh_token) {
                  const accessToken = jwt.sign(
                    {
                      email: ref_decoded.email,
                    },
                    process.env.ACCESS_TOKEN,
                    {
                      expiresIn: "5s",
                      issuer: "ksh",
                    }
                  );

                  req.session.access_token = accessToken;
                  next();
                } else {
                  res.send("다시 로그인해주세요");
                }
              })
              .catch((err) => {
                res.send(err);
              });
          }
        }
      );
    } else {
      next();
    }
  });
};

app.get("/check", middleware, (req, res) => {
  res.send("로그인 되어있음");
});

app.listen(3000, () => {
  console.log(3000, "server running");
});
