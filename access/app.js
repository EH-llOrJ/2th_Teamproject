const express = require("express");
const fs = require("fs");
const path = require("path");
const dot = require("dotenv").config();
const { sequelize, User } = require("./model");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const session = require("express-session");
const ejs = require("ejs");
const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(express.static(__dirname));
app.set("view engine", "ejs");
app.set("views", "./view");

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
    console.log("DB connected");
  })
  .catch((err) => {
    console.log(err);
  });

app.get("/", (req, res) => {
  res.render("./loginPage/login");
});

app.get("/join", (req, res) => {
  res.render("./joinPage/joinMember");
});

app.get("/find", (req, res) => {
  res.render("./findPage/find");
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

app.post("/findCheck", (req, res) => {
  const { email, name, phone, birth } = req.body;

  User.findOne({
    where: {
      email: email,
      name: name,
      phone: phone,
      birth: birth,
    },
  }).then((e) => {
    if (e === null) {
      res.send("fail");
    } else {
      const accessToken = jwt.sign(
        {
          email: e.email,
          password: e.password,
        },
        process.env.ACCESS_TOKEN,
        {
          expiresIn: "5s",
          issuer: "ksh",
        }
      );
      req.session.access_token = accessToken;
      res.send("success");
    }
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
  const { id, pw } = req.body;
  User.findOne({ where: { email: id } })
    .then((e) => {
      if (e) {
        bcrypt.compare(pw, e?.password, (err, same) => {
          if (same) {
            const accessToken = jwt.sign(
              {
                email: id,
                name: e.name,
              },
              process.env.ACCESS_TOKEN,
              {
                expiresIn: "5s",
                issuer: "ksh",
              }
            );

            const refreshToken = jwt.sign(
              {
                email: id,
              },
              process.env.REFRESH_TOKEN,
              {
                expiresIn: "5m",
                issuer: "ksh",
              }
            );

            User.update({ refresh: refreshToken }, { where: { email: id } });

            req.session.access_token = accessToken;
            req.session.refresh_token = refreshToken;
            res.send("login true");
          } else {
            res.send("fail");
          }
        });
      } else {
        res.send("fail");
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
            // res.send("refesh token이 만료되었습니다. 다시 로그인해주세요");
            res.redirect("/");
          } else {
            User.findOne({ where: { email: ref_decoded.email } })
              .then((e) => {
                if (e?.refresh == refresh_token) {
                  const accessToken = jwt.sign(
                    {
                      email: ref_decoded.email,
                      name: ref_decoded.name,
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
                  res.redirect("/");
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

app.get("/keep", middleware, (req, res) => {
  let email = jwt.verify(
    req.session.access_token,
    process.env.ACCESS_TOKEN,
    (err, result) => {
      return result.email;
    }
  );
  User.findOne({ where: { email: email } }).then((e) => {
    let name = e.name;
    res.render("./loginPage/login(keep)", {
      id: name,
    });
  });
});

app.get("/change", (req, res) => {
  let result = jwt.verify(
    req.session.access_token,
    process.env.ACCESS_TOKEN,
    (err, acc_decoded) => {
      if (err) {
        res.redirect("/find");
      } else {
        return acc_decoded;
      }
    }
  );
  res.render("./findPage/pwchange", { result: result });
});

app.post("/passcha", (req, res) => {
  const { password, user } = req.body;
  User.update({ password: password }, { where: { email: user.email } }).then(
    () => {
      res.send("success");
    }
  );
});

app.listen(3000, () => {
  console.log(3000, "server running");
});
