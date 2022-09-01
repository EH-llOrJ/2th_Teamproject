const express = require("express");
const path = require("path");
const dot = require("dotenv").config();
const { sequelize, User } = require("./model");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const session = require("express-session");
const ejs = require("ejs");
const app = express();
const { Op } = require("sequelize");
const { fstat } = require("fs");

app.use(express.urlencoded({ extended: false }));
app.use(express.static(__dirname));
app.set("view engine", "ejs");
app.set("views", "./view");

// session 사용
app.use(
  session({
    secret: process.env.SESSION_KEY,
    resave: false,
    saveUninitialized: true,
  })
);

// sequelize DB 연결
sequelize
  .sync({ force: false })
  .then(() => {
    console.log("DB connected");
  })
  .catch((err) => {
    console.log(err);
  });

app.get("/", (req, res) => {
  res.render("./startPage/start");
});

/////////////////////////////////////////////////////////////////////////////////////////

// 로그인 페이지 = (1)
app.get("/log", (req, res) => {
  res.render("./loginPage/login");
});

// (1), 로그인 시 id,pw 확인하여 (acc_tok , ref_tok) 발급
app.post("/login", (req, res) => {
  const { id, pw } = req.body;
  User.findOne({ where: { user_id: id } })
    .then((e) => {
      // 이메일로 받은 값이 가입된 회원일 경우 암호화된 비밀번호 비교
      if (e) {
        bcrypt.compare(pw, e?.password, (err, same) => {
          // 암호화된 비밀번호가 같을경우 토큰 발급
          if (same) {
            const accessToken = jwt.sign(
              {
                user_id: id,
                name: e.name,
              },
              process.env.ACCESS_TOKEN,
              {
                expiresIn: "5m",
                issuer: "ksh",
              }
            );

            const refreshToken = jwt.sign(
              {
                user_id: id,
              },
              process.env.REFRESH_TOKEN,
              {
                expiresIn: "5m",
                issuer: "ksh",
              }
            );

            // ref_tok를 확인해서 acc_tok 재발급하기 위해 db에 추가
            User.update({ refresh: refreshToken }, { where: { user_id: id } });

            // session에 발급된 토큰 저장
            req.session.access_token = accessToken;
            req.session.refresh_token = refreshToken;

            res.send("login true");
          } else {
            // 비밀번호가 다를경우
            res.send("fail");
          }
        });
        // 회원이 아닐경우
      } else {
        res.send("fail");
      }
    })
    .catch((err) => {
      res.send(err);
    });
});

// (1), 토큰 확인하여 로그인 유지 (middleware 설정)
const middleware = (req, res, next) => {
  // session에서 로그인시 발급된 토큰 가져오기
  const { access_token, refresh_token } = req.session;

  // acc_tok 검증
  jwt.verify(access_token, process.env.ACCESS_TOKEN, (err, acc_decoded) => {
    if (err) {
      // acc_tok 유효기간 지났을 경우 ref_tok 검증
      jwt.verify(
        refresh_token,
        process.env.REFRESH_TOKEN,
        (err, ref_decoded) => {
          // ref_tok 만료된 경우
          if (err) {
            res.redirect("/");
          } else {
            // ref_tok 존재하여 해당 email 찾아 acc_tok 재발급
            User.findOne({ where: { user_id: ref_decoded.user_id } })
              .then((e) => {
                if (e?.refresh == refresh_token) {
                  const accessToken = jwt.sign(
                    {
                      user_id: ref_decoded.user_id,
                      name: ref_decoded.name,
                    },
                    process.env.ACCESS_TOKEN,
                    {
                      expiresIn: "5m",
                      issuer: "ksh",
                    }
                  );

                  req.session.access_token = accessToken;
                  // acc_tok 재발급하여 로그인 유지
                  next();
                } else {
                  // tok 전부 만료되어 다시 로그인
                  res.redirect("/log");
                }
              })
              .catch((err) => {
                res.send(err);
              });
          }
        }
      );
    } else {
      // acc_tok 유효하여 로그인 유지
      next();
    }
  });
};

// (1), acc_tok 확인하여 로그인 유지 (middleware 수행)
app.get("/keep", middleware, (req, res) => {
  // acc_tok 검증하여 해당 email 변수 담기
  let user_id = jwt.verify(
    req.session.access_token,
    process.env.ACCESS_TOKEN,
    (err, result) => {
      return result.user_id;
    }
  );
  // 담은 변수를 render page에 정보 보내기
  User.findOne({ where: { user_id: user_id } }).then((e) => {
    let name = e.name;
    res.render("./loginPage/login(keep)", {
      id: name,
    });
  });
});

///////////////////////////////////////////////////////////////////////////////////////////

// 회원가입 페이지 = (2)
app.get("/join", (req, res) => {
  res.render("./joinPage/joinMember");
});

// (2), 아이디 중복확인 >> 아이디값 받고 해당 아이디 유무 확인후 값 반환
app.post("/userIdCheck", (req, res) => {
  const { user_id } = req.body;
  User.findOne({ where: { user_id: user_id } })
    .then((e) => {
      // 가입된 아이디 없을때
      if (e === null) {
        res.send("usable");
        // 가입된 아이디 있을때
      } else {
        res.send("disusable");
      }
    })
    // findOne 실행 안될때
    .catch((err) => {
      res.send(err);
    });
});

app.post("/nickCheck", (req, res) => {
  const { nickName } = req.body;
  User.findOne({ where: { nick: nickName } })
    .then((e) => {
      // 가입된 아이디 없을때
      if (e === null) {
        res.send("usable");
        // 가입된 아이디 있을때
      } else {
        res.send("disusable");
      }
    })
    // findOne 실행 안될때
    .catch((err) => {
      res.send(err);
    });
});

// (2), 회원정보를 받고 table에 DB생성
app.post("/signUpPro", (req, res) => {
  const { user_id, email, nick, password, name, phone } = req.body;

  // phone은 unique 속성으로 db에 유무 검사 후 저장
  User.findOne({ where: { phone: phone } }).then((e) => {
    if (e === null) {
      res.send("success");
      // pw 암호화 하여 저장
      bcrypt.hash(password, 10).then((e) => {
        User.create({
          user_id: user_id,
          email: email,
          nick: nick,
          password: e,
          name: name,
          phone: phone,
        });
      });
    } else {
      res.send("phone");
    }
  });
});

///////////////////////////////////////////////////////////////////////////////////////////

// 비밀번호 & 아이디 찾기 페이지 = (3)
app.get("/find", (req, res) => {
  res.render("./findPage/find");
});

// (3), 회원가입 유무 확인하여 토큰 발급 및 값 반환
app.post("/findCheck", (req, res) => {
  const { user_id, email, name, phone } = req.body;

  User.findOne({
    where: {
      user_id: user_id,
      email: email,
      name: name,
      phone: phone,
    },
  }).then((e) => {
    // 가입이 확인되지 않을때
    if (e === null) {
      res.send("fail");
      // 가입이 확인될때
    } else {
      // 비밀번호 변경 페이지에서 유지하기 위한 토큰 발급
      const accessToken = jwt.sign(
        {
          email: e.email,
          password: e.password,
          name: e.name,
        },
        process.env.ACCESS_TOKEN,
        {
          expiresIn: "5m",
          issuer: "ksh",
        }
      );
      req.session.access_token = accessToken;
      res.send("success");
    }
  });
});

// (3), 비밀번호 재설정 페이지 유지
app.get("/change", (req, res) => {
  // 발급된 토큰 검증
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
  // 비밀번호 재설정페이지 render , 유저정보 보내기
  res.render("./findPage/pwchange", { result: result });
});

// (3), 재설정한 비밀번호 암호화
app.post("/passcha", (req, res) => {
  const { passwordDom } = req.body;
  jwt.verify(
    req.session.access_token,
    process.env.ACCESS_TOKEN,
    (err, acc_decoded) => {
      if (err) {
        res.send("fail");
      } else {
        bcrypt.hash(passwordDom, 10).then((e) => {
          User.update(
            { password: e },
            { where: { email: acc_decoded.email } }
          ).then(() => {
            res.send("success");
          });
        });
      }
    }
  );
});

//////////////////////////////////////////////////////////////////////////////////////////////

// 이메일찾기 페이지 = (3-1)
app.get("/findEmail", (req, res) => {
  res.render("./findPage/findEmail");
});

// (3-1), 내 이메일보기 페이지 유지하기 위해 토큰 발급 및 값 반환
app.post("/checkPerson", (req, res) => {
  const { email, name, phone } = req.body;

  User.findOne({
    where: {
      email: email,
      name: name,
      phone: phone,
    },
  }).then((e) => {
    if (e == null) {
      // 회원이 아닐경우
      res.send("fail");
    } else {
      // 회원일 경우 토큰 발급
      const accessToken = jwt.sign(
        {
          user_id: e.user_id,
          email: e.email,
          name: e.name,
        },
        process.env.ACCESS_TOKEN,
        {
          expiresIn: "5m",
          issuer: "ksh",
        }
      );

      req.session.access_token = accessToken;

      res.send("success");
    }
  });
});

// (3-1), 찾은 내 이메일 보기 페이지 유지
app.get("/viewEmail", (req, res) => {
  // 발급된 tok 검증
  let result = jwt.verify(
    req.session.access_token,
    process.env.ACCESS_TOKEN,
    (err, acc_decoded) => {
      // tok 만료시 개인정보 재입력
      if (err) {
        res.redirect("/findEmail");
      } else {
        return acc_decoded;
      }
    }
  );
  // 내 이메일보기 페이지로 이동 , 유저정보 같이 보내서 내 이메일 보기
  res.render("./findPage/myEmail", { result: result });
});

//////////////////////////////////////////////////////////////////////////////////////////

// 로그인 전 store 페이지
app.get("/store", (req, res) => {
  res.render("./storePage/store");
});

// 로그인 후 유저 store keeping page
app.get("/storeKeep", (req, res) => {
  res.render("./storePage/store(keep)");
});

app.get("/storeManager", (req, res) => {
  res.render("./storePage/store(manager)");
});

//////////////////////////////////////////////////////////////////////////////////////////

// 서버 open
app.listen(3000, () => {
  console.log(3000, "server running");
});
