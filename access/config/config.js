const dot = require("dotenv").config();

const config = {
  dev: {
    username: "root",
    password: process.env.DB_PASSWORD,
    database: "myUser",
    host: "127.0.0.1",
    dialect: "mysql",
  },
};

module.exports = config;