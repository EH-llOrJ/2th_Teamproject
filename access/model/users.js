const Sequelize = require("sequelize");

class User extends Sequelize.Model {
  static init(sequelize) {
    return super.init(
      {
        user_id: {
          type: Sequelize.STRING(100),
          allowNull: false,
          unique: true,
        },
        email: {
          type: Sequelize.STRING(100),
          allowNull: false,
          unique: true,
        },
        nick: {
          type: Sequelize.STRING(100),
          allowNull: false,
          unique: true,
        },
        name: {
          type: Sequelize.STRING(20),
          allowNull: false,
        },
        password: {
          type: Sequelize.STRING(255),
          allowNull: false,
        },
        phone: {
          type: Sequelize.STRING(72),
          allowNull: false,
          unique: true,
        },
        refresh: {
          type: Sequelize.STRING(255),
          allowNull: true,
          unique: true,
        },
      },
      {
        sequelize,
        timestamps: true,
        underscored: false,
        modelName: "User",
        tableName: "users",
        paranoid: false,
        charset: "utf8",
        collate: "utf8_general_ci",
      }
    );
  }
}

module.exports = User;
