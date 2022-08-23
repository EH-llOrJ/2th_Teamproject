const Sequelize = require("sequelize");

class User extends Sequelize.Model {
  static init(sequelize) {
    return super.init(
      {
        email: {
          type: Sequelize.STRING(100),
          allowNull: false,
          unique: true,
        },
        password: {
          type: Sequelize.STRING(255),
          allowNull: false,
        },
        name: {
          type: Sequelize.STRING(20),
          allowNull: false,
        },
        phone: {
          type: Sequelize.STRING(72),
          allowNull: false,
          unique: true,
        },
        birth: {
          type: Sequelize.STRING(72),
          allowNull: false,
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
