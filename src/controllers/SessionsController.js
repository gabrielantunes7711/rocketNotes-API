const { compare } = require("bcryptjs");
const { sign } = require("jsonwebtoken");
const Knex = require("../database/knex");
const AppError = require("../utils/AppError");
const authConfig = require("../configs/auth");

class SessionsController {
  async create(request, response) {
    const { email, password } = request.body;

    const user = await Knex("users").where({ email }).first();

    if (!user) {
      throw new AppError("Email e/ou senha incorreta", 401);
    }

    const passwordMatch = await compare(password, user.password);

    if (!passwordMatch) {
      throw new AppError("Email e/ou senha incorreta", 401);
    }

    const { secret, expiresIn } = authConfig.jwt;
    const token = sign({}, secret, {
      subject: String(user.id),
      expiresIn,
    });

    return response.json({ user, token });
  }
}

module.exports = SessionsController;
