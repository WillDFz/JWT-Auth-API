// imports
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// Config JSON
app.use(express.json());

// Models
const User = require("./models/User");

app.get("/", (req, res) => {
    res.status(200).json({ msg: "Ok!" });
});

// Register User
app.post("/auth/register", async (req, res) => {
    const { name, email, password, confirmpassword } = req.body;

    // validations
    if (!name) {
        return res.status(422).json({ Erro: "Nome obrigatório" });
    }
    if (!email) {
        return res.status(422).json({ Erro: "E-mail obrigatório" });
    }
    if (!password) {
        return res.status(422).json({ Erro: "Senha obrigatória" });
    }
    if (password !== confirmpassword) {
        return res.status(422).json({ Erro: "Senhas diferentes" });
    }

    // Check if user exists
    const userExists = await User.findOne({ email: email });

    if (userExists) {
        return res
            .status(422)
            .json({ Erro: "E-mail já existe no banco de dados" });
    }

    // Create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // Create user
    const user = new User({ name, email, password: passwordHash });

    try {
        await user.save()
        res.status(201).json({Msg: "Usuário criado com sucesso"})
    } catch (error) {
        res.status(500).json({Erro: "error"})
    }
});

// Credentials
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose
    .connect(
        `mongodb+srv://${dbUser}:${dbPassword}@cluster0.jazch13.mongodb.net/?retryWrites=true&w=majority`
    )
    .then(() => {
        app.listen(3000);
        console.log("Connected");
    })
    .catch((error) => console.log(error));
