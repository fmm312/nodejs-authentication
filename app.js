require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// Config JSON response
app.use(express.json());

// Models
const User = require("./models/User");

// Open route - Public Route
app.get("/", (req, res) => {
    res.status(200).json({ msg: "Bem vindo a nossa API!" });
});

// Private route

// Register User
app.post("/auth/register", async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;

    // validations
    if (!name) {
        return res.status(422).json({ msg: "o nome é obrigatório" });
    }

    if (!email) {
        return res.status(422).json({ msg: "o email é obrigatório" });
    }

    if (!password) {
        return res.status(422).json({ msg: "A senha é obrigatória" });
    }

    if (password !== confirmPassword) {
        return res.status(422).json({ msg: "As senhas não conferem" });
    }

    // Check if user exists
    const userExists = await User.findOne({ email });

    if (userExists) {
        return res.status(422).json({ msg: "Por favor, utilize outro e-mail!" });
    }

    // Create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // Create user
    const user = new User({
        name,
        email,
        password: passwordHash
    });

    try {
        await user.save();
        res.status(201).json({ msg: "Usuário criado com sucesso" });
    } catch (error) {
        console.log(error);
        res.status(500).json({ msg: "Aconteceu um erro no servidor, tente novamente mais tarde!" });
    }
});

// Login user
app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body;

    // Validations
    if (!email) {
        return res.status(422).json({ msg: "o email é obrigatório" });
    }

    if (!password) {
        return res.status(422).json({ msg: "A senha é obrigatória" });
    }

    // Check if user exists
    const user = await User.findOne({ email });

    if (!user) {
        return res.status(404).json({ msg: "Usuário não encontrado!" });
    }

    // Check if password match
    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
        return res.status(422).json({ msg: "Senha inválida!" });
    }

    try {
        const secret = process.env.SECRET;

        const token = jwt.sign(
            {
                id: user._id,
            },
            secret,
        );

        res.status(200).json({ msg: "Autenticação realizada com sucesso", token });
    } catch (error) {
        console.log(error);
        res.status(500).json({ msg: "Aconteceu um erro no servidor, tente novamente mais tarde!" });
    }
});

// DB connection
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose.set("strictQuery", false);
mongoose
.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.i3qfxit.mongodb.net/?retryWrites=true&w=majority`)
.then(() => {
    app.listen(3000);
    console.log("Conectou ao banco!")
})
.catch(err => {
    console.log(err);
});

app.listen(8080);
