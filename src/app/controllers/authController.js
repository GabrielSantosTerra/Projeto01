const express= require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const mailer = require ('../../modules/mailer');

const authConfig = require('../../confg/auth');

const User = require('../models/user');

const router = express.Router();

function generateToken(params = {}) {
    return jwt.sign(params, authConfig.secret, {
        expiresIn: 86400,
    });
};

router.post('/register', async (req, res) => {
    const { email } = req.body;

    try {
        if (await User.findOne({ email })){
            return res.status(400).send({ error: 'Usuário já tem cadastro' });
        }
        
        const user = await User.create(req.body);

        user.password = undefined;

        return res.send({ 
            user, 
            token: generateToken({ id: user.id}),
        });
    }   
    
    catch ( err ){
        return res.status(400).send({ error: 'Email, senha e úsuarios inválidos' });
    }
});

router.post ('/authenticate', async(req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select('+password');

    if (!user) {
        return res.status(400).send({ error: 'Usuário não encontrado ;-;'})
    }
    if (!await bcrypt.compare(password, user.password)) {
        return res.status(400).send({ error: 'Senha iválida'});

    }
    user.password = undefined;

    res.send({ 
        user, 
        token: generateToken({ id: user.id }),
    });   
});

router.post('/forgot_password', async (req,res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user){
            return res.status(400).send({ error: 'User not find'})
        };

        const token = crypto.randomBytes(20).toString('hex');

        const now = new Date();
        now.setHours(now.getHours() + 1);

        await User.findByIdAndUpdate(user.id, {
            '$set': {
                passwordResetToken: token,
                passwordResetExpires: now,
            }
        });

        mailer.sendMail({
            to: email,
            from: 'gabrielsantosterra@gmail.com',
            template: 'auth/forgot_password',
            context: { token },
        }, (err) => {
            if (err){
            return res.status(400).send({ error: 'cannot send forgot password email' });
           }
           
           return res.send();
        });
        console.log(token, now);
    } catch (err) {
        console.log(err);
        res.status(400).send({ error: 'Erro ao recuperar senha tente novamente'});
    }
});

router.post('/reset_password', async (req, res) => {
    const { email, token, password } = req.body;

    const user = await User.findOne({ email });

    try {
        const user = await User.findOne({ email })
        .select('+passwordResetToken passwordResetExpires');

        if (!user) { 
            return res.status(400).send({ error: 'Usuário não encontrado'});
        }

        if (token !== user.passwordResetToken){
            return res.status(400).send({ error: 'Token inválido'});
        }

        const now = new Date();

        if (now > user.passwordResetExpires) {
            return res.status(400).send({ error: 'Token expirado, gere outro!'});
        }

        user.password = password;

        await user.save();

        res.send();

    } catch (err) {
        res.status(400).send({ error: 'Não foi possível resetar sua senha, tente de novo'});
    }
});

module.exports = app => app.use('/auth', router);