const mongoose = require('../../database');
const bcrypt = require('bcryptjs');

const UserSchema =  new mongoose.Schema({
    name:{
        type: String,
        require: true,
    },
    email: {
        type: String,
        unique: true, // único
        required: true, // campo obrigatório
        lowercase: true, //colocar o email em minúsculo
    },
    password: {
        type: String,
        required: true,
        select: false, // para não retornar a senha do sistema carregado

    },
    passwordResetToken: {
        type: String,
        select: false,
    },
    passwordResetExpires: {
        type: Date,
        select: false,
    },
    CreatedAt: {
        type: Date,
        default: Date.now, // atribuir data do sistema ao cadastrar novo usuário
    },

});

UserSchema.pre('save', async function(next) {
    const hash = await bcrypt.hash(this.password, 10);
    this.password = hash;

    next();
});

const User = mongoose.model('User', UserSchema);

module.exports = User;

