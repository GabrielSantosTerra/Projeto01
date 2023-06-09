const express = require('express');
const bodyParser = require('body-parser');

const app = express();

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false}));

app.get('/', (req,res) =>{
    res.send('servidor de pé')
});

require('./app/controllers/index')(app);

app.listen(3000);
