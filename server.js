const express = require('express');
const dotenv = require('dotenv');
const authRoutes = require('./routes/auth');

dotenv.config();
const app = express();
app.use(express.json());

app.use('/api',authRoutes);

app.listen(3000,()=>console.log('Server running on port 3000'));