const bcrypt = require('bcrypt');

const password = 'password123'; // Change this to the desired password
const saltRounds = 10;

bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) throw err;
    console.log('Hashed Password:', hash);
});
