const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const {join} = require('path');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = 3000;
const FILE_NAME = 'data.json';
const JWT_SECRET = '(*)jj**asLOLom';


app.use(cors({
    origin: 'https://password-manager-9868.onrender.com',
    optionsSuccessStatus: 200,
}));


app.use(bodyParser.json());
app.use(express.static(join(__dirname, 'public')));

app.post('/register', async (req, res) => {
    const data = readDataFromFile();
    const {username, password} = req.body;

    if (data.find(user => user.username === username)) {
        return res.status(400).send('Username already taken.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
        userId: data.length + 1,
        username,
        password: hashedPassword,
        credentials: [],
    };

    data.push(newUser);
    saveDataToFile(data);

    res.status(201).send('User registered successfully.');
});

app.post('/login', (req, res) => {
    const data = readDataFromFile();
    const {username, password} = req.body;
    const user = data.find(user => user.username === username);

    if (user && bcrypt.compareSync(password, user.password)) {
        const token = jwt.sign({userId: user.userId}, JWT_SECRET, {expiresIn: '1h'});
        res.json({message: 'Login successful.', token: token});
    } else {
        res.status(401).send('Invalid credentials.');
    }
});

app.get('/data', verifyToken, (req, res) => {
    const data = readDataFromFile();
    const userData = data.find(user => user.userId === req.user.userId);

    if (userData) {
        res.json(userData);
    } else {
        res.status(404).send('User data not found');
    }
});

app.post('/password/strength', (req, res) => {
    const password = req.body.password;
    const result = checkPasswordStrength(password);
    res.json(result);
});

function verifyToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) return res.status(403).send('A token is required for authentication');

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
    } catch (err) {
        return res.status(401).send('Invalid Token');
    }
    return next();
}

function readDataFromFile() {
    try {
        const data = fs.readFileSync(FILE_NAME, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading the data file:', error);
        return [];
    }
}

function saveDataToFile(data) {
    try {
        fs.writeFileSync(FILE_NAME, JSON.stringify(data), 'utf8');
    } catch (error) {
        console.error('Error writing to the data file:', error);
    }
}

app.post('/user/credentials', verifyToken, (req, res) => {
    const {service, username, password} = req.body;
    const userId = req.user.userId;
    const data = readDataFromFile();

    const user = data.find(u => u.userId === userId);
    if (!user) {
        return res.status(404).send('User not found.');
    }

    const newCredential = {service, username, password};
    user.credentials.push(newCredential);
    saveDataToFile(data);

    res.status(201).send('Credential added successfully.');
});
app.post('/user/delete-records', verifyToken, (req, res) => {
    const {records} = req.body;
    const userId = req.user.userId;
    const data = readDataFromFile();

    const user = data.find(u => u.userId === userId);
    if (!user) {
        return res.status(404).send('User not found.');
    }

    user.credentials = user.credentials.filter((credential) => !records.includes(credential.service));

    saveDataToFile(data);

    res.json({message: 'Records deleted successfully'});
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
