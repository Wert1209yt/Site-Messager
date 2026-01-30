const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');

const app = express();
const PORT = 3000;
const USERS_FILE = './users.json';
const CHATS_FILE = './chats.json';
const SECRET_KEY = 'YOUR_SECRET_KEY'; // Замените на свой секретный ключ
const ADMIN_PASSWORD = '1425@#$nj)'; 

// Multer для загрузки файлов
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

app.use(bodyParser.json());
app.use(express.static('public'));
app.use(cookieParser());
app.use('/uploads', express.static('uploads'));

// --- Работа с файлами ---
function readJSON(file) {
    if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify([]));
    return JSON.parse(fs.readFileSync(file));
}
function writeJSON(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// --- Пользователи ---
function readUsers() { return readJSON(USERS_FILE); }
function writeUsers(users) { writeJSON(USERS_FILE, users); }

// --- Чаты ---
function readChats() { return readJSON(CHATS_FILE); }
function writeChats(chats) { writeJSON(CHATS_FILE, chats); }

// --- Регистрация ---
app.post('/register', (req, res) => {
    const { nickname, password } = req.body;
    if (!nickname || !password) return res.status(400).send('Никнейм и пароль обязательны.');

    const users = readUsers();
    if (users.find(u => u.nickname === nickname)) return res.status(400).send('Никнейм уже занят.');

    users.push({ nickname, password: bcrypt.hashSync(password, 10), blocked: false });
    writeUsers(users);
    res.status(201).send('Пользователь зарегистрирован.');
});

// --- Логин ---
app.post('/login', (req, res) => {
    const { nickname, password } = req.body;
    const users = readUsers();
    const user = users.find(u => u.nickname === nickname);
    if (!user || user.blocked || !bcrypt.compareSync(password, user.password)) {
        return res.status(400).send('Неверный никнейм или пароль или аккаунт заблокирован.');
    }
    const token = jwt.sign({ nickname }, SECRET_KEY, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true });
    res.send('Вход выполнен успешно!');
});

app.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.send('Вы вышли из аккаунта.');
});

// --- Middleware для аутентификации ---
function auth(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.status(401).send('Необходима аутентификация.');
    try {
        req.user = jwt.verify(token, SECRET_KEY);
        const users = readUsers();
        const u = users.find(x => x.nickname === req.user.nickname);
        if (!u || u.blocked) return res.status(403).send('Аккаунт заблокирован.');
        next();
    } catch {
        return res.status(401).send('Токен недействителен.');
    }
}

// --- Создать чат ---
app.post('/chat/create', auth, (req, res) => {
    const { name, members } = req.body;
    if (!name || !Array.isArray(members)) return res.status(400).send('Название и участники обязательны.');

    const chats = readChats();
    const chat = {
        id: Date.now(),
        name,
        owner: req.user.nickname,
        members: [...new Set([req.user.nickname, ...members])],
        messages: []
    };
    chats.push(chat);
    writeChats(chats);
    res.status(201).json(chat);
});

// --- Присоединиться к чату ---
app.post('/chat/join', auth, (req, res) => {
    const { chatId } = req.body;
    const chats = readChats();
    const chat = chats.find(c => c.id == chatId);
    if (!chat) return res.status(404).send('Чат не найден.');
    if (!chat.members.includes(req.user.nickname)) chat.members.push(req.user.nickname);
    writeChats(chats);
    res.send(`Вы присоединились к чату ${chat.name}`);
});

// --- Получить чаты пользователя ---
app.get('/chats', auth, (req, res) => {
    const chats = readChats();
    res.json(chats.filter(c => c.members.includes(req.user.nickname)));
});

// --- Отправка сообщений в чат ---
app.post('/chat/:chatId/message', auth, upload.single('file'), (req, res) => {
    const chatId = parseInt(req.params.chatId);
    const { text } = req.body;
    const chats = readChats();
    const chat = chats.find(c => c.id === chatId);
    if (!chat) return res.status(404).send('Чат не найден.');
    if (!chat.members.includes(req.user.nickname)) return res.status(403).send('Вы не участник чата.');

    let message = { author: req.user.nickname, timestamp: Date.now() };

    if (text) message.type = 'text', message.content = text;
    else if (req.file) {
        message.type = req.file.mimetype.startsWith('image') ? 'image' : 'voice';
        message.content = `/uploads/${req.file.filename}`;
    } else return res.status(400).send('Сообщение пустое.');

    chat.messages.push(message);
    writeChats(chats);
    res.json(message);
});

// --- Получение сообщений ---
app.get('/chat/:chatId/messages', auth, (req, res) => {
    const chatId = parseInt(req.params.chatId);
    const chats = readChats();
    const chat = chats.find(c => c.id === chatId);
    if (!chat) return res.status(404).send('Чат не найден.');
    if (!chat.members.includes(req.user.nickname)) return res.status(403).send('Вы не участник чата.');
    res.json(chat.messages);
});

// --- Кикнуть участника (только автор) ---
app.post('/chat/:chatId/kick', auth, (req, res) => {
    const chatId = parseInt(req.params.chatId);
    const { member } = req.body;
    const chats = readChats();
    const chat = chats.find(c => c.id === chatId);
    if (!chat) return res.status(404).send('Чат не найден.');
    if (chat.owner !== req.user.nickname) return res.status(403).send('Вы не автор чата.');

    chat.members = chat.members.filter(m => m !== member);
    writeChats(chats);
    res.send(`Пользователь ${member} исключён из чата.`);
});

// --- Админ ---
app.post('/admin/login', (req, res) => {
    const { password } = req.body;
    if (password !== ADMIN_PASSWORD) return res.status(403).send('Неверный пароль.');
    res.send('Вы вошли в админ-панель.');
});

// --- Админ: управление чатами ---
app.get('/admin/chats', (req, res) => {
    const chats = readChats();
    res.json(chats);
});

app.post('/admin/kick', (req, res) => {
    const { chatId, member } = req.body;
    const chats = readChats();
    const chat = chats.find(c => c.id == chatId);
    if (!chat) return res.status(404).send('Чат не найден.');
    chat.members = chat.members.filter(m => m !== member);
    writeChats(chats);
    res.send(`Админ исключил ${member} из чата ${chat.name}`);
});

app.listen(PORT, () => console.log(`Сервер запущен на http://localhost:${PORT}`));
