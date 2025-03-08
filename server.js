const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = 3000;
const USERS_FILE = './users.json';
const TEXT_FILE = './shared_text.txt';
const SECRET_KEY = 'YOUR_SECRET_KEY'; // Секретный ключ для JWT

// Middleware
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(cookieParser()); // Подключение cookie-parser

// Функция для чтения пользователей из файла
function readUsers() {
    if (!fs.existsSync(USERS_FILE)) {
        fs.writeFileSync(USERS_FILE, JSON.stringify([]));
    }
    const data = fs.readFileSync(USERS_FILE);
    return JSON.parse(data);
}

// Функция для записи пользователей в файл
function writeUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Регистрация пользователя
app.post('/register', (req, res) => {
    const { nickname, password } = req.body;

    if (!nickname || !password) {
        return res.status(400).send('Никнейм и пароль обязательны.');
    }

    let users = readUsers();

    // Проверка на уникальность ника
    if (users.find(user => user.nickname === nickname)) {
        return res.status(400).send('Никнейм уже занят.');
    }

    // Хеширование пароля
    const hashedPassword = bcrypt.hashSync(password, 10);

    // Добавление нового пользователя
    users.push({ nickname, password: hashedPassword });
    writeUsers(users);

    // Запись сообщения о присоединении в файл
    const joinMessage = `${nickname} присоединился\n`;
    fs.appendFile(TEXT_FILE, joinMessage, (err) => {
        if (err) {
            console.error('Ошибка при записи в файл:', err);
        }
    });

    res.status(201).send('Пользователь зарегистрирован.');
});

// Вход в аккаунт
app.post('/login', (req, res) => {
    const { nickname, password } = req.body;

    if (!nickname || !password) {
        return res.status(400).send('Никнейм и пароль обязательны.');
    }

    let users = readUsers();

    // Поиск пользователя по нику
    const user = users.find(user => user.nickname === nickname);
    if (!user) {
        return res.status(400).send('Неверный никнейм или пароль.');
    }

    // Проверка пароля
    const isMatch = bcrypt.compareSync(password, user.password);
    if (!isMatch) {
        return res.status(400).send('Неверный никнейм или пароль.');
    }

    // Генерация токена
    const token = jwt.sign({ nickname: user.nickname }, SECRET_KEY, { expiresIn: '1h' });

    // Установка cookie с токеном
    res.cookie('token', token, { httpOnly: true }); // Устанавливаем cookie с токеном
    res.json({ message: 'Вход выполнен успешно!' });
});

// Выход из аккаунта
app.post('/logout', (req, res) => {
    res.clearCookie('token'); // Удаляем cookie с токеном
    res.send('Вы вышли из аккаунта.');
});

// Обработка POST-запроса для сохранения текста
app.post('/save-text', (req, res) => {
    const { text } = req.body;
    const token = req.cookies.token; // Получаем токен из cookies

    if (!token) {
        return res.status(401).send('Необходима аутентификация.');
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const nickname = decoded.nickname;

        if (!text) {
            return res.status(400).send('Текст не может быть пустым.');
        }

        //
    
