const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const USERS_FILE = './users.json';
const TEXT_FILE = './shared_text.txt';
const SECRET_KEY = 'YOUR_SECRET_KEY'; // Секретный ключ для JWT

// Middleware
app.use(bodyParser.json());
app.use(express.static('public'));

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
    res.json({ token });
});

// Обработка POST-запроса для сохранения текста
app.post('/save-text', (req, res) => {
    const { text } = req.body;
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).send('Необходима аутентификация.');
    }

    try {
        const decoded = jwt.verify(token.split(' ')[1], SECRET_KEY);
        const nickname = decoded.nickname;

        if (!text) {
            return res.status(400).send('Текст не может быть пустым.');
        }

        // Форматируем строку для записи
        const formattedText = `${nickname} > ${text}\n`;

        // Добавляем текст в файл
        fs.appendFile(TEXT_FILE, formattedText, (err) => {
            if (err) {
                return res.status(500).send('Ошибка при сохранении файла.');
            }
            res.send('Текст успешно добавлен!');
        });
        
    } catch (error) {
        return res.status(401).send('Токен недействителен.');
    }
});

// Обработка GET-запроса для получения текста
app.get('/get-text', (req, res) => {
    fs.readFile(TEXT_FILE, 'utf8', (err, data) => {
        if (err) {
            return res.status(500).send('Ошибка при чтении файла.');
        }
        res.send(data);
    });
});

// Запуск сервера
app.listen(PORT, () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
});
