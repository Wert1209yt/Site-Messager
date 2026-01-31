const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 3000;

// Пути к файлам данных
const DATA_DIR = './data';
const CHATS_DIR = path.join(DATA_DIR, 'chats');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const GROUPS_FILE = path.join(DATA_DIR, 'groups.json');
const TEXT_FILE = path.join(CHATS_DIR, 'general.txt');

const SECRET_KEY = 'YOUR_SECRET_KEY';
const ADMIN_PASSWORD = '1425@#$nj)';

// Создание необходимых директорий
function initializeDirectories() {
    [DATA_DIR, CHATS_DIR, 'uploads'].forEach(dir => {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
    });
}

initializeDirectories();

// Настройка multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});

const upload = multer({ storage });

app.use(bodyParser.json());
app.use(express.static('public'));
app.use(cookieParser());
app.use('/uploads', express.static('uploads'));

// ==================== УТИЛИТЫ ====================

function readJSON(filePath, defaultValue = []) {
    if (!fs.existsSync(filePath)) {
        fs.writeFileSync(filePath, JSON.stringify(defaultValue, null, 2));
    }
    return JSON.parse(fs.readFileSync(filePath));
}

function writeJSON(filePath, data) {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function readUsers() {
    return readJSON(USERS_FILE, []);
}

function writeUsers(users) {
    writeJSON(USERS_FILE, users);
}

function readGroups() {
    return readJSON(GROUPS_FILE, []);
}

function writeGroups(groups) {
    writeJSON(GROUPS_FILE, groups);
}

function getGroupChatFile(groupId) {
    return path.join(CHATS_DIR, `group_${groupId}.txt`);
}

function getChatFile(groupId = null) {
    return groupId ? getGroupChatFile(groupId) : TEXT_FILE;
}

function readMessages(groupId = null) {
    const filePath = getChatFile(groupId);
    if (!fs.existsSync(filePath)) {
        fs.writeFileSync(filePath, '');
        return [];
    }
    const data = fs.readFileSync(filePath, 'utf8');
    return data.split('\n').filter(line => line.trim()).map((line, index) => {
        try {
            return JSON.parse(line);
        } catch {
            // Поддержка старого формата
            return { id: `legacy_${index}`, content: line, timestamp: Date.now() };
        }
    });
}

function writeMessages(messages, groupId = null) {
    const filePath = getChatFile(groupId);
    const data = messages.map(msg => JSON.stringify(msg)).join('\n');
    fs.writeFileSync(filePath, data + (messages.length ? '\n' : ''));
}

function appendMessage(message, groupId = null) {
    const filePath = getChatFile(groupId);
    fs.appendFileSync(filePath, JSON.stringify(message) + '\n');
}

function verifyToken(req) {
    const token = req.cookies.token;
    if (!token) return null;
    try {
        return jwt.verify(token, SECRET_KEY);
    } catch {
        return null;
    }
}

function getUserByNickname(nickname) {
    const users = readUsers();
    return users.find(u => u.nickname === nickname);
}

function isUserBlocked(nickname) {
    const user = getUserByNickname(nickname);
    return user && user.blocked;
}

// Middleware для аутентификации
function authMiddleware(req, res, next) {
    const decoded = verifyToken(req);
    if (!decoded) {
        return res.status(401).send('Необходима аутентификация.');
    }
    if (isUserBlocked(decoded.nickname)) {
        return res.status(403).send('Ваш аккаунт заблокирован.');
    }
    req.user = decoded;
    next();
}

// ==================== АУТЕНТИФИКАЦИЯ ====================

// Регистрация пользователя
app.post('/register', (req, res) => {
    const { nickname, password } = req.body;

    if (!nickname || !password) {
        return res.status(400).send('Никнейм и пароль обязательны.');
    }

    if (nickname.length < 3 || nickname.length > 20) {
        return res.status(400).send('Никнейм должен быть от 3 до 20 символов.');
    }

    if (password.length < 6) {
        return res.status(400).send('Пароль должен быть минимум 6 символов.');
    }

    let users = readUsers();

    if (users.find(user => user.nickname.toLowerCase() === nickname.toLowerCase())) {
        return res.status(400).send('Никнейм уже занят.');
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    const newUser = {
        id: uuidv4(),
        nickname,
        password: hashedPassword,
        blocked: false,
        createdAt: Date.now(),
        groups: []
    };

    users.push(newUser);
    writeUsers(users);

    const joinMessage = {
        id: uuidv4(),
        type: 'system',
        content: `${nickname} присоединился`,
        timestamp: Date.now()
    };
    appendMessage(joinMessage);

    res.status(201).send('Пользователь зарегистрирован.');
});

// Вход в аккаунт
app.post('/login', (req, res) => {
    const { nickname, password } = req.body;

    if (!nickname || !password) {
        return res.status(400).send('Никнейм и пароль обязательны.');
    }

    const user = getUserByNickname(nickname);

    if (!user) {
        return res.status(400).send('Неверный никнейм или пароль.');
    }

    if (user.blocked) {
        return res.status(403).send('Ваш аккаунт заблокирован.');
    }

    if (!bcrypt.compareSync(password, user.password)) {
        return res.status(400).send('Неверный никнейм или пароль.');
    }

    const token = jwt.sign({ nickname: user.nickname, id: user.id }, SECRET_KEY, { expiresIn: '24h' });
    res.cookie('token', token, { httpOnly: true });
    res.json({ message: 'Вход выполнен успешно!', user: { nickname: user.nickname, id: user.id } });
});

// Выход из аккаунта
app.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.send('Вы вышли из аккаунта.');
});

// ==================== ПРОФИЛЬ ПОЛЬЗОВАТЕЛЯ ====================

// Изменение никнейма
app.post('/change-nickname', authMiddleware, (req, res) => {
    const { newNickname, currentPassword } = req.body;
    const { nickname } = req.user;

    if (!newNickname || !currentPassword) {
        return res.status(400).send('Новый никнейм и текущий пароль обязательны.');
    }

    if (newNickname.length < 3 || newNickname.length > 20) {
        return res.status(400).send('Никнейм должен быть от 3 до 20 символов.');
    }

    let users = readUsers();
    const userIndex = users.findIndex(u => u.nickname === nickname);

    if (userIndex === -1) {
        return res.status(404).send('Пользователь не найден.');
    }

    if (!bcrypt.compareSync(currentPassword, users[userIndex].password)) {
        return res.status(400).send('Неверный текущий пароль.');
    }

    if (users.find(u => u.nickname.toLowerCase() === newNickname.toLowerCase() && u.nickname !== nickname)) {
        return res.status(400).send('Этот никнейм уже занят.');
    }

    const oldNickname = users[userIndex].nickname;
    users[userIndex].nickname = newNickname;
    writeUsers(users);

    // Обновляем никнейм в группах
    let groups = readGroups();
    groups.forEach(group => {
        if (group.creator === oldNickname) {
            group.creator = newNickname;
        }
        const memberIndex = group.members.indexOf(oldNickname);
        if (memberIndex !== -1) {
            group.members[memberIndex] = newNickname;
        }
    });
    writeGroups(groups);

    // Создаём новый токен
    const token = jwt.sign({ nickname: newNickname, id: users[userIndex].id }, SECRET_KEY, { expiresIn: '24h' });
    res.cookie('token', token, { httpOnly: true });

    res.json({ message: 'Никнейм успешно изменён.', newNickname });
});

// Изменение пароля
app.post('/change-password', authMiddleware, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const { nickname } = req.user;

    if (!currentPassword || !newPassword) {
        return res.status(400).send('Текущий и новый пароль обязательны.');
    }

    if (newPassword.length < 6) {
        return res.status(400).send('Новый пароль должен быть минимум 6 символов.');
    }

    let users = readUsers();
    const userIndex = users.findIndex(u => u.nickname === nickname);

    if (userIndex === -1) {
        return res.status(404).send('Пользователь не найден.');
    }

    if (!bcrypt.compareSync(currentPassword, users[userIndex].password)) {
        return res.status(400).send('Неверный текущий пароль.');
    }

    users[userIndex].password = bcrypt.hashSync(newPassword, 10);
    writeUsers(users);

    res.send('Пароль успешно изменён.');
});

// Получение информации о профиле
app.get('/profile', authMiddleware, (req, res) => {
    const user = getUserByNickname(req.user.nickname);
    if (!user) {
        return res.status(404).send('Пользователь не найден.');
    }
    res.json({
        id: user.id,
        nickname: user.nickname,
        createdAt: user.createdAt,
        groups: user.groups || []
    });
});

// ==================== СООБЩЕНИЯ ====================

// Сохранение текста
app.post('/save-text', authMiddleware, (req, res) => {
    const { text, groupId } = req.body;
    const { nickname } = req.user;

    if (!text || !text.trim()) {
        return res.status(400).send('Текст не может быть пустым.');
    }

    // Проверка доступа к группе
    if (groupId) {
        const groups = readGroups();
        const group = groups.find(g => g.id === groupId);
        if (!group) {
            return res.status(404).send('Группа не найдена.');
        }
        if (!group.members.includes(nickname)) {
            return res.status(403).send('Вы не являетесь участником этой группы.');
        }
    }

    const message = {
        id: uuidv4(),
        type: 'text',
        author: nickname,
        content: text.trim(),
        timestamp: Date.now(),
        edited: false
    };

    appendMessage(message, groupId);
    res.json({ message: 'Текст успешно добавлен!', messageId: message.id });
});

// Редактирование сообщения
app.post('/edit-message', authMiddleware, (req, res) => {
    const { messageId, newContent, groupId } = req.body;
    const { nickname } = req.user;

    if (!messageId || !newContent || !newContent.trim()) {
        return res.status(400).send('ID сообщения и новый текст обязательны.');
    }

    let messages = readMessages(groupId);
    const messageIndex = messages.findIndex(m => m.id === messageId);

    if (messageIndex === -1) {
        return res.status(404).send('Сообщение не найдено.');
    }

    if (messages[messageIndex].author !== nickname) {
        return res.status(403).send('Вы можете редактировать только свои сообщения.');
    }

    if (messages[messageIndex].type !== 'text') {
        return res.status(400).send('Можно редактировать только текстовые сообщения.');
    }

    messages[messageIndex].content = newContent.trim();
    messages[messageIndex].edited = true;
    messages[messageIndex].editedAt = Date.now();

    writeMessages(messages, groupId);
    res.send('Сообщение успешно отредактировано.');
});

// Удаление своего сообщения
app.post('/delete-my-message', authMiddleware, (req, res) => {
    const { messageId, groupId } = req.body;
    const { nickname } = req.user;

    if (!messageId) {
        return res.status(400).send('ID сообщения обязателен.');
    }

    let messages = readMessages(groupId);
    const messageIndex = messages.findIndex(m => m.id === messageId);

    if (messageIndex === -1) {
        return res.status(404).send('Сообщение не найдено.');
    }

    if (messages[messageIndex].author !== nickname) {
        return res.status(403).send('Вы можете удалять только свои сообщения.');
    }

    messages.splice(messageIndex, 1);
    writeMessages(messages, groupId);
    res.send('Сообщение удалено.');
});

// Загрузка изображения
app.post('/upload-image', authMiddleware, upload.single('image'), (req, res) => {
    const { nickname } = req.user;
    const groupId = req.body.groupId;

    if (!req.file) {
        return res.status(400).send('Файл не загружен.');
    }

    // Проверка доступа к группе
    if (groupId) {
        const groups = readGroups();
        const group = groups.find(g => g.id === groupId);
        if (!group || !group.members.includes(nickname)) {
            return res.status(403).send('Нет доступа к этой группе.');
        }
    }

    const message = {
        id: uuidv4(),
        type: 'image',
        author: nickname,
        content: `/uploads/${req.file.filename}`,
        timestamp: Date.now()
    };

    appendMessage(message, groupId);
    res.json({ message: 'Изображение успешно загружено.', messageId: message.id });
});

// Загрузка голосового сообщения
app.post('/upload-voice', authMiddleware, upload.single('voice'), (req, res) => {
    const { nickname } = req.user;
    const groupId = req.body.groupId;

    if (!req.file) {
        return res.status(400).send('Файл не загружен.');
    }

    // Проверка доступа к группе
    if (groupId) {
        const groups = readGroups();
        const group = groups.find(g => g.id === groupId);
        if (!group || !group.members.includes(nickname)) {
            return res.status(403).send('Нет доступа к этой группе.');
        }
    }

    const message = {
        id: uuidv4(),
        type: 'voice',
        author: nickname,
        content: `/uploads/${req.file.filename}`,
        timestamp: Date.now()
    };

    appendMessage(message, groupId);
    res.json({ message: 'Голосовое сообщение успешно загружено.', messageId: message.id });
});

// Получение текста
app.get('/get-text', (req, res) => {
    const groupId = req.query.groupId;
    
    // Проверка доступа к группе
    if (groupId) {
        const decoded = verifyToken(req);
        if (!decoded) {
            return res.status(401).send('Необходима аутентификация.');
        }
        const groups = readGroups();
        const group = groups.find(g => g.id === groupId);
        if (!group || !group.members.includes(decoded.nickname)) {
            return res.status(403).send('Нет доступа к этой группе.');
        }
    }

    const messages = readMessages(groupId);
    res.json(messages);
});

// ==================== ГРУППОВЫЕ ЧАТЫ ====================

// Создание группы
app.post('/groups/create', authMiddleware, (req, res) => {
    const { name } = req.body;
    const { nickname } = req.user;

    if (!name || !name.trim()) {
        return res.status(400).send('Название группы обязательно.');
    }

    if (name.length < 2 || name.length > 50) {
        return res.status(400).send('Название группы должно быть от 2 до 50 символов.');
    }

    const groups = readGroups();

    const newGroup = {
        id: uuidv4(),
        name: name.trim(),
        creator: nickname,
        members: [nickname],
        createdAt: Date.now()
    };

    groups.push(newGroup);
    writeGroups(groups);

    // Создаём файл чата для группы
    fs.writeFileSync(getGroupChatFile(newGroup.id), '');

    // Добавляем группу пользователю
    let users = readUsers();
    const userIndex = users.findIndex(u => u.nickname === nickname);
    if (userIndex !== -1) {
        if (!users[userIndex].groups) users[userIndex].groups = [];
        users[userIndex].groups.push(newGroup.id);
        writeUsers(users);
    }

    res.json({ message: 'Группа создана.', group: newGroup });
});

// Получение списка групп пользователя
app.get('/groups', authMiddleware, (req, res) => {
    const { nickname } = req.user;
    const groups = readGroups();
    const userGroups = groups.filter(g => g.members.includes(nickname));
    res.json(userGroups);
});

// Получение информации о группе
app.get('/groups/:groupId', authMiddleware, (req, res) => {
    const { groupId } = req.params;
    const { nickname } = req.user;

    const groups = readGroups();
    const group = groups.find(g => g.id === groupId);

    if (!group) {
        return res.status(404).send('Группа не найдена.');
    }

    if (!group.members.includes(nickname)) {
        return res.status(403).send('Вы не являетесь участником этой группы.');
    }

    res.json(group);
});

// Изменение названия группы
app.post('/groups/:groupId/rename', authMiddleware, (req, res) => {
    const { groupId } = req.params;
    const { newName } = req.body;
    const { nickname } = req.user;

    if (!newName || !newName.trim()) {
        return res.status(400).send('Новое название обязательно.');
    }

    if (newName.length < 2 || newName.length > 50) {
        return res.status(400).send('Название группы должно быть от 2 до 50 символов.');
    }

    let groups = readGroups();
    const groupIndex = groups.findIndex(g => g.id === groupId);

    if (groupIndex === -1) {
        return res.status(404).send('Группа не найдена.');
    }

    if (groups[groupIndex].creator !== nickname) {
        return res.status(403).send('Только создатель может переименовать группу.');
    }

    groups[groupIndex].name = newName.trim();
    writeGroups(groups);

    res.json({ message: 'Название группы изменено.', newName: newName.trim() });
});

// Добавление участника в группу
app.post('/groups/:groupId/add-member', authMiddleware, (req, res) => {
    const { groupId } = req.params;
    const { memberNickname } = req.body;
    const { nickname } = req.user;

    if (!memberNickname) {
        return res.status(400).send('Никнейм участника обязателен.');
    }

    let groups = readGroups();
    const groupIndex = groups.findIndex(g => g.id === groupId);

    if (groupIndex === -1) {
        return res.status(404).send('Группа не найдена.');
    }

    if (groups[groupIndex].creator !== nickname) {
        return res.status(403).send('Только создатель может добавлять участников.');
    }

    const memberUser = getUserByNickname(memberNickname);
    if (!memberUser) {
        return res.status(404).send('Пользователь не найден.');
    }

    if (groups[groupIndex].members.includes(memberNickname)) {
        return res.status(400).send('Пользователь уже в группе.');
    }

    groups[groupIndex].members.push(memberNickname);
    writeGroups(groups);

    // Добавляем группу пользователю
    let users = readUsers();
    const userIndex = users.findIndex(u => u.nickname === memberNickname);
    if (userIndex !== -1) {
        if (!users[userIndex].groups) users[userIndex].groups = [];
        users[userIndex].groups.push(groupId);
        writeUsers(users);
    }

    // Системное сообщение
    const message = {
        id: uuidv4(),
        type: 'system',
        content: `${memberNickname} добавлен в группу`,
        timestamp: Date.now()
    };
    appendMessage(message, groupId);

    res.send('Участник добавлен.');
});

// Удаление участника из группы
app.post('/groups/:groupId/remove-member', authMiddleware, (req, res) => {
    const { groupId } = req.params;
    const { memberNickname } = req.body;
    const { nickname } = req.user;

    let groups = readGroups();
    const groupIndex = groups.findIndex(g => g.id === groupId);

    if (groupIndex === -1) {
        return res.status(404).send('Группа не найдена.');
    }

    if (groups[groupIndex].creator !== nickname) {
        return res.status(403).send('Только создатель может удалять участников.');
    }

    if (memberNickname === groups[groupIndex].creator) {
        return res.status(400).send('Создатель не может быть удалён из группы.');
    }

    const memberIndex = groups[groupIndex].members.indexOf(memberNickname);
    if (memberIndex === -1) {
        return res.status(404).send('Участник не найден в группе.');
    }

    groups[groupIndex].members.splice(memberIndex, 1);
    writeGroups(groups);

    // Удаляем группу у пользователя
    let users = readUsers();
    const userIndex = users.findIndex(u => u.nickname === memberNickname);
    if (userIndex !== -1 && users[userIndex].groups) {
        users[userIndex].groups = users[userIndex].groups.filter(g => g !== groupId);
        writeUsers(users);
    }

    // Системное сообщение
    const message = {
        id: uuidv4(),
        type: 'system',
        content: `${memberNickname} удалён из группы`,
        timestamp: Date.now()
    };
    appendMessage(message, groupId);

    res.send('Участник удалён.');
});

// Выход из группы
app.post('/groups/:groupId/leave', authMiddleware, (req, res) => {
    const { groupId } = req.params;
    const { nickname } = req.user;

    let groups = readGroups();
    const groupIndex = groups.findIndex(g => g.id === groupId);

    if (groupIndex === -1) {
        return res.status(404).send('Группа не найдена.');
    }

    if (groups[groupIndex].creator === nickname) {
        return res.status(400).send('Создатель не может покинуть группу. Удалите группу вместо этого.');
    }

    const memberIndex = groups[groupIndex].members.indexOf(nickname);
    if (memberIndex === -1) {
        return res.status(404).send('Вы не являетесь участником этой группы.');
    }

    groups[groupIndex].members.splice(memberIndex, 1);
    writeGroups(groups);

    // Удаляем группу у пользователя
    let users = readUsers();
    const userIndex = users.findIndex(u => u.nickname === nickname);
        if (userIndex !== -1 && users[userIndex].groups) {
        users[userIndex].groups = users[userIndex].groups.filter(g => g !== groupId);
        writeUsers(users);
    }

    // Системное сообщение
    const message = {
        id: uuidv4(),
        type: 'system',
        content: `${nickname} покинул группу`,
        timestamp: Date.now()
    };
    appendMessage(message, groupId);

    res.send('Вы покинули группу.');
});

// Удаление группы
app.post('/groups/:groupId/delete', authMiddleware, (req, res) => {
    const { groupId } = req.params;
    const { nickname } = req.user;

    let groups = readGroups();
    const groupIndex = groups.findIndex(g => g.id === groupId);

    if (groupIndex === -1) {
        return res.status(404).send('Группа не найдена.');
    }

    if (groups[groupIndex].creator !== nickname) {
        return res.status(403).send('Только создатель может удалить группу.');
    }

    const members = groups[groupIndex].members;

    // Удаляем группу у всех участников
    let users = readUsers();
        users.forEach((user, index) => {
        if (user.groups && user.groups.includes(groupId)) {
            users[index].groups = user.groups.filter(g => g !== groupId);
        }
    });
    writeUsers(users);

    // Удаляем файл чата
    const chatFile = getGroupChatFile(groupId);
    if (fs.existsSync(chatFile)) {
        fs.unlinkSync(chatFile);
    }

    groups.splice(groupIndex, 1);
    writeGroups(groups);

    res.send('Группа удалена.');
});

// ==================== АДМИН-ПАНЕЛЬ ====================

// Проверка пароля для доступа к админ-панели
app.post('/admin/login', (req, res) => {
    const { password } = req.body;

    if (!password || password !== ADMIN_PASSWORD) {
        return res.status(403).send('Неверный пароль.');
    }

    res.send('Вы успешно вошли в админ-панель.');
});

// Получение всех пользователей
app.get('/admin/users', (req, res) => {
    const users = readUsers().map(u => ({
        id: u.id,
        nickname: u.nickname,
        blocked: u.blocked,
        createdAt: u.createdAt,
        groups: u.groups || []
    }));
    res.json(users);
});

// Получение всех групп
app.get('/admin/groups', (req, res) => {
    const groups = readGroups();
    res.json(groups);
});

// Блокировка пользователя
app.post('/admin/block-user', (req, res) => {
    const { nickname } = req.body;

    let users = readUsers();
    const userIndex = users.findIndex(user => user.nickname === nickname);

    if (userIndex === -1) {
        return res.status(404).send('Пользователь не найден.');
    }

    users[userIndex].blocked = true;
    writeUsers(users);

    // Удаляем сообщения пользователя из общего чата
    let messages = readMessages();
    messages = messages.filter(m => m.author !== nickname);
    writeMessages(messages);

    res.send(`Пользователь ${nickname} заблокирован.`);
});

// Разблокировка пользователя
app.post('/admin/unblock-user', (req, res) => {
    const { nickname } = req.body;

    let users = readUsers();
    const userIndex = users.findIndex(user => user.nickname === nickname);

    if (userIndex === -1) {
        return res.status(404).send('Пользователь не найден.');
    }

    users[userIndex].blocked = false;
    writeUsers(users);

    res.send(`Пользователь ${nickname} разблокирован.`);
});

// Отправка сообщения от сервера
app.post('/admin/send-message', (req, res) => {
    const { message, groupId } = req.body;

    if (!message || !message.trim()) {
        return res.status(400).send('Сообщение не может быть пустым.');
    }

    const serverMessage = {
        id: uuidv4(),
        type: 'server',
        author: 'Сервер',
        content: message.trim(),
        timestamp: Date.now()
    };

    appendMessage(serverMessage, groupId);
    res.send('Сообщение от сервера успешно отправлено.');
});

// Удаление сообщения по индексу
app.post('/admin/delete-message', (req, res) => {
    const { index, groupId } = req.body;

    let messages = readMessages(groupId);

    if (index < 0 || index >= messages.length) {
        return res.status(404).send('Сообщение не найдено.');
    }

    messages.splice(index, 1);
    writeMessages(messages, groupId);
    res.send('Сообщение удалено.');
});

// Удаление сообщения по ID
app.post('/admin/delete-message-by-id', (req, res) => {
    const { messageId, groupId } = req.body;

    let messages = readMessages(groupId);
    const messageIndex = messages.findIndex(m => m.id === messageId);

    if (messageIndex === -1) {
        return res.status(404).send('Сообщение не найдено.');
    }

    messages.splice(messageIndex, 1);
    writeMessages(messages, groupId);
    res.send('Сообщение удалено.');
});

// Очистка чата
app.post('/admin/clear-chat', (req, res) => {
    const { groupId } = req.body;
    writeMessages([], groupId);
    res.send('Чат успешно очищен.');
});

// Удаление группы админом
app.post('/admin/delete-group', (req, res) => {
    const { groupId } = req.body;

    let groups = readGroups();
    const groupIndex = groups.findIndex(g => g.id === groupId);
    if (groupIndex === -1) {
        return res.status(404).send('Группа не найдена.');
    }

    // Удаляем группу у всех участников
    let users = readUsers();
    users.forEach((user, index) => {
        if (user.groups && user.groups.includes(groupId)) {
            users[index].groups = user.groups.filter(g => g !== groupId);
        }
    });
    writeUsers(users);

    // Удаляем файл чата
    const chatFile = getGroupChatFile(groupId);
    if (fs.existsSync(chatFile)) {
        fs.unlinkSync(chatFile);
    }

    groups.splice(groupIndex, 1);
    writeGroups(groups);

    res.send('Группа удалена администратором.');
});

// Запуск сервера
app.listen(PORT, () => console.log(`Сервер запущен на http://localhost:${PORT}`));
