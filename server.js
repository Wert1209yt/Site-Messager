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
const TEXT_FILE = './shared_text.txt';
const SECRET_KEY = 'YOUR_SECRET_KEY'; // Замените на свой секретный ключ
const ADMIN_PASSWORD = '1425@#$nj)'; // Установленный пароль для админ-панели

// Настройка multer для загрузки изображений
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/'); // Папка для хранения загруженных изображений
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname); // Уникальное имя файла
    }
});

const upload = multer({ storage: storage });

app.use(bodyParser.json());
app.use(express.static('public'));
app.use(cookieParser());
app.use('/uploads', express.static('uploads'));

// Функция для чтения пользователей из файла
function readUsers() {
    if (!fs.existsSync(USERS_FILE)) {
        fs.writeFileSync(USERS_FILE, JSON.stringify([]));
    }
    return JSON.parse(fs.readFileSync(USERS_FILE));
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
    users.push({ nickname, password: hashedPassword, blocked: false });
    writeUsers(users);

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
    
    // Проверка блокировки пользователя
    if (user && user.blocked) {
        return res.status(403).send('Ваш аккаунт заблокирован.');
    }

    if (!user) {
        return res.status(400).send('Неверный никнейм или пароль.');
    }

    const isMatch = bcrypt.compareSync(password, user.password);
    if (!isMatch) {
        return res.status(400).send('Неверный никнейм или пароль.');
    }

    const token = jwt.sign({ nickname: user.nickname }, SECRET_KEY, { expiresIn: '1h' });
    
    res.cookie('token', token, { httpOnly: true });
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

       let users = readUsers();
       const user = users.find(user => user.nickname === nickname);

       // Проверка блокировки пользователя
       if (user.blocked) {
           return res.status(403).send('Ваш аккаунт заблокирован.');
       }

       if (!text) {
           return res.status(400).send('Текст не может быть пустым.');
       }

       const formattedText = `${nickname} > ${text}\n`;
       fs.appendFile(TEXT_FILE, formattedText, (err) => {
           if (err) {
               return res.status(500).send('Ошибка при сохранении текста.');
           }
           res.send('Текст успешно добавлен!');
       });

   } catch (error) {
       return res.status(401).send('Токен недействителен.');
   }
});

// Обработка загрузки изображения
app.post('/upload-image', upload.single('image'), (req, res) => {
   const token = req.cookies.token;

   if (!token) {
       return res.status(401).send('Необходима аутентификация.');
   }

   try {
       const decoded = jwt.verify(token, SECRET_KEY);
       const nickname = decoded.nickname;

       let users = readUsers();
       const user = users.find(user => user.nickname === nickname);

       // Проверка блокировки пользователя
       if (user.blocked) {
           return res.status(403).send('Ваш аккаунт заблокирован.');
       }

       if (!req.file) {
           return res.status(400).send('Файл не загружен.');
       }

       const imageMessage = `${nickname} отправил изображение: <img src="/uploads/${req.file.filename}" alt="Image">\n`;
       
       fs.appendFile(TEXT_FILE, imageMessage, (err) => {
           if (err) {
               return res.status(500).send('Ошибка при сохранении информации об изображении.');
           }
           res.send(`Изображение успешно загружено.`);
       });

   } catch (error) {
       return res.status(401).send('Токен недействителен.');
   }
});

// Получение текста и изображений
app.get('/get-text', (req, res) => {
   fs.readFile(TEXT_FILE, 'utf8', (err, data) => {
       if (err) return res.status(500).send('Ошибка при чтении файла.');
       res.send(data);
   });
});

// Проверка пароля для доступа к админ-панели
app.post('/admin/login', (req, res) => {
   const { password } = req.body;

   if (!password || password !== ADMIN_PASSWORD) { 
      return res.status(403).send("Неверный пароль.");
   }

   // Если пароль верный - возвращаем сообщение об успешном входе в админ-панель
   res.send("Вы успешно вошли в админ-панель.");
});

// Админский маршрут для получения всех пользователей
app.get('/admin/users', (req, res) => {
   const users = readUsers();
   res.json(users); // Возвращаем список пользователей в формате JSON
});

// Админский маршрут для блокировки пользователя
app.post('/admin/block-user', (req, res) => {
   const { nickname } = req.body;

   let users = readUsers();
   const userIndex = users.findIndex(user => user.nickname === nickname);

   if (userIndex === -1) {
       return res.status(404).send('Пользователь не найден.');
   }

   users[userIndex].blocked = true; // Блокируем пользователя
   writeUsers(users);
   
   // Удаляем все сообщения пользователя из файла shared_text.txt
   fs.readFile(TEXT_FILE, 'utf8', (err, data) => {
      if (!err && data.includes(nickname)) {
          const updatedData = data.split('\n').filter(line => !line.startsWith(nickname)).join('\n');
          fs.writeFile(TEXT_FILE, updatedData + '\n', err => {});
      }
   });

   res.send(`Пользователь ${nickname} заблокирован.`);
});

// Админский маршрут для разблокировки пользователя
app.post('/admin/unblock-user', (req, res) => {
   const { nickname } = req.body;

   let users = readUsers();
   const userIndex = users.findIndex(user => user.nickname === nickname);

   if (userIndex === -1) {
       return res.status(404).send('Пользователь не найден.');
   }

   users[userIndex].blocked = false; // Разблокируем пользователя
   writeUsers(users);

   res.send(`Пользователь ${nickname} разблокирован.`);
});

// Админский маршрут для отправки сообщения от имени сервера
app.post('/admin/send-message', (req, res) => {
     const { message } = req.body;

     if (!message || message.trim() === '') {
         return res.status(400).send('Сообщение не может быть пустым.');
     }

     // Форматируем сообщение от имени сервера
     const serverMessage = `Сервер > ${message}\n`;

     // Сохраняем сообщение в файл
     fs.appendFile(TEXT_FILE, serverMessage, (err) => {
         if (err) {
             return res.status(500).send('Ошибка при сохранении сообщения.');
         }
         res.send('Сообщение от сервера успешно отправлено.');
     });
});

// Админский маршрут для удаления сообщения по индексу
app.post('/admin/delete-message', (req, res) => {
     const { index } = req.body; // Индекс сообщения

     fs.readFile(TEXT_FILE, 'utf8', (err, data) => {
         if (err) return res.status(500).send('Ошибка при чтении файла.');

         let messagesArray = data.split('\n').filter(line => line); // Разделяем на массив сообщений

         if(index < 0 || index >= messagesArray.length){
             return res.status(404).send("Сообщение не найдено.");
         }

         messagesArray.splice(index, 1); // Удаляем сообщение по индексу

         fs.writeFile(TEXT_FILE, messagesArray.join('\n') + '\n', err => { 
             if(err){
                 return res.status(500).send("Ошибка при удалении сообщения.");
             }
             res.send("Сообщение удалено.");
         });
     });
});

// Админский маршрут для очистки чата
app.post('/admin/clear-chat', (req, res) => {
    fs.writeFile(TEXT_FILE, '', (err) => { // Очищаем файл чата
        if (err) {
            return res.status(500).send('Ошибка при очистке чата.');
        }
        res.send('Чат успешно очищен.');
    });
});

// Запуск сервера
app.listen(PORT, () => console.log(`Сервер запущен на http://localhost:${PORT}`));
