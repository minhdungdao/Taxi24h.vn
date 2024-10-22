const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const fs = require('fs').promises;
const path = require('path');
 // Đảm bảo đã yêu cầu module 'path'

const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const crypto = require('crypto');
const mysql = require('mysql2');
// const http = require('http');

const cors = require('cors');
// const server = http.createServer(app);

// Khởi tạo Express app
const WebSocket = require('ws');

const app = express();
// const wss = new WebSocket.Server({ port: 3000 }); // Chọn cổng 3001 hoặc cổng khác

// Middleware
app.use(bodyParser.json());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static('views'));  // Nếu bạn để HTML trong thư mục views

// Cấu hình session cho Passport
app.use(session({
    secret: 'secret_key',
    resave: false,
    saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());
// Cấu hình kết nối MySQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'batdongsan',
});
// Tạo kết nối đến MySQL
// const connection = mysql.createConnection(dbConfig);

// Kết nối đến MySQL khi khởi động server
// Kiểm tra kết nối
db.connect((err) => {
    if (err) {
        console.error('Error connecting to database:', err);
        return;
    }
    console.log('Connected to MySQL database');
});
// Cấu hình Nodemailer để gửi email xác nhận (Thay thế bằng thông tin của bạn)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'dungdmth1906007@fpt.edu.vn', // Thay thế bằng email của bạn
        pass: 'fdxh sfgj llzg xwhn',    // Thay thế bằng mật khẩu ứng dụng email của bạn
    },
});

// Tạo mã ngẫu nhiên
function generateRandomToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Cấu hình Passport để sử dụng Facebook OAuth
passport.use(new FacebookStrategy({
    clientID: 'FACEBOOK_APP_ID',
    clientSecret: 'FACEBOOK_APP_SECRET',
    callbackURL: "/auth/facebook/callback",
    profileFields: ['id', 'displayName', 'email']
},
    async (accessToken, refreshToken, profile, done) => {
        try {
            const [rows] = await connection.promise().execute('SELECT * FROM users WHERE facebookId = ?', [profile.id]);
            if (rows.length > 0) {
                return done(null, rows[0]);
            } else {
                await connection.promise().execute('INSERT INTO users (fullName, email, facebookId) VALUES (?, ?, ?)',
                    [profile.displayName, profile.emails[0].value, profile.id]);
                return done(null, profile);
            }
        } catch (err) {
            return done(err);
        }
    }
));

// Cấu hình Passport để sử dụng Google OAuth
passport.use(new GoogleStrategy({
    clientID: 'GOOGLE_CLIENT_ID',
    clientSecret: 'GOOGLE_CLIENT_SECRET',
    callbackURL: "/auth/google/callback"
},
    async (accessToken, refreshToken, profile, done) => {
        try {
            const [rows] = await connection.promise().execute('SELECT * FROM users WHERE googleId = ?', [profile.id]);
            if (rows.length > 0) {
                return done(null, rows[0]);
            } else {
                await connection.promise().execute('INSERT INTO users (fullName, email, googleId) VALUES (?, ?, ?)',
                    [profile.displayName, profile.emails[0].value, profile.id]);
                return done(null, profile);
            }
        } catch (err) {
            return done(err);
        }
    }
));

// Passport serialize/deserialize
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const [rows] = await connection.promise().execute('SELECT * FROM users WHERE id = ?', [id]);
        done(null, rows[0]);
    } catch (err) {
        done(err);
    }
});

// Hàm lấy thông tin người dùng theo ID
async function getUserById(userId) {
    const [rows] = await connection.promise().execute('SELECT * FROM users WHERE id = ?', [userId]);
    return rows[0];
}

// Gửi email xác nhận đăng ký
async function sendEmail(email, fullName) {
    const mailOptions = {
        from: 'your_email@example.com', // Thay thế bằng email của bạn
        to: email,
        subject: 'Xác Nhận Đăng Ký',
        text: `Chào ${fullName},\n\nCảm ơn bạn đã đăng ký!`,
    };

    return transporter.sendMail(mailOptions);
}

// Route GET để hiển thị trang chính
app.get('/', async (req, res) => {
    const isLoggedIn = req.session.userId !== undefined; // Kiểm tra người dùng đã đăng nhập
    const user = isLoggedIn ? await getUserById(req.session.userId) : null; // Lấy thông tin người dùng nếu đã đăng nhập

    // Gửi tệp HTML
    res.sendFile(path.join(__dirname, 'views', 'index.html'), {
        user: user || {},
        isLoggedIn: isLoggedIn
    });
});

// Route GET để hiển thị form đăng ký
app.get('/register', async (req, res) => {
    try {
        const data = await fs.readFile(path.join(__dirname, 'views', 'register.html'), 'utf8');
        res.send(data);
    } catch (err) {
        res.status(500).send('Đã xảy ra lỗi khi tải trang đăng ký.');
    }
});

// Route POST để xử lý đăng ký người dùng mới
app.post('/register', async (req, res) => {
    const { fullName, phoneNumber, email, password } = req.body;

    try {
        if (!password || password.trim() === '') {
            return res.status(400).send('Mật khẩu không được để trống.');
        }

        const [results] = await connection.promise().execute('SELECT * FROM users WHERE email = ?', [email]);
        if (results.length > 0) {
            return res.status(400).send('Email đã tồn tại. Vui lòng chọn email khác.');
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        await connection.promise().execute('INSERT INTO users (fullName, phoneNumber, email, password) VALUES (?, ?, ?, ?)',
            [fullName, phoneNumber, email, hashedPassword]);

        await sendEmail(email, fullName);
        res.sendFile(path.join(__dirname, 'views', 'success.html'));
    } catch (error) {
        console.error(error);
        res.status(500).send('Đã xảy ra lỗi. Vui lòng thử lại sau.');
    }
});

// Route GET để hiển thị form đăng nhập
app.get('/login', async (req, res) => {
    try {
        const data = await fs.readFile(path.join(__dirname, 'views', 'login.html'), 'utf8');
        res.send(data);
    } catch (err) {
        res.status(500).send('Đã xảy ra lỗi khi tải trang đăng nhập.');
    }
});

// Route POST để xử lý đăng nhập người dùng
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [results] = await connection.promise().execute('SELECT * FROM users WHERE email = ?', [email]);
        if (results.length === 0) {
            return res.status(401).send('Email không tồn tại');
        }

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).send('Mật khẩu không đúng');
        }

        req.session.userId = user.id;
        req.session.user = user; // Lưu thông tin người dùng trong session
        res.send('Đăng nhập thành công');
    } catch (error) {
        console.error('Lỗi truy vấn:', error);
        res.status(500).send('Có lỗi xảy ra');
    }
});

// Route cho việc đặt lại mật khẩu
app.post('/reset-password', async (req, res) => {
    const { email } = req.body;

    try {
        const [results] = await connection.promise().execute('SELECT * FROM users WHERE email = ?', [email]);
        if (results.length === 0) {
            return res.status(404).send('Email không tồn tại');
        }

        const token = generateRandomToken();
        const resetLink = `http://localhost:3000/reset-password-form?token=${token}&email=${encodeURIComponent(email)}`;

        const mailOptions = {
            from: 'dungth1906007@fpt.edu.vn', // Thay thế bằng email của bạn
            to: email,
            subject: 'Yêu cầu đặt lại mật khẩu',
            html: `
                <p>Vui lòng nhấp vào liên kết dưới đây để đặt lại mật khẩu của bạn:</p>
                <p><a href="${resetLink}" style="color: blue; text-decoration: underline;">Quên mật khẩu</a></p>
                <p>Nếu bạn không yêu cầu đặt lại mật khẩu, vui lòng bỏ qua email này.</p>
            `
        };

        await transporter.sendMail(mailOptions);
        res.send('Email đặt lại mật khẩu đã được gửi');
    } catch (error) {
        console.error('Lỗi gửi email:', error);
        res.status(500).send('Có lỗi xảy ra khi gửi email');
    }
});

// Route GET để hiển thị trang đặt lại mật khẩu
app.get('/reset-password-form', async (req, res) => {
    const { token, email } = req.query;
    res.sendFile(path.join(__dirname, 'views', 'reset-password.html'));
});

// Route POST để xử lý đặt lại mật khẩu
app.post('/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;

    try {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        await connection.promise().execute('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);
        res.send('Mật khẩu đã được cập nhật thành công');
    } catch (error) {
        console.error('Lỗi cập nhật mật khẩu:', error);
        res.status(500).send('Có lỗi xảy ra trong quá trình cập nhật mật khẩu');
    }
});

// Route GET cho trang tài khoản
app.get('/account', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).send('Bạn cần phải đăng nhập để truy cập trang này.');
    }

    try {
        const [rows] = await connection.promise().execute('SELECT * FROM users WHERE id = ?', [req.session.userId]);
        const user = rows[0];

        if (user) {
            const accountPage = `
                <!DOCTYPE html>
                <html lang="vi">
                <head>
                    <meta charset="UTF-8">
                    <title>Tài khoản của tôi</title>
                </head>
                <body>
                    <h1>Tài khoản của tôi</h1>
                    <p>Họ và tên: ${user.fullName}</p>
                    <p>Email: ${user.email}</p>
                    <p>Số điện thoại: ${user.phoneNumber}</p>
                    
                    <!-- Form để đăng xuất -->
                    <form action="/logout" method="POST">
                        <button type="submit">Đăng xuất</button>
                    </form>

                    <a href="/">Về trang chính</a>
                </body>
                </html>
            `;
            res.send(accountPage);
        } else {
            res.status(404).send('Người dùng không tồn tại.');
        }
    } catch (error) {
        console.error('Lỗi truy vấn:', error);
        res.status(500).send('Có lỗi xảy ra khi lấy thông tin tài khoản.');
    }
});

// Route POST để xử lý đăng xuất
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Có lỗi xảy ra khi đăng xuất.');
        }
        res.redirect('/'); // Chuyển hướng về trang chính
    });
});

// Route GET để hiển thị trang mua xe
app.get('/buy-car', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'buy-car.html'));
});

// Route cho trang giới thiệu
app.get('/introduction', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'introduction.html'));
});

// Route cho trang tuyển dụng
app.get('/recruitment', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'recruitment.html'));
});


// Xử lý khi người dùng submit form
  // Lấy dữ liệu từ form gửi lên
app.post('/recruitment', (req, res) => {
    const { name, age, email, phone, service_type, vehicle_type, experience, pickup_location, start_time, return_time, notes } = req.body;

    // Kiểm tra các trường bắt buộc
    if (!name || !email || !phone || !service_type) {
        return res.status(400).json({ error: 'Vui lòng cung cấp đầy đủ thông tin!' });
    }

    // Câu lệnh SQL để thêm dữ liệu vào cơ sở dữ liệu
    const sql = `
        INSERT INTO quanlydon 
        (name, age, email, phone, service_type, vehicle_type, experience, pickup_location, start_time, return_time, notes, registered_time) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    `;

    // Giá trị của các cột trong bảng
    const values = [name, age, email, phone, service_type, vehicle_type, experience, pickup_location, start_time, return_time, notes];

    // Thực thi câu lệnh SQL
    db.query(sql, values, (err, result) => {
        if (err) {
            console.error('Lỗi khi thêm vào cơ sở dữ liệu:', err);
            return res.status(500).json({ error: 'Đã xảy ra lỗi với cơ sở dữ liệu.' });
        }
        res.status(200).json({ message: 'Đơn tư vấn đã được gửi thành công!' });
    });
});

app.get('/dich-vu-khac', (req, res) => {
    const filePath = path.join(__dirname, 'views', 'dich-vu-khac.html');
    console.log('Serving file from:', filePath);
    res.sendFile(filePath);
});


app.get('/inform-company', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'inform-company.html'));
});
// Endpoint để hiển thị trang admin
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});


// Route để lấy tất cả đơn đăng ký
app.get('/api/quanlydon', (req, res) => {
    db.query('SELECT * FROM quanlydon', (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi khi lấy dữ liệu' });
        }
        res.json(results);
    });
});

// Route để lấy một đơn đăng ký theo ID
app.get('/api/quanlydon/:id', (req, res) => {
    const id = req.params.id;
    db.query('SELECT * FROM quanlydon WHERE id = ?', [id], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi khi lấy dữ liệu' });
        }
        if (results.length > 0) {
            res.json(results[0]);
        } else {
            res.status(404).json({ error: 'Không tìm thấy đơn đăng ký' });
        }
    });
});

// Route để cập nhật một đơn đăng ký theo ID
app.put('/api/quanlydon/:id', (req, res) => {
    const id = req.params.id;
    db.query('UPDATE quanlydon SET ? WHERE id = ?', [req.body, id], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi khi cập nhật dữ liệu' });
        }
        if (results.affectedRows > 0) {
            res.json({ message: 'Cập nhật thành công' });
        } else {
            res.status(404).json({ error: 'Không tìm thấy đơn đăng ký' });
        }
    });
});
app.put('/api/updateContactStatus/:id', (req, res) => {
    const donId = req.params.id;
    const { is_contacted } = req.body;

    // Cập nhật trạng thái "đã liên lạc" trong cơ sở dữ liệu
    const sql = `UPDATE quanlydon SET is_contacted = ? WHERE id = ?`;
    db.query(sql, [is_contacted, donId], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Cập nhật thất bại' });
        }
        res.json({ message: 'Cập nhật thành công' });
    });
});

// Route để xóa một đơn đăng ký theo ID
app.delete('/api/quanlydon/:id', (req, res) => {
    const id = req.params.id;
    db.query('DELETE FROM quanlydon WHERE id = ?', [id], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Lỗi khi xóa dữ liệu' });
        }
        if (results.affectedRows > 0) {
            res.json({ message: 'Xóa thành công' });
        } else {
            res.status(404).json({ error: 'Không tìm thấy đơn đăng ký' });
        }
    });
});

app.patch('/api/quanlydon/:id', (req, res) => {
    console.log('Request body:', req.body); // Log body yêu cầu
    const registration = registrations.find(r => r.id == req.params.id);
    if (registration) {
        if (req.body.has_contacted !== undefined) {
            registration.has_contacted = req.body.has_contacted;
            res.json({ message: 'Cập nhật trạng thái thành công' });
        } else {
            console.error('Missing has_contacted field'); // Log lỗi
            res.status(400).json({ error: 'Thiếu thông tin cập nhật' });
        }
    } else {
        console.error('Registration not found'); // Log lỗi
        res.status(404).json({ error: 'Không tìm thấy đơn đăng ký' });
    }
});



// Chạy server
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0'; // Địa chỉ IP LAN cụ thể của bạn
app.listen(PORT, HOST, () => {
    console.log(`Server đang chạy trên ${HOST}:${PORT}`);
});

