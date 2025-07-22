const express = require('express');
const bcrypt = require('bcrypt');
const db = require('./db');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const swaggerUI = require('swagger-ui-express');
const swaggerSpec = require('./swagger');
require('dotenv').config();

const app = express();
app.use('/api-docs', swaggerUI.serve, swaggerUI.setup(swaggerSpec));
app.use(express.json());

// Email setup
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

function generateCode() {
  return Math.floor(1000 + Math.random() * 9000).toString();
}

   /**
    * @swagger
    * /register:
    *   post:
    *     summary: Хэрэглэгч бүртгүүлэх
    *     responses:
    *       201:
    *         description: Хүсэлт амжилттай
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   description: Амжилттай
    *                   example: Код илгээгдлээ. Email-ээ шалгана уу
    *       400:
    *         description: Оруулсан датаг шалгана уу
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   description: Алдааны мэдээлэл
    *                   example: Энэ email бүртгэлтэй байна
    *       500:
    *         description: Системийн админтай холбогдоно уу
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   description: Алдааны мэдээлэл
    *                   example: Код илгээхэд алдаа гарлаа
    */

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        if (await isUserExists(email)) {
            return res.status(400).json({ error: 'Энэ email бүртгэлтэй байна' });
        }

        if (!/^[A-Za-z]+$/.test(name)) {
            return res.status(400).json({ error: 'Нэр зөвхөн үсгээс бүрдэх ёстой' });
        }
        if (!email.includes('@') || !email.includes('.')) {
            return res.status(400).json({ error: 'email буруу байна' });
        }
        if (!password || password.length < 8) {
            return res.status(400).json({ error: 'Нууц үг багадаа 8 тэмдэгт байх ёстой' });
        }
        function generateCode() {
            return Math.floor(1000 + Math.random() * 9000).toString();
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const code = generateCode();

        const query = 'INSERT INTO otp (email, code) VALUES (?, ?)';
        db.query(query, [email, code])

        const query2 = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
        db.query(query2, [name, email, hashedPassword], (err, result) => {
            if (err) throw err;

            transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Баталгаажуулах код',
                text: `Таны баталгаажуулах код: ${code}`
            }, (error, info) => {
                if (error) {
                    console.error(error);
                    return res.status(500).send('Код илгээхэд алдаа гарлаа');
                } else {
                    res.status(201).json({ message: 'Код илгээгдлээ. Email-ээ шалгана уу.' });
                }
            });
        });

    } catch (error) {
        console.error(error);
        res.status(500).send('Серверийн алдаа');
    }
});

/**
    * @swagger
    * /login:
    *   post:
    *     summary: Хэрэглэгч нэвтрэх
    *     responses:
    *       500:
    *         description: Системийн админтай холбогдоно уу
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   description: Алдааны мэдээлэл
    *                   example: Серверийн алдаа
    *       401:
    *         description: Оруулсан датаг шалгана уу
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   description: Алдааны мэдээлэл
    *                   example: Нэвтрэх мэдээлэл буруу байна!
    *       200:
    *         description: Хүсэлт амжилттай
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   description: Амжилттай
    *                   example: Амжилттай нэвтэрлээ
    */

// Login endpoint
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  db.query('SELECT * FROM users WHERE email = ? AND is_verified = true', [email], async (err, results) => {
    if (err) return res.status(500).send('Серверийн алдаа');

    if (results.length > 0) {
      const user = results[0];
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(401).send('Нэвтрэх мэдээлэл буруу байна');

      const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.status(200).json({ message: 'Амжилттай нэвтэрлээ', token });
    } else {
      res.status(401).send('Нэвтрэх мэдээлэл буруу байна!');
    }
  });
});

/**
    * @swagger
    * /verify:
    *   post:
    *     summary: Хэрэглэгч баталгаажуулах
    *     responses:
    *       500:
    *         description: Системийн админтай холбогдоно уу
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   description: Алдааны мэдээлэл
    *                   example: Өгөгдлийн сангийн алдаа
    *       400:
    *         description: Оруулсан датаг шалгана уу
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   description: Алдааны мэдээлэл
    *                   example: OTP хугацаа хэтэрсэн. Дахин бүртгүүлнэ үү!
    *       401:
    *         description: Оруулсан датаг шалгана уу
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   description: Алдааны мэдээлэл
    *                   example: Токен олдсонгүй
    *       403:
    *         description: Оруулсан датаг шалгана уу
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   description: Алдааны мэдээлэл
    *                   example: Токен хүчингүй
    */

// Verify OTP
app.post('/verify', (req, res) => {
  const { email, code } = req.body;
  db.query('SELECT * FROM otp WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).send('Өгөгдлийн сангийн алдаа');
    if (results.length === 0) return res.status(400).send('OTP олдсонгүй');

    const otpData = results[0];
    const elapsedTime = (Date.now() - new Date(otpData.created_at)) / 1000;
    if (elapsedTime > 60) {
      db.query('DELETE FROM otp WHERE email = ?', [email]);
      return res.status(400).send('OTP хугацаа хэтэрсэн. Дахин бүртгүүлнэ үү!');
    }

    if (otpData.code !== code) {
      const attempts = (otpData.attempts || 0) + 1;
      if (attempts >= 3) {
        db.query('DELETE FROM otp WHERE email = ?', [email]);
        db.query('DELETE FROM users WHERE email = ?', [email]);
        return res.status(400).send('Код 3 удаа буруу орсон тул бүртгэл устгагдлаа.');
      } else {
        db.query('UPDATE otp SET attempts = ? WHERE email = ?', [attempts, email]);
        return res.status(400).send(`Код буруу. Үлдсэн оролдлого: ${3 - attempts}`);
      }
    }

    db.query('UPDATE users SET is_verified = TRUE WHERE email = ?', [email]);
    db.query('DELETE FROM otp WHERE email = ?', [email]);
    res.send('Баталгаажуулалт амжилттай. OTP устгагдлаа.');
  });
});

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).send('Токен олдсонгүй');

  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send('Токен хүчингүй');
    req.user = user; // token дээр хадгалсан хэрэглэгчийн мэдээлэл
    next();
  });
}

function isAdmin(req, res, next) {
  const userId = req.user.id;
  db.query('SELECT is_admin FROM users WHERE id = ?', [userId], (err, results) => {
    if (err) return res.status(500).send('Өгөгдлийн сангийн алдаа');
    if (results.length === 0 || !results[0].is_admin) {
      return res.status(403).send('Энэ үйлдлийг зөвшөөрөх эрхгүй');
    }
    next();
  });
}

/**
    * @swagger
    * /products:
    *   post:
    *     summary: Бараа нэмэх 
    *     responses:
    *       500:
    *         description: Системийн админтай холбогдоно уу
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   description: Алдааны мэдээлэл
    *                   example: Бараа нэмэхэд алдаа гарлаа
    *       201:
    *         description: Хүсэлт амжилттай
    *         content: 
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   description: Амжилттай
    *                   example: Бараа амжилттай нэмэгдлээ
    *                 
    */

// Products endpoints
// Зөвхөн админ бараа нэмэх эрхтэй
app.post('/products', verifyToken, isAdmin, (req, res) => {
  const { name, description, price, image_url, stock } = req.body;
  db.query(
    'INSERT INTO products (name, description, price, image_url, stock_quantity) VALUES (?, ?, ?, ?, ?)',
    [name, description, price, image_url, stock],
    (err, result) => {
      if (err) return res.status(500).send('Бараа нэмэхэд алдаа гарлаа');
      res.status(201).send('Бараа амжилттай нэмэгдлээ');
    }
  );
});

/**
 * @swagger
 * /products/{id}:
 *   delete:
 *     summary: Бараа устгах
 *     responses:
 *       500:
 *         description: Системийн админтай холбогдоно уу
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error: 
 *                   type: string
 *                   description: Алдааны мэдээлэл
 *                   example: Бараа устгахад алдаа гарлаа
 *       404:  
 *         description: Оруулсан датаг шалгана уу
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error: 
 *                   type: string
 *                   description: Алдааны мэдээлэл
 *                   example: Ийм ID-тай бараа олдсонгүй
*/

// Зөвхөн админ бараа устгах эрхтэй
app.delete('/products/:id', verifyToken, isAdmin, (req, res) => {
  const productId = req.params.id;

  db.query('DELETE FROM products WHERE id = ?', [productId], (err, result) => {
    if (err) return res.status(500).send('Бараа устгахад алдаа гарлаа');

    if (result.affectedRows === 0) {
      return res.status(404).send('Ийм ID-тай бараа олдсонгүй');
    }

    res.send('Бараа амжилттай устгагдлаа');
  });
});
// Products endpoints
/**
    * @swagger
    * /products:
    *   get:
    *     summary: Барааны жагсаалт
    *     responses:
    *       500:
    *         description: Системийн админтай холбогдоно уу
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   description: Алдааны мэдээлэл
    *                   example: Бараа уншихад алдаа гарлаа
    *       200:
    *         description: Хүсэлт амжилттай
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 title:
    *                   type: string
    *                   description: Амжилттай
    *                   example: Барааны жагсаалт
    *                 id: 
    *                   type: integer
    *                   example: 1
    *                 name:
    *                   type: string
    *                   example: Toy Car
    *                 description:
    *                   type: string
    *                   example: Kids remote toy car
    *                 image_url:
    *                   type: string
    *                   format: uri
    *                   example: https://example.com/image.jpg
    *                 price:
    *                   type: number
    *                   format: float
    *                   example: 25.5
    *                 stock_quantity:
    *                   type: integer
    *                   example: 10
    */
app.get('/products', (req, res) => {
  db.query('SELECT * FROM products', (err, results) => {
    if (err) return res.status(500).send('Бараа уншихад алдаа гарлаа');
    res.json(results);
  });
});

/**
    * @swagger
    * /cart:
    *   post:
    *     summary: Хэрэглэгч бүртгүүлэх
    *     responses:
    *       500:
    *         description: Системийн админтай холбогдоно уу
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   description: Алдааны мэдээлэл
    *                   example: Сагсанд нэмэхэд алдаа гарлаа
    *       201:
    *         description: Хүсэлт амжилттай
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   description: Амжилттай
    *                   example: Сагсанд нэмэгдлээ
    */

// Cart endpoints
app.post('/cart', verifyToken, (req, res) => {
  const user_id = req.user.id;
  const { product_id, quantity } = req.body;
  db.query(
    'INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE quantity = quantity + VALUES(quantity)',
    [user_id, product_id, quantity],
    (err, result) => {
      if (err) return res.status(500).send('Сагсанд нэмэхэд алдаа гарлаа');
      res.status(201).send('Сагсанд нэмэгдлээ');
    }
  );
});

/**
    * @swagger
    * /cart user:
    *   get:
    *     summary: Сагсан дахь бараа харах
    *     responses:
    *       500:
    *         description: Системийн админтай холбогдоно уу
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   description: Алдааны мэдээлэл
    *                   example: Сагсны мэдээлэл авахад алдаа гарлаа
    */

app.get('/cart', verifyToken, (req, res) => {
  const userId = req.user.id;
  db.query(
    'SELECT c.id, c.quantity, p.name, p.price FROM cart c JOIN products p ON c.product_id = p.id WHERE c.user_id = ?',
    [userId],
    (err, results) => {
      if (err) return res.status(500).send('Сагсны мэдээлэл авахад алдаа гарлаа');
      res.json(results);
    }
  );
});

/**
    * @swagger
    * /orders:
    *   post:
    *     summary: захиалга үүсгэх
    *     responses:
    *       500:
    *         description: Системийн админтай холбогдоно уу
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   description: Алдааны мэдээлэл
    *                   example: Захиалга үүсгэхэд алдаа гарлаа
    *       201:
    *         description: Хүсэлт амжилттай
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   description: Амжилттай
    *                   example: Захиалга амжилттай үүслээ
    */

// Orders endpoint
app.post('/orders', (req, res) => {
  const { user_id, cart_items } = req.body;

  db.query(
    'INSERT INTO orders (user_id, order_date) VALUES (?, NOW())',
    [user_id],
    (err, orderResult) => {
      if (err) return res.status(500).send('Захиалга үүсгэхэд алдаа гарлаа');

      const orderId = orderResult.insertId;
      const orderItems = cart_items.map(item => [orderId, item.product_id, item.quantity]);

      db.query(
        'INSERT INTO order_items (order_id, product_id, quantity) VALUES ?',
        [orderItems],
        (err2, result2) => {
          if (err2) return res.status(500).send('Захиалгын бараа нэмэхэд алдаа гарлаа');

          db.query('DELETE FROM cart WHERE user_id = ?', [user_id]);
          res.status(201).send('Захиалга амжилттай үүслээ');
        }
      );
    }
  );
});

// Home test endpoint
app.get('/home', (req, res) => {
  res.send('Hello World!');
});


const isUserExists = (email) => {
    return new Promise((resolve, reject) => {
        const query = 'SELECT * FROM users WHERE email = ?';
        db.query(query, [email], (err, results) => {
        console.log(1111)
            if (err) return reject(err);
            if(results.length > 0) {
                if(results[0].is_verified)
                    resolve(true)
                else {
                    const query = 'DELETE FROM users WHERE email = ?';
                    db.query(query, [email], (err, results) => {
                        if (err) return reject(err);
                    });
                    resolve(false)
                }
            }
            resolve(false);
        });
    });
};

app.listen(3000, () => {
  console.log('Online store app listening on port 3000');
});
