const express = require('express');
const cors = require('cors');
const multer = require('multer');
const dns = require('dns');
const net = require('net');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(express.static('public'));

// Настройка multer для загрузки больших файлов
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = 'uploads';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 100 * 1024 * 1024, // 100MB max file size
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'text/plain' || 
            file.mimetype === 'text/csv' || 
            file.mimetype === 'application/vnd.ms-excel' ||
            file.originalname.match(/\.(txt|csv)$/)) {
            cb(null, true);
        } else {
            cb(new Error('Разрешены только TXT и CSV файлы'), false);
        }
    }
});

class AdvancedSMTPValidator {
    constructor(timeout = 15000) {
        this.timeout = timeout;
        this.concurrentLimit = 5; // Уменьшено для стабильности
        this.rateLimitDelay = 200; // Задержка между группами
    }

    isValidFormat(email) {
        const pattern = /^[a-zA-Z0-9][a-zA-Z0-9._%+-]{0,63}@[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}\.[a-zA-Z]{2,}$/;
        return pattern.test(email);
    }

    getMxRecords(domain) {
        return new Promise((resolve, reject) => {
            dns.resolveMx(domain, (err, addresses) => {
                if (err || !addresses || addresses.length === 0) {
                    resolve([]);
                } else {
                    const sorted = addresses.sort((a, b) => a.priority - b.priority);
                    resolve(sorted.map(record => record.exchange));
                }
            });
        });
    }

    async verifyEmail(email) {
        const result = {
            email: email,
            isValid: false,
            category: 'invalid',
            message: '',
            details: {}
        };

        // 1. Проверка формата
        if (!this.isValidFormat(email)) {
            result.message = 'Неверный формат email';
            result.category = 'invalid_format';
            return result;
        }

        const [, domain] = email.split('@');
        
        // 2. Проверка MX записей
        let mxRecords;
        try {
            mxRecords = await this.getMxRecords(domain);
            if (mxRecords.length === 0) {
                result.message = 'MX записи не найдены';
                result.category = 'no_mx_records';
                return result;
            }
            result.details.mxRecords = mxRecords;
        } catch (error) {
            result.message = 'Ошибка поиска MX записей';
            result.category = 'dns_error';
            return result;
        }

        // 3. SMTP проверка
        for (const mxHost of mxRecords) {
            try {
                const smtpResult = await this.checkSmtpServer(mxHost, email);
                if (smtpResult.isValid) {
                    result.isValid = true;
                    result.message = 'Email существует';
                    result.category = 'valid';
                    result.details.smtpServer = mxHost;
                    return result;
                } else {
                    result.message = smtpResult.message;
                    result.category = smtpResult.category || 'smtp_error';
                    result.details.smtpServer = mxHost;
                    // Продолжаем пробовать другие MX серверы
                    continue;
                }
            } catch (error) {
                // Пробуем следующий MX сервер
                continue;
            }
        }

        // Если все MX серверы не ответили
        if (!result.message) {
            result.message = 'Все SMTP серверы недоступны';
            result.category = 'smtp_timeout';
        }

        return result;
    }

    checkSmtpServer(mxHost, email) {
        return new Promise((resolve, reject) => {
            const socket = net.createConnection(25, mxHost);
            let timeoutId;
            let responseBuffer = '';

            const cleanup = () => {
                if (timeoutId) clearTimeout(timeoutId);
                try {
                    socket.write('QUIT\r\n');
                    setTimeout(() => {
                        socket.end();
                        socket.destroy();
                    }, 100);
                } catch (e) {}
            };

            timeoutId = setTimeout(() => {
                cleanup();
                resolve({ 
                    isValid: false, 
                    message: 'Таймаут подключения',
                    category: 'smtp_timeout'
                });
            }, this.timeout);

            socket.on('connect', () => {
                responseBuffer = '';
            });

            socket.on('data', (data) => {
                responseBuffer += data.toString();
                const lines = responseBuffer.split('\r\n');
                
                for (let i = 0; i < lines.length - 1; i++) {
                    const line = lines[i];
                    const code = parseInt(line.substring(0, 3));
                    
                    if (line.startsWith('220')) {
                        // Приветственное сообщение сервера
                        socket.write(`HELO email-validator.com\r\n`);
                    } else if (line.startsWith('250') && line.includes('HELO')) {
                        // Ответ на HELO
                        socket.write(`MAIL FROM: <check@email-validator.com>\r\n`);
                    } else if (line.startsWith('250') && line.includes('MAIL')) {
                        // Ответ на MAIL FROM
                        socket.write(`RCPT TO: <${email}>\r\n`);
                    } else if (line.startsWith('250') && line.includes('RCPT')) {
                        // Успешный ответ на RCPT TO - email существует
                        cleanup();
                        resolve({ 
                            isValid: true, 
                            message: 'Email существует',
                            category: 'valid'
                        });
                        return;
                    } else if (code === 550 || code === 551) {
                        // Email не существует
                        cleanup();
                        resolve({ 
                            isValid: false, 
                            message: 'Email не существует',
                            category: 'not_existing'
                        });
                        return;
                    } else if (code === 552 || code === 553) {
                        // Ошибка почтового ящика
                        cleanup();
                        resolve({ 
                            isValid: false, 
                            message: 'Ошибка почтового ящика',
                            category: 'mailbox_error'
                        });
                        return;
                    } else if (code === 421 || code === 450) {
                        // Временная ошибка сервера
                        cleanup();
                        resolve({ 
                            isValid: false, 
                            message: 'Временная ошибка сервера',
                            category: 'temporary_error'
                        });
                        return;
                    } else if (code >= 500 && code <= 599) {
                        // Постоянная ошибка
                        cleanup();
                        resolve({ 
                            isValid: false, 
                            message: `Ошибка сервера: ${line}`,
                            category: 'smtp_error'
                        });
                        return;
                    }
                }
            });

            socket.on('error', (error) => {
                cleanup();
                resolve({ 
                    isValid: false, 
                    message: `Ошибка подключения: ${error.message}`,
                    category: 'connection_error'
                });
            });

            socket.on('end', () => {
                cleanup();
            });
        });
    }

    // Анализ статистики по результатам
    analyzeResults(results) {
        const stats = {
            total: results.length,
            valid: 0,
            invalid: 0,
            categories: {
                valid: 0,
                invalid_format: 0,
                no_mx_records: 0,
                dns_error: 0,
                not_existing: 0,
                smtp_timeout: 0,
                smtp_error: 0,
                connection_error: 0,
                mailbox_error: 0,
                temporary_error: 0
            },
            domains: {},
            topDomains: []
        };

        results.forEach(result => {
            if (result.isValid) {
                stats.valid++;
                stats.categories.valid++;
            } else {
                stats.invalid++;
                stats.categories[result.category] = (stats.categories[result.category] || 0) + 1;
            }

            // Статистика по доменам
            if (result.email.includes('@')) {
                const domain = result.email.split('@')[1];
                if (!stats.domains[domain]) {
                    stats.domains[domain] = { total: 0, valid: 0, invalid: 0 };
                }
                stats.domains[domain].total++;
                if (result.isValid) {
                    stats.domains[domain].valid++;
                } else {
                    stats.domains[domain].invalid++;
                }
            }
        });

        // Топ доменов
        stats.topDomains = Object.entries(stats.domains)
            .sort(([, a], [, b]) => b.total - a.total)
            .slice(0, 10)
            .map(([domain, data]) => ({
                domain,
                ...data,
                validityRate: ((data.valid / data.total) * 100).toFixed(1)
            }));

        return stats;
    }

    // Пакетная обработка с прогрессом
    async processBatch(emails, onProgress, onStatsUpdate) {
        const results = [];
        let completed = 0;
        const total = emails.length;

        // Функция для обработки группы email'ов
        const processGroup = async (group) => {
            const groupPromises = group.map(async (email) => {
                try {
                    const result = await this.verifyEmail(email);
                    completed++;
                    
                    if (onProgress) {
                        onProgress(completed, total, result);
                    }

                    // Обновляем статистику каждые 100 email'ов
                    if (completed % 100 === 0 && onStatsUpdate) {
                        const currentStats = this.analyzeResults(results);
                        onStatsUpdate(currentStats);
                    }

                    return result;
                } catch (error) {
                    completed++;
                    const errorResult = {
                        email,
                        isValid: false,
                        category: 'processing_error',
                        message: `Ошибка обработки: ${error.message}`,
                        details: {}
                    };
                    
                    if (onProgress) {
                        onProgress(completed, total, errorResult);
                    }
                    
                    return errorResult;
                }
            });

            return await Promise.all(groupPromises);
        };

        // Разбиваем на группы для параллельной обработки
        const groups = [];
        for (let i = 0; i < emails.length; i += this.concurrentLimit) {
            groups.push(emails.slice(i, i + this.concurrentLimit));
        }

        // Обрабатываем группы последовательно с задержкой
        for (let i = 0; i < groups.length; i++) {
            if (i > 0) {
                await new Promise(resolve => setTimeout(resolve, this.rateLimitDelay));
            }

            const groupResults = await processGroup(groups[i]);
            results.push(...groupResults);
        }

        // Финальная статистика
        const finalStats = this.analyzeResults(results);
        if (onStatsUpdate) {
            onStatsUpdate(finalStats);
        }

        return {
            results,
            statistics: finalStats
        };
    }
}

const validator = new AdvancedSMTPValidator();

// Маршруты
app.post('/api/validate-single', async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ error: 'Email обязателен' });
    }

    try {
        const result = await validator.verifyEmail(email);
        res.json(result);
    } catch (error) {
        res.status(500).json({ 
            isValid: false, 
            message: `Ошибка проверки: ${error.message}`,
            category: 'server_error'
        });
    }
});

app.post('/api/validate-batch', async (req, res) => {
    const { emails } = req.body;
    
    if (!emails || !Array.isArray(emails)) {
        return res.status(400).json({ error: 'Массив emails обязателен' });
    }

    // Лимит 50,000 email'ов
    if (emails.length > 50000) {
        return res.status(400).json({ error: 'Максимум 50,000 email адресов за раз' });
    }

    try {
        console.log(`Начинаем проверку ${emails.length} email адресов...`);
        
        const batchResult = await validator.processBatch(
            emails, 
            (completed, total, result) => {
                console.log(`Прогресс: ${completed}/${total} - ${result.email}`);
            },
            (stats) => {
                console.log('Обновление статистики:', stats);
            }
        );
        
        res.json({ 
            success: true,
            total: emails.length,
            ...batchResult
        });
    } catch (error) {
        res.status(500).json({ 
            error: `Ошибка пакетной проверки: ${error.message}` 
        });
    }
});

app.post('/api/upload', upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Файл не загружен' });
    }

    try {
        const content = fs.readFileSync(req.file.path, 'utf8');
        
        // Парсим email адреса из файла
        const emails = content.split('\n')
            .map(email => email.trim())
            .filter(email => {
                if (email.length === 0) return false;
                if (email.startsWith('#')) return false;
                if (email.startsWith('//')) return false;
                
                // Поддержка CSV формата
                if (email.includes(',')) {
                    const firstColumn = email.split(',')[0].trim();
                    return firstColumn.includes('@') && firstColumn.length > 3;
                }
                
                return email.includes('@') && email.length > 3;
            })
            .map(email => {
                // Извлекаем email если это CSV
                if (email.includes(',')) {
                    return email.split(',')[0].trim();
                }
                return email;
            })
            .slice(0, 50000); // Лимит 50,000

        console.log(`Загружено ${emails.length} email адресов из файла`);

        // Начинаем проверку
        const batchResult = await validator.processBatch(emails, 
            (completed, total, result) => {
                console.log(`Прогресс: ${completed}/${total} - ${result.email}`);
            },
            (stats) => {
                console.log('Статистика обновлена:', stats);
            }
        );

        // Удаляем временный файл
        fs.unlinkSync(req.file.path);

        res.json({ 
            success: true,
            total: emails.length,
            ...batchResult
        });
    } catch (error) {
        // Удаляем временный файл в случае ошибки
        if (fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        
        res.status(500).json({ 
            error: `Ошибка обработки файла: ${error.message}` 
        });
    }
});

// Маршрут для проверки статуса сервера
app.get('/api/status', (req, res) => {
    res.json({ 
        status: 'ok', 
        maxEmails: 50000,
        features: ['smtp_validation', 'detailed_statistics', 'batch_processing'],
        message: 'Сервер готов к работе' 
    });
});

// Главная страница
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Обработка ошибок
app.use((error, req, res, next) => {
    console.error('Ошибка сервера:', error);
    res.status(500).json({ 
        error: 'Внутренняя ошибка сервера',
        message: error.message 
    });
});

app.listen(PORT, () => {
    console.log(`🚀 Advanced SMTP Email Validator server running on port ${PORT}`);
    console.log(`📧 Access the application at: http://localhost:${PORT}`);
    console.log(`📊 Maximum emails per batch: 50,000`);
    console.log(`⚡ Concurrent validations: ${validator.concurrentLimit}`);
    console.log(`📈 Features: Detailed statistics, Category analysis, Domain analytics`);
});