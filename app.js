import express from 'express';
import cors from 'cors';
import { generateToken04 } from './src/token.js';

const app = express();

// 从环境变量获取 ZEGO AppID 和 Secret
const APP_ID = Number(process.env.ZEGO_APP_ID) || 0;
const APP_SECRET = process.env.ZEGO_APP_SECRET || '';

console.log('ZEGO_APP_ID:', APP_ID ? `${APP_ID}` : 'not set');
console.log('ZEGO_APP_SECRET length:', APP_SECRET ? APP_SECRET.length : 'not set');
console.log('Expected secret length: 32 bytes');

app.use(cors());
app.use(express.json());

// 生成 Token 接口
app.post('/token', (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ error: 'userId 是必填项' });
  }

  if (!APP_ID || !APP_SECRET) {
    return res.status(500).json({
      error: '服务器配置错误：未设置 ZEGO_APP_ID 或 ZEGO_APP_SECRET',
    });
  }

  try {
    // Token 有效期 24 小时
    const token = generateToken04(APP_ID, userId, APP_SECRET, 86400);
    res.json({ token });
  } catch (error) {
    console.error('Token generation error:', error);
    res.status(500).json({ error: '生成 Token 失败' });
  }
});

// 健康检查
app.get('/', (req, res) => {
  res.json({ status: 'ok' });
});

export default app;