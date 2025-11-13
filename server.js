import express from 'express'
import cookieParser from 'cookie-parser';
import cors from 'cors';
import dotenv from 'dotenv';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import hpp from 'hpp';
dotenv.config();

import './firebase.js';
import { userRoutres } from './routes/user_routes.js';
import { errorHandler, notFoundHandler } from './middlewares/error_middlewares.js';

const app = express()

// Disable x-powered-by header
app.disable('x-powered-by');

// Trust proxy in production (needed for secure cookies and rate limiting behind proxies)
if (process.env.NODE_ENV === 'production') {
	app.set('trust proxy', 1);
}

// Basic health
app.get('/', (req, res) => {
  res.send('Hello World!')
});

const PORT = process.env.PORT || 8000

// Security: Helmet
app.use(helmet({
	crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

// Request size limits and parsing
app.use(express.json({ limit: '100kb', type: ['application/json', 'application/*+json'] }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));
app.use(cookieParser());

// Prevent HTTP Parameter Pollution
app.use(hpp());

// CORS (configured for cross-origin)
const allowedOrigin = process.env.CLIENT_ORIGIN;
console.log('[SERVER] Allowed CORS origin:', allowedOrigin);

// Build allowed origins array
const allowedOrigins = [];
if (allowedOrigin) {
	allowedOrigins.push(allowedOrigin);
}
if (process.env.NODE_ENV !== 'production') {
	allowedOrigins.push('http://localhost:5173');
}

app.use(cors({
	origin: function (origin, callback) {
		// Allow requests with no origin (like mobile apps or curl requests)
		if (!origin) return callback(null, true);
		
		// Check if origin is in allowed list
		if (allowedOrigins.includes(origin)) {
			callback(null, true);
		} else {
			console.warn('[CORS] Blocked origin:', origin);
			callback(new Error('Not allowed by CORS'));
		}
	},
	credentials: true, // CRITICAL: Must be true for cookies to work
	methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
	allowedHeaders: ['Content-Type','Authorization','X-Requested-With','X-CSRF-Token'],
	exposedHeaders: ['Set-Cookie'], // Expose Set-Cookie header
}));

// Anti-CSRF: validate Origin for state-changing requests (production only)
// Note: Relaxed for cross-origin cookie support
if (process.env.NODE_ENV === 'production' && process.env.COOKIE_SAME_SITE !== 'none') {
	app.use((req, res, next) => {
		const method = req.method.toUpperCase();
		if (['POST','PUT','PATCH','DELETE'].includes(method)) {
			const origin = req.headers.origin;
			if (origin && !allowedOrigins.includes(origin)) {
				console.warn('[CSRF] Blocked request from origin:', origin);
				return res.status(403).json({ error: 'Forbidden: invalid origin' });
			}
		}
		next();
	});
}

// Rate limiting (per IP)
const limiter = rateLimit({
	windowMs: 5 * 60 * 1000, // 5 minutes
	max: Number(process.env.RATE_LIMIT_MAX || 200), // max requests per window per IP
	standardHeaders: true,
	legacyHeaders: false,
	message: { error: 'Too many requests, please try again later.' },
});
app.use('/api/', limiter);

// Routes
app.use('/api/users', userRoutres);

// Error handling middleware (must be after routes)
app.use(notFoundHandler);
app.use(errorHandler);

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`)
})