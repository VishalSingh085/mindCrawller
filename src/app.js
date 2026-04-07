
// // // // src/app.js
// // // import express from "express";
// // // import cors from "cors";

// // // import { authRoutes } from "./routes/authRoutes.js";
// // // import messageRoutes from "./routes/messageRoutes.js"
// // // import cookieParser from "cookie-parser";
// // // import path from "path";
// // // import { fileURLToPath } from "url";
// // // import http from "http";
// // // import { Server } from "socket.io";
// // // import SocketHandler from "./socket/socketHandler.js"
// // // import callRoutes from "./routes/callRoutes.js"

// // // const __filename = fileURLToPath(import.meta.url);
// // // const __dirname = path.dirname(__filename);

// // // const app = express();
// // // app.use(cookieParser());
// // // app.use(cors());
// // // app.use(express.json());
// // // app.use(express.urlencoded({ extended: true }));

// // // const server = http.createServer(app);
// // // const io = new Server(server, {
// // //   cors: {
// // //     origin: process.env.CLIENT_URL || "http://localhost:3000",
// // //     credentials: true
// // //   }
// // // });

// // // // Initialize socket handler
// // // const socketHandler = new SocketHandler(io);
// // // socketHandler.initialize();


// // // // Serve static files (uploaded images)
// // // app.use('/uploads', express.static(path.join(__dirname, '../uploads')));
// // // app.get('/reset-password/:token', (req, res) => {
// // //     // Send the HTML file
// // //     res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
// // // });

// // // app.use("/api/auth", authRoutes);
// // // app.use("/api/chat",messageRoutes)
// // // app.use("/api/call",callRoutes)

// // // // export default app;
// // // export default server;

// // // src/app.js
// // import express from "express";
// // import cors from "cors";
// // import cookieParser from "cookie-parser";
// // import path from "path";
// // import { fileURLToPath } from "url";
// // import http from "http";
// // import { Server } from "socket.io";

// // import { authRoutes } from "./routes/authRoutes.js";
// // import videoRoutes from "./routes/videoRoutes.js"
// // import messageRoutes from "./routes/messageRoutes.js";
// // import callRoutes from "./routes/callRoutes.js";
// // import SocketHandler from "./socket/socketHandler.js";

// // const __filename = fileURLToPath(import.meta.url);
// // const __dirname = path.dirname(__filename);

// // const app = express();

// // // ---------------------------
// // // 1. CORS configuration (ONCE)
// // // ---------------------------
// // const allowedOrigins = [
// //   'http://localhost:3000',                 // React dev server
// //   'http://localhost:5173', 
// //   'http://192.168.0.138:5173',                       // Vite (if used)
// //   'https://your-frontend-domain.com',      // production domain
// //   'https://td6lmn5q-5000.inc1.devtunnels.ms',
// //   'https://aichatbotmediconeckt.netlify.app' 
// //    // your tunnel
// // ];

// // // app.use(cors({
// // //   origin: function (origin, callback) {
// // //     // Allow requests with no origin (like mobile apps, curl, Postman)
// // //     if (!origin) return callback(null, true);
// // //     if (allowedOrigins.indexOf(origin) !== -1) {
// // //       callback(null, true);
// // //     } else {
// // //       console.warn(`CORS blocked origin: ${origin}`);
// // //       callback(new Error('Not allowed by CORS'), false);
// // //     }
// // //   },
// // //   credentials: true,      // ✅ allow cookies to be sent/received
// // //   methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
// // //   allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
// // // }));

// // // ---------------------------
// // // 2. Other middleware
// // // ---------------------------
// // app.use(cors({
// //   origin: function (origin, callback) {
// //     // ✅ Allow requests with no origin (file:// protocol, mobile apps, Postman, etc.)
// //     if (!origin) return callback(null, true);
    
// //     // Also check against allowed origins
// //     if (allowedOrigins.indexOf(origin) !== -1) {
// //       callback(null, true);
// //     } else {
// //       console.warn(`CORS blocked origin: ${origin}`);
// //       callback(new Error('Not allowed by CORS'), false);
// //     }
// //   },
// //   credentials: true,
// //   methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
// //   allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
// // }));
// // app.use(helmet());
// // app.use(compression());
// // app.use(cookieParser());
// // app.use(express.json());
// // app.use(express.urlencoded({ extended: true }));

// // // ---------------------------
// // // 3. Static files
// // // ---------------------------
// // app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// // // Serve password reset HTML page
// // app.get('/reset-password/:token', (req, res) => {
// //   res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
// // });

// // // ---------------------------
// // // 4. Routes
// // // ---------------------------
// // app.use("/api/auth", authRoutes);
// // app.use("/api/chat", messageRoutes);
// // app.use("/api/call", callRoutes);
// // app.use("/api/video",videoRoutes);
// // // ---------------------------
// // // 5. HTTP & Socket.IO server
// // // ---------------------------
// // const server = http.createServer(app);
// // const io = new Server(server, {
// //   cors: {
// //     origin: process.env.CLIENT_URL || "http://localhost:3000",
// //     credentials: true
// //   }
// // });

// // // Initialize socket handler
// // const socketHandler = new SocketHandler(io);
// // socketHandler.initialize();

// // export default server;

// // src/app.js
// import express from "express";
// import cors from "cors";
// import helmet from "helmet";  // Add this
// import compression from "compression";  // Add this
// import cookieParser from "cookie-parser";
// import path from "path";
// import { fileURLToPath } from "url";
// import http from "http";
// import { Server } from "socket.io";
// import { authRoutes } from "./routes/authRoutes.js";
// import videoRoutes from "./routes/videoRoutes.js";
// import messageRoutes from "./routes/messageRoutes.js";
// import callRoutes from "./routes/callRoutes.js";
// import SocketHandler from "./socket/socketHandler.js";

// const __filename = fileURLToPath(import.meta.url);
// const __dirname = path.dirname(__filename);

// const app = express();
// app.use(express.json());
// // ---------------------------
// // 1. CORS configuration
// // ---------------------------
// const allowedOrigins = [
//   'https://your-frontend-origin.com',
//   'http://localhost:3000',
//   'http://localhost:5173', 
//   'http://192.168.0.138:5173',
//   'https://your-frontend-domain.com',
//   'https://td6lmn5q-5000.inc1.devtunnels.ms',
//   'https://aichatbotmediconeckt.netlify.app' 
// ];

// app.use(cors({
//   origin: function (origin, callback) {
//     if (!origin) return callback(null, true);
//     if (allowedOrigins.indexOf(origin) !== -1) {
//       callback(null, true);
//     } else {
//       console.warn(`CORS blocked origin: ${origin}`);
//       callback(new Error('Not allowed by CORS'), false);
//     }
//   },
//   credentials: true,
//   methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
//   allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
// }));



// app.use(express.urlencoded({ extended: true }));
// app.use(helmet());
// app.use(compression());
// app.use(cookieParser());


// // ---------------------------
// // 3. Static files
// // ---------------------------
// app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// // Serve password reset HTML page
// app.get('/reset-password/:token', (req, res) => {
//   res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
// });

// // ---------------------------
// // 4. Routes
// // ---------------------------
// app.use("/api/auth", authRoutes);
// app.use("/api/chat", messageRoutes);
// app.use("/api/call", callRoutes);
// app.use("/api/video", videoRoutes); 

// // ---------------------------
// // 5. HTTP & Socket.IO server
// // ---------------------------
// const server = http.createServer(app);
// const io = new Server(server, {
//   cors: {
//     origin: process.env.CLIENT_URL || "http://localhost:3000",
//     credentials: true
//   }
// });

// // Initialize socket handler
// const socketHandler = new SocketHandler(io);
// socketHandler.initialize();

// export default server;

// src/app.js
import express from "express";
import cors from "cors";
import helmet from "helmet";
import compression from "compression";
import cookieParser from "cookie-parser";
import path from "path";
import { fileURLToPath } from "url";
import http from "http";
import { Server } from "socket.io";
import { authRoutes } from "./routes/authRoutes.js";
import videoRoutes from "./routes/videoRoutes.js";
import messageRoutes from "./routes/messageRoutes.js";
import callRoutes from "./routes/callRoutes.js";
import SocketHandler from "./socket/socketHandler.js";
import { videoCallController } from "./controllers/videoCallController.js"; // Add this import

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

// ---------------------------
// 1. CORS configuration
// ---------------------------
const allowedOrigins = [
  'https://your-frontend-origin.com',
  'http://localhost:3000',
  'http://localhost:5173', 
  'http://192.168.0.138:5173',
  'https://your-frontend-domain.com',
  'https://td6lmn5q-5000.inc1.devtunnels.ms',
  'https://aichatbotmediconeckt.netlify.app' 
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.warn(`CORS blocked origin: ${origin}`);
      callback(new Error('Not allowed by CORS'), false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
}));

app.use(express.urlencoded({ extended: true }));
app.use(helmet());
app.use(compression());
app.use(cookieParser());

// ---------------------------
// 3. Static files
// ---------------------------
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// Serve password reset HTML page
app.get('/reset-password/:token', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});

// ---------------------------
// 4. Routes
// ---------------------------
app.use("/api/auth", authRoutes);
app.use("/api/chat", messageRoutes);
app.use("/api/call", callRoutes);
app.use("/api/video", videoRoutes); 

// ---------------------------
// 5. HTTP & Socket.IO server
// ---------------------------
const server = http.createServer(app);

// Create Socket.IO server with proper CORS
const io = new Server(server, {
  cors: {
    origin: allowedOrigins, // Use your allowed origins array
    methods: ["GET", "POST"],
    credentials: true
  }
});

// Make io accessible globally for your controllers
global.io = io;

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);
  
  // Setup WebRTC signaling for video calls
  videoCallController.handleWebRTCSignaling(io, socket);
  
  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// Initialize your existing socket handler (for chat, etc.)
const socketHandler = new SocketHandler(io);
socketHandler.initialize();

export default server;