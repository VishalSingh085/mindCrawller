// import Chat from '../models/Chat.js';
// import Message from '../models/Message.js';
// import User from '../models/userModel.js';

// class SocketHandler {
//   constructor(io) {
//     this.io = io;
//   }

//   initialize() {
//     this.io.on('connection', async (socket) => {
//       console.log(`📱 User connected: ${socket.userId} (${socket.userRole})`);
      
//       // Get user details
//       const user = await User.findById(socket.userId);
//       if (!user) {
//         console.log(`User not found: ${socket.userId}`);
//         socket.disconnect();
//         return;
//       }
      
//       // Join user's personal room
//       const userRoom = `${socket.userRole}_${socket.userId}`;
//       socket.join(userRoom);
      
//       // Join all active chats for this user
//       await this.joinExistingChats(socket);
      
//       // Handle joining a specific chat
//       socket.on('join-chat', (data) => this.handleJoinChat(socket, data));
      
//       // Handle sending message
//       socket.on('send-message', (data) => this.handleSendMessage(socket, data));
      
//       // Handle typing indicator
//       socket.on('typing', (data) => this.handleTyping(socket, data));
      
//       // Handle mark as read
//       socket.on('mark-read', (data) => this.handleMarkRead(socket, data));
      
//       // Handle disconnection
//       socket.on('disconnect', () => {
//         console.log(`📱 User disconnected: ${socket.userId}`);
//       });
//     });
//   }

//   async joinExistingChats(socket) {
//     try {
//       let chats;
//       if (socket.userRole === 'user') {
//         chats = await Chat.find({ userId: socket.userId, isActive: true });
//       } else if (socket.userRole === 'counsellor') {
//         chats = await Chat.find({ counselorId: socket.userId, isActive: true });
//       }
      
//       if (chats && chats.length > 0) {
//         chats.forEach(chat => {
//           const chatRoom = `chat_${chat.chatId}`;
//           socket.join(chatRoom);
//           console.log(`Joined existing chat room: ${chatRoom}`);
//         });
//       }
//     } catch (error) {
//       console.error('Error joining existing chats:', error);
//     }
//   }

//   async handleJoinChat(socket, { chatId }) {
//     try {
//       const chat = await Chat.findById(chatId);
      
//       if (!chat) {
//         socket.emit('error', { message: 'Chat not found' });
//         return;
//       }
      
//       // Verify authorization
//       const isAuthorized = (socket.userRole === 'user' && chat.userId.toString() === socket.userId) ||
//                           (socket.userRole === 'counsellor' && chat.counselorId.toString() === socket.userId);
      
//       if (!isAuthorized) {
//         socket.emit('error', { message: 'Unauthorized' });
//         return;
//       }
      
//       const chatRoom = `chat_${chat.chatId}`;
//       socket.join(chatRoom);
      
//       // Mark messages as read
//       const updateResult = await Message.updateMany(
//         {
//           chatId: chat._id,
//           senderRole: socket.userRole === 'user' ? 'counsellor' : 'user',
//           isRead: false
//         },
//         {
//           isRead: true,
//           readAt: new Date()
//         }
//       );
      
//       if (updateResult.modifiedCount > 0) {
//         socket.to(chatRoom).emit('messages-read', { chatId: chat._id });
//       }
      
//       socket.emit('chat-joined', { 
//         chatId: chat._id, 
//         chatRoom,
//         message: 'Successfully joined chat'
//       });
      
//     } catch (error) {
//       console.error('Error joining chat:', error);
//       socket.emit('error', { message: 'Error joining chat' });
//     }
//   }

//   async handleSendMessage(socket, { chatId, content, contentType = 'TEXT' }) {
//     try {
//       const chat = await Chat.findById(chatId)
//         .populate('userId', 'fullName email profilePhoto')
//         .populate('counselorId', 'fullName specialization profilePhoto rating');
      
//       if (!chat) {
//         socket.emit('error', { message: 'Chat not found' });
//         return;
//       }
      
//       // Verify authorization
//       const isAuthorized = (socket.userRole === 'user' && chat.userId._id.toString() === socket.userId) ||
//                           (socket.userRole === 'counsellor' && chat.counselorId._id.toString() === socket.userId);
      
//       if (!isAuthorized) {
//         socket.emit('error', { message: 'Unauthorized' });
//         return;
//       }
      
//       // Create message
//       const message = await Message.create({
//         chatId: chat._id,
//         senderId: socket.userId,
//         senderRole: socket.userRole,
//         content: content,
//         contentType: contentType
//       });
      
//       // Update chat
//       await Chat.findByIdAndUpdate(chat._id, {
//         lastMessage: content,
//         lastMessageAt: new Date(),
//         updatedAt: new Date()
//       });
      
//       const messageData = {
//         id: message._id,
//         messageId: message.messageId,
//         chatId: message.chatId,
//         content: message.content,
//         senderRole: message.senderRole,
//         contentType: message.contentType,
//         createdAt: message.createdAt,
//         isRead: message.isRead
//       };
      
//       // Emit to chat room
//       const chatRoom = `chat_${chat.chatId}`;
//       this.io.to(chatRoom).emit('new-message', messageData);
      
//       // Notify other user
//       const otherUserRoom = socket.userRole === 'user' 
//         ? `counsellor_${chat.counselorId._id}` 
//         : `user_${chat.userId._id}`;
      
//       const senderInfo = socket.userRole === 'user' ? chat.userId : chat.counselorId;
      
//       this.io.to(otherUserRoom).emit('message-notification', {
//         chatId: chat._id,
//         message: messageData,
//         sender: {
//           id: senderInfo._id,
//           name: senderInfo.fullName,
//           role: socket.userRole
//         }
//       });
      
//       console.log(`Message sent in chat ${chat._id} by ${socket.userRole}_${socket.userId}`);
      
//     } catch (error) {
//       console.error('Error sending message:', error);
//       socket.emit('error', { message: 'Error sending message' });
//     }
//   }

//   handleTyping(socket, { chatId, isTyping }) {
//     const chatRoom = `chat_${chatId}`;
//     socket.to(chatRoom).emit('user-typing', {
//       userId: socket.userId,
//       userRole: socket.userRole,
//       isTyping
//     });
//   }

//   async handleMarkRead(socket, { chatId }) {
//     try {
//       const updateResult = await Message.updateMany(
//         {
//           chatId: chatId,
//           senderRole: socket.userRole === 'user' ? 'counsellor' : 'user',
//           isRead: false
//         },
//         {
//           isRead: true,
//           readAt: new Date()
//         }
//       );
      
//       if (updateResult.modifiedCount > 0) {
//         const chat = await Chat.findById(chatId);
//         if (chat) {
//           const chatRoom = `chat_${chat.chatId}`;
//           this.io.to(chatRoom).emit('messages-read', { chatId: chatId });
//         }
//       }
//     } catch (error) {
//       console.error('Error marking messages as read:', error);
//     }
//   }
// }

// export default SocketHandler;

import Chat from '../models/Chat.js';
import Message from '../models/Message.js';
import User from '../models/userModel.js';
import Call from '../models/Call.js';

class SocketHandler {
  constructor(io) {
    this.io = io;
  }

  initialize() {
    this.io.on('connection', async (socket) => {
      console.log(`📱 User connected: ${socket.userId} (${socket.userRole})`);
      
      // Get user details
      const user = await User.findById(socket.userId);
      if (!user) {
        console.log(`User not found: ${socket.userId}`);
        socket.disconnect();
        return;
      }
      
      // Join the role-specific room and a stable fallback room so
      // call notifications can be delivered regardless of role spelling.
      const userRoom = `${socket.userRole}_${socket.userId}`;
      socket.join(userRoom);
      socket.join(`user_${socket.userId}`);
      if (socket.userRole === 'counsellor') {
        socket.join(`counselor_${socket.userId}`);
      }
      if (socket.userRole === 'counselor') {
        socket.join(`counsellor_${socket.userId}`);
      }
      
      // Join all active chats for this user
      await this.joinExistingChats(socket);
      
      // Handle joining a specific chat
      socket.on('join-chat', (data) => this.handleJoinChat(socket, data));
      
      // Handle sending message
      socket.on('send-message', (data) => this.handleSendMessage(socket, data));
      
      // Handle typing indicator
      socket.on('typing', (data) => this.handleTyping(socket, data));
      
      // Handle mark as read
      socket.on('mark-read', (data) => this.handleMarkRead(socket, data));
      
      // ========== CALL SIGNALING HANDLERS ==========
      
      // Handle joining a call room
      socket.on('join-call', async ({ callId }) => {
        try {
          const call = await Call.findOne({ callId: callId });
          if (!call) {
            socket.emit('error', { message: 'Call not found' });
            return;
          }
          
          // Check if user is authorized to join this call
          const isAuthorized = (call.callerId.toString() === socket.userId) ||
                              (call.receiverId.toString() === socket.userId);
          
          if (!isAuthorized) {
            socket.emit('error', { message: 'Unauthorized to join this call' });
            return;
          }
          
          const callRoom = `call_${callId}`;
          socket.join(callRoom);
          
          // Setup call signaling for this socket
          this.setupCallSignaling(socket, callId);
          
          socket.emit('call-joined', { 
            callId, 
            callRoom,
            callType: call.callType,
            message: 'Successfully joined call'
          });
          
          console.log(`User ${socket.userId} joined call room: ${callRoom}`);
        } catch (error) {
          console.error('Error joining call:', error);
          socket.emit('error', { message: 'Error joining call' });
        }
      });
      
      // Handle leaving a call
      socket.on('leave-call', ({ callId }) => {
        const callRoom = `call_${callId}`;
        socket.leave(callRoom);
        console.log(`User ${socket.userId} left call room: ${callRoom}`);
        
        // Notify others in the call
        socket.to(callRoom).emit('user-left-call', {
          userId: socket.userId,
          userRole: socket.userRole,
          callId: callId
        });
      });
      
      // Handle disconnection
      socket.on('disconnect', () => {
        console.log(`📱 User disconnected: ${socket.userId}`);
      });
    });
  }

  async joinExistingChats(socket) {
    try {
      let chats;
      if (socket.userRole === 'user') {
        chats = await Chat.find({ userId: socket.userId, isActive: true });
      } else if (socket.userRole === 'counsellor') {
        chats = await Chat.find({ counselorId: socket.userId, isActive: true });
      }
      
      if (chats && chats.length > 0) {
        chats.forEach(chat => {
          const chatRoom = `chat_${chat.chatId}`;
          socket.join(chatRoom);
          console.log(`Joined existing chat room: ${chatRoom}`);
        });
      }
    } catch (error) {
      console.error('Error joining existing chats:', error);
    }
  }

  async handleJoinChat(socket, { chatId }) {
    try {
      const chat = await Chat.findById(chatId);
      
      if (!chat) {
        socket.emit('error', { message: 'Chat not found' });
        return;
      }
      
      // Verify authorization
      const isAuthorized = (socket.userRole === 'user' && chat.userId.toString() === socket.userId) ||
                          (socket.userRole === 'counsellor' && chat.counselorId.toString() === socket.userId);
      
      if (!isAuthorized) {
        socket.emit('error', { message: 'Unauthorized' });
        return;
      }
      
      const chatRoom = `chat_${chat.chatId}`;
      socket.join(chatRoom);
      
      // Mark messages as read
      const updateResult = await Message.updateMany(
        {
          chatId: chat._id,
          senderRole: socket.userRole === 'user' ? 'counsellor' : 'user',
          isRead: false
        },
        {
          isRead: true,
          readAt: new Date()
        }
      );
      
      if (updateResult.modifiedCount > 0) {
        socket.to(chatRoom).emit('messages-read', { chatId: chat._id });
      }
      
      socket.emit('chat-joined', { 
        chatId: chat._id, 
        chatRoom,
        message: 'Successfully joined chat'
      });
      
    } catch (error) {
      console.error('Error joining chat:', error);
      socket.emit('error', { message: 'Error joining chat' });
    }
  }

  async handleSendMessage(socket, { chatId, content, contentType = 'TEXT' }) {
    try {
      const chat = await Chat.findById(chatId)
        .populate('userId', 'fullName email profilePhoto')
        .populate('counselorId', 'fullName specialization profilePhoto rating');
      
      if (!chat) {
        socket.emit('error', { message: 'Chat not found' });
        return;
      }
      
      // Verify authorization
      const isAuthorized = (socket.userRole === 'user' && chat.userId._id.toString() === socket.userId) ||
                          (socket.userRole === 'counsellor' && chat.counselorId._id.toString() === socket.userId);
      
      if (!isAuthorized) {
        socket.emit('error', { message: 'Unauthorized' });
        return;
      }
      
      // Create message
      const message = await Message.create({
        chatId: chat._id,
        senderId: socket.userId,
        senderRole: socket.userRole,
        content: content,
        contentType: contentType
      });
      
      // Update chat
      await Chat.findByIdAndUpdate(chat._id, {
        lastMessage: content,
        lastMessageAt: new Date(),
        updatedAt: new Date()
      });
      
      const messageData = {
        id: message._id,
        messageId: message.messageId,
        chatId: message.chatId,
        content: message.content,
        senderRole: message.senderRole,
        contentType: message.contentType,
        createdAt: message.createdAt,
        isRead: message.isRead
      };
      
      // Emit to chat room
      const chatRoom = `chat_${chat.chatId}`;
      this.io.to(chatRoom).emit('new-message', messageData);
      
      // Notify other user
      const otherUserRoom = socket.userRole === 'user' 
        ? `counsellor_${chat.counselorId._id}` 
        : `user_${chat.userId._id}`;
      
      const senderInfo = socket.userRole === 'user' ? chat.userId : chat.counselorId;
      
      this.io.to(otherUserRoom).emit('message-notification', {
        chatId: chat._id,
        message: messageData,
        sender: {
          id: senderInfo._id,
          name: senderInfo.fullName,
          role: socket.userRole
        }
      });
      
      console.log(`Message sent in chat ${chat._id} by ${socket.userRole}_${socket.userId}`);
      
    } catch (error) {
      console.error('Error sending message:', error);
      socket.emit('error', { message: 'Error sending message' });
    }
  }

  handleTyping(socket, { chatId, isTyping }) {
    const chatRoom = `chat_${chatId}`;
    socket.to(chatRoom).emit('user-typing', {
      userId: socket.userId,
      userRole: socket.userRole,
      isTyping
    });
  }

  async handleMarkRead(socket, { chatId }) {
    try {
      const updateResult = await Message.updateMany(
        {
          chatId: chatId,
          senderRole: socket.userRole === 'user' ? 'counsellor' : 'user',
          isRead: false
        },
        {
          isRead: true,
          readAt: new Date()
        }
      );
      
      if (updateResult.modifiedCount > 0) {
        const chat = await Chat.findById(chatId);
        if (chat) {
          const chatRoom = `chat_${chat.chatId}`;
          this.io.to(chatRoom).emit('messages-read', { chatId: chatId });
        }
      }
    } catch (error) {
      console.error('Error marking messages as read:', error);
    }
  }

  // ========== CALL SIGNALING METHODS ==========

  setupCallSignaling(socket, callId) {
    const callRoom = `call_${callId}`;
    
    // WebRTC Offer
    socket.on('call-offer', ({ callId: callIdParam, offer, to }) => {
      if (callIdParam !== callId) return;
      console.log(`📞 Call offer from ${socket.userId} to ${to}`);
      const toRoom = `user_${to}`;
      socket.to(toRoom).emit('call-offer', {
        callId: callIdParam,
        offer,
        from: socket.userId,
        fromRole: socket.userRole,
        to
      });
      // Also broadcast to call room
      socket.to(callRoom).emit('call-offer', {
        callId: callIdParam,
        offer,
        from: socket.userId,
        fromRole: socket.userRole,
        to
      });
    });
    
    // WebRTC Answer
    socket.on('call-answer', ({ callId: callIdParam, answer, to }) => {
      if (callIdParam !== callId) return;
      console.log(`📞 Call answer from ${socket.userId} to ${to}`);
      const toRoom = `user_${to}`;
      socket.to(toRoom).emit('call-answer', {
        callId: callIdParam,
        answer,
        from: socket.userId,
        to
      });
      // Also broadcast to call room
      socket.to(callRoom).emit('call-answer', {
        callId: callIdParam,
        answer,
        from: socket.userId,
        to
      });
    });
    
    // WebRTC ICE Candidate
    socket.on('ice-candidate', ({ callId: callIdParam, candidate, to }) => {
      if (callIdParam !== callId) return;
      console.log(`🎯 ICE candidate from ${socket.userId}`);
      const toRoom = `user_${to}`;
      socket.to(toRoom).emit('ice-candidate', {
        callId: callIdParam,
        candidate,
        from: socket.userId,
        to
      });
      // Also broadcast to call room
      socket.to(callRoom).emit('ice-candidate', {
        callId: callIdParam,
        candidate,
        from: socket.userId,
        to
      });
    });
    
    // Call status updates
    socket.on('call-status-update', ({ callId: callIdParam, status, to }) => {
      if (callIdParam !== callId) return;
      const toRoom = `user_${to}`;
      socket.to(toRoom).emit('call-status-update', {
        callId: callIdParam,
        status,
        from: socket.userId,
        to,
        timestamp: new Date()
      });
      // Broadcast to call room
      socket.to(callRoom).emit('call-status-update', {
        callId: callIdParam,
        status,
        from: socket.userId,
        to,
        timestamp: new Date()
      });
    });
    
    // Mute/Unmute
    socket.on('call-mute-toggle', ({ callId: callIdParam, isMuted, to }) => {
      if (callIdParam !== callId) return;
      const toRoom = `user_${to}`;
      socket.to(toRoom).emit('call-mute-toggle', {
        callId: callIdParam,
        isMuted,
        from: socket.userId,
        to
      });
      // Broadcast to call room
      socket.to(callRoom).emit('call-mute-toggle', {
        callId: callIdParam,
        isMuted,
        from: socket.userId,
        to
      });
    });
    
    // Speaker toggle
    socket.on('call-speaker-toggle', ({ callId: callIdParam, isSpeakerOn, to }) => {
      if (callIdParam !== callId) return;
      const toRoom = `user_${to}`;
      socket.to(toRoom).emit('call-speaker-toggle', {
        callId: callIdParam,
        isSpeakerOn,
        from: socket.userId,
        to
      });
      // Broadcast to call room
      socket.to(callRoom).emit('call-speaker-toggle', {
        callId: callIdParam,
        isSpeakerOn,
        from: socket.userId,
        to
      });
    });
    
    // Hold/Resume
    socket.on('call-hold-toggle', ({ callId: callIdParam, isOnHold, to }) => {
      if (callIdParam !== callId) return;
      const toRoom = `user_${to}`;
      socket.to(toRoom).emit('call-hold-toggle', {
        callId: callIdParam,
        isOnHold,
        from: socket.userId,
        to
      });
      // Broadcast to call room
      socket.to(callRoom).emit('call-hold-toggle', {
        callId: callIdParam,
        isOnHold,
        from: socket.userId,
        to
      });
    });
    
    // Call quality update
    socket.on('call-quality-update', ({ callId: callIdParam, quality, to }) => {
      if (callIdParam !== callId) return;
      const toRoom = `user_${to}`;
      socket.to(toRoom).emit('call-quality-update', {
        callId: callIdParam,
        quality,
        from: socket.userId,
        to
      });
      // Broadcast to call room
      socket.to(callRoom).emit('call-quality-update', {
        callId: callIdParam,
        quality,
        from: socket.userId,
        to
      });
    });
  }
}

export default SocketHandler;
