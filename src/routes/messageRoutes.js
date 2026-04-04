// import express from 'express';
// import { authenticateToken } from '../middleware/auth.js';
// import {
//   getChats,
//   startChat,
//   getChatMessages,
//   deleteChat,
//   getCounselors,
//   getCounselorDetails,
//   updateStatus
// } from '../controllers/messageController.js';

// const router = express.Router();

// // ==================== CHAT MANAGEMENT ROUTES ====================

// /**
//  * @route   GET /api/chat/chats
//  * @desc    Get all chats for current user (user or counselor)
//  * @access  Private (requires authentication)
//  * @returns {Array} List of chats with last message and unread count
//  */
// router.get('/chats', authenticateToken, getChats);

// /**
//  * @route   POST /api/chat/chat/start
//  * @desc    Start a new chat with a counselor
//  * @access  Private (only users can start chats)
//  * @body    { counselorId: string }
//  * @returns {Object} Chat object with messages
//  */
// router.post('/start', authenticateToken, startChat);

// /**
//  * @route   GET /api/chat/chat/:chatId/messages
//  * @desc    Get all messages for a specific chat
//  * @access  Private (only participants of the chat)
//  * @param   {string} chatId - Chat ID
//  * @returns {Array} List of messages
//  */
// router.get('/chat/:chatId/messages', authenticateToken, getChatMessages);

// /**
//  * @route   DELETE /api/chat/chat/:chatId
//  * @desc    Soft delete a chat (mark as inactive)
//  * @access  Private (only participants of the chat)
//  * @param   {string} chatId - Chat ID
//  * @returns {Object} Success message
//  */
// router.delete('/chat/:chatId', authenticateToken, deleteChat);

// // ==================== COUNSELOR MANAGEMENT ROUTES ====================

// /**
//  * @route   GET /api/chat/counselors
//  * @desc    Get all available counselors (for users)
//  * @access  Private (only users can view counselors)
//  * @returns {Array} List of counselors
//  */
// router.get('/counselors', authenticateToken, getCounselors);

// /**
//  * @route   GET /api/chat/counselor/:counselorId
//  * @desc    Get detailed information about a specific counselor
//  * @access  Private (users can view counselor details)
//  * @param   {string} counselorId - Counselor ID
//  * @returns {Object} Counselor details
//  */
// router.get('/counselor/:counselorId', authenticateToken, getCounselorDetails);

// /**
//  * @route   PATCH /api/chat/status
//  * @desc    Update counselor's online status
//  * @access  Private (only counselors can update their status)
//  * @body    { online: boolean }
//  * @returns {Object} Success message with new status
//  */
// router.patch('/status', authenticateToken, updateStatus);

// // ==================== OPTIONAL: ADDITIONAL UTILITY ROUTES ====================

// /**
//  * @route   GET /api/chat/unread-count
//  * @desc    Get total unread messages count for current user
//  * @access  Private
//  * @returns {Object} { unreadCount: number }
//  */
// router.get('/unread-count', authenticateToken, async (req, res) => {
//   try {
//     let unreadCount = 0;
    
//     if (req.user.role === 'user') {
//       // Get all chats for user
//       const chats = await Chat.find({ userId: req.user._id, isActive: true });
      
//       // Count unread messages from counselors
//       for (const chat of chats) {
//         const count = await Message.countDocuments({
//           chatId: chat._id,
//           senderRole: 'counsellor',
//           isRead: false
//         });
//         unreadCount += count;
//       }
//     } else if (req.user.role === 'counsellor') {
//       // Get all chats for counselor
//       const chats = await Chat.find({ counselorId: req.user._id, isActive: true });
      
//       // Count unread messages from users
//       for (const chat of chats) {
//         const count = await Message.countDocuments({
//           chatId: chat._id,
//           senderRole: 'user',
//           isRead: false
//         });
//         unreadCount += count;
//       }
//     }
    
//     res.json({ success: true, unreadCount });
//   } catch (error) {
//     console.error('Error getting unread count:', error);
//     res.status(500).json({ error: 'Error getting unread count' });
//   }
// });

// /**
//  * @route   POST /api/chat/mark-all-read
//  * @desc    Mark all messages in a chat as read
//  * @access  Private
//  * @body    { chatId: string }
//  * @returns {Object} Success message
//  */
// router.post('/mark-all-read', authenticateToken, async (req, res) => {
//   try {
//     const { chatId } = req.body;
    
//     const chat = await Chat.findById(chatId);
//     if (!chat) {
//       return res.status(404).json({ error: 'Chat not found' });
//     }
    
//     // Check authorization
//     const isAuthorized = (req.user.role === 'user' && chat.userId.toString() === req.user._id.toString()) ||
//                         (req.user.role === 'counsellor' && chat.counselorId.toString() === req.user._id.toString());
    
//     if (!isAuthorized) {
//       return res.status(403).json({ error: 'Unauthorized' });
//     }
    
//     // Mark messages as read
//     const result = await Message.updateMany(
//       {
//         chatId: chat._id,
//         senderRole: req.user.role === 'user' ? 'counsellor' : 'user',
//         isRead: false
//       },
//       {
//         isRead: true,
//         readAt: new Date()
//       }
//     );
    
//     res.json({ 
//       success: true, 
//       message: 'All messages marked as read',
//       modifiedCount: result.modifiedCount
//     });
//   } catch (error) {
//     console.error('Error marking messages as read:', error);
//     res.status(500).json({ error: 'Error marking messages as read' });
//   }
// });

// /**
//  * @route   DELETE /api/chat/clear/:chatId
//  * @desc    Clear all messages in a chat (hard delete messages)
//  * @access  Private (only participants of the chat)
//  * @param   {string} chatId - Chat ID
//  * @returns {Object} Success message
//  */
// router.delete('/clear/:chatId', authenticateToken, async (req, res) => {
//   try {
//     const chat = await Chat.findById(req.params.chatId);
    
//     if (!chat) {
//       return res.status(404).json({ error: 'Chat not found' });
//     }
    
//     // Check authorization
//     const isAuthorized = (req.user.role === 'user' && chat.userId.toString() === req.user._id.toString()) ||
//                         (req.user.role === 'counsellor' && chat.counselorId.toString() === req.user._id.toString());
    
//     if (!isAuthorized) {
//       return res.status(403).json({ error: 'Unauthorized' });
//     }
    
//     // Delete all messages in the chat
//     const result = await Message.deleteMany({ chatId: chat._id });
    
//     // Update chat's last message
//     await Chat.findByIdAndUpdate(chat._id, {
//       lastMessage: null,
//       lastMessageAt: null,
//       updatedAt: new Date()
//     });
    
//     res.json({ 
//       success: true, 
//       message: 'Chat cleared successfully',
//       deletedCount: result.deletedCount
//     });
//   } catch (error) {
//     console.error('Error clearing chat:', error);
//     res.status(500).json({ error: 'Error clearing chat' });
//   }
// });

// /**
//  * @route   GET /api/chat/search/counselors
//  * @desc    Search counselors by name, specialization, or location
//  * @access  Private (users only)
//  * @query   { string } q - Search query
//  * @returns {Array} List of matching counselors
//  */
// router.get('/search/counselors', authenticateToken, async (req, res) => {
//   try {
//     if (req.user.role !== 'user') {
//       return res.status(403).json({ error: 'Only users can search counselors' });
//     }
    
//     const { q } = req.query;
//     if (!q) {
//       return res.status(400).json({ error: 'Search query is required' });
//     }
    
//     const searchRegex = new RegExp(q, 'i');
    
//     const counselors = await User.find(
//       {
//         role: 'counsellor',
//         isActive: true,
//         isVerified: true,
//         $or: [
//           { fullName: searchRegex },
//           { specialization: { $in: [searchRegex] } },
//           { location: searchRegex },
//           { aboutMe: searchRegex }
//         ]
//       },
//       {
//         password: 0,
//         emailOTP: 0,
//         phoneOTP: 0,
//         profilePhotoPublicId: 0
//       }
//     )
//     .select('fullName specialization experience qualification aboutMe profilePhoto rating totalSessions languages consultationMode location')
//     .sort({ rating: -1, fullName: 1 });
    
//     res.json({ counselors, count: counselors.length });
//   } catch (error) {
//     console.error('Error searching counselors:', error);
//     res.status(500).json({ error: 'Error searching counselors' });
//   }
// });

// /**
//  * @route   GET /api/chat/recent-chats
//  * @desc    Get recent chats with pagination
//  * @access  Private
//  * @query   { number } page - Page number (default: 1)
//  * @query   { number } limit - Items per page (default: 20)
//  * @returns {Object} Paginated chats
//  */
// router.get('/recent-chats', authenticateToken, async (req, res) => {
//   try {
//     const page = parseInt(req.query.page) || 1;
//     const limit = parseInt(req.query.limit) || 20;
//     const skip = (page - 1) * limit;
    
//     let chats;
//     let total;
    
//     if (req.user.role === 'user') {
//       total = await Chat.countDocuments({ userId: req.user._id, isActive: true });
//       chats = await Chat.find({ userId: req.user._id, isActive: true })
//         .populate('counselorId', 'fullName specialization profilePhoto rating isActive')
//         .sort({ updatedAt: -1 })
//         .skip(skip)
//         .limit(limit);
//     } else if (req.user.role === 'counsellor') {
//       total = await Chat.countDocuments({ counselorId: req.user._id, isActive: true });
//       chats = await Chat.find({ counselorId: req.user._id, isActive: true })
//         .populate('userId', 'fullName email profilePhoto isActive')
//         .sort({ updatedAt: -1 })
//         .skip(skip)
//         .limit(limit);
//     } else {
//       return res.status(403).json({ error: 'Invalid user role' });
//     }
    
//     // Add unread counts and last messages
//     const chatsWithDetails = await Promise.all(chats.map(async (chat) => {
//       const lastMessage = await Message.findOne({ chatId: chat._id })
//         .sort({ createdAt: -1 });
      
//       let unreadCount = 0;
//       if (req.user.role === 'user') {
//         unreadCount = await Message.countDocuments({
//           chatId: chat._id,
//           senderRole: 'counsellor',
//           isRead: false
//         });
//       } else {
//         unreadCount = await Message.countDocuments({
//           chatId: chat._id,
//           senderRole: 'user',
//           isRead: false
//         });
//       }
      
//       const otherParty = req.user.role === 'user' ? chat.counselorId : chat.userId;
      
//       return {
//         id: chat._id,
//         chatId: chat.chatId,
//         otherParty: {
//           id: otherParty._id,
//           name: otherParty.fullName,
//           avatar: otherParty.profilePhoto?.url || null,
//           ...(req.user.role === 'user' && { 
//             specialization: otherParty.specialization,
//             rating: otherParty.rating,
//             isActive: otherParty.isActive
//           })
//         },
//         lastMessage: lastMessage ? {
//           content: lastMessage.content,
//           createdAt: lastMessage.createdAt,
//           senderRole: lastMessage.senderRole
//         } : null,
//         unreadCount,
//         updatedAt: chat.updatedAt,
//         startedAt: chat.startedAt
//       };
//     }));
    
//     res.json({
//       chats: chatsWithDetails,
//       pagination: {
//         page,
//         limit,
//         total,
//         pages: Math.ceil(total / limit)
//       }
//     });
//   } catch (error) {
//     console.error('Error fetching recent chats:', error);
//     res.status(500).json({ error: 'Error fetching recent chats' });
//   }
// });

// /**
//  * @route   POST /api/chat/message/:messageId
//  * @desc    Delete a specific message (for the current user only)
//  * @access  Private
//  * @param   {string} messageId - Message ID
//  * @returns {Object} Success message
//  */
// router.delete('/message/:messageId', authenticateToken, async (req, res) => {
//   try {
//     const message = await Message.findById(req.params.messageId);
    
//     if (!message) {
//       return res.status(404).json({ error: 'Message not found' });
//     }
    
//     // Check if user is the sender
//     if (message.senderId.toString() !== req.user._id.toString()) {
//       return res.status(403).json({ error: 'You can only delete your own messages' });
//     }
    
//     // Soft delete or hard delete? Here we'll do hard delete
//     await message.deleteOne();
    
//     res.json({ success: true, message: 'Message deleted successfully' });
//   } catch (error) {
//     console.error('Error deleting message:', error);
//     res.status(500).json({ error: 'Error deleting message' });
//   }
// });

// export default router;
import express from 'express';
import { authenticateToken } from '../middleware/auth.js';
import {
  getChats,
  startChat,
  acceptChat,
  rejectChat,
  getPendingRequests,
  getChatMessages,
  sendMessage,
  deleteChat,
  clearChat,
  markAllRead,
  getUnreadCount,
  getCounselors,
  getCounselorDetails,
  updateStatus,
  searchCounselors
} from '../controllers/messageController.js';

const router = express.Router();

// ==================== CHAT REQUEST ROUTES ====================
router.post('/start', authenticateToken, startChat);
router.patch('/accept/:chatId', authenticateToken, acceptChat);
router.patch('/reject/:chatId', authenticateToken, rejectChat);
router.get('/pending-requests', authenticateToken, getPendingRequests);

// ==================== CHAT MANAGEMENT ROUTES ====================
router.get('/chats', authenticateToken, getChats);
router.get('/chat/:chatId/messages', authenticateToken, getChatMessages);
router.post('/chat/:chatId/message', authenticateToken, sendMessage);
router.delete('/chat/:chatId', authenticateToken, deleteChat);
router.delete('/clear/:chatId', authenticateToken, clearChat);
router.post('/mark-all-read', authenticateToken, markAllRead);
router.get('/unread-count', authenticateToken, getUnreadCount);

// ==================== COUNSELOR ROUTES ====================
router.get('/counselors', authenticateToken, getCounselors);
router.get('/counselor/:counselorId', authenticateToken, getCounselorDetails);
router.patch('/status', authenticateToken, updateStatus);
router.get('/search/counselors', authenticateToken, searchCounselors);

// Get all counsellors from database


export default router;