import mongoose from "mongoose";
import Chat from "../models/Chat.js";
import Message from "../models/Message.js";
import User from "../models/userModel.js";

// ==================== HELPER FUNCTION ====================

// Helper function to find chat by either _id or chatId
const findChatByIdentifier = async (identifier) => {
  // Check if it's a valid ObjectId
  if (mongoose.Types.ObjectId.isValid(identifier)) {
    const chat = await Chat.findById(identifier);
    if (chat) return chat;
  }

  // Try to find by chatId field
  return await Chat.findOne({ chatId: identifier });
};

export const startChat = async (req, res) => {
  try {
    const { counselorId } = req.body;

    if (req.user.role !== "user") {
      return res
        .status(403)
        .json({ error: "Only users can request chats with counselors" });
    }

    console.log("User ID:", req.user._id);
    console.log("Counselor ID:", counselorId);

    // Check if counselor exists
    const counselor = await User.findOne({
      _id: counselorId,
      role: "counsellor",
      isActive: true,
    });

    if (!counselor) {
      return res.status(404).json({ error: "Counselor not found" });
    }

    // Check for existing chat
    let existingChat = await Chat.findOne({
      userId: req.user._id,
      counselorId: counselorId,
    });

    // If chat exists, handle it
    if (existingChat) {
      // Check if chat is in a state that allows reactivation
      const canReactivate =
        existingChat.status === "cancelled" ||
        existingChat.status === "rejected" ||
        existingChat.status === "closed" ||
        (existingChat.status === "pending" &&
          existingChat.expiresAt &&
          new Date() > existingChat.expiresAt) ||
        !existingChat.isActive;

      // Check if there's an active pending request
      if (existingChat.status === "pending" && existingChat.isActive) {
        // Check if it's expired
        if (existingChat.expiresAt && new Date() > existingChat.expiresAt) {
          console.log("Request expired, reactivating");
          // Reactivate the expired chat
          existingChat.status = "pending";
          existingChat.isActive = true;
          existingChat.cancelledAt = null;
          existingChat.rejectedAt = null;

          // Set new expiration time (10 seconds from now)
          const expiresAt = new Date();
          expiresAt.setSeconds(expiresAt.getSeconds() + 10);
          existingChat.expiresAt = expiresAt;

          existingChat.updatedAt = new Date();
          await existingChat.save();

          // Add new request message
          await Message.create({
            chatId: existingChat._id,
            senderId: req.user._id,
            senderRole: "user",
            content: `🔄 Sending a new request. (Expires in 10 seconds)`,
            contentType: "TEXT",
          });

          const populatedChat = await Chat.findById(existingChat._id)
            .populate("userId", "fullName email profilePhoto anonymous") // Add anonymous here
            .populate(
              "counselorId",
              "fullName specialization profilePhoto rating isActive",
            );

          return res.json({
            success: true,
            message: "New request sent successfully",
            chat: {
              id: populatedChat._id,
              chatId: populatedChat.chatId,
              status: populatedChat.status,
              expiresAt: populatedChat.expiresAt,
              counselor: {
                id: populatedChat.counselorId._id,
                name: populatedChat.counselorId.fullName,
                specialization: populatedChat.counselorId.specialization,
                avatar: populatedChat.counselorId.profilePhoto?.url || null,
              },
              user: {
                id: populatedChat.userId._id,
                name: populatedChat.userId.fullName,
                anonymous: populatedChat.userId.anonymous, // Add anonymous here
                email: populatedChat.userId.email,
              },
              startedAt: populatedChat.startedAt,
            },
          });
        } else if (
          existingChat.expiresAt &&
          new Date() <= existingChat.expiresAt
        ) {
          // Active pending request exists
          const populatedChat = await Chat.findById(existingChat._id)
            .populate("userId", "fullName email profilePhoto anonymous")
            .populate(
              "counselorId",
              "fullName specialization profilePhoto rating isActive",
            );

          // Calculate remaining seconds
          const remainingSeconds = Math.max(
            0,
            Math.floor((existingChat.expiresAt - new Date()) / 1000),
          );

          return res.status(400).json({
            error: `Chat request already active. Please wait ${remainingSeconds} seconds before sending another request.`,
            status: existingChat.status,
            chatId: existingChat._id,
            expiresAt: existingChat.expiresAt,
            remainingSeconds: remainingSeconds,
          });
        }
      }

      // If chat is accepted or active, return error
      if (
        existingChat.status === "accepted" ||
        existingChat.status === "active"
      ) {
        const populatedChat = await Chat.findById(existingChat._id)
          .populate("userId", "fullName email profilePhoto anonymous")
          .populate(
            "counselorId",
            "fullName specialization profilePhoto rating isActive",
          );

        return res.status(400).json({
          error: "Chat already active. Please continue your conversation.",
          status: existingChat.status,
          chatId: existingChat._id,
        });
      }

      // For cancelled, rejected, closed, or inactive chats, reactivate
      if (canReactivate) {
        console.log("Reactivating chat from status:", existingChat.status);

        // Reset the chat for new request
        existingChat.status = "pending";
        existingChat.isActive = true;
        existingChat.rejectedAt = null;
        existingChat.closedAt = null;
        existingChat.cancelledAt = null;
        existingChat.acceptedAt = null;

        // Set expiration time (10 seconds from now)
        const expiresAt = new Date();
        expiresAt.setSeconds(expiresAt.getSeconds() + 10);
        existingChat.expiresAt = expiresAt;

        existingChat.updatedAt = new Date();
        await existingChat.save();

        // Add new request message
        await Message.create({
          chatId: existingChat._id,
          senderId: req.user._id,
          senderRole: "user",
          content: `👋 I'd like to start a conversation. (Request will expire in 10 seconds)`,
          contentType: "TEXT",
        });

        const populatedChat = await Chat.findById(existingChat._id)
          .populate("userId", "fullName email profilePhoto anonymous")
          .populate(
            "counselorId",
            "fullName specialization profilePhoto rating isActive",
          );

        return res.json({
          success: true,
          message: "Chat request sent successfully",
          chat: {
            id: populatedChat._id,
            chatId: populatedChat.chatId,
            status: populatedChat.status,
            expiresAt: populatedChat.expiresAt,
            counselor: {
              id: populatedChat.counselorId._id,
              name: populatedChat.counselorId.fullName,
              specialization: populatedChat.counselorId.specialization,
              avatar: populatedChat.counselorId.profilePhoto?.url || null,
            },
            user: {
              id: populatedChat.userId._id,
              name: populatedChat.userId.fullName,
              anonymous: populatedChat.userId.anonymous,
              email: populatedChat.userId.email,
            },
            startedAt: populatedChat.startedAt,
          },
        });
      }
    }

    // ONLY create new chat if NO existing chat exists
    console.log("No existing chat found, creating brand new chat");

    // Set expiration time (10 seconds from now)
    const expiresAt = new Date();
    expiresAt.setSeconds(expiresAt.getSeconds() + 10);

    const chat = await Chat.create({
      userId: req.user._id,
      counselorId: counselorId,
      status: "pending",
      expiresAt: expiresAt,
      startedAt: new Date(),
      updatedAt: new Date(),
    });

    // Add request message
    await Message.create({
      chatId: chat._id,
      senderId: req.user._id,
      senderRole: "user",
      content: `👋 Hello! I'd like to start a conversation with you. (Request will expire in 10 seconds)`,
      contentType: "TEXT",
    });

    const populatedChat = await Chat.findById(chat._id)
      .populate("userId", "fullName email profilePhoto anonymous")
      .populate(
        "counselorId",
        "fullName specialization profilePhoto rating isActive",
      );

    res.json({
      success: true,
      chat: {
        id: populatedChat._id,
        chatId: populatedChat.chatId,
        status: populatedChat.status,
        expiresAt: populatedChat.expiresAt,
        counselor: {
          id: populatedChat.counselorId._id,
          name: populatedChat.counselorId.fullName,
          specialization: populatedChat.counselorId.specialization,
          avatar: populatedChat.counselorId.profilePhoto?.url || null,
        },
        user: {
          id: populatedChat.userId._id,
          name: populatedChat.userId.fullName,
          anonymous: populatedChat.userId.anonymous,
          email: populatedChat.userId.email,
        },
        startedAt: populatedChat.startedAt,
      },
    });
  } catch (error) {
    console.error("Error starting chat:", error);

    // Handle duplicate key error by finding and reactivating the existing chat
    if (error.code === 11000) {
      console.log(
        "Duplicate key error, attempting to reactivate existing chat",
      );

      const existingChat = await Chat.findOne({
        userId: req.user._id,
        counselorId: req.body.counselorId,
      });

      if (existingChat) {
        // Reactivate the existing chat
        console.log("Found existing chat, reactivating...");

        existingChat.status = "pending";
        existingChat.isActive = true;
        existingChat.rejectedAt = null;
        existingChat.closedAt = null;
        existingChat.cancelledAt = null;
        existingChat.acceptedAt = null;

        const expiresAt = new Date();
        expiresAt.setSeconds(expiresAt.getSeconds() + 10);
        existingChat.expiresAt = expiresAt;

        existingChat.updatedAt = new Date();
        await existingChat.save();

        // Add new request message
        await Message.create({
          chatId: existingChat._id,
          senderId: req.user._id,
          senderRole: "user",
          content: `🔄 Sending a new request. (Expires in 10 seconds)`,
          contentType: "TEXT",
        });

        const populatedChat = await Chat.findById(existingChat._id)
          .populate("userId", "fullName email profilePhoto anonymous")
          .populate(
            "counselorId",
            "fullName specialization profilePhoto rating isActive",
          );

        return res.json({
          success: true,
          message: "Request sent successfully",
          chat: {
            id: populatedChat._id,
            chatId: populatedChat.chatId,
            status: populatedChat.status,
            expiresAt: populatedChat.expiresAt,
            counselor: {
              id: populatedChat.counselorId._id,
              name: populatedChat.counselorId.fullName,
              specialization: populatedChat.counselorId.specialization,
              avatar: populatedChat.counselorId.profilePhoto?.url || null,
            },
            user: {
              id: populatedChat.userId._id,
              name: populatedChat.userId.fullName,
              anonymous: populatedChat.userId.anonymous,
              email: populatedChat.userId.email,
            },
            startedAt: populatedChat.startedAt,
          },
        });
      }
    }

    res.status(500).json({ error: "Error starting chat" });
  }
};

// Accept chat request (counselor only)
// export const acceptChat = async (req, res) => {
//   try {
//     const { chatId } = req.params;

//     console.log('Accepting chat with identifier:', chatId);

//     // Use helper function to find chat by either _id or chatId
//     const chat = await findChatByIdentifier(chatId);

//     if (!chat) {
//       return res.status(404).json({ error: 'Chat not found' });
//     }

//     console.log('Found chat:', {
//       id: chat._id,
//       chatId: chat.chatId,
//       status: chat.status,
//       counselorId: chat.counselorId,
//       expiresAt: chat.expiresAt
//     });

//     // Check if counselor is authorized
//     if (req.user.role !== 'counsellor' || chat.counselorId.toString() !== req.user._id.toString()) {
//       return res.status(403).json({ error: 'Only the assigned counselor can accept this chat' });
//     }

//     // Check if request has expired
//     if (chat.status === 'pending' && chat.expiresAt && new Date() > chat.expiresAt) {
//       chat.status = 'cancelled';
//       chat.cancelledAt = new Date();
//       await chat.save();

//       return res.status(400).json({
//         error: 'Chat request has expired. User needs to send a new request.',
//         status: 'expired'
//       });
//     }

//     if (chat.status !== 'pending') {
//       return res.status(400).json({ error: `Chat is already ${chat.status}` });
//     }

//     // Accept the chat
//     chat.status = 'accepted';
//     chat.acceptedAt = new Date();
//     chat.expiresAt = null; // Clear expiration
//     chat.updatedAt = new Date();
//     await chat.save();

//     // Add acceptance message
//     await Message.create({
//       chatId: chat._id,
//       senderId: req.user._id,
//       senderRole: 'counsellor',
//       content: `✅ I've accepted your request. How can I help you today?`,
//       contentType: 'TEXT'
//     });

//     res.json({
//       success: true,
//       message: 'Chat request accepted',
//       chat: {
//         id: chat._id,
//         chatId: chat.chatId,
//         status: chat.status,
//         acceptedAt: chat.acceptedAt
//       }
//     });
//   } catch (error) {
//     console.error('Error accepting chat:', error);
//     res.status(500).json({ error: 'Error accepting chat' });
//   }
// };
// Accept chat request (counselor only)
export const acceptChat = async (req, res) => {
  try {
    const { chatId } = req.params;

    console.log("Accepting chat with identifier:", chatId);

    // Use helper function to find chat by either _id or chatId
    const chat = await findChatByIdentifier(chatId);

    if (!chat) {
      return res.status(404).json({ error: "Chat not found" });
    }

    console.log("Found chat:", {
      id: chat._id,
      chatId: chat.chatId,
      status: chat.status,
      counselorId: chat.counselorId,
      expiresAt: chat.expiresAt,
      isActive: chat.isActive,
    });

    // Check if counselor is authorized
    if (
      req.user.role !== "counsellor" ||
      chat.counselorId.toString() !== req.user._id.toString()
    ) {
      return res
        .status(403)
        .json({ error: "Only the assigned counselor can accept this chat" });
    }

    // Check if chat is cancelled (expired)
    if (chat.status === "cancelled") {
      return res.status(400).json({
        error:
          "This chat request has expired. The user needs to send a new request.",
        status: "expired",
        canResend: true,
        chatId: chat._id,
      });
    }

    // Check if request has expired
    if (
      chat.status === "pending" &&
      chat.expiresAt &&
      new Date() > chat.expiresAt
    ) {
      chat.status = "cancelled";
      chat.cancelledAt = new Date();
      chat.isActive = false;
      await chat.save();

      return res.status(400).json({
        error: "Chat request has expired. User needs to send a new request.",
        status: "expired",
        canResend: true,
        chatId: chat._id,
      });
    }

    // Check if chat is pending
    if (chat.status !== "pending") {
      return res.status(400).json({
        error: `Cannot accept chat. Current status: ${chat.status}`,
        status: chat.status,
      });
    }

    // Accept the chat
    chat.status = "accepted";
    chat.acceptedAt = new Date();
    chat.expiresAt = null; // Clear expiration
    chat.updatedAt = new Date();
    await chat.save();

    // Add acceptance message
    await Message.create({
      chatId: chat._id,
      senderId: req.user._id,
      senderRole: "counsellor",
      content: `✅ I've accepted your request. How can I help you today?`,
      contentType: "TEXT",
    });

    // Get populated chat details
    const populatedChat = await Chat.findById(chat._id)
      .populate("userId", "fullName email profilePhoto isActive")
      .populate(
        "counselorId",
        "fullName specialization profilePhoto rating isActive",
      );

    // Get messages
    const messages = await Message.find({ chatId: chat._id }).sort({
      createdAt: 1,
    });

    res.json({
      success: true,
      message: "Chat request accepted",
      chat: {
        id: populatedChat._id,
        chatId: populatedChat.chatId,
        status: populatedChat.status,
        acceptedAt: populatedChat.acceptedAt,
        user: {
          id: populatedChat.userId._id,
          name: populatedChat.userId.fullName,
          anonymous: populatedChat.userId.anonymous,
          email: populatedChat.userId.email,
          avatar: populatedChat.userId.profilePhoto?.url || null,
          isOnline: populatedChat.userId.isActive,
        },
        counselor: {
          id: populatedChat.counselorId._id,
          name: populatedChat.counselorId.fullName,
          specialization: populatedChat.counselorId.specialization,
          avatar: populatedChat.counselorId.profilePhoto?.url || null,
          rating: populatedChat.counselorId.rating,
          isOnline: populatedChat.counselorId.isActive,
        },
        messages: messages.map((msg) => ({
          id: msg._id,
          messageId: msg.messageId,
          content: msg.content,
          senderRole: msg.senderRole,
          contentType: msg.contentType,
          createdAt: msg.createdAt,
          isRead: msg.isRead,
        })),
        startedAt: populatedChat.startedAt,
      },
    });
  } catch (error) {
    console.error("Error accepting chat:", error);
    res.status(500).json({ error: "Error accepting chat" });
  }
};

// Auto-cancel expired chat requests (background job)
export const cancelExpiredRequests = async () => {
  try {
    const now = new Date();

    // Find all pending chats that have expired
    const expiredChats = await Chat.find({
      status: "pending",
      expiresAt: { $lt: now },
      isActive: true,
    });

    console.log(`Found ${expiredChats.length} expired chat requests to cancel`);

    // Update each expired chat
    for (const chat of expiredChats) {
      chat.status = "cancelled";
      chat.cancelledAt = now;
      chat.isActive = false; // Optionally deactivate
      await chat.save();

      // Add auto-cancel message
      await Message.create({
        chatId: chat._id,
        senderId: null,
        senderRole: "system",
        content: `⏰ Chat request automatically cancelled after 10 seconds. You can send a new request.`,
        contentType: "TEXT",
      });

      console.log(`Cancelled expired chat: ${chat._id}`);
    }

    return expiredChats.length;
  } catch (error) {
    console.error("Error cancelling expired requests:", error);
    return 0;
  }
};

// Reject chat request (counselor only)
export const rejectChat = async (req, res) => {
  try {
    const { chatId } = req.params;
    const { reason } = req.body;

    console.log("Rejecting chat with identifier:", chatId);

    // Use helper function to find chat by either _id or chatId
    const chat = await findChatByIdentifier(chatId);

    if (!chat) {
      return res.status(404).json({ error: "Chat not found" });
    }

    // Check if counselor is authorized
    if (
      req.user.role !== "counsellor" ||
      chat.counselorId.toString() !== req.user._id.toString()
    ) {
      return res
        .status(403)
        .json({ error: "Only the assigned counselor can reject this chat" });
    }

    if (chat.status !== "pending") {
      return res.status(400).json({ error: `Chat is already ${chat.status}` });
    }

    // Reject the chat
    chat.status = "rejected";
    chat.rejectedAt = new Date();
    chat.expiresAt = null; // Clear expiration
    chat.updatedAt = new Date();
    await chat.save();

    // Add rejection message
    await Message.create({
      chatId: chat._id,
      senderId: req.user._id,
      senderRole: "counsellor",
      content: `❌ I'm currently unavailable. ${reason ? `Reason: ${reason}` : "Please try again later."}`,
      contentType: "TEXT",
    });

    res.json({
      success: true,
      message: "Chat request rejected",
      chat: {
        id: chat._id,
        chatId: chat.chatId,
        status: chat.status,
        rejectedAt: chat.rejectedAt,
      },
    });
  } catch (error) {
    console.error("Error rejecting chat:", error);
    res.status(500).json({ error: "Error rejecting chat" });
  }
};

// Get pending chat requests (counselor only) - Filter out expired requests
// export const getPendingRequests = async (req, res) => {
//   try {
//     if (req.user.role !== 'counsellor') {
//       return res.status(403).json({ error: 'Only counselors can view pending requests' });
//     }

//     const counselorId = req.user._id;
//     console.log('Counselor ID:', counselorId);

//     // First, fix any legacy chats without status
//     await Chat.updateMany(
//       {
//         counselorId: counselorId,
//         status: { $exists: false },
//         isActive: true
//       },
//       { $set: { status: 'pending' } }
//     );

//     // Get pending chats that haven't expired
//     const pendingChats = await Chat.find({
//       counselorId: counselorId,
//       status: 'pending',
//       isActive: true,
//       $or: [
//         { expiresAt: { $gt: new Date() } }, // Not expired yet
//         { expiresAt: { $exists: false } }   // No expiration set (legacy)
//       ]
//     })
//     .populate('userId', 'fullName email profilePhoto')
//     .sort({ startedAt: -1 });

//     console.log('Pending chats found:', pendingChats.length);

//     const requests = await Promise.all(pendingChats.map(async (chat) => {
//       const requestMessage = await Message.findOne({
//         chatId: chat._id,
//         senderRole: 'user'
//       }).sort({ createdAt: 1 });

//       // Calculate remaining time
//       let remainingSeconds = null;
//       if (chat.expiresAt) {
//         remainingSeconds = Math.max(0, Math.floor((chat.expiresAt - new Date()) / 1000));
//       }

//       return {
//         id: chat._id,
//         chatId: chat.chatId,
//         user: {
//           id: chat.userId._id,
//           name: chat.userId.fullName,
//           anonymous: chat.userId.anonymous,

//           email: chat.userId.email,
//           Image: chat.userId.profilePhoto?.url || null
//         },
//         requestMessage: requestMessage?.content || 'No message',
//         requestedAt: chat.startedAt,
//         status: chat.status,
//         expiresAt: chat.expiresAt,
//         remainingSeconds: remainingSeconds
//       };
//     }));

//     res.json({ requests, count: requests.length });
//   } catch (error) {
//     console.error('Error fetching pending requests:', error);
//     res.status(500).json({ error: 'Error fetching pending requests' });
//   }
// };
// Get pending chat requests (counselor only) - Filter out expired requests
export const getPendingRequests = async (req, res) => {
  try {
    if (req.user.role !== "counsellor") {
      return res
        .status(403)
        .json({ error: "Only counselors can view pending requests" });
    }

    const counselorId = req.user._id;
    console.log("Counselor ID:", counselorId);

    // First, fix any legacy chats without status
    await Chat.updateMany(
      {
        counselorId: counselorId,
        status: { $exists: false },
        isActive: true,
      },
      { $set: { status: "pending" } },
    );

    // Get pending chats that haven't expired - ADD 'anonymous' to populate
    const pendingChats = await Chat.find({
      counselorId: counselorId,
      status: "pending",
      isActive: true,
      $or: [
        { expiresAt: { $gt: new Date() } }, // Not expired yet
        { expiresAt: { $exists: false } }, // No expiration set (legacy)
      ],
    })
      .populate("userId", "fullName email profilePhoto anonymous") // ADD anonymous here
      .sort({ startedAt: -1 });

    console.log("Pending chats found:", pendingChats.length);

    const requests = await Promise.all(
      pendingChats.map(async (chat) => {
        const requestMessage = await Message.findOne({
          chatId: chat._id,
          senderRole: "user",
        }).sort({ createdAt: 1 });

        // Calculate remaining time
        let remainingSeconds = null;
        if (chat.expiresAt) {
          remainingSeconds = Math.max(
            0,
            Math.floor((chat.expiresAt - new Date()) / 1000),
          );
        }

        // Handle anonymous the same way as in startChat
        // Since anonymous is stored as string in your database
        return {
          id: chat._id,
          chatId: chat.chatId,
          user: {
            id: chat.userId._id,
            name: chat.userId.fullName,
            anonymous: chat.userId.anonymous, // Pass the raw value (string "true"/"false")
            email: chat.userId.email,
            avatar: chat.userId.profilePhoto?.url || null,
          },
          requestMessage: requestMessage?.content || "No message",
          requestedAt: chat.startedAt,
          status: chat.status,
          expiresAt: chat.expiresAt,
          remainingSeconds: remainingSeconds,
        };
      }),
    );

    res.json({ requests, count: requests.length });
  } catch (error) {
    console.error("Error fetching pending requests:", error);
    res.status(500).json({ error: "Error fetching pending requests" });
  }
};

// Resend/Retry cancelled chat request (user only)
export const resendRequest = async (req, res) => {
  try {
    const { chatId } = req.params;

    if (req.user.role !== "user") {
      return res.status(403).json({ error: "Only users can resend requests" });
    }

    const chat = await Chat.findById(chatId);

    if (!chat) {
      return res.status(404).json({ error: "Chat not found" });
    }

    // Check authorization
    if (chat.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    // Only allow resend if chat is cancelled or expired
    if (chat.status !== "cancelled") {
      return res
        .status(400)
        .json({ error: `Cannot resend. Chat is ${chat.status}` });
    }

    // Reset the chat for new request
    chat.status = "pending";
    chat.isActive = true;
    chat.cancelledAt = null;

    // Set new expiration time (10 seconds from now)
    const expiresAt = new Date();
    expiresAt.setSeconds(expiresAt.getSeconds() + 10);
    chat.expiresAt = expiresAt;

    chat.updatedAt = new Date();
    await chat.save();

    // Add new request message
    await Message.create({
      chatId: chat._id,
      senderId: req.user._id,
      senderRole: "user",
      content: `🔄 I'm sending a new request. (Request will expire in 10 seconds)`,
      contentType: "TEXT",
    });

    const populatedChat = await Chat.findById(chat._id)
      .populate("userId", "fullName email profilePhoto")
      .populate(
        "counselorId",
        "fullName specialization profilePhoto rating isActive",
      );

    res.json({
      success: true,
      message: "Request resent successfully",
      chat: {
        id: populatedChat._id,
        chatId: populatedChat.chatId,
        status: populatedChat.status,
        expiresAt: populatedChat.expiresAt,
        counselor: {
          id: populatedChat.counselorId._id,
          name: populatedChat.counselorId.fullName,
          specialization: populatedChat.counselorId.specialization,
          avatar: populatedChat.counselorId.profilePhoto?.url || null,
        },
        user: {
          id: populatedChat.userId._id,
          name: populatedChat.userId.fullName,
          email: populatedChat.userId.email,
        },
        startedAt: populatedChat.startedAt,
      },
    });
  } catch (error) {
    console.error("Error resending request:", error);
    res.status(500).json({ error: "Error resending request" });
  }
};

// ==================== CHAT MANAGEMENT ====================

// Get all chats for current user
export const getChats = async (req, res) => {
  try {
    let chats;
    // let query = { isActive: true };
    let query = {
      isActive: true,
      status: { $in: ["accepted", "active"] },
    };

    if (req.user.role === "user") {
      query.userId = req.user._id;
    } else if (req.user.role === "counsellor") {
      query.counselorId = req.user._id;
    } else {
      return res.status(403).json({ error: "Invalid user role" });
    }

    chats = await Chat.find(query)
      .populate("userId", "fullName email profilePhoto anonymous isActive")
      .populate(
        "counselorId",
        "fullName specialization profilePhoto rating isActive",
      )
      .sort({ updatedAt: -1 });

    const chatsWithDetails = await Promise.all(
      chats.map(async (chat) => {
        const lastMessage = await Message.findOne({ chatId: chat._id }).sort({
          createdAt: -1,
        });

        let unreadCount = 0;
        if (req.user.role === "user") {
          unreadCount = await Message.countDocuments({
            chatId: chat._id,
            senderRole: "counsellor",
            isRead: false,
          });
        } else {
          unreadCount = await Message.countDocuments({
            chatId: chat._id,
            senderRole: "user",
            isRead: false,
          });
        }

        const otherParty =
          req.user.role === "user" ? chat.counselorId : chat.userId;

        // A referenced user/counsellor can be missing (deleted/deactivated record).
        // Skip orphaned chats instead of crashing on otherParty._id.
        if (!otherParty) {
          console.warn(
            `Skipping orphaned chat ${chat._id}: missing ${req.user.role === "user" ? "counselorId" : "userId"} reference`,
          );
          return null;
        }

        // Check if request is expired
        let isExpired = false;
        if (
          chat.status === "pending" &&
          chat.expiresAt &&
          new Date() > chat.expiresAt
        ) {
          isExpired = true;
        }

        return {
          id: chat._id,
          chatId: chat.chatId,
          status: chat.status,
          isExpired: isExpired,
          expiresAt: chat.expiresAt,
          otherParty: {
            id: otherParty._id,
            name: otherParty.fullName,
            anonymous: otherParty.anonymous,
            avatar: otherParty.profilePhoto?.url || null,
            ...(req.user.role === "user" && {
              specialization: otherParty.specialization,
              rating: otherParty.rating,
              isActive: otherParty.isActive,
            }),
          },
          lastMessage: lastMessage
            ? {
                content: lastMessage.content,
                createdAt: lastMessage.createdAt,
                senderRole: lastMessage.senderRole,
              }
            : null,
          unreadCount,
          updatedAt: chat.updatedAt,
          startedAt: chat.startedAt,
          acceptedAt: chat.acceptedAt,
          rejectedAt: chat.rejectedAt,
          cancelledAt: chat.cancelledAt,
        };
      }),
    );

    res.json({ chats: chatsWithDetails.filter(Boolean) });
  } catch (error) {
    console.error("Error fetching chats:", error);
    res.status(500).json({ error: "Error fetching chats" });
  }
};

// Get chat messages
export const getChatMessages = async (req, res) => {
  try {
    const { chatId } = req.params;

    // console.log('Getting messages for chat:', chatId);

    // Try to find chat by _id first, then by chatId
    let chat;

    if (mongoose.Types.ObjectId.isValid(chatId)) {
      chat = await Chat.findById(chatId);
    }

    if (!chat) {
      chat = await Chat.findOne({ chatId: chatId });
    }

    if (!chat) {
      return res.status(404).json({ error: "Chat not found" });
    }

    // Check authorization
    const isAuthorized =
      (req.user.role === "user" &&
        chat.userId.toString() === req.user._id.toString()) ||
      (req.user.role === "counsellor" &&
        chat.counselorId.toString() === req.user._id.toString());

    if (!isAuthorized) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    // Only allow viewing messages if chat is accepted or active
    if (chat.status !== "accepted" && chat.status !== "active") {
      return res.status(403).json({
        error: `Chat is ${chat.status}. Cannot view messages.`,
        status: chat.status,
      });
    }

    const messages = await Message.find({ chatId: chat._id }).sort({
      createdAt: 1,
    });

    // Mark messages as read
    if (chat.status === "accepted" || chat.status === "active") {
      if (req.user.role === "user") {
        await Message.updateMany(
          {
            chatId: chat._id,
            senderRole: "counsellor",
            isRead: false,
          },
          { isRead: true, readAt: new Date() },
        );
      } else {
        await Message.updateMany(
          {
            chatId: chat._id,
            senderRole: "user",
            isRead: false,
          },
          { isRead: true, readAt: new Date() },
        );
      }
    }

    res.json({
      chatStatus: chat.status,
      messages: messages.map((msg) => ({
        id: msg._id,
        messageId: msg.messageId,
        content: msg.content,
        senderRole: msg.senderRole,
        contentType: msg.contentType,
        attachmentUrl: msg.attachmentUrl,
        attachmentName: msg.attachmentName,
        attachmentMimeType: msg.attachmentMimeType,
        attachmentSize: msg.attachmentSize,
        createdAt: msg.createdAt,
        isRead: msg.isRead,
      })),
    });
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ error: "Error fetching messages" });
  }
};

// Send message (only if chat is accepted)
// export const sendMessage = async (req, res) => {
//   try {
//     const { chatId } = req.params;
//     const { content } = req.body;

//     if (!content || content.trim() === '') {
//       return res.status(400).json({ error: 'Message content is required' });
//     }

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

//     // Only allow messaging if chat is accepted
//     if (chat.status !== 'accepted' && chat.status !== 'active') {
//       return res.status(403).json({
//         error: `Cannot send messages. Chat is ${chat.status}.`,
//         status: chat.status
//       });
//     }

//     // Create message
//     const message = await Message.create({
//       chatId: chat._id,
//       senderId: req.user._id,
//       senderRole: req.user.role,
//       content: content.trim(),
//       contentType: 'TEXT'
//     });

//     // Update chat's last message
//     chat.lastMessage = content.trim();
//     chat.lastMessageAt = new Date();
//     chat.updatedAt = new Date();
//     await chat.save();

//     res.json({
//       success: true,
//       message: {
//         id: message._id,
//         messageId: message.messageId,
//         content: message.content,
//         senderRole: message.senderRole,
//         createdAt: message.createdAt
//       }
//     });
//   } catch (error) {
//     console.error('Error sending message:', error);
//     res.status(500).json({ error: 'Error sending message' });
//   }
// };
// Send message (only if chat is accepted)
export const sendMessage = async (req, res) => {
  try {
    const { chatId } = req.params;
    const { content } = req.body;
    const attachment = req.file;
    const trimmedContent = typeof content === "string" ? content.trim() : "";

    if (!attachment && !trimmedContent) {
      return res
        .status(400)
        .json({ error: "Message content or attachment is required" });
    }

    // Find chat by either _id OR chatId
    let chat;

    // Check if it's a valid ObjectId
    if (mongoose.Types.ObjectId.isValid(chatId)) {
      chat = await Chat.findById(chatId);
    }

    // If not found by _id, try to find by chatId field
    if (!chat) {
      chat = await Chat.findOne({ chatId: chatId });
    }

    if (!chat) {
      return res.status(404).json({ error: "Chat not found" });
    }

    // Check authorization
    const isAuthorized =
      (req.user.role === "user" &&
        chat.userId.toString() === req.user._id.toString()) ||
      (req.user.role === "counsellor" &&
        chat.counselorId.toString() === req.user._id.toString());

    if (!isAuthorized) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    // Only allow messaging if chat is accepted or active
    if (chat.status !== "accepted" && chat.status !== "active") {
      return res.status(403).json({
        error: `Cannot send messages. Chat is ${chat.status}.`,
        status: chat.status,
      });
    }

    const hasAttachment = Boolean(attachment);
    const isImageAttachment =
      hasAttachment && (attachment.mimetype || "").startsWith("image/");
    const messageContent = hasAttachment
      ? trimmedContent || attachment.originalname || "Attachment"
      : trimmedContent;

    const messagePayload = {
      chatId: chat._id,
      senderId: req.user._id,
      senderRole: req.user.role,
      content: messageContent,
      contentType: hasAttachment
        ? isImageAttachment
          ? "IMAGE"
          : "FILE"
        : "TEXT",
    };

    if (hasAttachment) {
      messagePayload.attachmentUrl =
        attachment.path || attachment.secure_url || null;
      messagePayload.attachmentName = attachment.originalname || null;
      messagePayload.attachmentMimeType = attachment.mimetype || null;
      messagePayload.attachmentSize = attachment.size || null;
    }

    // Create message using chat._id (ObjectId)
    const message = await Message.create(messagePayload);

    // Update chat's last message
    chat.lastMessage = hasAttachment
      ? `📎 ${messagePayload.attachmentName || "Attachment"}`
      : messageContent;
    chat.lastMessageAt = new Date();
    chat.updatedAt = new Date();
    await chat.save();

    // Populate the message with sender info
    const populatedMessage = await Message.findById(message._id).populate(
      "senderId",
      "fullName profilePhoto",
    );

    res.json({
      success: true,
      message: {
        id: populatedMessage._id,
        messageId: populatedMessage.messageId,
        content: populatedMessage.content,
        senderRole: populatedMessage.senderRole,
        senderName: populatedMessage.senderId?.fullName,
        contentType: populatedMessage.contentType,
        attachmentUrl: populatedMessage.attachmentUrl,
        attachmentName: populatedMessage.attachmentName,
        attachmentMimeType: populatedMessage.attachmentMimeType,
        attachmentSize: populatedMessage.attachmentSize,
        createdAt: populatedMessage.createdAt,
        isRead: populatedMessage.isRead,
      },
    });
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(500).json({ error: "Error sending message" });
  }
};

// Delete chat (soft delete)
export const deleteChat = async (req, res) => {
  try {
    const chat = await Chat.findById(req.params.chatId);

    if (!chat) {
      return res.status(404).json({ error: "Chat not found" });
    }

    // Check authorization
    const isAuthorized =
      (req.user.role === "user" &&
        chat.userId.toString() === req.user._id.toString()) ||
      (req.user.role === "counsellor" &&
        chat.counselorId.toString() === req.user._id.toString());

    if (!isAuthorized) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    // Soft delete
    chat.isActive = false;
    await chat.save();

    res.json({ message: "Chat deleted successfully" });
  } catch (error) {
    console.error("Error deleting chat:", error);
    res.status(500).json({ error: "Error deleting chat" });
  }
};

// Clear all messages in chat
export const clearChat = async (req, res) => {
  try {
    const chat = await Chat.findById(req.params.chatId);

    if (!chat) {
      return res.status(404).json({ error: "Chat not found" });
    }

    // Check authorization
    const isAuthorized =
      (req.user.role === "user" &&
        chat.userId.toString() === req.user._id.toString()) ||
      (req.user.role === "counsellor" &&
        chat.counselorId.toString() === req.user._id.toString());

    if (!isAuthorized) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    // Delete all messages
    const result = await Message.deleteMany({ chatId: chat._id });

    // Update chat
    chat.lastMessage = null;
    chat.lastMessageAt = null;
    chat.updatedAt = new Date();
    await chat.save();

    res.json({
      success: true,
      message: "Chat cleared successfully",
      deletedCount: result.deletedCount,
    });
  } catch (error) {
    console.error("Error clearing chat:", error);
    res.status(500).json({ error: "Error clearing chat" });
  }
};

// Mark all messages as read
// export const markAllRead = async (req, res) => {
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
//       { isRead: true, readAt: new Date() }
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
// };

// Get unread count
export const getUnreadCount = async (req, res) => {
  try {
    let unreadCount = 0;

    if (req.user.role === "user") {
      const chats = await Chat.find({ userId: req.user._id, isActive: true });
      for (const chat of chats) {
        const count = await Message.countDocuments({
          chatId: chat._id,
          senderRole: "counsellor",
          isRead: false,
        });
        unreadCount += count;
      }
    } else if (req.user.role === "counsellor") {
      const chats = await Chat.find({
        counselorId: req.user._id,
        isActive: true,
      });
      for (const chat of chats) {
        const count = await Message.countDocuments({
          chatId: chat._id,
          senderRole: "user",
          isRead: false,
        });
        unreadCount += count;
      }
    }

    res.json({ success: true, unreadCount });
  } catch (error) {
    console.error("Error getting unread count:", error);
    res.status(500).json({ error: "Error getting unread count" });
  }
};

// ==================== COUNSELOR MANAGEMENT ====================

// Get available counselors
export const getCounselors = async (req, res) => {
  try {
    if (req.user.role !== "user") {
      return res.status(403).json({ error: "Only users can view counselors" });
    }

    const counselors = await User.find(
      {
        role: "counsellor",
        isActive: true,
      },
      {
        password: 0,
        emailOTP: 0,
        phoneOTP: 0,
        profilePhotoPublicId: 0,
      },
    )
      .select(
        "fullName specialization experience qualification aboutMe profilePhoto rating totalSessions languages consultationMode location",
      )
      .sort({ rating: -1, fullName: 1 });

    res.json({ counselors });
  } catch (error) {
    console.error("Error fetching counselors:", error);
    res.status(500).json({ error: "Error fetching counselors" });
  }
};

// Get counselor details
export const getCounselorDetails = async (req, res) => {
  try {
    const counselor = await User.findOne(
      {
        _id: req.params.counselorId,
        role: "counsellor",
        isActive: true,
      },
      {
        password: 0,
        emailOTP: 0,
        phoneOTP: 0,
        profilePhotoPublicId: 0,
      },
    );

    if (!counselor) {
      return res.status(404).json({ error: "Counselor not found" });
    }

    res.json({ counselor });
  } catch (error) {
    console.error("Error fetching counselor:", error);
    res.status(500).json({ error: "Error fetching counselor" });
  }
};

// Update online status (counselor only)
export const updateStatus = async (req, res) => {
  try {
    if (req.user.role !== "counsellor") {
      return res
        .status(403)
        .json({ error: "Only counselors can update status" });
    }

    const { online } = req.body;

    // Update counselor status in database if you have an isOnline field
    // await User.findByIdAndUpdate(req.user._id, { isOnline: online });

    res.json({ message: "Status updated successfully", online });
  } catch (error) {
    console.error("Error updating status:", error);
    res.status(500).json({ error: "Error updating status" });
  }
};

// Search counselors
export const searchCounselors = async (req, res) => {
  try {
    if (req.user.role !== "user") {
      return res
        .status(403)
        .json({ error: "Only users can search counselors" });
    }

    const { q } = req.query;
    if (!q) {
      return res.status(400).json({ error: "Search query is required" });
    }

    const searchRegex = new RegExp(q, "i");

    const counselors = await User.find(
      {
        role: "counsellor",
        isActive: true,
        $or: [
          { fullName: searchRegex },
          { specialization: { $in: [searchRegex] } },
          { location: searchRegex },
          { aboutMe: searchRegex },
        ],
      },
      {
        password: 0,
        emailOTP: 0,
        phoneOTP: 0,
        profilePhotoPublicId: 0,
      },
    )
      .select(
        "fullName specialization experience qualification aboutMe profilePhoto rating totalSessions languages consultationMode location",
      )
      .sort({ rating: -1, fullName: 1 });

    res.json({ counselors, count: counselors.length });
  } catch (error) {
    console.error("Error searching counselors:", error);
    res.status(500).json({ error: "Error searching counselors" });
  }
};

export const markAllRead = async (req, res) => {
  try {
    const { chatId } = req.body;

    let chat = await findChatByIdentifier(chatId);

    // Fallback: if frontend sends otherParty._id as chatId
    if (!chat && mongoose.Types.ObjectId.isValid(chatId)) {
      chat = await Chat.findOne({
        $or: [
          { userId: chatId, counselorId: req.user._id },
          { userId: req.user._id, counselorId: chatId },
        ],
      });
    }

    if (!chat) {
      return res.status(404).json({ error: "Chat not found" });
    }

    // Check authorization
    const isAuthorized =
      (req.user.role === "user" &&
        chat.userId.toString() === req.user._id.toString()) ||
      (req.user.role === "counsellor" &&
        chat.counselorId.toString() === req.user._id.toString());

    if (!isAuthorized) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    // Mark messages as read
    const result = await Message.updateMany(
      {
        $or: [{ chatId: chat._id }, { chatId: chat.chatId }],
        senderRole: req.user.role === "user" ? "counsellor" : "user",
        isRead: false,
      },
      {
        $set: { isRead: true, readAt: new Date() },
      },
    );

    res.json({
      success: true,
      message: "All messages marked as read",
      modifiedCount: result.modifiedCount,
    });
  } catch (error) {
    console.error("Error marking messages as read:", error);
    res.status(500).json({ error: "Error marking messages as read" });
  }
};
