import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
import User from '../models/userModel.js';

// In-memory storage (replace with database in production)
const callHistory = [];
const activeCalls = new Map();
const userCallHistory = new Map(); // userId -> array of calls
const userStatus = new Map(); // Track online/busy status of users

export const videoCallController = {
  
  // Helper function to get user details from your database
  // async getUserDetails(userId, userType) {
  //   try {
  //     if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
  //       console.log(`Invalid user ID format: ${userId}`);
  //       return null;
  //     }
      
  //     const user = await User.findById(userId).select(
  //       'fullName email role profilePhoto specialization rating experience location qualification languages aboutMe isActive'
  //     );
      
  //     if (!user) {
  //       console.log(`User not found with ID: ${userId}`);
  //       return null;
  //     }
      
  //     if (!user.isActive) {
  //       console.log(`User is inactive: ${userId}`);
  //       return null;
  //     }
      
  //     return {
  //       id: user._id,
  //       name: user.fullName,
  //       anonymous:user?.anonymous,
  //       email: user.email,
  //       type: user.role,
  //       profilePhoto: user.profilePhoto?.url || null,
  //       specialization: user.specialization || [],
  //       rating: user.rating || 0,
  //       experience: user.experience || 0,
  //       qualification: user.qualification || '',
  //       location: user.location || '',
  //       languages: user.languages || [],
  //       aboutMe: user.aboutMe || '',
  //       isActive: user.isActive
  //     };
      
  //   } catch (error) {
  //     console.error('Error in getUserDetails:', error);
  //     return null;
  //   }
  // },
  // Helper function to get user details - FIXED
async getUserDetails(userId, userType) {
  try {
    if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
      console.log(`Invalid user ID format: ${userId}`);
      return null;
    }
    
    const user = await User.findById(userId).select(
      'fullName email role profilePhoto specialization rating experience location qualification languages aboutMe isActive anonymous'
    );
    
    if (!user) {
      console.log(`User not found with ID: ${userId}`);
      return null;
    }
    
    if (!user.isActive) {
      console.log(`User is inactive: ${userId}`);
      return null;
    }
    
    return {
      id: user._id,
      name: user.fullName,
      anonymous: user.anonymous || false, // Ensure it's a boolean
      email: user.email,
      type: user.role,
      profilePhoto: user.profilePhoto?.url || null,
      specialization: user.specialization || [],
      rating: user.rating || 0,
      experience: user.experience || 0,
      qualification: user.qualification || '',
      location: user.location || '',
      languages: user.languages || [],
      aboutMe: user.aboutMe || '',
      isActive: user.isActive
    };
    
  } catch (error) {
    console.error('Error in getUserDetails:', error);
    return null;
  }
},

// Helper function to get display name based on anonymous status and viewer role
getDisplayName(user, viewerRole, callerRole = null) {
  // If user is not anonymous, return real name
  if (!user.anonymous) {
    return user.name;
  }
  
  // If user is anonymous
  // For counsellor viewing patient - show as "Anonymous Patient"
  if (viewerRole === 'counsellor' && user.type === 'patient') {
    return 'Anonymous Patient';
  }
  
  // For patient viewing counsellor - show counsellor's real name (privacy concern?)
  // Better to show as "Counsellor" for patients
  if (viewerRole === 'patient' && user.type === 'counsellor') {
    return 'Counsellor'; // Or 'Mental Health Professional'
  }
  
  // Default anonymous display
  return 'Anonymous User';
},

// 1. Initiate a video call request - FIXED
initiateCall: async (req, res) => {
  try {
    const { 
      initiatorId, 
      initiatorType,
      receiverId, 
      receiverType,
      callType = 'video',
      message = "I'd like to start a video call with you."
    } = req.body;
    
    if (!initiatorId || !initiatorType || !receiverId || !receiverType) {
      return res.status(400).json({ 
        success: false, 
        error: 'initiatorId, initiatorType, receiverId, and receiverType are required' 
      });
    }
    
    // Validate ObjectIds
    if (!mongoose.Types.ObjectId.isValid(initiatorId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid initiatorId format'
      });
    }
    
    if (!mongoose.Types.ObjectId.isValid(receiverId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid receiverId format'
      });
    }
    
    // Get user details
    const initiatorDetails = await videoCallController.getUserDetails(initiatorId, initiatorType);
    const receiverDetails = await videoCallController.getUserDetails(receiverId, receiverType);
    
    if (!initiatorDetails) {
      return res.status(404).json({ 
        success: false, 
        error: `Initiator not found` 
      });
    }
    
    if (!receiverDetails) {
      return res.status(404).json({ 
        success: false, 
        error: `Receiver not found` 
      });
    }
    
    // Check for existing active call request
    let existingCall = null;
    for (const [callId, call] of activeCalls.entries()) {
      if (((call.initiator.id === initiatorId && call.receiver.id === receiverId) ||
           (call.initiator.id === receiverId && call.receiver.id === initiatorId)) &&
          call.status === 'pending' && call.isActive) {
        existingCall = call;
        break;
      }
    }
    
    const callId = uuidv4();
    const roomId = uuidv4();
    
    // Set expiration time (10 seconds from now)
    const expiresAt = new Date();
    expiresAt.setSeconds(expiresAt.getSeconds() + 10);
    
    // If existing pending call exists, check if expired
    if (existingCall) {
      if (existingCall.expiresAt && new Date() > existingCall.expiresAt) {
        console.log('Call request expired, reactivating');
        
        existingCall.status = 'pending';
        existingCall.isActive = true;
        existingCall.expiresAt = expiresAt;
        existingCall.initiator = {
          id: initiatorId,
          name: initiatorDetails.name,
          anonymous: initiatorDetails.anonymous,
          type: initiatorType,
          profilePhoto: initiatorDetails.profilePhoto
        };
        existingCall.receiver = {
          id: receiverId,
          name: receiverDetails.name,
          anonymous: receiverDetails.anonymous,
          type: receiverType,
          profilePhoto: receiverDetails.profilePhoto
        };
        existingCall.requestMessage = message;
        existingCall.updatedAt = new Date();
        
        activeCalls.set(existingCall.callId, existingCall);
        
        // Emit real-time notification - FIXED: Show appropriate display names
        if (global.io) {
          const initiatorDisplayName = videoCallController.getDisplayName(
            { name: initiatorDetails.name, anonymous: initiatorDetails.anonymous },
            receiverType, // The receiver's role determines what they see
            initiatorType
          );
          
          global.io.to(`user_${receiverId}`).emit('incoming_call_request', {
            callId: existingCall.callId,
            roomId: existingCall.roomId,
            from: initiatorDisplayName, // Use display name instead of real name
            fromId: initiatorId,
            fromType: initiatorType,
            fromProfilePhoto: initiatorDetails.profilePhoto,
            callType,
            message,
            expiresAt,
            remainingSeconds: 10,
            timestamp: new Date()
          });
        }
        
        return res.status(201).json({
          success: true,
          message: 'New call request sent',
          callId: existingCall.callId,
          roomId: existingCall.roomId,
          status: 'pending',
          expiresAt,
          callData: {
            id: existingCall.callId,
            roomId: existingCall.roomId,
            initiator: { 
              id: initiatorId, 
              name: videoCallController.getDisplayName(
                { name: initiatorDetails.name, anonymous: initiatorDetails.anonymous },
                receiverType,
                initiatorType
              ),
              anonymous: initiatorDetails.anonymous,
              type: initiatorType,
              profilePhoto: initiatorDetails.profilePhoto
            },
            receiver: { 
              id: receiverId, 
              name: videoCallController.getDisplayName(
                { name: receiverDetails.name, anonymous: receiverDetails.anonymous },
                initiatorType,
                receiverType
              ),
              type: receiverType,
              profilePhoto: receiverDetails.profilePhoto
            },
            status: 'pending',
            expiresAt,
            createdAt: new Date()
          }
        });
      } else {
        // Active pending request exists
        const remainingSeconds = Math.max(0, Math.floor((existingCall.expiresAt - new Date()) / 1000));
        
        return res.status(400).json({ 
          success: false,
          error: `Call request already active. Please wait ${remainingSeconds} seconds before sending another request.`,
          status: existingCall.status,
          callId: existingCall.callId,
          expiresAt: existingCall.expiresAt,
          remainingSeconds
        });
      }
    }
    
    // Create new call request (pending)
    const callData = {
      callId,
      roomId,
      type: callType,
      status: 'pending', // Like chat: pending, accepted, rejected, cancelled, active, ended
      initiatedBy: initiatorType,
      initiator: {
        id: initiatorId,
        name: initiatorDetails.name,
        anonymous: initiatorDetails.anonymous,
        type: initiatorType,
        profilePhoto: initiatorDetails.profilePhoto,
        email: initiatorDetails.email,
        specialization: initiatorDetails.specialization,
        rating: initiatorDetails.rating
      },
      receiver: {
        id: receiverId,
        name: receiverDetails.name,
        anonymous: receiverDetails.anonymous,
        type: receiverType,
        profilePhoto: receiverDetails.profilePhoto,
        email: receiverDetails.email,
        specialization: receiverDetails.specialization,
        rating: receiverDetails.rating
      },
      requestMessage: message,
      createdAt: new Date(),
      expiresAt: expiresAt,
      startTime: null,
      endTime: null,
      duration: 0,
      participants: new Map(),
      endedBy: null,
      isActive: true
    };
    
    // Add initiator to participants
    callData.participants.set(initiatorId, {
      userId: initiatorId,
      userName: initiatorDetails.name,
      anonymous: initiatorDetails.anonymous,
      role: 'initiator',
      type: initiatorType,
      joinedAt: new Date(),
      isVideoEnabled: true,
      isAudioEnabled: true,
      isScreenSharing: false,
      profilePhoto: initiatorDetails.profilePhoto
    });
    
    activeCalls.set(callId, callData);
    
    // Emit real-time notification to receiver - FIXED
    if (global.io) {
      const initiatorDisplayName = videoCallController.getDisplayName(
        { name: initiatorDetails.name, anonymous: initiatorDetails.anonymous },
        receiverType,
        initiatorType
      );
      
      global.io.to(`user_${receiverId}`).emit('incoming_call_request', {
        callId,
        roomId,
        from: initiatorDisplayName, // Use display name
        fromId: initiatorId,
        fromType: initiatorType,
        fromProfilePhoto: initiatorDetails.profilePhoto,
        callType,
        message,
        expiresAt,
        remainingSeconds: 10,
        timestamp: new Date()
      });
    }
    
    res.status(201).json({
      success: true,
      message: 'Call request sent successfully',
      callId,
      roomId,
      status: 'pending',
      expiresAt,
      callData: {
        id: callId,
        roomId,
        initiator: { 
          id: initiatorId, 
          name: videoCallController.getDisplayName(
            { name: initiatorDetails.name, anonymous: initiatorDetails.anonymous },
            receiverType,
            initiatorType
          ),
          anonymous: initiatorDetails.anonymous, 
          type: initiatorType,
          profilePhoto: initiatorDetails.profilePhoto
        },
        receiver: { 
          id: receiverId, 
          name: videoCallController.getDisplayName(
            { name: receiverDetails.name, anonymous: receiverDetails.anonymous },
            initiatorType,
            receiverType
          ),
          anonymous: receiverDetails.anonymous,
          type: receiverType,
          profilePhoto: receiverDetails.profilePhoto
        },
        status: 'pending',
        expiresAt,
        createdAt: new Date()
      }
    });
    
  } catch (error) {
    console.error('Error initiating call:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to initiate call',
      details: error.message 
    });
  }
},

// 2. Get pending call requests - FIXED
getPendingRequests: async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Get the user's role to determine display names
    const currentUser = await User.findById(userId).select('role');
    if (!currentUser) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    const pendingRequests = [];
    
    for (const [callId, call] of activeCalls.entries()) {
      if (call.receiver.id === userId && 
          call.status === 'pending' && 
          call.isActive &&
          call.expiresAt && 
          new Date() < call.expiresAt) {
        
        const remainingSeconds = Math.max(0, Math.floor((call.expiresAt - new Date()) / 1000));
        
        // Get display name for the caller based on current user's role
        const callerDisplayName = videoCallController.getDisplayName(
          { name: call.initiator.name, anonymous: call.initiator.anonymous },
          currentUser.role,
          call.initiator.type
        );
        
        pendingRequests.push({
          callId: call.callId,
          roomId: call.roomId,
          from: {
            id: call.initiator.id,
            name: callerDisplayName, // Use display name instead of real name
            anonymous: call.initiator.anonymous,
            type: call.initiator.type,
            profilePhoto: call.initiator.profilePhoto,
            specialization: call.initiator.specialization,
            rating: call.initiator.rating
          },
          callType: call.type,
          requestMessage: call.requestMessage,
          requestedAt: call.createdAt,
          expiresAt: call.expiresAt,
          remainingSeconds
        });
      }
    }
    
    res.json({
      success: true,
      pendingRequests,
      count: pendingRequests.length
    });
    
  } catch (error) {
    console.error('Error getting pending requests:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to get pending requests',
      details: error.message 
    });
  }
},

// 3. Accept call request - FIXED
acceptCall: async (req, res) => {
  try {
    const { callId } = req.params;
    const { acceptorId, acceptorType } = req.body;
    
    if (!mongoose.Types.ObjectId.isValid(acceptorId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid acceptorId format'
      });
    }
    
    const call = activeCalls.get(callId);
    
    if (!call) {
      return res.status(404).json({ 
        success: false, 
        error: 'Call request not found' 
      });
    }
    
    // Verify the acceptor is the intended receiver
    if (call.receiver.id !== acceptorId) {
      return res.status(403).json({ 
        success: false, 
        error: 'You are not the intended recipient of this call' 
      });
    }
    
    // Check if request has expired
    if (call.status === 'pending' && call.expiresAt && new Date() > call.expiresAt) {
      call.status = 'cancelled';
      call.isActive = false;
      call.cancelledAt = new Date();
      activeCalls.set(callId, call);
      
      return res.status(400).json({ 
        success: false,
        error: 'Call request has expired. User needs to send a new request.',
        status: 'expired',
        canResend: true,
        callId: call._id
      });
    }
    
    if (call.status !== 'pending') {
      return res.status(400).json({ 
        success: false,
        error: `Cannot accept call. Current status: ${call.status}`,
        status: call.status
      });
    }
    
    // Get acceptor details
    const acceptorDetails = await videoCallController.getUserDetails(acceptorId, acceptorType);
    
    if (!acceptorDetails) {
      return res.status(404).json({
        success: false,
        error: 'Acceptor not found'
      });
    }
    
    // Update call status to accepted/active
    call.status = 'active';
    call.acceptedAt = new Date();
    call.expiresAt = null;
    call.receiver.name = acceptorDetails.name;
    call.receiver.anonymous = acceptorDetails.anonymous;
    call.receiver.profilePhoto = acceptorDetails.profilePhoto;
    call.receiver.specialization = acceptorDetails.specialization;
    call.receiver.rating = acceptorDetails.rating;
    
    // Add receiver to participants
    call.participants.set(acceptorId, {
      userId: acceptorId,
      userName: acceptorDetails.name,
      anonymous: acceptorDetails.anonymous,
      role: 'receiver',
      type: acceptorType,
      joinedAt: new Date(),
      isVideoEnabled: true,
      isAudioEnabled: true,
      isScreenSharing: false,
      profilePhoto: acceptorDetails.profilePhoto
    });
    
    // Update user status
    userStatus.set(call.initiator.id, { status: 'busy', currentCall: callId });
    userStatus.set(call.receiver.id, { status: 'busy', currentCall: callId });
    
    activeCalls.set(callId, call);
    
    // Get initiator's role for display name calculation
    const initiatorUser = await User.findById(call.initiator.id).select('role');
    const acceptorUser = await User.findById(acceptorId).select('role');
    
    // Notify initiator that call was accepted - FIXED: Show appropriate display name
    if (global.io) {
      const acceptorDisplayName = videoCallController.getDisplayName(
        { name: acceptorDetails.name, anonymous: acceptorDetails.anonymous },
        initiatorUser?.role || 'user',
        acceptorType
      );
      
      global.io.to(`user_${call.initiator.id}`).emit('call_accepted', {
        callId,
        roomId: call.roomId,
        by: acceptorDisplayName,
        byProfilePhoto: acceptorDetails.profilePhoto,
        timestamp: new Date()
      });
    }
    
    // Prepare response with appropriate display names
    const initiatorDisplayName = videoCallController.getDisplayName(
      { name: call.initiator.name, anonymous: call.initiator.anonymous },
      acceptorType,
      call.initiator.type
    );
    
    const receiverDisplayName = videoCallController.getDisplayName(
      { name: acceptorDetails.name, anonymous: acceptorDetails.anonymous },
      call.initiator.type,
      acceptorType
    );
    
    res.json({
      success: true,
      message: 'Call request accepted',
      callId,
      roomId: call.roomId,
      status: 'active',
      acceptedAt: call.acceptedAt,
      participants: Array.from(call.participants.values()).map(p => ({
        ...p,
        userName: p.userId === call.initiator.id 
          ? initiatorDisplayName 
          : (p.userId === acceptorId ? receiverDisplayName : p.userName)
      }))
    });
    
  } catch (error) {
    console.error('Error accepting call:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to accept call',
      details: error.message 
    });
  }
},

  // ==================== VIDEO CALL REQUEST MANAGEMENT ====================
  
  // // 1. Initiate a video call request (works like startChat)
  // initiateCall: async (req, res) => {
  //   try {
  //     const { 
  //       initiatorId, 
  //       initiatorType,
  //       receiverId, 
  //       receiverType,
  //       callType = 'video',
  //       message = "I'd like to start a video call with you."
  //     } = req.body;
      
  //     if (!initiatorId || !initiatorType || !receiverId || !receiverType) {
  //       return res.status(400).json({ 
  //         success: false, 
  //         error: 'initiatorId, initiatorType, receiverId, and receiverType are required' 
  //       });
  //     }
      
  //     // Validate ObjectIds
  //     if (!mongoose.Types.ObjectId.isValid(initiatorId)) {
  //       return res.status(400).json({
  //         success: false,
  //         error: 'Invalid initiatorId format'
  //       });
  //     }
      
  //     if (!mongoose.Types.ObjectId.isValid(receiverId)) {
  //       return res.status(400).json({
  //         success: false,
  //         error: 'Invalid receiverId format'
  //       });
  //     }
      
  //     // Get user details
  //     const initiatorDetails = await videoCallController.getUserDetails(initiatorId, initiatorType);
  //     const receiverDetails = await videoCallController.getUserDetails(receiverId, receiverType);
      
  //     if (!initiatorDetails) {
  //       return res.status(404).json({ 
  //         success: false, 
  //         error: `Initiator not found` 
  //       });
  //     }
      
  //     if (!receiverDetails) {
  //       return res.status(404).json({ 
  //         success: false, 
  //         error: `Receiver not found` 
  //       });
  //     }
      
  //     // Check for existing active call request
  //     let existingCall = null;
  //     for (const [callId, call] of activeCalls.entries()) {
  //       if (((call.initiator.id === initiatorId && call.receiver.id === receiverId) ||
  //            (call.initiator.id === receiverId && call.receiver.id === initiatorId)) &&
  //           call.status === 'pending' && call.isActive) {
  //         existingCall = call;
  //         break;
  //       }
  //     }
      
  //     const callId = uuidv4();
  //     const roomId = uuidv4();
      
  //     // Set expiration time (10 seconds from now)
  //     const expiresAt = new Date();
  //     expiresAt.setSeconds(expiresAt.getSeconds() + 10);
      
  //     // If existing pending call exists, check if expired
  //     if (existingCall) {
  //       if (existingCall.expiresAt && new Date() > existingCall.expiresAt) {
  //         // Expired, reactivate it
  //         console.log('Call request expired, reactivating');
          
  //         existingCall.status = 'pending';
  //         existingCall.isActive = true;
  //         existingCall.expiresAt = expiresAt;
  //         existingCall.initiator = {
  //           id: initiatorId,
  //           name: initiatorDetails.name,
  //           anonymous:initiatorDetails?.anonymous,
  //           type: initiatorType,
  //           profilePhoto: initiatorDetails.profilePhoto
  //         };
  //         existingCall.receiver = {
  //           id: receiverId,
  //           name: receiverDetails.name,
  //           anonymous:receiverDetails?.anonymous,
  //           type: receiverType,
  //           profilePhoto: receiverDetails.profilePhoto
  //         };
  //         existingCall.requestMessage = message;
  //         existingCall.updatedAt = new Date();
          
  //         activeCalls.set(existingCall.callId, existingCall);
          
  //         // Emit real-time notification
  //         if (global.io) {
  //           global.io.to(`user_${receiverId}`).emit('incoming_call_request', {
  //             callId: existingCall.callId,
  //             roomId: existingCall.roomId,
  //             from: initiatorDetails.name,
  //             from:initiatorDetails?.anonymous,
  //             fromId: initiatorId,
  //             fromType: initiatorType,
  //             fromProfilePhoto: initiatorDetails.profilePhoto,
  //             callType,
  //             message,
  //             expiresAt,
  //             remainingSeconds: 10,
  //             timestamp: new Date()
  //           });
  //         }
          
  //         return res.status(201).json({
  //           success: true,
  //           message: 'New call request sent',
  //           callId: existingCall.callId,
  //           roomId: existingCall.roomId,
  //           status: 'pending',
  //           expiresAt,
  //           callData: {
  //             id: existingCall.callId,
  //             roomId: existingCall.roomId,
  //             initiator: { 
  //               id: initiatorId, 
  //               name: initiatorDetails.name, 
  //               anonymous:initiatorDetails?.anonymous,
  //               type: initiatorType,
  //               profilePhoto: initiatorDetails.profilePhoto
  //             },
  //             receiver: { 
  //               id: receiverId, 
  //               name: receiverDetails.name, 
  //               type: receiverType,
  //               profilePhoto: receiverDetails.profilePhoto
  //             },
  //             status: 'pending',
  //             expiresAt,
  //             createdAt: new Date()
  //           }
  //         });
  //       } else {
  //         // Active pending request exists
  //         const remainingSeconds = Math.max(0, Math.floor((existingCall.expiresAt - new Date()) / 1000));
          
  //         return res.status(400).json({ 
  //           success: false,
  //           error: `Call request already active. Please wait ${remainingSeconds} seconds before sending another request.`,
  //           status: existingCall.status,
  //           callId: existingCall.callId,
  //           expiresAt: existingCall.expiresAt,
  //           remainingSeconds
  //         });
  //       }
  //     }
      
  //     // Create new call request (pending)
  //     const callData = {
  //       callId,
  //       roomId,
  //       type: callType,
  //       status: 'pending', // Like chat: pending, accepted, rejected, cancelled, active, ended
  //       initiatedBy: initiatorType,
  //       initiator: {
  //         id: initiatorId,
  //         name: initiatorDetails.name,
  //         anonymous:initiatorDetails?.anonymous,
  //         type: initiatorType,
  //         profilePhoto: initiatorDetails.profilePhoto,
  //         email: initiatorDetails.email,
  //         specialization: initiatorDetails.specialization,
  //         rating: initiatorDetails.rating
  //       },
  //       receiver: {
  //         id: receiverId,
  //         name: receiverDetails.name,
  //         anonymous:receiverDetails?.anonymous,
  //         type: receiverType,
  //         profilePhoto: receiverDetails.profilePhoto,
  //         email: receiverDetails.email,
  //         specialization: receiverDetails.specialization,
  //         rating: receiverDetails.rating
  //       },
  //       requestMessage: message,
  //       createdAt: new Date(),
  //       expiresAt: expiresAt,
  //       startTime: null,
  //       endTime: null,
  //       duration: 0,
  //       participants: new Map(),
  //       endedBy: null,
  //       isActive: true
  //     };
      
  //     // Add initiator to participants
  //     callData.participants.set(initiatorId, {
  //       userId: initiatorId,
  //       userName: initiatorDetails.name,
  //       anonymous:initiatorDetails?.anonymous,
  //       role: 'initiator',
  //       type: initiatorType,
  //       joinedAt: new Date(),
  //       isVideoEnabled: true,
  //       isAudioEnabled: true,
  //       isScreenSharing: false,
  //       profilePhoto: initiatorDetails.profilePhoto
  //     });
      
  //     activeCalls.set(callId, callData);
      
  //     // Emit real-time notification to receiver
  //     if (global.io) {
  //       global.io.to(`user_${receiverId}`).emit('incoming_call_request', {
  //         callId,
  //         roomId,
  //         from: initiatorDetails.name,
  //         from:initiatorDetails.anonymous,
  //         fromId: initiatorId,
  //         fromType: initiatorType,
  //         fromProfilePhoto: initiatorDetails.profilePhoto,
  //         callType,
  //         message,
  //         expiresAt,
  //         remainingSeconds: 10,
  //         timestamp: new Date()
  //       });
  //     }
      
  //     res.status(201).json({
  //       success: true,
  //       message: 'Call request sent successfully',
  //       callId,
  //       roomId,
  //       status: 'pending',
  //       expiresAt,
  //       callData: {
  //         id: callId,
  //         roomId,
  //         initiator: { 
  //           id: initiatorId, 
  //           name: initiatorDetails.name,
  //           anonymous:initiatorDetails?.anonymous, 
  //           type: initiatorType,
  //           profilePhoto: initiatorDetails.profilePhoto
  //         },
  //         receiver: { 
  //           id: receiverId, 
  //           name: receiverDetails.name, 
  //           anonymous:receiverDetails?.anonymous,
  //           type: receiverType,
  //           profilePhoto: receiverDetails.profilePhoto
  //         },
  //         status: 'pending',
  //         expiresAt,
  //         createdAt: new Date()
  //       }
  //     });
      
  //   } catch (error) {
  //     console.error('Error initiating call:', error);
  //     res.status(500).json({ 
  //       success: false, 
  //       error: 'Failed to initiate call',
  //       details: error.message 
  //     });
  //   }
  // },
  
  // // 2. Get pending call requests (like getPendingRequests for chat)
  // getPendingRequests: async (req, res) => {
  //   try {
  //     const { userId } = req.params;
      
  //     const pendingRequests = [];
      
  //     for (const [callId, call] of activeCalls.entries()) {
  //       if (call.receiver.id === userId && 
  //           call.status === 'pending' && 
  //           call.isActive &&
  //           call.expiresAt && 
  //           new Date() < call.expiresAt) {
          
  //         const remainingSeconds = Math.max(0, Math.floor((call.expiresAt - new Date()) / 1000));
          
  //         pendingRequests.push({
  //           callId: call.callId,
  //           roomId: call.roomId,
  //           from: {
  //             id: call.initiator.id,
  //             name: call.initiator.name,
  //             anonymous:call?.initiator?.anonymous,
  //             type: call.initiator.type,
  //             profilePhoto: call.initiator.profilePhoto,
  //             specialization: call.initiator.specialization,
  //             rating: call.initiator.rating
  //           },
  //           callType: call.type,
  //           requestMessage: call.requestMessage,
  //           requestedAt: call.createdAt,
  //           expiresAt: call.expiresAt,
  //           remainingSeconds
  //         });
  //       }
  //     }
      
  //     res.json({
  //       success: true,
  //       pendingRequests,
  //       count: pendingRequests.length
  //     });
      
  //   } catch (error) {
  //     console.error('Error getting pending requests:', error);
  //     res.status(500).json({ 
  //       success: false, 
  //       error: 'Failed to get pending requests',
  //       details: error.message 
  //     });
  //   }
  // },
  
  // // 3. Accept call request (like acceptChat)
  // acceptCall: async (req, res) => {
  //   try {
  //     const { callId } = req.params;
  //     const { acceptorId, acceptorType } = req.body;
      
  //     if (!mongoose.Types.ObjectId.isValid(acceptorId)) {
  //       return res.status(400).json({
  //         success: false,
  //         error: 'Invalid acceptorId format'
  //       });
  //     }
      
  //     const call = activeCalls.get(callId);
      
  //     if (!call) {
  //       return res.status(404).json({ 
  //         success: false, 
  //         error: 'Call request not found' 
  //       });
  //     }
      
  //     // Verify the acceptor is the intended receiver
  //     if (call.receiver.id !== acceptorId) {
  //       return res.status(403).json({ 
  //         success: false, 
  //         error: 'You are not the intended recipient of this call' 
  //       });
  //     }
      
  //     // Check if request has expired
  //     if (call.status === 'pending' && call.expiresAt && new Date() > call.expiresAt) {
  //       call.status = 'cancelled';
  //       call.isActive = false;
  //       call.cancelledAt = new Date();
  //       activeCalls.set(callId, call);
        
  //       return res.status(400).json({ 
  //         success: false,
  //         error: 'Call request has expired. User needs to send a new request.',
  //         status: 'expired',
  //         canResend: true,
  //         callId: call._id
  //       });
  //     }
      
  //     if (call.status !== 'pending') {
  //       return res.status(400).json({ 
  //         success: false,
  //         error: `Cannot accept call. Current status: ${call.status}`,
  //         status: call.status
  //       });
  //     }
      
  //     // Get acceptor details
  //     const acceptorDetails = await videoCallController.getUserDetails(acceptorId, acceptorType);
      
  //     if (!acceptorDetails) {
  //       return res.status(404).json({
  //         success: false,
  //         error: 'Acceptor not found'
  //       });
  //     }
      
  //     // Update call status to accepted/active
  //     call.status = 'active';
  //     call.acceptedAt = new Date();
  //     call.expiresAt = null;
  //     call.receiver.name = acceptorDetails.name;
  //     call.receiver.profilePhoto = acceptorDetails.profilePhoto;
  //     call.receiver.specialization = acceptorDetails.specialization;
  //     call.receiver.rating = acceptorDetails.rating;
      
  //     // Add receiver to participants
  //     call.participants.set(acceptorId, {
  //       userId: acceptorId,
  //       userName: acceptorDetails.name,
  //       role: 'receiver',
  //       type: acceptorType,
  //       joinedAt: new Date(),
  //       isVideoEnabled: true,
  //       isAudioEnabled: true,
  //       isScreenSharing: false,
  //       profilePhoto: acceptorDetails.profilePhoto
  //     });
      
  //     // Update user status
  //     userStatus.set(call.initiator.id, { status: 'busy', currentCall: callId });
  //     userStatus.set(call.receiver.id, { status: 'busy', currentCall: callId });
      
  //     activeCalls.set(callId, call);
      
  //     // Notify initiator that call was accepted
  //     if (global.io) {
  //       global.io.to(`user_${call.initiator.id}`).emit('call_accepted', {
  //         callId,
  //         roomId: call.roomId,
  //         by: acceptorDetails.name,
  //         byProfilePhoto: acceptorDetails.profilePhoto,
  //         timestamp: new Date()
  //       });
  //     }
      
  //     res.json({
  //       success: true,
  //       message: 'Call request accepted',
  //       callId,
  //       roomId: call.roomId,
  //       status: 'active',
  //       acceptedAt: call.acceptedAt,
  //       participants: Array.from(call.participants.values())
  //     });
      
  //   } catch (error) {
  //     console.error('Error accepting call:', error);
  //     res.status(500).json({ 
  //       success: false, 
  //       error: 'Failed to accept call',
  //       details: error.message 
  //     });
  //   }
  // },
  
  // 4. Reject call request (like rejectChat)
  rejectCall: async (req, res) => {
    try {
      const { callId } = req.params;
      const { userId, reason = 'unavailable' } = req.body;
      
      const call = activeCalls.get(callId);
      
      if (!call) {
        return res.status(404).json({ 
          success: false, 
          error: 'Call not found' 
        });
      }
      
      // Verify authorization
      if (call.receiver.id !== userId && call.initiator.id !== userId) {
        return res.status(403).json({ 
          success: false, 
          error: 'Not authorized to reject this call' 
        });
      }
      
      if (call.status !== 'pending') {
        return res.status(400).json({ 
          success: false, 
          error: `Cannot reject call. Current status: ${call.status}` 
        });
      }
      
      // Save to history as rejected
      const historyEntry = {
        id: call.callId,
        roomId: call.roomId,
        type: call.type,
        status: 'rejected',
        initiatedBy: call.initiatedBy,
        initiator: call.initiator,
        receiver: call.receiver,
        createdAt: call.createdAt,
        rejectedAt: new Date(),
        reason,
        duration: 0,
        rejectedBy: userId
      };
      
      callHistory.unshift(historyEntry);
      
      // Store in user's call history
      [call.initiator.id, call.receiver.id].forEach(uid => {
        if (!userCallHistory.has(uid)) {
          userCallHistory.set(uid, []);
        }
        userCallHistory.get(uid).push(historyEntry);
      });
      
      // Update call status
      call.status = 'rejected';
      call.isActive = false;
      call.rejectedAt = new Date();
      
      // Notify initiator
      if (global.io) {
        global.io.to(`user_${call.initiator.id}`).emit('call_rejected', {
          callId,
          reason,
          by: call.receiver.name
        });
      }
      
      // Remove from active calls
      activeCalls.delete(callId);
      
      res.json({
        success: true,
        message: 'Call request rejected',
        call: historyEntry
      });
      
    } catch (error) {
      console.error('Error rejecting call:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Failed to reject call',
        details: error.message 
      });
    }
  },
  
  // 5. Join active call (after accepted)
  joinCall: async (req, res) => {
    try {
      const { callId } = req.params;
      const { userId, userType } = req.body;
      
      if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid userId format'
        });
      }
      
      const call = activeCalls.get(callId);
      
      if (!call) {
        return res.status(404).json({ 
          success: false, 
          error: 'Call not found' 
        });
      }
      
      if (call.status === 'ended') {
        return res.status(400).json({ 
          success: false, 
          error: 'Call has already ended' 
        });
      }
      
      if (call.status !== 'active') {
        return res.status(400).json({ 
          success: false, 
          error: `Cannot join call. Current status: ${call.status}` 
        });
      }
      
      // Check if user is authorized
      const isInitiator = call.initiator.id === userId;
      const isReceiver = call.receiver.id === userId;
      
      if (!isInitiator && !isReceiver) {
        return res.status(403).json({ 
          success: false, 
          error: 'Not authorized to join this call' 
        });
      }
      
      // Get user details
      const userDetails = await videoCallController.getUserDetails(userId, userType);
      
      if (!userDetails) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }
      
      // Add or update participant
      if (!call.participants.has(userId)) {
        call.participants.set(userId, {
          userId,
          userName: userDetails.name,
          role: isInitiator ? 'initiator' : 'receiver',
          type: userType,
          joinedAt: new Date(),
          isVideoEnabled: true,
          isAudioEnabled: true,
          isScreenSharing: false,
          profilePhoto: userDetails.profilePhoto
        });
      }
      
      // If this is the first participant joining, set start time
      if (!call.startTime && call.participants.size >= 1) {
        call.startTime = new Date();
      }
      
      res.json({
        success: true,
        callId,
        roomId: call.roomId,
        status: call.status,
        participants: Array.from(call.participants.values()),
        startTime: call.startTime,
        token: call.roomId
      });
      
    } catch (error) {
      console.error('Error joining call:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Failed to join call',
        details: error.message 
      });
    }
  },
  
  // 6. End active call
  endCall: async (req, res) => {
    try {
      const { callId } = req.params;
      const { userId } = req.body;
      
      const call = activeCalls.get(callId);
      
      if (!call) {
        return res.status(404).json({ 
          success: false, 
          error: 'Call not found' 
        });
      }
      
      const endTime = new Date();
      const duration = call.startTime 
        ? Math.floor((endTime - call.startTime) / 1000)
        : 0;
      
      // Determine who ended the call
      const endedBy = call.initiator.id === userId ? call.initiator : call.receiver;
      
      // Save to history
      const historyEntry = {
        id: call.callId,
        roomId: call.roomId,
        type: call.type,
        status: 'completed',
        initiatedBy: call.initiatedBy,
        initiator: call.initiator,
        receiver: call.receiver,
        createdAt: call.createdAt,
        acceptedAt: call.acceptedAt,
        startTime: call.startTime,
        endTime,
        duration,
        endedBy: {
          id: endedBy.id,
          name: endedBy.name,
          type: endedBy.type
        },
        participants: Array.from(call.participants.values())
      };
      
      callHistory.unshift(historyEntry);
      
      // Store in user's call history
      [call.initiator.id, call.receiver.id].forEach(uid => {
        if (!userCallHistory.has(uid)) {
          userCallHistory.set(uid, []);
        }
        userCallHistory.get(uid).push(historyEntry);
      });
      
      // Update user status
      userStatus.set(call.initiator.id, { status: 'online', currentCall: null });
      userStatus.set(call.receiver.id, { status: 'online', currentCall: null });
      
      // Update call status
      call.status = 'ended';
      call.endTime = endTime;
      call.duration = duration;
      
      // Remove from active calls
      activeCalls.delete(callId);
      
      // Notify other participant
      const otherParticipant = call.initiator.id === userId ? call.receiver.id : call.initiator.id;
      if (global.io) {
        global.io.to(`user_${otherParticipant}`).emit('call_ended', {
          callId,
          duration,
          endedBy: endedBy.name
        });
      }
      
      res.json({
        success: true,
        message: 'Call ended successfully',
        callSummary: {
          callId,
          duration,
          endedAt: endTime,
          with: endedBy.id === userId ? call.receiver.name : call.initiator.name,
          endedBy: endedBy.name
        }
      });
      
    } catch (error) {
      console.error('Error ending call:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Failed to end call',
        details: error.message 
      });
    }
  },
  
  // 7. Resend expired call request (like resendRequest)
  resendCallRequest: async (req, res) => {
    try {
      const { callId } = req.params;
      const { userId, userType } = req.body;
      
      const call = activeCalls.get(callId);
      
      if (!call) {
        return res.status(404).json({ 
          success: false, 
          error: 'Call not found' 
        });
      }
      
      // Check authorization
      if (call.initiator.id !== userId) {
        return res.status(403).json({ 
          success: false, 
          error: 'Only the initiator can resend the request' 
        });
      }
      
      // Only allow resend if call is cancelled or expired
      if (call.status !== 'cancelled' && call.status !== 'rejected') {
        return res.status(400).json({ 
          success: false,
          error: `Cannot resend. Call is ${call.status}` 
        });
      }
      
      // Reset the call for new request
      const expiresAt = new Date();
      expiresAt.setSeconds(expiresAt.getSeconds() + 10);
      
      call.status = 'pending';
      call.isActive = true;
      call.expiresAt = expiresAt;
      call.cancelledAt = null;
      call.rejectedAt = null;
      call.updatedAt = new Date();
      
      activeCalls.set(callId, call);
      
      // Emit new request notification
      if (global.io) {
        global.io.to(`user_${call.receiver.id}`).emit('incoming_call_request', {
          callId,
          roomId: call.roomId,
          from: call.initiator.name,
          fromId: call.initiator.id,
          fromType: call.initiator.type,
          fromProfilePhoto: call.initiator.profilePhoto,
          callType: call.type,
          message: call.requestMessage,
          expiresAt,
          remainingSeconds: 10,
          timestamp: new Date()
        });
      }
      
      res.json({
        success: true,
        message: 'Call request resent successfully',
        callId,
        status: 'pending',
        expiresAt
      });
      
    } catch (error) {
      console.error('Error resending request:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Failed to resend request',
        details: error.message 
      });
    }
  },
  
  // 8. Auto-cancel expired call requests (background job)
  cancelExpiredRequests: async () => {
    try {
      const now = new Date();
      let cancelledCount = 0;
      
      for (const [callId, call] of activeCalls.entries()) {
        if (call.status === 'pending' && 
            call.expiresAt && 
            new Date(call.expiresAt) < now &&
            call.isActive) {
          
          call.status = 'cancelled';
          call.isActive = false;
          call.cancelledAt = now;
          activeCalls.set(callId, call);
          cancelledCount++;
          
          console.log(`Cancelled expired call request: ${callId}`);
          
          // Notify initiator
          if (global.io) {
            global.io.to(`user_${call.initiator.id}`).emit('call_expired', {
              callId,
              message: 'Call request expired after 10 seconds'
            });
          }
        }
      }
      
      return cancelledCount;
    } catch (error) {
      console.error('Error cancelling expired requests:', error);
      return 0;
    }
  },
  
  // ==================== STATUS MANAGEMENT ====================
  
  // 9. Update user status
  updateUserStatus: async (req, res) => {
    try {
      const { userId, status } = req.body;
      
      if (!['online', 'offline', 'busy', 'away'].includes(status)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid status'
        });
      }
      
      const currentStatus = userStatus.get(userId) || { status: 'offline', currentCall: null };
      currentStatus.status = status;
      userStatus.set(userId, currentStatus);
      
      if (mongoose.Types.ObjectId.isValid(userId)) {
        await User.findByIdAndUpdate(userId, { 
          $set: { isActive: status === 'online' }
        });
      }
      
      if (global.io) {
        global.io.emit('user_status_changed', {
          userId,
          status,
          timestamp: new Date()
        });
      }
      
      res.json({
        success: true,
        message: 'Status updated successfully',
        status: currentStatus
      });
      
    } catch (error) {
      console.error('Error updating status:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to update status'
      });
    }
  },
  
  // 10. Get user status
  getUserStatus: async (req, res) => {
    try {
      const { userId } = req.params;
      const status = userStatus.get(userId) || { status: 'offline', currentCall: null };
      
      res.json({
        success: true,
        userId,
        status: status.status,
        currentCall: status.currentCall,
        isAvailable: status.status === 'online'
      });
      
    } catch (error) {
      console.error('Error getting status:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to get status'
      });
    }
  },
  
  // ==================== CALL HISTORY ====================
  
  // 11. Get call history
  getCallHistory: async (req, res) => {
    try {
      const { userId } = req.params;
      const { page = 1, limit = 20, status = 'all', type = 'all' } = req.query;
      
      let userCalls = userCallHistory.get(userId) || [];
      
      if (status !== 'all') {
        userCalls = userCalls.filter(call => call.status === status);
      }
      
      if (type === 'initiated') {
        userCalls = userCalls.filter(call => call.initiator.id === userId);
      } else if (type === 'received') {
        userCalls = userCalls.filter(call => call.receiver.id === userId);
      }
      
      userCalls.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
      
      const start = (parseInt(page) - 1) * parseInt(limit);
      const end = start + parseInt(limit);
      const paginatedCalls = userCalls.slice(start, end);
      
      const formattedCalls = paginatedCalls.map(call => {
        const isInitiator = call.initiator.id === userId;
        const otherParticipant = isInitiator ? call.receiver : call.initiator;
        
        return {
          id: call.id,
          with: otherParticipant.name,
          withId: otherParticipant.id,
          withType: otherParticipant.type,
          withProfilePhoto: otherParticipant.profilePhoto,
          type: call.type,
          duration: call.duration,
          timestamp: call.createdAt,
          status: call.status,
          role: isInitiator ? 'initiator' : 'receiver',
          endedBy: call.endedBy,
          reason: call.reason,
          acceptedAt: call.acceptedAt,
          rejectedAt: call.rejectedAt
        };
      });
      
      res.json({
        success: true,
        history: formattedCalls,
        total: userCalls.length,
        page: parseInt(page),
        totalPages: Math.ceil(userCalls.length / parseInt(limit))
      });
      
    } catch (error) {
      console.error('Error fetching history:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Failed to fetch history'
      });
    }
  },
  
  // 12. Get active calls
  getActiveCalls: async (req, res) => {
    try {
      const { userId } = req.params;
      const activeCallsList = [];
      
      for (const [callId, call] of activeCalls.entries()) {
        if (call.status !== 'ended' && 
            call.isActive &&
            (call.initiator.id === userId || call.receiver.id === userId)) {
          
          const isInitiator = call.initiator.id === userId;
          const otherParticipant = isInitiator ? call.receiver : call.initiator;
          
          activeCallsList.push({
            callId,
            roomId: call.roomId,
            with: otherParticipant.name,
            withId: otherParticipant.id,
            withType: otherParticipant.type,
            withProfilePhoto: otherParticipant.profilePhoto,
            status: call.status,
            startTime: call.startTime,
            createdAt: call.createdAt,
            participants: Array.from(call.participants.values()),
            duration: call.startTime 
              ? Math.floor((new Date() - call.startTime) / 1000)
              : 0
          });
        }
      }
      
      res.json({
        success: true,
        activeCalls: activeCallsList,
        count: activeCallsList.length
      });
      
    } catch (error) {
      console.error('Error fetching active calls:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Failed to fetch active calls'
      });
    }
  },
  
  // 13. Get call details
  getCallDetails: async (req, res) => {
    try {
      const { callId } = req.params;
      
      let call = activeCalls.get(callId);
      let isActive = true;
      
      if (!call) {
        call = callHistory.find(c => c.id === callId);
        isActive = false;
      }
      
      if (!call) {
        return res.status(404).json({ 
          success: false, 
          error: 'Call not found' 
        });
      }
      
      res.json({
        success: true,
        call: {
          id: call.id || call.callId,
          roomId: call.roomId,
          type: call.type,
          status: call.status,
          initiator: call.initiator,
          receiver: call.receiver,
          requestMessage: call.requestMessage,
          createdAt: call.createdAt,
          acceptedAt: call.acceptedAt,
          rejectedAt: call.rejectedAt,
          cancelledAt: call.cancelledAt,
          startTime: call.startTime,
          endTime: call.endTime,
          duration: call.duration,
          participants: isActive ? Array.from(call.participants.values()) : call.participants,
          endedBy: call.endedBy,
          expiresAt: call.expiresAt
        },
        isActive
      });
      
    } catch (error) {
      console.error('Error fetching call details:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Failed to fetch call details'
      });
    }
  },
  
  // ==================== UTILITY ENDPOINTS ====================
  
  // 14. Get all pending calls (for debugging)
  getAllPendingCalls: async (req, res) => {
    try {
      const pendingCalls = [];
      
      for (const [callId, call] of activeCalls.entries()) {
        if (call.status === 'pending' && call.isActive) {
          const remainingSeconds = call.expiresAt 
            ? Math.max(0, Math.floor((call.expiresAt - new Date()) / 1000))
            : null;
          
          pendingCalls.push({
            callId: call.callId,
            initiator: call.initiator,
            receiver: call.receiver,
            expiresAt: call.expiresAt,
            remainingSeconds,
            createdAt: call.createdAt
          });
        }
      }
      
      res.json({
        success: true,
        pendingCalls,
        count: pendingCalls.length
      });
      
    } catch (error) {
      console.error('Error getting pending calls:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Failed to get pending calls'
      });
    }
  },
  
  // 15. Test endpoint - get all calls
  getAllCalls: async (req, res) => {
    try {
      const allCalls = [];
      
      for (const [callId, call] of activeCalls.entries()) {
        allCalls.push({
          callId: call.callId,
          initiator: call.initiator,
          receiver: call.receiver,
          status: call.status,
          isActive: call.isActive,
          expiresAt: call.expiresAt,
          participants: Array.from(call.participants.values())
        });
      }
      
      res.json({
        success: true,
        activeCalls: allCalls,
        history: callHistory,
        userStatus: Array.from(userStatus.entries()),
        activeCount: activeCalls.size,
        historyCount: callHistory.length
      });
      
    } catch (error) {
      console.error('Error getting all calls:', error);
      res.status(500).json({ 
        success: false, 
        error: 'Failed to get calls'
      });
    }
  }
};

// Auto-cancel expired requests every second
setInterval(async () => {
  const cancelled = await videoCallController.cancelExpiredRequests();
  if (cancelled > 0) {
    console.log(`Auto-cancelled ${cancelled} expired call requests`);
  }
}, 1000);