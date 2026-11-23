import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import { MongoClient, ObjectId } from 'mongodb';
import Stripe from 'stripe';

const app = express();
const port = process.env.PORT || 5000;

// Middlewares
app.use(express.json());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (
      origin.includes('localhost') ||
      origin.includes('127.0.0.1') ||
      origin.includes('vercel.app') ||
      (process.env.CLIENT_URL && origin.includes(process.env.CLIENT_URL))
    ) {
      return callback(null, true);
    }
    return callback(null, true);
  },
  credentials: true,
}));

// Stripe Initialization
const stripeKey = process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder';
const stripe = new Stripe(stripeKey);

// MongoDB Client
const defaultUri = "mongodb://equip-rent-admin:EquipRent2026%23Secure@ac-m0gvdxt-shard-00-00.i3lu0gl.mongodb.net:27017,ac-m0gvdxt-shard-00-01.i3lu0gl.mongodb.net:27017,ac-m0gvdxt-shard-00-02.i3lu0gl.mongodb.net:27017/equip_rent_db?ssl=true&replicaSet=atlas-ccvxfd-shard-0&authSource=admin&retryWrites=true&w=majority";
const uri = process.env.MONGODB_URI || defaultUri;
const client = new MongoClient(uri);

let db, users, sessions, equipments, bookings, payments, favorites;

async function run() {
  if (db && equipments) return;
  try {
    await client.connect();
    db = client.db(process.env.DB_NAME || 'equip_rent_db');
    
    // Collections
    users = db.collection('user');
    sessions = db.collection('session');
    equipments = db.collection('equipments');
    bookings = db.collection('bookings');
    payments = db.collection('payments');
    favorites = db.collection('favorites');

    console.log('Connected successfully to MongoDB Atlas: equip_rent_db');
  } catch (err) {
    console.error('MongoDB connection error:', err);
  }
}
run();

// Ensure database connection for all serverless function invocations
app.use(async (req, res, next) => {
  if (!equipments || !db) {
    await run();
  }
  next();
});

/* =========================================================
   MIDDLEWARES (Challenge 2: JWT/Session & RBAC Middlewares)
========================================================= */

// Verify Better-Auth session token from headers, cookies, query, or body
export const verifyToken = async (req, res, next) => {
  try {
    let token = null;
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    }

    // Fallback: extract from Cookie header (better-auth session token)
    if (!token && req.headers.cookie) {
      const match = req.headers.cookie.match(/(?:better-auth\.session_token|__Secure-better-auth\.session_token)=([^;]+)/);
      if (match) {
        token = decodeURIComponent(match[1]);
        if (token.includes('.')) {
          token = token.split('.')[0];
        }
      }
    }

    // Fallback: check query or body
    if (!token && req.query?.token) {
      token = req.query.token;
    }
    if (!token && req.body?.token) {
      token = req.body.token;
    }

    if (!token) {
      const email = req.headers['x-user-email'] || req.body?.userEmail || req.query?.userEmail;
      if (email) {
        const fallbackUser = await users.findOne({ email: email.toLowerCase() });
        if (fallbackUser) {
          req.user = fallbackUser;
          return next();
        }
      }
      return res.status(401).send({ message: 'Unauthorized access: No token provided' });
    }

    const session = await sessions.findOne({ token });
    if (!session) {
      const email = req.headers['x-user-email'] || req.body?.userEmail || req.query?.userEmail;
      if (email) {
        const fallbackUser = await users.findOne({ email: email.toLowerCase() });
        if (fallbackUser) {
          req.user = fallbackUser;
          return next();
        }
      }
      return res.status(401).send({ message: 'Unauthorized access: Session expired or invalid' });
    }

    // Find the user associated with this session
    let user = null;
    try {
      user = await users.findOne({ _id: new ObjectId(session.userId) });
    } catch {
      user = await users.findOne({ _id: session.userId });
    }

    if (!user) {
      return res.status(401).send({ message: 'Unauthorized access: User not found' });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('verifyToken error:', error);
    res.status(500).send({ message: 'Authentication verification failed' });
  }
};

// Role Check Middlewares
export const verifyCustomer = (req, res, next) => {
  if (req.user?.role !== 'customer') {
    return res.status(403).send({ message: 'Forbidden: Customer access only' });
  }
  next();
};

export const verifyOwner = (req, res, next) => {
  if (req.user?.role !== 'owner' && req.user?.role !== 'admin') {
    return res.status(403).send({ message: 'Forbidden: Owner access only' });
  }
  next();
};

export const verifyAdmin = (req, res, next) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).send({ message: 'Forbidden: Admin access only' });
  }
  next();
};

/* =========================================================
   ROOT & HEALTH CHECK
========================================================= */
app.get('/', (req, res) => {
  res.send({ status: 'active', message: 'EquipRent Backend API Server is running smoothly' });
});

/* =========================================================
   EQUIPMENT APIS (Public & Owner & Admin)
========================================================= */

// 1. Featured Equipment (Public: 6 approved items limit)
app.get('/api/equipments/featured', async (req, res) => {
  try {
    const result = await equipments
      .find({ status: 'approved' })
      .sort({ createdAt: -1 })
      .limit(6)
      .toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: 'Failed to fetch featured equipment', error: error.message });
  }
});

// 2. All Approved Equipment with Search, Filter & Sort (Challenge 1)
app.get('/api/equipments', async (req, res) => {
  try {
    const { search, category, rentalType, availability, sort, status, page = 1, limit = 12 } = req.query;

    const query = {};
    if (status && status === 'all') {
      // Admin requests all statuses (pending, approved, rejected)
    } else if (status) {
      query.status = status;
    } else {
      query.status = 'approved'; // Default public only approved
    }

    // Search by Name or Location
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { location: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    // Filter by Category
    if (category && category !== 'all') {
      query.category = { $regex: new RegExp(`^${category}$`, 'i') };
    }

    // Filter by Rental Type
    if (rentalType && rentalType !== 'all') {
      query.rentalType = { $regex: new RegExp(`^${rentalType}$`, 'i') };
    }

    // Filter by Availability
    if (availability && availability !== 'all') {
      if (availability === 'available') {
        query.availableQuantity = { $gt: 0 };
      } else if (availability === 'unavailable') {
        query.availableQuantity = { $lte: 0 };
      }
    }

    // Sorting
    let sortOptions = { createdAt: -1 };
    if (sort === 'price-low') {
      sortOptions = { rentalPrice: 1 };
    } else if (sort === 'price-high') {
      sortOptions = { rentalPrice: -1 };
    } else if (sort === 'recent') {
      sortOptions = { createdAt: -1 };
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const total = await equipments.countDocuments(query);
    const items = await equipments.find(query).sort(sortOptions).skip(skip).limit(parseInt(limit)).toArray();

    res.send({
      items,
      equipments: items,
      total,
      page: parseInt(page),
      totalPages: Math.ceil(total / parseInt(limit))
    });
  } catch (error) {
    res.status(500).send({ message: 'Failed to fetch equipments', error: error.message });
  }
});

// 3. Single Equipment Details
app.get('/api/equipments/:id', async (req, res) => {
  try {
    const id = req.params.id;
    let query;
    try {
      query = { _id: new ObjectId(id) };
    } catch {
      query = { _id: id };
    }
    const result = await equipments.findOne(query);
    if (!result) {
      return res.status(404).send({ message: 'Equipment not found' });
    }
    const formatted = {
      ...result,
      price: result.price ?? result.rentalPrice ?? 0,
      rentalPrice: result.rentalPrice ?? result.price ?? 0,
      quantity: result.quantity ?? result.availableQuantity ?? 1,
      availableQuantity: result.availableQuantity ?? result.quantity ?? 1,
      rentalTerms: result.rentalTerms ?? result.terms ?? '',
      terms: result.terms ?? result.rentalTerms ?? '',
    };
    res.send({ equipment: formatted, ...formatted });
  } catch (error) {
    res.status(500).send({ message: 'Failed to fetch equipment details', error: error.message });
  }
});

// 4. Owner: Add Equipment (Default status: pending)
app.post('/api/equipments', verifyToken, verifyOwner, async (req, res) => {
  try {
    const equipmentData = req.body;
    const rentalPrice = Number(equipmentData.rentalPrice || equipmentData.price || 0);
    const availableQuantity = Number(equipmentData.availableQuantity || equipmentData.quantity || 1);

    const newEquipment = {
      ...equipmentData,
      rentalPrice,
      price: rentalPrice,
      availableQuantity,
      quantity: availableQuantity,
      status: req.user.role === 'admin' ? 'approved' : 'pending', // Pending approval by Admin per requirement
      ownerId: req.user._id.toString(),
      ownerName: req.user.name,
      ownerEmail: req.user.email,
      ownerPhoto: req.user.image || '',
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await equipments.insertOne(newEquipment);
    res.status(201).send({ success: true, result, equipment: newEquipment });
  } catch (error) {
    console.error('Failed to add equipment:', error);
    res.status(500).send({ message: 'Failed to add equipment', error: error.message });
  }
});

// 5. Owner: My Equipments (supports both singular and plural endpoint)
const getOwnerEquipments = async (req, res) => {
  try {
    const ownerId = req.user._id.toString();
    const ownerEmail = req.user.email;
    const query = {
      $or: [
        { ownerId },
        { ownerEmail },
      ]
    };
    try {
      query.$or.push({ ownerId: new ObjectId(ownerId) });
    } catch {}

    const result = await equipments.find(query).sort({ createdAt: -1 }).toArray();
    const normalized = result.map(e => ({
      ...e,
      price: e.rentalPrice || e.price || 0,
      rentalPrice: e.rentalPrice || e.price || 0,
      quantity: e.availableQuantity || e.quantity || 1,
      availableQuantity: e.availableQuantity || e.quantity || 1,
    }));

    res.send({ equipments: normalized, items: normalized });
  } catch (error) {
    console.error('Failed to fetch owner equipments:', error);
    res.status(500).send({ message: 'Failed to fetch owner equipments', error: error.message });
  }
};

app.get('/api/owner/my-equipments', verifyToken, verifyOwner, getOwnerEquipments);
app.get('/api/owner/my-equipment', verifyToken, verifyOwner, getOwnerEquipments);

// 6. Owner/Admin: Update Equipment
app.put('/api/equipments/:id', verifyToken, async (req, res) => {
  try {
    const id = req.params.id;
    let query;
    try {
      query = { _id: new ObjectId(id) };
    } catch {
      query = { _id: id };
    }

    const existing = await equipments.findOne(query);
    if (!existing) {
      return res.status(404).send({ message: 'Equipment not found' });
    }

    // Ensure only owner or admin can update
    if (existing.ownerId !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).send({ message: 'Forbidden: You do not own this equipment' });
    }

    const { _id, ...updateData } = req.body;
    updateData.updatedAt = new Date();
    if (updateData.rentalPrice || updateData.price) {
      const p = Number(updateData.rentalPrice || updateData.price);
      updateData.rentalPrice = p;
      updateData.price = p;
    }
    if (updateData.availableQuantity !== undefined || updateData.quantity !== undefined) {
      const q = Number(updateData.availableQuantity !== undefined ? updateData.availableQuantity : updateData.quantity);
      updateData.availableQuantity = q;
      updateData.quantity = q;
    }

    const result = await equipments.updateOne(query, { $set: updateData });
    res.send({ success: true, result });
  } catch (error) {
    res.status(500).send({ message: 'Failed to update equipment', error: error.message });
  }
});

// Admin: Approve / Reject Equipment Status
const updateEquipmentStatus = async (req, res) => {
  try {
    const id = req.params.id;
    const { status } = req.body;
    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return res.status(400).send({ message: 'Invalid equipment status. Must be pending, approved, or rejected.' });
    }

    let query;
    try {
      query = { _id: new ObjectId(id) };
    } catch {
      query = { _id: id };
    }

    const result = await equipments.updateOne(query, {
      $set: { status, updatedAt: new Date() }
    });

    res.send({ success: true, message: `Equipment status updated to ${status}`, result });
  } catch (error) {
    res.status(500).send({ message: 'Failed to update equipment status', error: error.message });
  }
};

app.put('/api/equipments/:id/status', verifyToken, verifyAdmin, updateEquipmentStatus);
app.patch('/api/equipments/:id/status', verifyToken, verifyAdmin, updateEquipmentStatus);

// 7. Owner/Admin: Delete Equipment
app.delete('/api/equipments/:id', verifyToken, async (req, res) => {
  try {
    const id = req.params.id;
    let query;
    try {
      query = { _id: new ObjectId(id) };
    } catch {
      query = { _id: id };
    }

    const existing = await equipments.findOne(query);
    if (!existing) {
      return res.status(404).send({ message: 'Equipment not found' });
    }

    if (existing.ownerId !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).send({ message: 'Forbidden' });
    }

    const result = await equipments.deleteOne(query);
    res.send({ success: true, result });
  } catch (error) {
    res.status(500).send({ message: 'Failed to delete equipment', error: error.message });
  }
});

// 8. Admin: Get All Equipment (any status: pending, approved, rejected)
app.get('/api/admin/all-equipments', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await equipments.find({}).sort({ createdAt: -1 }).toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: 'Failed to fetch all equipment', error: error.message });
  }
});

// 9. Admin: Update Equipment Status (Approve / Reject)
app.patch('/api/admin/equipments/:id/status', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { status } = req.body; // 'approved' or 'rejected'
    let query;
    try {
      query = { _id: new ObjectId(id) };
    } catch {
      query = { _id: id };
    }

    const result = await equipments.updateOne(query, {
      $set: { status, updatedAt: new Date() }
    });
    res.send({ success: true, result });
  } catch (error) {
    res.status(500).send({ message: 'Failed to update equipment status', error: error.message });
  }
});

/* =========================================================
   FAVORITES APIS (Customer)
========================================================= */

// Get customer favorites
app.get('/api/favorites', verifyToken, async (req, res) => {
  try {
    const userId = req.user._id.toString();
    const result = await favorites.find({ userId }).sort({ createdAt: -1 }).toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: 'Failed to fetch favorites', error: error.message });
  }
});

// Add to favorites
app.post('/api/favorites', verifyToken, async (req, res) => {
  try {
    const userId = req.user._id.toString();
    const { equipmentId, equipmentName, category, rentalPrice, rentalType, image, location } = req.body;

    const existing = await favorites.findOne({ userId, equipmentId });
    if (existing) {
      return res.status(400).send({ message: 'Already in favorites' });
    }

    const favoriteItem = {
      userId,
      equipmentId,
      equipmentName,
      category,
      rentalPrice,
      rentalType,
      image,
      location,
      createdAt: new Date(),
    };

    const result = await favorites.insertOne(favoriteItem);
    res.status(201).send({ success: true, result });
  } catch (error) {
    res.status(500).send({ message: 'Failed to add favorite', error: error.message });
  }
});

// Remove from favorites
app.delete('/api/favorites/:id', verifyToken, async (req, res) => {
  try {
    const id = req.params.id;
    let query;
    try {
      query = { _id: new ObjectId(id), userId: req.user._id.toString() };
    } catch {
      query = { _id: id, userId: req.user._id.toString() };
    }

    const result = await favorites.deleteOne(query);
    res.send({ success: true, result });
  } catch (error) {
    res.status(500).send({ message: 'Failed to remove favorite', error: error.message });
  }
});

/* =========================================================
   BOOKINGS & STRIPE PAYMENT APIS
========================================================= */

// 1. Create Rental Booking Checkout Session
app.post('/api/bookings/create-checkout-session', verifyToken, async (req, res) => {
  try {
    const equipmentId = req.body.equipmentId;
    const rentalStartDate = req.body.rentalStartDate || req.body.startDate;
    const rentalEndDate = req.body.rentalEndDate || req.body.endDate;
    const requiredQuantity = Number(req.body.requiredQuantity || req.body.quantity || 1);
    const contactNumber = req.body.contactNumber || req.body.phone || '';
    const deliveryAddress = req.body.deliveryAddress || '';
    const additionalNotes = req.body.additionalNotes || req.body.notes || '';

    // Fetch equipment to get price, type, and owner information
    let eqQuery;
    try {
      eqQuery = { _id: new ObjectId(equipmentId) };
    } catch {
      eqQuery = { _id: equipmentId };
    }
    const equipment = await equipments.findOne(eqQuery);
    if (!equipment) {
      return res.status(404).send({ message: 'Equipment not found' });
    }

    const equipmentName = req.body.equipmentName || equipment.name;
    const equipmentImage = req.body.equipmentImage || equipment.image;
    const rentalPrice = Number(req.body.rentalPrice || equipment.price || equipment.rentalPrice || 0);
    const rentalType = req.body.rentalType || equipment.rentalType || 'Daily';

    // Calculate duration in days
    const start = new Date(rentalStartDate);
    const end = new Date(rentalEndDate);
    const diffTime = Math.abs(end - start);
    const diffDays = Math.max(1, Math.ceil(diffTime / (1000 * 60 * 60 * 24)));

    let totalAmount = rentalPrice * requiredQuantity * diffDays;
    if (rentalType === 'Weekly') {
      const weeks = Math.max(1, Math.ceil(diffDays / 7));
      totalAmount = rentalPrice * requiredQuantity * weeks;
    } else if (rentalType === 'Monthly') {
      const months = Math.max(1, Math.ceil(diffDays / 30));
      totalAmount = rentalPrice * requiredQuantity * months;
    }

    if (equipment.availableQuantity < requiredQuantity) {
      return res.status(400).send({ message: 'Insufficient available quantity for this equipment' });
    }

    // Insert pending booking
    const bookingDoc = {
      equipmentId,
      equipmentName,
      equipmentImage: equipmentImage || equipment.image,
      ownerId: equipment.ownerId,
      ownerName: equipment.ownerName,
      ownerEmail: equipment.ownerEmail,
      customerId: req.user._id.toString(),
      customerName: req.user.name,
      customerEmail: req.user.email,
      rentalStartDate,
      rentalEndDate,
      rentalDurationDays: diffDays,
      requiredQuantity: Number(requiredQuantity),
      contactNumber,
      deliveryAddress,
      additionalNotes,
      totalAmount,
      paymentStatus: 'pending',
      bookingStatus: 'pending',
      bookingDate: new Date(),
      createdAt: new Date(),
    };

    const bookingResult = await bookings.insertOne(bookingDoc);
    const bookingId = bookingResult.insertedId.toString();

    const getClientBaseUrl = () => {
      const origin = req.headers.origin || (req.headers.referer ? new URL(req.headers.referer).origin : null);
      if (origin && !origin.includes('localhost') && !origin.includes('127.0.0.1')) {
        return origin;
      }
      if (process.env.CLIENT_URL && !process.env.CLIENT_URL.includes('localhost') && !process.env.CLIENT_URL.includes('127.0.0.1')) {
        return process.env.CLIENT_URL;
      }
      return 'https://equip-rent-client-nine.vercel.app';
    };

    const clientBaseUrl = getClientBaseUrl();

    // Check if Stripe key is mock or real
    if (stripeKey.includes('sk_test_placeholder') || stripeKey.includes('Mock')) {
      // Mock payment redirect URL for development test flow
      return res.send({
        url: `${clientBaseUrl}/checkout/success?session_id=mock_session_${bookingId}&booking_id=${bookingId}`,
        sessionId: `mock_session_${bookingId}`,
        bookingId,
      });
    }

    // Real Stripe Checkout Session
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: `Rental: ${equipmentName}`,
              description: `Rental Period: ${rentalStartDate} to ${rentalEndDate} (${diffDays} days, Qty: ${requiredQuantity})`,
              ...(equipmentImage && equipmentImage.startsWith('http') && !equipmentImage.includes('localhost') ? { images: [equipmentImage] } : {}),
            },
            unit_amount: Math.round(totalAmount * 100), // amount in cents
          },
          quantity: 1,
        },
      ],
      mode: 'payment',
      customer_email: req.user.email,
      metadata: {
        bookingId,
        equipmentId,
        userId: req.user._id.toString(),
        requiredQuantity: String(requiredQuantity),
      },
      success_url: `${clientBaseUrl}/checkout/success?session_id={CHECKOUT_SESSION_ID}&booking_id=${bookingId}`,
      cancel_url: `${clientBaseUrl}/equipment/${equipmentId}?canceled=true`,
    });

    res.send({ url: session.url, sessionId: session.id, bookingId });
  } catch (error) {
    console.error('Checkout error:', error);
    res.status(500).send({ message: 'Failed to initiate checkout', error: error.message });
  }
});

// 2. Verify Stripe Payment & Update Booking + Payment Record
app.post('/api/payments/verify', async (req, res) => {
  try {
    const { sessionId, bookingId } = req.body;

    if (!sessionId || !bookingId) {
      return res.status(400).send({ success: false, message: 'Session ID and Booking ID are required' });
    }

    // Optional user from token if provided
    let authUser = null;
    try {
      const authHeader = req.headers.authorization;
      if (authHeader) {
        const token = authHeader.split(' ')[1];
        if (token) {
          const sessionDoc = await sessions.findOne({ token });
          if (sessionDoc) {
            authUser = await users.findOne({ _id: new ObjectId(sessionDoc.userId) }).catch(() => users.findOne({ _id: sessionDoc.userId }));
          }
        }
      }
    } catch {}

    // Check if already verified
    const existingPayment = await payments.findOne({ sessionId });
    if (existingPayment) {
      const existingBooking = await bookings.findOne({ _id: new ObjectId(bookingId) }).catch(() => bookings.findOne({ _id: bookingId }));
      return res.send({ success: true, message: 'Payment already verified', payment: existingPayment, booking: existingBooking });
    }

    // Update booking document
    let bQuery;
    try {
      bQuery = { _id: new ObjectId(bookingId) };
    } catch {
      bQuery = { _id: bookingId };
    }

    const booking = await bookings.findOne(bQuery);
    if (!booking) {
      return res.status(404).send({ success: false, message: 'Booking record not found' });
    }

    let paymentStatus = 'paid';
    let paymentIntent = 'pi_mock_intent';
    let customerEmail = authUser?.email || booking.customerEmail || 'customer@equiprent.com';

    // If real Stripe session
    if (!sessionId.startsWith('mock_session_')) {
      const retrievedSession = await stripe.checkout.sessions.retrieve(sessionId);
      if (retrievedSession.status !== 'complete' || retrievedSession.payment_status !== 'paid') {
        return res.status(400).send({ success: false, message: 'Payment verification failed at Stripe' });
      }
      paymentStatus = retrievedSession.payment_status;
      paymentIntent = retrievedSession.payment_intent;
      customerEmail = retrievedSession.customer_email || booking.customerEmail || authUser?.email || 'customer@equiprent.com';
    }

    const updateBookingResult = await bookings.updateOne(bQuery, {
      $set: {
        paymentStatus: 'paid',
        bookingStatus: 'confirmed',
        paidAt: new Date(),
        updatedAt: new Date(),
      },
    });

    // Reduce available quantity on equipment
    try {
      let eqQuery = { _id: new ObjectId(booking.equipmentId) };
      await equipments.updateOne(eqQuery, {
        $inc: { availableQuantity: -Number(booking.requiredQuantity) }
      });
    } catch (e) {
      console.warn('Could not decrement equipment quantity:', e.message);
    }

    // Insert Payment record
    const paymentRecord = {
      sessionId,
      bookingId,
      equipmentId: booking.equipmentId,
      equipmentName: booking.equipmentName,
      customerId: authUser?._id?.toString() || booking.customerId,
      customerEmail,
      amount: booking.totalAmount,
      paymentStatus,
      paymentIntent,
      paymentDate: new Date(),
    };

    const paymentResult = await payments.insertOne(paymentRecord);
    const updatedBooking = await bookings.findOne(bQuery);

    res.send({
      success: true,
      message: 'Payment verified and booking confirmed successfully',
      bookingId,
      booking: updatedBooking || { ...booking, paymentStatus: 'paid', bookingStatus: 'confirmed' },
      paymentId: paymentResult.insertedId,
    });
  } catch (error) {
    console.error('Payment verify error:', error);
    res.status(500).send({ success: false, message: 'Payment verification failed', error: error.message });
  }
});

// 3. Customer: My Rentals
app.get('/api/customer/my-rentals', verifyToken, async (req, res) => {
  try {
    const customerId = req.user._id.toString();
    const customerEmail = req.user.email;
    const query = {
      $or: [
        { customerId },
        { customerEmail },
      ]
    };
    try {
      query.$or.push({ customerId: new ObjectId(customerId) });
    } catch {}

    const result = await bookings.find(query).sort({ bookingDate: -1, createdAt: -1 }).toArray();

    const normalized = result.map(b => ({
      ...b,
      startDate: b.rentalStartDate || b.startDate,
      endDate: b.rentalEndDate || b.endDate,
      quantity: b.requiredQuantity || b.quantity || 1,
    }));

    res.send({ rentals: normalized, items: normalized });
  } catch (error) {
    console.error('Failed to fetch rentals:', error);
    res.status(500).send({ message: 'Failed to fetch rentals', error: error.message });
  }
});

// 4. Owner: My Equipment Rentals (rentals of items owned by this owner)
app.get('/api/owner/my-rentals', verifyToken, verifyOwner, async (req, res) => {
  try {
    const ownerId = req.user._id.toString();
    const ownerEmail = req.user.email;
    const query = {
      $or: [
        { ownerId },
        { ownerEmail },
      ]
    };
    try {
      query.$or.push({ ownerId: new ObjectId(ownerId) });
    } catch {}

    const result = await bookings.find(query).sort({ bookingDate: -1, createdAt: -1 }).toArray();

    const normalized = result.map(b => ({
      ...b,
      startDate: b.rentalStartDate || b.startDate,
      endDate: b.rentalEndDate || b.endDate,
      quantity: b.requiredQuantity || b.quantity || 1,
    }));

    res.send({ rentals: normalized, items: normalized });
  } catch (error) {
    console.error('Failed to fetch owner equipment rentals:', error);
    res.status(500).send({ message: 'Failed to fetch owner equipment rentals', error: error.message });
  }
});

// 5. Admin: All Rentals
app.get('/api/admin/all-rentals', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await bookings.find({}).sort({ bookingDate: -1, createdAt: -1 }).toArray();

    const normalized = result.map(b => ({
      ...b,
      startDate: b.rentalStartDate || b.startDate,
      endDate: b.rentalEndDate || b.endDate,
      quantity: b.requiredQuantity || b.quantity || 1,
    }));

    res.send({ rentals: normalized, items: normalized });
  } catch (error) {
    console.error('Failed to fetch all rentals:', error);
    res.status(500).send({ message: 'Failed to fetch all rentals', error: error.message });
  }
});

/* =========================================================
   USER & PROFILE MANAGEMENT APIS
========================================================= */

// 1. Admin: All Users
app.get('/api/admin/users', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const result = await users.find({}).sort({ createdAt: -1 }).toArray();
    res.send({ users: result, items: result });
  } catch (error) {
    res.status(500).send({ message: 'Failed to fetch users', error: error.message });
  }
});

// 2. Admin: Update User Role (Customer, Owner, Admin)
const updateUserRole = async (req, res) => {
  try {
    const id = req.params.id;
    const { role } = req.body;
    if (!['customer', 'owner', 'admin'].includes(role)) {
      return res.status(400).send({ message: 'Invalid role' });
    }

    let query;
    try {
      query = { _id: new ObjectId(id) };
    } catch {
      query = { _id: id };
    }

    const result = await users.updateOne(query, {
      $set: { role, updatedAt: new Date() }
    });
    res.send({ success: true, message: `User role updated to ${role}`, result });
  } catch (error) {
    res.status(500).send({ message: 'Failed to update user role', error: error.message });
  }
};

app.put('/api/admin/users/:id/role', verifyToken, verifyAdmin, updateUserRole);
app.patch('/api/admin/users/:id/role', verifyToken, verifyAdmin, updateUserRole);

// 3. User Profile Update (Name, Image, Phone, Address)
app.patch('/api/user/profile', verifyToken, async (req, res) => {
  try {
    const { name, image, phone, address } = req.body;
    const query = { _id: req.user._id };

    const updateDoc = {
      $set: {
        ...(name && { name }),
        ...(image && { image }),
        ...(phone && { phone }),
        ...(address && { address }),
        updatedAt: new Date(),
      }
    };

    const result = await users.updateOne(query, updateDoc);
    res.send({ success: true, result });
  } catch (error) {
    res.status(500).send({ message: 'Failed to update profile', error: error.message });
  }
});

/* =========================================================
   DASHBOARD ANALYTICS APIS (Challenge 3)
========================================================= */

// Admin Analytics: Total Users, Equipments, Bookings, Revenue, Pending approvals, Monthly stats
app.get('/api/admin/analytics', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const totalUsers = await users.countDocuments();
    const totalEquipments = await equipments.countDocuments();
    const pendingEquipments = await equipments.countDocuments({ status: 'pending' });
    const approvedEquipments = await equipments.countDocuments({ status: 'approved' });
    const totalBookings = await bookings.countDocuments();
    const paidBookings = await bookings.countDocuments({ paymentStatus: 'paid' });

    // Revenue calculation
    const revenuePipeline = [
      { $match: { paymentStatus: 'paid' } },
      { $group: { _id: null, totalRevenue: { $sum: '$totalAmount' } } }
    ];
    const revenueResult = await bookings.aggregate(revenuePipeline).toArray();
    const totalRevenue = revenueResult[0]?.totalRevenue || 0;

    // Monthly bookings analytics (last 6 months)
    const monthlyStats = await bookings.aggregate([
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
          count: { $sum: 1 },
          revenue: { $sum: { $cond: [{ $eq: ["$paymentStatus", "paid"] }, "$totalAmount", 0] } }
        }
      },
      { $sort: { _id: 1 } },
      { $limit: 6 }
    ]).toArray();

    // Role distribution
    const roleStats = await users.aggregate([
      { $group: { _id: '$role', count: { $sum: 1 } } }
    ]).toArray();
    const roleDistribution = roleStats.map(r => ({ name: r._id || 'user', value: r.count }));

    const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const monthlyData = monthlyStats.map(m => {
      const parts = m._id ? m._id.split('-') : [];
      const mIdx = parts[1] ? parseInt(parts[1], 10) - 1 : 0;
      return {
        month: monthNames[mIdx] || m._id,
        revenue: m.revenue,
        bookings: m.count,
      };
    });

    const adminPayload = {
      totalUsers,
      totalEquipments,
      pendingEquipments,
      approvedEquipments,
      totalBookings,
      completedRentals: paidBookings,
      totalRevenue,
      monthlyStats,
      monthlyData,
      roleDistribution,
    };

    res.send({
      ...adminPayload,
      analytics: adminPayload,
    });
  } catch (error) {
    console.error('Failed to fetch admin analytics:', error);
    res.status(500).send({ message: 'Failed to fetch admin analytics', error: error.message });
  }
});

// Owner Analytics: Total Listed, Completed Rentals, Total Earnings, Monthly Earnings
app.get('/api/owner/analytics', verifyToken, verifyOwner, async (req, res) => {
  try {
    const ownerId = req.user._id.toString();
    const ownerEmail = req.user.email;
    const ownerMatch = {
      $or: [
        { ownerId },
        { ownerEmail },
      ]
    };
    try {
      ownerMatch.$or.push({ ownerId: new ObjectId(ownerId) });
    } catch {}

    const totalListed = await equipments.countDocuments(ownerMatch);
    const pendingListed = await equipments.countDocuments({ ...ownerMatch, status: 'pending' });
    const totalOwnerBookings = await bookings.countDocuments(ownerMatch);
    const completedRentals = await bookings.countDocuments({ ...ownerMatch, paymentStatus: 'paid' });

    // Owner Earnings
    const earningsPipeline = [
      { $match: { ...ownerMatch, paymentStatus: 'paid' } },
      { $group: { _id: null, totalEarnings: { $sum: '$totalAmount' } } }
    ];
    const earningsResult = await bookings.aggregate(earningsPipeline).toArray();
    const totalRevenue = earningsResult[0]?.totalEarnings || 0;

    // Monthly earnings
    const monthlyEarningsRaw = await bookings.aggregate([
      { $match: { ...ownerMatch, paymentStatus: 'paid' } },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m", date: { $ifNull: ["$paidAt", "$createdAt"] } } },
          revenue: { $sum: "$totalAmount" },
          bookings: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } },
      { $limit: 6 }
    ]).toArray();

    const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const monthlyData = monthlyEarningsRaw.map(m => {
      const parts = m._id ? m._id.split('-') : [];
      const mIdx = parts[1] ? parseInt(parts[1], 10) - 1 : 0;
      return {
        month: monthNames[mIdx] || m._id,
        revenue: m.revenue,
        bookings: m.bookings,
      };
    });

    // Category distribution
    const catPipeline = [
      { $match: ownerMatch },
      { $group: { _id: '$category', count: { $sum: 1 } } }
    ];
    const catResult = await equipments.aggregate(catPipeline).toArray();
    const categoryDistribution = catResult.map(c => ({ name: c._id || 'Equipment', value: c.count }));

    const analyticsPayload = {
      totalRevenue,
      totalEarnings: totalRevenue,
      totalListings: totalListed,
      totalListed,
      completedRentals,
      totalBookings: totalOwnerBookings,
      totalOwnerBookings,
      pendingListed,
      monthlyData,
      monthlyEarnings: monthlyEarningsRaw,
      categoryDistribution,
    };

    res.send({
      ...analyticsPayload,
      analytics: analyticsPayload,
    });
  } catch (error) {
    console.error('Failed to fetch owner analytics:', error);
    res.status(500).send({ message: 'Failed to fetch owner analytics', error: error.message });
  }
});

// Start Server
app.listen(port, () => {
  console.log(`EquipRent Backend Server running on port ${port}`);
});

export default app;
