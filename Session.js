import mongoose from 'mongoose';

const sessionSchema = new mongoose.Schema({
    sessionId: { type: String, required: true, unique: true },
    email: { type: String, required: true },
    nickname: { type: String, required: true },
    status: {
        type: String,
        enum: [
          'Activa',
          'Inactiva',
          'Finalizada por el Usuario',
          'Finalizada por falla de Sistema',
          'Finalizada por inactividad'  // Agregar este estado
        ],
        required: true
    },
    clientIp: { type: String },  // Ahora en la raíz del esquema
    clientMac: { type: String }, // Ahora en la raíz del esquema
    serverIp: { type: String },  // Ahora en la raíz del esquema
    serverMac: { type: String }, // Ahora en la raíz del esquema
    createdAt: { type: Date, default: Date.now },
    lastAccessed: { type: Date, default: Date.now }
});

const Session = mongoose.model('Session', sessionSchema);
export default Session;
