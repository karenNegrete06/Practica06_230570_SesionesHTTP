// Propósito: Conectar a la base de datos de MongoDB
import mongoose from 'mongoose';

const connectDB = async () => {
    try {
        await mongoose.connect('mongodb+srv://KarenNegrete:06karenlizbeth@cluster230570.977pc.mongodb.net/practica06_control_db?retryWrites=true&w=majority&appName=Cluster230570');
        console.log('Conexión a MongoDB establecida');
    } catch (error) {
        console.error('Error al conectar a MongoDB:', error);
    }
};

export default connectDB;