const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

/* ==========================================================================
   1. CONFIGURACIÓN FIREBASE (La misma de tu web, sin Service Accounts)
   ========================================================================== */
const FIREBASE_API_KEY = "AIzaSyDoIGXJQ2NEgeUXCDHLSFc7YDA6EtDYUSg";
const DATABASE_URL = "https://socios666-7056e-default-rtdb.firebaseio.com";

// Esta llave la configuras en Railway (pestaña Variables). Si no la pones, usa esta por defecto.
const XIT_API_KEY = process.env.XIT_API_KEY || "clave_super_secreta_sebasxit";

/* ==========================================================================
   2. EL GUARDIÁN (Middleware sin Admin SDK)
   ========================================================================== */
async function guardianXit(req, res, next) {
    const clientApiKey = req.headers['x-xit-api-key'];
    const authHeader = req.headers['authorization'];

    // FILTRO 1: Llave del servidor
    if (clientApiKey !== XIT_API_KEY) {
        console.log(`[🔴 BLOQUEO] Intento sin API KEY desde IP: ${req.ip}`);
        return res.status(403).json({ error: "SISTEMA XIT: Acceso denegado." });
    }

    // FILTRO 2: Presencia del Token de sesión de la Web
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: "SISTEMA XIT: Falta token de sesión." });
    }

    const idToken = authHeader.split('Bearer ')[1];

    try {
        // FILTRO 3: Validar el token con Google REST API (Evita usar el ServiceAccount.json)
        const verifyRes = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_API_KEY}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ idToken: idToken })
        });
        
        const verifyData = await verifyRes.json();
        if (verifyData.error) {
            return res.status(401).json({ error: "SISTEMA XIT: Token inválido o manipulado." });
        }

        const uid = verifyData.users[0].localId;

        // FILTRO 4: Revisar en la base de datos si este UID es de "sebasxit"
        // Le pasamos el auth=${idToken} a la URL para que Firebase nos deje leer si hay reglas de seguridad
        const dbRes = await fetch(`${DATABASE_URL}/users/${uid}.json?auth=${idToken}`);
        const userData = await dbRes.json();

        if (!userData || !userData.username || userData.username.toLowerCase() !== 'sebasxit') {
            console.log(`[🚨 ALERTA INTRUSO] UID: ${uid} intentó acceder al panel.`);
            return res.status(403).json({ error: "GUARDIÁN: Permisos insuficientes. Solo el Administrador." });
        }

        // SI LLEGA AQUÍ: Es SebasXit 100% real no fake.
        req.adminUser = userData;
        req.idToken = idToken; // Guardamos su token por si el server necesita modificar la BD en su nombre
        next();

    } catch (error) {
        console.error("Error en Guardián:", error);
        return res.status(500).json({ error: "SISTEMA XIT: Error interno del servidor." });
    }
}

/* ==========================================================================
   3. RUTAS DEL SERVIDOR
   ========================================================================== */

// Ruta Pública (Para saber si el server está vivo)
app.get('/api/ping', (req, res) => {
    res.json({ status: "ONLINE", message: "Servidor XIT melo y corriendo." });
});

// Ruta Protegida: Ejemplo de agregar un nuevo producto
app.post('/api/admin/nuevo-producto', guardianXit, async (req, res) => {
    // Como pasó el Guardián, estamos seguros que es SebasXit.
    const { idProducto, datosProducto } = req.body;
    
    try {
        // Usamos el token de SebasXit (req.idToken) para escribir en la BD mediante REST API
        const patchRes = await fetch(`${DATABASE_URL}/productos/${idProducto}.json?auth=${req.idToken}`, {
            method: 'PATCH', // PATCH actualiza o crea
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(datosProducto)
        });

        const patchData = await patchRes.json();

        res.json({ 
            success: true, 
            message: "Producto subido con éxito a la base de datos",
            data: patchData
        });

    } catch (error) {
        res.status(500).json({ error: "Error escribiendo en Firebase" });
    }
});

/* ==========================================================================
   4. INICIO DEL SERVIDOR
   ========================================================================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.clear();
    console.log(`
  ██╗  ██╗██╗████████╗
  ╚██╗██╔╝██║╚══██╔══╝
   ╚███╔╝ ██║   ██║   
   ██╔██╗ ██║   ██║   
  ██╔╝ ██╗██║   ██║   
  ╚═╝  ╚═╝╚═╝   ╚═╝   
  ==========================================
  🛡️ GUARDIÁN ONLINE SIN SERVICE ACCOUNT
  ==========================================
  PORT: ${PORT}
  ==========================================
    `);
});

