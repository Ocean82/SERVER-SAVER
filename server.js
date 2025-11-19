require("dotenv").config();
const express = require("express");
const cors = require("cors");
const {
    spawn
} = require("child_process");
const path = require("path");
const fs = require("fs");
// Security Middleware
const { rateLimiters, validateInput, securityHeaders, getCorsConfig, safeQuery, csrfProtection, getCsrfToken } = require('./security-middleware');
const csrfRoutes = require('./csrf-routes');
const session = require("express-session");

const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const {
    createClerkClient,
    verifyToken
} = require("@clerk/backend");

// Initialize Clerk with secret key
const clerk = createClerkClient({
    secretKey: process.env.CLERK_SECRET_KEY,
});
const {
    Pool
} = require("pg");

// Database connection pool with timeouts
// Handle RDS SSL configuration properly
// Remove sslmode=require from URL (it conflicts with rejectUnauthorized: false)
const dbUrl = process.env.DATABASE_URL ?
    process.env.DATABASE_URL.replace("?sslmode=require", "").replace(
        "&sslmode=require",
        ""
    ) :
    process.env.DATABASE_URL;

const pool = new Pool({
    connectionString: dbUrl,
    max: 20, // Maximum pool size
    idleTimeoutMillis: 30000, // Close idle clients after 30 seconds
    connectionTimeoutMillis: 10000, // Return error after 10 seconds if no connection
    ssl: {
        rejectUnauthorized: false, // Always accept RDS self-signed certs (required for AWS RDS)
    },
});

const app = express();
const PORT = 8000;
// CORS Configuration

app.use(cors({
    ...getCorsConfig(),
    credentials: true
}));
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
 resave: false,
 saveUninitialized: false,
 cookie: {
 secure: process.env.NODE_ENV === "production",
 httpOnly: true,
 maxAge: 24 * 60 * 60 * 1000 // 24 hours
 },
}));
// Security Headers
app.use(securityHeaders);

// Input Validation
app.use(validateInput);


// Security: Trust proxy for production (behind nginx/load balancer)
app.set("trust proxy", 1);

// Body parsing with limits
app.use(
    express.json({
        limit: "50mb",
    })
);
app.use(
    express.urlencoded({
        extended: true,
        limit: "50mb",
    })
);

// Request logging middleware
app.use((req, res, next) => {
    const start = Date.now();
    res.on("finish", () => {
        const duration = Date.now() - start;
        console.log(
            `${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`
        );
    });
    next();
});


// Rate Limiting
app.use('/api', rateLimiters.api);
// Health check endpoint (before other routes, no auth needed)
app.get("/health", (req, res) => {
    res.json({
        status: "healthy",
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        service: "BurntBeats MVP",
 });
});

app.post("/api/debug-token", rateLimiters.auth, (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader ? authHeader.replace("Bearer ", "") : "";

    res.json({
        hasAuthHeader: !!authHeader,
        authHeaderPrefix: authHeader ? authHeader.substring(0, 20) + "..." : "NONE",
        tokenPrefix: token ? token.substring(0, 30) + "..." : "NONE",
        tokenLength: token ? token.length : 0,
        headers: {
            host: req.headers.host,
            origin: req.headers.origin,
            referer: req.headers.referer,
        },
    });
});

// Simple auth middleware
const requireAuth = async (req, res, next) => {
    // LOCALHOST BYPASS: Skip Clerk auth entirely on localhost
    const isLocalhost =
        req.hostname === "localhost" ||
        req.hostname === "127.0.0.1" ||
        (req.headers.host && req.headers.host.includes("localhost"));
    if (isLocalhost) {
        req.auth = {
            userId: "localhost-test-user",
        };
        return next();
    }

    const token = req.headers.authorization ?
        req.headers.authorization.replace("Bearer ", "") :
        "";

    console.log(" Auth Check:", {
        path: req.path,
        hasAuth: !!req.headers.authorization,
        tokenPrefix: token ? token.substring(0, 20) + "..." : "NO TOKEN",
    });

    if (!token) {
        console.log(" No token provided");
        return res.status(401).json({
            error: "Unauthorized - No token provided",
        });
    }

    // TEST MODE: Allow bypass for local testing
    if (token === "test-mode") {
        req.auth = {
            userId: "test-user-123",
        };
        next();
        return;
    }

    try {
        // Use the standalone verifyToken function from @clerk/backend
        const payload = await verifyToken(token, {
            secretKey: process.env.CLERK_SECRET_KEY,
        });

        console.log(" Token verified for user:", payload.sub);
        req.auth = {
            userId: payload.sub,
        };
        next();
    } catch (err) {
        console.log(" Token verification failed:", err.message);
        res.status(401).json({
            error: "Invalid token: " + err.message,
        });
    }
};

// Initialize database with payment tracking
pool
    .query(
        `
  CREATE TABLE IF NOT EXISTS songs (
    id SERIAL PRIMARY KEY,
    song_id VARCHAR(255) UNIQUE NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    prompt TEXT,
    file_path TEXT NOT NULL,
    size_mb DECIMAL(10,2),
    paid BOOLEAN DEFAULT FALSE,
    stripe_session_id VARCHAR(255),
    payment_date TIMESTAMP,
    package_type VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW()
  )
`
    )
    .catch(console.error);

// Serve landing page at root
app.get("/", (req, res) => {
    res.setHeader("Cache-Control", "no-cache");
    res.sendFile(path.join(__dirname, "public", "landing.html"));
});

// Serve app at /app
app.get("/app", (req, res) => {
    res.setHeader("Cache-Control", "no-cache");
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use(express.static("public"));

// Serve song files from /songs directory with proper headers
app.use(
    "/songs",
    express.static(path.join(__dirname, "songs"), {
        setHeaders: (res, filePath) => {
            if (
                filePath.endsWith(".wav") ||
                filePath.endsWith(".mp3") ||
                filePath.endsWith(".flac")
            ) {
                res.setHeader("Content-Type", "audio/wav");
                res.setHeader("Accept-Ranges", "bytes");
                res.setHeader("Cache-Control", "public, max-age=31536000"); // Cache for 1 year
                res.setHeader("Access-Control-Allow-Origin", "*"); // Allow audio to be played from any origin
            }
        },
    })
);

const PACKAGES = {
    superbasic: {
        name: "Super Basic",
        priceId: "price_1S2E57P38C54URjEtKKG2NCd",
        price: 0.99,
        minMB: 0.1,
        maxMB: 3.9,
        quality: "mp3-192",
    },
    basic: {
        name: "Basic Song",
        priceId: "price_1RdtMaP38C54URjEOv5LJOwF",
        price: 1.99,
        minMB: 4,
        maxMB: 8.9,
        quality: "mp3-192",
    },
    premium: {
        name: "Premium Song",
        priceId: "price_1RdtMcP38C54URjEAw1Wkaz8",
        price: 4.99,
        minMB: 9,
        maxMB: 19.9,
        quality: "wav",
    },
    ultra: {
        name: "Ultra Super Great Amazing Song",
        priceId: "price_1Rdu4mP38C54URjExR5Jbr60",
        price: 8.99,
        minMB: 20.1,
        maxMB: 80,
        quality: "flac",
    },
};

// Get packages
app.get("/api/packages", (req, res) => {
    try {
        res.setHeader("Cache-Control", "public, max-age=3600"); // Cache for 1 hour
        res.json(PACKAGES);
    } catch (err) {
        console.error("Error sending packages:", err);
        res.status(500).json({
            error: "Failed to retrieve packages",
        });
    }
});

// Create checkout session with fixed price (new length-based pricing)
app.post("/api/create-checkout-fixed", csrfProtection, requireAuth, async (req, res) => {
    const {
        songId,
        lengthTier,
        packageType
    } = req.body;

    if (!packageType) {
        return res.status(400).json({
            error: "Package type required",
        });
    }

    const pkg = PACKAGES[packageType];
    if (!pkg) {
        return res.status(400).json({
            error: "Invalid package type",
        });
    }

    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ["card"],
            line_items: [{
                price: pkg.priceId,
                quantity: 1,
            }, ],
            mode: "payment",
            success_url: `${
        req.headers.origin || "http://localhost:8000"
      }/app?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${req.headers.origin || "http://localhost:8000"}/app`,
            metadata: {
                packageType,
                songId,
                lengthTier: lengthTier || "custom",
            },
        });

        res.json({
            url: session.url,
        });
    } catch (err) {
        res.status(500).json({
            error: err.message,
        });
    }
});

// Legacy: Create checkout session based on song size (for backward compatibility)
app.post("/api/create-checkout", async (req, res) => {
    const {
        songId,
        sizeMB
    } = req.body;

    // Determine package based on file size
    let packageType = "superbasic";
    for (const [key, pkg] of Object.entries(PACKAGES)) {
        if (sizeMB >= pkg.minMB && sizeMB <= pkg.maxMB) {
            packageType = key;
            break;
        }
    }

    const pkg = PACKAGES[packageType];

    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ["card"],
            line_items: [{
                price: pkg.priceId,
                quantity: 1,
            }, ],
            mode: "payment",
            success_url: `${
        req.headers.origin || "http://localhost:8000"
      }/app?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${req.headers.origin || "http://localhost:8000"}/app`,
            metadata: {
                packageType,
                songId,
                sizeMB: sizeMB.toString(),
            },
        });

        res.json({
            url: session.url,
        });
    } catch (err) {
        res.status(500).json({
            error: err.message,
        });
    }
});

// Generate song endpoint (requires auth)
app.post("/api/generate", csrfProtection, rateLimiters.aiGeneration, requireAuth, async (req, res) => {
    const userId = req.auth.userId;
    const {
        prompt,
        lyrics,
        inputMode,
        voiceId,
        lengthTier,
        targetSeconds,
        packageType,
        genre,
        mood,
        tempo,
    } = req.body;

    if (!prompt && !lyrics) {
        return res.status(400).json({
            error: "Prompt or lyrics required",
        });
    }

    const songId = Date.now().toString();
    const outputPath = path.join(__dirname, "songs", `${songId}.wav`);

    if (!fs.existsSync(path.join(__dirname, "songs"))) {
        fs.mkdirSync(path.join(__dirname, "songs"));
    }

    const mode = inputMode || "description";
    const displayText = mode === "lyrics" ? "Custom lyrics" : prompt;
    console.log(
        `Generating song: ${displayText} (${targetSeconds}s, tier: ${
      lengthTier || "auto"
    }, mode: ${mode})`
    );

    // Use local Python for development, venv python for production
    const pythonPath =
        process.platform === "win32" ?
        "python" // Windows
        :
        path.join(__dirname, "ai-venv", "bin", "python3"); // Linux/Production - use venv python with AI packages

    //  QUALITY FIRST! Use REAL PROFESSIONAL AUDIO!
    // generate-complete-fixed.py → GTZAN professional samples → REAL instruments!
    // Users are PAYING - they deserve REAL AUDIO!
    const generatorScript =
        process.platform === "win32" ?
        path.join(__dirname, "generate-local.py") // Local dev version
        :
        path.join(__dirname, "generate-with-professional-audio.py"); // PROFESSIONAL + MASTERING!

    // Pass parameters to Python script
    // generate-complete.py expects: <prompt> <output_path> [voice_id] [target_seconds] [--lyrics-mode] [custom_lyrics]

    console.log(` Generation: "${prompt}" (${targetSeconds}s, mode: ${mode})`);

    const scriptArgs = [
        generatorScript,
        prompt || lyrics || "Custom song",
        outputPath,
        voiceId || "default-voice",
        targetSeconds ? targetSeconds.toString() : "60",
    ];

    // Add lyrics mode if user provided custom lyrics
    if (mode === "lyrics" && lyrics) {
        scriptArgs.push("--lyrics-mode");
        scriptArgs.push(lyrics);
    }

    // Add target seconds if provided
    if (targetSeconds) {
        scriptArgs.push(targetSeconds.toString());
    }

    // Add lyrics mode flag and lyrics if in lyrics mode
    if (mode === "lyrics" && lyrics) {
        scriptArgs.push("--lyrics-mode");
        scriptArgs.push(lyrics);
    }

    const python = spawn(pythonPath, scriptArgs);

    let output = "";
    let error = "";

    python.stdout.on("data", (data) => {
        output += data.toString();
        console.log(data.toString());
    });

    python.stderr.on("data", (data) => {
        error += data.toString();
        console.error(data.toString());
    });

    python.on("close", async (code) => {
        if (code === 0 && fs.existsSync(outputPath)) {
            try {
                const stats = fs.statSync(outputPath);
                const sizeMB = stats.size / (1024 * 1024);

                // Save to database with package type if provided
                await safeQuery(pool,
                    "INSERT INTO songs (song_id, user_id, prompt, file_path, size_mb, package_type) VALUES ($1, $2, $3, $4, $5, $6)",
                    [songId, userId, prompt, outputPath, sizeMB, packageType || null]
                );

                console.log(
                    `Song saved: ${songId} (${sizeMB.toFixed(2)}MB, ${
            packageType || "auto"
          })`
                );

                res.json({
                    success: true,
                    songId,
                    url: `/songs/${songId}.wav`,
                    sizeMB: sizeMB.toFixed(2),
                    lengthTier: lengthTier,
                    packageType: packageType,
                });
            } catch (dbError) {
                console.error("Database save error:", dbError);
                // Still return success if file exists, even if DB save fails
                const stats = fs.statSync(outputPath);
                const sizeMB = stats.size / (1024 * 1024);
                res.json({
                    success: true,
                    songId,
                    url: `/songs/${songId}.wav`,
                    sizeMB: sizeMB.toFixed(2),
                    lengthTier: lengthTier,
                    packageType: packageType,
                    warning: "Song created but not saved to database",
                });
            }
        } else {
            console.error(`Generation failed. Exit code: ${code}`);
            console.error("Error output:", error);
            console.error("Standard output:", output);
            res.status(500).json({
                error: "Generation failed",
                details: error || output || "Unknown error",
            });
        }
    });

    // Handle Python process errors
    python.on("error", (err) => {
        console.error("Failed to start Python process:", err);
        res.status(500).json({
            error: "Failed to start generation process",
            details: err.message,
        });
    });
});

app.get("/api/songs", requireAuth, async (req, res) => {
    const userId = req.auth.userId;
    try {
        const result = await safeQuery(pool,
            "SELECT song_id, prompt, size_mb, paid, package_type, created_at FROM songs WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100",
            [userId]
        );

        const songs = result.rows.map((row) => {
            // Determine package and price based on size
            let packageType = "superbasic";
            let price = 0.99;

            for (const [key, pkg] of Object.entries(PACKAGES)) {
                if (row.size_mb >= pkg.minMB && row.size_mb <= pkg.maxMB) {
                    packageType = key;
                    price = pkg.price;
                    break;
                }
            }

            return {
                id: row.song_id,
                prompt: row.prompt,
                url: `/songs/${row.song_id}.wav`,
                sizeMB: parseFloat(row.size_mb),
                paid: row.paid || false,
                packageType: row.package_type || packageType,
                price: price,
                created: row.created_at,
            };
        });

        res.json(songs);
    } catch (err) {
        console.error("Database error:", err);
        res.status(500).json({
            error: "Failed to load songs",
            details: err.message,
        });
    }
});

// Protected download endpoint - requires payment
app.get("/api/download/:songId", requireAuth, async (req, res) => {
    const userId = req.auth.userId;
    const {
        songId
    } = req.params;

    try {
        // Check if song exists and belongs to user
        const result = await safeQuery(pool,
            "SELECT song_id, file_path, size_mb, paid, user_id FROM songs WHERE song_id = $1",
            [songId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                error: "Song not found",
            });
        }

        const song = result.rows[0];

        // Verify ownership
        if (song.user_id !== userId) {
            return res.status(403).json({
                error: "Not authorized to download this song",
            });
        }

        // Check if paid
        if (song.paid) {
            // Already paid - allow download
            const filePath = song.file_path;

            if (fs.existsSync(filePath)) {
                res.setHeader(
                    "Content-Disposition",
                    `attachment; filename="burntbeats-${songId}.wav"`
                );
                res.setHeader("Content-Type", "audio/wav");
                res.download(filePath);
            } else {
                res.status(404).json({
                    error: "Song file not found",
                });
            }
        } else {
            // Not paid - return payment required
            const sizeMB = parseFloat(song.size_mb);

            // Determine package based on size
            let packageType = "superbasic";
            let price = 0.99;

            for (const [key, pkg] of Object.entries(PACKAGES)) {
                if (sizeMB >= pkg.minMB && sizeMB <= pkg.maxMB) {
                    packageType = key;
                    price = pkg.price;
                    break;
                }
            }

            res.status(402).json({
                error: "Payment required",
                songId: songId,
                sizeMB: sizeMB,
                packageType: packageType,
                price: price,
                requiresPayment: true,
            });
        }
    } catch (err) {
        console.error("Download error:", err);
        res.status(500).json({
            error: "Download failed",
            details: err.message,
        });
    }
});

// Create checkout for specific song download
app.post("/api/checkout-for-download", csrfProtection, requireAuth, async (req, res) => {
    const userId = req.auth.userId;
    const {
        songId
    } = req.body;

    try {
        // Get song details
        const result = await safeQuery(pool,
            "SELECT song_id, size_mb, prompt, paid FROM songs WHERE song_id = $1 AND user_id = $2",
            [songId, userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                error: "Song not found",
            });
        }

        const song = result.rows[0];

        // Check if already paid
        if (song.paid) {
            return res.json({
                alreadyPaid: true,
            });
        }

        const sizeMB = parseFloat(song.size_mb);

        // Determine package based on file size
        let packageType = "superbasic";
        for (const [key, pkg] of Object.entries(PACKAGES)) {
            if (sizeMB >= pkg.minMB && sizeMB <= pkg.maxMB) {
                packageType = key;
                break;
            }
        }

        const pkg = PACKAGES[packageType];

        // Create Stripe checkout session
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ["card"],
            line_items: [{
                price: pkg.priceId,
                quantity: 1,
            }, ],
            mode: "payment",
            success_url: `${
        req.headers.origin || "http://localhost:8000"
      }/app?session_id={CHECKOUT_SESSION_ID}&download=${songId}`,
            cancel_url: `${req.headers.origin || "http://localhost:8000"}/app`,
            metadata: {
                packageType,
                songId,
                sizeMB: sizeMB.toString(),
                userId: userId,
            },
        });

        // Save session ID to track payment
        await safeQuery(pool,
            "UPDATE songs SET stripe_session_id = $1, package_type = $2 WHERE song_id = $3",
            [session.id, packageType, songId]
        );

        res.json({
            url: session.url,
            sessionId: session.id,
        });
    } catch (err) {
        console.error("Checkout error:", err);
        res.status(500).json({
            error: err.message,
        });
    }
});

// Webhook endpoint - bypasses CSRF (Stripe signature verification used instead)
app.post("/api/webhook/stripe",
    express.raw({
        type: "application/json",
    }),
    async (req, res) => {
        const sig = req.headers["stripe-signature"];

        try {
            // Verify webhook signature (if webhook secret is set)
            let event;
            if (process.env.STRIPE_WEBHOOK_SECRET) {
                event = stripe.webhooks.constructEvent(
                    req.body,
                    sig,
                    process.env.STRIPE_WEBHOOK_SECRET
                );
            } else {
                // For testing without webhook secret
                event = JSON.parse(req.body.toString());
            }

            // Handle checkout.session.completed event
            if (event.type === "checkout.session.completed") {
                const session = event.data.object;
                const songId = session.metadata.songId;

                if (songId) {
                    // Mark song as paid
                    await safeQuery(pool,
                        "UPDATE songs SET paid = TRUE, payment_date = NOW(), stripe_session_id = $1 WHERE song_id = $2",
                        [session.id, songId]
                    );

                    console.log(`Song ${songId} marked as paid`);
                }
            }

            res.json({
                received: true,
            });
        } catch (err) {
            console.error("Webhook error:", err);
            res.status(400).json({
                error: err.message,
            });
        }
    }
);

// Logout endpoint with CSRF protection
app.post("/api/auth/logout", csrfProtection, async (req, res) => {
  try {
    // Clear session even if not authenticated (allows clearing stale sessions)
    // Clear session
    if (req.session) {
      req.session.destroy((err) => {
        if (err) {
          console.error("Session destroy error:", err);
        }
      });
    }
    
    // Clear cookies
    res.clearCookie("burntbeatz_session");
    res.clearCookie("session");
    res.clearCookie("connect.sid");
    
    res.json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ error: "Logout failed" });
  }
});

app.post("/api/verify-payment", requireAuth, async (req, res) => {
    const {
        sessionId,
        songId
    } = req.body;
    const userId = req.auth.userId;

    try {
        // Verify with Stripe
        const session = await stripe.checkout.sessions.retrieve(sessionId);

        if (session.payment_status === "paid") {
            // Get songId from session metadata if not provided
            const metadataSongId =
                songId || (session.metadata && session.metadata.songId);

            if (metadataSongId) {
                // Verify the song belongs to the user
                const songCheck = await safeQuery(pool,
                    "SELECT song_id, paid FROM songs WHERE song_id = $1 AND user_id = $2",
                    [metadataSongId, userId]
                );

                if (songCheck.rows.length > 0 && !songCheck.rows[0].paid) {
                    // Mark song as paid
                    await safeQuery(pool,
                        "UPDATE songs SET paid = TRUE, payment_date = NOW(), stripe_session_id = $1 WHERE song_id = $2 AND user_id = $3",
                        [sessionId, metadataSongId, userId]
                    );

                    console.log(`Song ${metadataSongId} marked as paid via verification`);
                    res.json({
                        success: true,
                        paid: true,
                        songId: metadataSongId,
                    });
                } else if (songCheck.rows.length > 0 && songCheck.rows[0].paid) {
                    // Already paid
                    res.json({
                        success: true,
                        paid: true,
                        songId: metadataSongId,
                        alreadyPaid: true,
                    });
                } else {
                    res.json({
                        success: false,
                        paid: false,
                        error: "Song not found or access denied",
                    });
                }
            } else {
                // No songId in metadata - might be a different type of payment
                res.json({
                    success: true,
                    paid: true,
                    note: "Payment verified but no song ID found",
                });
            }
        } else {
            res.json({
                success: false,
                paid: false,
                error: "Payment not completed",
            });
        }
    } catch (err) {
        console.error("Payment verification error:", err);
        res.status(500).json({
            error: "Payment verification failed",
            details: err.message,
        });
    }
});

// Catch-all for undefined API routes
app.all("/api/*", (req, res) => {
    res.status(404).json({
        error: "API endpoint not found",
        path: req.path,
        method: req.method,
        message: `${req.method} ${req.path} does not exist`,
    });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(` Server running on port ${PORT}`);
    console.log(` Listening on http://0.0.0.0:${PORT}`);
});

