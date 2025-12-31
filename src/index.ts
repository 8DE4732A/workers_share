import { Hono } from 'hono'
import { serveStatic } from 'hono/cloudflare-workers'

type Bindings = {
  DB: D1Database
  SECRET_KEY: string
}

const app = new Hono<{ Bindings: Bindings }>()

// --- Crypto Helpers ---

// Convert Buffer/ArrayBuffer to Hex string
function buf2hex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)]
    .map(x => x.toString(16).padStart(2, '0'))
    .join('')
}

// Check if run in an environment that supports web crypto (Cloudflare Workers does)
// We need to encode/decode text
const enc = new TextEncoder()
const dec = new TextDecoder()

/**
 * Encrypts plaintext using AES-GCM with a provided key.
 * Returns IV + Ciphertext concatenated as hex string.
 */
async function encryptData(plaintext: string, keyBytes: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes as any,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  )
  const iv = crypto.getRandomValues(new Uint8Array(12)) // 12 bytes IV for GCM
  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    key,
    enc.encode(plaintext)
  )

  // Combine IV + Encrypted Data
  const combined = new Uint8Array(iv.byteLength + encrypted.byteLength)
  combined.set(iv, 0)
  combined.set(new Uint8Array(encrypted), iv.byteLength)

  return buf2hex(combined.buffer)
}

/**
 * Decrypts hex string (IV+Ciphertext) using AES-GCM with a provided key.
 */
async function decryptData(hexStr: string, keyBytes: Uint8Array): Promise<string> {
  // Convert hex to Uint8Array
  const combined = new Uint8Array(
    hexStr.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16))
  )

  // Extract IV (first 12 bytes)
  const iv = combined.slice(0, 12)
  const data = combined.slice(12)

  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes as any,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  )

  try {
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      key,
      data
    )
    return dec.decode(decrypted)
  } catch (e) {
    throw new Error('Decryption failed')
  }
}

/**
 * Derive a consistent key from the string secret (for token encryption).
 * In production, SECRET_KEY should be a strong random string.
 * We'll use SHA-256 to ensure it's 32 bytes.
 */
async function getMasterKey(secret: string): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest('SHA-256', enc.encode(secret))
  return new Uint8Array(hash)
}

// --- API ---

app.post('/api/share', async (c) => {
  const text = await c.req.text()
  if (!text) return c.text('Error: Text required', 400)
  if (text.length > 1024 * 1024) return c.text('Error: Text too large (>1MB)', 400)

  // 1. Generate ID and Data Key
  const id = crypto.randomUUID()
  const dataKey = crypto.getRandomValues(new Uint8Array(32)) // 256-bit key

  // 2. Encrypt Content with Data Key
  const encryptedContent = await encryptData(text, dataKey)

  // 3. Store in DB
  try {
    await c.env.DB.prepare(
      'INSERT INTO shares (id, content, created_at) VALUES (?, ?, ?)'
    ).bind(id, encryptedContent, Date.now()).run()
  } catch (e) {
    console.error(e)
    return c.text('Error: Database error', 500)
  }

  // 4. Encrypt ID+Key with Master Secret
  const payload = JSON.stringify({ id, key: buf2hex(dataKey.buffer) })
  const masterKey = await getMasterKey(c.env.SECRET_KEY)
  const token = await encryptData(payload, masterKey)

  return c.text(token)
})

app.get('/api/retrieve', async (c) => {
  const token = c.req.query('token')
  if (!token) return c.text('Error: Token required', 400)

  try {
    // 1. Decrypt Token -> ID + Data Key
    const masterKey = await getMasterKey(c.env.SECRET_KEY)
    let payloadStr: string;
    try {
      payloadStr = await decryptData(token, masterKey)
    } catch (e) {
      return c.text('Error: Invalid token', 400)
    }
    const { id, key: keyHex } = JSON.parse(payloadStr)

    // 2. Fetch Encrypted Content
    const result = await c.env.DB.prepare(
      'SELECT content FROM shares WHERE id = ?'
    ).bind(id).first<{ content: string }>()

    if (!result) return c.text('Error: Not found', 404)

    // 3. Decrypt Content
    const keyBytes = new Uint8Array(
      keyHex.match(/.{1,2}/g)!.map((byte: string) => parseInt(byte, 16))
    )
    const content = await decryptData(result.content, keyBytes)

    return c.text(content)
  } catch (e) {
    console.error('Retrieve error:', e)
    return c.text('Error: Decryption failed or system error', 500)
  }
})

// --- Frontend ---

const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Secure Text Share</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-gray-100 min-h-screen flex items-center justify-center p-4 font-sans">
  <div class="max-w-2xl w-full bg-gray-800 rounded-xl shadow-2xl p-8 border border-gray-700">
    <h1 class="text-3xl font-bold mb-6 text-center bg-gradient-to-r from-blue-400 to-purple-500 text-transparent bg-clip-text">
      Secure Text Share
    </h1>

    <!-- Create Section -->
    <div id="create-section">
      <div class="mb-4">
        <label class="block text-sm font-medium mb-2 text-gray-300">Enter Text (max 1MB)</label>
        <textarea id="input-text" rows="10" 
          class="w-full bg-gray-900 border border-gray-600 rounded-lg p-4 text-gray-200 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition"
          placeholder="Paste your sensitive text here..."></textarea>
      </div>
      
      <div class="flex items-center justify-between mb-6">
        <div class="relative group">
           <input type="file" id="file-input" class="hidden" accept=".txt">
           <label for="file-input" class="cursor-pointer px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm transition flex items-center gap-2">
             <span>📂 Upload File</span>
           </label>
        </div>
        <button id="share-btn" class="px-6 py-2 bg-blue-600 hover:bg-blue-500 rounded-lg font-semibold transition shadow-lg shadow-blue-500/30">
          Encrypt & Share
        </button>
      </div>
    </div>

    <!-- Result Section -->
    <div id="result-section" class="hidden mb-6 p-4 bg-gray-900 rounded-lg border border-green-900/50">
      <p class="text-green-400 mb-2 font-medium">Link Generated:</p>
      <div class="flex gap-2">
        <input id="share-link" readonly class="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-1 text-sm text-gray-300">
        <button id="copy-btn" class="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-sm transition">Copy</button>
      </div>
    </div>

    <!-- View Section -->
    <div id="view-section" class="hidden">
       <div class="mb-4">
        <label class="block text-sm font-medium mb-2 text-gray-300">Decrypted Content</label>
        <pre id="view-content" class="w-full bg-gray-900 border border-gray-600 rounded-lg p-4 text-gray-200 overflow-auto max-h-[60vh] whitespace-pre-wrap"></pre>
      </div>
      <button id="new-share-btn" class="w-full px-6 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg font-semibold transition mt-4">
        Create New Share
      </button>
    </div>

    <!-- Loading Overlay -->
    <div id="loading" class="hidden absolute inset-0 bg-gray-900/80 backdrop-blur-sm flex items-center justify-center rounded-xl z-10">
      <div class="animate-spin rounded-full h-12 w-12 border-4 border-blue-500 border-t-transparent"></div>
    </div>

    <!-- Curl Usage Section -->
    <div class="mt-8 pt-6 border-t border-gray-700 text-sm text-gray-400">
      <h3 class="font-bold text-gray-300 mb-2">⚡️ Curl Usage</h3>
      <div class="space-y-3">
        <div>
          <p class="mb-1 text-xs uppercase tracking-wider">Share:</p>
          <code class="block bg-gray-900 p-2 rounded border border-gray-700 font-mono select-all overflow-x-auto">
            curl -X POST -d "Expected content" <span class="origin-text"></span>/api/share
          </code>
        </div>
        <div>
           <p class="mb-1 text-xs uppercase tracking-wider">Retrieve:</p>
           <code class="block bg-gray-900 p-2 rounded border border-gray-700 font-mono select-all overflow-x-auto">
             curl "<span class="origin-text"></span>/api/retrieve?token=TOKEN"
           </code>
        </div>
      </div>
    </div>

  </div>

  <script>
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    
    // Set origin for curl examples
    document.querySelectorAll('.origin-text').forEach(el => {
        el.textContent = window.location.origin;
    });

    const createSection = document.getElementById('create-section');
    const viewSection = document.getElementById('view-section');
    const resultSection = document.getElementById('result-section');
    const loading = document.getElementById('loading');

    // Helper: Show/Hide Loading
    const toggleLoading = (show) => {
      loading.classList.toggle('hidden', !show);
    };

    if (token) {
      // View Mode
      createSection.classList.add('hidden');
      viewSection.classList.remove('hidden');
      fetchContent(token);
    }

    async function fetchContent(t) {
      toggleLoading(true);
      try {
        const res = await fetch(\`/api/retrieve?token=\${encodeURIComponent(t)}\`);
        const text = await res.text();
        if (!res.ok) throw new Error(text);
        
        document.getElementById('view-content').textContent = text;
      } catch (e) {
        document.getElementById('view-content').textContent = 'Error: ' + e.message;
        document.getElementById('view-content').classList.add('text-red-400');
      } finally {
        toggleLoading(false);
      }
    }

    // Share Logic
    document.getElementById('share-btn').addEventListener('click', async () => {
      const text = document.getElementById('input-text').value;
      if (!text) return alert('Please enter some text');
      
      toggleLoading(true);
      try {
        const res = await fetch('/api/share', {
          method: 'POST',
          body: text
        });
        const token = await res.text();
        if (!res.ok) throw new Error(token);

        const link = \`\${window.location.origin}/?token=\${token}\`;
        document.getElementById('share-link').value = link;
        resultSection.classList.remove('hidden');
      } catch (e) {
        alert('Error sharing: ' + e.message);
      } finally {
        toggleLoading(false);
      }
    });

    // File Upload Logic
    document.getElementById('file-input').addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (!file) return;
      if (file.size > 1024 * 1024) return alert('File too large (>1MB)');
      
      const reader = new FileReader();
      reader.onload = (e) => {
        document.getElementById('input-text').value = e.target.result;
      };
      reader.readAsText(file);
    });

    // Copy Logic
    document.getElementById('copy-btn').addEventListener('click', () => {
      const copyText = document.getElementById('share-link');
      copyText.select();
      navigator.clipboard.writeText(copyText.value);
      alert('Copied to clipboard!');
    });

    // New Share logic
    document.getElementById('new-share-btn').addEventListener('click', () => {
      window.location.href = '/';
    });
  </script>
</body>
</html>
`

app.get('/', (c) => c.html(html))

export default app
