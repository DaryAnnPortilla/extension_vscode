// Patrones y reconocedores de escritura "normal" de código.
// Se usan para NO penalizar texto corto que el editor o el propio estudiante
// generan de forma legítima (cierres automáticos, palabras clave, etc.).
// Un pegado explícito (Ctrl+V) de texto externo NUNCA se salva con estos patrones.

export const SAFE_PATTERN_MAX_LENGTH = 80;
const MARKUP_ONLY_MAX_LENGTH = 100;

export const SAFE_PATTERNS: RegExp[] = [
    // ========== HTML ==========
    /<!DOCTYPE\s+html\b/i,
    /<\/?(?:html|head|body|div|span|p|form|input|button|table|tr|td|ul|ol|li|script|style)\b[^>]*>/i,
    /<a\s+[^>]*href\s*=/i,
    /<img\s+[^>]*src\s*=/i,
    /<link\s+[^>]*rel\s*=\s*["']stylesheet["']/i,

    // ========== CSS ==========
    /[.#][a-zA-Z_][\w-]*\s*\{/i,
    /@[a-z-]+\s*[^{]*\{/i,
    /\b(?:color|background(?:-color)?|font-(?:size|family|weight)|margin(?:-[a-z]+)?|padding(?:-[a-z]+)?|width|height|border(?:-[a-z]+)?|justify-content|align-items)\s*:\s*[^;]+;/i,
    /\bdisplay\s*:\s*(?:block|flex|grid|inline|none)\s*;/i,
    /\bposition\s*:\s*(?:absolute|relative|fixed|sticky|static)\s*;/i,
    /\btext-align\s*:\s*(?:left|right|center|justify)\s*;/i,

    // ========== JS / TS ==========
    /\bfunction\s+\w+\s*\(/i,
    /\b(?:for|if|while|switch)\s*\([^)]*\)\s*\{/i,
    /\bcase\s+.+:/i,
    /\bconsole\.(?:log|error|warn|info)\s*\(/i,
    /\b(?:const|let|var)\s+\w+\s*=/i,
    /\breturn\b/i,
    /\btry\s*\{/i,
    /\bcatch\s*\(/i,
    /\bfinally\s*\{/i,
    /\bexport\s+(?:default\s+)?/i,
    /\bawait\s+/i,
    /\basync\s+function/i,
    /\bnew\s+\w+\s*\(/i,
    /\bclass\s+\w+/i,
    /\bextends\s+\w+/i,
    /=>/,
    /\bdocument\.(?:getElementById|querySelector|querySelectorAll)\s*\(/i,
    /\blocalStorage\.(?:getItem|setItem|removeItem)\s*\(/i,

    // ========== PYTHON ==========
    /\bdef\s+\w+\s*\(/i,
    /\bimport\s+\w+/i,
    /\bfrom\s+\w+(?:\.\w+)*\s+import\s+/i,
    /\b(?:if|elif|while)\s+.+:/i,
    /\belse\s*:/i,
    /\bfor\s+\w+\s+in\s+.+:/i,
    /\btry\s*:/i,
    /\bexcept\s+(?:\w+)?\s*(?:as\s+\w+)?\s*:/i,
    /\bfinally\s*:/i,
    /\bwith\s+.+\s+as\s+\w+\s*:/i,
    /\byield\b/i,
    /\braise\s+\w+/i,
    /\b(?:print|len|range|enumerate|super)\s*\(/i,
    /\blambda\s+.+:/i,
    /self\.\w+/i,
    /__name__\s*==\s*["']__main__["']/i,

    // ========== GENÉRICOS ==========
    /\/\/.*/,
    /\/\*[\s\S]*?\*\//,
    /#.*/,
    /<!--[\s\S]*?-->/,
    /^[\s]*[\)\}\]]/,
    /^[\s]*\;$/
];

const CLOSING_TAGS_ONLY = /^(?:<\/[A-Za-z][\w:.-]*\s*>\s*)+$/;
const TAG_NAME_COMPLETION = /^[A-Za-z][\w:.-]*\s*>$/;
const TAGS_ONLY = /^(?:<\/?[A-Za-z][\w:.-]*(?:\s+(?:class|id)\s*=\s*["'][\w\s-]{0,40}["'])*\s*\/?>\s*)+$/;

/**
 * Detecta texto insertado por el cierre automático de etiquetas HTML/XML del editor
 * (o por una expansión corta de Emmet), que NO es código copiado.
 */
export function isAutoClosedMarkup(text: string): boolean {
    const trimmed = text.trim();
    if (trimmed.length === 0) {
        return false;
    }
    if (trimmed.length <= SAFE_PATTERN_MAX_LENGTH &&
        (CLOSING_TAGS_ONLY.test(trimmed) || TAG_NAME_COMPLETION.test(trimmed))) {
        return true;
    }
    return trimmed.length <= MARKUP_ONLY_MAX_LENGTH && TAGS_ONLY.test(trimmed);
}