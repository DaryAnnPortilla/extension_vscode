import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { PdfReportGenerator, PdfReportData } from './pdfGenerator';

// ==================== INTERFACES ====================

interface SuspiciousSnippet {
    timestamp: string;
    code: string;
    reason: string;
}

interface FileMetrics {
    lastChangeTimestamp: number;
    lastCodeLength: number;
    changeHistory: number[];
    safeOperations: number;
    fileName: string;
    isInitializing: boolean;
    consecutiveChanges: number;
    lastChangeWasSafe: boolean;
    totalChangesAnalyzed: number;
    suspiciousSnippets: SuspiciousSnippet[];
}

interface SessionData {
    studentName: string;
    sessionCode: string;
}

interface ChangeAnalysis {
    isAbrupt: boolean;
    reason: string;
    confidence: number;
    abruptnessScore: number;
}

interface InternalCopyRecord {
    text: string;
    sourceFile: string;
    timestamp: number;
}

interface AnalysisConfig {
    changeThreshold: number;
    timeThreshold: number;
    minCodeLength: number;
    maxWarnings: number;
    penaltyAmount: number;
    maxPenalties: number;
    initializationTime: number;
    maxHistoryLength: number;
    maxGlobalSuspiciousEvents: number;
    minAbruptPasteLength: number;
}

// ==================== CONFIGURACIÓN ====================

const DEFAULT_CONFIG: AnalysisConfig = {
    changeThreshold: 0.6,
    timeThreshold: 1500,
    minCodeLength: 50,
    maxWarnings: 2,
    penaltyAmount: 0.25, // Descuento de 0.25 por sanción
    maxPenalties: 40,    // 40 sanciones de 0.25 = 10 puntos
    initializationTime: 15000,
    maxHistoryLength: 20,
    maxGlobalSuspiciousEvents: 3,
    minAbruptPasteLength: 120
};

// ==================== CLASE PRINCIPAL ====================

export class CodeAnalyzer {
    // Métricas por archivo (solo rastrean actividad, no calificación individual)
    private fileMetrics: Map<string, FileMetrics> = new Map();
    private timeoutIds: Map<string, NodeJS.Timeout> = new Map();

    // Contador general único por estudiante
    private globalScore: number = 10;
    private maxScore: number = 10;
    private globalWarningCount: number = 0;
    private globalPenaltyCount: number = 0;

    // Estado de sesión
    private isMonitoring: boolean = false;
    private currentSession: SessionData | null = null;
    private config: AnalysisConfig;
    
    // Logging
    private logFile: string = '';
    private logChannel: vscode.OutputChannel | null = null;
    
    // Estadísticas globales
    private startTime: number = 0;
    private totalSafeOperations: number = 0;
    private totalPenaltiesApplied: number = 0;
    private totalWarningsIssued: number = 0;
    private globalSuspiciousCount: number = 0;
    private statusBarItem: vscode.StatusBarItem | null = null;

    // Listeners y temporizador periódico
    private disposables: vscode.Disposable[] = [];
    private periodicTimer: NodeJS.Timeout | null = null;

    // Intercepción explícita del comando de pegar (Ctrl+V / Cmd+V)
    private pasteInProgress: boolean = false;

    // Detección de copia/pegado interno (dentro del mismo archivo)
    private lastInternalCopy: InternalCopyRecord | null = null;
    private pendingInternalPaste: boolean = false;
    private readonly INTERNAL_COPY_VALID_MS = 20000;

    // Intercepción de aceptación de sugerencias de autocompletado (Tab/Enter)
    private pendingSuggestionAccept: boolean = false;

    // Detección de foco de la ventana de VSCode
    private lastFocusLostTimestamp: number | null = null;
    private lastFocusRegainedTimestamp: number | null = null;
    private readonly FOCUS_REGAIN_WINDOW_MS = 3000;

    private readonly SAFE_PATTERN_MAX_LENGTH = 80;

    // Patrones seguros
    private safePatterns = [
        //========== HTML ==========
        /<!DOCTYPE\s+html\b/i,
        /<html\b[^>]*>/i,
        /<\/html\s*>/i,
        /<head\b[^>]*>/i,
        /<body\b[^>]*>/i,
        /<div\b[^>]*>/i,
        /<\/div\s*>/i,
        /<span\b[^>]*>/i,
        /<p\b[^>]*>/i,
        /<a\s+[^>]*href\s*=/i,
        /<img\s+[^>]*src\s*=/i,
        /<form\b[^>]*>/i,
        /<input\b[^>]*>/i,
        /<button\b[^>]*>/i,
        /<table\b[^>]*>/i,
        /<tr\b[^>]*>/i,
        /<td\b[^>]*>/i,
        /<ul\b[^>]*>/i,
        /<ol\b[^>]*>/i,
        /<li\b[^>]*>/i,
        /<script\b[^>]*>/i,
        /<style\b[^>]*>/i,
        /<link\s+[^>]*rel\s*=\s*["']stylesheet["']/i,

        //========== CSS ==========
        /[.#][a-zA-Z_][\w-]*\s*\{/i,
        /@[a-z-]+\s*[^{]*\{/i,
        /\bcolor\s*:\s*[^;]+;/i,
        /\bbackground(?:-color)?\s*:\s*[^;]+;/i,
        /\bfont-size\s*:\s*[^;]+;/i,
        /\bfont-family\s*:\s*[^;]+;/i,
        /\bfont-weight\s*:\s*[^;]+;/i,
        /\bmargin(?:-[a-z]+)?\s*:\s*[^;]+;/i,
        /\bpadding(?:-[a-z]+)?\s*:\s*[^;]+;/i,
        /\bwidth\s*:\s*[^;]+;/i,
        /\bheight\s*:\s*[^;]+;/i,
        /\bdisplay\s*:\s*(?:block|flex|grid|inline|none)\s*;/i,
        /\bposition\s*:\s*(?:absolute|relative|fixed|sticky|static)\s*;/i,
        /\bborder(?:-[a-z]+)?\s*:\s*[^;]+;/i,
        /\bborder-radius\s*:\s*[^;]+;/i,
        /\btext-align\s*:\s*(?:left|right|center|justify)\s*;/i,
        /\bjustify-content\s*:\s*[^;]+;/i,
        /\balign-items\s*:\s*[^;]+;/i,
        /\@media\s*\([^)]*\)\s*\{/i,
        /\@keyframes\s+[a-zA-Z_][\w-]*\s*\{/i,

        //========== JS ==========
        /\bfunction\s+\w+\s*\(/i,
        /\bfor\s*\([^)]*\)\s*\{/i,
        /\bif\s*\([^)]*\)\s*\{/i,
        /\bwhile\s*\([^)]*\)\s*\{/i,
        /\bswitch\s*\([^)]*\)\s*\{/i,
        /\bcase\s+.+:/i,
        /\bconsole\.(?:log|error|warn|info)\s*\(/i,
        /\bconst\s+\w+\s*=/i,
        /\blet\s+\w+\s*=/i,
        /\bvar\s+\w+\s*=/i,
        /\breturn\b/i,
        /\btry\s*\{/i,
        /\bcatch\s*\(/i,
        /\bfinally\s*\{/i,
        /\bexport\s+(?:default\s+)?/i,
        /\bdefault\s+/i,
        /\bawait\s+/i,
        /\basync\s+function/i,
        /\bnew\s+\w+\s*\(/i,
        /\bclass\s+\w+/i,
        /\bextends\s+\w+/i,
        /\bimport\s+.+\s+from\s+["']/i,
        /=>/i,
        /\bdocument\.(?:getElementById|querySelector|querySelectorAll)\s*\(/i,
        /\blocalStorage\.(?:getItem|setItem|removeItem)\s*\(/i,

        //========== PYTHON ==========
        /\bdef\s+\w+\s*\(/i,
        /\bclass\s+\w+(?:\([^)]*\))?\s*:/i,
        /\bimport\s+\w+/i,
        /\bfrom\s+\w+(?:\.\w+)*\s+import\s+/i,
        /\bif\s+.+:/i,
        /\belif\s+.+:/i,
        /\belse\s*:/i,
        /\bfor\s+\w+\s+in\s+.+:/i,
        /\bwhile\s+.+:/i,
        /\btry\s*:/i,
        /\bexcept\s+(?:\w+)?\s*(?:as\s+\w+)?\s*:/i,
        /\bfinally\s*:/i,
        /\bwith\s+.+\s+as\s+\w+\s*:/i,
        /\breturn\b/i,
        /\byield\b/i,
        /\braise\s+\w+/i,
        /\bprint\s*\(/i,
        /\blen\s*\(/i,
        /\brange\s*\(/i,
        /\benumerate\s*\(/i,
        /\bsuper\s*\(/i,
        /\blambda\s+.+:/i,
        /self\.\w+/i,
        /__name__\s*==\s*["']__main__["']/i,

        //========== PATRONES GENÉRICOS ==========
        /\/\/.*/,
        /\/\*[\s\S]*?\*\//,
        /#.*/,
        /<!--[\s\S]*?-->/,
        /^[\s]*[\)\}\]]/,
        /^[\s]*\;$/
    ];

    // ==================== CONSTRUCTOR ====================

    constructor() {
        this.config = { ...DEFAULT_CONFIG };
        this.loadConfigFromVSCode();
        this.initializeLogFile();
        this.createStatusBarItem();
    }

    // ==================== CONFIGURACIÓN ====================

    private loadConfigValue<T>(key: string, defaultValue: T): T {
        const config = vscode.workspace.getConfiguration('codeAnalyzer');
        const value = config.get<T>(key);
        return value !== undefined ? value : defaultValue;
    }

    private loadConfigFromVSCode() {
        const vsConfig = vscode.workspace.getConfiguration('codeAnalyzer');
        this.maxScore = vsConfig.get('maxScore', 10);
        this.globalScore = this.maxScore;

        this.config = {
            changeThreshold: this.loadConfigValue('changeThreshold', DEFAULT_CONFIG.changeThreshold),
            timeThreshold: this.loadConfigValue('timeThreshold', DEFAULT_CONFIG.timeThreshold),
            minCodeLength: this.loadConfigValue('minCodeLength', DEFAULT_CONFIG.minCodeLength),
            maxWarnings: this.loadConfigValue('maxWarnings', DEFAULT_CONFIG.maxWarnings),
            penaltyAmount: this.loadConfigValue('penaltyAmount', DEFAULT_CONFIG.penaltyAmount),
            maxPenalties: this.loadConfigValue('maxPenalties', DEFAULT_CONFIG.maxPenalties),
            initializationTime: this.loadConfigValue('initializationTime', DEFAULT_CONFIG.initializationTime),
            maxHistoryLength: this.loadConfigValue('maxHistoryLength', DEFAULT_CONFIG.maxHistoryLength),
            maxGlobalSuspiciousEvents: this.loadConfigValue('maxGlobalSuspiciousEvents', DEFAULT_CONFIG.maxGlobalSuspiciousEvents),
            minAbruptPasteLength: this.loadConfigValue('minAbruptPasteLength', DEFAULT_CONFIG.minAbruptPasteLength)
        };
    }

    // ==================== INICIALIZACIÓN ====================

    private initializeLogFile() {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders || workspaceFolders.length === 0) {
            return;
        }

        this.logFile = path.join(workspaceFolders[0].uri.fsPath, 'code-analyzer-log.txt');
        this.logChannel = vscode.window.createOutputChannel('Code Analyzer Log');

        const header = this.generateLogHeader();
        
        try {
            const dir = path.dirname(this.logFile);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            fs.writeFileSync(this.logFile, header, { encoding: 'utf8' });
        } catch (error) {
            console.error('Error creando archivo de log:', error);
        }
    }

    private generateLogHeader(): string {
        return `=== CODE ANALYZER LOG ===\n` +
               `Versión: 3.1 (Contador Global Único)\n` +
               `Inicio: ${new Date().toLocaleString()}\n` +
               `Configuración:\n` +
               `  - Nota inicial: ${this.maxScore}\n` +
               `  - Umbral de cambio: ${this.config.changeThreshold * 100}%\n` +
               `  - Tiempo mínimo: ${this.config.timeThreshold}ms\n` +
               `  - Longitud mínima: ${this.config.minCodeLength} caracteres\n` +
               `  - Máx advertencias: ${this.config.maxWarnings}\n` +
               `  - Penalización: ${this.config.penaltyAmount} puntos\n` +
               `  - Máx penalizaciones: ${this.config.maxPenalties}\n` +
               `=================================\n\n`;
    }

    private createStatusBarItem() {
        this.statusBarItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Right,
            100
        );
        this.statusBarItem.text = '$(circle-slash) Code Analyzer: Inactivo';
        this.statusBarItem.tooltip = 'Code Analyzer - Click para ver estado';
        this.statusBarItem.command = 'codeAnalyzer.verifyStatus';
        this.statusBarItem.show();
    }

    // ==================== MONITOREO ====================

    public async startVerificationMonitoring() {
        if (this.isMonitoring) {
            const response = await vscode.window.showWarningMessage(
                'El monitoreo ya está activo. ¿Deseas reiniciarlo?',
                'Sí', 'No'
            );
            
            if (response !== 'Sí') {
                return;
            }
            
            this.stopMonitoring();
        }

        const studentName = await this.getStudentName();
        if (!studentName) {
            vscode.window.showErrorMessage('❌ Evaluación cancelada: Debes ingresar tu nombre');
            return;
        }

        if (!this.ensureWorkspaceExists()) {
            return;
        }

        this.currentSession = this.createSession(studentName);
        this.startMonitoring();
        this.createVerificationFile();
        this.showStartupMessage(studentName);
    }

    private async getStudentName(): Promise<string | undefined> {
        return await vscode.window.showInputBox({
            prompt: '🔐 INGRESA TU NOMBRE PARA LA EVALUACIÓN',
            placeHolder: 'Ej: María González López',
            ignoreFocusOut: true,
            validateInput: (text) => {
                if (!text || text.trim().length < 3) {
                    return 'El nombre debe tener al menos 3 caracteres';
                }
                if (text.trim().length > 50) {
                    return 'El nombre es demasiado largo (máx 50 caracteres)';
                }
                if (!/^[a-zA-ZáéíóúñÑ\s]+$/.test(text)) {
                    return 'El nombre solo puede contener letras y espacios';
                }
                return null;
            }
        });
    }

    private ensureWorkspaceExists(): boolean {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders || workspaceFolders.length === 0) {
            vscode.window.showErrorMessage('❌ No hay workspace abierto. Abre una carpeta para comenzar.');
            return false;
        }
        return true;
    }

    private createSession(studentName: string): SessionData {
        const sessionCode = this.generateSessionCode();
        return {
            studentName: studentName.trim(),
            sessionCode: sessionCode
        };
    }

    private generateSessionCode(): string {
        const timestamp = Date.now().toString(36).toUpperCase().slice(-6);
        const random = Math.random().toString(36).substring(2, 5).toUpperCase();
        return `STU${timestamp}${random}`;
    }

    private showStartupMessage(studentName: string) {
        vscode.window.showInformationMessage(
            `✅ EVALUACIÓN INICIADA\n` +
            `Estudiante: ${studentName}\n` +
            `Código: ${this.currentSession?.sessionCode}\n` +
            `Nota inicial: ${this.globalScore.toFixed(2)}/${this.maxScore}`
        );
    }

    // ==================== INICIO/DETENCIÓN ====================

    public startMonitoring() {
        if (this.isMonitoring) {
            vscode.window.showWarningMessage('⚠️ El monitoreo ya está activo');
            return;
        }

        const vsConfig = vscode.workspace.getConfiguration('codeAnalyzer');
        this.maxScore = vsConfig.get('maxScore', 10);
        this.globalScore = this.maxScore;
        this.globalWarningCount = 0;
        this.globalPenaltyCount = 0;

        this.isMonitoring = true;
        this.startTime = Date.now();
        this.totalSafeOperations = 0;
        this.totalPenaltiesApplied = 0;
        this.totalWarningsIssued = 0;
        this.globalSuspiciousCount = 0;
        this.fileMetrics.clear();

        vscode.workspace.textDocuments.forEach(doc => {
            if (this.isSupportedFile(doc)) {
                this.initializeFileMetrics(doc.fileName);
            }
        });

        this.setupEventListeners();
        this.updateStatusBar();
        this.logEvent('SISTEMA_INICIADO', 'Monitoreo iniciado correctamente con contador global');
        vscode.window.showInformationMessage('🔍 Monitoreo de código activado');
    }

    public async stopMonitoring() {
        if (!this.isMonitoring) {
            return;
        }

        this.isMonitoring = false;
        this.clearAllTimeouts();
        this.disposeListeners();
        this.updateStatusBar();
        this.logEvent('MONITOREO_DETENIDO', 'Monitoreo detenido por el usuario');
        vscode.window.showInformationMessage('⏹️ Monitoreo desactivado');
    
        if (this.fileMetrics.size > 0) {
            await this.generatePdfReport();
        }
    }

    private clearAllTimeouts() {
        this.timeoutIds.forEach((timeoutId) => {
            clearTimeout(timeoutId);
        });
        this.timeoutIds.clear();
    }

    // ==================== EVENT LISTENERS ====================

    private setupEventListeners() {
        this.disposables.push(
            vscode.workspace.onDidChangeTextDocument(this.handleDocumentChange.bind(this)),

            vscode.workspace.onDidOpenTextDocument((doc) => {
                if (this.isMonitoring && this.isSupportedFile(doc)) {
                    this.initializeFileMetrics(doc.fileName);
                }
            }),

            vscode.window.onDidChangeWindowState(this.handleWindowStateChange.bind(this))
        );

        this.setupPeriodicVerification();
    }

    private disposeListeners() {
        this.disposables.forEach(d => d.dispose());
        this.disposables = [];

        if (this.periodicTimer) {
            clearInterval(this.periodicTimer);
            this.periodicTimer = null;
        }
    }

    private handleWindowStateChange(state: vscode.WindowState) {
        if (!this.isMonitoring) {
            return;
        }

        if (!state.focused) {
            this.lastFocusLostTimestamp = Date.now();
        } else if (this.lastFocusLostTimestamp !== null) {
            this.lastFocusRegainedTimestamp = Date.now();
        }
    }

    private handleDocumentChange(event: vscode.TextDocumentChangeEvent) {
        if (!this.isMonitoring || !this.isSupportedFile(event.document)) {
            return;
        }

        const fileName = event.document.fileName;
        let metrics = this.fileMetrics.get(fileName);
        
        if (!metrics) {
            this.initializeFileMetrics(fileName);
            metrics = this.fileMetrics.get(fileName);
            if (!metrics) return;
        }

        // FILTRO UNDO/REDO: Evita que el historial nativo dispare falsos positivos
        if (event.reason === vscode.TextDocumentChangeReason.Undo || 
            event.reason === vscode.TextDocumentChangeReason.Redo) {
            
            metrics.lastCodeLength = event.document.getText().length;
            metrics.lastChangeTimestamp = Date.now();
            return;
        }

        this.analyzeCodeChange(event, metrics);
    }

    // ==================== ANÁLISIS DE CÓDIGO ====================

    private analyzeCodeChange(event: vscode.TextDocumentChangeEvent, metrics: FileMetrics) {
        const currentTime = Date.now();
        const timeSinceLastChange = currentTime - metrics.lastChangeTimestamp;
        const currentCodeLength = event.document.getText().length;

        // 0. Consumir bandera de pegado interno
        const isInternalPaste = this.pendingInternalPaste;
        if (this.pendingInternalPaste) {
            this.pendingInternalPaste = false;
        }

        // 0.1 Detectar sugerencia de autocompletado aceptada
        const isCompletionAccept = this.looksLikeCompletionAccept(event.contentChanges);

        // 0.2 Consumir bandera de aceptación de sugerencia interceptada
        const isSuggestionAccept = this.pendingSuggestionAccept;
        if (this.pendingSuggestionAccept) {
            this.pendingSuggestionAccept = false;
        }

        // 1. Determinar si el cambio es seguro
        const isSafe = isInternalPaste || isCompletionAccept || isSuggestionAccept || 
                       this.isSafeOperation(event.document.getText(), event.contentChanges);
        
        const addedLength = event.contentChanges.reduce((sum, c) => sum + c.text.length, 0);

        const isExplicitPaste = this.pasteInProgress;
        if (this.pasteInProgress) {
            this.pasteInProgress = false;
        }

        const isRecentFocusRegain = this.lastFocusRegainedTimestamp !== null &&
            (currentTime - this.lastFocusRegainedTimestamp) < this.FOCUS_REGAIN_WINDOW_MS;

        // 2. Analizar el contexto del cambio
        const contextAnalysis = this.analyzeChangeContext(
            currentCodeLength,
            metrics.lastCodeLength,
            timeSinceLastChange,
            metrics.consecutiveChanges,
            metrics.lastChangeWasSafe,
            metrics.isInitializing,
            addedLength,
            isExplicitPaste,
            isRecentFocusRegain
        );

        // 3. Actualizar estadísticas de seguridad
        this.updateSecurityStatistics(metrics, isSafe);

        // 4. Actualizar cambios consecutivos
        this.updateConsecutiveChanges(metrics, timeSinceLastChange);

        // 5. Registrar en historial
        this.recordChangeHistory(metrics, currentCodeLength, contextAnalysis, isSafe);

        // 6. Aplicar penalización global si es necesario
        if (this.shouldApplyPenalty(contextAnalysis, isSafe, metrics)) {
            const pastedCode = event.contentChanges
                .map(change => change.text)
                .join('\n')
                .trim();
        
            if (pastedCode.length > 0) {
                metrics.suspiciousSnippets.push({
                    timestamp: new Date().toLocaleTimeString(),
                    code: pastedCode.substring(0, 300),
                    reason: contextAnalysis.reason
                });
            }

            this.applyPenalty(event.document.fileName, contextAnalysis);
        }

        // 7. Actualizar estado final del archivo
        this.updateFinalState(metrics, currentTime, currentCodeLength, isSafe);

        // 8. Registrar eventos de log
        this.logChangeEvent(event.document.fileName, contextAnalysis, isSafe);

        if (isInternalPaste) {
            this.logEvent('PASTE_INTERNO_DETECTADO',
                `Archivo: ${path.basename(event.document.fileName)} — coincide con copia registrada del mismo archivo`);
        }

        if (isCompletionAccept && !isInternalPaste) {
            this.logEvent('AUTOCOMPLETADO_DETECTADO',
                `Archivo: ${path.basename(event.document.fileName)} — cambio identificado como aceptación de sugerencia`);
        }

        if (isSuggestionAccept && !isInternalPaste) {
            this.logEvent('SUGERENCIA_INTERCEPTADA_DETECTADA',
                `Archivo: ${path.basename(event.document.fileName)} — cambio identificado vía Tab/Enter interceptado`);
        }
    }

    // ==================== ANÁLISIS DE CONTEXTO ====================

    private analyzeChangeContext(
        currentLength: number,
        previousLength: number,
        timeDiff: number,
        consecutiveChanges: number,
        lastChangeWasSafe: boolean,
        isInitializing: boolean,
        addedLength: number,
        isExplicitPaste: boolean,
        isRecentFocusRegain: boolean
    ): ChangeAnalysis {
        if (isInitializing) {
            return {
                isAbrupt: false,
                reason: 'inicialización',
                confidence: 0,
                abruptnessScore: 0
            };
        }

        let abruptnessScore = 0;

        if (addedLength >= this.config.minAbruptPasteLength) {
            abruptnessScore += 0.4;
            if (addedLength >= this.config.minAbruptPasteLength * 2) {
                abruptnessScore += 0.2;
            }
        }

        if (isExplicitPaste && addedLength >= this.config.minAbruptPasteLength) {
            abruptnessScore += 0.5;
        }

        if (isRecentFocusRegain && addedLength >= this.config.minAbruptPasteLength) {
            abruptnessScore += isExplicitPaste ? 0.3 : 0.15;
        }

        if (abruptnessScore === 0 &&
            (previousLength < this.config.minCodeLength || currentLength < this.config.minCodeLength)) {
            return {
                isAbrupt: false,
                reason: 'archivo_pequeño',
                confidence: 0.1,
                abruptnessScore: 0
            };
        }

        const lengthChange = Math.abs(currentLength - previousLength);
        const changeRatio = previousLength > 0 ? lengthChange / previousLength : 0;

        if (changeRatio > this.config.changeThreshold) {
            abruptnessScore += 0.4;
            if (changeRatio > 0.8) abruptnessScore += 0.2;
        }

        if (timeDiff < this.config.timeThreshold) {
            abruptnessScore += 0.3;
            if (timeDiff < 500) abruptnessScore += 0.1;
        }

        if (consecutiveChanges > 3) {
            abruptnessScore += 0.2;
            if (consecutiveChanges > 5) abruptnessScore += 0.1;
        }

        if (!lastChangeWasSafe) {
            abruptnessScore += 0.1;
        }

        const isAbrupt = abruptnessScore > 0.6;

        let reason = 'cambio_normal';
        if (isAbrupt) {
            if (isExplicitPaste && isRecentFocusRegain && addedLength >= this.config.minAbruptPasteLength) {
                reason = 'paste_tras_perdida_de_foco';
            } else if (isExplicitPaste && addedLength >= this.config.minAbruptPasteLength) {
                reason = 'paste_explicito_detectado';
            } else if (addedLength >= this.config.minAbruptPasteLength * 2) {
                reason = 'paste_grande_detectado';
            } else if (changeRatio > 0.9 && timeDiff < 5000) {
                reason = 'cambio_masivo_detectado';
            } else if (consecutiveChanges > 5 && timeDiff < 1000) {
                reason = 'rafaga_cambios_consecutivos';
            } else if (changeRatio > this.config.changeThreshold) {
                reason = 'cambio_abrupto_detectado';
            } else {
                reason = 'patron_sospechoso';
            }
        }

        return {
            isAbrupt,
            reason,
            confidence: Math.min(abruptnessScore + 0.2, 1.0),
            abruptnessScore
        };
    }

    // ==================== OPERACIONES SEGURAS ====================

    private isSafeOperation(content: string, changes: readonly vscode.TextDocumentContentChangeEvent[]): boolean {
        if (content.length < this.config.minCodeLength) {
            return true;
        }

        if (changes.length === 0) {
            return true;
        }

        let allSafe = true;

        for (const change of changes) {
            const addedText = change.text;
            const trimmed = addedText.trim();

            if (trimmed.length === 0) {
                continue;
            }
            if (trimmed.length <= 3) {
                continue;
            }

            let matchedSafePattern = false;
            if (addedText.length <= this.SAFE_PATTERN_MAX_LENGTH) {
                for (const pattern of this.safePatterns) {
                    if (pattern.test(addedText)) {
                        matchedSafePattern = true;
                        break;
                    }
                }
            }

            if (!matchedSafePattern) {
                allSafe = false;
            }
        }

        if (allSafe) {
            return true;
        }

        if (changes.length > 1 && changes.length <= 4) {
            const totalChanges = changes.reduce((sum, change) => sum + change.text.length, 0);
            if (totalChanges < 20) {
                return true;
            }
        }

        return false;
    }

    // ==================== DETECCIÓN DE AUTOCOMPLETADO ====================
    
    private looksLikeCompletionAccept(changes: readonly vscode.TextDocumentContentChangeEvent[]): boolean {
        if (changes.length !== 1) {
            return false;
        }

        const change = changes[0];

        if (change.rangeLength === 0) {
            return false;
        }

        if (change.text.length > this.config.minAbruptPasteLength) {
            return false;
        }
        if ((change.text.match(/\n/g) || []).length > 3) {
            return false;
        }

        return true;
    }

    // ==================== ACTUALIZACIÓN DE ESTADO ====================

    private updateSecurityStatistics(metrics: FileMetrics, isSafe: boolean) {
        if (isSafe) {
            this.totalSafeOperations++;
            metrics.safeOperations++;
            metrics.lastChangeWasSafe = true;
        } else {
            metrics.lastChangeWasSafe = false;
        }
        metrics.totalChangesAnalyzed++;
    }

    private updateConsecutiveChanges(metrics: FileMetrics, timeSinceLastChange: number) {
        if (timeSinceLastChange < 2000) {
            metrics.consecutiveChanges++;
        } else {
            metrics.consecutiveChanges = 0;
        }
    }

    private recordChangeHistory(
        metrics: FileMetrics,
        currentCodeLength: number,
        contextAnalysis: ChangeAnalysis,
        isSafe: boolean
    ) {
        if (!contextAnalysis.isAbrupt && !isSafe) {
            const changeRatio = metrics.lastCodeLength > 0 ?
                Math.abs(currentCodeLength - metrics.lastCodeLength) / metrics.lastCodeLength : 0;

            if (changeRatio > 0.01) {
                metrics.changeHistory.push(changeRatio);
                
                if (metrics.changeHistory.length > this.config.maxHistoryLength) {
                    metrics.changeHistory = metrics.changeHistory.slice(-this.config.maxHistoryLength);
                }
            }
        }
    }

    private updateFinalState(
        metrics: FileMetrics,
        currentTime: number,
        currentCodeLength: number,
        isSafe: boolean
    ) {
        metrics.lastChangeTimestamp = currentTime;
        metrics.lastCodeLength = currentCodeLength;
        if (isSafe) {
            metrics.lastChangeWasSafe = true;
        }
    }

    private logChangeEvent(
        fileName: string,
        contextAnalysis: ChangeAnalysis,
        isSafe: boolean
    ) {
        if (contextAnalysis.isAbrupt && contextAnalysis.confidence > 0.8 && !isSafe) {
            this.logEvent('CAMBIO_SIGNIFICATIVO',
                `Archivo: ${path.basename(fileName)}, ` +
                `Confianza: ${(contextAnalysis.confidence * 100).toFixed(1)}%, ` +
                `Razón: ${contextAnalysis.reason}, ` +
                `Seguro: ${isSafe}`
            );
        }
        
        if (isSafe && contextAnalysis.abruptnessScore > 0.3) {
            this.logEvent('CAMBIO_SEGURO_CON_TENSION',
                `Archivo: ${path.basename(fileName)}, ` +
                `Puntuación abruptness: ${(contextAnalysis.abruptnessScore * 100).toFixed(1)}%`
            );
        }
    }

    // ==================== PENALIZACIONES (CONTADOR GLOBAL ÚNICO) ====================

    private shouldApplyPenalty(
        contextAnalysis: ChangeAnalysis,
        isSafe: boolean,
        metrics: FileMetrics
    ): boolean {
        return contextAnalysis.isAbrupt &&
               !isSafe &&
               !metrics.isInitializing &&
               contextAnalysis.confidence > 0.7;
    }

    private applyPenalty(
        fileName: string,
        contextAnalysis: ChangeAnalysis
    ) {
        this.globalSuspiciousCount++;
        const globalLimitReached = this.globalSuspiciousCount > this.config.maxGlobalSuspiciousEvents;

        // 1. Advertencias globales
        if (this.globalWarningCount < this.config.maxWarnings && !globalLimitReached) {
            this.globalWarningCount++;
            this.totalWarningsIssued++;
            this.showWarning(fileName, contextAnalysis);
            return;
        }

        // 2. Si ya alcanzó el límite de penalizaciones o llegó a 0
        if (this.globalPenaltyCount >= this.config.maxPenalties || this.globalScore <= 0) {
            this.logEvent('INFRACCION_POST_LIMITE', `El estudiante sigue incurriendo en infracciones tras llegar a 0. Archivo: ${path.basename(fileName)}`);
            return;
        }

        // 3. Descuento global de 0.25 (toFixed(2) mantiene los dos decimales)
        const penaltyAmount = this.config.penaltyAmount;
        const newScore = Number(Math.max(0, this.globalScore - penaltyAmount).toFixed(2));
        const actualReduction = Number((this.globalScore - newScore).toFixed(2));
        
        this.globalScore = newScore;
        this.globalPenaltyCount++;
        this.totalPenaltiesApplied++;

        this.logPenalty(fileName, penaltyAmount, actualReduction, contextAnalysis);
        this.showPenaltyNotification(fileName, penaltyAmount, actualReduction);
        this.updateStatusBar();
    }

    private showWarning(
        fileName: string,
        contextAnalysis: ChangeAnalysis
    ) {
        const remaining = this.config.maxWarnings - this.globalWarningCount;
        const message = `⚠️ Advertencia ${this.globalWarningCount}/${this.config.maxWarnings}`;
        const detail = `Archivo: ${path.basename(fileName)}\n` +
                      `Razón: ${contextAnalysis.reason}\n` +
                      `Confianza: ${(contextAnalysis.confidence * 100).toFixed(1)}%\n` +
                      `${remaining} advertencia(s) restante(s) antes de penalizar (-${this.config.penaltyAmount}p)`;

        vscode.window.showWarningMessage(
            message,
            { detail: detail },
            '📊 Ver detalles'
        ).then(selection => {
            if (selection === '📊 Ver detalles') {
                this.showDetailedReport(fileName);
            }
        });
    }

    private showPenaltyNotification(
        fileName: string,
        penaltyAmount: number,
        actualReduction: number
    ) {
        const message = `⚖️ Penalización aplicada -${penaltyAmount.toFixed(2)}p (reducción real: ${actualReduction.toFixed(2)}p)`;
        const detail = `Archivo: ${path.basename(fileName)}\n` +
                      `Calificación global actual: ${this.globalScore.toFixed(2)}/${this.maxScore}\n` +
                      `Total penalizaciones: ${this.globalPenaltyCount}/${this.config.maxPenalties}\n` +
                      `Operaciones seguras totales: ${this.totalSafeOperations}`;

        vscode.window.showWarningMessage(
            message,
            { detail: detail },
            '📊 Ver detalles',
            '🛑 Desactivar'
        ).then(selection => {
            if (selection === '📊 Ver detalles') {
                this.showDetailedReport(fileName);
            } else if (selection === '🛑 Desactivar') {
                this.stopMonitoring();
            }
        });
    }

    // ==================== INICIALIZACIÓN DE MÉTRICAS POR ARCHIVO ====================

    private initializeFileMetrics(fileName: string) {
        if (this.fileMetrics.has(fileName)) {
            return;
        }

        if (this.timeoutIds.has(fileName)) {
            clearTimeout(this.timeoutIds.get(fileName)!);
            this.timeoutIds.delete(fileName);
        }

        const initialMetrics: FileMetrics = {
            lastChangeTimestamp: Date.now(),
            lastCodeLength: this.getFileLength(fileName),
            changeHistory: [],
            safeOperations: 0,
            fileName: fileName,
            isInitializing: true,
            consecutiveChanges: 0,
            lastChangeWasSafe: true,
            totalChangesAnalyzed: 0,
            suspiciousSnippets: []
        };

        this.fileMetrics.set(fileName, initialMetrics);

        const timeoutId = setTimeout(() => {
            this.finishInitialization(fileName);
        }, this.config.initializationTime);

        this.timeoutIds.set(fileName, timeoutId);
    }

    private finishInitialization(fileName: string) {
        const metrics = this.fileMetrics.get(fileName);
        if (metrics && metrics.isInitializing) {
            metrics.isInitializing = false;
            this.logEvent('INICIALIZACION_COMPLETADA',
                `Modo inicialización desactivado para: ${path.basename(fileName)}`);
        }
        this.timeoutIds.delete(fileName);
    }

    // ==================== UTILIDADES ====================

    private readonly MONITORED_SCHEMES = ['file', 'untitled'];

    private isSupportedFile(document: vscode.TextDocument): boolean {
        if (!this.MONITORED_SCHEMES.includes(document.uri.scheme)) {
            return false;
        }
        
        const unsupportedExtensions = ['.log', '.txt', '.md', '.json', '.xml', '.yml', '.yaml'];
        const fileExtension = path.extname(document.fileName).toLowerCase();
        return !unsupportedExtensions.includes(fileExtension) && 
               document.languageId !== 'plaintext';
    }

    private getFileLength(fileName: string): number {
        try {
            if (fs.existsSync(fileName)) {
                const content = fs.readFileSync(fileName, 'utf8');
                return content.length;
            }
        } catch (error) {
            // Silenciosamente ignorar error
        }
        return 0;
    }

    // ==================== VERIFICACIÓN PERIÓDICA ====================

    private setupPeriodicVerification() {
        if (this.periodicTimer) {
            clearInterval(this.periodicTimer);
        }

        this.periodicTimer = setInterval(() => {
            if (this.isMonitoring) {
                this.updateStatusBar();
                this.logEvent('VERIFICACION_PERIODICA',
                    `Sistema activo. Nota actual: ${this.globalScore.toFixed(2)}/${this.maxScore} | Archivos: ${this.fileMetrics.size}`);
            }
        }, 120000);
    }

    private updateStatusBar() {
        if (!this.statusBarItem) return;

        if (this.isMonitoring) {
            const totalFiles = this.fileMetrics.size;
            
            this.statusBarItem.text = `$(graph) Nota: ${this.globalScore.toFixed(2)}/${this.maxScore} (${totalFiles} archivos)`;
            this.statusBarItem.tooltip = `Code Analyzer Activo\n` +
                                        `Calificación global: ${this.globalScore.toFixed(2)}/${this.maxScore}\n` +
                                        `Archivos monitoreados: ${totalFiles}\n` +
                                        `Penalizaciones totales: ${this.globalPenaltyCount}\n` +
                                        `Operaciones seguras: ${this.totalSafeOperations}`;
            this.statusBarItem.backgroundColor = undefined;
        } else {
            this.statusBarItem.text = '$(circle-slash) Analyzer: Inactivo';
            this.statusBarItem.tooltip = 'Code Analyzer Inactivo - Haz clic para iniciar';
            this.statusBarItem.backgroundColor = undefined;
        }
        this.statusBarItem.show();
    }

    // ==================== REPORTES ====================

    public showDetailedReport(fileName: string) {
        const metrics = this.fileMetrics.get(fileName);
        if (!metrics) {
            vscode.window.showWarningMessage('No hay datos de análisis para este archivo');
            return;
        }

        const avgChange = this.calculateAverageChange(metrics);
        const report = this.generateDetailedReport(metrics, avgChange);

        const channel = vscode.window.createOutputChannel('Code Analyzer - Reporte Detallado');
        channel.clear();
        channel.appendLine(report);
        channel.show();

        this.logEvent('REPORTE_SOLICITADO', `Reporte detallado para ${path.basename(fileName)}`);
    }

    private calculateAverageChange(metrics: FileMetrics): number {
        if (metrics.changeHistory.length === 0) return 0;
        return metrics.changeHistory.reduce((a, b) => a + b, 0) / metrics.changeHistory.length;
    }

    private calculateEffectiveness(totalSafeOps: number, totalChanges: number): string {
        return totalChanges > 0 ? ((totalSafeOps / totalChanges) * 100).toFixed(1) : '0.0';
    }

    private generateDetailedReport(metrics: FileMetrics, avgChange: number): string {
        const studentName = this.currentSession?.studentName || 'Estudiante';
        const sessionCode = this.currentSession?.sessionCode || 'SESION';

        return `📊 REPORTE DETALLADO DE ANÁLISIS - VERSIÓN 3.1
=================================
Archivo: ${path.basename(metrics.fileName)}
Estudiante: ${studentName}
Sesión: ${sessionCode}

ESTADO GLOBAL DE EVALUACIÓN:
• Calificación Global: ${this.globalScore.toFixed(2)}/${this.maxScore}
• Penalizaciones Globales: ${this.globalPenaltyCount}/${this.config.maxPenalties} (-${(this.globalPenaltyCount * this.config.penaltyAmount).toFixed(2)} pts)
• Advertencias Globales: ${this.globalWarningCount}/${this.config.maxWarnings}

MÉTRICAS DEL ARCHIVO ACTUAL:
• Operaciones seguras: ${metrics.safeOperations}
• Cambios analizados: ${metrics.totalChangesAnalyzed}
• Cambios consecutivos: ${metrics.consecutiveChanges}
• Modo inicialización: ${metrics.isInitializing ? 'ACTIVO' : 'INACTIVO'}

HISTORIAL DE CAMBIOS:
${metrics.changeHistory.slice(-10).map((r, i) => 
    `  ${i + 1}. ${(r * 100).toFixed(1)}%`
).join('\n')}

ESTADÍSTICAS DE SESIÓN:
• Promedio cambio (archivo): ${(avgChange * 100).toFixed(1)}%
• Tiempo monitoreo: ${Math.round((Date.now() - this.startTime) / 60000)} min
• Archivos monitoreados: ${this.fileMetrics.size}
• Total operaciones seguras: ${this.totalSafeOperations}

FRAGMENTOS SOSPECHOSOS EN ESTE ARCHIVO:
${metrics.suspiciousSnippets.length === 0 ? '✅ Ningún código copiado detectado en este archivo.' : 
    metrics.suspiciousSnippets.map((s, i) => 
    `Fragmento ${i + 1}:\n[${s.timestamp}] Motivo: ${s.reason}\n\`\`\`\n${s.code}${s.code.length >= 300 ? '...\n(código truncado)' : ''}\n\`\`\``
    ).join('\n\n')}

RECOMENDACIONES:
✅ Escribe código progresivamente
✅ Evita copiar y pegar bloques grandes
✅ Comprende cada línea que escribes
✅ Haz cambios pequeños y frecuentes
=================================`;
    }

    public async generateFinalReport() {
        if (this.fileMetrics.size === 0) {
            vscode.window.showWarningMessage('No hay datos de monitoreo para generar reporte');
            return;
        }

        const report = this.generateFinalReportContent();
        this.showFinalReport(report);

        await this.generatePdfReport();
    }

    private generateFinalReportContent(): string {
        let report = `📈 REPORTE FINAL DE EVALUACIÓN - VERSIÓN 3.1\n`;
        report += `===============================\n`;
        report += `Fecha: ${new Date().toLocaleString()}\n`;
        report += `Estudiante: ${this.currentSession?.studentName || 'No identificado'}\n`;
        report += `Sesión: ${this.currentSession?.sessionCode || 'No activa'}\n`;
        report += `Duración: ${this.calculateDuration()}\n`;
        report += `Archivos analizados: ${this.fileMetrics.size}\n\n`;

        report += `🏆 CALIFICACIÓN GENERAL:\n`;
        report += `   Nota Final: ${this.globalScore.toFixed(2)} / ${this.maxScore}\n`;
        report += `   Penalizaciones totales: ${this.globalPenaltyCount} (-${(this.globalPenaltyCount * this.config.penaltyAmount).toFixed(2)} pts)\n`;
        report += `   Advertencias emitidas: ${this.globalWarningCount}\n\n`;

        let totalSafeOps = 0;
        let totalChanges = 0;

        this.fileMetrics.forEach((metrics, fileName) => {
            const avgChange = this.calculateAverageChange(metrics);
            
            report += `📄 ${path.basename(fileName)}\n`;
            report += `   Operaciones seguras: ${metrics.safeOperations}\n`;
            report += `   Cambios analizados: ${metrics.totalChangesAnalyzed}\n`;
            report += `   Fragmentos sospechosos: ${metrics.suspiciousSnippets.length}\n`;
            report += `   Promedio cambio: ${(avgChange * 100).toFixed(1)}%\n`;
            report += `   -----------------------------------\n`;

            totalSafeOps += metrics.safeOperations;
            totalChanges += metrics.totalChangesAnalyzed;
        });

        const effectiveness = this.calculateEffectiveness(totalSafeOps, totalChanges);
        report += `\n🎯 RESUMEN DE ACTIVIDAD:\n`;
        report += `Total operaciones seguras: ${totalSafeOps}\n`;
        report += `Total cambios analizados: ${totalChanges}\n`;
        report += `Efectividad: ${effectiveness}%\n`;
        report += `===============================\n`;

        return report;
    }

    private calculateDuration(): string {
        const duration = Date.now() - this.startTime;
        const minutes = Math.floor(duration / 60000);
        const seconds = Math.floor((duration % 60000) / 1000);
        return `${minutes} minutos, ${seconds} segundos`;
    }

    private showFinalReport(report: string) {
        const channel = vscode.window.createOutputChannel('Reporte Final - Code Analyzer');
        channel.clear();
        channel.appendLine(report);
        channel.show();
    }

    // Generar el reporte en formato PDF
    public async generatePdfReport() {
        if (this.fileMetrics.size === 0) {
            vscode.window.showWarningMessage('No hay datos de monitoreo para generar el PDF');
            return;
        }

        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            vscode.window.showErrorMessage('Se requiere un área de trabajo abierta para guardar el reporte.');
            return;
        }

        const allSnippets: Array<{ fileName: string; timestamp: string; reason: string; code: string }> = [];
        const fileDetails: PdfReportData['fileDetails'] = [];

        let totalSafeOps = 0;
        let totalChanges = 0;

        this.fileMetrics.forEach((metrics, fileName) => {
            totalSafeOps += metrics.safeOperations;
            totalChanges += metrics.totalChangesAnalyzed;

            fileDetails.push({
                fileName: path.basename(fileName),
                safeOps: metrics.safeOperations,
                changesAnalyzed: metrics.totalChangesAnalyzed,
                suspiciousCount: metrics.suspiciousSnippets.length
            });

            if (metrics.suspiciousSnippets) {
                metrics.suspiciousSnippets.forEach(s => {
                    allSnippets.push({
                        fileName: path.basename(fileName),
                        timestamp: s.timestamp,
                        reason: s.reason,
                        code: s.code
                    });
                });
            }
        });

        const sessionCode = this.currentSession?.sessionCode || 'GENERAL';
        const pdfPath = path.join(
            workspaceFolders[0].uri.fsPath,
            `REPORTE_EVALUACION_${sessionCode}_${new Date().toISOString().slice(0, 10)}.pdf`
        );

        const pdfData: PdfReportData = {
            studentName: this.currentSession?.studentName || 'Estudiante',
            sessionCode: sessionCode,
            duration: this.calculateDuration(),
            totalFiles: this.fileMetrics.size,
            safeOperations: this.totalSafeOperations,
            totalPenalties: this.globalPenaltyCount,
            totalWarnings: this.globalWarningCount,
            finalScore: this.globalScore,
            maxScore: this.maxScore,
            penaltyAmount: this.config.penaltyAmount,
            effectiveness: this.calculateEffectiveness(totalSafeOps, totalChanges),
            fileDetails: fileDetails,
            suspiciousSnippets: allSnippets
        };

        try {
            await PdfReportGenerator.generatePdf(pdfPath, pdfData);
            vscode.window.showInformationMessage(`📄 Reporte PDF generado exitosamente: ${path.basename(pdfPath)}`);
            this.logEvent('REPORTE_PDF_GUARDADO', `PDF guardado en: ${pdfPath}`);
        } catch (error) {
            vscode.window.showErrorMessage(`Error al generar el reporte PDF: ${error}`);
        }
    }

    // ==================== COMANDOS PÚBLICOS ====================

    public showScore() {
        const message = `🎯 Calificación Global: ${this.globalScore.toFixed(2)}/${this.maxScore} ` +
                        `| Penalizaciones: ${this.globalPenaltyCount} ` +
                        `| Advertencias: ${this.globalWarningCount} ` +
                        `| Operaciones seguras: ${this.totalSafeOperations}`;
        
        vscode.window.showInformationMessage(message);
    }

    public getCurrentScore(): number {
        return this.globalScore;
    }

    public resetScores() {
        this.clearAllTimeouts();
        this.fileMetrics.clear();
        this.globalScore = this.maxScore;
        this.globalWarningCount = 0;
        this.globalPenaltyCount = 0;
        this.totalSafeOperations = 0;
        this.totalPenaltiesApplied = 0;
        this.totalWarningsIssued = 0;
        this.globalSuspiciousCount = 0;
        this.updateStatusBar();
        
        this.logEvent('PUNTUACIONES_REINICIADAS', 'La calificación global y métricas fueron reseteadas');
        vscode.window.showInformationMessage('🔄 Calificación reiniciada a ' + this.globalScore.toFixed(2));
    }

    public showLogFile() {
        if (!this.logFile || !fs.existsSync(this.logFile)) {
            vscode.window.showWarningMessage('No hay archivo de log disponible');
            return;
        }

        try {
            const logContent = fs.readFileSync(this.logFile, 'utf8');
            if (this.logChannel) {
                this.logChannel.clear();
                this.logChannel.appendLine('=== LOG DEL SISTEMA ===\n');
                this.logChannel.appendLine(logContent);
                this.logChannel.show();
            }
            vscode.window.showInformationMessage('📋 Log mostrado');
        } catch (error) {
            vscode.window.showErrorMessage(`Error leyendo log: ${error}`);
        }
    }

    public verifyCurrentStatus() {
        const activeEditor = vscode.window.activeTextEditor;
        const fileName = activeEditor?.document.fileName;
        
        const status = this.isMonitoring ? '🟢 ACTIVO' : '🔴 INACTIVO';
        const message = `
✅ ESTADO DEL SISTEMA
============================
Estado: ${status}
Calificación Global: ${this.globalScore.toFixed(2)}/${this.maxScore}
Penalizaciones: ${this.globalPenaltyCount}/${this.config.maxPenalties}
Advertencias: ${this.globalWarningCount}/${this.config.maxWarnings}
Archivo activo: ${fileName ? path.basename(fileName) : 'Ninguno'}
Estudiante: ${this.currentSession?.studentName || 'No identificado'}
Sesión: ${this.currentSession?.sessionCode || 'No activa'}
Archivos monitoreados: ${this.fileMetrics.size}
Tiempo: ${this.isMonitoring ? this.calculateDuration() : 'N/A'}
============================`;

        vscode.window.showInformationMessage(message, '📊 Ver detalles')
            .then(selection => {
                if (selection === '📊 Ver detalles' && fileName) {
                    this.showDetailedReport(fileName);
                }
            });
    }

    public isMonitoringActive(): boolean {
        return this.isMonitoring;
    }

    // ==================== INTERCEPCIÓN DE PASTE ====================

    public async markPasteStarted() {
        this.pasteInProgress = true;
        setTimeout(() => { this.pasteInProgress = false; }, 500);

        const editor = vscode.window.activeTextEditor;
        const targetFile = editor?.document.fileName;

        try {
            const clipboardText = await vscode.env.clipboard.readText();
            this.pendingInternalPaste = targetFile
                ? this.isInternalCopyMatch(clipboardText, targetFile)
                : false;
        } catch {
            this.pendingInternalPaste = false;
        }

        setTimeout(() => { this.pendingInternalPaste = false; }, 500);
    }

    public markCopyStarted() {
        const editor = vscode.window.activeTextEditor;
        if (!editor) return;

        const text = editor.selections
            .map(sel => editor.document.getText(sel))
            .join('\n');

        if (text.trim().length > 0) {
            this.lastInternalCopy = {
                text: text,
                sourceFile: editor.document.fileName,
                timestamp: Date.now()
            };
        }
    }

    private isInternalCopyMatch(clipboardText: string, targetFileName: string): boolean {
        if (!this.lastInternalCopy) return false;

        const elapsed = Date.now() - this.lastInternalCopy.timestamp;
        if (elapsed > this.INTERNAL_COPY_VALID_MS) return false;

        if (this.lastInternalCopy.sourceFile !== targetFileName) return false;

        return clipboardText.trim() === this.lastInternalCopy.text.trim();
    }

    // ==================== INTERCEPCIÓN DE SUGERENCIAS (AUTOCOMPLETADO) ====================

    public markSuggestionAccepted() {
        this.pendingSuggestionAccept = true;
        setTimeout(() => { this.pendingSuggestionAccept = false; }, 500);
    }

    // ==================== LOGGING ====================

    private logEvent(eventType: string, message: string) {
        if (!this.logFile) return;

        const timestamp = new Date().toISOString();
        const logEntry = `[${timestamp}] ${eventType}\n` +
                        `Mensaje: ${message}\n` +
                        `---------------------------------\n`;

        try {
            fs.appendFileSync(this.logFile, logEntry, { encoding: 'utf8' });
        } catch (error) {
            console.error('Error escribiendo en log:', error);
        }
    }

    private logPenalty(
        fileName: string,
        penaltyAmount: number,
        actualReduction: number,
        contextAnalysis: ChangeAnalysis
    ) {
        if (!this.logFile) return;

        const logEntry = `[${new Date().toLocaleString()}] PENALIZACIÓN GLOBAL APLICADA\n` +
                        `Archivo origen: ${path.basename(fileName)}\n` +
                        `Estudiante: ${this.currentSession?.studentName || 'Estudiante'}\n` +
                        `Sesión: ${this.currentSession?.sessionCode || 'SESION'}\n` +
                        `Puntos restados: ${penaltyAmount.toFixed(2)}\n` +
                        `Reducción real: ${actualReduction.toFixed(2)}\n` +
                        `Calificación global actual: ${this.globalScore.toFixed(2)}/${this.maxScore}\n` +
                        `Total penalizaciones: ${this.globalPenaltyCount}\n` +
                        `Razón: ${contextAnalysis.reason}\n` +
                        `Confianza: ${(contextAnalysis.confidence * 100).toFixed(1)}%\n` +
                        `---------------------------------\n`;

        try {
            fs.appendFileSync(this.logFile, logEntry, { encoding: 'utf8' });
        } catch (error) {
            console.error('Error escribiendo en log:', error);
        }
    }

    // ==================== VERIFICACIÓN ====================

    private createVerificationFile() {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) return;

        const verificationFile = path.join(
            workspaceFolders[0].uri.fsPath,
            'VERIFICACION_MONITOREO.txt'
        );
        
        const content = this.generateVerificationContent();
        
        try {
            fs.writeFileSync(verificationFile, content, 'utf8');
            this.logEvent('ARCHIVO_VERIFICACION', 'Archivo de verificación creado');
        } catch (error) {
            console.error('Error creando archivo de verificación:', error);
        }
    }

    private generateVerificationContent(): string {
        return `
EVALUACIÓN EN CURSO - EXTENSIÓN ACTIVA
=======================================
Estudiante: ${this.currentSession?.studentName || 'No identificado'}
Código de Sesión: ${this.currentSession?.sessionCode || 'No activa'}
Fecha/Hora: ${new Date().toLocaleString()}
Versión: 3.1 (Contador Global Único)
Estado: 🟢 MONITOREO ACTIVO

CONFIGURACIÓN DEL SISTEMA:
- Nota inicial: ${this.maxScore} puntos
- Umbral de cambio: ${this.config.changeThreshold * 100}%
- Tiempo mínimo: ${this.config.timeThreshold}ms
- Longitud mínima: ${this.config.minCodeLength} caracteres
- Máx advertencias: ${this.config.maxWarnings}
- Penalización por infracción: -${this.config.penaltyAmount.toFixed(2)} puntos
- Máx penalizaciones: ${this.config.maxPenalties}

INSTRUCCIONES:
✅ NO cerrar VS Code
✅ Continuar programando normalmente
✅ Hacer cambios pequeños y frecuentes
❌ NO copiar y pegar código grande
❌ NO intentar evadir el sistema

El sistema aplica una calificación global única para todo el proyecto.
=======================================`;
    }

    // ==================== LIMPIEZA ====================

    public dispose() {
        this.stopMonitoring();
        this.clearAllTimeouts();
        if (this.statusBarItem) {
            this.statusBarItem.dispose();
            this.statusBarItem = null;
        }
        if (this.logChannel) {
            this.logChannel.dispose();
            this.logChannel = null;
        }
        this.logEvent('SISTEMA_DETENIDO', 'Recursos liberados correctamente');
    }
}

// ==================== EXPORTACIÓN ====================

export function activate(context: vscode.ExtensionContext) {
    const analyzer = new CodeAnalyzer();
    
    const commands = [
        vscode.commands.registerCommand('codeAnalyzer.startMonitoring', () => {
            analyzer.startVerificationMonitoring();
        }),
        vscode.commands.registerCommand('codeAnalyzer.stopMonitoring', () => {
            analyzer.stopMonitoring();
        }),
        vscode.commands.registerCommand('codeAnalyzer.showScore', () => {
            analyzer.showScore();
        }),
        vscode.commands.registerCommand('codeAnalyzer.showDetailedReport', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                analyzer.showDetailedReport(editor.document.fileName);
            } else {
                vscode.window.showWarningMessage('No hay archivo activo');
            }
        }),
        vscode.commands.registerCommand('codeAnalyzer.generateFinalReport', () => {
            analyzer.generateFinalReport();
        }),
        vscode.commands.registerCommand('codeAnalyzer.resetScores', () => {
            analyzer.resetScores();
        }),
        vscode.commands.registerCommand('codeAnalyzer.showLog', () => {
            analyzer.showLogFile();
        }),
        vscode.commands.registerCommand('codeAnalyzer.verifyStatus', () => {
            analyzer.verifyCurrentStatus();
        }),
        vscode.commands.registerCommand('codeAnalyzer.generatePdfReport', () => {
            analyzer.generatePdfReport();
        }),
        vscode.commands.registerCommand('codeAnalyzer.deactivateExtension', () => {
            analyzer.dispose();
        }),
        vscode.commands.registerCommand('codeAnalyzer.interceptPaste', async () => {
            await analyzer.markPasteStarted();
            await vscode.commands.executeCommand('editor.action.clipboardPasteAction');
        }),
        vscode.commands.registerCommand('codeAnalyzer.interceptCopy', async () => {
            analyzer.markCopyStarted();
            await vscode.commands.executeCommand('editor.action.clipboardCopyAction');
        }),
        vscode.commands.registerCommand('codeAnalyzer.interceptCut', async () => {
            analyzer.markCopyStarted();
            await vscode.commands.executeCommand('editor.action.clipboardCutAction');
        }),
        vscode.commands.registerCommand('codeAnalyzer.acceptSuggestionTab', async () => {
            analyzer.markSuggestionAccepted();
            await vscode.commands.executeCommand('acceptSelectedSuggestion');
        }),
        vscode.commands.registerCommand('codeAnalyzer.acceptSuggestionEnter', async () => {
            analyzer.markSuggestionAccepted();
            await vscode.commands.executeCommand('acceptSelectedSuggestion');
        })
    ];

    context.subscriptions.push(...commands);

    context.subscriptions.push({
        dispose: () => {
            analyzer.dispose();
        }
    });
}

export function deactivate() {
    // Cleanup handled by disposers
}