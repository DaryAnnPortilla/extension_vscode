import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { PdfReportGenerator, PdfReportData } from './pdfGenerator';
import { SAFE_PATTERNS, SAFE_PATTERN_MAX_LENGTH, isAutoClosedMarkup } from './safePatterns';
import { askStudentNameModal } from './studentModal';

// ==================== TIPOS ====================

interface SuspiciousSnippet {
    timestamp: string;
    code: string;
    reason: string;
}

interface FileMetrics {
    fileName: string;
    lastText: string;
    lastChangeTimestamp: number;
    changeHistory: number[];
    safeOperations: number;
    totalChangesAnalyzed: number;
    consecutiveChanges: number;
    lastChangeWasSafe: boolean;
    isInitializing: boolean;
    trustedSource: boolean;
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

interface ChangeContext {
    addedLength: number;
    previousLength: number;
    currentLength: number;
    timeDiff: number;
    consecutiveChanges: number;
    lastChangeWasSafe: boolean;
    isInitializing: boolean;
    isExternalPaste: boolean;
    isRecentFocusRegain: boolean;
}

interface AnalysisConfig {
    maxScore: number;
    penaltyAmount: number;
    maxWarnings: number;
    changeThreshold: number;
    timeThreshold: number;
    minCodeLength: number;
    minSuspiciousLength: number;
    minAbruptPasteLength: number;
    initializationTime: number;
    maxHistoryLength: number;
}

type FlagName = 'paste' | 'suggestion';

// ==================== CONSTANTES ====================

const VERSION = '3.2 (Contador Global Único)';

const DEFAULT_CONFIG: AnalysisConfig = {
    maxScore: 10,
    penaltyAmount: 0.25,
    maxWarnings: 2,
    changeThreshold: 0.6,
    timeThreshold: 1500,
    minCodeLength: 50,
    minSuspiciousLength: 40,
    minAbruptPasteLength: 120,
    initializationTime: 15000,
    maxHistoryLength: 20
};

const FLAG_WINDOW_MS = 400;
const FOCUS_REGAIN_WINDOW_MS = 3000;
const SNIPPET_MAX_LENGTH = 300;
const MIN_MATCH_LENGTH = 20;
const MAX_COMPLETION_LENGTH = 85;
const MAX_COMPLETION_LINES = 3;
const MONITORED_SCHEMES = ['file', 'untitled'];
const UNSUPPORTED_EXTENSIONS = ['.log', '.txt', '.md', '.json', '.xml', '.yml', '.yaml'];

// Quita espacios: compara contenido ignorando indentación
const squash = (text: string) => text.replace(/\s+/g, '');
// Quita además lo que suele tocar un formateador (comillas, punto y coma, comas, paréntesis)
const squashFormatting = (text: string) => text.replace(/[\s;,'"`()]/g, '');

// ==================== CLASE PRINCIPAL ====================

export class CodeAnalyzer {
    private config: AnalysisConfig = { ...DEFAULT_CONFIG };
    private fileMetrics = new Map<string, FileMetrics>();
    private initTimeouts = new Map<string, NodeJS.Timeout>();

    // Estado global del estudiante: la nota se calcula a partir de las penalizaciones
    private warningCount = 0;
    private penaltyCount = 0;
    private totalSafeOperations = 0;

    private isMonitoring = false;
    private currentSession: SessionData | null = null;
    private startTime = 0;

    // Canales visuales en VS Code (sin archivos .txt en disco)
    private detailChannel: vscode.OutputChannel | null = null;
    private finalReportChannel: vscode.OutputChannel | null = null;
    private statusBarItem: vscode.StatusBarItem | null = null;

    private disposables: vscode.Disposable[] = [];
    private periodicTimer: NodeJS.Timeout | null = null;

    // Ventanas de tiempo que abren los comandos interceptados (Ctrl+V, Tab/Enter en sugerencias)
    private flagUntil: Record<FlagName, number> = { paste: 0, suggestion: 0 };
    private windowFocused = true;
    private lastFocusRegainedTimestamp: number | null = null;

    constructor() {
        this.loadConfigFromVSCode();
        this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
        this.statusBarItem.command = 'codeAnalyzer.verifyStatus';
        this.updateStatusBar();
    }

    // ==================== VALORES DERIVADOS ====================

    private get score(): number {
        const raw = this.config.maxScore - this.penaltyCount * this.config.penaltyAmount;
        return Math.max(0, Math.round(raw * 100) / 100);
    }

    private get maxPenalties(): number {
        return Math.ceil(this.config.maxScore / this.config.penaltyAmount);
    }

    private get scoreText(): string {
        return `${this.score.toFixed(2)}/${this.config.maxScore}`;
    }

    private get pointsLost(): string {
        return (this.config.maxScore - this.score).toFixed(2);
    }

    private get studentName(): string {
        return this.currentSession?.studentName ?? 'No identificado';
    }

    private get sessionCode(): string {
        return this.currentSession?.sessionCode ?? 'Sin sesión';
    }

    // ==================== CONFIGURACIÓN ====================

    private loadConfigFromVSCode() {
        const vsConfig = vscode.workspace.getConfiguration('codeAnalyzer');
        const config = { ...DEFAULT_CONFIG };
        for (const key of Object.keys(DEFAULT_CONFIG) as (keyof AnalysisConfig)[]) {
            config[key] = vsConfig.get<number>(key, DEFAULT_CONFIG[key]);
        }
        if (config.penaltyAmount <= 0) {
            config.penaltyAmount = DEFAULT_CONFIG.penaltyAmount;
        }
        this.config = config;
    }

    private getWorkspaceRoot(): string | null {
        const folders = vscode.workspace.workspaceFolders;
        return folders && folders.length > 0 ? folders[0].uri.fsPath : null;
    }

    // ==================== INICIO / DETENCIÓN ====================

    public async startVerificationMonitoring() {
        if (this.isMonitoring) {
            const response = await vscode.window.showWarningMessage(
                'El monitoreo ya está activo. ¿Deseas reiniciarlo?', 'Sí', 'No'
            );
            if (response !== 'Sí') return;
            await this.stopMonitoring();
        }

        const root = this.getWorkspaceRoot();
        if (!root) {
            vscode.window.showErrorMessage('❌ No hay workspace abierto. Abre una carpeta para comenzar.');
            return;
        }

        const studentName = await askStudentNameModal();
        if (!studentName) {
            vscode.window.showErrorMessage('❌ Evaluación cancelada: debes ingresar tu nombre');
            return;
        }

        this.currentSession = { studentName, sessionCode: this.generateSessionCode() };
        this.startMonitoring();

        vscode.window.showInformationMessage(
            `✅ Evaluación iniciada — ${this.studentName} | Sesión: ${this.sessionCode} | Nota: ${this.scoreText}`
        );
    }

    private generateSessionCode(): string {
        const timestamp = Date.now().toString(36).toUpperCase().slice(-6);
        const random = Math.random().toString(36).substring(2, 5).toUpperCase();
        return `STU${timestamp}${random}`;
    }

    private resetCounters() {
        this.clearInitTimeouts();
        this.fileMetrics.clear();
        this.warningCount = 0;
        this.penaltyCount = 0;
        this.totalSafeOperations = 0;
        this.flagUntil = { paste: 0, suggestion: 0 };
        this.lastFocusRegainedTimestamp = null;
    }

    private startMonitoring() {
        this.loadConfigFromVSCode();
        this.resetCounters();
        this.isMonitoring = true;
        this.startTime = Date.now();

        vscode.workspace.textDocuments.forEach(doc => {
            if (this.isSupportedFile(doc)) {
                this.initializeFileMetrics(doc, true);
            }
        });

        this.setupEventListeners();
        this.updateStatusBar();
    }

    public async stopMonitoring() {
        if (!this.isMonitoring) return;

        this.isMonitoring = false;
        this.clearInitTimeouts();
        this.disposeListeners();
        this.updateStatusBar();

        if (this.fileMetrics.size > 0) {
            await this.generatePdfReport();
        }
        vscode.window.showInformationMessage('⏹️ Monitoreo finalizado');
    }

    private clearInitTimeouts() {
        this.initTimeouts.forEach(id => clearTimeout(id));
        this.initTimeouts.clear();
    }

    // ==================== EVENT LISTENERS ====================

    private setupEventListeners() {
        this.disposables.push(
            vscode.workspace.onDidChangeTextDocument(event => this.handleDocumentChange(event)),
            vscode.workspace.onDidOpenTextDocument(doc => {
                if (this.isSupportedFile(doc)) {
                    this.initializeFileMetrics(doc, false);
                }
            }),
            vscode.window.onDidChangeWindowState(state => this.handleWindowStateChange(state))
        );

        this.periodicTimer = setInterval(() => {
            this.updateStatusBar();
        }, 60000);
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
        if (state.focused && !this.windowFocused) {
            this.lastFocusRegainedTimestamp = Date.now();
        }
        this.windowFocused = state.focused;
    }

    private handleDocumentChange(event: vscode.TextDocumentChangeEvent) {
        if (!this.isMonitoring || event.contentChanges.length === 0 || !this.isSupportedFile(event.document)) {
            return;
        }

        const metrics = this.fileMetrics.get(event.document.fileName);
        if (!metrics) {
            this.initializeFileMetrics(event.document, false);
            return;
        }

        const currentText = event.document.getText();

        // Deshacer/rehacer y formateo (Prettier, Shift+Alt+F, formatOnSave/Paste) no son escritura nueva
        const isHistory = event.reason === vscode.TextDocumentChangeReason.Undo ||
                          event.reason === vscode.TextDocumentChangeReason.Redo;
        if (isHistory || this.isFormattingOnly(event.contentChanges, metrics.lastText)) {
            metrics.lastText = currentText;
            metrics.lastChangeTimestamp = Date.now();
            return;
        }

        this.analyzeCodeChange(event.contentChanges, metrics, currentText);
    }

    // ==================== MÉTRICAS POR ARCHIVO ====================

    private initializeFileMetrics(document: vscode.TextDocument, atSessionStart: boolean): FileMetrics {
        const fileName = document.fileName;
        const existing = this.fileMetrics.get(fileName);
        if (existing) return existing;

        const text = document.getText();
        const insideWorkspace = document.uri.scheme === 'untitled' || !!vscode.workspace.getWorkspaceFolder(document.uri);
        const contentIsOwn = atSessionStart || text.trim().length === 0 ||
            this.existedBeforeSession(fileName) || this.matchesTrackedContent(text);

        const metrics: FileMetrics = {
            fileName,
            lastText: text,
            lastChangeTimestamp: Date.now(),
            changeHistory: [],
            safeOperations: 0,
            totalChangesAnalyzed: 0,
            consecutiveChanges: 0,
            lastChangeWasSafe: true,
            isInitializing: atSessionStart,
            trustedSource: insideWorkspace && contentIsOwn,
            suspiciousSnippets: []
        };
        this.fileMetrics.set(fileName, metrics);

        if (atSessionStart) {
            this.initTimeouts.set(fileName, setTimeout(() => {
                metrics.isInitializing = false;
                this.initTimeouts.delete(fileName);
            }, this.config.initializationTime));
        }

        if (insideWorkspace && !contentIsOwn) {
            this.handleExternalFile(metrics, text);
        }

        return metrics;
    }

    // Archivo que aparece durante la sesión con contenido externo copiado a la carpeta
    private handleExternalFile(metrics: FileMetrics, text: string) {
        if (squash(text).length >= this.config.minSuspiciousLength) {
            const analysis: ChangeAnalysis = {
                isAbrupt: true,
                reason: 'archivo_con_contenido_externo',
                confidence: 1,
                abruptnessScore: 1
            };
            this.recordSuspiciousSnippet(metrics, text, analysis.reason);
            this.applyPenalty(metrics.fileName, analysis);
        }

        metrics.trustedSource = true;
    }

    private existedBeforeSession(fileName: string): boolean {
        try {
            const stats = fs.statSync(fileName);
            return (stats.birthtimeMs || stats.ctimeMs) < this.startTime;
        } catch {
            return false;
        }
    }

    // ¿El texto ya existe en algún archivo propio monitoreado? (copia interna entre archivos)
    private matchesTrackedContent(text: string): boolean {
        const needle = squash(text);
        if (needle.length < MIN_MATCH_LENGTH) return false;

        for (const metrics of this.fileMetrics.values()) {
            if (metrics.trustedSource && squash(metrics.lastText).includes(needle)) {
                return true;
            }
        }
        return false;
    }

    private isFormattingOnly(changes: readonly vscode.TextDocumentContentChangeEvent[], previousText: string): boolean {
        return changes.every(change => {
            const replaced = previousText.slice(change.rangeOffset, change.rangeOffset + change.rangeLength);
            return squashFormatting(replaced) === squashFormatting(change.text);
        });
    }

    // ==================== ANÁLISIS DE CÓDIGO ====================

    private analyzeCodeChange(
        changes: readonly vscode.TextDocumentContentChangeEvent[],
        metrics: FileMetrics,
        currentText: string
    ) {
        const now = Date.now();
        const timeDiff = now - metrics.lastChangeTimestamp;
        const previousLength = metrics.lastText.length;
        const insertedText = changes.map(c => c.text).join('\n');
        const addedLength = changes.reduce((sum, c) => sum + c.text.length, 0);

        const isExplicitPaste = this.isFlagActive('paste');
        const isSuggestionAccept = !isExplicitPaste && this.isFlagActive('suggestion');
        const isFromWorkspace = addedLength >= this.config.minSuspiciousLength && this.matchesTrackedContent(insertedText);
        const isExternalPaste = isExplicitPaste && !isFromWorkspace;

        // Autocompletado nativo (teclado o clic con ratón): solo se evalúa si NO hubo pegado externo
        const isCompletion = !isExternalPaste && this.isNativeCompletion(changes);

        const isSafe = isFromWorkspace || isSuggestionAccept || isCompletion ||
                       (!isExplicitPaste && this.areSafeInsertions(changes));

        const analysis = this.analyzeChangeContext({
            addedLength,
            previousLength,
            currentLength: currentText.length,
            timeDiff,
            consecutiveChanges: metrics.consecutiveChanges,
            lastChangeWasSafe: metrics.lastChangeWasSafe,
            isInitializing: metrics.isInitializing,
            isExternalPaste,
            isRecentFocusRegain: this.lastFocusRegainedTimestamp !== null &&
                (now - this.lastFocusRegainedTimestamp) < FOCUS_REGAIN_WINDOW_MS
        });

        if (isSafe) {
            this.totalSafeOperations++;
            metrics.safeOperations++;
            metrics.consecutiveChanges = 0; // Reinicia ráfagas para no castigar el uso fluido de IntelliSense
        } else {
            metrics.consecutiveChanges = timeDiff < 2000 ? metrics.consecutiveChanges + 1 : 0;
        }

        metrics.totalChangesAnalyzed++;
        metrics.lastChangeWasSafe = isSafe;
        this.recordChangeHistory(metrics, previousLength, currentText.length, analysis, isSafe);

        if (analysis.isAbrupt && !isSafe && analysis.confidence > 0.7) {
            this.recordSuspiciousSnippet(metrics, insertedText, analysis.reason);
            this.applyPenalty(metrics.fileName, analysis);
        }

        metrics.lastChangeTimestamp = now;
        metrics.lastText = currentText;
    }

    /**
     * Reconoce sugerencias aceptadas de IntelliSense/Emmet tanto por teclado como por clic del ratón:
     * reemplazos parciales de palabras, métodos con argumentos cortos, autocierre de etiquetas y
     * saltos de línea con auto-indentación.
     */
    private isNativeCompletion(changes: readonly vscode.TextDocumentContentChangeEvent[]): boolean {
        if (changes.length === 0) return false;

        const firstText = changes[0].text;
        const isUniformChange = changes.every(c => c.text === firstText);
        if (!isUniformChange && changes.length > 2) return false;

        return changes.every(change => {
            const inserted = change.text;
            const trimmed = inserted.trim();

            // Borrados puros o auto-indentación al presionar Enter
            if (trimmed.length === 0) return true;

            const lineCount = (inserted.match(/\n/g) || []).length + 1;
            if (inserted.length > MAX_COMPLETION_LENGTH || lineCount > MAX_COMPLETION_LINES) {
                return false;
            }

            // Reemplazo de palabra parcial escrita por el estudiante (ej. "doc" -> "document")
            if (change.rangeLength > 0 && trimmed.length <= MAX_COMPLETION_LENGTH) {
                return true;
            }

            // Inserción por clic tras punto, llamada a método con parámetros cortos, cierre o atributo HTML
            const identifierOrCallPattern = /^[\w$@#.:-]+(?:\([^()\n]{0,40}\))?;?$/;
            const htmlClosingTagPattern = /^<\/[a-zA-Z][\w-]*>$/;
            const htmlAttributePattern = /^[a-zA-Z-]+=["'][^"']*["']$/;

            return identifierOrCallPattern.test(trimmed) ||
                   htmlClosingTagPattern.test(trimmed) ||
                   htmlAttributePattern.test(trimmed);
        });
    }

    private analyzeChangeContext(ctx: ChangeContext): ChangeAnalysis {
        const notAbrupt = (reason: string): ChangeAnalysis =>
            ({ isAbrupt: false, reason, confidence: 0, abruptnessScore: 0 });
        const cfg = this.config;

        if (ctx.isInitializing) return notAbrupt('inicializacion');
        if (ctx.addedLength < cfg.minSuspiciousLength) return notAbrupt('cambio_pequeño');

        let score = 0;
        const isBigInsertion = ctx.addedLength >= cfg.minAbruptPasteLength;

        // Evidencia 1: tamaño de lo insertado
        if (isBigInsertion) {
            score += 0.4;
            if (ctx.addedLength >= cfg.minAbruptPasteLength * 2) score += 0.2;
        }

        // Evidencia 2: Ctrl+V de un texto que no existe en el proyecto
        if (ctx.isExternalPaste) {
            score += isBigInsertion ? 0.5 : 0.35;
            if (ctx.isRecentFocusRegain) score += 0.3;
        } else if (ctx.isRecentFocusRegain && isBigInsertion) {
            score += 0.15;
        }

        // Evidencia 3: proporción respecto al archivo (solo si ya tenía contenido)
        const changeRatio = ctx.previousLength >= cfg.minCodeLength
            ? Math.abs(ctx.currentLength - ctx.previousLength) / ctx.previousLength
            : 0;
        if (changeRatio > cfg.changeThreshold) {
            score += 0.4;
            if (changeRatio > 0.8) score += 0.2;
        }

        if (score === 0) return notAbrupt('cambio_normal');

        // Refuerzos de ritmo
        if (ctx.timeDiff < cfg.timeThreshold) {
            score += 0.3;
            if (ctx.timeDiff < 500) score += 0.1;
        }
        if (ctx.consecutiveChanges > 3) {
            score += 0.2;
            if (ctx.consecutiveChanges > 5) score += 0.1;
        }
        if (!ctx.lastChangeWasSafe) score += 0.1;

        const isAbrupt = score > 0.6;
        return {
            isAbrupt,
            reason: isAbrupt ? this.describeReason(ctx, changeRatio) : 'cambio_normal',
            confidence: Math.min(score + 0.2, 1),
            abruptnessScore: score
        };
    }

    private describeReason(ctx: ChangeContext, changeRatio: number): string {
        if (ctx.isExternalPaste && ctx.isRecentFocusRegain) return 'paste_tras_perdida_de_foco';
        if (ctx.isExternalPaste) return 'paste_externo_detectado';
        if (ctx.addedLength >= this.config.minAbruptPasteLength * 2) return 'insercion_grande_detectada';
        if (ctx.addedLength >= this.config.minAbruptPasteLength) return 'insercion_abrupta_detectada';
        if (changeRatio > this.config.changeThreshold) return 'cambio_masivo_detectado';
        return 'patron_sospechoso';
    }

    private areSafeInsertions(changes: readonly vscode.TextDocumentContentChangeEvent[]): boolean {
        return changes.every(change => this.isSafeInsertion(change.text));
    }

    private isSafeInsertion(text: string): boolean {
        if (text.trim().length <= 3) return true;
        if (isAutoClosedMarkup(text)) return true;
        return text.length <= SAFE_PATTERN_MAX_LENGTH && SAFE_PATTERNS.some(pattern => pattern.test(text));
    }

    private recordChangeHistory(
        metrics: FileMetrics,
        previousLength: number,
        currentLength: number,
        analysis: ChangeAnalysis,
        isSafe: boolean
    ) {
        if (analysis.isAbrupt || isSafe || previousLength <= 0) return;

        const changeRatio = Math.abs(currentLength - previousLength) / previousLength;
        if (changeRatio > 0.01) {
            metrics.changeHistory.push(changeRatio);
            if (metrics.changeHistory.length > this.config.maxHistoryLength) {
                metrics.changeHistory = metrics.changeHistory.slice(-this.config.maxHistoryLength);
            }
        }
    }

    private recordSuspiciousSnippet(metrics: FileMetrics, text: string, reason: string) {
        const code = text.trim();
        if (code.length === 0) return;

        metrics.suspiciousSnippets.push({
            timestamp: new Date().toLocaleTimeString(),
            code: code.length > SNIPPET_MAX_LENGTH
                ? `${code.slice(0, SNIPPET_MAX_LENGTH)}\n… (código truncado)`
                : code,
            reason
        });
    }

    // ==================== PENALIZACIONES ====================

    private applyPenalty(fileName: string, analysis: ChangeAnalysis) {
        if (this.warningCount < this.config.maxWarnings) {
            this.warningCount++;
            this.showWarning(fileName, analysis);
            return;
        }

        if (this.score <= 0) {
            return;
        }

        this.penaltyCount++;
        this.showPenaltyNotification(fileName, analysis);
        this.updateStatusBar();
    }

    private showWarning(fileName: string, analysis: ChangeAnalysis) {
        const remaining = this.config.maxWarnings - this.warningCount;
        const detail = `Archivo: ${path.basename(fileName)}\n` +
                       `Razón: ${analysis.reason}\n` +
                       `${remaining} advertencia(s) restante(s) antes de penalizar (-${this.config.penaltyAmount.toFixed(2)}p)`;

        vscode.window.showWarningMessage(
            `⚠️ Advertencia ${this.warningCount}/${this.config.maxWarnings}`, { detail }, '📊 Ver detalles'
        ).then(selection => {
            if (selection === '📊 Ver detalles') this.showDetailedReport(fileName);
        });
    }

    private showPenaltyNotification(fileName: string, analysis: ChangeAnalysis) {
        const detail = `Archivo: ${path.basename(fileName)}\n` +
                       `Razón: ${analysis.reason}\n` +
                       `Nota actual: ${this.scoreText}\n` +
                       `Penalizaciones: ${this.penaltyCount}/${this.maxPenalties}`;

        vscode.window.showWarningMessage(
            `⚖️ Penalización aplicada: -${this.config.penaltyAmount.toFixed(2)}p`, { detail }, '📊 Ver detalles'
        ).then(selection => {
            if (selection === '📊 Ver detalles') this.showDetailedReport(fileName);
        });
    }

    // ==================== UTILIDADES ====================

    private isSupportedFile(document: vscode.TextDocument): boolean {
        if (!MONITORED_SCHEMES.includes(document.uri.scheme)) return false;
        const ext = path.extname(document.fileName).toLowerCase();
        return !UNSUPPORTED_EXTENSIONS.includes(ext) && document.languageId !== 'plaintext';
    }

    private isFlagActive(name: FlagName): boolean {
        return Date.now() < this.flagUntil[name];
    }

    private activateFlag(name: FlagName) {
        this.flagUntil[name] = Date.now() + FLAG_WINDOW_MS;
    }

    public markPasteStarted() {
        this.activateFlag('paste');
    }

    public markSuggestionAccepted() {
        this.activateFlag('suggestion');
    }

    private updateStatusBar() {
        if (!this.statusBarItem) return;

        if (this.isMonitoring) {
            this.statusBarItem.text = `$(graph) Nota: ${this.scoreText} (${this.fileMetrics.size} archivos)`;
            this.statusBarItem.tooltip =
                `Code Analyzer activo\n` +
                `Nota: ${this.scoreText}\n` +
                `Advertencias: ${this.warningCount}/${this.config.maxWarnings}\n` +
                `Penalizaciones: ${this.penaltyCount}/${this.maxPenalties}\n` +
                `Archivos monitoreados: ${this.fileMetrics.size}`;
        } else {
            this.statusBarItem.text = '$(circle-slash) Code Analyzer: Inactivo';
            this.statusBarItem.tooltip = 'Code Analyzer inactivo - Haz clic para ver el estado';
        }
        this.statusBarItem.show();
    }

    // ==================== REPORTES ====================

    private calculateAverageChange(metrics: FileMetrics): number {
        if (metrics.changeHistory.length === 0) return 0;
        return metrics.changeHistory.reduce((a, b) => a + b, 0) / metrics.changeHistory.length;
    }

    private calculateEffectiveness(totalSafeOps: number, totalChanges: number): string {
        return totalChanges > 0 ? ((totalSafeOps / totalChanges) * 100).toFixed(1) : '0.0';
    }

    private calculateDuration(): string {
        const duration = Date.now() - this.startTime;
        const minutes = Math.floor(duration / 60000);
        const seconds = Math.floor((duration % 60000) / 1000);
        return `${minutes} minutos, ${seconds} segundos`;
    }

    private aggregateSessionMetrics() {
        let totalSafeOps = 0;
        let totalChanges = 0;
        const fileDetails: PdfReportData['fileDetails'] = [];
        const allSnippets: PdfReportData['suspiciousSnippets'] = [];

        this.fileMetrics.forEach((metrics, fileName) => {
            const baseName = path.basename(fileName);
            totalSafeOps += metrics.safeOperations;
            totalChanges += metrics.totalChangesAnalyzed;

            fileDetails.push({
                fileName: baseName,
                safeOps: metrics.safeOperations,
                changesAnalyzed: metrics.totalChangesAnalyzed,
                suspiciousCount: metrics.suspiciousSnippets.length
            });

            metrics.suspiciousSnippets.forEach(s => {
                allSnippets.push({ fileName: baseName, timestamp: s.timestamp, reason: s.reason, code: s.code });
            });
        });

        return { totalSafeOps, totalChanges, fileDetails, allSnippets };
    }

    private getChannel(kind: 'detail' | 'final'): vscode.OutputChannel {
        if (kind === 'detail') {
            return this.detailChannel ??= vscode.window.createOutputChannel('Code Analyzer - Reporte Detallado');
        }
        return this.finalReportChannel ??= vscode.window.createOutputChannel('Code Analyzer - Reporte Final');
    }

    private showInChannel(kind: 'detail' | 'final', content: string) {
        const channel = this.getChannel(kind);
        channel.clear();
        channel.appendLine(content);
        channel.show();
    }

    public showDetailedReport(fileName: string) {
        const metrics = this.fileMetrics.get(fileName);
        if (!metrics) {
            vscode.window.showWarningMessage('No hay datos de análisis para este archivo');
            return;
        }

        const avgChange = this.calculateAverageChange(metrics);
        const snippetsSection = metrics.suspiciousSnippets.length === 0
            ? '✅ Ningún código copiado detectado en este archivo.'
            : metrics.suspiciousSnippets.map((s, i) =>
                `Fragmento ${i + 1}:\n[${s.timestamp}] Motivo: ${s.reason}\n\`\`\`\n${s.code}\n\`\`\``
            ).join('\n\n');

        this.showInChannel('detail', `📊 REPORTE DETALLADO — VERSIÓN ${VERSION}
=================================
Archivo: ${path.basename(metrics.fileName)}
Estudiante: ${this.studentName}
Sesión: ${this.sessionCode}

ESTADO GLOBAL DE EVALUACIÓN:
• Nota: ${this.scoreText}
• Penalizaciones: ${this.penaltyCount}/${this.maxPenalties} (-${this.pointsLost} pts)
• Advertencias: ${this.warningCount}/${this.config.maxWarnings}

MÉTRICAS DEL ARCHIVO:
• Operaciones seguras: ${metrics.safeOperations}
• Cambios analizados: ${metrics.totalChangesAnalyzed}
• Promedio de cambio: ${(avgChange * 100).toFixed(1)}%
• Modo inicialización: ${metrics.isInitializing ? 'ACTIVO' : 'INACTIVO'}

HISTORIAL DE CAMBIOS (últimos 10):
${metrics.changeHistory.slice(-10).map((r, i) => `  ${i + 1}. ${(r * 100).toFixed(1)}%`).join('\n') || '  (sin registros)'}

FRAGMENTOS SOSPECHOSOS EN ESTE ARCHIVO:
${snippetsSection}

RECOMENDACIONES:
✅ Escribe código progresivamente
✅ Evita copiar y pegar bloques grandes
✅ Comprende cada línea que escribes
=================================`);
    }

    public async generateFinalReport() {
        if (this.fileMetrics.size === 0) {
            vscode.window.showWarningMessage('No hay datos de monitoreo para generar el reporte');
            return;
        }

        const { totalSafeOps, totalChanges } = this.aggregateSessionMetrics();
        let report = `📈 REPORTE FINAL DE EVALUACIÓN — VERSIÓN ${VERSION}\n` +
                     `===============================\n` +
                     `Fecha: ${new Date().toLocaleString()}\n` +
                     `Estudiante: ${this.studentName}\n` +
                     `Sesión: ${this.sessionCode}\n` +
                     `Duración: ${this.calculateDuration()}\n` +
                     `Archivos analizados: ${this.fileMetrics.size}\n\n` +
                     `🏆 CALIFICACIÓN:\n` +
                     `   Nota final: ${this.scoreText}\n` +
                     `   Penalizaciones: ${this.penaltyCount} (-${this.pointsLost} pts)\n` +
                     `   Advertencias: ${this.warningCount}\n\n`;

        this.fileMetrics.forEach((metrics, fileName) => {
            report += `📄 ${path.basename(fileName)}\n` +
                      `   Operaciones seguras: ${metrics.safeOperations}\n` +
                      `   Cambios analizados: ${metrics.totalChangesAnalyzed}\n` +
                      `   Fragmentos sospechosos: ${metrics.suspiciousSnippets.length}\n` +
                      `   -----------------------------------\n`;
        });

        report += `\n🎯 RESUMEN:\n` +
                  `Total operaciones seguras: ${totalSafeOps}\n` +
                  `Total cambios analizados: ${totalChanges}\n` +
                  `Efectividad: ${this.calculateEffectiveness(totalSafeOps, totalChanges)}%\n` +
                  `===============================\n`;

        this.showInChannel('final', report);
        await this.generatePdfReport();
    }

    public async generatePdfReport() {
        if (this.fileMetrics.size === 0) {
            vscode.window.showWarningMessage('No hay datos de monitoreo para generar el PDF');
            return;
        }

        const root = this.getWorkspaceRoot();
        if (!root) {
            vscode.window.showErrorMessage('❌ Se requiere una carpeta abierta para guardar el reporte.');
            return;
        }

        const { totalSafeOps, totalChanges, fileDetails, allSnippets } = this.aggregateSessionMetrics();
        const pdfPath = path.join(
            root,
            `REPORTE_EVALUACION_${this.sessionCode}_${new Date().toISOString().slice(0, 10)}.pdf`
        );

        const pdfData: PdfReportData = {
            studentName: this.studentName,
            sessionCode: this.sessionCode,
            duration: this.calculateDuration(),
            totalFiles: this.fileMetrics.size,
            safeOperations: this.totalSafeOperations,
            totalPenalties: this.penaltyCount,
            totalWarnings: this.warningCount,
            finalScore: this.score,
            maxScore: this.config.maxScore,
            penaltyAmount: this.config.penaltyAmount,
            effectiveness: this.calculateEffectiveness(totalSafeOps, totalChanges),
            fileDetails,
            suspiciousSnippets: allSnippets
        };

        try {
            await PdfReportGenerator.generatePdf(pdfPath, pdfData);
            vscode.window.showInformationMessage(`📄 Reporte PDF generado: ${path.basename(pdfPath)}`);
        } catch (error) {
            vscode.window.showErrorMessage(`Error al generar el reporte PDF: ${error}`);
        }
    }

    // ==================== COMANDOS PÚBLICOS ====================

    public showScore() {
        vscode.window.showInformationMessage(
            `🎯 Nota: ${this.scoreText} | Penalizaciones: ${this.penaltyCount} | ` +
            `Advertencias: ${this.warningCount}/${this.config.maxWarnings}`
        );
    }

    public resetScores() {
        this.resetCounters();
        this.updateStatusBar();
        vscode.window.showInformationMessage(`🔄 Calificación reiniciada a ${this.scoreText}`);
    }

    public verifyCurrentStatus() {
        const fileName = vscode.window.activeTextEditor?.document.fileName;
        const message =
            `Estado: ${this.isMonitoring ? '🟢 ACTIVO' : '🔴 INACTIVO'} | ` +
            `Nota: ${this.scoreText} | ` +
            `Advertencias: ${this.warningCount}/${this.config.maxWarnings} | ` +
            `Penalizaciones: ${this.penaltyCount}/${this.maxPenalties} | ` +
            `Estudiante: ${this.studentName} | ` +
            `Archivos: ${this.fileMetrics.size}` +
            (this.isMonitoring ? ` | Tiempo: ${this.calculateDuration()}` : '');

        vscode.window.showInformationMessage(message, '📊 Ver detalles').then(selection => {
            if (selection === '📊 Ver detalles' && fileName) {
                this.showDetailedReport(fileName);
            }
        });
    }

    // ==================== LIMPIEZA ====================

    public dispose() {
        this.clearInitTimeouts();
        this.disposeListeners();
        this.statusBarItem?.dispose();
        this.detailChannel?.dispose();
        this.finalReportChannel?.dispose();
        this.statusBarItem = null;
        this.detailChannel = null;
        this.finalReportChannel = null;
    }
}

// ==================== ACTIVACIÓN Y DESACTIVACIÓN ====================

let analyzerInstance: CodeAnalyzer | undefined;

export function activate(context: vscode.ExtensionContext) {
    const analyzer = new CodeAnalyzer();
    analyzerInstance = analyzer;

    const intercept = (id: string, nativeCommand: string, notify?: () => void) =>
        vscode.commands.registerCommand(id, async () => {
            notify?.();
            await vscode.commands.executeCommand(nativeCommand);
        });

    context.subscriptions.push(
        vscode.commands.registerCommand('codeAnalyzer.startMonitoring', () => analyzer.startVerificationMonitoring()),
        vscode.commands.registerCommand('codeAnalyzer.stopMonitoring', () => analyzer.stopMonitoring()),
        vscode.commands.registerCommand('codeAnalyzer.showScore', () => analyzer.showScore()),
        vscode.commands.registerCommand('codeAnalyzer.showDetailedReport', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                analyzer.showDetailedReport(editor.document.fileName);
            } else {
                vscode.window.showWarningMessage('No hay archivo activo');
            }
        }),
        vscode.commands.registerCommand('codeAnalyzer.generateFinalReport', () => analyzer.generateFinalReport()),
        vscode.commands.registerCommand('codeAnalyzer.resetScores', () => analyzer.resetScores()),
        vscode.commands.registerCommand('codeAnalyzer.verifyStatus', () => analyzer.verifyCurrentStatus()),
        vscode.commands.registerCommand('codeAnalyzer.generatePdfReport', () => analyzer.generatePdfReport()),
        vscode.commands.registerCommand('codeAnalyzer.deactivateExtension', async () => {
            await analyzer.stopMonitoring();
            analyzer.dispose();
        }),

        intercept('codeAnalyzer.interceptPaste', 'editor.action.clipboardPasteAction', () => analyzer.markPasteStarted()),
        intercept('codeAnalyzer.interceptCopy', 'editor.action.clipboardCopyAction'),
        intercept('codeAnalyzer.interceptCut', 'editor.action.clipboardCutAction'),
        intercept('codeAnalyzer.acceptSuggestionTab', 'acceptSelectedSuggestion', () => analyzer.markSuggestionAccepted()),
        intercept('codeAnalyzer.acceptSuggestionEnter', 'acceptSelectedSuggestion', () => analyzer.markSuggestionAccepted()),

        { dispose: () => analyzer.dispose() }
    );
}

// VS Code espera a que termine: garantiza la generación del PDF al cerrar el editor
export async function deactivate() {
    await analyzerInstance?.stopMonitoring();
}