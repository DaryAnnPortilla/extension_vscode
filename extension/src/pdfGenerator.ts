import PDFDocument from 'pdfkit';
import * as fs from 'fs';

export interface PdfReportData {
    studentName: string;
    sessionCode: string;
    duration: string;
    totalFiles: number;
    safeOperations: number;
    totalPenalties: number;
    totalWarnings: number;
    finalScore: number;
    maxScore: number;
    penaltyAmount: number;
    effectiveness: string;
    fileDetails: Array<{
        fileName: string;
        safeOps: number;
        changesAnalyzed: number;
        suspiciousCount: number;
    }>;
    suspiciousSnippets: Array<{
        fileName: string;
        timestamp: string;
        reason: string;
        code: string;
    }>;
}

const PAGE_MARGIN = 50;
const CONTENT_WIDTH = 495; // 595 (ancho A4) - 2 * 50 de margen
const PAGE_BOTTOM = 740;

export class PdfReportGenerator {
    public static generatePdf(outputPath: string, data: PdfReportData): Promise<void> {
        return new Promise((resolve, reject) => {
            const doc = new PDFDocument({ margin: PAGE_MARGIN, size: 'A4' });
            const stream = fs.createWriteStream(outputPath);
            doc.pipe(stream);

            this.renderHeader(doc);
            this.renderSummaryBox(doc, data);
            this.renderFileDetails(doc, data);
            this.renderSuspiciousSnippets(doc, data);

            doc.end();

            stream.on('finish', () => resolve());
            stream.on('error', (err) => reject(err));
        });
    }

    // Salta de página si lo que viene a continuación no cabe en el espacio restante
    private static checkPageBreak(doc: PDFKit.PDFDocument, neededHeight: number) {
        if (doc.y + neededHeight > PAGE_BOTTOM) {
            doc.addPage();
        }
    }

    private static renderHeader(doc: PDFKit.PDFDocument) {
        doc.fillColor('#1e293b')
           .font('Helvetica-Bold')
           .fontSize(20)
           .text('Reporte de Evaluación de Código', { align: 'center' });

        doc.moveDown(0.3);

        doc.font('Helvetica')
           .fontSize(9)
           .fillColor('#64748b')
           .text(`Generado el: ${new Date().toLocaleString()}`, { align: 'center' });

        doc.moveDown(1);
    }

    private static renderSummaryBox(doc: PDFKit.PDFDocument, data: PdfReportData) {
        const boxTop = doc.y;
        const boxHeight = 96;
        const padding = 15;
        const colGap = 20;
        const colWidth = (CONTENT_WIDTH - padding * 2 - colGap) / 2;

        doc.rect(PAGE_MARGIN, boxTop, CONTENT_WIDTH, boxHeight)
           .fillAndStroke('#f8fafc', '#cbd5e1');

        const leftX = PAGE_MARGIN + padding;
        const rightX = PAGE_MARGIN + padding + colWidth + colGap;
        const textTop = boxTop + 14;
        const lineGap = 16;

        doc.font('Helvetica').fontSize(10).fillColor('#0f172a');

        // Columna izquierda: Datos de la sesión
        doc.text(`Estudiante: ${data.studentName}`, leftX, textTop, { width: colWidth });
        doc.text(`Código de Sesión: ${data.sessionCode}`, leftX, textTop + lineGap, { width: colWidth });
        doc.text(`Duración: ${data.duration}`, leftX, textTop + lineGap * 2, { width: colWidth });
        doc.text(`Archivos Analizados: ${data.totalFiles}`, leftX, textTop + lineGap * 3, { width: colWidth });

        // Columna derecha: Calificación global única y sanciones
        const totalDeducted = (data.totalPenalties * data.penaltyAmount).toFixed(2);

        doc.font('Helvetica-Bold').fillColor('#0f172a');
        doc.text(`Calificación Final: ${data.finalScore.toFixed(2)} / ${data.maxScore}`, rightX, textTop, { width: colWidth });

        doc.font('Helvetica').fillColor('#0f172a');
        doc.text(`Penalizaciones: ${data.totalPenalties} (-${totalDeducted} pts)`, rightX, textTop + lineGap, { width: colWidth });
        doc.text(`Advertencias: ${data.totalWarnings}`, rightX, textTop + lineGap * 2, { width: colWidth });
        doc.text(`Efectividad: ${data.effectiveness}%`, rightX, textTop + lineGap * 3, { width: colWidth });

        doc.y = boxTop + boxHeight + 20;
        doc.x = PAGE_MARGIN;
    }

    private static renderFileDetails(doc: PDFKit.PDFDocument, data: PdfReportData) {
        this.checkPageBreak(doc, 40);

        doc.fillColor('#1e293b')
           .font('Helvetica-Bold')
           .fontSize(14)
           .text('Actividad por Archivo', PAGE_MARGIN, doc.y, { underline: true });

        doc.moveDown(0.6);

        data.fileDetails.forEach((file, index) => {
            this.checkPageBreak(doc, 34);

            const rowTop = doc.y;

            // Franjas alternas para facilitar la lectura
            if (index % 2 === 0) {
                doc.rect(PAGE_MARGIN, rowTop - 2, CONTENT_WIDTH, 30).fill('#f8fafc');
            }

            doc.font('Helvetica-Bold').fontSize(10).fillColor('#0f172a')
               .text(file.fileName, PAGE_MARGIN + 10, rowTop + 2, { width: CONTENT_WIDTH - 20 });

            doc.font('Helvetica').fontSize(9).fillColor('#475569')
               .text(
                   `Ops. seguras: ${file.safeOps}   |   Cambios analizados: ${file.changesAnalyzed}   |   Fragmentos sospechosos: ${file.suspiciousCount}`,
                   PAGE_MARGIN + 10, rowTop + 16, { width: CONTENT_WIDTH - 20 }
               );

            doc.y = rowTop + 32;
            doc.x = PAGE_MARGIN;
        });

        doc.moveDown(1);
    }

    private static renderSuspiciousSnippets(doc: PDFKit.PDFDocument, data: PdfReportData) {
        this.checkPageBreak(doc, 40);

        doc.fillColor('#b91c1c')
           .font('Helvetica-Bold')
           .fontSize(14)
           .text('Evidencia de Código Copiado / Cambios Abruptos', PAGE_MARGIN, doc.y, { underline: true });

        doc.moveDown(0.6);

        if (data.suspiciousSnippets.length === 0) {
            doc.font('Helvetica').fontSize(10).fillColor('#166534')
               .text('No se detectaron fragmentos sospechosos durante la sesión.', PAGE_MARGIN, doc.y);
            return;
        }

        data.suspiciousSnippets.forEach((item, index) => {
            const cleanCode = item.code.replace(/\r/g, '');
            const truncated = cleanCode.length > 250 ? cleanCode.substring(0, 250) + '...' : cleanCode;

            doc.font('Courier').fontSize(8);
            const codeHeight = doc.heightOfString(truncated, { width: CONTENT_WIDTH - 20 });
            const blockHeight = codeHeight + 16;
            const totalNeeded = 34 + blockHeight + 14;

            this.checkPageBreak(doc, totalNeeded);

            doc.font('Helvetica-Bold').fontSize(10).fillColor('#991b1b')
               .text(`Fragmento #${index + 1} — ${item.fileName} [${item.timestamp}]`, PAGE_MARGIN, doc.y, { width: CONTENT_WIDTH });

            doc.font('Helvetica').fontSize(9).fillColor('#475569')
               .text(`Motivo: ${item.reason}`, PAGE_MARGIN, doc.y + 2, { width: CONTENT_WIDTH });

            doc.moveDown(0.4);

            const codeBlockY = doc.y;
            doc.rect(PAGE_MARGIN, codeBlockY, CONTENT_WIDTH, blockHeight).fill('#f1f5f9');
            doc.fillColor('#0f172a')
               .font('Courier')
               .fontSize(8)
               .text(truncated, PAGE_MARGIN + 10, codeBlockY + 8, { width: CONTENT_WIDTH - 20 });

            doc.font('Helvetica');
            doc.y = codeBlockY + blockHeight + 14;
            doc.x = PAGE_MARGIN;
        });
    }
}