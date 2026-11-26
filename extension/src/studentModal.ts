import * as vscode from 'vscode';

/**
 * Muestra una tarjeta flotante centrada en el editor para solicitar el nombre del estudiante.
 * Devuelve el nombre limpio o `undefined` si el usuario cancela o cierra la pestaña.
 */
export function askStudentNameModal(): Promise<string | undefined> {
    return new Promise((resolve) => {
        let resolved = false;

        const panel = vscode.window.createWebviewPanel(
            'codeAnalyzerStudentModal',
            'Registro de Evaluación',
            vscode.ViewColumn.Active,
            {
                enableScripts: true,
                retainContextWhenHidden: false
            }
        );

        panel.webview.html = getStudentModalHtml();

        panel.webview.onDidReceiveMessage((message) => {
            if (message.command === 'submit') {
                resolved = true;
                const cleanName = (message.name || '').trim();
                panel.dispose();
                resolve(cleanName);
            } else if (message.command === 'cancel') {
                resolved = true;
                panel.dispose();
                resolve(undefined);
            }
        });

        panel.onDidDispose(() => {
            if (!resolved) {
                resolve(undefined);
            }
        });
    });
}

function getStudentModalHtml(): string {
    return `<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: var(--vscode-font-family, 'Segoe UI', sans-serif);
        }
        body {
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background-color: rgba(0, 0, 0, 0.35);
            color: var(--vscode-foreground);
        }
        .modal-card {
            width: 100%;
            max-width: 420px;
            padding: 28px;
            border-radius: 10px;
            background-color: var(--vscode-editorWidget-background, #252526);
            border: 1px solid var(--vscode-editorWidget-border, #454545);
            box-shadow: 0 12px 32px rgba(0, 0, 0, 0.45);
            animation: fadeIn 0.18s ease-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-8px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .badge {
            display: inline-block;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 3px 8px;
            border-radius: 4px;
            background-color: var(--vscode-badge-background);
            color: var(--vscode-badge-foreground);
            margin-bottom: 12px;
        }
        h2 {
            font-size: 18px;
            margin-bottom: 6px;
            font-weight: 600;
        }
        p.subtitle {
            font-size: 13px;
            color: var(--vscode-descriptionForeground);
            margin-bottom: 20px;
            line-height: 1.4;
        }
        label {
            display: block;
            font-size: 12px;
            font-weight: 600;
            margin-bottom: 6px;
        }
        input {
            width: 100%;
            padding: 9px 12px;
            font-size: 14px;
            border-radius: 5px;
            border: 1px solid var(--vscode-input-border, #3c3c3c);
            background-color: var(--vscode-input-background);
            color: var(--vscode-input-foreground);
            outline: none;
        }
        input:focus {
            border-color: var(--vscode-focusBorder);
        }
        .error-msg {
            min-height: 18px;
            margin-top: 6px;
            font-size: 12px;
            color: var(--vscode-errorForeground, #f48771);
        }
        .actions {
            margin-top: 18px;
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }
        button {
            padding: 8px 16px;
            font-size: 13px;
            font-weight: 500;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        .btn-cancel {
            background-color: var(--vscode-button-secondaryBackground);
            color: var(--vscode-button-secondaryForeground);
        }
        .btn-cancel:hover {
            background-color: var(--vscode-button-secondaryHoverBackground);
        }
        .btn-submit {
            background-color: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
        }
        .btn-submit:hover {
            background-color: var(--vscode-button-hoverBackground);
        }
    </style>
</head>
<body>
    <div class="modal-card">
        <span class="badge">Code Analyzer</span>
        <h2>Inicio de Evaluación</h2>
        <p class="subtitle">Ingresa tu nombre completo para registrar tu sesión y comenzar el monitoreo.</p>

        <label for="studentName">Nombre del estudiante</label>
        <input type="text" id="studentName" placeholder="Ej: María González López" autofocus />
        <div class="error-msg" id="errorMsg"></div>

        <div class="actions">
            <button type="button" class="btn-cancel" id="cancelBtn">Cancelar</button>
            <button type="button" class="btn-submit" id="submitBtn">Comenzar evaluación</button>
        </div>
    </div>

    <script>
        const vscode = acquireVsCodeApi();
        const input = document.getElementById('studentName');
        const errorMsg = document.getElementById('errorMsg');
        const submitBtn = document.getElementById('submitBtn');
        const cancelBtn = document.getElementById('cancelBtn');

        window.addEventListener('load', () => input.focus());

        function validateAndSubmit() {
            const value = input.value.trim();
            if (value.length < 3) {
                errorMsg.textContent = 'El nombre debe tener al menos 3 caracteres.';
                return;
            }
            if (value.length > 50) {
                errorMsg.textContent = 'El nombre es demasiado largo (máx. 50 caracteres).';
                return;
            }
            if (!/^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\\s'-]+$/.test(value)) {
                errorMsg.textContent = 'El nombre solo puede contener letras y espacios.';
                return;
            }

            errorMsg.textContent = '';
            vscode.postMessage({ command: 'submit', name: value });
        }

        submitBtn.addEventListener('click', validateAndSubmit);
        cancelBtn.addEventListener('click', () => {
            vscode.postMessage({ command: 'cancel' });
        });

        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') validateAndSubmit();
            if (e.key === 'Escape') vscode.postMessage({ command: 'cancel' });
        });
    </script>
</body>
</html>`;
}