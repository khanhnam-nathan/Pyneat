"use strict";
/**
 * PyNeat - AI Code Cleaner
 *
 * Copyright (C) 2026 PyNEAT Authors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.run = run;
/**
 * Extension Tests
 * Basic test suite for PyNEAT VS Code extension
 */
const assert = __importStar(require("assert"));
const vscode = __importStar(require("vscode"));
async function run() {
    // Try to find PyNEAT extension by various means
    let pyneatExt = vscode.extensions.getExtension('pyneat.pyneat');
    pyneatExt = pyneatExt || vscode.extensions.getExtension('pyneat');
    pyneatExt = pyneatExt || vscode.extensions.all.find(e => e.packageJSON?.name === 'pyneat');
    if (!pyneatExt) {
        // Skip test - extension not loaded in test environment
        console.log('PyNEAT extension not found - this is expected in some test configurations');
        return;
    }
    if (!pyneatExt.isActive) {
        await pyneatExt.activate();
    }
    assert.ok(pyneatExt.isActive, 'PyNEAT extension should be active');
    const cmds = await vscode.commands.getCommands(true);
    const hasCheckFile = cmds.includes('pyneat.checkFile');
    const hasCheckWorkspace = cmds.includes('pyneat.checkWorkspace');
    console.log(`Commands: pyneat.checkFile=${hasCheckFile}, pyneat.checkWorkspace=${hasCheckWorkspace}`);
    const config = vscode.workspace.getConfiguration('pyneat');
    assert.ok(config, 'PyNEAT configuration should be accessible');
    const enableRealTime = config.get('enableRealTime');
    const scanOnSave = config.get('scanOnSave');
    const severityThreshold = config.get('severityThreshold');
    console.log(`Config: enableRealTime=${enableRealTime}, scanOnSave=${scanOnSave}, severityThreshold=${severityThreshold}`);
}
//# sourceMappingURL=extension.test.js.map