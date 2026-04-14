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

/**
 * Test Runner
 * Launches VS Code test environment and runs extension tests
 */

import * as path from 'path';
import { runTests } from '@vscode/test-electron';

async function main(): Promise<void> {
  try {
    await runTests({
      extensionDevelopmentPath: path.resolve(__dirname, '../../'),
      extensionTestsPath: path.resolve(__dirname, './extension.test'),
      launchArgs: ['--disable-extensions', '--disable-gpu', '--no-sandbox'],
    });
    console.log('All tests passed!');
  } catch (err) {
    console.error('Failed to run tests:', err);
    process.exit(1);
  }
}

main();
