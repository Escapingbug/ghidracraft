/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.emulator;

import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class EmulatorHelper extends AbstractEmulatorHelper {

    private String lastError;
    private Emulator emulator;

    private BreakCallBack addressBreak = new BreakCallBack() {
		@Override
		public boolean addressCallback(Address addr) {
			emulator.setHalt(true);
			return true;
		}
	};

    public EmulatorHelper(Program program) {
        super(program, Emulator.class);
        this.emulator = ((Emulator)super.emulator);
    }

    /**
	 * Step execution one instruction which may consist of multiple
	 * pcode operations.  No adjustment will be made to the context beyond the normal 
	 * context flow behavior defined by the language.
	 * Method will block until execution stops.
	 * @return true if execution completes without error
	 * @throws CancelledException if execution cancelled via monitor
	 */
	public synchronized boolean step(TaskMonitor monitor) throws CancelledException {
		executeInstruction(true, monitor);
		return lastError == null;
	}

    /**
	 * @return last error message associated with execution failure
	 */
	public String getLastError() {
		return lastError;
	}

    /**
	 * Execute instruction at current address
	 * @param stopAtBreakpoint if true and breakpoint hits at current execution address
	 * execution will halt without executing instruction.
	 * @throws CancelledException if execution was cancelled
	 */
	private void executeInstruction(boolean stopAtBreakpoint, TaskMonitor monitor)
			throws CancelledException {

		lastError = null;
		try {
			if (emulator.getLastExecuteAddress() == null) {
				setProcessorContext();
			}
			emulator.executeInstruction(stopAtBreakpoint, monitor);
		}
		catch (Throwable t) {
//	TODO: need to enumerate errors better !!
			lastError = t.getMessage();
			if (lastError == null) {
				lastError = t.toString();
			}
			emulator.setHalt(true); // force execution to stop
			if (t instanceof CancelledException) {
				throw (CancelledException) t;
			}
		}
	}

    /**
	 * Continue execution and block until either a breakpoint hits or error occurs.
	 * @throws CancelledException if execution was cancelled
	 */
    @Override
	protected void continueExecution(TaskMonitor monitor) throws CancelledException {
		emulator.setHalt(false);
		do {
			executeInstruction(true, monitor);
		}
		while (!emulator.getHalt());
	}

    /**
	 * Establish breakpoint
	 * @param addr memory address for new breakpoint
	 */
    @Override
	public void setBreakpoint(Address addr) {
		emulator.getBreakTable().registerAddressCallback(addr, addressBreak);
	}

    /**
	 * @return the low-level emulator execution state
	 */
	public EmulateExecutionState getEmulateExecutionState() {
		return emulator.getEmulateExecutionState();
	}

    public Emulator getEmulator() {
		return emulator;
	}

    @Override
    protected boolean isInstructionDecoding() {
		if (emulator.getEmulateExecutionState() == EmulateExecutionState.INSTRUCTION_DECODE) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public boolean isAtBreakpoint() {
        return this.emulator.isAtBreakpoint();
    }
}
