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

import java.util.List;

import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.pcode.emulate.InstructionDecodeException;
import ghidra.pcode.error.LowlevelError;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.RegisterValue;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Emulator extends AbstractEmulator {

    private Emulate emulator;
	private int instExecuted = 0;

    public Emulator(EmulatorConfiguration cfg) {
        super(cfg);
        emulator = new Emulate(language, memState, breakTable);
    }

    @Override
    public void setExecuteAddress(long addressableWordOffset) {
		AddressSpace space = addrFactory.getDefaultAddressSpace();
		Address address = space.getTruncatedAddress(addressableWordOffset, true);
		emulator.setExecuteAddress(address);
    }

    @Override
    public Address getExecuteAddress() {
        return emulator.getExecuteAddress();
    }

    public Address getLastExecuteAddress() {
        return emulator.getLastExecuteAddress();
    }

    public void executeInstruction(boolean stopAtBreakpoint, TaskMonitor monitor)
            throws CancelledException, LowlevelError, InstructionDecodeException {
		isExecuting = true;
		try {
			emulator.executeInstruction(stopAtBreakpoint, monitor);
			instExecuted++;
		}
		finally {
			isExecuting = false;
		}
    }

    /**
	 * @return true if halted at a breakpoint
	 */
	public boolean isAtBreakpoint() {
		return getHalt() && emulator.getExecutionState() == EmulateExecutionState.BREAKPOINT;
	}

	/**
	 * @return emulator execution state.  This can be useful within a memory fault handler to
	 * determine if a memory read was associated with instruction parsing (i.e., PCODE_EMIT) or
	 * normal an actual emulated read (i.e., EXECUTE).
	 */
	public EmulateExecutionState getEmulateExecutionState() {
		return emulator.getExecutionState();
	}

	public int getTickCount() {
		return instExecuted;
	}

    /**
	 * Returns the current context register value.  The context value returned reflects
	 * its state when the previously executed instruction was 
	 * parsed/executed.  The context value returned will feed into the next 
	 * instruction to be parsed with its non-flowing bits cleared and
	 * any future context state merged in.
	 * @return context as a RegisterValue object
	 */
	public RegisterValue getContextRegisterValue() {
		return emulator.getContextRegisterValue();
	}

	/**
	 * Sets the context register value at the current execute address.
	 * The Emulator should not be running when this method is invoked.
	 * Only flowing context bits should be set, as non-flowing bits
	 * will be cleared prior to parsing on instruction.  In addition,
	 * any future context state set by the pcode emitter will
	 * take precedence over context set using this method.  This method
	 * is primarily intended to be used to establish the initial 
	 * context state.
	 * @param regValue is the value to set context to
	 */
	public void setContextRegisterValue(RegisterValue regValue) {
		emulator.setContextRegisterValue(regValue);
	}

    /**
	 * Disassemble from the current execute address
	 * @param count number of contiguous instructions to disassemble
	 * @param context The emulate disassembler context to disassemble
	 * @return list of instructions
	 */
    public List<String> disassemble(Integer count) {
        return disassemble(count, emulator.getNewDisassemblerContext());
    }

    public void dispose() {
        super.dispose();
        emulator.dispose();
    }
    
}
