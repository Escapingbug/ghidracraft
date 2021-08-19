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

import ghidra.app.emulator.memory.EmulatorLoadData;
import ghidra.app.emulator.memory.MemoryLoadImage;
import ghidra.app.emulator.memory.ProgramMappedMemory;
import ghidra.app.emulator.memory.ProgramMappedLoadImage;
import ghidra.app.emulator.state.DumpMiscState;
import ghidra.app.emulator.state.RegisterState;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GraalEmulatorHelper extends AbstractEmulatorHelper {

    private final GraalEmulator emulator;
    private boolean atBreakpoint = false;
    private BreakCallBack addressBreak = new BreakCallBack() {
		@Override
		public boolean addressCallback(Address addr) {
			emulator.setHalt(true);
            atBreakpoint = true;
			return true;
		}
	};

    
    public GraalEmulatorHelper(Program program) {
        super(program);
        this.emulator = new GraalEmulator(this);
        super.initEmulator(emulator);
    }

    @Override
    public boolean isAtBreakpoint() {
        return atBreakpoint;
    }

    @Override
    public void setBreakpoint(Address addr) {
        emulator.getBreakTable().registerAddressCallback(addr, addressBreak);
    }

    @Override
    protected void continueExecution(TaskMonitor monitor) throws CancelledException {
        atBreakpoint = false;
        emulator.continueExecution(monitor);
    }

    @Override
    public boolean step(TaskMonitor monitor) throws CancelledException {
        // TODO: this is a todo yet...
        throw new RuntimeException("step in graal emulator not yet implemented");
    }

    @Override
    protected boolean isInstructionDecoding() {
        // TODO: do we need execution state as well?
        return false;
    }
    
}
