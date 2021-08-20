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
import ghidra.pcode.pcodetruffle.PcodeOpContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GraalEmulatorHelper extends AbstractEmulatorHelper {

    private final GraalEmulator emulator;
    private BreakCallBack addressBreak = new BreakCallBack() {
		@Override
		public boolean addressCallback(Address addr) {
			emulator.setHalt(true);
            getContext().setAtBreakpoint(true);
			return true;
		}
	};

    
    public GraalEmulatorHelper(Program program) {
        super(program);
        this.emulator = new GraalEmulator(this);
        super.initEmulator(emulator);
    }

    public PcodeOpContext getContext() {
        return this.emulator.getContext();
    }

    @Override
    public boolean isAtBreakpoint() {
        return getContext().isAtBreakpoint();
    }

    @Override
    public void setBreakpoint(Address addr) {
        emulator.getBreakTable().registerAddressCallback(addr, addressBreak);
    }

    @Override
    protected void continueExecution(TaskMonitor monitor) throws CancelledException {
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
