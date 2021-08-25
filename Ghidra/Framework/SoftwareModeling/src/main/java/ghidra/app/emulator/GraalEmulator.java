/* ###
 * IP: BinCraft
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

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emulate.BreakTableCallBack;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.pcodetruffle.GraalEmulate;
import ghidra.pcode.pcodetruffle.PcodeOpContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.RegisterValue;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GraalEmulator extends AbstractEmulator {
	private GraalEmulate emulate;

    public GraalEmulator(EmulatorConfiguration cfg) {
		super(cfg);
	}

	@Override
	protected void initEmulator(SleighLanguage language, MemoryState memState, BreakTableCallBack breakTable) {
		this.emulate = new GraalEmulate(language, memState, breakTable);
	}

	public void continueExecution(TaskMonitor monitor) throws CancelledException {
		emulate.continueExecution(monitor);
	}

	@Override
	public void setHalt(boolean halt) {
		this.emulate.getContext().setHalt(halt);
		super.setHalt(halt);
	}

	@Override
	public void setExecuteAddress(long addressableWordOffset) {
		AddressSpace space = addrFactory.getDefaultAddressSpace();
		Address address = space.getTruncatedAddress(addressableWordOffset, true);
		emulate.setExecuteAddress(address);
	}

	@Override
	public Address getExecuteAddress() {
		return emulate.getExecuteAddress();
	}


	@Override
	public RegisterValue getContextRegisterValue() {
		return emulate.getContextRegisterValue();
	}


	@Override
	public void setContextRegisterValue(RegisterValue regValue) {
		emulate.setContextRegisterValue(regValue);
	}

	@Override
	public boolean isInstructionDecoding() {
		return false;
	}

	public PcodeOpContext getContext() {
		return this.emulate.getContext();
	}
}

