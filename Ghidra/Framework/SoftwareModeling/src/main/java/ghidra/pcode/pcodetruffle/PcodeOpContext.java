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
package ghidra.pcode.pcodetruffle;

import java.util.HashMap;

import com.oracle.truffle.api.TruffleLanguage;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emulate.BreakTable;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.TaskMonitor;

public class PcodeOpContext {
    private final TruffleLanguage.Env env;
    private final PcodeOpLanguage language;
    private final AddressFactory addrFactory;
    private final MemoryState memoryState;
    private final SleighLanguage sleighLang;
    private final GraalEmulate emulate;
    private TaskMonitor monitor;

    private Register pcRegister;

    private HashMap<Address, PcodeOpBlockNode> blockCache = new HashMap<Address, PcodeOpBlockNode>();
    private Address currentAddress;
    /**
     * After breakpoint, the continue should execute next address which recorded here.
     */
    private Address continueAddress;
    private boolean halt = false;
    private boolean atBreakpoint = false;

    public PcodeOpContext(GraalEmulate emulate) {
        this(emulate, null);
    }

    public PcodeOpContext(GraalEmulate emulate, Address curAddress) {
        this(null, null, emulate);
        this.currentAddress = curAddress;
    }

    public PcodeOpContext(
        final PcodeOpLanguage language,
        final TruffleLanguage.Env env,
        final GraalEmulate emulate
    ) {
        this.monitor = TaskMonitor.DUMMY;
        this.emulate = emulate;
        this.sleighLang = emulate.getLanguage();
        this.env = env;
        this.language = language;
        this.addrFactory = sleighLang.getAddressFactory();
        this.memoryState = emulate.getMemoryState();
        this.pcRegister = sleighLang.getProgramCounter();
    }

    public void setCurrentAddress(Address addr) {
        this.currentAddress = addr;
        memoryState.setValue(pcRegister, currentAddress.getAddressableWordOffset());
    }

    public void setTaskMonitor(TaskMonitor monitor) {
        this.monitor = monitor;
    }

    protected SleighLanguage getSleighLanguage() {
        return this.sleighLang;
    }

    public PcodeOp[] emitPcode(Address entry) {
        return this.emulate.emitPcode(entry);
    }

    public int getLastEmittedInstructionLength() {
        return this.emulate.getLastEmittedInstructionLength();
    }

    public EmulateInstructionStateModifier getInstructionStateModifier() {
        return this.emulate.getInstructionStateModifier();
    }

    public HashMap<Address, PcodeOpBlockNode> getBlockCache() {
        return this.blockCache;
    }

    public TruffleLanguage.Env getEnv() {
        return this.env;
    }

    public PcodeOpLanguage getLanguage() {
        return this.language;
    }

    public AddressFactory getAddressFactory() {
        return this.addrFactory;
    }

    public MemoryState getMemoryState() {
        return this.memoryState;
    }

    public Address getCurrentAddress() {
        return this.currentAddress;
    }

    public void setContinueAddress(Address contAddress) {
        this.continueAddress = contAddress;
    }

    public void continueExecution() {
        long pc = getMemoryState().getValue(this.sleighLang.getProgramCounter());
        this.halt = false;
        if (pc != this.currentAddress.getOffset()) {
            // breakpoint sets pc
            this.continueAddress = null;
            this.currentAddress = this.currentAddress.getNewAddress(pc);
        } else if (this.continueAddress != null) {
            setCurrentAddress(this.continueAddress);
            this.continueAddress = null;
        }
    }

    public boolean getHalt() {
        return halt;
    }

    public void setHalt(boolean halt) {
        this.halt = halt;
    }

    public GraalEmulate getEmulate() {
        return emulate;
    }

    public BreakTable getBreaktable() {
        return emulate.getBreaktable();
    }
    
    public void setAtBreakpoint(boolean atBreakpoint) {
        this.atBreakpoint = atBreakpoint;
    }

    public boolean isAtBreakpoint() {
        return atBreakpoint;
    }
}
