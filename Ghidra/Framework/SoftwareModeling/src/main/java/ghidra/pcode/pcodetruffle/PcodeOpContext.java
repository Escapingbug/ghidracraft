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

import com.oracle.truffle.api.CallTarget;
import com.oracle.truffle.api.Truffle;
import com.oracle.truffle.api.TruffleLanguage;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emulate.BreakTable;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.emulate.UnimplementedCallOtherException;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.Task;
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
    private boolean halt = false;

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

    /*
    private void executeBranch(PcodeOp op) {
        Address dest = op.getInput(0).getAddress();
        if (dest.getAddressSpace().isConstantSpace()) {
            throw new RuntimeException("trying to branch relatively out of block node");
        } else {
            setCurrentAddress(dest);
        }
    }

    private void doCall(Address targetAddr) {
        try {
            setCurrentAddress(targetAddr);
            CallTarget target = Truffle.getRuntime()
                    .createCallTarget(new PcodeOpRootNode(
                        language,
                        sleighLang,
                        this));

            target.call();
        }
        catch (PcodeOpReturnException returnException) {
        }
    }

    private void executeCall(PcodeOp op) {
        Address targetAddr = op.getInput(0).getAddress();
        doCall(targetAddr);
    }

    private void executeCallind(PcodeOp op) {
        long offset = memoryState.getValue(op.getInput(0));
		AddressSpace space = op.getSeqnum().getTarget().getAddressSpace();
        Address targetAddr = space.getTruncatedAddress(offset, true);
        doCall(targetAddr);
    }

    private void executeBranchind(PcodeOp op) {
        long offset = memoryState.getValue(op.getInput(0));
		AddressSpace space = op.getSeqnum().getTarget().getAddressSpace();
		setCurrentAddress(space.getTruncatedAddress(offset, true));
    }

    private void executeReturn(PcodeOp op) {
        long offset = memoryState.getValue(op.getInput(0));
		AddressSpace space = op.getSeqnum().getTarget().getAddressSpace();
		throw new PcodeOpReturnException(space.getTruncatedAddress(offset, true));
    }

    private void executeCallother(PcodeOp op) {
        EmulateInstructionStateModifier instructionStateModifier = getInstructionStateModifier();
        PcodeOpRaw opRaw = new PcodeOpRaw(op);
        if ((instructionStateModifier == null || !instructionStateModifier.executeCallOther(op)) &&
            !getBreaktable().doPcodeOpBreak(opRaw)) {
            int userOp = (int) op.getInput(0).getOffset();
            String pcodeOpName = sleighLang.getUserDefinedOpName(userOp);
            throw new UnimplementedCallOtherException(opRaw, pcodeOpName);
        }
    }

    public void handleBranchException(PcodeOpBranchException e) {
        PcodeOp op = e.getOp();

        switch (op.getOpcode()) {
            case PcodeOp.BRANCH: {
                executeBranch(op);
                break;
            }

            case PcodeOp.CBRANCH: {
                // only taken branch should throw branch exception
                executeBranch(op);
                break;
            }

            case PcodeOp.BRANCHIND: {
                executeBranchind(op);
                break;
            }

            case PcodeOp.CALL: {
                executeCall(op);
                break;
            }

            case PcodeOp.CALLIND: {
                executeCallind(op);
                break;
            }

            case PcodeOp.CALLOTHER: {
                executeCallother(op);
                break;
            }

            case PcodeOp.RETURN: {
                executeReturn(op);
                break;
            }

            default: {
                throw new RuntimeException("unknown branch pcode " + op.toString());
            }
        }
    }
    */

    protected SleighLanguage getSleighLanguage() {
        return this.sleighLang;
    }

    public PcodeOp[] emitPcode(Address entry) {
        return this.emulate.emitPcode(entry);
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
}
