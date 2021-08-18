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
import java.util.Vector;

import com.oracle.truffle.api.CallTarget;
import com.oracle.truffle.api.Truffle;
import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.nodes.RootNode;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emulate.BreakTable;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.emulate.UnimplementedCallOtherException;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;

public class PcodeOpRootNode extends RootNode {

    private Register pcRegister;
    private SleighLanguage lang;
    private PcodeOpLanguage pcodeOpLanguage;
    private MemoryState state;
    private HashMap<Address, PcodeOpBlockNode> blocks;
    private PcodeOpContext context;


    public PcodeOpRootNode(PcodeOpLanguage pcodeOpLanguage, SleighLanguage lang, PcodeOpContext context) {
        super(pcodeOpLanguage);
        this.context = context;
        this.pcodeOpLanguage = pcodeOpLanguage;

        this.state = getContext().getMemoryState();
        this.blocks = getContext().getBlockCache();
        this.lang = lang;
        this.pcRegister = lang.getProgramCounter();
    }

    public PcodeOpRootNode(PcodeOpLanguage pcodeOpLanguage, SleighLanguage lang) {
        this(pcodeOpLanguage, lang, null);
    }

    private PcodeOpContext getContext() {
        if (context != null) {
            return context;
        } else {
            return lookupContextReference(PcodeOpLanguage.class).get();
        }
    }

    private PcodeOpBlockNode newBlockNode(Address blockEntry) {
        Vector<PcodeOpNode> ops = new Vector<PcodeOpNode>();
        for (PcodeOp pcode : getContext().emitPcode(blockEntry)) {
            PcodeOpNode node = PcodeOpNodeFactory.createNodeFromPcodeOp(pcode, getContext());
            ops.add(node);
        }
        return new PcodeOpBlockNode(ops, getContext());
    }

    private void setCurrentAddress(Address addr) {
        this.context.setCurrentAddress(addr);
        Address currentAddress = this.context.getCurrentAddress();
        state.setValue(pcRegister, currentAddress.getAddressableWordOffset());
    }

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
            this.context.setCurrentAddress(targetAddr);
            CallTarget target = Truffle.getRuntime()
                    .createCallTarget(new PcodeOpRootNode(
                        pcodeOpLanguage,
                        lang,
                        context));

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
        long offset = state.getValue(op.getInput(0));
		AddressSpace space = op.getSeqnum().getTarget().getAddressSpace();
        Address targetAddr = space.getTruncatedAddress(offset, true);
        doCall(targetAddr);
    }

    private void executeBranchind(PcodeOp op) {
        long offset = state.getValue(op.getInput(0));
		AddressSpace space = op.getSeqnum().getTarget().getAddressSpace();
		setCurrentAddress(space.getTruncatedAddress(offset, true));
    }

    private void executeReturn(PcodeOp op) {
        long offset = state.getValue(op.getInput(0));
		AddressSpace space = op.getSeqnum().getTarget().getAddressSpace();
		throw new PcodeOpReturnException(space.getTruncatedAddress(offset, true));
    }

    private void executeCallother(PcodeOp op) {
        EmulateInstructionStateModifier instructionStateModifier = getContext().getInstructionStateModifier();
        BreakTable breakTable = getContext().getBreaktable();
        PcodeOpRaw opRaw = new PcodeOpRaw(op);
        if ((instructionStateModifier == null || !instructionStateModifier.executeCallOther(op)) &&
            !breakTable.doPcodeOpBreak(opRaw)) {
            int userOp = (int) op.getInput(0).getOffset();
            String pcodeOpName = getContext().getSleighLanguage().getUserDefinedOpName(userOp);
            throw new UnimplementedCallOtherException(opRaw, pcodeOpName);
        }
    }

    protected void handleBranchException(PcodeOpBranchException e) {
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

    @Override
    public Object execute(VirtualFrame frame) {
        while (true) {
            Address currentAddress = this.context.getCurrentAddress();
            PcodeOpBlockNode block = blocks.get(currentAddress);
            if (block == null) {
                block = newBlockNode(currentAddress);
                blocks.put(currentAddress, block);
            }

            try {
                block.execute(frame);
            } catch (PcodeOpBranchException e) {
                handleBranchException(e);
            }
        }
    }
}
