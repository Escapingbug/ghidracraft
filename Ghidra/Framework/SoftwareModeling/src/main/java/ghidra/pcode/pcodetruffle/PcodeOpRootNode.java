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
import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.OpBehavior;
import ghidra.pcode.opbehavior.OpBehaviorFactory;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
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
    private HashMap<Address, PcodeOpBlockNode> blocks; // <-- This should be children, but it can't since it is not fixed.
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

    @Override
    public String getName() {
        return "PcodeOpRootNode";
    }

    private PcodeOpContext getContext() {
        if (context != null) {
            return context;
        } else {
            return lookupContextReference(PcodeOpLanguage.class).get();
        }
    }

    private boolean isEndOfBlock(PcodeOp[] pcodeOps) {
        // This works like NOP, so no.
        if (pcodeOps.length == 0) {
            return false;
        }

        PcodeOp pcodeOp = pcodeOps[pcodeOps.length - 1];
        OpBehavior behavior = OpBehaviorFactory.getOpBehavior(pcodeOp.getOpcode());
        if (behavior instanceof BinaryOpBehavior) {
            return false;
        } else if (behavior instanceof UnaryOpBehavior) {
            return false;
        } else {
            switch (pcodeOp.getOpcode()) {
                case PcodeOp.STORE:
                case PcodeOp.LOAD:
                    return false;
                default:
                    return true;
            }
        }
    }

    private PcodeOpBlockNode newBlockNode(Address blockEntry) {
        Address cur = blockEntry;
        Vector<PcodeOpAsmInstNode> nodes = new Vector<>();
        while (true) {

            PcodeOp[] ops = getContext().emitPcode(cur);
            int instructionLength = getContext().getLastEmittedInstructionLength();
            nodes.add(new PcodeOpAsmInstNode(ops, cur, instructionLength, getContext()));

            // we have a breakpoint, split the block to avoid unpredicted access after breakpoint
            if (isEndOfBlock(ops) || getContext().getBreaktable().hasAddressBreak(cur)) {
                return new PcodeOpBlockNode(nodes, getContext());
            }

            cur = cur.addWrap(instructionLength);
        }
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
                //executeReturn(op);
                executeBranchind(op);
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
            } catch (PcodeOpHaltException e) {
                return PcodeOpNull.SINGLETON;
            }
        }
    }
}
