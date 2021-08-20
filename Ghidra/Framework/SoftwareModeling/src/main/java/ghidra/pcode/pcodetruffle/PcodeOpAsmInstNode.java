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

import java.util.Arrays;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.instrumentation.Tag;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A block of several instructions that represents a single assembly instruction.
 * One example is that, a single <code>PUSH RSP</code> in x86_64 can be translated
 * into several pcode, and this node represent that several pcodes that refer to
 * the same assembly instruction.
 */
public class PcodeOpAsmInstNode extends PcodeOpNode {

    // The reason we don't make this a official <code>BlockNode</code>
    // as normally do in Truffle implementation is that, we need to
    // handle local branch ourselves. Local branch, i.e, intra-assembly
    // branch, the branch within a single assembly instruction.
    //
    // Thus, we need an index ourselves to track which one is to be
    // executed exactly and cannot just rely on @Child nodes execution.
    private PcodeOpPcodeInstNode[] nodes;
    private final Address address;
    private final int instructionLength;
    private int currentIndex = 0;
    private boolean hasBreaked = false;

    public PcodeOpAsmInstNode(
        PcodeOp[] pcodeOps,
        final Address address,
        final int instructionLength,
        final PcodeOpContext context) {
        super(context);

        this.address = address;
        this.instructionLength = instructionLength;

        nodes = Arrays.stream(pcodeOps)
            .map(pcode -> PcodeOpNodeFactory.createNodeFromPcodeOp(pcode, context))
            .toArray(PcodeOpPcodeInstNode[]::new);
    }

    private boolean executeBranch(PcodeOp op) {
        Address dest = op.getInput(0).getAddress();
        if (dest.getAddressSpace().isConstantSpace()) {
            long id = dest.getOffset();
            currentIndex += id;
            if (currentIndex < 0 || currentIndex >= nodes.length) {
                throw new RuntimeException("invalid in-assembly branch");
            }

            return true;
        } else {
            // Not a valid in-assembly branch. We cannot handle it here.
            return false;
        }
    }

    @Override
    public void execute(VirtualFrame frame) {

        currentIndex = 0;

        if (getContext().getHalt() == true) {
            throw new PcodeOpHaltException();
        }


        // FIXME: this does not actually integrated Graal VM. Use static block discovering in RootNode to fix this.
        if (!hasBreaked && getContext().getBreaktable().doAddressBreak(getAddress())) {
            // do not execute the pcodes in this case
            hasBreaked = true;
            return;
        }

        getContext().setAtBreakpoint(false);
        hasBreaked = false;

        while (currentIndex < nodes.length) {
            try {
                nodes[currentIndex].execute(frame);
            } catch (PcodeOpBranchException e) {
                PcodeOp op = e.getOp();
                switch (op.getOpcode()) {
                    case PcodeOp.BRANCH: {
                        if (!executeBranch(op)) {
                            throw e;
                        }
                    }

                    default:
                        throw e;
                }
            }

            currentIndex += 1;
        }

        // forward the current address as we finished executing a single address of assembly
        getContext().setCurrentAddress(address.addWrap(instructionLength));
    }

    @Override
    public Address getAddress() {
        return address;
    }

    @Override
    public boolean hasTag(Class<? extends Tag> tag) {
        if (tag == PcodeOpLanguage.ASSEMBLY) {
            return true;
        } else {
            return false;
        }
    }
}
