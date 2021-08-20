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

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.instrumentation.Tag;


import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;

/**
 * Common base class for single pcode op instruction.
 * i.e, represents a single pcodeop node.
 */
public abstract class PcodeOpPcodeInstNode extends PcodeOpNode {

    protected final PcodeOp pcodeOp;

    public PcodeOpPcodeInstNode(final PcodeOp pcodeOp, PcodeOpContext context) {
        super(context);
        this.pcodeOp = pcodeOp;
    }

    @Override
    public void execute(VirtualFrame frame) {
        if (getContext().getHalt() == true) {
            throw new PcodeOpHaltException();
        }

        doExecute(frame);
    }

    public abstract void doExecute(VirtualFrame frame);

    @Override
    public Address getAddress() {
        return this.pcodeOp.getSeqnum().getTarget();
    }

    @Override
    public boolean hasTag(Class<? extends Tag> tag) {
        if (tag == PcodeOpLanguage.STATEMENT) {
			return true;
		}
		return false;
    }
}
