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

import java.math.BigInteger;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.instrumentation.Tag;

import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class PcodeOpUnaryNode extends PcodeOpInstNode {

    private UnaryOpBehavior behavior;

    public PcodeOpUnaryNode(final PcodeOp pcodeOp, UnaryOpBehavior behavior, PcodeOpContext context) {
        super(pcodeOp, context);
        this.behavior = behavior;
    }

    public PcodeOpUnaryNode(final PcodeOp pcodeOp, UnaryOpBehavior behavior) {
        this(pcodeOp, behavior, null);
    }

    @Override
    public void execute(VirtualFrame frame) {
        Varnode vIn = pcodeOp.getInput(0);
        Varnode vOut = pcodeOp.getOutput();
        if (vIn.getSize() > 8 || vOut.getSize() > 8) {
            BigInteger in = state.getBigInteger(vIn, false);
            BigInteger out = behavior.evaluateUnary(vOut.getSize(), vIn.getSize(), in);
            state.setValue(vOut, out);
        } else {
            long in = state.getValue(vIn);
            long out = behavior.evaluateUnary(vOut.getSize(), vIn.getSize(), in);
            state.setValue(vOut, out);
        }
    }

    @Override
    public Address getAddress() {
        return this.pcodeOp.getSeqnum().getTarget();
    }

    @Override
    public boolean hasTag(Class<? extends Tag> tag) {
        if (tag == PcodeOpLanguage.STATEMENT) {
            return true;
        } else {
            return false;
        }
    }
}
