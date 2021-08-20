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

import java.util.Vector;

import com.oracle.truffle.api.frame.VirtualFrame;
import com.oracle.truffle.api.instrumentation.Tag;
import com.oracle.truffle.api.nodes.BlockNode;
import com.oracle.truffle.api.nodes.BlockNode.ElementExecutor;

import ghidra.program.model.address.Address;

public class PcodeOpBlockNode extends PcodeOpNode implements ElementExecutor<PcodeOpAsmInstNode> {

    @Child BlockNode<PcodeOpAsmInstNode> ops;

    public PcodeOpBlockNode(Vector<PcodeOpAsmInstNode> ops, PcodeOpContext context) {
        super(context);
        this.ops = BlockNode.create(ops.toArray(PcodeOpAsmInstNode[]::new), this);
    }

    public PcodeOpBlockNode(Vector<PcodeOpAsmInstNode> ops) {
        this(ops, null);
    }


    @Override
    public void execute(VirtualFrame frame) {
        ops.executeVoid(frame, 0);
    }

    @Override
    public Address getAddress() {
        return this.ops.getElements()[0].getAddress();
    }
    
    @Override
    public boolean hasTag(Class<? extends Tag> tag) {
        if (tag == PcodeOpLanguage.BLOCK) {
            return true;
        }
        return false;
    }

    @Override
    public void executeVoid(VirtualFrame frame, PcodeOpAsmInstNode node, int index, int argument) {
        node.execute(frame);
    }
}
