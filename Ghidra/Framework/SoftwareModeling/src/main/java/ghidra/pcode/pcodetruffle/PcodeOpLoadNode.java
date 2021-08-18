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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class PcodeOpLoadNode extends PcodeOpInstNode {
    public PcodeOpLoadNode(final PcodeOp pcodeOp, PcodeOpContext context) {
        super(pcodeOp, context);
    }

    public PcodeOpLoadNode(final PcodeOp pcodeOp) {
        this(pcodeOp, null);
    }

    @Override
    public void execute(VirtualFrame frame) {
        int spaceId = (int) pcodeOp.getInput(0).getAddress().getOffset();
        AddressSpace space = addrFactory.getAddressSpace(spaceId);

        long offset = state.getValue(pcodeOp.getInput(1)); // Offset to read from
        long byteOffset =
			space.truncateAddressableWordOffset(offset) * space.getAddressableUnitSize();

        Varnode outvar = pcodeOp.getOutput();
		if (outvar.getSize() > 8) {
			BigInteger res =
				state.getBigInteger(space, byteOffset, pcodeOp.getOutput().getSize(), false);
			state.setValue(outvar, res);
		}
		else {
			long res = state.getValue(space, byteOffset, pcodeOp.getOutput().getSize());
			state.setValue(pcodeOp.getOutput(), res);
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
        }
        return false;
    }
}
