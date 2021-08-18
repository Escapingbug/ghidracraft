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

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;

public abstract class PcodeOpInstNode extends PcodeOpNode {

    protected final PcodeOp pcodeOp;

    public PcodeOpInstNode(final PcodeOp pcodeOp, PcodeOpContext context) {
        super(context);
        this.pcodeOp = pcodeOp;
    }

    @Override
    public abstract void execute(VirtualFrame frame);

    @Override
    public abstract Address getAddress();
    
}
