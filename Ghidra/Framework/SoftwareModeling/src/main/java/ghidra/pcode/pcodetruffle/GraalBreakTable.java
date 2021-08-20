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
import com.oracle.truffle.api.instrumentation.EventContext;
import com.oracle.truffle.api.instrumentation.ExecutionEventListener;
import com.oracle.truffle.api.instrumentation.Instrumenter;
import com.oracle.truffle.api.instrumentation.SourceSectionFilter;

import ghidra.pcode.emulate.AbstractEmulate;
import ghidra.pcode.emulate.BreakTable;
import ghidra.program.model.address.Address;

// FIXME: this class is not actually used right now!
public class GraalBreakTable implements ExecutionEventListener {

    
    private BreakTable breakTable;

    public GraalBreakTable(Instrumenter instrumenter) {
        // FIXME: this might not be actually useful as we have no children under RootNode.
        final SourceSectionFilter INST_FILTER = SourceSectionFilter.newBuilder()
            .tagIs(PcodeOpLanguage.STATEMENT).build();

        instrumenter.attachExecutionEventListener(INST_FILTER, this);
    }

    public void setBreakTable(BreakTable breakTable) {
        this.breakTable = breakTable;
    }

    public void setEmulate(AbstractEmulate emulate) {
        this.breakTable.setEmulate(emulate);
    }

    @Override
    public void onEnter(EventContext context, VirtualFrame frame) {
        Object node = context.getNodeObject();
        if (node instanceof PcodeOpNode) {
            PcodeOpNode opNode = (PcodeOpNode) node;
            Address addr = opNode.getAddress();
            breakTable.doAddressBreak(addr);
        }
        // FIXME: previous implementation of the emulate does not use pcode op break
        // other than implementing call other. We might just follow that here. But
        // it is possible that we missed something.
    }

    @Override
    public void onReturnValue(EventContext context, VirtualFrame frame, Object result) {
    }

    @Override
    public void onReturnExceptional(EventContext context, VirtualFrame frame, Throwable exception) {
    }
    
}
