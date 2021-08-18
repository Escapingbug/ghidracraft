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
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.emulate.BreakTable;
import ghidra.pcode.emulate.BreakTableCallBack;
import ghidra.program.model.address.Address;

public class GraalBreakTable implements ExecutionEventListener {

    private static final SourceSectionFilter INST_FILTER = SourceSectionFilter.newBuilder().tagIs(
        PcodeOpLanguage.STATEMENT
    ).build();
    private BreakTable breakTable;

    public GraalBreakTable(Instrumenter instrumenter) {
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
        // Not used.
    }

    @Override
    public void onReturnExceptional(EventContext context, VirtualFrame frame, Throwable exception) {
        // This could happen when breakpoint callback tries to throw control flow exception to
        // modify control flow.

        // XXX Do we actually need to handle branch exception here?
        /*
        if (exception instanceof PcodeOpBranchException) {
            PcodeOpBranchException e = (PcodeOpBranchException) exception;
            Node node = context.getInstrumentedNode();
            if (node instanceof PcodeOpNode) {
                PcodeOpNode opNode = (PcodeOpNode) node;
                opNode.getContext().handleBranchException(e);
            }
        }
        */
    }
    
}
