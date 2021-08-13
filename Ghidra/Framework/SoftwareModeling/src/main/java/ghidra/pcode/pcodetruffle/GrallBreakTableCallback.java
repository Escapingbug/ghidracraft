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

import org.hamcrest.core.IsInstanceOf;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.emulate.BreakTableCallBack;
import ghidra.program.model.address.Address;

public class GrallBreakTableCallback extends BreakTableCallBack implements ExecutionEventListener {

    private final Instrumenter instrumenter;
    private static final SourceSectionFilter OUR_TAGS_FILTER = SourceSectionFilter.newBuilder().tagIs(
        PcodeOpLanguage.STATEMENT,
        PcodeOpLanguage.BLOCK,
        PcodeOpLanguage.FUNC
    ).build();

    public GrallBreakTableCallback(SleighLanguage language, Instrumenter instrumenter) {
        super(language);
        this.instrumenter = instrumenter;
        instrumenter.attachExecutionEventListener(OUR_TAGS_FILTER, this);
    }

    @Override
    public void registerPcodeCallback(String name, BreakCallBack func) {
        super.registerPcodeCallback(name, func);
    }

    @Override
    public void onEnter(EventContext context, VirtualFrame frame) {
        Object node = context.getNodeObject();
        if (node instanceof PcodeOpNode) {
            PcodeOpNode opNode = (PcodeOpNode) node;
            Address addr = opNode.getAddress();
            doAddressBreak(addr);
            // TODO: handling other callbacks
        }
    }

    @Override
    public void onReturnValue(EventContext context, VirtualFrame frame, Object result) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void onReturnExceptional(EventContext context, VirtualFrame frame, Throwable exception) {
        // TODO Auto-generated method stub
    }
    
}
