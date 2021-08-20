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

import com.oracle.truffle.api.instrumentation.ProvidedTags;
import com.oracle.truffle.api.instrumentation.StandardTags;
import com.oracle.truffle.api.instrumentation.Tag;
import com.oracle.truffle.api.instrumentation.Tag.Identifier;

import ghidra.pcode.pcodetruffle.PcodeOpLanguage.BlockTag;
import ghidra.pcode.pcodetruffle.PcodeOpLanguage.AssemblyTag;

import com.oracle.truffle.api.CallTarget;
import com.oracle.truffle.api.Truffle;
import com.oracle.truffle.api.TruffleLanguage;

@ProvidedTags({ StandardTags.StatementTag.class, BlockTag.class, AssemblyTag.class })
@TruffleLanguage.Registration(
    id = PcodeOpLanguage.ID,
    name = "PcodeOp",
    defaultMimeType = PcodeOpLanguage.MIME_TYPE,
    characterMimeTypes = PcodeOpLanguage.MIME_TYPE,
    contextPolicy = TruffleLanguage.ContextPolicy.SHARED
)
public class PcodeOpLanguage extends TruffleLanguage<PcodeOpContext> {
    public static final String ID = "pcode";
    public static final String MIME_TYPE = "application/x-pcode";

    public static final Class<? extends Tag> STATEMENT = StandardTags.StatementTag.class;
    public static final Class<? extends Tag> BLOCK = BlockTag.class;
    public static final Class<? extends Tag> ASSEMBLY = AssemblyTag.class;

    private static GraalEmulate emulate = null;
    private static PcodeOpContext cachedContext = null;

    // UGLY ALERT! There might be a better way of doing this (attaching a custom object
    // on the TruffleLanguage implementation). Option is possible to GET the value out
    // But currently I have no idea how to PUT the value in the <code>Env</code> object
    // when using Context and Engine.
    //
    // This implemetation will not work under multi-threading context. SO DON'T DO THAT!
    public static void setEmulate(GraalEmulate emulate) {
        PcodeOpLanguage.emulate = emulate;
    }

    // UGLY ALERT! See above (setEmulate).
    public static PcodeOpContext getCachedContext() {
        return PcodeOpLanguage.cachedContext;
    }

    private GraalEmulate getEmulate() {
        if (emulate != null) {
            return emulate;
        } else {
            throw new IllegalArgumentException("GraalEmulate must be set on the PcodeOpLanguage class before use");
        }
    }

    /**
     * The block is a real basic block contains multiple assemblies
     */
    @Identifier("BLOCK")
    static class BlockTag extends Tag {}

    /**
     * multiple pcode(statement)s form a single assembly
     */
    @Identifier("ASSEMBLY")
    static class AssemblyTag extends Tag {}

    @Override
    protected PcodeOpContext createContext(Env env) {
        PcodeOpLanguage.cachedContext = new PcodeOpContext(this, env, getEmulate());
        return PcodeOpLanguage.cachedContext;
    }

    /**
     * HACK ALERT! The actual "source" is the starting address where we'd like to make
     * a call target.
     */
    @Override
    protected CallTarget parse(ParsingRequest request) throws Exception {
        PcodeOpContext context = getCurrentContext(PcodeOpLanguage.class);
        /*
        Source source = request.getSource();
        Address target = getEmulate().parseAddress(source.getCharacters().toString());
        context.setCurrentAddress(target);
        */
        return Truffle.getRuntime().createCallTarget(new PcodeOpRootNode(this, emulate.getLanguage(), context));
    }
}
