/* ###
 * IP: GHIDRA
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
package ghidra.pcode.emulate;

import java.lang.reflect.Constructor;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.memstate.UniqueMemoryBank;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.GhidraLanguagePropertyKeys;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;

public abstract class AbstractEmulate {
    private final SleighLanguage language;
    private final AddressFactory addrFactory;

    private BreakTable breaktable; ///< The table of breakpoints
    private MemoryState memState; /// the memory state of the emulator
    private UniqueMemoryBank uniqueBank;

    private EmulateInstructionStateModifier instructionStateModifier;


    public AbstractEmulate(SleighLanguage language, MemoryState memState, BreakTable breakTable) {
        this.language = language;
        this.addrFactory = language.getAddressFactory();
        this.memState = memState;
        this.breaktable = breakTable;
        this.breaktable.setEmulate(this);

        AddressSpace uniqueSpace = language.getAddressFactory().getUniqueSpace();
        this.uniqueBank = new UniqueMemoryBank(uniqueSpace, language.isBigEndian());
        memState.setMemoryBank(uniqueBank);

        initInstuctionStateModifier();
    }

    @SuppressWarnings("unchecked")
	private void initInstuctionStateModifier() {
		String classname = language.getProperty(
			GhidraLanguagePropertyKeys.EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS);
		if (classname == null) {
			return;
		}
		try {
			Class<?> c = Class.forName(classname);
			if (!EmulateInstructionStateModifier.class.isAssignableFrom(c)) {
				Msg.error(this,
					"Language " + language.getLanguageID() + " does not specify a valid " +
						GhidraLanguagePropertyKeys.EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS);
				throw new RuntimeException(classname + " does not implement interface " +
					EmulateInstructionStateModifier.class.getName());
			}
			Class<? extends EmulateInstructionStateModifier> instructionStateModifierClass =
				(Class<? extends EmulateInstructionStateModifier>) c;
			Constructor<? extends EmulateInstructionStateModifier> constructor =
				instructionStateModifierClass.getConstructor(Emulate.class);
			instructionStateModifier = constructor.newInstance(this);
		}
		catch (Exception e) {
			Msg.error(this, "Language " + language.getLanguageID() + " does not specify a valid " +
				GhidraLanguagePropertyKeys.EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS);
			throw new RuntimeException(
				"Failed to instantiate " + classname + " for language " + language.getLanguageID(),
				e);
		}
	}

    public SleighLanguage getLanguage() {
        return this.language;
    }

    protected AddressFactory getAddrFactory() {
        return addrFactory;
    }

    public BreakTable getBreaktable() {
        return breaktable;
    }

	/// \return the memory state object which this emulator uses
    public MemoryState getMemoryState() {
        return memState;
    }

    public UniqueMemoryBank getUniqueBank() {
        return uniqueBank;
    }

    public EmulateInstructionStateModifier getInstructionStateModifier() {
        return instructionStateModifier;
    }

    public abstract void setExecuteAddress(Address address);
    public abstract Address getExecuteAddress();
}
