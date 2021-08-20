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
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.GhidraLanguagePropertyKeys;
import ghidra.program.model.lang.InstructionBlock;
import ghidra.program.model.lang.InstructionError;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractEmulate {
    private final SleighLanguage language;
    private final AddressFactory addrFactory;

    private BreakTable breaktable; ///< The table of breakpoints
    private MemoryState memState; /// the memory state of the emulator
    private UniqueMemoryBank uniqueBank;

	protected int instructionLength; ///< Length of current instruction in bytes (must include any delay slots)
    private InstructionBlock lastPseudoInstructionBlock;
	private Disassembler pseudoDisassembler;
	private Instruction pseudoInstruction;
	protected RegisterValue nextContextRegisterValue = null;

    private EmulateMemoryStateBuffer memBuffer; // used for instruction parsing

    protected EmulateInstructionStateModifier instructionStateModifier;


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

        memBuffer =
			new EmulateMemoryStateBuffer(memState, getAddrFactory().getDefaultAddressSpace().getMinAddress());

//		emitterContext = new EmulateDisassemblerContext(lang, s);

		pseudoDisassembler =
			Disassembler.getDisassembler(language, getAddrFactory(), TaskMonitor.DUMMY, null);
    }

	/**
	 * Get the length of last emitted instruction. This should be valid after calling emitPcode
	 * @return the length of last emitted instruction.
	 */
	public int getLastEmittedInstructionLength() {
		return this.instructionLength;
	}
    
    /**
	 * Get length of instruction including any delay-slotted instructions.
	 * Must be called by emitPcode with lastPseudoInstructionBlock properly set.
	 * @param instr
	 * @return length of instruction in bytes for use in computing fall-through location
	 */
	private int getInstructionLength(Instruction instr) throws InstructionDecodeException {
		int length = instr.getLength();
		int delaySlots = instr.getDelaySlotDepth();
		while (delaySlots != 0) {
			try {
				Address nextAddr = instr.getAddress().addNoWrap(instr.getLength());
				Instruction nextInstr = lastPseudoInstructionBlock.getInstructionAt(nextAddr);
				if (nextInstr == null) {
					throw new InstructionDecodeException("Failed to parse delay slot instruction",
						nextAddr);
				}
				instr = nextInstr;
				length += instr.getLength();
				--delaySlots;
			}
			catch (AddressOverflowException e) {
				throw new InstructionDecodeException(
					"Failed to parse delay slot instruction at end of address space",
					instr.getAddress());
			}
		}
		return length;
	}

	protected PcodeOp[] emitPcode(Address addr) throws InstructionDecodeException {

		memBuffer.setAddress(addr);
		pseudoInstruction = null;

		if (lastPseudoInstructionBlock != null) {
			pseudoInstruction = lastPseudoInstructionBlock.getInstructionAt(addr);
			if (pseudoInstruction != null) {
				instructionLength = getInstructionLength(pseudoInstruction);
				return pseudoInstruction.getPcode(false);
			}

			InstructionError error = lastPseudoInstructionBlock.getInstructionConflict();
			if (error != null && addr.equals(error.getInstructionAddress())) {
				throw new InstructionDecodeException(error.getConflictMessage(), addr);
			}

		}

		lastPseudoInstructionBlock =
			pseudoDisassembler.pseudoDisassembleBlock(memBuffer, nextContextRegisterValue, 1);
		nextContextRegisterValue = null;
		if (lastPseudoInstructionBlock != null) {
			pseudoInstruction = lastPseudoInstructionBlock.getInstructionAt(addr);
			if (pseudoInstruction != null) {
				instructionLength = getInstructionLength(pseudoInstruction);
				return pseudoInstruction.getPcode(false);
			}
			InstructionError error = lastPseudoInstructionBlock.getInstructionConflict();
			if (error != null && addr.equals(error.getInstructionAddress())) {
				throw new InstructionDecodeException(error.getConflictMessage(), addr);
			}
		}

		throw new InstructionDecodeException("unknown reason", addr);
	}

	/**
	 * Returns the current context register value.  The context value returned reflects
	 * its state when the previously executed instruction was 
	 * parsed/executed.  The context value returned will feed into the next 
	 * instruction to be parsed with its non-flowing bits cleared and
	 * any future context state merged in.  If no instruction has been executed,
	 * the explicitly set context will be returned.  A null value is returned
	 * if no context register is defined by the language or initial context has 
	 * not been set.
	 */
	public RegisterValue getContextRegisterValue() {
		Register contextReg = getLanguage().getContextBaseRegister();
		if (contextReg == null) {
			return null;
		}
		if (pseudoInstruction != null) {
			return pseudoInstruction.getRegisterValue(contextReg);
		}
		return nextContextRegisterValue;
	}

	/**
	 * Sets the context register value at the current execute address.
	 * The Emulator should not be running when this method is invoked.
	 * Only flowing context bits should be set, as non-flowing bits
	 * will be cleared prior to parsing on instruction.  In addition,
	 * any future context state set by the pcode emitter will
	 * take precedence over context set using this method.  This method
	 * is primarily intended to be used to establish the initial 
	 * context state.
	 * @param regValue
	 */
	public void setContextRegisterValue(RegisterValue regValue) {
		
		if (regValue != null) {
			Register reg = regValue.getRegister();
			if (!reg.isProcessorContext()) {
				throw new IllegalArgumentException("processor context register required");
			}
			if (!reg.isBaseRegister()) {
				regValue = regValue.getBaseRegisterValue();
				reg = regValue.getRegister();
				if (nextContextRegisterValue != null) {
					regValue = nextContextRegisterValue.combineValues(regValue);
				}
			}
			if (!reg.equals(getLanguage().getContextBaseRegister())) {
				throw new IllegalArgumentException("invalid processor context register");
			}
		}
		nextContextRegisterValue = regValue;
		lastPseudoInstructionBlock = null;
		pseudoInstruction = null;
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
