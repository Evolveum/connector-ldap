/**
 * Copyright (c) 2021 DAASI International
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.evolveum.polygon.connector.ldap.ad;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;

public class AdUserParametersHandler {

    private static final String stringSeperatorChar = Integer.toHexString(0).toUpperCase()
            + Integer.toHexString(0).toUpperCase();
    private static final Log LOG = Log.getLog(AdUserParametersHandler.class);
    public static final String USER_PARAMETERS_LDAP_ATTR_NAME = "userParameters";
    // bytes before that position are reserved for microsoft
    public static final int SIGNATURE_POSITION = 96;
    public static final int NUMBER_OF_ATTRIBUTES_POSITION = 98;

    public static final Charset CHARSET = StandardCharsets.UTF_16LE;
    public static final Charset ASCII_CHARSET = StandardCharsets.US_ASCII;

    public static final long CNF_PRESENT_DEFAULT = 0x551e0bb0L;
        
    // value of raw userParameters (value in LDAP)
    private byte[] userParameters;

    /**
     * Bit positions of flags contained in the CtxCfgFlags1 attribute contained by
     * userParameters
     */
    public static enum CtxCfgFlagsBitValues {
        UNDEFINED1(0x00000000), UNDEFINED2(0x00000001), UNDEFINED3(0x00000002), UNDEFINED4(0x10000000),
        UNDEFINED5(0x20000000), UNDEFINED6(0x40000000), UNDEFINED7(0x80000000), INHERITCALLBACK(0x08000000),
        INHERITCALLBACKNUMBER(0x04000000), INHERITSHADOW(0x02000000), INHERITMAXSESSIONTIME(0x01000000),
        INHERITMAXDISCONNECTIONTIME(0x00800000), INHERITMAXIDLETIME(0x00400000), INHERITAUTOCLIENT(0x00200000),
        INHERITSECURITY(0x00100000), PROMPTFORPASSWORD(0x00080000), RESETBROKEN(0x00040000), RECONNECTSAME(0x00020000),
        LOGONDISABLED(0x00010000), AUTOCLIENTDRIVES(0x00008000), AUTOCLIENTLPTS(0x00004000),
        FORCECLIENTLPTDEF(0x00002000), DISABLEENCRYPTION(0x00001000), HOMEDIRECTORYMAPROOT(0x00000800),
        USEDEFAULTGINA(0x00000400), DISABLECPM(0x00000200), DISABLECDM(0x00000100), DISABLECCM(0x00000080),
        DISABLELPT(0x00000040), DISABLECLIP(0x00000020), DISABLEEXE(0x00000010), WALLPAPERDISABLED(0x00000008),
        DISABLECAM(0x00000004);

        private long mask;

        CtxCfgFlagsBitValues(long mask) {
            this.mask = mask;
        }

        public boolean isBit(long val) {
            return ((val & mask) == mask);
        }

        /**
         * Sets corresponding bit in incoming integer to 1 or 0 depending on boolean
         * set.
         * 
         * @param val incoming value of flags integer
         * @param set if true will set bit to 1 otherwise 0
         * @return updated flags integer value
         */
        public long setBit(long flagsVal, boolean set) {
            if (set) {
                flagsVal |= mask;
            } else {
                flagsVal &= ~mask;
            }
            return flagsVal;
        }

        /**
         * 
         * @param paramName
         * @return is incoming CtxCfgFlagparam name is contained by this enumaration
         */
        public static boolean contains(String paramName) {
            boolean result = false;
            for (CtxCfgFlagsBitValues val : values()) {
                if (val.name().equals(paramName)) {
                    result = true;
                    break;
                }
            }
            return result;
        }
    }

    /**
     * Maps different numbers to string values used in the CtxShadow attribute
     * contained by userParameters
     *
     */
    private static enum CtxShadowValues {
        DISABLE(0x0, "Disable"), ENABLE_INPUT_NOTIFY(0x1000000, "EnableInputNotify"),
        ENABLE_INPUT_NO_NOTIFY(0x2000000, "EnableInputNoNotify"),
        ENABLE_NO_INPUT_NOTIFY(0x3000000, "EnableNoInputNotify"),
        ENABLE_NO_INPUT_NO_NOTIFY(0x4000000, "EnableNoInputNoNotify");

        private int value;
        private String description;

        CtxShadowValues(int value, String description) {
            this.value = value;
            this.description = description;
        }

        public int getValue() {
            return value;
        }

        public String getDescription() {
            return description;
        }

        /**
         * Finds the CtxShadowValues object corresponding to the given number
         * 
         * @param value number value of searched CtxShadowValues instance
         * @return corresponding CtxShadowValues instance or null if nothing matches.
         */
        public static CtxShadowValues getByValue(int value) {
            CtxShadowValues result = null;
            for (CtxShadowValues next : CtxShadowValues.values()) {
                if (next.getValue() == value) {
                    result = next;
                    break;
                }
            }
            return result;
        }

        /**
         * Finds the CtxShadowValues object corresponding to the given string
         * description
         * 
         * @param description string value of searched CtxShadowValues instance
         * @return corresponding CtxShadowValues instance or null if nothing matches.
         */
        public static CtxShadowValues getByDescription(String description) {
            CtxShadowValues result = null;
            for (CtxShadowValues next : CtxShadowValues.values()) {
                if (next.getDescription().equals(description)) {
                    result = next;
                    break;
                }
            }
            return result;
        }
    }

    /**
     * These are all possible types of a userParameters attribute
     */
    public static enum UserParametersValueTypes {
        INTEGER_VALUE, STRING_VALUE, SHADOW_VALUE, TIME_VALUE, FLAG_VALUE;
    }

    /**
     * This contains all supported userParameters attributes with their names and
     * their value types
     */
    public static enum UserParametersAttributes {
        CTX_CFG_PRESENT("CtxCfgPresent", UserParametersValueTypes.INTEGER_VALUE, 8),
        CTX_CFG_FLAGS1("CtxCfgFlags1", UserParametersValueTypes.FLAG_VALUE, 8),
        CTX_CALL_BACK("CtxCallBack", UserParametersValueTypes.INTEGER_VALUE, 8),
        CTX_KEYBOARD_LAYOUT("CtxKeyboardLayout", UserParametersValueTypes.INTEGER_VALUE, 8),
        CTX_MIN_ENCRYPTION_LEVEL("CtxMinEncryptionLevel", UserParametersValueTypes.INTEGER_VALUE, 2, true),
        CTX_NW_LOGON_SERVER("CtxNWLogonServer", UserParametersValueTypes.INTEGER_VALUE, 8),
        CTX_MAX_CONNECTION_TIME("CtxMaxConnectionTime", UserParametersValueTypes.TIME_VALUE, 8),
        CTX_MAX_DISCONNECTION_TIME("CtxMaxDisconnectionTime", UserParametersValueTypes.TIME_VALUE, 8),
        CTX_MAX_IDLE_TIME("CtxMaxIdleTime", UserParametersValueTypes.TIME_VALUE, 8),
        CTX_SHADOW("CtxShadow", UserParametersValueTypes.SHADOW_VALUE, 8), CTX_WF_HOME_DIR_DRIVE("CtxWFHomeDirDrive"),
        CTX_WF_HOME_DIR("CtxWFHomeDir"), CTX_WF_HOME_DRIVE("CtxWFHomeDrive"), CTX_INITIAL_PROGRAM("CtxInitialProgram"),
        CTX_WF_PROFILE_PATH("CtxWFProfilePath"), CTX_WORK_DIRECTORY("CtxWorkDirectory"),
        CTX_CALLBACK_NUMBER("CtxCallbackNumber");

        // userParameters attribute name
        private String name;
        // attribute type
        private UserParametersValueTypes type;
        // attribute length in bytes (numbers are stored in hex -> 32 bit integer = 8
        // bit hex)
        private int length;
        // is number representation signed
        private boolean signedInt;

        UserParametersAttributes(String name) {
            this(name, UserParametersValueTypes.STRING_VALUE);
        }

        UserParametersAttributes(String name, UserParametersValueTypes type) {
            this(name, type, 0);
        }

        UserParametersAttributes(String name, UserParametersValueTypes type, int length) {
            this(name, type, length, false);
        }

        UserParametersAttributes(String name, UserParametersValueTypes type, int length, boolean signed) {
            this.name = name;
            this.type = type;
            this.length = length;
            this.signedInt = signed;
        }

        public String getName() {
            return name;
        }

        public UserParametersValueTypes getType() {
            return type;
        }

        public int getLength() {
            return length;
        }

        public boolean isSignedInt() {
            return signedInt;
        }

        public static UserParametersAttributes getByName(String name) {
            UserParametersAttributes result = null;
            if (isWideStringAttr(name)) {
                name = name.substring(0, name.length() - 1);
            }
            for (UserParametersAttributes next : values()) {
		// we ignore case here since it is possible that other applications write
		// atrtibutes with case insensitive names
                if (next.getName().equalsIgnoreCase(name)) {
                    result = next;
                    break;
                }
            }

            return result;
        }

    }

    /**
     * Adds the provided value for parameter into global userParameters variable.
     * Note that the original value of userParameters must be set before the first
     * change. Call getUserParameters after all changes are done to get the value
     * that can be inserted into ad.
     * 
     * @param paramName  name of parameter to add/update
     * @param paramValue value of parameter to add/update
     * @throws AdUserParametersHandlerException if any error happens (see message)
     */
    public void toLdap(String paramName, Object paramValue) throws AdUserParametersHandlerException {
        LOG.ok("AdUserParametersHandler toLdap is called with attrName {0} and attrVal {1}", paramName, paramValue);
        boolean delete = paramValue == null;

        // build new value
        byte[] arrayValue = delete ? new byte[0] : getValueByteArray(paramName, paramValue);
        // all flag values are written in the same userParameters attribute
        if (CtxCfgFlagsBitValues.contains(paramName)) {
            paramName = UserParametersAttributes.CTX_CFG_FLAGS1.name;
            if (delete) {
                // you can't delete flags, therefore set it to false
                paramValue = false;
                delete = false;
            }
        }
        byte[] paramNameArray = paramName.getBytes(CHARSET);

        // check if attribute already contained in existing userParameters
        boolean foundExisting = false;
        if (userParameters != null) {
            ByteBuffer buffer = getByteBuffer(userParameters);
            buffer.position(SIGNATURE_POSITION);
            char signature = buffer.getChar();
            if (signature == 'P') {
                int nbAttrs = (int) buffer.getChar();
                for (int i = 0; i < nbAttrs; i++) {
                    AttributeBuilder nextAttrBuilder = new AttributeBuilder();
                    int nameLength = (int) buffer.getChar();
                    int valueLengthPosition = buffer.position();
                    int valueLength = (int) buffer.getChar();
                    int type = (int) buffer.getChar();
                    
                    byte[] attrNameTab = new byte[nameLength];
                    buffer.get(attrNameTab);
                    String attrName = new String(attrNameTab, CHARSET);
                    nextAttrBuilder.setName(attrName);
                    LOG.ok("Valuelength of attr {0} is {1}", attrName, valueLength);
                    byte[] attrValue = new byte[valueLength];
                    buffer.get(attrValue);
                    if (attrName.equalsIgnoreCase(paramName)) {
                        updateExistingAttribute(delete, arrayValue, buffer.position(), nbAttrs, nameLength,
                                valueLengthPosition, valueLength, attrName, attrValue);
                        foundExisting = true;
                        break;
                    }
                }
            } else {
                throw new AdUserParametersHandlerException("Signature of userParameters was violated!");
            }

        }
        if (!foundExisting && !delete) {
            if (userParameters == null) {
                appendAttribute(intToHexaByteArray(CNF_PRESENT_DEFAULT, 8), UserParametersAttributes.CTX_CFG_PRESENT.name.getBytes(CHARSET));
            }
            appendAttribute(arrayValue, paramNameArray);
        }
        // if a string value is edited the wide string value must be edited as well
        UserParametersAttributes userParametersAttr = UserParametersAttributes.getByName(paramName);
        if (userParametersAttr != null && userParametersAttr.getType().equals(UserParametersValueTypes.STRING_VALUE)) {
            if (!isWideStringAttr(paramName)) {
                toLdap(paramName + "W", paramValue);
            }
        }
    }

    /**
     * Will update existing attribute in userparameters
     * @param delete should the attribute be deleted instead of updated?
     * @param updatedValue updated value of the attribute
     * @param positionAfterValue buffer position after current attribute value
     * @param nbAttrs total number of attributes contained in userParameters
     * @param nameLength length of the attribute name
     * @param valueLengthPosition position of information about value length in the buffer
     * @param valueLength length of old attribute value
     * @param attrName attribute name
     * @param attrValue old attribute value
     */
    private void updateExistingAttribute(boolean delete, byte[] updatedValue, int positionAfterValue,
            int nbAttrs, int nameLength, int valueLengthPosition, int valueLength, String attrName, byte[] attrValue) {
        LOG.ok("Found existing entry of attribute {0} and will update it", attrName);
        int positionPreValue;
        int positionAfterValueNew;
        if (delete) {
            // delete value, name and information about valueLength, nameLength and type,
            // which are all 2 byte -> 3 * 2 byte
            positionPreValue = positionAfterValue - valueLength - nameLength - 3 * 2;
            positionAfterValueNew = positionAfterValue;
        } else {
            positionPreValue = positionAfterValue - valueLength;
            positionAfterValueNew = positionPreValue + attrValue.length;
        }

        byte[] arrayBeforeValue = Arrays.copyOfRange(userParameters, 0, positionPreValue);
        byte[] arrayAfterValue = Arrays.copyOfRange(userParameters, positionAfterValueNew,
                userParameters.length);
        byte[] updated = ArrayUtils.addAll(arrayBeforeValue, updatedValue);
        updated = ArrayUtils.addAll(updated, arrayAfterValue);

        ByteBuffer updatedBuffer = getByteBuffer(updated);
        if (!delete) {
            // update value length
            updatedBuffer.putChar(valueLengthPosition, (char) updatedValue.length);
        } else {
            // update number of attributes
            updatedBuffer.putChar(NUMBER_OF_ATTRIBUTES_POSITION, (char) (nbAttrs - 1));
        }
        updatedBuffer.position(0);
        userParameters = new byte[updatedBuffer.remaining()];
        updatedBuffer.get(userParameters);
    }

    /**
     * Appends not contained attribute to userparameters
     * @param arrayValue value of the new attribute
     * @param paramNameArray
     * @param paramNameLength
     * @throws AdUserParametersHandlerException
     */
    private void appendAttribute(byte[] arrayValue, byte[] paramNameArray)
            throws AdUserParametersHandlerException {
        // append new attribute to existing userParameters
        // there are 96 spaces before actual values + 2 bytes of information (signature
        // + number of attributes
        int currentSize = userParameters == null ? SIGNATURE_POSITION + 2 * 2 : userParameters.length;

        int paramNameLength = paramNameArray.length;
        int newValueLength = arrayValue.length;
        // 3 chars (a 2 bytes) representing namelength, valuelength, type
        int updatedSize = currentSize + 3 * 2 + paramNameLength + arrayValue.length;
       
        
        byte[] updatedParameters = new byte[updatedSize];
        if (userParameters != null) {
            System.arraycopy(userParameters, 0, updatedParameters, 0, userParameters.length);
        }
        ByteBuffer buffer = getByteBuffer(updatedParameters);
        if (userParameters == null) {
            // somehow the first 80 bytes must look like this 32,0,32,0,...
            for (int i = 0; i<SIGNATURE_POSITION; i+=2) {
                buffer.position(i).putChar((char)32);
            }
            buffer.position(SIGNATURE_POSITION).putChar('P');
            buffer.position(NUMBER_OF_ATTRIBUTES_POSITION).putChar((char) 0);
        }
        buffer.position(SIGNATURE_POSITION);
        char signature = buffer.getChar();
        LOG.ok("Signature : " + signature);
        if (signature != 'P') {
            throw new AdUserParametersHandlerException("Signature of userParameters was violated!");
        }
        int nbAttrsInit = (int) buffer.getChar();
        int updatedAttrsNum = nbAttrsInit + 1;
        buffer.position(NUMBER_OF_ATTRIBUTES_POSITION).putChar((char) (updatedAttrsNum));
        signature = buffer.position(SIGNATURE_POSITION).getChar();
        int nbAttrs = (int) buffer.position(NUMBER_OF_ATTRIBUTES_POSITION).getChar();

        buffer.position(currentSize).putChar((char) paramNameLength);
        buffer.position(currentSize + 2).putChar((char) newValueLength);
        buffer.position(currentSize + 4).putChar((char) 1);
        buffer.position(currentSize + 6).put(paramNameArray, 0, paramNameLength);
        buffer.position(currentSize + 6 + paramNameLength).put(arrayValue, 0, newValueLength);
        buffer.position(0);
        userParameters = new byte[buffer.remaining()];
        buffer.get(userParameters);
    }

    /**
     * creates a new ByteBuffer from given byteArray with order LITTLE_ENDIAN and
     * initial position 96
     * 
     * @param byteArray
     * @return created ByteBuffer
     */
    private ByteBuffer getByteBuffer(byte[] byteArray) {
        ByteBuffer updatedBuffer = ByteBuffer.wrap(byteArray);
        updatedBuffer.order(ByteOrder.LITTLE_ENDIAN);
        updatedBuffer.position(SIGNATURE_POSITION);
        return updatedBuffer;
    }

    /**
     * builds the value of provided parameter to be inserted into userParameters
     * byte array
     * 
     * @param paramName  name of the parameter
     * @param paramValue value of the parameter (either string or boolean)
     * @return byte array representation in userParameters
     * @throws AdUserParametersHandlerException parameter name is not known
     */
    private byte[] getValueByteArray(String paramName, Object paramValue) throws AdUserParametersHandlerException {
        byte[] result = null;
        CtxCfgFlagsBitValues flagAttr = null;
        UserParametersAttributes attr = UserParametersAttributes.getByName(paramName);
        if (attr == null) {
            if (CtxCfgFlagsBitValues.contains(paramName)) {
                flagAttr = CtxCfgFlagsBitValues.valueOf(paramName);
            }
            if (flagAttr == null) {
                throw new AdUserParametersHandlerException("Unknown userParameter attribute " + paramName);
            }
        }
        if (attr != null) {
            switch (attr.getType()) {
            case TIME_VALUE:
            case INTEGER_VALUE:
                if (!(paramValue instanceof String)) {
                    throw new AdUserParametersHandlerException("Invalid userParameters attribute value type "
                            + paramValue.getClass().getName() + " for integer (but string represented) type parameter");
                }
                int intValue = Integer.parseInt((String) paramValue);
                result = intToHexaByteArray(intValue, attr.getLength());
                break;
            case SHADOW_VALUE:
                if (!(paramValue instanceof String)) {
                    throw new AdUserParametersHandlerException("Invalid userParameters attribute value type "
                            + paramValue.getClass().getName() + " for Shadow (e.g. String) type parameter");
                }
                String paramValueStr = (String) paramValue;
                CtxShadowValues shadowValue = CtxShadowValues.getByDescription(paramValueStr);
                if (shadowValue == null) {
                    throw new IllegalArgumentException("Unsupported CtxShadowValue " + paramValueStr);
                }

                result = intToHexaByteArray(shadowValue.getValue(), attr.getLength());
                break;
            case STRING_VALUE:
                if (!(paramValue instanceof String)) {
                    throw new AdUserParametersHandlerException("Invalid userParameters attribute value type "
                            + paramValue.getClass().getName() + " for String type parameter");
                }
                String hexValue = convertStringToHex((String) paramValue, true, isWideStringAttr(paramName));
                result = ((String) hexValue).getBytes(ASCII_CHARSET);
                break;
            default:
                throw new AdUserParametersHandlerException(
                        "Unkown userParameter attr type " + attr.getType().toString());
            }
        } else {
            byte[] flagArray;
            long currentFlagsVal = getCurrentFlagVal();
            LOG.ok("Currentflag value: {0}", currentFlagsVal);
            if (paramValue instanceof Boolean) {
                long updatedFlagsVal = flagAttr.setBit(currentFlagsVal, (boolean) paramValue);
                flagArray = intToHexaByteArray(updatedFlagsVal, 8);
            } else {
                throw new AdUserParametersHandlerException("Unkown userParameter attr flag value type "
                        + paramValue.getClass().getName() + ". Expected boolean.");
            }
            // see #getRealValue for insights why we are doing this
            ArrayUtils.reverse(flagArray);
            result = new byte[flagArray.length];
            for (int i = 0; i<flagArray.length; i+=2) {
                result[i] = flagArray[i+1];
                result[i+1] = flagArray[i];
            }
        }
        return result;
    }

    /**
     * Creates a byte[] with given size that contains the characters of the
     * hexstring representation of given integer
     * 
     * @param paramValue integer to get the hex representation
     * @param size       of the hex and therefore size of the built byte array
     * @return byte array containing the characters of hex representation of given
     *         integer
     */
    private byte[] intToHexaByteArray(long paramValue, int size) {
        String hexString = Long.toHexString(paramValue);
        for (int i = hexString.length(); i < size; i++) {
            hexString = "0" + hexString;
        }
        ByteBuffer buffer = ByteBuffer.allocate(size);
        buffer.position(0);
        for (char c : hexString.toCharArray()) {
            byte b = (byte) c;
            buffer.put(b);
        }
        byte[] result = buffer.array();
        return result;
    }

    /**
     * 
     * @return the current int value of CtxCfgFlags1 parameter contained in global
     *         userParameters byte array representation
     * @throws AdUserParametersHandlerException if signature of global
     *                                          userParameters is violated
     */
    private long getCurrentFlagVal() throws AdUserParametersHandlerException {
        long currentValue = 0;
        if (userParameters != null) {
            ByteBuffer buffer = getByteBuffer(userParameters);
            buffer.position(SIGNATURE_POSITION);
            char signature = buffer.getChar();
            if (signature == 'P') {
                int nbAttrs = (int) buffer.getChar();
                for (int i = 0; i < nbAttrs; i++) {
                    int nameLength = (int) buffer.getChar();
                    int valueLength = (int) buffer.getChar();
                    int type = (int) buffer.getChar();
    
                    byte[] attrNameTab = new byte[nameLength];
                    buffer.get(attrNameTab);
                    byte[] attrValue = new byte[valueLength];
                    buffer.get(attrValue);
                    String attrName = new String(attrNameTab, CHARSET);
                    if (attrName.equals(UserParametersAttributes.CTX_CFG_FLAGS1.getName())) {
                        currentValue = getFlagValue(attrValue);
                    }
                }
            } else {
                throw new AdUserParametersHandlerException("Signature of userParameters was violated!");
            }
        }
        return currentValue;
    }

    /**
     * Converts the global userParameters into List of ICF attributes
     * 
     * @return List of ICF attributes built from global userParameters
     * @throws AdUserParametersHandlerException if any error occures (see message)
     */
    public List<Attribute> toIcf() throws AdUserParametersHandlerException {
        // build partition of parameter to real values
        if (userParameters == null) {
            throw new AdUserParametersHandlerException("userParameters must be set before parsing");
        }
        List<Attribute> result = new ArrayList<Attribute>();
        ByteBuffer buffer = ByteBuffer.wrap(userParameters);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.position(SIGNATURE_POSITION);
        char signature = buffer.getChar();
        LOG.ok("Signature when calling toIcf: " + signature);

        if (signature != 'P') {
            throw new AdUserParametersHandlerException("Signature of userParameters was violated!");
        }

        int nbAttrs = (int) buffer.getChar();
        LOG.ok("Number of userParameters attributes: " + nbAttrs);

        for (int i = 0; i < nbAttrs; i++) {
            AttributeBuilder nextAttrBuilder = new AttributeBuilder();
            int nameLength = (int) buffer.getChar();

            int valueLength = (int) buffer.getChar();
            int type = (int) buffer.getChar();

            byte[] attrNameTab = new byte[nameLength];
            buffer.get(attrNameTab);
            String attrName = new String(attrNameTab, CHARSET);
            LOG.ok("Next attribute: " + attrName + " with value length " + valueLength);
            byte[] attrValue = new byte[valueLength];
            buffer.get(attrValue);
            UserParametersAttributes userParametersAttribute = UserParametersAttributes.getByName(attrName);
            if (userParametersAttribute == null) {
                throw new AdUserParametersHandlerException("Unknown userParameter attribute " + attrName);
            }
            nextAttrBuilder.setName(userParametersAttribute.getName());

            boolean alreadyAdded = false;
            long valueLong;
            switch (userParametersAttribute.getType()) {
            case FLAG_VALUE:
                // this field is represented as a bitmask
                valueLong = getFlagValue(attrValue);
                alreadyAdded = true;
                for (CtxCfgFlagsBitValues en : CtxCfgFlagsBitValues.values()) {
                    boolean value = en.isBit(valueLong);
                    result.add(AttributeBuilder.build(en.name(), value));
                    LOG.ok("Setting flag " + en.name() + " to " + value);
                }
                LOG.ok("FLAGS long value: " + valueLong);
                break;
            case TIME_VALUE:
            case INTEGER_VALUE:
                valueLong = getIntValue(attrValue, userParametersAttribute.isSignedInt());
                nextAttrBuilder.addValue(valueLong);
                LOG.ok("attrValue : " + valueLong);
                break;
            case SHADOW_VALUE:
                valueLong = getIntValue(attrValue, false);
                CtxShadowValues value = CtxShadowValues.getByValue((int) valueLong);
                if (value == null) {
                    LOG.warn("Did not find CtxShadow value for integer value {0}", valueLong);
                } else {
                    nextAttrBuilder.addValue(value.getDescription());
                }
                LOG.ok("attrValue : " + valueLong);
                break;
            case STRING_VALUE:
                String str = new String(attrValue, ASCII_CHARSET);
                String valueStr = convertHexToString(str);
                valueStr = valueStr.substring(0, valueStr.length() - 1);

                if (isWideStringAttr(attrName)) {
                    // handle wide strings
                    valueStr = new String(
                            new String(valueStr.getBytes(ASCII_CHARSET), ASCII_CHARSET).getBytes(ASCII_CHARSET),
                            CHARSET);
                    valueStr = valueStr.substring(0, valueStr.length() - 1);
                }
                LOG.ok("attrValue : " + valueStr);
                nextAttrBuilder.addValue(valueStr);
                break;
            default:
                throw new AdUserParametersHandlerException(
                        "Unkown userParameter attr type " + userParametersAttribute.getType().toString());
            }
            if (!alreadyAdded) {
                result.add(nextAttrBuilder.build());
            }
        }
        LOG.ok("Returning {0} userParameters attributes", result.size());
        return result;

    }
    
    /**
     * Due to encoding in saved parameters we need to change the incoming array.
     * Read more here
     * https://stackoverflow.com/questions/47659621/how-can-i-read-the-content-of-the-user-parameters-attribute-of-an-active-directo
     * 
     * @param attrValue original bytes read from AD
     * @return real hex-interpretation of the bytes
     * @throws AdUserParametersHandlerException
     */
    private byte[] getRealValue(byte[] attrValue) throws AdUserParametersHandlerException {
        byte[] realValue = new byte[attrValue.length / 2];

        for (int i = 0; i<attrValue.length; i+=2) {
            byte first = attrValue[i];
            byte second = attrValue[i+1];
            char firstChar = (char) first;
            char secondChar = (char) second;
            String hexStr = String.valueOf(firstChar) + String.valueOf(secondChar);
            int firstInt = hexToInt(first);
            int secondInt = hexToInt(second);
            realValue[i/2] = (byte) (firstInt << 4 | secondInt);
            LOG.ok("Next real hex value: " + hexStr);
        }
        ArrayUtils.reverse(realValue);
        return realValue;
    }

    private static int hexToInt(byte value) throws AdUserParametersHandlerException {
        if ('0' <= value && value <= '9') {
            return value - '0';
        }

        if ('a' <= value && value <= 'f') {
            return value - 'a' + 10;
        }

        if ('A' <= value && value <= 'F') {
            return value - 'A' + 10;
        }

        throw new AdUserParametersHandlerException("Invalid character.");
    }

    /**
     * Returns empty user parameters
     * @return
     */
    public String getDefaultUserParameters() {
        byte[] defaultUserParameters = new byte[NUMBER_OF_ATTRIBUTES_POSITION+4];
        ByteBuffer buffer = getByteBuffer(defaultUserParameters);
        for (int i = 0; i<SIGNATURE_POSITION; i+=2) {
            buffer.position(i).putChar((char)32);
        }
        buffer.position(SIGNATURE_POSITION).putChar('P');
        buffer.position(NUMBER_OF_ATTRIBUTES_POSITION).putChar((char) 0);
        return new String(defaultUserParameters, CHARSET);
    }

    /**
     * this converts a byte array to an integer. That byte array contains the string
     * representation of a hex representation of the given integer.
     * We use Long to convert to handle unsigned integers.
     * 
     * @param attrValue
     * @return
     * @throws AdUserParametersHandlerException 
     */
    private long getIntValue(byte[] attrValue, boolean signed) throws AdUserParametersHandlerException {
        Long valueLong;
        String valueStr = "";

        for (byte b : attrValue) {
            char nextChar = (char) b;
            LOG.ok("Next byte value: {0}", nextChar);
            valueStr += nextChar;
        }

        if (signed) {
            valueLong =  Long.parseLong(valueStr, 16);
        } else {
            valueLong =  Long.parseUnsignedLong(valueStr, 16);
        }
        return valueLong;
    }
    
    /**
     * Gets the decimal value of provided byte array handled as CtxCfgFlags1
     * 
     */
    private long getFlagValue(byte[] attrValue) throws AdUserParametersHandlerException {
        byte[] attrValueReal = getRealValue(attrValue);
        return new BigInteger(attrValueReal).longValueExact();
    }

    /**
     * converts a hex string to a string with char representation of each digit of
     * the hex string
     * 
     * @param hex string
     * @return
     */
    public static String convertHexToString(String hex) {

        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < hex.length() - 1; i += 2) {
            // grab the hex in pairs
            String output = hex.substring(i, (i + 2));
            // convert hex to decimal
            int decimal = Integer.parseUnsignedInt(output, 16);
            // convert the decimal to character
            sb.append((char) decimal);
        }
        return sb.toString();
    }

    /**
     * converts a each char of a string to its hex representation and appends it to
     * the result.
     * 
     * @param str
     * @param appendSuffix if set will append two '0' to the result. String
     *                     parameters are stored like this in userParameters
     *                     internally
     * @return hex string representation of the chars of given string
     */
    public static String convertStringToHex(String str, boolean appendSuffix, boolean wideString) {
        StringBuilder sb = new StringBuilder();
        char[] ch = str.toCharArray();
        for (char c : ch) {
            int i = (int) c;
            sb.append(Integer.toHexString(i).toUpperCase());
            if (wideString) {
                sb.append(stringSeperatorChar);
            }
        }
        // wide strings need an extra seperator char
        if (wideString) {
            sb.append(stringSeperatorChar);
        }
        if (appendSuffix) {
            sb.append(stringSeperatorChar);
        }
        return sb.toString();
    }

    public String getUserParameters() {
        String result = null;
        if (userParameters != null) {
            result = new String(userParameters, CHARSET);
        }
        else {
            result = getDefaultUserParameters();
        }
        return result;
    }

    public void setUserParameters(String userParameters) {
        this.userParameters = userParameters.getBytes(CHARSET);
    }

    public static boolean isUserParametersAttribute(String attrName) {
        boolean result = false;
        LOG.ok("Checking {0}...", attrName);
        result = UserParametersAttributes.getByName(attrName) != null || CtxCfgFlagsBitValues.contains(attrName);

        return result;
    }

    public static boolean isWideStringAttr(String attrName) {
        return attrName.matches(".*W$");
    }

}
