/*
 * To change this license header, choose License Headers in Project Properties. To change this
 * template file, choose Tools | Templates and open the template in the editor.
 */
package com.coolbitx.wallet.signing.scriptlib;

import com.coolbitx.wallet.signing.utils.HexUtil;
import com.coolbitx.wallet.signing.utils.ScriptArgumentComposer;
import com.coolbitx.wallet.signing.utils.ScriptAssembler;
import com.coolbitx.wallet.signing.utils.ScriptData;
import com.coolbitx.wallet.signing.utils.ScriptAssembler.HashType;
import com.coolbitx.wallet.signing.utils.ScriptAssembler.SignType;
import com.coolbitx.wallet.signing.utils.ScriptData.Buffer;

public class VlxScript {

    public static void listAll() {
        System.out.println("Vlx eip1559: \n" + getEIP1559TransferScript() + "\n");
        System.out.println("Vlx eip1559 erc20: \n" + getEIP1559ERC20Script() + "\n");
        System.out.println("Vlx eip1559 Smart Contract: \n" + getEIP1559SmartContractScript() + "\n");
        System.out.println("Vlx eip1559 Smart Contract Segment: \n" + getEIP1559SmartContractSegmentScript() + "\n");
        System.out.println("Vlx transfer: \n" + getTransferScript() + "\n");
        System.out.println("Vlx erc20: \n" + getERC20Script() + "\n");
        System.out.println("Vlx Smart Contract: \n" + getVelasContractBlindScript() + "\n");
        System.out.println("Vlx Smart Contract Segment: \n" + getVelasContractBlindSegmentScript() + "\n");
        System.out.println("Vlx Message: \n" + getMessageScript() + "\n");
        System.out.println("Vlx TypedData: \n" + getTypedDataScript() + "\n");
    }

    /*
    txType(EIP-2718) : 02
    rlpLength :        e5
    chainId :          01
    nonce :            80
    maxPriorityFee :   01
    maxFee :           81 ff
    gasLimit :         84 02625a00
    to address :       94 cccccccccccccccccccccccccccccccccccccccc
    value :            83 0186a0
    data :             80
    accessList :       c0
     */
    public static String getEIP1559TransferScript() {
        ScriptArgumentComposer sac = new ScriptArgumentComposer();
        ScriptData argTo = sac.getArgument(20);
        ScriptData argValue = sac.getArgumentRightJustified(10);
        ScriptData argGasTipCap = sac.getArgumentRightJustified(10);
        ScriptData argGasFeeCap = sac.getArgumentRightJustified(10);
        ScriptData argGasLimit = sac.getArgumentRightJustified(10);
        ScriptData argNonce = sac.getArgumentRightJustified(8);

        String script = new ScriptAssembler()
                // set coinType to 3C
                .setCoinType(0x3C)
                // txType (EIP-2718)
                .copyString("02").arrayPointer()
                // chainId
                .copyString("6A")
                // nonce
                .rlpString(argNonce)
                // gasTipCap (maxPriorityFeePerGas)
                .rlpString(argGasTipCap)
                // gasFeeCap (maxFeePerGas)
                .rlpString(argGasFeeCap)
                // gasLimit
                .rlpString(argGasLimit)
                // toAddress
                .copyString("94").copyArgument(argTo)
                // value
                .rlpString(argValue)
                // data
                .copyString("80")
                // accessList
                .copyString("C0")
                .arrayEnd(1)
                // txDetail
                .showMessage("VLX")
                .copyString(HexUtil.toHexString("0x"), Buffer.CACHE2)
                .baseConvert(argTo, Buffer.CACHE2, 0, ScriptAssembler.hexadecimalCharset,
                        ScriptAssembler.zeroInherit)
                .showAddress(ScriptData.getDataBufferAll(Buffer.CACHE2)).showAmount(argValue, 18)
                .showPressButton()
                // version=04 ScriptAssembler.hash=06=ScriptAssembler.Keccak256 sign=01=ECDSA
                .setHeader(HashType.Keccak256, SignType.ECDSA).getScript();
        return script;
    }

    public static String ETHEIP1559ScriptSignature
            = "3046022100F3CA891D06B8284C01B9E51CD478E7BBA14CD99F137383F2EAD642747222E2F9022100A121B0DE524F00D063DAB9E51E86B4CAF1B1874F79570AEE1AA437DFAD750C1C";

    /*
    txType(EIP-2718) : 02
    rlpLength :        f86a
    chainId :          01
    nonce :            80
    maxPriorityFee :   01
    maxFee :           81 ff
    gasLimit :         84 02625a00
    to address :       94 cccccccccccccccccccccccccccccccccccccccc
    value :            83 0186a0
    data :             b844 a9059cbb
                    0000000000000000000000009e3a6e03298780078003d3965689b8f653ee87b1
                    0000000000000000000000000000000000000000000000004563918244f40000
    accessList :       c0
     */
    public static String getEIP1559ERC20Script() {
        ScriptArgumentComposer sac = new ScriptArgumentComposer();
        ScriptData argTo = sac.getArgument(20);
        ScriptData argValue = sac.getArgument(12);
        ScriptData argGasTipCap = sac.getArgumentRightJustified(10);
        ScriptData argGasFeeCap = sac.getArgumentRightJustified(10);
        ScriptData argGasLimit = sac.getArgumentRightJustified(10);
        ScriptData argNonce = sac.getArgumentRightJustified(8);
        ScriptData argTokenInfo = sac.getArgumentUnion(0, 29);
        ScriptData argDecimal = sac.getArgument(1);
        ScriptData argNameLength = sac.getArgument(1);
        ScriptData argName = sac.getArgumentVariableLength(7);
        ScriptData argContractAddress = sac.getArgument(20);
        ScriptData argSign = sac.getArgument(72);

        String script = new ScriptAssembler()
                // set coinType to 3C
                .setCoinType(0x3C)
                // txType (EIP-2718)
                .copyString("02")
                .arrayPointer()
                // chainId
                .copyString("6A").rlpString(argNonce).rlpString(argGasTipCap)
                .rlpString(argGasFeeCap).rlpString(argGasLimit).copyString("94")
                .copyArgument(argContractAddress)
                // data, Length = 68
                .copyString("80B844a9059cbb000000000000000000000000").copyArgument(argTo)
                .copyString("0000000000000000000000000000000000000000").copyArgument(argValue)
                // accessList
                .copyString("C0").arrayEnd(1).showMessage("VLX")
                .ifSigned(argTokenInfo, argSign, "",
                        new ScriptAssembler().copyString(HexUtil.toHexString("@"), Buffer.CACHE2)
                                .getScript())
                // txDetail
                .setBufferInt(argNameLength, 1, 7)
                .copyArgument(argName, Buffer.CACHE2)
                .showMessage(ScriptData.getDataBufferAll(Buffer.CACHE2))
                .clearBuffer(Buffer.CACHE2)
                .copyString(HexUtil.toHexString("0x"), Buffer.CACHE2)
                .baseConvert(argTo, Buffer.CACHE2, 0, ScriptAssembler.hexadecimalCharset,
                        ScriptAssembler.zeroInherit)
                .showAddress(ScriptData.getDataBufferAll(Buffer.CACHE2))
                .setBufferInt(argDecimal, 0, 20)
                .showAmount(argValue, 1000)
                .showPressButton()
                // version=04 ScriptAssembler.hash=06=ScriptAssembler.Keccak256 sign=01=ECDSA
                .setHeader(HashType.Keccak256, SignType.ECDSA).getScript();
        return script;
    }

    public static String ETHEIP1559ERC20ScriptSignature
            = "00304502207A63FB17CEA7E123C1BF12CBE3687614FCD677DE13171CC0B275E9659421762A022100ED2A5EC6AB2736C1D9087033CB48181784859A10C8A9674ADEFE34A84D520646";

    public static String getEIP1559SmartContractScript() {
        ScriptArgumentComposer sac = new ScriptArgumentComposer();
        ScriptData argTo = sac.getArgument(20);
        ScriptData argValue = sac.getArgumentRightJustified(10);
        ScriptData argGasTipCap = sac.getArgumentRightJustified(10);
        ScriptData argGasFeeCap = sac.getArgumentRightJustified(10);
        ScriptData argGasLimit = sac.getArgumentRightJustified(10);
        ScriptData argNonce = sac.getArgumentRightJustified(8);
        ScriptData argData = sac.getArgumentAll();

        String script
                = // set coinType to 3C
                new ScriptAssembler()
                        .setCoinType(0x3C)
                        // txType (EIP-2718)
                        .copyString("02")
                        .arrayPointer()
                        // chainId
                        .copyString("6A")
                        .rlpString(argNonce)
                        .rlpString(argGasTipCap)
                        .rlpString(argGasFeeCap)
                        .rlpString(argGasLimit)
                        .copyString("94")
                        .copyArgument(argTo)
                        .rlpString(argValue)
                        .rlpString(argData)
                        // accessList
                        .copyString("C0")
                        .arrayEnd(1)
                        // txDetail
                        .showMessage("VLX")
                        .showWrap("SMART", "")
                        .showPressButton()
                        // version=04 ScriptAssembler.hash=06=ScriptAssembler.Keccak256 sign=01=ECDSA
                        .setHeader(HashType.Keccak256, SignType.ECDSA)
                        .getScript();

        return script;
    }

    public static String ETHEIP1559SmartScriptSignature
            = "003045022100D28537F886B9330A61BB88B7ED436A4E66C50A03EDB883FCB78279FE2C704BD402205C2E473AA2302133B659D7BD95FD8D7D80B7BF5C1B65FCC4519E7B189600BA89";

    public static String getEIP1559SmartContractSegmentScript() {
        ScriptArgumentComposer sac = new ScriptArgumentComposer();
        ScriptData argTo = sac.getArgument(20);
        ScriptData argValue = sac.getArgumentRightJustified(10);
        ScriptData argGasTipCap = sac.getArgumentRightJustified(10);
        ScriptData argGasFeeCap = sac.getArgumentRightJustified(10);
        ScriptData argGasLimit = sac.getArgumentRightJustified(10);
        ScriptData argNonce = sac.getArgumentRightJustified(8);
        ScriptData argData = sac.getArgument(4);

        String script = new ScriptAssembler()
                // set coinType to 3C
                .setCoinType(0x3C)
                // txType (EIP-2718)
                .copyString("02")
                .arrayPointer()
                // chainId
                .copyString("6A")
                .rlpString(argNonce)
                .rlpString(argGasTipCap)
                .rlpString(argGasFeeCap)
                .rlpString(argGasLimit)
                .copyString("94")
                .copyArgument(argTo)
                .rlpString(argValue)
                .rlpDataPlaceholder(argData)
                // accessList
                .copyString("C0").arrayEnd(1).showMessage("VLX").showWrap("SMART", "")
                .showPressButton()
                // version=05 ScriptAssembler.hash=06=ScriptAssembler.Keccak256 sign=01=ECDSA
                .setHeader(HashType.Keccak256, SignType.ECDSA).getScript();
        return script;
    }

    public static String ETHEIP1559SmartSegmentScriptSignature
            = "003045022100F994CBD35DA01724AE1189B299F80FB5DD6A304EB0C27E5DBA7B9AD6588C92E70220170BBE5ADFF78C30FDA82784ED4C647D6D855EBACC5F13D8C171C5E529E1AF39";

    /*
    E7
    2A
    85 09C74AFE1F
    82 5208
    94 A3255ECFE3F6727A62D938F4C29B2F73C361B26C
    83 989680
    80
    03
    80
    80
     */
    public static String getTransferScript() {
        ScriptArgumentComposer sac = new ScriptArgumentComposer();
        ScriptData argTo = sac.getArgument(20);
        ScriptData argValue = sac.getArgumentRightJustified(10);
        ScriptData argGasPrice = sac.getArgumentRightJustified(10);
        ScriptData argGasLimit = sac.getArgumentRightJustified(10);
        ScriptData argNonce = sac.getArgumentRightJustified(8);

        String script = new ScriptAssembler()
                // set coinType to 3C
                .setCoinType(0x3C)
                // temp byte for rlpList
                // .copyString("C0")
                .arrayPointer()
                // nonce
                .rlpString(argNonce)
                // gasPrice
                .rlpString(argGasPrice)
                // gasLimit
                .rlpString(argGasLimit)
                // toAddress
                .copyString("94")
                .copyArgument(argTo)
                // value
                .rlpString(argValue)
                // data
                .copyString("80")
                // chainId v
                // + ScriptAssembler.rlpString(argChainId)
                .copyString("6A", Buffer.CACHE1)
                .rlpString(ScriptData.getDataBufferAll(Buffer.CACHE1))
                // r,s
                .copyString("8080")
                .arrayEnd(1)
                // .rlpList(1)
                // txDetail
                .showMessage("VLX")
                .copyString(HexUtil.toHexString("0x"), Buffer.CACHE2)
                .baseConvert(argTo, Buffer.CACHE2, 0, ScriptAssembler.hexadecimalCharset,
                        ScriptAssembler.zeroInherit)
                .showAddress(ScriptData.getDataBufferAll(Buffer.CACHE2))
                .showAmount(argValue, 18)
                .showPressButton()
                // version=00 ScriptAssembler.hash=06=ScriptAssembler.Keccak256 sign=01=ECDSA
                .setHeader(HashType.Keccak256, SignType.ECDSA).getScript();
        return script;
    }

    public static String ETHScriptSignature
            = "0030450220201C3ADEEF531C6CD6E8F082477FF048E45F39B85086C2F40BE96840CA4840F6022100C8A36252C7606D9F2D9E6F58538F967C7F6DEFEE52B536439512CB8CD9993DB0";

    /*
     * f86a 1e 85 01718c7e00 83 030d40 94 86fa049857e0209aa7d9e616f7eb3b3b78ecfdb0 80 b844 a9059cbb
     * 0000000000000000000000009e3a6e03298780078003d3965689b8f653ee87b1
     * 0000000000000000000000000000000000000000000000004563918244f40000 01 80 80
     */
    public static String getERC20Script() {
      ScriptArgumentComposer sac = new ScriptArgumentComposer();
      ScriptData argTo = sac.getArgument(20);
      ScriptData argValue = sac.getArgument(12);
      ScriptData argGasPrice = sac.getArgumentRightJustified(10);
      ScriptData argGasLimit = sac.getArgumentRightJustified(10);
      ScriptData argNonce = sac.getArgumentRightJustified(8);
      ScriptData argTokenInfo = sac.getArgumentUnion(0, 29);
      ScriptData argDecimal = sac.getArgument(1);
      ScriptData argNameLength = sac.getArgument(1);
      ScriptData argName = sac.getArgumentVariableLength(7);
      ScriptData argContractAddress = sac.getArgument(20);
      ScriptData argSign = sac.getArgument(72);

      String script = new ScriptAssembler()
              // set coinType to 3C
              .setCoinType(0x3C)
              .arrayPointer()
              // .copyString("F800")
              .rlpString(argNonce)
              .rlpString(argGasPrice)
              .rlpString(argGasLimit)
              .copyString("94")
              .copyArgument(argContractAddress)
              // data, Length = 68
              .copyString("80B844a9059cbb000000000000000000000000")
              .copyArgument(argTo)
              .copyString("0000000000000000000000000000000000000000")
              .copyArgument(argValue)
              // chainId v
              // .rlpString(argChainId)
              .copyString("6A", Buffer.CACHE1)
              .rlpString(ScriptData.getDataBufferAll(Buffer.CACHE1))
              // r,s
              .copyString("8080")
              // .rlpList(2)
              .arrayEnd(1)
              .showMessage("VLX")
              .ifSigned(
                      argTokenInfo,
                      argSign,
                      "",
                      new ScriptAssembler()
                              .copyString(HexUtil.toHexString("@"), Buffer.CACHE2)
                              .getScript()
              )
              .setBufferInt(argNameLength, 1, 7)
              .copyArgument(argName, Buffer.CACHE2)
              .showMessage(ScriptData.getDataBufferAll(Buffer.CACHE2))
              .clearBuffer(Buffer.CACHE2)
              .copyString(HexUtil.toHexString("0x"), Buffer.CACHE2)
              .baseConvert(
                      argTo,
                      Buffer.CACHE2,
                      0,
                      ScriptAssembler.hexadecimalCharset,
                      ScriptAssembler.zeroInherit
              )
              .showAddress(ScriptData.getDataBufferAll(Buffer.CACHE2))
              .setBufferInt(argDecimal, 0, 20)
              .showAmount(argValue, 1000)
              .showPressButton()
              // version=00 ScriptAssembler.hash=06=ScriptAssembler.Keccak256 sign=01=ECDSA
              .setHeader(HashType.Keccak256, SignType.ECDSA)
              .getScript();
      return script;
    }

    public static String ERC20ScriptSignature
            = "30460221009A706915A2EE0AE663ACF90D9DD59BBEEC111EB12B099E4751219DDC993A01E7022100BA25635AB68F4EF7711D8D880A0BB1A81CA899C78884ECC4183B715F8F047D69";

    public static String getVelasContractBlindScript() {
        ScriptArgumentComposer sac = new ScriptArgumentComposer();
        ScriptData argTo = sac.getArgument(20);
        ScriptData argValue = sac.getArgumentRightJustified(10);
        ScriptData argGasPrice = sac.getArgumentRightJustified(10);
        ScriptData argGasLimit = sac.getArgumentRightJustified(10);
        ScriptData argNonce = sac.getArgumentRightJustified(8);
        ScriptData argChainId = sac.getArgumentRightJustified(2);
        ScriptData argData = sac.getArgumentAll();

        String script = new ScriptAssembler()
                // set coinType to 3C
                .setCoinType(0x3C)
                .arrayPointer()
                // nonce
                .rlpString(argNonce)
                // gasPrice
                .rlpString(argGasPrice)
                // gasLimit
                .rlpString(argGasLimit)
                // toAddress
                .copyString("94")
                .copyArgument(argTo)
                // value
                .rlpString(argValue)
                // data
                .rlpString(argData)
                // chainId v
                //.rlpString(argChainId)
                .copyString("6A", Buffer.CACHE1)
                .rlpString(ScriptData.getDataBufferAll(Buffer.CACHE1))
                .copyString("8080")
                .arrayEnd(1)
                .showMessage("VLX")
                .showWrap("SMART", "")
                .showPressButton()
                // version=05 ScriptAssembler.hash=06=ScriptAssembler.Keccak256 sign=01=ECDSA
                .setHeader(HashType.Keccak256, SignType.ECDSA)
                .getScript();
        return script;
    }

    public static String EtherContractBlindScriptSignature
            = "3046022100EC9BC856CEC733451CF4063C60DE27F9E920F7423122CCA19DC47B82E694799C0221008F754911B9C966EF430ED8919A58333D9800E8EBF4FB98B06C797E991DA03697";

    public static String getVelasContractBlindSegmentScript() {
        ScriptArgumentComposer sac = new ScriptArgumentComposer();
        ScriptData argTo = sac.getArgument(20);
        ScriptData argValue = sac.getArgumentRightJustified(10);
        ScriptData argGasPrice = sac.getArgumentRightJustified(10);
        ScriptData argGasLimit = sac.getArgumentRightJustified(10);
        ScriptData argNonce = sac.getArgumentRightJustified(8);
        ScriptData argData = sac.getArgument(4);

        String script = new ScriptAssembler()
                // set coinType to 3C
                .setCoinType(0x3C).arrayPointer()
                // nonce
                .rlpString(argNonce)
                // gasPrice
                .rlpString(argGasPrice)
                // gasLimit
                .rlpString(argGasLimit)
                // toAddress
                .copyString("94").copyArgument(argTo)
                // value
                .rlpString(argValue)
                // data
                .rlpDataPlaceholder(argData)
                // chainId v
                .copyString("6A", Buffer.CACHE1)
                .rlpString(ScriptData.getDataBufferAll(Buffer.CACHE1))
                .copyString("8080")
                .arrayEnd(1)
                // txDetail
                .showMessage("VLX")
                .showWrap("SMART", "")
                .showPressButton()
                // version=05 ScriptAssembler.hash=06=ScriptAssembler.Keccak256 sign=01=ECDSA
                .setHeader(HashType.Keccak256, SignType.ECDSA).getScript();
        return script;
    }

    public static String EtherContractBlindSegmentScriptSignature
            = "003045022060FC29B9ACA3BDFA237ED377E410A9A9BB12FB88416C06298857AE17D688992D022100F87D2C80BBECDC7192FF64D13A28F7763D6E1610FC1B1254B3D6446822CBA414";

    public static String getMessageScript() {
        ScriptArgumentComposer sac = new ScriptArgumentComposer();
        ScriptData argMessage = sac.getArgumentAll();

        String script = new ScriptAssembler()
                // set coinType to 3C
                .setCoinType(0x3C)
                .copyString("19457468657265756D205369676E6564204D6573736167653A0A")
                .copyArgument(argMessage)
                // txDetail
                .showMessage("VLX")
                .showWrap("MESSAGE", "")
                .showPressButton()
                // version=00 ScriptAssembler.hash=06=ScriptAssembler.Keccak256 sign=01=ECDSA
                .setHeader(HashType.Keccak256, SignType.ECDSA).getScript();
        return script;
    }

    public static String EtherMessageBlindScriptSignature
            = "0000304402200745C5665A9CE0FA0C2894E77629A33077D9AE76F23566DC804C64BF38D27FC0022076645BEEF5A522A02D272DA3D7065D1F092C5C03B024A3F1B3A19C144CF98970";

    public static String getTypedDataScript() {
        ScriptArgumentComposer sac = new ScriptArgumentComposer();
        ScriptData argDomainSeparator = sac.getArgument(32);
        ScriptData argMessage = sac.getArgumentAll();

        String script = new ScriptAssembler()
                // set coinType to 3C
                .setCoinType(0x3C)
                .copyString("1901")
                .copyArgument(argDomainSeparator)
                .hash(argMessage, Buffer.TRANSACTION, ScriptAssembler.Keccak256)
                // txDetail
                .showMessage("VLX")
                .showWrap("EIP712", "")
                .showPressButton()
                // version=00 ScriptAssembler.hash=06=ScriptAssembler.Keccak256 sign=01=ECDSA
                .setHeader(HashType.Keccak256, SignType.ECDSA).getScript();
        return script;
    }

}
