/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.coolbitx.wallet.signing.scriptlib;

import com.coolbitx.wallet.signing.utils.HexUtil;
import com.coolbitx.wallet.signing.utils.ScriptArgumentComposer;
import com.coolbitx.wallet.signing.utils.ScriptAssembler;
import com.coolbitx.wallet.signing.utils.ScriptData;
import com.coolbitx.wallet.signing.utils.ScriptData.Buffer;
import com.google.common.base.Strings;

public class BtcScript {

    public static void main(String[] args) {
        listAll();
    }

    public static void listAll() {
        System.out.println("Btc: \n" + getBTCScript(false) + "\n");
        System.out.println("USDT: \n" + getUSDTScript(false) + "\n");
    }

    public static String getAddressScript(boolean isTestnet, ScriptData argOutputScriptType, ScriptData argOutputDest20, ScriptData argOutputDest32) {
        String hrp = !isTestnet ? "bc" : "tb";
        String hrpExpand = "";
        for (int i = 0; i < hrp.length(); i++) {
            hrpExpand += HexUtil.toHexString((hrp.charAt(i) >> 5) & 7, 1);
        }
        hrpExpand += "00";
        for (int i = 0; i < hrp.length(); i++) {
            hrpExpand += HexUtil.toHexString(hrp.charAt(i) & 31, 1);
        }
        String bech32Address = new ScriptAssembler()
                .ifRange(argOutputScriptType, "02", "03",
                        new ScriptAssembler().copyString(hrpExpand + "00", Buffer.CACHE2).getScript(), // vitness version 0
                        // 04
                        new ScriptAssembler().copyString(hrpExpand + "01", Buffer.CACHE2).getScript()) // vitness version 1
                .ifEqual(argOutputScriptType, "02",
                        new ScriptAssembler().baseConvert(argOutputDest20, Buffer.CACHE2, 32, ScriptAssembler.binary32Charset, ScriptAssembler.bitLeftJustify8to5).getScript(),
                        // 03, 04
                        new ScriptAssembler().baseConvert(argOutputDest32, Buffer.CACHE2, 52, ScriptAssembler.binary32Charset, ScriptAssembler.bitLeftJustify8to5).getScript()
                )
                .copyString("000000000000", Buffer.CACHE2)
                .ifRange(argOutputScriptType, "02", "03",
                        new ScriptAssembler().bech32Polymod(ScriptData.getDataBufferAll(Buffer.CACHE2), Buffer.CACHE1).getScript(),
                        // 04
                        new ScriptAssembler().bech32mPolymod(ScriptData.getDataBufferAll(Buffer.CACHE2), Buffer.CACHE1).getScript())
                .clearBuffer(Buffer.CACHE2)
                .copyString(HexUtil.toHexString(hrp + "1p"), Buffer.CACHE2)
                .ifEqual(argOutputScriptType, "02",
                        new ScriptAssembler().baseConvert(argOutputDest20, Buffer.CACHE2, 32, ScriptAssembler.base32BitcoinCashCharset, ScriptAssembler.bitLeftJustify8to5).getScript(),
                        new ScriptAssembler().baseConvert(argOutputDest32, Buffer.CACHE2, 52, ScriptAssembler.base32BitcoinCashCharset, ScriptAssembler.bitLeftJustify8to5).getScript()
                )
                .baseConvert(ScriptData.getDataBufferAll(Buffer.CACHE1), Buffer.CACHE2, 6, ScriptAssembler.base32BitcoinCashCharset, 0)
                .showAddress(ScriptData.getDataBufferAll(Buffer.CACHE2))
                .getScript();

        String addressScript = new ScriptAssembler()
                // if P2PKH/P2SH , base58 address
                .ifRange(argOutputScriptType, "00", "01",
                        new ScriptAssembler().switchString(argOutputScriptType, Buffer.CACHE2, !isTestnet ? "00,05" : "6F,C4") // 1,3:mn,2
                                .copyArgument(argOutputDest20, Buffer.CACHE2)
                                .hash(ScriptData.getDataBufferAll(Buffer.CACHE2), Buffer.CACHE2, ScriptAssembler.HashType.DoubleSHA256)
                                .baseConvert(ScriptData.getBuffer(Buffer.CACHE2, 0, 25), Buffer.CACHE1, 0, ScriptAssembler.base58Charset, ScriptAssembler.zeroInherit)
                                .showAddress(ScriptData.getDataBufferAll(Buffer.CACHE1))
                                .getScript(), // else P2WPKH/P2WSH , bech32 address
                        bech32Address).getScript();
        return addressScript;
    }

    public static String getBTCScript(boolean isTestnet) {
        ScriptArgumentComposer sac = new ScriptArgumentComposer();
        ScriptData argReverseVersion = sac.getArgument(4);
        ScriptData argHashPrevouts = sac.getArgument(32);
        ScriptData argHashSequences = sac.getArgument(32);
        ScriptData argZeroPadding = sac.getArgument(4);
        // Depending on destination address
        // P2PKH  = 00 start with 1
        // P2SH   = 01 start with 3
        // P2WPKH = 02 start with bc1 and decode to 20bytes
        // P2WSH  = 03 start with bc1 and decode to 32bytes
        // P2TR   = 04 start with bc1 and decode to 32bytes
        ScriptData argOutputScriptType = sac.getArgument(1);
        ScriptData argOutputAmount = sac.getArgument(8);
        ScriptData argOutputDest20 = sac.getArgumentUnion(12, 20);
        ScriptData argOutputDest32 = sac.getArgument(32);
        ScriptData argHaveChange = sac.getArgument(1);
        ScriptData argChangeScriptType = sac.getArgument(1);
        ScriptData argChangeAmount = sac.getArgument(8);
        ScriptData argChangePath = sac.getArgument(21);
        ScriptData argReverseSequence = sac.getArgument(4);
        ScriptData argReverseLockTime = sac.getArgument(4);
        ScriptData argReverseHashType = sac.getArgument(4);

        String addressScript = getAddressScript(isTestnet, argOutputScriptType, argOutputDest20, argOutputDest32);

        String script = new ScriptAssembler()
                .setCoinType(0x00)
                .copyArgument(argReverseVersion)
                .copyArgument(argHashPrevouts)
                .copyArgument(argHashSequences)
                .utxoDataPlaceholder(argZeroPadding)
                .copyArgument(argReverseSequence)
                .baseConvert(argOutputAmount, Buffer.CACHE1, 8, ScriptAssembler.binaryCharset, ScriptAssembler.littleEndian)
                // switch redeemScript P2PKH=00,P2SH=01,P2WPKH=02,P2WSH=03
                .switchString(argOutputScriptType, Buffer.CACHE1, "1976A914,17A914,160014,220020,[]")
                .ifEqual(argOutputScriptType, "03",
                        new ScriptAssembler().copyArgument(argOutputDest32, Buffer.CACHE1).getScript(),
                        new ScriptAssembler().copyArgument(argOutputDest20, Buffer.CACHE1).getScript())
                .switchString(argOutputScriptType, Buffer.CACHE1, "88AC,87,[],[],[]")
                // if haveChange
                .ifEqual(argHaveChange, "01",
                        new ScriptAssembler()
                                .baseConvert(argChangeAmount, Buffer.CACHE1, 8, ScriptAssembler.binaryCharset, ScriptAssembler.littleEndian)
                                .derivePublicKey(argChangePath, Buffer.CACHE2)
                                .switchString(argChangeScriptType, Buffer.CACHE1, "1976A914,17A914,160014")
                                // if P2PKH
                                .ifEqual(argChangeScriptType, "00",
                                        new ScriptAssembler().hash(ScriptData.getDataBufferAll(Buffer.CACHE2), Buffer.CACHE1, ScriptAssembler.HashType.SHA256RipeMD160).getScript(),
                                        "")
                                // if P2WPKH in P2SH
                                .ifEqual(argChangeScriptType, "01",
                                        new ScriptAssembler().copyString("0014", Buffer.CACHE2)
                                                .hash(ScriptData.getBuffer(Buffer.CACHE2, 0, 33), Buffer.CACHE2, ScriptAssembler.HashType.SHA256RipeMD160)
                                                .hash(ScriptData.getBuffer(Buffer.CACHE2, 33, 22), Buffer.CACHE1, ScriptAssembler.HashType.SHA256RipeMD160).getScript(),
                                        "")
                                .switchString(argChangeScriptType, Buffer.CACHE1, "88AC,87,[]").getScript(), "")
                .hash(ScriptData.getDataBufferAll(Buffer.CACHE1), Buffer.TRANSACTION, ScriptAssembler.HashType.DoubleSHA256)
                .copyArgument(argReverseLockTime)
                .copyArgument(argReverseHashType)
                .clearBuffer(Buffer.CACHE1)
                .clearBuffer(Buffer.CACHE2)
                .showMessage("BTC")
                .insertString(addressScript)
                .showAmount(argOutputAmount, 8)
                .showPressButton()
                .setHeader(ScriptAssembler.HashType.DoubleSHA256, ScriptAssembler.SignType.ECDSA).getScript();
        return script;
    }

    public static String BTCScriptSignature = Strings.padStart("3045022100cb805153b688bd7c778861baa0a938463b66ab1149145141eb4caa8947409c6502204049a8dc5fc00445be5f60deb8337838cf034180f23b973c5d7ac9c044d8e482", 144, '0');
//    public static String BTCScriptSignature = Strings.padEnd("FA", 144, '0');

    public static String getUSDTScript(boolean isTestnet) {
        ScriptArgumentComposer sac = new ScriptArgumentComposer();
        ScriptData argReverseVersion = sac.getArgument(4);
        ScriptData argHashPrevouts = sac.getArgument(32);
        ScriptData argHashSequences = sac.getArgument(32);
        ScriptData argZeroPadding = sac.getArgument(4);
        // Depending on destination address
        // P2PKH  = 00 start with 1
        // P2SH   = 01 start with 3
        // P2WPKH = 02 start with bc1 and decode to 20bytes
        // P2WSH  = 03 start with bc1 and decode to 32bytes
        ScriptData argOutputScriptType = sac.getArgument(1);
        ScriptData argUsdtDust = sac.getArgument(8);
        ScriptData argOutputAmount = sac.getArgument(8);
        ScriptData argOutputDest20 = sac.getArgumentUnion(12, 20);
        ScriptData argOutputDest32 = sac.getArgument(32);
        ScriptData argHaveChange = sac.getArgument(1);
        ScriptData argChangeScriptType = sac.getArgument(1);
        ScriptData argChangeAmount = sac.getArgument(8);
        ScriptData argChangePath = sac.getArgument(21);
        ScriptData argReverseSequence = sac.getArgument(4);
        ScriptData argReverseLockTime = sac.getArgument(4);
        ScriptData argReverseHashType = sac.getArgument(4);

        String addressScript = getAddressScript(isTestnet, argOutputScriptType, argOutputDest20, argOutputDest32);

        String script = new ScriptAssembler()
                .setCoinType(0x00)
                .copyArgument(argReverseVersion)
                .copyArgument(argHashPrevouts)
                .copyArgument(argHashSequences)
                .utxoDataPlaceholder(argZeroPadding)
                .copyArgument(argReverseSequence)
                .baseConvert(argUsdtDust, Buffer.CACHE1, 8, ScriptAssembler.binaryCharset, ScriptAssembler.littleEndian)
                // switch redeemScript P2PKH=00,P2SH=01,P2WPKH=02,P2WSH=03
                .switchString(argOutputScriptType, Buffer.CACHE1, "1976A914,17A914,160014,220020")
                .ifEqual(argOutputScriptType, "03",
                        new ScriptAssembler().copyArgument(argOutputDest32, Buffer.CACHE1).getScript(),
                        new ScriptAssembler().copyArgument(argOutputDest20, Buffer.CACHE1).getScript())
                .switchString(argOutputScriptType, Buffer.CACHE1, "88AC,87,[],[]")
                .copyString("0000000000000000166a146f6d6e69000000000000001f", Buffer.CACHE1)
                .copyArgument(argOutputAmount, Buffer.CACHE1)
                // if haveChange
                .ifEqual(argHaveChange, "01",
                        new ScriptAssembler()
                                .baseConvert(argChangeAmount, Buffer.CACHE1, 8, ScriptAssembler.binaryCharset, ScriptAssembler.littleEndian)
                                .derivePublicKey(argChangePath, Buffer.CACHE2)
                                .switchString(argChangeScriptType, Buffer.CACHE1, "1976A914,17A914,160014")
                                // if P2PKH
                                .ifEqual(argChangeScriptType, "00",
                                        new ScriptAssembler().hash(ScriptData.getDataBufferAll(Buffer.CACHE2), Buffer.CACHE1, ScriptAssembler.HashType.SHA256RipeMD160).getScript(),
                                        "")
                                // if P2WPKH in P2SH
                                .ifEqual(argChangeScriptType, "01",
                                        new ScriptAssembler().copyString("0014", Buffer.CACHE2)
                                                .hash(ScriptData.getBuffer(Buffer.CACHE2, 0, 33), Buffer.CACHE2, ScriptAssembler.HashType.SHA256RipeMD160)
                                                .hash(ScriptData.getBuffer(Buffer.CACHE2, 33, 22), Buffer.CACHE1, ScriptAssembler.HashType.SHA256RipeMD160).getScript(),
                                        "")
                                .switchString(argChangeScriptType, Buffer.CACHE1, "88AC,87,[]").getScript(), "")
                .hash(ScriptData.getDataBufferAll(Buffer.CACHE1), Buffer.TRANSACTION, ScriptAssembler.HashType.DoubleSHA256)
                .copyArgument(argReverseLockTime)
                .copyArgument(argReverseHashType)
                .clearBuffer(Buffer.CACHE1)
                .clearBuffer(Buffer.CACHE2)
                .showMessage("BTC")
                .showMessage("USDT")
                .insertString(addressScript)
                .showAmount(argOutputAmount, 8)
                .showPressButton()
                .setHeader(ScriptAssembler.HashType.DoubleSHA256, ScriptAssembler.SignType.ECDSA).getScript();
        return script;
    }

    public static String USDTScriptSignature = Strings.padStart("3045022076e7c6a62c1c5bb1e1a82d6deb7e12fbbfbd1d757fece058e28cb076281325fe022100adf483e7cc12ae814bd447517dbed3850b6324ab122c9454416916bae6734c80", 144, '0');
//    public static String USDTScriptSignature = Strings.padEnd("FA", 144, '0');
}
