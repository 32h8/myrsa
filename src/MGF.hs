{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE NumericUnderscores #-}

module MGF
    ( mgf1
    , prop_mgf1_len
    , prop_mgf1_v1v2
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Word ( Word8 )
import Data.Bits
import Crypto.Util (bs2i, i2bs)
import qualified Crypto.Hash.SHA256 as SHA256

import qualified Data.ByteString.UTF8 as BSU
import Test.QuickCheck

mgf1 = mgf1_v2

prop_mgf1_len = 
    \(xs :: [Word8]) -> let seed = B.pack xs in
        forAll (chooseInt (0, 300)) $ \len -> 
            len == B.length (mgf1 seed len)

-- length in octets
mgf1_v1 :: ByteString -> Int -> ByteString
mgf1_v1 seed len = 
    if len > (hLen `shiftL` 32)
    then error "mask too long"
    else go 0 B.empty
    where
    bitsIn4bytes :: Int = 8 * 4
    hLen :: Int = 32
    go :: Int -> ByteString -> ByteString
    go counter t =
        if B.length t < len
        then 
            let c :: ByteString = i2bs bitsIn4bytes $ fromIntegral counter
            in go (counter + 1) $ B.append t $ SHA256.hash $ B.append seed c
        else B.take len t

mgf1_v2 :: ByteString -> Int -> ByteString
mgf1_v2 seed len = 
    if len > (hLen `shiftL` 32)
    then error "mask too long"
    else go 0 0 []
    where
    bitsIn4bytes :: Int = 8 * 4
    hLen :: Int = 32
    go :: Int -> Int -> [ByteString] -> ByteString
    go l counter bss =
        if l < len
        then 
            let c :: ByteString = i2bs bitsIn4bytes $ fromIntegral counter
            in go (l + hLen) (counter + 1) $ (:bss) $ SHA256.hash $ B.append seed c
        else B.take len $ B.concat $ reverse bss

prop_mgf1_v1v2 :: String  -> Property
prop_mgf1_v1v2 s = forAll (chooseInt (100, 300)) $ \len ->
    let seed = BSU.fromString "bar" in
        mgf1_v2 seed len == mgf1_v1 seed len
