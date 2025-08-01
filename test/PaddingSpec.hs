{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE NumericUnderscores #-}

module PaddingSpec where

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck
import Padding

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Word ( Word8 )
import Control.Exception (evaluate)

spec :: Spec
spec = do
    addPaddingSpec
    stripPaddingSpec

addPaddingSpec :: Spec
addPaddingSpec =
    describe "add padding tests" $ do
        it "handles empty ByteString" $
            let len = 100
                padding = B.replicate len (fromIntegral len)
            in pad len B.empty `shouldBe` (padding, Nothing)
        it "handles full ByteString" $
            let len = 100
                full = B.replicate len 0b010
                padding = B.replicate len (fromIntegral len)
            in pad len full `shouldBe` (full, Just padding)
        it "pad to 255 bytes" $
            let len = 255
                inputLen = 10
                input = B.replicate inputLen 0b101
                paddingLen = len - inputLen
                padding = B.replicate paddingLen $ fromIntegral paddingLen
                output = B.append input padding
            in pad len input `shouldBe` (output, Nothing)
        it "throws when padding to 256 bytes" $
            let len = 256
                inputLen = 10
                input = B.replicate inputLen 0b101
            in evaluate (pad len input) `shouldThrow` anyErrorCall
        it "throws when padding too long input" $
            let len = 20
                inputLen = len + 1
                input = B.replicate inputLen 0b101
            in evaluate (pad len input) `shouldThrow` anyErrorCall
        it "throws when target length is zero" $
            evaluate (pad 0 B.empty) `shouldThrow` anyErrorCall
        it "throws when target length less than zero" $
            evaluate (pad (-1) B.empty) `shouldThrow` anyErrorCall
        prop "padding needed" $
            forAll (chooseInt (1, 255)) $ \len ->
            forAll (chooseInt (0, len - 1)) $ \inputLen ->
            \(b :: Word8) ->
            let input = B.replicate inputLen b
                paddingLen = len - inputLen
                padding = B.replicate paddingLen (fromIntegral paddingLen)
                output = B.append input padding
            in pad len input == (output, Nothing)
        prop "padding not needed" $
            forAll (chooseInt (1, 255)) $ \len ->
            \(b :: Word8) ->
            let input = B.replicate len b
                padding = B.replicate len (fromIntegral len)
            in pad len input == (input, Just padding)

stripPaddingSpec :: Spec
stripPaddingSpec =
    describe "strip padding tests" $ do
        prop "pad then strip" $
            forAll (chooseInt (1, 255)) $ \len ->
            forAll (chooseInt (0, len - 1)) $ \inputLen ->
            \(b :: Word8) ->
            let input = B.replicate inputLen b
            in input == (stripPadding $ fst $ pad len input)
