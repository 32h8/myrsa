{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE NumericUnderscores #-}

module OAEPSpec where

import OAEP

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Control.Exception (evaluate)

spec :: Spec
spec = do
    describe "encode decode" $ do
        modifyMaxSuccess (const 1000) $ 
            prop "encode then decode" $
                prop_encodeDecode
    describe "decode" $ do 
        it "throws when input has wrong size" $
            let k = 128
                bs = B.replicate (k - 1) 0b101
            in evaluate (decode k bs) `shouldThrow` anyErrorCall
        it "throws when first byte is not 0x00" $
            let k = 128
                bs = B.replicate (k - 1) 0b101
            in evaluate (decode k bs) `shouldThrow` anyErrorCall
