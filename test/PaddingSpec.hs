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

spec :: Spec
spec = do
    describe "padding tests" $ do
        it "handles empty ByteString" $
            let len = 100
                b :: Word8 = fromIntegral len
            in pad len B.empty `shouldBe` (B.replicate len b, Nothing)
        it "handles full ByteString" $
            let len = 100
                full = B.replicate len 0b010
                padding = B.replicate len (fromIntegral len)
            in pad len full `shouldBe` (full, Just padding)

