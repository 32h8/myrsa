{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE NumericUnderscores #-}

module MGFSpec where

import MGF

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck
import MGF (mgf1, prop_mgf1_v1v2)

import qualified Data.ByteString.UTF8 as BSU
import qualified Data.Text as T 
import Text.Hex (encodeHex, decodeHex)

spec :: Spec
spec = do
    describe "mgf1" $ do
        prop "length check" $
            prop_mgf1_len
        prop "equal to other implementation" $
            prop_mgf1_v1v2
        it "handles example" $
            let outhex :: T.Text = encodeHex $ mgf1 (BSU.fromString "bar") 50
            in outhex `shouldBe` T.pack "382576a7841021cc28fc4c0948753fb8312090cea942ea4c4e735d10dc724b155f9f6069f289d61daca0cb814502ef04eae1"
