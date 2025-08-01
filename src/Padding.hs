{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedRecordDot #-}

module Padding
    ( pad, stripPadding, maxEncInputBlockSize
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Word ( Word8 )

-- max block size allowed by current padding method
-- which assumes block size fits in 1 byte
maxEncInputBlockSize :: Int
maxEncInputBlockSize = 255

-- fill up the last block using PKCS #7
-- https://datatracker.ietf.org/doc/html/rfc2315#section-10.3
-- first arg is the traget block size (bytes)
pad :: Int -> ByteString -> (ByteString, Maybe ByteString)
pad k bs
    | k <= 0 = error "target length must be > 0"
    | k > maxEncInputBlockSize = error "currently padding is not implemented for input blocks bigger than 255 bytes"
    | B.length bs > k = error "bytestring is too big for padding"
    | otherwise = 
        if B.length bs == k
        then (check bs, Just $ check $ B.replicate k (fromIntegral k))
        else (check $ B.append bs padding, Nothing)
    where
    paddingLength :: Int
    paddingLength = k - (B.length bs `mod` k)
    padding :: ByteString
    padding = B.replicate paddingLength (fromIntegral paddingLength)

    check :: ByteString -> ByteString
    check bs = if B.length bs /= k then error "bytestring has wrong length" else bs

stripPadding :: ByteString -> ByteString
stripPadding bs = 
    if paddingLength > B.length bs
    then error "invalid padding: given padding length is bigger than block length"
    else
        let (original, padding) = B.splitAt originalLength bs
            validPadding = B.all (== B.last bs) padding
        in if validPadding
            then original
            else error "invalid padding"  
    where
        paddingLength :: Int = fromIntegral $ B.last bs
        originalLength = B.length bs - paddingLength
