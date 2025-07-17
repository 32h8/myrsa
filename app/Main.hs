{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedRecordDot #-}

module Main (main) where

import Lib

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Bits
import System.IO
import Control.Monad
import Crypto.Number.Prime (generatePrime)
import Crypto.Number.Basic (gcde)

import System.Environment (getArgs)
import Crypto.Util (bs2i, i2bs)
import GHC.Num (integerFromInt, integerToInt)

import Data.Semigroup ((<>))
import Options.Applicative

-- stack run -- --help
-- or
-- stack build
-- stack exec myrsa-exe -- -h

newtype PubKey = PubKey (Integer, Integer)
newtype PrivKey = PrivKey (Integer, Integer)

-- returns floor of logarithm with base 2
myLog :: Integer -> Int
myLog x =
    if x <= 1
    then 0
    else 1 + myLog (x `div` 2)

nOfBits :: Integer -> Int
nOfBits x = 1 + myLog x  

pubKeyFileName :: String
pubKeyFileName = "PUB.txt"
privKeyFileName :: String
privKeyFileName = "PRIV.txt"

data Opts = Opts
    { optCommand :: !Command }

data Command
    = Encrypt EncOpts
    | Decrypt DecOpts
    | GenKeys GenKeysOpts

data EncOpts = EncOpts
    { optEncInput :: FilePath
    , optEncOutput :: FilePath
    , optEncKey :: FilePath
    }

data DecOpts = DecOpts
    { optDecInput :: FilePath
    , optDecOutput :: FilePath
    , optDecKey :: FilePath
    }

data GenKeysOpts = GenKeyOpts
    { optKeySize :: Int
    , optPrivKey :: FilePath
    , optPubKey :: FilePath
    }

currentVersion :: String
currentVersion = "0.1.0.0"

main :: IO ()
main = do
    (opts :: Opts) <- execParser optsParser
    case optCommand opts of
        Encrypt e -> runEncrypt e 
        Decrypt d -> runDecrypt d
        GenKeys keysOpts -> runGenKeys keysOpts
    
    where
    optsParser :: ParserInfo Opts
    optsParser =
        info
            (helper <*> versionOption <*> programOptions)
            (fullDesc <> progDesc "Encrypts files using RSA algorithm (without padding)." <> 
                header "myrsa - an encryption CLI tool for educational purposes" <>
                footer "Note: This is an experimental tool. The size of last input chunk is appended to output file in plaintext.")
    
    versionOption :: Parser (a -> a)
    versionOption = infoOption currentVersion (long "version" <> help "Show version")

    programOptions :: Parser Opts
    programOptions =
        Opts <$> hsubparser (encCommand <> decCommand <> genKeysCommand)

    encCommand :: Mod CommandFields Command
    encCommand =
        command 
            "enc"
            (info (Encrypt <$> encOptions) (progDesc "Encrypt a file"))
    
    encOptions :: Parser EncOpts
    encOptions =
        EncOpts <$>
        strArgument (metavar "IN_FILE" <> help "Input filename") <*>
        strArgument (metavar "OUT_FILE" <> help "Output filename") <*>
        strOption
            (short 'k' <> metavar "KEY_FILE" <> showDefault <> value pubKeyFileName <> help "Public key filename")

    decCommand :: Mod CommandFields Command
    decCommand =
        command 
            "dec"
            (info (Decrypt <$> decOptions) (progDesc "Decrypt a file"))

    decOptions :: Parser DecOpts
    decOptions =
        DecOpts <$>
        strArgument (metavar "IN_FILE" <> help "Input filename") <*>
        strArgument (metavar "OUT_FILE" <> help "Output filename") <*>
        strOption
            (short 'k' <> metavar "KEY_FILE" <> showDefault <> value privKeyFileName <> help "Private key filename")

    genKeysCommand :: Mod CommandFields Command
    genKeysCommand =
        command
            "gen" 
            (info (GenKeys <$> genKeysOptions) (progDesc "Generate keys"))

    genKeysOptions :: Parser GenKeysOpts
    genKeysOptions =
        GenKeyOpts <$>
        option auto (long "key-size" <> short 's' <> help "Key size (modulus size in bits)" <> showDefault <> value 2048 <> metavar "BITS") <*>
        strOption (long "pri" <> metavar "PRIVATE_KEY_FILE" <> showDefault <> value privKeyFileName <> help "Private key file") <*>
        strOption (long "pub" <> metavar "PUBLIC_KEY_FILE" <> showDefault <> value pubKeyFileName <> help "Public key file")

readPrivKey :: FilePath -> IO PrivKey
readPrivKey file = do
    putStrLn $ "reading private key from file " ++ file 
    hFlush stdout
    (n, d) <- readIntegers file
    putStrLn $ "modulus size: " ++ show (nOfBits n) ++ " bits" 
    hFlush stdout
    return $ PrivKey (n, d)

readPubKey :: FilePath -> IO PubKey
readPubKey file = do
    putStrLn $ "reading public key from file " ++ file 
    hFlush stdout
    (n, e) <- readIntegers file
    putStrLn $ "modulus size: " ++ show (nOfBits n) ++ " bits" 
    hFlush stdout
    return $ PubKey (n, e)

readIntegers :: FilePath -> IO (Integer, Integer)
readIntegers file = do
    handle <- openFile file ReadMode
    str1 <- hGetLine handle
    let a = read str1 :: Integer
    str2 <- hGetLine handle
    let b = read str2 :: Integer
    hClose handle
    return (a, b)

writeIntegers :: FilePath -> Integer -> Integer -> IO ()
writeIntegers file a b = do
    handle <- openFile file WriteMode
    hPutStrLn handle $ show a
    hPutStrLn handle $ show b
    hClose handle
    
-- number of bytes in encryption input block
-- argument is modulus
encInputBlockSize :: Integer -> Int
encInputBlockSize n
    | n <= (2^8 - 1) = error "too small n: can't encrypt even 1 byte"
    | otherwise = go 1 (2^8)
    where
    -- max value for k bytes is (2^8)^k - 1
    -- finds maximum k such that
    -- (2^8)^k - 1 < n
    -- so (2^8)^k < n + 1
    n2 = n + 1
    go :: Int -> Integer -> Int
    go !k x =
        let x2 = x `shiftL` 8 
        in if x2 < n2 then go (k+1) x2 else k

-- number of bytes in encryption output block
-- argument is modulus
encOutputBlockSize :: Integer -> Int
encOutputBlockSize n = go 1 (2^8)
    where
    -- max value for k bytes is (2^8)^k - 1 
    -- finds minimum k such that 
    -- (2^8)^k - 1 >= n - 1
    -- so (2^8)^k >= n
    go :: Int -> Integer -> Int
    go !k x =
        if x >= n
        then k
        else go (k+1) $ x `shiftL` 8 

-- expmod m a k = a^k mod m 
expmod :: (Integral a, Integral p) => p -> p -> a -> p
expmod m a k = expmod' a k 1
    where
    expmod' a k s
        | k == 0 = s
        | otherwise = expmod' (a*a `mod` m) (k `div` 2) $ if even k then s else s*a `mod` m

enc :: PubKey -> Handle -> Handle -> IO ()
enc (PubKey (n, e)) hIn hOut = 
    loop
    where
    inBlockSize = encInputBlockSize n -- bytes
    outBlockSize = encOutputBlockSize n
    outBits = (outBlockSize * 8)

    loop = do
        bs <- B.hGet hIn inBlockSize
        let m = bs2i bs
        let m2 = expmod n m e
        let bsOut = i2bs outBits m2
        B.hPut hOut bsOut
        eof <- hIsEOF hIn
        if eof 
        then do
            -- we write the size (in bytes) of last chunk (in plaintext)
            let lastChunkSize = integerFromInt $ B.length bs
            B.hPut hOut $
                i2bs outBits lastChunkSize
        else loop

dec :: PrivKey -> Handle -> Handle -> IO ()
dec (PrivKey (n, d)) hIn hOut = 
    go
    where
    inBlockSize = encOutputBlockSize n
    outBlockSize = encInputBlockSize n
    outBits = outBlockSize * 8

    go :: IO ()
    go = do
        bs <- B.hGet hIn inBlockSize
        eof <- hIsEOF hIn
        if eof
        then return ()
        else do
            let m = bs2i bs
            let m2 = expmod n m d
            loop m2
    loop prevDecryptedBlock = do
        bs <- B.hGet hIn inBlockSize
        eof <- hIsEOF hIn
        if eof
        then do
            let lastChunkBytes = integerToInt $ bs2i bs
            B.hPut hOut $ i2bs (lastChunkBytes * 8) prevDecryptedBlock
        else do
            B.hPut hOut $ i2bs outBits prevDecryptedBlock
            let m = bs2i bs
            let m2 = expmod n m d
            loop m2

runEncrypt :: EncOpts -> IO ()
runEncrypt e = do
    key <- readPubKey e.optEncKey
    putStrLn $ "encrypting " ++ e.optEncInput ++ " to " ++ e.optEncOutput
    hFlush stdout
    hIn <- openBinaryFile e.optEncInput ReadMode
    hOut <- openBinaryFile e.optEncOutput WriteMode
    enc key hIn hOut
    hClose hOut
    hClose hIn

runDecrypt :: DecOpts -> IO ()
runDecrypt d = do
    key <- readPrivKey d.optDecKey
    putStrLn $ "decrypting " ++ d.optDecInput ++ " to " ++ d.optDecOutput
    hFlush stdout
    hIn <- openBinaryFile d.optDecInput ReadMode
    hOut <- openBinaryFile d.optDecOutput WriteMode
    dec key hIn hOut
    hClose hOut
    hClose hIn

-- Key generation
runGenKeys :: GenKeysOpts -> IO ()
runGenKeys opts = do
    (PubKey (n, e), PrivKey (_, d)) <- genKeys opts.optKeySize
    -- TODO: check if files exist and ask to overwrite
    writeIntegers (opts.optPubKey) n e
    writeIntegers (opts.optPrivKey) n d
    putStrLn $ "public encryption key saved in file " ++ opts.optPubKey
    putStrLn $ "private decryption key saved in file " ++ opts.optPrivKey

genKeys :: Int -> IO (PubKey, PrivKey)
genKeys size = do
    putStrLn $ "generating keys of size " ++ show size ++ " bits"
    -- TODO: check if size is valid
    let primeSize = size `div` 2
    hFlush stdout
    p <- generatePrime primeSize
    q <- generatePrime primeSize
    let n = p * q
    putStrLn $ "modulus size: " ++ show (nOfBits n) ++ " bits"
    hFlush stdout
    -- Euler's totient function
    let tot = (p - 1) * (q - 1)
    let e = 2^16 + 1
    if not (1 < e && e < tot)
    then error "error generating keys: wrong e param"
    else do
        let d = mminv e tot
        return (PubKey (n, e), PrivKey (n, d)) 

-- modular multiplicative inverse of a modulo m
mminv :: Integer -> Integer -> Integer
mminv a m =
    let (x, _y, gcd_am) = mygcde a m
    -- let (x, _y, gcd_am) = gcde a m -- external func
    in if gcd_am /= 1
        then error "cannot find modular multiplicative inverse of a modulo m because a and m are not coprime"
        else x `mod` m -- fixes sign 

-- extended Euclidean algorithm
-- ax + by = gdc(a,b)
-- egcde a b == (x,y,gcd a b)
mygcde :: Integer -> Integer -> (Integer, Integer, Integer)
mygcde a b = 
    loop a b 1 0 0 1
    where
    loop !old_r !r !old_s !s !old_t !t =
        if r /= 0
        then 
            let qoutient = old_r `div` r
                (old_r', r') = (r, old_r - qoutient * r)
                (old_s', s') = (s, old_s - qoutient * s)
                (old_t', t') = (t, old_t - qoutient * t)
            in loop old_r' r' old_s' s' old_t' t'
        else (old_s, old_t, old_r)