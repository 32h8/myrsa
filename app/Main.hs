{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedRecordDot #-}

module Main (main) where

import Lib

import System.IO
import System.Directory (doesFileExist)
import Control.Monad

import Data.Semigroup ((<>))
import Options.Applicative

-- stack run -- --help
-- or
-- stack build
-- stack exec myrsa-exe -- -h

-- default filenames for keys
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
    , optOverwrite :: Bool
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
        strOption (long "priv" <> metavar "PRIVATE_KEY_FILE" <> showDefault <> value privKeyFileName <> help "Private key file") <*>
        strOption (long "pub" <> metavar "PUBLIC_KEY_FILE" <> showDefault <> value pubKeyFileName <> help "Public key file") <*>
        switch (short 'f' <> help "Allow overwriting of existing key files")

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
    pubExists <- doesFileExist pub
    privExists <- doesFileExist priv
    when pubExists $ putStrLn $ "File " ++ pub ++ " already exists."
    when privExists $ putStrLn $ "File " ++ priv ++ " already exists."
    if pubExists || privExists 
        then do
            if opts.optOverwrite
            then proceed
            else putStrLn "Aborting. Set option to overwrite files."
        else proceed
    where
        pub = opts.optPubKey
        priv = opts.optPrivKey
        proceed = do 
            (PubKey (n, e), PrivKey (_, d)) <- genKeys opts.optKeySize
            writeIntegers pub n e
            writeIntegers priv n d
            putStrLn $ "public encryption key saved in file " ++ pub
            putStrLn $ "private decryption key saved in file " ++ priv

