#!/usr/bin/env stack
-- stack --resolver lts-21.25 script --package minio-hs --package optparse-applicative --package filepath --package aeson --package text --package unliftio
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE DeriveGeneric       #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | A small MinIO file uploader driven by a JSON description of the upload.
--
-- Usage:
--   ./uploader.hs request.json
--
-- where request.json looks like:
--   { "filename": "report.pdf", "author": "Jane Doe" }
--
-- "filename" is the path (on this machine) of the file to upload.
-- "author" is stored as user metadata on the uploaded object.
--
-- By default this connects to the public play.min.io test server. Point it
-- at your own MinIO server instead by setting these environment variables
-- before running it:
--   MINIO_HOST, MINIO_PORT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY
--   (optionally MINIO_SECURE=true to use HTTPS)

module Main (main) where

import qualified Data.ByteString.Lazy.Char8 as BLC
import           Data.Aeson                 (FromJSON, eitherDecode,
                                              eitherDecodeFileStrict)
import           Data.Text                  (Text, pack)
import           GHC.Generics                (Generic)
import           Network.Minio
import           Options.Applicative
import           System.Environment          (lookupEnv)
import           System.FilePath.Posix       (takeBaseName)
import           UnliftIO                    (throwIO, try)

-- | The shape of the JSON input.
data UploadRequest = UploadRequest
  { filename :: FilePath
  , author   :: Text
  } deriving (Show, Generic)

instance FromJSON UploadRequest

-- | Single positional argument: either a literal JSON string, or the path
-- to a JSON file containing the request.
jsonArg :: Parser String
jsonArg = strArgument
  ( metavar "JSON"
 <> help "Either a JSON object '{\"filename\":...,\"author\":...}' or a path to a file containing one"
  )

cmdParser :: ParserInfo String
cmdParser = info
  (helper <*> jsonArg)
  ( fullDesc
 <> progDesc "FileUploader"
 <> header "FileUploader - a simple file-uploader program using minio-hs"
  )

bucket :: Bucket
bucket = "my-bucket"

-- | Decode the argument as JSON directly; if that fails, treat it as a
-- path to a JSON file and read it from there.
decodeRequest :: String -> IO (Either String UploadRequest)
decodeRequest arg = case eitherDecode (BLC.pack arg) of
  Right req -> pure (Right req)
  Left _    -> eitherDecodeFileStrict arg

-- | Build connection info from MINIO_* environment variables if present,
-- otherwise fall back to the public play.min.io test server.
getConnectInfo :: IO ConnectInfo
getConnectInfo = do
  mHost <- lookupEnv "MINIO_HOST"
  mAccessKey <- lookupEnv "MINIO_ACCESS_KEY"
  mSecretKey <- lookupEnv "MINIO_SECRET_KEY"
  case (mHost, mAccessKey, mSecretKey) of
    (Just host, Just ak, Just sk) -> do
      mPort <- lookupEnv "MINIO_PORT"
      mSecure <- lookupEnv "MINIO_SECURE"
      let port   = maybe 9000 read mPort
          secure = maybe False (== "true") mSecure
          base   = minioCI (pack host) port secure
      pure base { connectAccessKey = pack ak, connectSecretKey = pack sk }
    _ -> pure minioPlayCI

main :: IO ()
main = do
  arg <- execParser cmdParser

  decoded <- decodeRequest arg
  case decoded of
    Left err -> putStrLn $ "Failed to parse JSON input: " ++ err
    Right UploadRequest { filename = filepath, author = uploadAuthor } -> do
      connInfo <- getConnectInfo
      let object  = pack (takeBaseName filepath)
          options = defaultPutObjectOptions
            { pooUserMetadata = [("author", uploadAuthor)] }

      res <- runMinio connInfo $ do
        -- Make the bucket; ignore the error if it already exists.
        bErr <- try $ makeBucket bucket Nothing
        case bErr of
          Left BucketAlreadyOwnedByYou -> return ()
          Left e                       -> throwIO e
          Right _                      -> return ()

        -- Upload the file; object name is derived from its filename.
        fPutObject bucket object filepath options

      case res of
        Left e   -> putStrLn $ "file upload failed due to " ++ show e
        Right () -> putStrLn $
          "file upload succeeded: " ++ filepath ++
          " (author: " ++ show uploadAuthor ++ ")"