{-# LANGUAGE OverloadedStrings #-}
module Main where

import Lib
import Data.ByteString as B
import Data.ByteArray (convert, ByteArray)
import Crypto.ECC.Edwards25519
import Crypto.Hash
import Crypto.Error
import Data.Serialize.Put
import Data.Serialize (encode)
import Data.Word

main :: IO ()
main = do
    schnorr
    fiatShamir
    schnorrWithMessage ""

schnorr :: IO ()
schnorr = do
    α <- scalarGenerate
    challenge <- scalarGenerate
    privateKey <- scalarGenerate
    let
        publicKey :: Point
        publicKey = toPoint privateKey
        αG :: Point
        αG = toPoint α
        response :: Scalar
        response = α `scalarAdd` (challenge `scalarMul` privateKey)
        lhs :: Point
        lhs  = toPoint response
        rhs :: Point
        rhs = αG `pointAdd` (challenge `pointMul` publicKey)
    print lhs
    print rhs

fiatShamir :: IO ()
fiatShamir = do
    α <- scalarGenerate
    privateKey <- scalarGenerate
    let
        publicKey :: Point
        publicKey = toPoint privateKey
        αG :: Point
        αG = toPoint α
        challenge :: Scalar
        challenge = throwCryptoError . scalarDecodeLong . hashWith SHA256 $ (pointEncode αG :: ByteString)
        response :: Scalar
        response = α `scalarAdd` (challenge `scalarMul` privateKey)
        lhs :: Point
        lhs  = toPoint response
        rhs :: Point
        rhs = αG `pointAdd` (challenge `pointMul` publicKey)
    print lhs
    print rhs

type Message = ByteString

schnorrWithMessage :: Message -> IO ()
schnorrWithMessage m = do
    α <- scalarGenerate
    privateKey <- scalarGenerate
    let
        publicKey :: Point
        publicKey = toPoint privateKey
        αG :: Point
        αG = toPoint α
        αG' :: ByteString
        αG' = pointEncode αG
        challenge :: Scalar
        challenge = throwCryptoError . scalarDecodeLong . hashWith SHA256 $ (B.concat [m, αG'])
        response :: Point
        response = αG `pointAdd` (pointNegate (toPoint (challenge `scalarMul` privateKey)))
        lhs :: Point
        lhs = toPoint challenge
        rhs :: Point
        rhs = toPoint . throwCryptoError . scalarDecodeLong . hashWith SHA256 $ (
                B.concat [
                    m,
                    pointEncode $ response `pointAdd` (challenge `pointMul` publicKey)
                 ]
          )
    print lhs
    print rhs
