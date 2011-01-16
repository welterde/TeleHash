{-# language PackageImports, TypeSynonymInstances #-}

module Telehash where

--import Debug.Trace

import Control.Concurrent
import Control.Concurrent.STM
import Control.Monad

import Data.Bits
import Data.List
import Data.Map as M

import Data.ByteString.UTF8 as UTF8
import Data.ByteString.Lazy.UTF8 as LUTF8

import Data.Digest.Pure.SHA

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
 
import Network.Socket hiding (recv, recvFrom, send, sendTo)
import Network.Socket.ByteString (recvFrom, sendTo)
import Network.BSD

import Text.JSON.AttoJSON as J

import Text.ParserCombinators.Parsec

data Endpoint = Endpoint String Int

instance Show Endpoint where
    show (Endpoint ipAddr port) = ipAddr ++ ":" ++ (show port)

readEndpoint :: String -> Maybe Endpoint
readEndpoint s = 
    case parse parseEndpoint "" s of
        Left error ->
            Nothing
        Right endpoint ->
            Just endpoint

parseEndpoint = do
    hostName <- many1 $ digit <|> char '.'
    char ':'
    port <- many1 digit
    return $ Endpoint hostName (read port)

data RecvMsg = RecvMsg JSValue Int SockAddr

data SwitchStatus = Offline | Booting | Online | Shutdown

data LineInfo = LineInfo {
    
    lnEndP          :: Endpoint,
    lnEndH          :: Digest,
    lnBytesReceived :: Int,
    lnRingIn        :: Int,
    lnRingOut       :: Int
    
}

data SwitchInfo = SwitchInfo {
    
    swStat  :: SwitchStatus,
    swLines :: M.Map Endpoint LineInfo,
    swSocket :: Socket
    
}

class Hashable a where
    hash :: a -> Digest

instance Hashable String where
    hash s = sha1 $ LUTF8.fromString s

instance Hashable B.ByteString where
    hash s = sha1 $ BL.pack $ B.unpack s

instance Hashable Endpoint where
    hash s = sha1 $ LUTF8.fromString $ show s

telexGet :: JSON a => String -> JSValue -> Maybe a
telexGet key telex = 
    J.lookup (UTF8.fromString key) telex

telexWith :: JSON a => String -> a -> JSValue -> JSValue
telexWith key value telex = 
    J.updateField (UTF8.fromString key) value telex

quickSockAddr:: String -> Int -> IO SockAddr
quickSockAddr hostName port = 
    liftM addrAddress $ quickAddrInfo hostName port

quickAddrInfo :: String -> Int -> IO AddrInfo
quickAddrInfo hostName port = do
    addrinfos <- getAddrInfo 
                    (Just (defaultHints {addrFlags = [AI_PASSIVE]}))
                    Nothing (Just $ show port)
    return $ head addrinfos

-- Bind to a listening socket.
bindServer :: Endpoint -> IO Socket
bindServer (Endpoint hostName port) = do
    
    serveraddr <- quickAddrInfo hostName port
    
    sock <- socket (addrFamily serveraddr) Datagram defaultProtocol
    
    -- Bind it to the address we're listening to
    bindSocket sock (addrAddress serveraddr)
    
    return sock

-- Listen for incoming messages.
-- Dispatch those messages to the channel.
fetchMessage :: TChan RecvMsg -> Socket -> IO () 
fetchMessage msgChan sock = do
    (msgRaw, addr) <- recvFrom sock 1024
    let msg = readJSON msgRaw
    case readJSON msgRaw of
        Just msg ->
            atomically $ writeTChan msgChan $ 
                RecvMsg msg (B.length msgRaw) addr
        Nothing ->
            error "fetch failed"

sendMessage :: Socket -> B.ByteString -> IO ()
sendMessage socket msg = do
    let maybeEndpoint = 
            readJSON msg >>= telexGet "_to" >>= readEndpoint
    case maybeEndpoint of
        Just endpoint ->
            sendMessageTo socket msg endpoint
        Nothing ->
            error "send failed"

sendMessageTo :: Socket -> B.ByteString -> Endpoint -> IO ()
sendMessageTo socket msg (Endpoint hostName port) = do
    hostAddr <- quickSockAddr hostName port
    
    bytesSent <- sendTo socket msg hostAddr
    
    putStrLn $ "SEND[" ++ (show hostAddr) 
        ++ "][" ++ (show bytesSent) ++ "] " ++ (show msg)
    
    return ()

startSwitch :: TChan RecvMsg -> Socket -> IO ThreadId
startSwitch msgChan socket = do
    let state = SwitchInfo { 
        swStat  = Offline,
        swLines = M.empty,
        swSocket = socket
    }
    
    swVar <- atomically $ newTVar (state :: SwitchInfo)
    
    forkIO $ runSwitch swVar msgChan

runSwitch :: TVar SwitchInfo -> TChan RecvMsg -> IO ()
runSwitch swVar msgChan = do
    state <- atomically $ readTVar swVar
    
    telex <- case swStat state of
        Shutdown -> do
            return Nothing
        Offline -> do
            return Nothing
        _ -> do
            result <- atomically $ readTChan msgChan
            return $ Just result
    
    newState <- case swStat state of
        Offline -> do
            -- Send telex to bootstrap endpoint
            -- (unless of course, we're standalone)
            startBootstrap state
        
        Booting -> do
            completeBootstrap state telex
            dispatchTelex state telex
        
        Online -> do
            dispatchTelex state telex
        
        Shutdown -> do
            return state
        
    case swStat newState of
        Shutdown -> do
            return ()
        _ -> do
            atomically $ writeTVar swVar newState
            runSwitch swVar msgChan

startBootstrap :: SwitchInfo -> IO SwitchInfo
startBootstrap state = do
    let endpoint = Endpoint "127.0.0.1" 42424
    sendMessage (swSocket state) $
        showJSON $ toJSON [
            ("+end", show $ hash endpoint),
            ("_to", show endpoint)]
    
    return SwitchInfo { 
        swStat=Booting, 
        swLines=(swLines state), 
        swSocket=(swSocket state)}

completeBootstrap :: SwitchInfo -> Maybe RecvMsg -> IO SwitchInfo
completeBootstrap state telex = do
    return state

dispatchTelex :: SwitchInfo -> Maybe RecvMsg -> IO SwitchInfo
dispatchTelex state telex = do
    return state

-----------------------------------------------------------------------------
                          -- Telehash switch design --
-----------------------------------------------------------------------------
-- Use STM in a message-passing style. Listener thread will decode telex and
-- send to a reactor-dispatch process. This process will keep track of 
-- switch and line state in TVars.
--
-- I'm really new to Haskell but I'm thinking an application on top of the 
-- switch will need to "register" with the STM in such a way as to receive 
-- messages based on pattern matching
--
-----------------------------------------------------------------------------


