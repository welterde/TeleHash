{-# language PackageImports, TypeSynonymInstances #-}

module Telehash where

--import Debug.Trace

import Control.Concurrent
import Control.Concurrent.STM
import Control.Monad
import Control.Monad.Reader
import Control.Monad.State

import System.Random

import Data.Bits
import Data.List
import qualified Data.Map as M
import Data.Maybe

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
    deriving (Eq, Ord)

instance Show Endpoint where
    show (Endpoint ipAddr port) = ipAddr ++ ":" ++ (show port)

toEndpoint :: SockAddr -> Maybe Endpoint
toEndpoint s = 
    readEndpoint $ show s

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

data SwitchCommand = ProcessTelex {
        
        telexFrom :: Endpoint,
        telexLength :: Int,
        telexObj :: JSValue
        
    }
    | CheckLines
    | ShutdownSwitch

data SwitchStatus = Offline | Booting | Online | Shutdown
    deriving (Show)

data SwitchHandle = SwitchHandle {
    
    swChan :: TChan SwitchCommand,
    swThreads :: [ThreadId]
    
}

data LineInfo = LineInfo {
        
        lineEndpoint        :: Endpoint,
        lineEnd             :: Digest,
        lineBytesReceived   :: Int,
        lineBytesSent       :: Int,
        lineRingOut         :: Int,
        lineProduct         :: Int,
        lineNeighbors       :: [Digest]
        
    }

data SwitchConfig = SwitchConfig {
    
    swAddress :: Endpoint,
    swBootstrap :: Endpoint
    
}

data SwitchState = SwitchState {
    
    swStat  :: SwitchStatus,
    swPublic :: Maybe Endpoint,
    swLines :: M.Map Endpoint LineInfo,
    swSocket :: Socket,
    swMsgChan :: TChan SwitchCommand
    
}

type SwitchT = ReaderT SwitchConfig (StateT SwitchState IO)

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
fetchMessage :: TChan SwitchCommand -> Socket -> IO () 
fetchMessage msgChan sock = do
    (msgRaw, addr) <- recvFrom sock 1024
    case (do
            endpoint <- toEndpoint addr
            msg <- readJSON msgRaw
            return (endpoint, msg)) of
        Just (endpoint, msg) ->
            atomically $ writeTChan msgChan $ 
                        ProcessTelex endpoint (B.length msgRaw) msg
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

startSwitch :: SwitchConfig -> IO SwitchHandle
startSwitch config = do
    socket <- bindServer $ swAddress config
    msgChan <- newTChanIO
    let state = SwitchState {
            swStat  = Offline,
            swLines = M.empty,
            swPublic = Nothing,
            swSocket = socket,
            swMsgChan = msgChan
        }
    
    fetchTid <- forkIO $ forever $ fetchMessage msgChan socket
    
    logChan <- atomically $ dupTChan msgChan
    logTid <- forkIO $ forever $ logCommands logChan
    
    clTid <- forkIO $ repeatSend msgChan CheckLines 30
    
    swTid <- forkIO $ do
        evalStateT (runReaderT runSwitch config) state
    
    return SwitchHandle { 
            swChan = msgChan, 
            swThreads = [ fetchTid, clTid, swTid, logTid ] }

logCommands :: TChan SwitchCommand -> IO ()
logCommands logChan = 
    (atomically $ readTChan logChan) >>= logCommand

logCommand :: SwitchCommand -> IO ()
logCommand (ProcessTelex from len msg) = do
    putStrLn $ "RECV FROM[" ++ (show from) 
        ++ "][" ++ (show len) ++ "] " ++ (show msg)

logCommand CheckLines = do
    putStrLn "CHECK"

logCommand ShutdownSwitch = do
    putStrLn "SHUTDOWN"

repeatSend :: TChan SwitchCommand -> SwitchCommand -> Int -> IO ()
repeatSend chan cmd delay = do
    threadDelay (delay*1000000)
    atomically $ writeTChan chan cmd
    repeatSend chan cmd delay

stopSwitch :: SwitchHandle -> IO ()
stopSwitch handle = do
    atomically $ writeTChan (swChan handle) ShutdownSwitch

runSwitch :: SwitchT ()
runSwitch = do
    config <- ask
    state <- get
    
    let stateName = swStat state
    
    liftIO $ putStrLn $ "State: " ++ (show stateName)
    
    case swStat state of
        Shutdown -> do
            return ()
            
        Offline -> do
            startBootstrap
            runSwitch
            
        _ -> do
            
            cmd <- liftIO $
                atomically $ readTChan (swMsgChan state)
            dispatchCommand cmd
            
            runSwitch

updateLine :: Endpoint -> Int -> JSValue -> SwitchT ()
updateLine from len obj = do
    state <- get
    let lines = swLines state
    updatedLine <- case M.lookup from lines of
        Just line -> do
            return $ line {
                lineBytesReceived = len + lineBytesReceived line
            }
        Nothing -> do
            liftIO $ newLine from len
    put state { swLines = M.insert from updatedLine lines }

newLine :: Endpoint -> Int -> IO LineInfo
newLine endpoint len = do
    ringOut <- getStdRandom (randomR (1,32767))
    return $ LineInfo {
        lineEndpoint = endpoint,
        lineEnd = hash endpoint,
        lineBytesReceived = len,
        lineBytesSent = 0,
        lineRingOut = ringOut, -- you LIE!!!
        lineProduct = 0,
        lineNeighbors = []
    }

dispatchCommand :: SwitchCommand -> SwitchT ()
dispatchCommand (ProcessTelex from len obj) = do
    updateLine from len obj
    state <- get
    
    let processTelex = ProcessTelex from len obj
    case swStat state of
        Booting -> do
            completeBootstrap processTelex
        
        Online -> do
            dispatchTelex processTelex
        
        _ -> do
            return ()
    
dispatchCommand CheckLines = do
    state <- get
    
    -- TODO: scan lines, update state
    
    return ()

dispatchCommand ShutdownSwitch = do
    state <- get
    put $ state { swStat = Shutdown }

startBootstrap :: SwitchT ()
startBootstrap = do
    config <- ask
    state <- get
    
    let endpoint = swBootstrap config
    
    --newLine state endpoint
    
    liftIO $ sendMessage (swSocket state) $
        showJSON $ toJSON [
            ("+end", show $ hash endpoint),
            ("_to", show endpoint)]
    
    put state { swStat = Booting }

completeBootstrap :: SwitchCommand -> SwitchT ()
completeBootstrap processTelex = do
    let telex = telexObj processTelex
    state <- get
    
    case telexGet "_to" telex of
        Just public -> do 
            put state { swPublic = readEndpoint public, swStat = Online }
            dispatchTelex processTelex
        Nothing -> do
            return ()

dispatchTelex :: SwitchCommand -> SwitchT ()
dispatchTelex processTelex = do
    let telex = telexObj processTelex
--    seeNeighbors telex
--    update
    case fromJSON telex of
        Just (JSObject telexMap) ->
            mapM_ (dispatchField telex) (M.keys telexMap)
        _ ->
            return ()
    
--    let x = fromJSON telex
--    case fromJSON telex of
--        Just y ->
--            liftIO $ putStrLn y
--        Nothing ->
--            return ()

dispatchField :: JSValue -> ByteString -> SwitchT ()
    
dispatchField telex field = do
    liftIO $ putStrLn $ "dispatchField " ++ (show field)

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


