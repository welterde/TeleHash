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

import Data.Time.Clock
 
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
    
}   | CheckLines
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
    lineRingIn          :: Maybe Int,
    lineRingOut         :: Int,
    lineProduct         :: Maybe Int,
    lineNeighbors       :: [Digest],
    
    lineFirstSeenAt     :: UTCTime,
    lineLastSeenAt      :: UTCTime,
    lineLastCheckedAt   :: UTCTime
    
} deriving (Show)

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

telexFeed :: JSON a => String -> Maybe a -> JSValue -> JSValue
telexFeed key maybeValue obj =
    maybe obj (\value -> telexWith key value obj) maybeValue

isValidProduct :: LineInfo -> Bool
isValidProduct line =
    case getProductMatch line of
        Just productMatch ->
            productMatch
        Nothing ->
            False
    where
    getProductMatch line = let
        ringOut = lineRingOut line
        in do
        ringIn <- lineRingIn line
        product <- lineProduct line
        return $ product `rem` ringOut == 0

sendTelex :: JSValue -> SwitchT ()
sendTelex telex = do
    case return telex >>= telexGet "_to" >>= readEndpoint of
        Just endpoint -> do
            line <- lookupLine endpoint
            
            let msg = showJSON $
                        (telexFeed "_line" (validProduct line)) .
                        (telexFeed "_ring" (necessaryRingOut line)) $
                            telex
            
            updateLine $ line { 
                lineBytesSent = (lineBytesSent line) + B.length msg
            }
            
            state <- get
            liftIO $ sendMessageTo (swSocket state) msg endpoint
        Nothing -> do
            return ()
    
    where
    validProduct :: LineInfo -> Maybe Int
    validProduct line = 
        case isValidProduct line of
            True -> lineProduct line
            False -> Nothing
    
    necessaryRingOut :: LineInfo -> Maybe Int
    necessaryRingOut line =
        case isValidProduct line of
            True -> Nothing
            False -> Just $ lineRingOut line
   
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
        swThreads = [ fetchTid, clTid, swTid, logTid ]
    }

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
            
            cmd <- liftIO $ atomically $ readTChan (swMsgChan state)
            dispatchCommand cmd
            
            runSwitch

-- Kind of like a flipped-around maybe function for
-- conditionally modifying lines based on maybe a value.
lineFeed :: Maybe a -> (LineInfo -> a -> LineInfo) -> LineInfo -> LineInfo
lineFeed maybeValue nextLineF line =
    maybe line (nextLineF line) maybeValue

-- Update a line with bytes received
lineWithBr :: SwitchCommand -> LineInfo -> SwitchT LineInfo
lineWithBr (ProcessTelex from len obj) line = do
    return $ line {
        lineBytesReceived = (lineBytesReceived line) + len
    }

-- Update a line with bytes received
lineWithBsent :: Int -> LineInfo -> SwitchT LineInfo
lineWithBsent bsent line = do
    return $ line {
        lineBytesSent = (lineBytesSent line) + bsent
    }

-- Update a line with current time.
lineWithSeenAt :: SwitchCommand -> LineInfo -> SwitchT LineInfo
lineWithSeenAt (ProcessTelex from len obj) line = do
    now <- liftIO $ getCurrentTime
    return $ line { lineLastSeenAt = now }

-- Update a line with handshake info from incoming Telex.
lineWithHandshake :: SwitchCommand -> LineInfo -> SwitchT LineInfo
lineWithHandshake (ProcessTelex from len obj) line = do
    return $ (lineWithRingOut . lineDeriveRingIn . lineWithProduct) line
    
    where
    
    lineWithRingOut line = 
        lineFeed (telexGet "_ring" obj)
            (\line ringIn -> line { 
                lineRingIn = Just ringIn } ) line
    
    lineDeriveRingIn line = line {
        lineRingIn = case lineRingIn line of
            Just ringIn ->
                return ringIn
            Nothing -> let
                ringOut = lineRingOut line
                in do
                product <- lineProduct line
                return $ product `quot` ringOut
    }
    
    lineWithProduct line =
        lineFeed (telexGet "_line" obj)
            (\line product -> line {
                lineProduct = Just product } ) line

lookupLine :: Endpoint -> SwitchT LineInfo
lookupLine from = do
    state <- get
    let lines = swLines state
    case M.lookup from (swLines state) of
        Just line -> do
            return line
        Nothing -> do
            addLine from

updateLine :: LineInfo -> SwitchT LineInfo
updateLine line = do
    state <- get
    put state {
        swLines = M.insert (lineEndpoint line) line (swLines state)
    }
    return line

addLine :: Endpoint -> SwitchT LineInfo
addLine from = do
    state <- get
    let lines = swLines state
    line <- liftIO $ newLine from 0
    put state { swLines = M.insert from line lines }
    return line

newLine :: Endpoint -> Int -> IO LineInfo
newLine endpoint len = do
    ringOut <- getStdRandom (randomR (1,32767))
    now <- getCurrentTime
    return $ LineInfo {
        lineEndpoint = endpoint,
        lineEnd = hash endpoint,
        lineBytesReceived = len,
        lineBytesSent = 0,
        lineRingIn = Nothing,
        lineRingOut = ringOut,
        lineProduct = Nothing,
        lineNeighbors = [],
        lineFirstSeenAt = now,
        lineLastSeenAt = now,
        lineLastCheckedAt = now
    }

lineAge :: LineInfo -> NominalDiffTime
lineAge line = (lineLastCheckedAt line) `diffUTCTime` (lineFirstSeenAt line)

lineLastSeen :: LineInfo -> NominalDiffTime
lineLastSeen line = (lineLastCheckedAt line) `diffUTCTime` (lineLastSeenAt line)

checkLine :: SwitchState -> LineInfo -> Bool
checkLine state line = let
    age = lineAge line
    lastSeen = lineLastSeen line
    in
    (isValidProduct line && (lastSeen < 300)) || age < 60
    
keepaliveLine :: SwitchState -> LineInfo -> SwitchT ()
keepaliveLine state line = 
    case swPublic state of
        Just selfEndpoint -> do
            sendTelex . toJSON $ [
                    ("+end", show $ hash selfEndpoint),
                    ("_to", show $ lineEndpoint line)]
        Nothing -> do
            return ()

dispatchCommand :: SwitchCommand -> SwitchT ()
dispatchCommand (ProcessTelex from len obj) = do
    state <- get
    let processTelex = ProcessTelex from len obj
    
    lookupLine from >>=
        lineWithBr processTelex >>=
        lineWithSeenAt processTelex >>=
        lineWithHandshake processTelex >>=
        updateLine
    
    case swStat state of
        Booting -> do
            completeBootstrap processTelex
        
        Online -> do
            dispatchTelex processTelex
        
        _ -> do
            return ()
    
dispatchCommand CheckLines = do
    state <- get
    now <- liftIO getCurrentTime
    let withLastCheckTime = M.map (\line -> line { lineLastCheckedAt = now } )
        filterValid = M.filter (checkLine state)
    let updatedLines = (withLastCheckTime . filterValid . swLines) state
    
    put state {
        swLines = updatedLines
    }
    
    mapM_ (keepaliveLine state) $ M.elems updatedLines
    
    liftIO $ putStrLn $ "LINES:" ++ (show $ swLines state)

dispatchCommand ShutdownSwitch = do
    state <- get
    put $ state { swStat = Shutdown }

startBootstrap :: SwitchT ()
startBootstrap = do
    config <- ask
    
    let endpoint = swBootstrap config
    addLine endpoint
    
    state <- get
    put state { swStat = Booting }
    
    sendTelex . toJSON $ [
            ("+end", show $ hash endpoint),
            ("_to", show endpoint)]
    
    return ()

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


