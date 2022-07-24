namespace ES.Alan.Core

open System
open System.Linq
open System.Collections.Generic
open System.Collections.Concurrent
open System.Threading
open System.Threading.Tasks
open ES.Fslog

type private ICallbackObject =
    interface
        abstract Invoke: Object * Object -> unit
        abstract Callback: Object
        abstract Subscriber: Object
    end
    
[<CLIMutable>]
type Envelope<'a> = {
    Id : Guid
    Created : DateTimeOffset
    Item : 'a 
} with
    static member New(id: Guid, created: DateTimeOffset, item: 'a) = {
        Id = id
        Created = created
        Item = item
    }

    static member DefaultNew(item: 'a) =
        Envelope.New(Guid.NewGuid(), DateTimeOffset.Now, item)

type private CallbackObject<'a>(subscriber: Object, callback: Object * Envelope<'a> -> unit) =
    member this.Invoke(o: Object, message: Object) =
        let message = message :?> 'a
        callback(o, Envelope.DefaultNew(message))

    interface ICallbackObject with
        member this.Callback = upcast callback
        member this.Subscriber = subscriber
        member this.Invoke(o: Object, message: Object) =
            this.Invoke(o, message)

type MessageBroker(logProvider: ILogProvider) =
    let _messageSubscribers = new ConcurrentDictionary<String, List<ICallbackObject>>()
    let _callbacks = new BlockingCollection<unit -> unit>(new ConcurrentQueue<unit -> unit>())
    let _blockingCallbacks = new BlockingCollection<unit -> unit>(new ConcurrentQueue<unit -> unit>())
    let _syncRoot = new Object()
    let _workerRunning = ref 0

    let _logger =
        log "DefaultMessageBroker"
        |> error "Timeout" "Not message result was recevied after {1} seconds. Sender: {0}"
        |> error "DeadLock" "Trying to send a locking message '{0}' when message '{1}' is begin handled. Sender: {2}"
        |> buildAndAdd logProvider
    
    let getSubscriberFor(message: 'a) = lock _syncRoot (fun () ->
        _messageSubscribers
        |> Seq.filter(fun kv -> kv.Key.Equals(message.GetType().FullName))
        |> Seq.collect(fun kv -> kv.Value)
        |> Seq.toList
    )

    let messageConsumerWorker(callbacks: BlockingCollection<unit -> unit>) = Async.Start <| async {
        callbacks.GetConsumingEnumerable()
        |> Seq.iter(fun callback -> 
            callback()
        )
    }

    let consumeMessages() =
        if Interlocked.CompareExchange(_workerRunning, 1, 0) = 0 then            
            messageConsumerWorker(_callbacks)
            messageConsumerWorker(_blockingCallbacks)

    let dispatch(sender: Object, message: 'a, dispatchedEvent: ManualResetEventSlim option) =
        let mutable messageEnqueue = false
        let subscribers = getSubscriberFor(message)
        if subscribers.Any() then
            let callbacks =
                match dispatchedEvent with
                | Some _ -> _blockingCallbacks
                | None -> _callbacks

            if not callbacks.IsAddingCompleted then
                callbacks.Add(fun () ->
                    subscribers 
                    |> List.iter (fun callback ->
                        callback.Invoke(sender, message)
                    )

                    dispatchedEvent 
                    |> Option.iter(fun event ->                    
                        event.Set()
                    )
                )            
                messageEnqueue <- true
        else
            dispatchedEvent
            |> Option.iter(fun dispatchedEvent ->
                dispatchedEvent.Set()
            )

        consumeMessages()
        messageEnqueue
        
    member this.Subscribe(subscriber: Object, callback: Object * Envelope<'a> -> unit) = lock _syncRoot (fun () ->
        let subscriberType = typeof<'a>.FullName
        let callbackObject = new CallbackObject<'a>(subscriber, callback)
        if _messageSubscribers.ContainsKey(subscriberType) then
            _messageSubscribers.[subscriberType].Add(callbackObject)
        else
            let newList = new List<ICallbackObject>()
            newList.Add(callbackObject)
            _messageSubscribers.[subscriberType] <- newList
    )

    member this.Unsubscribe<'a>(subscriber: Object) = lock _syncRoot (fun () ->   
        // delete the specified subscriber
        _messageSubscribers.Values
        |> Seq.iter(fun subscriberList ->
            subscriberList
            |> Seq.tryFindIndex(fun sub ->
                Object.ReferenceEquals(subscriber, sub.Subscriber)
            )
            |> Option.iter(subscriberList.RemoveAt)
        )
        
        // delete all empty list of subscriber
        _messageSubscribers
        |> Seq.toList
        |> List.filter (fun kv -> kv.Value.Count = 0)
        |> List.iter (fun kv -> _messageSubscribers.TryRemove(kv.Key) |> ignore)
    )

    member this.Dispatch<'a>(sender: Object, message: 'a) =        
        dispatch(sender, message, None) |> ignore

    member this.DispatchAndWaitHandling<'a>(sender: Object, message: 'a) =  
        use resetEvent = new ManualResetEventSlim()
        dispatch(sender, message, Some resetEvent) |> ignore
        resetEvent.Wait()

    interface IDisposable with
        member this.Dispose() =
            _messageSubscribers.Clear()
            _callbacks.CompleteAdding()