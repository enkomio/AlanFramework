namespace ES.Alan.Core

open System
open ES.Alan.Core.Entities

type ObjectRepository<'T when 'T : not struct>() =
    let _repository = new LiteDbRepository<'T>()
    let mutable _disposed = false

    abstract Get: String -> 'T option
    default this.Get(id: String) =
        _repository.Get(id)

    abstract Upsert: DbEntity<'T> -> unit
    default this.Upsert(e: DbEntity<'T>) =
        _repository.Upsert(e)

    abstract Query: ('T -> Boolean) -> 'T array
    default this.Query(predicate: 'T -> Boolean) =
        _repository.Query(predicate)

    abstract Delete: String -> unit
    default this.Delete(id: String) =
        _repository.Delete(id)

    abstract Dispose: unit -> unit
    default this.Dispose() =
        if not _disposed then
            _disposed <- true
            _repository.Dispose()

    abstract Count: Int32
    default this.Count
        with get() = _repository.Count

    interface IDisposable with
        override this.Dispose() =
            _repository.Dispose()

type EndpointRepository() =
    inherit ObjectRepository<Endpoint>()