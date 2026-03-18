.class public interface abstract Ltechnology/cariad/cat/genx/ClientManagerDelegate;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0012\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008`\u0018\u00002\u00020\u0001J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004H\'\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u001f\u0010\r\u001a\u00020\u00022\u0006\u0010\n\u001a\u00020\t2\u0006\u0010\u000c\u001a\u00020\u000bH\'\u00a2\u0006\u0004\u0008\r\u0010\u000eJ\u0017\u0010\u000f\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\tH\'\u00a2\u0006\u0004\u0008\u000f\u0010\u0010J\u001f\u0010\u0013\u001a\u00020\u00062\u0006\u0010\u0012\u001a\u00020\u00112\u0006\u0010\u0005\u001a\u00020\u0004H\'\u00a2\u0006\u0004\u0008\u0013\u0010\u0014\u00a8\u0006\u0015\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/ClientManagerDelegate;",
        "Ljava/io/Closeable;",
        "",
        "isEnabled",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "transportType",
        "Llx0/b0;",
        "clientManagerDidUpdatedState",
        "(ZLtechnology/cariad/cat/genx/TransportType;)V",
        "Ltechnology/cariad/cat/genx/Client;",
        "client",
        "",
        "advertisement",
        "clientManagerDidDiscoverClient",
        "(Ltechnology/cariad/cat/genx/Client;[B)Z",
        "clientDidBecameUnreachable",
        "(Ltechnology/cariad/cat/genx/Client;)V",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "error",
        "clientManagerDidEncounteredError",
        "(Ltechnology/cariad/cat/genx/GenXError;Ltechnology/cariad/cat/genx/TransportType;)V",
        "genx_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# virtual methods
.method public abstract clientDidBecameUnreachable(Ltechnology/cariad/cat/genx/Client;)V
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method public abstract clientManagerDidDiscoverClient(Ltechnology/cariad/cat/genx/Client;[B)Z
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method public abstract clientManagerDidEncounteredError(Ltechnology/cariad/cat/genx/GenXError;Ltechnology/cariad/cat/genx/TransportType;)V
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method public abstract clientManagerDidUpdatedState(ZLtechnology/cariad/cat/genx/TransportType;)V
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method
