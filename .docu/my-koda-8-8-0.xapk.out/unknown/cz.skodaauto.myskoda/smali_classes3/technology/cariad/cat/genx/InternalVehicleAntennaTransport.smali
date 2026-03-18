.class public interface abstract Ltechnology/cariad/cat/genx/InternalVehicleAntennaTransport;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/VehicleAntennaTransport;
.implements Ltechnology/cariad/cat/genx/Referencing;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000^\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0005\n\u0002\u0008\u0006\n\u0002\u0010\u0012\n\u0002\u0008\u0004\n\u0002\u0010\t\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0002\u0008\n\n\u0002\u0010\u0016\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008`\u0018\u00002\u00020\u00012\u00020\u0002J\u001e\u0010\t\u001a\u0008\u0012\u0004\u0012\u00020\u00060\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u00a6@\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u0019\u0010\u000b\u001a\u0004\u0018\u00010\n2\u0006\u0010\u0004\u001a\u00020\u0003H\'\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\u0017\u0010\u000f\u001a\u00020\u00062\u0006\u0010\u000e\u001a\u00020\rH&\u00a2\u0006\u0004\u0008\u000f\u0010\u0010J\u0017\u0010\u0013\u001a\u00020\u00062\u0006\u0010\u0012\u001a\u00020\u0011H&\u00a2\u0006\u0004\u0008\u0013\u0010\u0014J\u0017\u0010\u0016\u001a\u00020\u00062\u0006\u0010\u0015\u001a\u00020\u0011H&\u00a2\u0006\u0004\u0008\u0016\u0010\u0014J\'\u0010\u001b\u001a\u00020\u00062\u0006\u0010\u0017\u001a\u00020\u00112\u0006\u0010\u0019\u001a\u00020\u00182\u0006\u0010\u001a\u001a\u00020\u0018H&\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ/\u0010#\u001a\u00020\u00062\u0006\u0010\u001e\u001a\u00020\u001d2\u0006\u0010\u001f\u001a\u00020\u00112\u0006\u0010!\u001a\u00020 2\u0006\u0010\"\u001a\u00020\u0018H&\u00a2\u0006\u0004\u0008#\u0010$J\u0017\u0010&\u001a\u00020\u00062\u0006\u0010%\u001a\u00020\nH&\u00a2\u0006\u0004\u0008&\u0010\'J\u0017\u0010)\u001a\u00020\u00062\u0006\u0010(\u001a\u00020 H&\u00a2\u0006\u0004\u0008)\u0010*J\u0017\u0010-\u001a\u00020\u00062\u0006\u0010,\u001a\u00020+H&\u00a2\u0006\u0004\u0008-\u0010.J\u000f\u0010/\u001a\u00020\u0006H&\u00a2\u0006\u0004\u0008/\u00100J\u0017\u00102\u001a\u00020\u00062\u0006\u00101\u001a\u00020 H&\u00a2\u0006\u0004\u00082\u0010*R\u001c\u00106\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u0018038&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u00084\u00105\u00a8\u00067\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/InternalVehicleAntennaTransport;",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport;",
        "Ltechnology/cariad/cat/genx/Referencing;",
        "Ltechnology/cariad/cat/genx/protocol/Message;",
        "message",
        "Llx0/o;",
        "Llx0/b0;",
        "sendDispatched-gIAlu-s",
        "(Ltechnology/cariad/cat/genx/protocol/Message;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "sendDispatched",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "sendNonDispatched",
        "(Ltechnology/cariad/cat/genx/protocol/Message;)Ltechnology/cariad/cat/genx/GenXError;",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;",
        "connection",
        "disconnect",
        "(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)V",
        "",
        "cgxTransportState",
        "onTransportStateChanged",
        "(B)V",
        "cgxReachable",
        "onReachabilityChanged",
        "cgxCar2PhoneMode",
        "",
        "reservedBytes",
        "nonce",
        "onAdvertisementInfoReceived",
        "(B[B[B)V",
        "",
        "rawAddress",
        "rawPriority",
        "",
        "requiresQueuing",
        "data",
        "onMessageReceived",
        "(JBZ[B)V",
        "error",
        "onErrorEncountered",
        "(Ltechnology/cariad/cat/genx/GenXError;)V",
        "isFull",
        "onSendWindowStateChanged",
        "(Z)V",
        "",
        "sendDurationsMillis",
        "onDurationsReported",
        "([J)V",
        "onServiceDiscoveryUpdated",
        "()V",
        "enabled",
        "setClientManagerState",
        "Lyy0/a2;",
        "getAdvertisementNonce",
        "()Lyy0/a2;",
        "advertisementNonce",
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
.method public abstract disconnect(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)V
.end method

.method public abstract getAdvertisementNonce()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract onAdvertisementInfoReceived(B[B[B)V
.end method

.method public abstract onDurationsReported([J)V
.end method

.method public abstract onErrorEncountered(Ltechnology/cariad/cat/genx/GenXError;)V
.end method

.method public abstract onMessageReceived(JBZ[B)V
.end method

.method public abstract onReachabilityChanged(B)V
.end method

.method public abstract onSendWindowStateChanged(Z)V
.end method

.method public abstract onServiceDiscoveryUpdated()V
.end method

.method public abstract onTransportStateChanged(B)V
.end method

.method public abstract sendDispatched-gIAlu-s(Ltechnology/cariad/cat/genx/protocol/Message;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/protocol/Message;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation
.end method

.method public abstract sendNonDispatched(Ltechnology/cariad/cat/genx/protocol/Message;)Ltechnology/cariad/cat/genx/GenXError;
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method public abstract setClientManagerState(Z)V
.end method
