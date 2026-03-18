.class public interface abstract Ltechnology/cariad/cat/genx/VehicleAntennaTransport;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/VehicleAntennaTransport$AntennaInformation;,
        Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;,
        Ltechnology/cariad/cat/genx/VehicleAntennaTransport$DefaultImpls;,
        Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0098\u0001\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0012\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0008f\u0018\u00002\u00020\u0001:\u0003<=>J\u001a\u0010\u0007\u001a\u0004\u0018\u00010\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u00a6@\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J \u0010\n\u001a\n\u0012\u0004\u0012\u00020\t\u0018\u00010\u00082\u0006\u0010\u0003\u001a\u00020\u0002H\u00a6@\u00a2\u0006\u0004\u0008\n\u0010\u0006J\u0018\u0010\r\u001a\u00020\u000c2\u0006\u0010\u000b\u001a\u00020\tH\u00a6@\u00a2\u0006\u0004\u0008\r\u0010\u000eJ.\u0010\u0016\u001a\u0008\u0012\u0004\u0012\u00020\u00130\u00122\u0006\u0010\u0010\u001a\u00020\u000f2\u000e\u0008\u0002\u0010\n\u001a\u0008\u0012\u0004\u0012\u00020\t0\u0011H\u00a6@\u00a2\u0006\u0004\u0008\u0014\u0010\u0015R\u0014\u0010\u001a\u001a\u00020\u00178&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0018\u0010\u0019R\u001a\u0010\u001f\u001a\u0008\u0012\u0004\u0012\u00020\u001c0\u001b8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u001d\u0010\u001eR\u001a\u0010 \u001a\u0008\u0012\u0004\u0012\u00020\u000c0\u001b8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008 \u0010\u001eR\u001a\u0010#\u001a\u0008\u0012\u0004\u0012\u00020!0\u001b8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\"\u0010\u001eR\u001c\u0010&\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010$0\u001b8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008%\u0010\u001eR\u001c\u0010)\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\'0\u001b8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008(\u0010\u001eR\u001a\u0010.\u001a\u0008\u0012\u0004\u0012\u00020+0*8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008,\u0010-R\u001a\u00101\u001a\u0008\u0012\u0004\u0012\u00020/0*8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u00080\u0010-R\u001a\u00104\u001a\u0008\u0012\u0004\u0012\u0002020*8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u00083\u0010-R\u001a\u00107\u001a\u0008\u0012\u0004\u0012\u0002050*8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u00086\u0010-R\u001a\u0010:\u001a\u0008\u0012\u0004\u0012\u0002080*8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u00089\u0010-R\u001a\u0010;\u001a\u0008\u0012\u0004\u0012\u00020\u000c0\u001b8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008;\u0010\u001e\u00a8\u0006?\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport;",
        "",
        "Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;",
        "globalServiceId",
        "Llx0/s;",
        "functionState-lj4SQcc",
        "(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "functionState",
        "",
        "Ltechnology/cariad/cat/genx/protocol/Address;",
        "addresses",
        "address",
        "",
        "isAddressRegistered",
        "(Ltechnology/cariad/cat/genx/protocol/Address;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;",
        "connectionDelegate",
        "",
        "Llx0/o;",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;",
        "connect-0E7RQCE",
        "(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;Ljava/util/Set;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "connect",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;",
        "getIdentifier",
        "()Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;",
        "identifier",
        "Lyy0/a2;",
        "Ltechnology/cariad/cat/genx/Reachability;",
        "getReachability",
        "()Lyy0/a2;",
        "reachability",
        "isConnectable",
        "Ltechnology/cariad/cat/genx/TransportState;",
        "getTransportState",
        "transportState",
        "Ltechnology/cariad/cat/genx/Car2PhoneMode;",
        "getCar2PhoneMode",
        "car2PhoneMode",
        "",
        "getBytesReserved",
        "bytesReserved",
        "Lyy0/i;",
        "Lmy0/c;",
        "getSendDurations",
        "()Lyy0/i;",
        "sendDurations",
        "Ltechnology/cariad/cat/genx/SendWindowState;",
        "getSendWindowState",
        "sendWindowState",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "getTransportErrors",
        "transportErrors",
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;",
        "getLinkParameters",
        "linkParameters",
        "Llx0/b0;",
        "getServiceDiscoveryChanged",
        "serviceDiscoveryChanged",
        "isTransportEnabled",
        "Connection",
        "Identifier",
        "AntennaInformation",
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


# direct methods
.method public static synthetic connect-0E7RQCE$default(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;Ljava/util/Set;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    if-nez p5, :cond_1

    .line 2
    .line 3
    and-int/lit8 p4, p4, 0x2

    .line 4
    .line 5
    if-eqz p4, :cond_0

    .line 6
    .line 7
    sget-object p2, Lmx0/u;->d:Lmx0/u;

    .line 8
    .line 9
    :cond_0
    invoke-interface {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->connect-0E7RQCE(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;Ljava/util/Set;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 15
    .line 16
    const-string p1, "Super calls with default arguments not supported in this target, function: connect-0E7RQCE"

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0
.end method


# virtual methods
.method public abstract addresses(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ljava/util/List<",
            "Ltechnology/cariad/cat/genx/protocol/Address;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation
.end method

.method public abstract connect-0E7RQCE(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;Ljava/util/Set;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;",
            "Ljava/util/Set<",
            "Ltechnology/cariad/cat/genx/protocol/Address;",
            ">;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation
.end method

.method public abstract functionState-lj4SQcc(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/s;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation
.end method

.method public abstract getBytesReserved()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getCar2PhoneMode()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;
.end method

.method public abstract getLinkParameters()Lyy0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i;"
        }
    .end annotation
.end method

.method public abstract getReachability()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getSendDurations()Lyy0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i;"
        }
    .end annotation
.end method

.method public abstract getSendWindowState()Lyy0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i;"
        }
    .end annotation
.end method

.method public abstract getServiceDiscoveryChanged()Lyy0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i;"
        }
    .end annotation
.end method

.method public abstract getTransportErrors()Lyy0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i;"
        }
    .end annotation
.end method

.method public abstract getTransportState()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isAddressRegistered(Ltechnology/cariad/cat/genx/protocol/Address;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/protocol/Address;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ljava/lang/Boolean;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation
.end method

.method public abstract isConnectable()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isTransportEnabled()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method
