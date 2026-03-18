.class public final Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/VehicleAntennaTransport;
.implements Lvy0/b0;
.implements Ljava/io/Closeable;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00c8\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\t\n\u0002\u0018\u0002\n\u0002\u0008\u0008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0008\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008\u0001\u0018\u00002\u00020\u00012\u00020\u00022\u00020\u0003B#\u0012\u0008\u0010\u0004\u001a\u0004\u0018\u00010\u0001\u0012\u0008\u0010\u0006\u001a\u0004\u0018\u00010\u0005\u0012\u0006\u0010\u0008\u001a\u00020\u0007\u00a2\u0006\u0004\u0008\t\u0010\nJ\u0017\u0010\u000c\u001a\u00020\u000b2\u0008\u0010\u0004\u001a\u0004\u0018\u00010\u0001\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u001a\u0010\u0013\u001a\u0004\u0018\u00010\u00102\u0006\u0010\u000f\u001a\u00020\u000eH\u0096@\u00a2\u0006\u0004\u0008\u0011\u0010\u0012J \u0010\u0016\u001a\n\u0012\u0004\u0012\u00020\u0015\u0018\u00010\u00142\u0006\u0010\u000f\u001a\u00020\u000eH\u0096@\u00a2\u0006\u0004\u0008\u0016\u0010\u0012J\u0018\u0010\u0019\u001a\u00020\u00182\u0006\u0010\u0017\u001a\u00020\u0015H\u0096@\u00a2\u0006\u0004\u0008\u0019\u0010\u001aJ,\u0010\"\u001a\u0008\u0012\u0004\u0012\u00020\u001f0\u001e2\u0006\u0010\u001c\u001a\u00020\u001b2\u000c\u0010\u0016\u001a\u0008\u0012\u0004\u0012\u00020\u00150\u001dH\u0096@\u00a2\u0006\u0004\u0008 \u0010!J\u000f\u0010#\u001a\u00020\u000bH\u0016\u00a2\u0006\u0004\u0008#\u0010$J\u0017\u0010%\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0001H\u0002\u00a2\u0006\u0004\u0008%\u0010&J\u0010\u0010\'\u001a\u00020\u000bH\u0082@\u00a2\u0006\u0004\u0008\'\u0010(R\u001a\u0010*\u001a\u00020)8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008*\u0010+\u001a\u0004\u0008,\u0010-R\u0018\u0010.\u001a\u0004\u0018\u00010\u00018\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008.\u0010/R\u0018\u00100\u001a\u0004\u0018\u00010\u00058\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u00080\u00101R\u001a\u00104\u001a\u0008\u0012\u0004\u0012\u000203028\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00084\u00105R \u00107\u001a\u0008\u0012\u0004\u0012\u000203068\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u00087\u00108\u001a\u0004\u00089\u0010:R\u001a\u0010<\u001a\u0008\u0012\u0004\u0012\u00020;028\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008<\u00105R \u0010=\u001a\u0008\u0012\u0004\u0012\u00020;068\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008=\u00108\u001a\u0004\u0008>\u0010:R\u001a\u0010?\u001a\u0008\u0012\u0004\u0012\u00020\u0018028\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008?\u00105R \u0010@\u001a\u0008\u0012\u0004\u0012\u00020\u0018068\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008@\u00108\u001a\u0004\u0008@\u0010:R\u001c\u0010B\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010A028\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008B\u00105R\"\u0010C\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010A068\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008C\u00108\u001a\u0004\u0008D\u0010:R\u001c\u0010F\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010E028\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008F\u00105R\"\u0010G\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010E068\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008G\u00108\u001a\u0004\u0008H\u0010:R\u001a\u0010K\u001a\u0008\u0012\u0004\u0012\u00020J0I8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008K\u0010LR \u0010N\u001a\u0008\u0012\u0004\u0012\u00020J0M8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008N\u0010O\u001a\u0004\u0008P\u0010QR\u001a\u0010S\u001a\u0008\u0012\u0004\u0012\u00020R0I8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008S\u0010LR \u0010T\u001a\u0008\u0012\u0004\u0012\u00020R0M8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008T\u0010O\u001a\u0004\u0008U\u0010QR\u001a\u0010W\u001a\u0008\u0012\u0004\u0012\u00020V0I8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008W\u0010LR \u0010X\u001a\u0008\u0012\u0004\u0012\u00020V0M8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008X\u0010O\u001a\u0004\u0008Y\u0010QR\u001a\u0010[\u001a\u0008\u0012\u0004\u0012\u00020Z0I8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008[\u0010LR \u0010\\\u001a\u0008\u0012\u0004\u0012\u00020Z0M8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\\\u0010O\u001a\u0004\u0008]\u0010QR\u001a\u0010^\u001a\u0008\u0012\u0004\u0012\u00020\u000b0I8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008^\u0010LR \u0010_\u001a\u0008\u0012\u0004\u0012\u00020\u000b0M8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008_\u0010O\u001a\u0004\u0008`\u0010QR\u001a\u0010a\u001a\u0008\u0012\u0004\u0012\u00020\u0018028\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008a\u00105R \u0010b\u001a\u0008\u0012\u0004\u0012\u00020\u0018068\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008b\u00108\u001a\u0004\u0008b\u0010:R\u0014\u0010f\u001a\u00020c8VX\u0096\u0004\u00a2\u0006\u0006\u001a\u0004\u0008d\u0010e\u00a8\u0006g"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport;",
        "Lvy0/b0;",
        "Ljava/io/Closeable;",
        "transport",
        "Lvy0/i1;",
        "supervisorJob",
        "Lvy0/x;",
        "ioDispatcher",
        "<init>",
        "(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Lvy0/i1;Lvy0/x;)V",
        "Llx0/b0;",
        "updateTransport",
        "(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)V",
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
        "close",
        "()V",
        "observeBLETransport",
        "(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Lvy0/i1;",
        "handleNoAvailableTransport",
        "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lpx0/g;",
        "coroutineContext",
        "Lpx0/g;",
        "getCoroutineContext",
        "()Lpx0/g;",
        "availableTransport",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport;",
        "bleTransportFacadeJob",
        "Lvy0/i1;",
        "Lyy0/j1;",
        "Ltechnology/cariad/cat/genx/Reachability;",
        "_reachability",
        "Lyy0/j1;",
        "Lyy0/a2;",
        "reachability",
        "Lyy0/a2;",
        "getReachability",
        "()Lyy0/a2;",
        "Ltechnology/cariad/cat/genx/TransportState;",
        "_transportState",
        "transportState",
        "getTransportState",
        "_isConnectable",
        "isConnectable",
        "Ltechnology/cariad/cat/genx/Car2PhoneMode;",
        "_car2PhoneMode",
        "car2PhoneMode",
        "getCar2PhoneMode",
        "",
        "_bytesReserved",
        "bytesReserved",
        "getBytesReserved",
        "Lyy0/i1;",
        "Lmy0/c;",
        "_sendDurations",
        "Lyy0/i1;",
        "Lyy0/i;",
        "sendDurations",
        "Lyy0/i;",
        "getSendDurations",
        "()Lyy0/i;",
        "Ltechnology/cariad/cat/genx/SendWindowState;",
        "_sendWindowState",
        "sendWindowState",
        "getSendWindowState",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "_transportErrors",
        "transportErrors",
        "getTransportErrors",
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;",
        "_linkParameters",
        "linkParameters",
        "getLinkParameters",
        "_serviceDiscoveryChanged",
        "serviceDiscoveryChanged",
        "getServiceDiscoveryChanged",
        "_isTransportEnabled",
        "isTransportEnabled",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;",
        "getIdentifier",
        "()Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;",
        "identifier",
        "remoteparkassistplugin_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final $stable:I = 0x8


# instance fields
.field private final _bytesReserved:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _car2PhoneMode:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isConnectable:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _isTransportEnabled:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _linkParameters:Lyy0/i1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/i1;"
        }
    .end annotation
.end field

.field private final _reachability:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _sendDurations:Lyy0/i1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/i1;"
        }
    .end annotation
.end field

.field private final _sendWindowState:Lyy0/i1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/i1;"
        }
    .end annotation
.end field

.field private final _serviceDiscoveryChanged:Lyy0/i1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/i1;"
        }
    .end annotation
.end field

.field private final _transportErrors:Lyy0/i1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/i1;"
        }
    .end annotation
.end field

.field private final _transportState:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private availableTransport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

.field private bleTransportFacadeJob:Lvy0/i1;

.field private final bytesReserved:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final car2PhoneMode:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final coroutineContext:Lpx0/g;

.field private final isConnectable:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isTransportEnabled:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final linkParameters:Lyy0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/i;"
        }
    .end annotation
.end field

.field private final reachability:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final sendDurations:Lyy0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/i;"
        }
    .end annotation
.end field

.field private final sendWindowState:Lyy0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/i;"
        }
    .end annotation
.end field

.field private final serviceDiscoveryChanged:Lyy0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/i;"
        }
    .end annotation
.end field

.field private final transportErrors:Lyy0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/i;"
        }
    .end annotation
.end field

.field private final transportState:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Lvy0/i1;Lvy0/x;)V
    .locals 2

    .line 1
    const-string v0, "ioDispatcher"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    const-string v0, "BLETransportFacade"

    .line 10
    .line 11
    invoke-static {v0, p3, p2}, Llp/h1;->a(Ljava/lang/String;Lvy0/x;Lvy0/i1;)Lpx0/g;

    .line 12
    .line 13
    .line 14
    move-result-object p2

    .line 15
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->coroutineContext:Lpx0/g;

    .line 16
    .line 17
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->availableTransport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 18
    .line 19
    if-eqz p1, :cond_0

    .line 20
    .line 21
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->getReachability()Lyy0/a2;

    .line 22
    .line 23
    .line 24
    move-result-object p2

    .line 25
    if-eqz p2, :cond_0

    .line 26
    .line 27
    invoke-interface {p2}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    check-cast p2, Ltechnology/cariad/cat/genx/Reachability;

    .line 32
    .line 33
    if-nez p2, :cond_1

    .line 34
    .line 35
    :cond_0
    sget-object p2, Ltechnology/cariad/cat/genx/Reachability;->UNREACHABLE:Ltechnology/cariad/cat/genx/Reachability;

    .line 36
    .line 37
    :cond_1
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 38
    .line 39
    .line 40
    move-result-object p2

    .line 41
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_reachability:Lyy0/j1;

    .line 42
    .line 43
    new-instance p3, Lyy0/l1;

    .line 44
    .line 45
    invoke-direct {p3, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 46
    .line 47
    .line 48
    iput-object p3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->reachability:Lyy0/a2;

    .line 49
    .line 50
    if-eqz p1, :cond_2

    .line 51
    .line 52
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->getTransportState()Lyy0/a2;

    .line 53
    .line 54
    .line 55
    move-result-object p2

    .line 56
    if-eqz p2, :cond_2

    .line 57
    .line 58
    invoke-interface {p2}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p2

    .line 62
    check-cast p2, Ltechnology/cariad/cat/genx/TransportState;

    .line 63
    .line 64
    if-nez p2, :cond_3

    .line 65
    .line 66
    :cond_2
    sget-object p2, Ltechnology/cariad/cat/genx/TransportState;->DISCONNECTED:Ltechnology/cariad/cat/genx/TransportState;

    .line 67
    .line 68
    :cond_3
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 69
    .line 70
    .line 71
    move-result-object p2

    .line 72
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_transportState:Lyy0/j1;

    .line 73
    .line 74
    new-instance p3, Lyy0/l1;

    .line 75
    .line 76
    invoke-direct {p3, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 77
    .line 78
    .line 79
    iput-object p3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->transportState:Lyy0/a2;

    .line 80
    .line 81
    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 82
    .line 83
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 84
    .line 85
    .line 86
    move-result-object p3

    .line 87
    iput-object p3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_isConnectable:Lyy0/j1;

    .line 88
    .line 89
    new-instance v0, Lyy0/l1;

    .line 90
    .line 91
    invoke-direct {v0, p3}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 92
    .line 93
    .line 94
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->isConnectable:Lyy0/a2;

    .line 95
    .line 96
    const/4 p3, 0x0

    .line 97
    if-eqz p1, :cond_4

    .line 98
    .line 99
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->getCar2PhoneMode()Lyy0/a2;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    if-eqz v0, :cond_4

    .line 104
    .line 105
    invoke-interface {v0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    check-cast v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 110
    .line 111
    goto :goto_0

    .line 112
    :cond_4
    move-object v0, p3

    .line 113
    :goto_0
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_car2PhoneMode:Lyy0/j1;

    .line 118
    .line 119
    new-instance v1, Lyy0/l1;

    .line 120
    .line 121
    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 122
    .line 123
    .line 124
    iput-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->car2PhoneMode:Lyy0/a2;

    .line 125
    .line 126
    if-eqz p1, :cond_5

    .line 127
    .line 128
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->getBytesReserved()Lyy0/a2;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    if-eqz p1, :cond_5

    .line 133
    .line 134
    invoke-interface {p1}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    move-object p3, p1

    .line 139
    check-cast p3, [B

    .line 140
    .line 141
    :cond_5
    invoke-static {p3}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 142
    .line 143
    .line 144
    move-result-object p1

    .line 145
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_bytesReserved:Lyy0/j1;

    .line 146
    .line 147
    new-instance p3, Lyy0/l1;

    .line 148
    .line 149
    invoke-direct {p3, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 150
    .line 151
    .line 152
    iput-object p3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->bytesReserved:Lyy0/a2;

    .line 153
    .line 154
    sget-object p1, Lxy0/a;->e:Lxy0/a;

    .line 155
    .line 156
    const/4 p3, 0x1

    .line 157
    invoke-static {p3, p3, p1}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 158
    .line 159
    .line 160
    move-result-object v0

    .line 161
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_sendDurations:Lyy0/i1;

    .line 162
    .line 163
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->sendDurations:Lyy0/i;

    .line 164
    .line 165
    invoke-static {p3, p3, p1}, Lyy0/u;->a(IILxy0/a;)Lyy0/q1;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_sendWindowState:Lyy0/i1;

    .line 170
    .line 171
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->sendWindowState:Lyy0/i;

    .line 172
    .line 173
    invoke-static {p3, p3, p1}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_transportErrors:Lyy0/i1;

    .line 178
    .line 179
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->transportErrors:Lyy0/i;

    .line 180
    .line 181
    const/4 v0, 0x2

    .line 182
    const/4 v1, 0x0

    .line 183
    invoke-static {v1, v0, p1}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 184
    .line 185
    .line 186
    move-result-object v0

    .line 187
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_linkParameters:Lyy0/i1;

    .line 188
    .line 189
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->linkParameters:Lyy0/i;

    .line 190
    .line 191
    invoke-static {p3, p3, p1}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 192
    .line 193
    .line 194
    move-result-object p1

    .line 195
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_serviceDiscoveryChanged:Lyy0/i1;

    .line 196
    .line 197
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->serviceDiscoveryChanged:Lyy0/i;

    .line 198
    .line 199
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 200
    .line 201
    .line 202
    move-result-object p1

    .line 203
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_isTransportEnabled:Lyy0/j1;

    .line 204
    .line 205
    new-instance p2, Lyy0/l1;

    .line 206
    .line 207
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 208
    .line 209
    .line 210
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->isTransportEnabled:Lyy0/a2;

    .line 211
    .line 212
    return-void
.end method

.method public static synthetic a(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->updateTransport$lambda$1(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final synthetic access$get_bytesReserved$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Lyy0/j1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_bytesReserved:Lyy0/j1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$get_car2PhoneMode$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Lyy0/j1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_car2PhoneMode:Lyy0/j1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$get_isConnectable$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Lyy0/j1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_isConnectable:Lyy0/j1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$get_isTransportEnabled$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Lyy0/j1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_isTransportEnabled:Lyy0/j1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$get_linkParameters$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Lyy0/i1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_linkParameters:Lyy0/i1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$get_reachability$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Lyy0/j1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_reachability:Lyy0/j1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$get_sendDurations$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Lyy0/i1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_sendDurations:Lyy0/i1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$get_sendWindowState$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Lyy0/i1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_sendWindowState:Lyy0/i1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$get_serviceDiscoveryChanged$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Lyy0/i1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_serviceDiscoveryChanged:Lyy0/i1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$get_transportErrors$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Lyy0/i1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_transportErrors:Lyy0/i1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$get_transportState$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Lyy0/j1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_transportState:Lyy0/j1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$handleNoAvailableTransport(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->handleNoAvailableTransport(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->close$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final close$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "close()"

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic d(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->handleNoAvailableTransport$lambda$0(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->observeBLETransport$lambda$0(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->updateTransport$lambda$0(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final handleNoAvailableTransport(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/b0;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    instance-of v0, p1, Lj61/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lj61/c;

    .line 7
    .line 8
    iget v1, v0, Lj61/c;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lj61/c;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lj61/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lj61/c;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lj61/c;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lj61/c;->f:I

    .line 30
    .line 31
    const/4 v3, 0x5

    .line 32
    const/4 v4, 0x4

    .line 33
    const/4 v5, 0x3

    .line 34
    const/4 v6, 0x2

    .line 35
    const/4 v7, 0x1

    .line 36
    const/4 v8, 0x0

    .line 37
    sget-object v9, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    if-eqz v2, :cond_6

    .line 40
    .line 41
    if-eq v2, v7, :cond_5

    .line 42
    .line 43
    if-eq v2, v6, :cond_4

    .line 44
    .line 45
    if-eq v2, v5, :cond_3

    .line 46
    .line 47
    if-eq v2, v4, :cond_2

    .line 48
    .line 49
    if-ne v2, v3, :cond_1

    .line 50
    .line 51
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    return-object v9

    .line 55
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 56
    .line 57
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 58
    .line 59
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p0

    .line 63
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    goto :goto_4

    .line 67
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    goto :goto_3

    .line 71
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    goto :goto_1

    .line 79
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    new-instance p1, Lh50/q0;

    .line 83
    .line 84
    const/16 v2, 0x10

    .line 85
    .line 86
    invoke-direct {p1, p0, v2}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 87
    .line 88
    .line 89
    invoke-static {p0, p1}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 90
    .line 91
    .line 92
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_reachability:Lyy0/j1;

    .line 93
    .line 94
    sget-object v2, Ltechnology/cariad/cat/genx/Reachability;->UNREACHABLE:Ltechnology/cariad/cat/genx/Reachability;

    .line 95
    .line 96
    iput v7, v0, Lj61/c;->f:I

    .line 97
    .line 98
    check-cast p1, Lyy0/c2;

    .line 99
    .line 100
    invoke-virtual {p1, v2, v0}, Lyy0/c2;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    if-ne v9, v1, :cond_7

    .line 104
    .line 105
    goto :goto_5

    .line 106
    :cond_7
    :goto_1
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_transportState:Lyy0/j1;

    .line 107
    .line 108
    sget-object v2, Ltechnology/cariad/cat/genx/TransportState;->DISCONNECTED:Ltechnology/cariad/cat/genx/TransportState;

    .line 109
    .line 110
    iput v6, v0, Lj61/c;->f:I

    .line 111
    .line 112
    check-cast p1, Lyy0/c2;

    .line 113
    .line 114
    invoke-virtual {p1, v2, v0}, Lyy0/c2;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    if-ne v9, v1, :cond_8

    .line 118
    .line 119
    goto :goto_5

    .line 120
    :cond_8
    :goto_2
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_isConnectable:Lyy0/j1;

    .line 121
    .line 122
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 123
    .line 124
    iput v5, v0, Lj61/c;->f:I

    .line 125
    .line 126
    check-cast p1, Lyy0/c2;

    .line 127
    .line 128
    invoke-virtual {p1, v2, v0}, Lyy0/c2;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    if-ne v9, v1, :cond_9

    .line 132
    .line 133
    goto :goto_5

    .line 134
    :cond_9
    :goto_3
    iget-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_car2PhoneMode:Lyy0/j1;

    .line 135
    .line 136
    iput v4, v0, Lj61/c;->f:I

    .line 137
    .line 138
    check-cast p1, Lyy0/c2;

    .line 139
    .line 140
    invoke-virtual {p1, v8, v0}, Lyy0/c2;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    if-ne v9, v1, :cond_a

    .line 144
    .line 145
    goto :goto_5

    .line 146
    :cond_a
    :goto_4
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->_bytesReserved:Lyy0/j1;

    .line 147
    .line 148
    iput v3, v0, Lj61/c;->f:I

    .line 149
    .line 150
    check-cast p0, Lyy0/c2;

    .line 151
    .line 152
    invoke-virtual {p0, v8, v0}, Lyy0/c2;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    if-ne v9, v1, :cond_b

    .line 156
    .line 157
    :goto_5
    return-object v1

    .line 158
    :cond_b
    return-object v9
.end method

.method private static final handleNoAvailableTransport$lambda$0(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "handleNoAvailableTransport(): set reachability to UNREACHABLE, transportState to DISCONNECTED and car2PhoneMode to null - "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private final observeBLETransport(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Lvy0/i1;
    .locals 3

    .line 1
    new-instance v0, Lj61/a;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, p1, p0, v1}, Lj61/a;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;I)V

    .line 5
    .line 6
    .line 7
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 8
    .line 9
    .line 10
    new-instance v0, Laa/s;

    .line 11
    .line 12
    const/16 v1, 0xc

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    invoke-direct {v0, v1, p1, p0, v2}, Laa/s;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 16
    .line 17
    .line 18
    const/4 p1, 0x3

    .line 19
    invoke-static {p0, v2, v2, v0, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method private static final observeBLETransport$lambda$0(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "observeBLETransport(): transport = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string p0, " - "

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method private static final updateTransport$lambda$0(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->availableTransport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 2
    .line 3
    new-instance v0, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v1, "updateTransport(): skip update - transport is the same. Available transport = "

    .line 6
    .line 7
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, ", new transport = "

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method

.method private static final updateTransport$lambda$1(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "updateTransport(): transport = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string p0, " - "

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method


# virtual methods
.method public addresses(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0
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

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->availableTransport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0, p1, p2}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->addresses(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return-object p0
.end method

.method public close()V
    .locals 2

    .line 1
    new-instance v0, Lj00/a;

    .line 2
    .line 3
    const/16 v1, 0xa

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lj00/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "close()"

    .line 12
    .line 13
    invoke-static {p0, v0}, Lvy0/e0;->l(Lvy0/b0;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public connect-0E7RQCE(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;Ljava/util/Set;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4
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

    .line 1
    instance-of v0, p3, Lj61/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lj61/b;

    .line 7
    .line 8
    iget v1, v0, Lj61/b;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lj61/b;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lj61/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lj61/b;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lj61/b;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lj61/b;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    check-cast p3, Llx0/o;

    .line 40
    .line 41
    iget-object p0, p3, Llx0/o;->d:Ljava/lang/Object;

    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    iget-object p3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->availableTransport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 56
    .line 57
    if-eqz p3, :cond_4

    .line 58
    .line 59
    iput v3, v0, Lj61/b;->f:I

    .line 60
    .line 61
    invoke-interface {p3, p1, p2, v0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->connect-0E7RQCE(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;Ljava/util/Set;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    if-ne p0, v1, :cond_3

    .line 66
    .line 67
    return-object v1

    .line 68
    :cond_3
    return-object p0

    .line 69
    :cond_4
    new-instance p1, Ljava/lang/Exception;

    .line 70
    .line 71
    new-instance p2, Ljava/lang/StringBuilder;

    .line 72
    .line 73
    const-string p3, "Transport is not available - "

    .line 74
    .line 75
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    invoke-direct {p1, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    return-object p0
.end method

.method public functionState-lj4SQcc(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0
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

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->availableTransport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0, p1, p2}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->functionState-lj4SQcc(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return-object p0
.end method

.method public getBytesReserved()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->bytesReserved:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getCar2PhoneMode()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->car2PhoneMode:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->coroutineContext:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;
    .locals 3

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->availableTransport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 2
    .line 3
    if-eqz p0, :cond_1

    .line 4
    .line 5
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    return-object p0

    .line 13
    :cond_1
    :goto_0
    new-instance p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 14
    .line 15
    sget-object v0, Ltechnology/cariad/cat/genx/Antenna;->OUTER:Ltechnology/cariad/cat/genx/Antenna;

    .line 16
    .line 17
    sget-object v1, Ltechnology/cariad/cat/genx/TransportType;->BLE:Ltechnology/cariad/cat/genx/TransportType;

    .line 18
    .line 19
    const-string v2, "UNKNOWN"

    .line 20
    .line 21
    invoke-direct {p0, v2, v0, v1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;-><init>(Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/TransportType;)V

    .line 22
    .line 23
    .line 24
    return-object p0
.end method

.method public getLinkParameters()Lyy0/i;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->linkParameters:Lyy0/i;

    .line 2
    .line 3
    return-object p0
.end method

.method public getReachability()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->reachability:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSendDurations()Lyy0/i;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->sendDurations:Lyy0/i;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSendWindowState()Lyy0/i;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->sendWindowState:Lyy0/i;

    .line 2
    .line 3
    return-object p0
.end method

.method public getServiceDiscoveryChanged()Lyy0/i;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->serviceDiscoveryChanged:Lyy0/i;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTransportErrors()Lyy0/i;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->transportErrors:Lyy0/i;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTransportState()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->transportState:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isAddressRegistered(Ltechnology/cariad/cat/genx/protocol/Address;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4
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

    .line 1
    instance-of v0, p2, Lj61/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lj61/d;

    .line 7
    .line 8
    iget v1, v0, Lj61/d;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lj61/d;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lj61/d;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lj61/d;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lj61/d;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lj61/d;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->availableTransport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 52
    .line 53
    if-eqz p0, :cond_4

    .line 54
    .line 55
    iput v3, v0, Lj61/d;->f:I

    .line 56
    .line 57
    invoke-interface {p0, p1, v0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->isAddressRegistered(Ltechnology/cariad/cat/genx/protocol/Address;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p2

    .line 61
    if-ne p2, v1, :cond_3

    .line 62
    .line 63
    return-object v1

    .line 64
    :cond_3
    :goto_1
    check-cast p2, Ljava/lang/Boolean;

    .line 65
    .line 66
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    goto :goto_2

    .line 71
    :cond_4
    const/4 p0, 0x0

    .line 72
    :goto_2
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0
.end method

.method public isConnectable()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->isConnectable:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isTransportEnabled()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->isTransportEnabled:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public final updateTransport(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->availableTransport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    new-instance v0, Lj61/a;

    .line 10
    .line 11
    invoke-direct {v0, p1, p0}, Lj61/a;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)V

    .line 12
    .line 13
    .line 14
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    new-instance v0, Lj61/a;

    .line 19
    .line 20
    const/4 v1, 0x1

    .line 21
    invoke-direct {v0, p1, p0, v1}, Lj61/a;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;I)V

    .line 22
    .line 23
    .line 24
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 25
    .line 26
    .line 27
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->availableTransport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 28
    .line 29
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->bleTransportFacadeJob:Lvy0/i1;

    .line 30
    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    const-string v1, "BLE job restarted due to new transport configuration"

    .line 34
    .line 35
    invoke-static {v1, v0}, Lvy0/e0;->k(Ljava/lang/String;Lvy0/i1;)V

    .line 36
    .line 37
    .line 38
    :cond_1
    const/4 v0, 0x0

    .line 39
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->bleTransportFacadeJob:Lvy0/i1;

    .line 40
    .line 41
    if-eqz p1, :cond_2

    .line 42
    .line 43
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->observeBLETransport(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Lvy0/i1;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->bleTransportFacadeJob:Lvy0/i1;

    .line 48
    .line 49
    return-void

    .line 50
    :cond_2
    new-instance p1, Lh40/h;

    .line 51
    .line 52
    const/16 v1, 0x15

    .line 53
    .line 54
    invoke-direct {p1, p0, v0, v1}, Lh40/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 55
    .line 56
    .line 57
    const/4 v1, 0x3

    .line 58
    invoke-static {p0, v0, v0, p1, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 59
    .line 60
    .line 61
    return-void
.end method
