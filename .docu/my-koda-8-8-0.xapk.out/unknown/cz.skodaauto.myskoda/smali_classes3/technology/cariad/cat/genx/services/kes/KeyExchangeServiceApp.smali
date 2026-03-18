.class public final Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;
.implements Ljava/io/Closeable;
.implements Lvy0/b0;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Companion;,
        Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result;,
        Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$WhenMappings;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00b0\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0010\u000e\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u0012\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0010\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0008\u0008\u0000\u0018\u0000 i2\u00020\u00012\u00020\u00022\u00020\u0003:\u0002jiB\u001f\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0006\u0010\u0007\u001a\u00020\u0006\u0012\u0006\u0010\u0008\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\t\u0010\nJ\r\u0010\u000c\u001a\u00020\u000b\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\r\u0010\u000f\u001a\u00020\u000e\u00a2\u0006\u0004\u0008\u000f\u0010\u0010J(\u0010\u0016\u001a\u001a\u0012\u0016\u0012\u0014\u0012\u0010\u0012\u000e\u0012\u0004\u0012\u00020\u0014\u0012\u0004\u0012\u00020\u00150\u00130\u00120\u0011H\u0086@\u00a2\u0006\u0004\u0008\u0016\u0010\u0017J\u0010\u0010\u0018\u001a\u00020\u000eH\u0086@\u00a2\u0006\u0004\u0008\u0018\u0010\u0017J\u001e\u0010\u001d\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00122\u0006\u0010\u001a\u001a\u00020\u0019H\u0080H\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ\u001f\u0010!\u001a\u00020\u000e2\u0006\u0010\u001e\u001a\u00020\u00152\u0006\u0010 \u001a\u00020\u001fH\u0016\u00a2\u0006\u0004\u0008!\u0010\"J\u001f\u0010#\u001a\u00020\u000e2\u0006\u0010\u001e\u001a\u00020\u00152\u0006\u0010\u001a\u001a\u00020\u0019H\u0016\u00a2\u0006\u0004\u0008#\u0010$J\u000f\u0010%\u001a\u00020\u000eH\u0016\u00a2\u0006\u0004\u0008%\u0010\u0010J\u000f\u0010\'\u001a\u00020&H\u0016\u00a2\u0006\u0004\u0008\'\u0010(J\u000f\u0010*\u001a\u00020)H\u0002\u00a2\u0006\u0004\u0008*\u0010+J\u001f\u0010-\u001a\u00020\u000e2\u0006\u0010,\u001a\u00020\u00142\u0006\u0010\u001e\u001a\u00020\u0015H\u0002\u00a2\u0006\u0004\u0008-\u0010.J\u001f\u00103\u001a\u00020\u000b2\u0006\u00100\u001a\u00020/2\u0006\u00102\u001a\u000201H\u0002\u00a2\u0006\u0004\u00083\u00104J#\u00107\u001a\u00020\u000e2\u0006\u00102\u001a\u0002012\n\u00106\u001a\u00060&j\u0002`5H\u0002\u00a2\u0006\u0004\u00087\u00108J#\u00109\u001a\u00020\u000e2\u0006\u00102\u001a\u0002012\n\u00106\u001a\u00060&j\u0002`5H\u0002\u00a2\u0006\u0004\u00089\u00108J#\u0010:\u001a\u00020\u000e2\u0006\u00102\u001a\u0002012\n\u00106\u001a\u00060&j\u0002`5H\u0002\u00a2\u0006\u0004\u0008:\u00108J\u000f\u0010;\u001a\u00020\u000eH\u0002\u00a2\u0006\u0004\u0008;\u0010\u0010J\u000f\u0010<\u001a\u00020\u000eH\u0002\u00a2\u0006\u0004\u0008<\u0010\u0010J\u0018\u0010?\u001a\u00020\u000e2\u0006\u0010>\u001a\u00020=H\u0082@\u00a2\u0006\u0004\u0008?\u0010@J\u0017\u0010B\u001a\u00020\u000e2\u0006\u0010A\u001a\u000201H\u0002\u00a2\u0006\u0004\u0008B\u0010CR\u0017\u0010\u0005\u001a\u00020\u00048\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0005\u0010D\u001a\u0004\u0008E\u0010FR\u0017\u0010\u0007\u001a\u00020\u00068\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0007\u0010G\u001a\u0004\u0008H\u0010IR$\u0010\u001e\u001a\u0010\u0012\u0004\u0012\u00020\u0014\u0012\u0004\u0012\u00020\u0015\u0018\u00010\u00138\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008\u001e\u0010JR\u0018\u00106\u001a\u00060&j\u0002`58\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00086\u0010KR\u0016\u0010L\u001a\u00020\u000b8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008L\u0010MR\u0014\u0010O\u001a\u00020N8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008O\u0010PR\u0018\u0010Q\u001a\u0004\u0018\u00010)8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008Q\u0010RR\u001c\u0010U\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010T0S8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008U\u0010VR\u001d\u0010X\u001a\u0008\u0012\u0004\u0012\u00020T0W8\u0006\u00a2\u0006\u000c\n\u0004\u0008X\u0010Y\u001a\u0004\u0008Z\u0010[R$\u0010]\u001a\u0004\u0018\u00010\\8\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008]\u0010^\u001a\u0004\u0008_\u0010`\"\u0004\u0008a\u0010bR\u0014\u0010f\u001a\u00020c8\u0016X\u0096\u0005\u00a2\u0006\u0006\u001a\u0004\u0008d\u0010eR\u0014\u0010h\u001a\u00020\u000b8BX\u0082\u0004\u00a2\u0006\u0006\u001a\u0004\u0008g\u0010\r\u00a8\u0006k"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;",
        "Ljava/io/Closeable;",
        "Lvy0/b0;",
        "Ltechnology/cariad/cat/genx/InternalVehicle;",
        "vehicle",
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "genXDispatcher",
        "coroutineScope",
        "<init>",
        "(Ltechnology/cariad/cat/genx/InternalVehicle;Ltechnology/cariad/cat/genx/GenXDispatcher;Lvy0/b0;)V",
        "",
        "isConnected",
        "()Z",
        "Llx0/b0;",
        "connectKES",
        "()V",
        "Lvy0/h0;",
        "Llx0/o;",
        "Llx0/l;",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport;",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;",
        "connect",
        "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "sendKESCanceledMessageToVehicleAndCloseConnection",
        "Ltechnology/cariad/cat/genx/protocol/Message;",
        "message",
        "sendMessage-gIAlu-s$genx_release",
        "(Ltechnology/cariad/cat/genx/protocol/Message;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "sendMessage",
        "connection",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "error",
        "onConnectionDropped",
        "(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;Ltechnology/cariad/cat/genx/GenXError;)V",
        "onConnectionReceived",
        "(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;Ltechnology/cariad/cat/genx/protocol/Message;)V",
        "close",
        "",
        "toString",
        "()Ljava/lang/String;",
        "Lvy0/i1;",
        "setupConnectionJobWithRetry",
        "()Lvy0/i1;",
        "transport",
        "onKESConnected",
        "(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)V",
        "",
        "rawAddress",
        "",
        "data",
        "handleMessage",
        "(J[B)Z",
        "Ltechnology/cariad/cat/genx/VIN;",
        "vin",
        "handleStaticInfoResponse",
        "([BLjava/lang/String;)V",
        "handleOuterAntennaKeyExchangeResponse",
        "handleOuterAntennaKeyExchangeStatus",
        "sendStaticInformationRequest",
        "sendVehicleKeyInfoRequest",
        "Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;",
        "outerAntennaKeyExchangeStatus",
        "sendStatus",
        "(Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "qpm1",
        "sendQPM1",
        "([B)V",
        "Ltechnology/cariad/cat/genx/InternalVehicle;",
        "getVehicle",
        "()Ltechnology/cariad/cat/genx/InternalVehicle;",
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "getGenXDispatcher",
        "()Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "Llx0/l;",
        "Ljava/lang/String;",
        "isClosed",
        "Z",
        "Lez0/a;",
        "isConnectingMutex",
        "Lez0/a;",
        "connectionJob",
        "Lvy0/i1;",
        "Lyy0/j1;",
        "Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result;",
        "_result",
        "Lyy0/j1;",
        "Lyy0/i;",
        "result",
        "Lyy0/i;",
        "getResult",
        "()Lyy0/i;",
        "Ltechnology/cariad/cat/genx/KeyExchangeInformation;",
        "keyExchangeInformation",
        "Ltechnology/cariad/cat/genx/KeyExchangeInformation;",
        "getKeyExchangeInformation",
        "()Ltechnology/cariad/cat/genx/KeyExchangeInformation;",
        "setKeyExchangeInformation",
        "(Ltechnology/cariad/cat/genx/KeyExchangeInformation;)V",
        "Lpx0/g;",
        "getCoroutineContext",
        "()Lpx0/g;",
        "coroutineContext",
        "getKesCompleted",
        "kesCompleted",
        "Companion",
        "Result",
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


# static fields
.field private static final ADDRESSES:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ltechnology/cariad/cat/genx/protocol/Address;",
            ">;"
        }
    .end annotation
.end field

.field public static final Companion:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Companion;

.field private static final GLOBAL_SERVICE_ID:Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

.field private static final OUTER_ANTENNA_KEY_EXCHANGE_QPM1:Ltechnology/cariad/cat/genx/protocol/Address;

.field private static final OUTER_ANTENNA_KEY_EXCHANGE_STATUS_RECEIVED:Ltechnology/cariad/cat/genx/protocol/Address;

.field private static final OUTER_ANTENNA_KEY_EXCHANGE_STATUS_SEND:Ltechnology/cariad/cat/genx/protocol/Address;

.field private static final OUTER_ANTENNA_VEHICLE_KEYS_INFO_REQUEST:Ltechnology/cariad/cat/genx/protocol/Address;

.field private static final OUTER_ANTENNA_VEHICLE_KEYS_INFO_RESPONSE:Ltechnology/cariad/cat/genx/protocol/Address;

.field private static final STATIC_INFO_REQUEST:Ltechnology/cariad/cat/genx/protocol/Address;

.field private static final STATIC_INFO_RESPONSE:Ltechnology/cariad/cat/genx/protocol/Address;


# instance fields
.field private final synthetic $$delegate_0:Lvy0/b0;

.field private final _result:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private connection:Llx0/l;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llx0/l;"
        }
    .end annotation
.end field

.field private connectionJob:Lvy0/i1;

.field private final genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

.field private isClosed:Z

.field private final isConnectingMutex:Lez0/a;

.field private keyExchangeInformation:Ltechnology/cariad/cat/genx/KeyExchangeInformation;

.field private final result:Lyy0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/i;"
        }
    .end annotation
.end field

.field private final vehicle:Ltechnology/cariad/cat/genx/InternalVehicle;

.field private final vin:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 12

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->Companion:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Companion;

    .line 8
    .line 9
    new-instance v0, Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 10
    .line 11
    const/16 v2, 0x45

    .line 12
    .line 13
    const/16 v3, 0x53

    .line 14
    .line 15
    const/16 v4, 0x4b

    .line 16
    .line 17
    invoke-direct {v0, v4, v2, v3, v1}, Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;-><init>(BBBLkotlin/jvm/internal/g;)V

    .line 18
    .line 19
    .line 20
    sput-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->GLOBAL_SERVICE_ID:Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 21
    .line 22
    new-instance v5, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 23
    .line 24
    sget-object v2, Ltechnology/cariad/cat/genx/protocol/AddressDirection$PhoneToVehicle;->INSTANCE:Ltechnology/cariad/cat/genx/protocol/AddressDirection$PhoneToVehicle;

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    invoke-direct {v5, v0, v3, v2, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 28
    .line 29
    .line 30
    sput-object v5, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->STATIC_INFO_REQUEST:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 31
    .line 32
    new-instance v6, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 33
    .line 34
    const/4 v4, 0x1

    .line 35
    invoke-direct {v6, v0, v4, v2, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 36
    .line 37
    .line 38
    sput-object v6, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->OUTER_ANTENNA_VEHICLE_KEYS_INFO_REQUEST:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 39
    .line 40
    new-instance v7, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 41
    .line 42
    const/4 v8, 0x2

    .line 43
    invoke-direct {v7, v0, v8, v2, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 44
    .line 45
    .line 46
    sput-object v7, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->OUTER_ANTENNA_KEY_EXCHANGE_STATUS_SEND:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 47
    .line 48
    move v9, v8

    .line 49
    new-instance v8, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 50
    .line 51
    const/4 v10, 0x3

    .line 52
    invoke-direct {v8, v0, v10, v2, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 53
    .line 54
    .line 55
    sput-object v8, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->OUTER_ANTENNA_KEY_EXCHANGE_QPM1:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 56
    .line 57
    move v2, v9

    .line 58
    new-instance v9, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 59
    .line 60
    sget-object v10, Ltechnology/cariad/cat/genx/protocol/AddressDirection$VehicleToPhone;->INSTANCE:Ltechnology/cariad/cat/genx/protocol/AddressDirection$VehicleToPhone;

    .line 61
    .line 62
    invoke-direct {v9, v0, v3, v10, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 63
    .line 64
    .line 65
    sput-object v9, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->STATIC_INFO_RESPONSE:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 66
    .line 67
    move-object v3, v10

    .line 68
    new-instance v10, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 69
    .line 70
    invoke-direct {v10, v0, v4, v3, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 71
    .line 72
    .line 73
    sput-object v10, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->OUTER_ANTENNA_VEHICLE_KEYS_INFO_RESPONSE:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 74
    .line 75
    new-instance v11, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 76
    .line 77
    invoke-direct {v11, v0, v2, v3, v1}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 78
    .line 79
    .line 80
    sput-object v11, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->OUTER_ANTENNA_KEY_EXCHANGE_STATUS_RECEIVED:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 81
    .line 82
    filled-new-array/range {v5 .. v11}, [Ltechnology/cariad/cat/genx/protocol/Address;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    sput-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->ADDRESSES:Ljava/util/Set;

    .line 91
    .line 92
    return-void
.end method

.method public constructor <init>(Ltechnology/cariad/cat/genx/InternalVehicle;Ltechnology/cariad/cat/genx/GenXDispatcher;Lvy0/b0;)V
    .locals 1

    .line 1
    const-string v0, "vehicle"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "genXDispatcher"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "coroutineScope"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p3, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->$$delegate_0:Lvy0/b0;

    .line 20
    .line 21
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vehicle:Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 22
    .line 23
    iput-object p2, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 24
    .line 25
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/Vehicle;->getVin()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vin:Ljava/lang/String;

    .line 30
    .line 31
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->isConnectingMutex:Lez0/a;

    .line 36
    .line 37
    const/4 p1, 0x0

    .line 38
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->_result:Lyy0/j1;

    .line 43
    .line 44
    new-instance p2, Lrz/k;

    .line 45
    .line 46
    const/16 p3, 0x15

    .line 47
    .line 48
    invoke-direct {p2, p1, p3}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 49
    .line 50
    .line 51
    iput-object p2, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->result:Lyy0/i;

    .line 52
    .line 53
    return-void
.end method

.method public static synthetic A0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connect$lambda$2$1(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic B()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connect$lambda$2$3$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic B0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connectKES$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic C0(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->onKESConnected$lambda$0(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic D0(Z)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->sendStaticInformationRequest$lambda$1(Z)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic E(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->onConnectionDropped$lambda$0(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic E0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connect$lambda$2$0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic F0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->onKESConnected$lambda$1(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic G0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleStaticInfoResponse$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic H(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connect$lambda$0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic H0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->sendKESCanceledMessageToVehicleAndCloseConnection$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic I0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->close$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic J0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleMessage$lambda$1(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic K0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connectKES$lambda$3()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic T()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connectKES$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic U(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->sendVehicleKeyInfoRequest$lambda$0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic V(Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->sendStatus$lambda$1$0(Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic W([BLtechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->sendQPM1$lambda$0([BLtechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic a(Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleOuterAntennaKeyExchangeResponse$lambda$1(Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final synthetic access$getADDRESSES$cp()Ljava/util/Set;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->ADDRESSES:Ljava/util/Set;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getConnection$p(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Llx0/l;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connection:Llx0/l;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getGLOBAL_SERVICE_ID$cp()Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->GLOBAL_SERVICE_ID:Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOUTER_ANTENNA_KEY_EXCHANGE_QPM1$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->OUTER_ANTENNA_KEY_EXCHANGE_QPM1:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOUTER_ANTENNA_KEY_EXCHANGE_STATUS_RECEIVED$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->OUTER_ANTENNA_KEY_EXCHANGE_STATUS_RECEIVED:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOUTER_ANTENNA_KEY_EXCHANGE_STATUS_SEND$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->OUTER_ANTENNA_KEY_EXCHANGE_STATUS_SEND:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOUTER_ANTENNA_VEHICLE_KEYS_INFO_REQUEST$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->OUTER_ANTENNA_VEHICLE_KEYS_INFO_REQUEST:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getOUTER_ANTENNA_VEHICLE_KEYS_INFO_RESPONSE$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->OUTER_ANTENNA_VEHICLE_KEYS_INFO_RESPONSE:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSTATIC_INFO_REQUEST$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->STATIC_INFO_REQUEST:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSTATIC_INFO_RESPONSE$cp()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->STATIC_INFO_RESPONSE:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getVin$p(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vin:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$get_result$p(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Lyy0/j1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->_result:Lyy0/j1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$isConnectingMutex$p(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Lez0/a;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->isConnectingMutex:Lez0/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$onKESConnected(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->onKESConnected(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static final synthetic access$sendQPM1(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;[B)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->sendQPM1([B)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static final synthetic access$sendStaticInformationRequest(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->sendStaticInformationRequest()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static final synthetic access$sendStatus(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->sendStatus(Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final synthetic access$setConnection$p(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Llx0/l;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connection:Llx0/l;

    .line 2
    .line 3
    return-void
.end method

.method public static final synthetic access$setConnectionJob$p(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Lvy0/i1;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connectionJob:Lvy0/i1;

    .line 2
    .line 3
    return-void
.end method

.method public static synthetic b(Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connect$lambda$3$0(Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final close$lambda$0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vin:Ljava/lang/String;

    .line 2
    .line 3
    const-string v0, "close(): "

    .line 4
    .line 5
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static final close$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "close(): Key exchange service was not completed yet"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final connect$lambda$0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 4

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vehicle:Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 2
    .line 3
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/InternalVehicle;->getInnerAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    sget-object v0, Ltechnology/cariad/cat/genx/Car2PhoneMode;->Companion:Ltechnology/cariad/cat/genx/Car2PhoneMode$Companion;

    .line 8
    .line 9
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/Car2PhoneMode$Companion;->getPairingActive()Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    sget-object v1, Ltechnology/cariad/cat/genx/TransportType;->BLE:Ltechnology/cariad/cat/genx/TransportType;

    .line 14
    .line 15
    new-instance v2, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    const-string v3, "connect(): Waiting for vehicle "

    .line 18
    .line 19
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string p0, " to not longer be in mode "

    .line 26
    .line 27
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string p0, " and to be reachable via "

    .line 34
    .line 35
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    return-object p0
.end method

.method private static final connect$lambda$2$0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Ljava/lang/String;
    .locals 3

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/TransportType;->BLE:Ltechnology/cariad/cat/genx/TransportType;

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vehicle:Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 4
    .line 5
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/InternalVehicle;->getInnerAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    new-instance v1, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v2, "connect(): "

    .line 12
    .line 13
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v0, " is now available on "

    .line 20
    .line 21
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string p0, ", observe transportState and car2Phone of "

    .line 28
    .line 29
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method

.method private static final connect$lambda$2$1(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "connect(): transport is ready, connect "

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
    const-string p0, " on "

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

.method private static final connect$lambda$2$2$0(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "connect(): Attempt succeeded: "

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

.method private static final connect$lambda$2$3$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "connect(): Attempt failed"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final connect$lambda$3$0(Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "connect(): Failed to retrieve BLE-Transport from "

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

.method private static final connectKES$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "connectKES()"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final connectKES$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "connectKES(): Connection establishment already in progress"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final connectKES$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "connectKES(): Connection already existing"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final connectKES$lambda$3()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "connectKES(): KES already completed"

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic d(Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleStaticInfoResponse$lambda$1(Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic e0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleOuterAntennaKeyExchangeStatus$lambda$3$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic f(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->sendStaticInformationRequest$lambda$0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->close$lambda$0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final getKesCompleted()Z
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->_result:Lyy0/j1;

    .line 2
    .line 3
    check-cast p0, Lyy0/c2;

    .line 4
    .line 5
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public static synthetic h()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connectKES$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic h0(Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->sendStatus$lambda$0(Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final handleMessage(J[B)Z
    .locals 10

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->STATIC_INFO_REQUEST:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    cmp-long v0, p1, v0

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    if-eqz v0, :cond_4

    .line 11
    .line 12
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->OUTER_ANTENNA_VEHICLE_KEYS_INFO_REQUEST:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 13
    .line 14
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 15
    .line 16
    .line 17
    move-result-wide v2

    .line 18
    cmp-long v0, p1, v2

    .line 19
    .line 20
    if-eqz v0, :cond_4

    .line 21
    .line 22
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->OUTER_ANTENNA_KEY_EXCHANGE_QPM1:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 23
    .line 24
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 25
    .line 26
    .line 27
    move-result-wide v2

    .line 28
    cmp-long v0, p1, v2

    .line 29
    .line 30
    if-eqz v0, :cond_4

    .line 31
    .line 32
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->OUTER_ANTENNA_KEY_EXCHANGE_STATUS_SEND:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 33
    .line 34
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 35
    .line 36
    .line 37
    move-result-wide v2

    .line 38
    cmp-long v0, p1, v2

    .line 39
    .line 40
    if-nez v0, :cond_0

    .line 41
    .line 42
    goto/16 :goto_0

    .line 43
    .line 44
    :cond_0
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->STATIC_INFO_RESPONSE:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 45
    .line 46
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 47
    .line 48
    .line 49
    move-result-wide v2

    .line 50
    cmp-long v0, p1, v2

    .line 51
    .line 52
    const-string v2, "getName(...)"

    .line 53
    .line 54
    sget-object v5, Lt51/d;->a:Lt51/d;

    .line 55
    .line 56
    if-nez v0, :cond_1

    .line 57
    .line 58
    new-instance v6, Ltechnology/cariad/cat/genx/services/kes/g;

    .line 59
    .line 60
    const/16 p1, 0xd

    .line 61
    .line 62
    invoke-direct {v6, p0, p1}, Ltechnology/cariad/cat/genx/services/kes/g;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;I)V

    .line 63
    .line 64
    .line 65
    new-instance v3, Lt51/j;

    .line 66
    .line 67
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v8

    .line 71
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v9

    .line 75
    const-string v4, "GenX"

    .line 76
    .line 77
    const/4 v7, 0x0

    .line 78
    invoke-direct/range {v3 .. v9}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-static {v3}, Lt51/a;->a(Lt51/j;)V

    .line 82
    .line 83
    .line 84
    iget-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vin:Ljava/lang/String;

    .line 85
    .line 86
    invoke-direct {p0, p3, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleStaticInfoResponse([BLjava/lang/String;)V

    .line 87
    .line 88
    .line 89
    return v1

    .line 90
    :cond_1
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->OUTER_ANTENNA_VEHICLE_KEYS_INFO_RESPONSE:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 91
    .line 92
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 93
    .line 94
    .line 95
    move-result-wide v3

    .line 96
    cmp-long v0, p1, v3

    .line 97
    .line 98
    if-nez v0, :cond_2

    .line 99
    .line 100
    new-instance v6, Ltechnology/cariad/cat/genx/services/kes/g;

    .line 101
    .line 102
    const/16 p1, 0xe

    .line 103
    .line 104
    invoke-direct {v6, p0, p1}, Ltechnology/cariad/cat/genx/services/kes/g;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;I)V

    .line 105
    .line 106
    .line 107
    new-instance v3, Lt51/j;

    .line 108
    .line 109
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object v8

    .line 113
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v9

    .line 117
    const-string v4, "GenX"

    .line 118
    .line 119
    const/4 v7, 0x0

    .line 120
    invoke-direct/range {v3 .. v9}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    invoke-static {v3}, Lt51/a;->a(Lt51/j;)V

    .line 124
    .line 125
    .line 126
    iget-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vin:Ljava/lang/String;

    .line 127
    .line 128
    invoke-direct {p0, p3, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleOuterAntennaKeyExchangeResponse([BLjava/lang/String;)V

    .line 129
    .line 130
    .line 131
    return v1

    .line 132
    :cond_2
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->OUTER_ANTENNA_KEY_EXCHANGE_STATUS_RECEIVED:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 133
    .line 134
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 135
    .line 136
    .line 137
    move-result-wide v3

    .line 138
    cmp-long p1, p1, v3

    .line 139
    .line 140
    if-nez p1, :cond_3

    .line 141
    .line 142
    new-instance v6, Ltechnology/cariad/cat/genx/services/kes/g;

    .line 143
    .line 144
    const/16 p1, 0xf

    .line 145
    .line 146
    invoke-direct {v6, p0, p1}, Ltechnology/cariad/cat/genx/services/kes/g;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;I)V

    .line 147
    .line 148
    .line 149
    new-instance v3, Lt51/j;

    .line 150
    .line 151
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object v8

    .line 155
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v9

    .line 159
    const-string v4, "GenX"

    .line 160
    .line 161
    const/4 v7, 0x0

    .line 162
    invoke-direct/range {v3 .. v9}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    invoke-static {v3}, Lt51/a;->a(Lt51/j;)V

    .line 166
    .line 167
    .line 168
    iget-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vin:Ljava/lang/String;

    .line 169
    .line 170
    invoke-direct {p0, p3, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleOuterAntennaKeyExchangeStatus([BLjava/lang/String;)V

    .line 171
    .line 172
    .line 173
    return v1

    .line 174
    :cond_3
    const/4 p0, 0x0

    .line 175
    return p0

    .line 176
    :cond_4
    :goto_0
    new-instance p3, Lh2/u2;

    .line 177
    .line 178
    const/4 v0, 0x4

    .line 179
    invoke-direct {p3, p1, p2, p0, v0}, Lh2/u2;-><init>(JLjava/lang/Object;I)V

    .line 180
    .line 181
    .line 182
    const/4 p1, 0x0

    .line 183
    const-string p2, "GenX"

    .line 184
    .line 185
    invoke-static {p0, p2, p1, p3}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 186
    .line 187
    .line 188
    return v1
.end method

.method private static final handleMessage$lambda$0(JLtechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/protocol/AddressKt;->toHexString(J)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p1, p2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vin:Ljava/lang/String;

    .line 6
    .line 7
    const-string p2, "handleMessage(): Message should not be handled by the client, address = "

    .line 8
    .line 9
    const-string v0, " - "

    .line 10
    .line 11
    invoke-static {p2, p0, v0, p1}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final handleMessage$lambda$1(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vin:Ljava/lang/String;

    .line 2
    .line 3
    const-string v0, "handleMessage(): Received \'staticInfoResponse\' - "

    .line 4
    .line 5
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static final handleMessage$lambda$2(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vin:Ljava/lang/String;

    .line 2
    .line 3
    const-string v0, "handleMessage(): Received \'outerAntennaVehicleKeysInfoResponse\' - "

    .line 4
    .line 5
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static final handleMessage$lambda$3(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vin:Ljava/lang/String;

    .line 2
    .line 3
    const-string v0, "handleMessage(): Received \'outerAntennaVehicleKeysInfoResponse\' - "

    .line 4
    .line 5
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private final handleOuterAntennaKeyExchangeResponse([BLjava/lang/String;)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    sget-object v1, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;->Companion:Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse$Companion;

    .line 6
    .line 7
    move-object/from16 v2, p1

    .line 8
    .line 9
    invoke-virtual {v1, v2}, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse$Companion;->fromBytes([B)Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;

    .line 10
    .line 11
    .line 12
    move-result-object v11

    .line 13
    const-string v1, "getName(...)"

    .line 14
    .line 15
    if-nez v11, :cond_0

    .line 16
    .line 17
    new-instance v5, Ltechnology/cariad/cat/genx/services/kes/a;

    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    invoke-direct {v5, v3, v2}, Ltechnology/cariad/cat/genx/services/kes/a;-><init>(Ljava/lang/String;I)V

    .line 21
    .line 22
    .line 23
    new-instance v2, Lt51/j;

    .line 24
    .line 25
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v7

    .line 29
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v8

    .line 33
    const-string v3, "GenX"

    .line 34
    .line 35
    sget-object v4, Lt51/e;->a:Lt51/e;

    .line 36
    .line 37
    const/4 v6, 0x0

    .line 38
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :cond_0
    new-instance v7, Ltechnology/cariad/cat/genx/services/kes/d;

    .line 46
    .line 47
    const/4 v2, 0x5

    .line 48
    invoke-direct {v7, v2, v11, v3}, Ltechnology/cariad/cat/genx/services/kes/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    new-instance v4, Lt51/j;

    .line 52
    .line 53
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v9

    .line 57
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v10

    .line 61
    const-string v5, "GenX"

    .line 62
    .line 63
    sget-object v14, Lt51/g;->a:Lt51/g;

    .line 64
    .line 65
    const/4 v8, 0x0

    .line 66
    move-object v6, v14

    .line 67
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 71
    .line 72
    .line 73
    iget-object v2, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vehicle:Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 74
    .line 75
    invoke-interface {v2}, Ltechnology/cariad/cat/genx/InternalVehicle;->getInnerAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    if-eqz v2, :cond_1

    .line 80
    .line 81
    invoke-interface {v2}, Ltechnology/cariad/cat/genx/VehicleAntenna;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    if-eqz v2, :cond_1

    .line 86
    .line 87
    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/VehicleAntenna$Information;->getLocalKeyPair()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 88
    .line 89
    .line 90
    move-result-object v2

    .line 91
    if-nez v2, :cond_2

    .line 92
    .line 93
    :cond_1
    sget-object v2, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;->Companion:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;

    .line 94
    .line 95
    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;->invoke()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 96
    .line 97
    .line 98
    move-result-object v2

    .line 99
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    new-instance v15, Ltechnology/cariad/cat/genx/services/kes/a;

    .line 103
    .line 104
    const/4 v4, 0x2

    .line 105
    invoke-direct {v15, v3, v4}, Ltechnology/cariad/cat/genx/services/kes/a;-><init>(Ljava/lang/String;I)V

    .line 106
    .line 107
    .line 108
    new-instance v12, Lt51/j;

    .line 109
    .line 110
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v17

    .line 114
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v18

    .line 118
    const-string v13, "GenX"

    .line 119
    .line 120
    const/16 v16, 0x0

    .line 121
    .line 122
    invoke-direct/range {v12 .. v18}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    invoke-static {v12}, Lt51/a;->a(Lt51/j;)V

    .line 126
    .line 127
    .line 128
    :cond_2
    new-instance v1, Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;

    .line 129
    .line 130
    new-instance v4, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 131
    .line 132
    sget-object v5, Ltechnology/cariad/cat/genx/Antenna;->OUTER:Ltechnology/cariad/cat/genx/Antenna;

    .line 133
    .line 134
    invoke-direct {v4, v3, v5}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;-><init>(Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;)V

    .line 135
    .line 136
    .line 137
    invoke-virtual {v11}, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;->getOuterAntennaPublicKey()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;

    .line 138
    .line 139
    .line 140
    move-result-object v5

    .line 141
    invoke-virtual {v11}, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;->getOuterAntennaLAMSecret()[B

    .line 142
    .line 143
    .line 144
    move-result-object v6

    .line 145
    invoke-virtual {v11}, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;->getOuterAntennaAdvertisementSecret()[B

    .line 146
    .line 147
    .line 148
    move-result-object v7

    .line 149
    invoke-virtual {v11}, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;->getBeaconMajor-Mh2AYeg()S

    .line 150
    .line 151
    .line 152
    move-result v8

    .line 153
    invoke-virtual {v11}, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;->getBeaconMinor-Mh2AYeg()S

    .line 154
    .line 155
    .line 156
    move-result v9

    .line 157
    const/4 v10, 0x0

    .line 158
    invoke-direct/range {v1 .. v10}, Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;-><init>(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ljava/lang/String;Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;[B[BSSLkotlin/jvm/internal/g;)V

    .line 159
    .line 160
    .line 161
    iput-object v1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->keyExchangeInformation:Ltechnology/cariad/cat/genx/KeyExchangeInformation;

    .line 162
    .line 163
    invoke-virtual {v11}, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;->isQPM1Expected()Z

    .line 164
    .line 165
    .line 166
    move-result v1

    .line 167
    if-eqz v1, :cond_3

    .line 168
    .line 169
    new-instance v1, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;

    .line 170
    .line 171
    const/4 v2, 0x0

    .line 172
    invoke-direct {v1, v0, v11, v2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$handleOuterAntennaKeyExchangeResponse$3;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;Lkotlin/coroutines/Continuation;)V

    .line 173
    .line 174
    .line 175
    const/4 v3, 0x3

    .line 176
    invoke-static {v0, v2, v2, v1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 177
    .line 178
    .line 179
    :cond_3
    return-void
.end method

.method private static final handleOuterAntennaKeyExchangeResponse$lambda$0(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "handleOuterAntennaKeyExchangeResponse(): Failed to parse \'VehicleKeyInfoResponse\' - "

    .line 2
    .line 3
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method private static final handleOuterAntennaKeyExchangeResponse$lambda$1(Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoResponse;Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "handleOuterAntennaKeyExchangeResponse(): Received response = "

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
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

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

.method private static final handleOuterAntennaKeyExchangeResponse$lambda$2$0(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "Created new EdDSASigningKeyPair for the outer antenna of "

    .line 2
    .line 3
    const-string v1, ", because EdDSASigningKeyPair of inner antenna was not found"

    .line 4
    .line 5
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private final handleOuterAntennaKeyExchangeStatus([BLjava/lang/String;)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    sget-object v2, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->Companion:Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus$Companion;

    .line 6
    .line 7
    move-object/from16 v3, p1

    .line 8
    .line 9
    invoke-virtual {v2, v3}, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus$Companion;->fromBytes([B)Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    new-instance v6, Ltechnology/cariad/cat/genx/services/kes/d;

    .line 14
    .line 15
    const/4 v3, 0x2

    .line 16
    invoke-direct {v6, v3, v2, v1}, Ltechnology/cariad/cat/genx/services/kes/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    new-instance v3, Lt51/j;

    .line 20
    .line 21
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v8

    .line 25
    const-string v10, "getName(...)"

    .line 26
    .line 27
    invoke-static {v10}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v9

    .line 31
    const-string v4, "GenX"

    .line 32
    .line 33
    sget-object v13, Lt51/g;->a:Lt51/g;

    .line 34
    .line 35
    const/4 v7, 0x0

    .line 36
    move-object v5, v13

    .line 37
    invoke-direct/range {v3 .. v9}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    invoke-static {v3}, Lt51/a;->a(Lt51/j;)V

    .line 41
    .line 42
    .line 43
    const/4 v3, -0x1

    .line 44
    if-nez v2, :cond_0

    .line 45
    .line 46
    move v2, v3

    .line 47
    goto :goto_0

    .line 48
    :cond_0
    sget-object v4, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$WhenMappings;->$EnumSwitchMapping$0:[I

    .line 49
    .line 50
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 51
    .line 52
    .line 53
    move-result v2

    .line 54
    aget v2, v4, v2

    .line 55
    .line 56
    :goto_0
    if-eq v2, v3, :cond_5

    .line 57
    .line 58
    const/4 v1, 0x1

    .line 59
    const/4 v3, 0x0

    .line 60
    if-eq v2, v1, :cond_4

    .line 61
    .line 62
    const/4 v1, 0x2

    .line 63
    if-eq v2, v1, :cond_2

    .line 64
    .line 65
    const/4 v1, 0x3

    .line 66
    if-ne v2, v1, :cond_1

    .line 67
    .line 68
    iput-object v3, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->keyExchangeInformation:Ltechnology/cariad/cat/genx/KeyExchangeInformation;

    .line 69
    .line 70
    iget-object v0, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->_result:Lyy0/j1;

    .line 71
    .line 72
    sget-object v1, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeCanceled;->INSTANCE:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeCanceled;

    .line 73
    .line 74
    check-cast v0, Lyy0/c2;

    .line 75
    .line 76
    invoke-virtual {v0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    return-void

    .line 80
    :cond_1
    new-instance v0, La8/r0;

    .line 81
    .line 82
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 83
    .line 84
    .line 85
    throw v0

    .line 86
    :cond_2
    iget-object v1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->keyExchangeInformation:Ltechnology/cariad/cat/genx/KeyExchangeInformation;

    .line 87
    .line 88
    if-eqz v1, :cond_3

    .line 89
    .line 90
    new-instance v14, Ltechnology/cariad/cat/genx/services/kes/e;

    .line 91
    .line 92
    const/4 v2, 0x2

    .line 93
    invoke-direct {v14, v1, v2}, Ltechnology/cariad/cat/genx/services/kes/e;-><init>(Ljava/lang/Object;I)V

    .line 94
    .line 95
    .line 96
    new-instance v11, Lt51/j;

    .line 97
    .line 98
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object v16

    .line 102
    invoke-static {v10}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object v17

    .line 106
    const-string v12, "GenX"

    .line 107
    .line 108
    const/4 v15, 0x0

    .line 109
    invoke-direct/range {v11 .. v17}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    invoke-static {v11}, Lt51/a;->a(Lt51/j;)V

    .line 113
    .line 114
    .line 115
    iput-object v3, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->keyExchangeInformation:Ltechnology/cariad/cat/genx/KeyExchangeInformation;

    .line 116
    .line 117
    iget-object v0, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->_result:Lyy0/j1;

    .line 118
    .line 119
    new-instance v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeSucceeded;

    .line 120
    .line 121
    invoke-direct {v2, v1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeSucceeded;-><init>(Ltechnology/cariad/cat/genx/KeyExchangeInformation;)V

    .line 122
    .line 123
    .line 124
    check-cast v0, Lyy0/c2;

    .line 125
    .line 126
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 127
    .line 128
    .line 129
    invoke-virtual {v0, v3, v2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    :cond_3
    return-void

    .line 133
    :cond_4
    iput-object v3, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->keyExchangeInformation:Ltechnology/cariad/cat/genx/KeyExchangeInformation;

    .line 134
    .line 135
    iget-object v0, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->_result:Lyy0/j1;

    .line 136
    .line 137
    new-instance v1, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeFailed;

    .line 138
    .line 139
    sget-object v2, Ltechnology/cariad/cat/genx/GenXError$KeyExchangeCanceledByVehicle;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$KeyExchangeCanceledByVehicle;

    .line 140
    .line 141
    invoke-direct {v1, v2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeFailed;-><init>(Ltechnology/cariad/cat/genx/GenXError;)V

    .line 142
    .line 143
    .line 144
    check-cast v0, Lyy0/c2;

    .line 145
    .line 146
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 147
    .line 148
    .line 149
    invoke-virtual {v0, v3, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    return-void

    .line 153
    :cond_5
    new-instance v7, Ltechnology/cariad/cat/genx/services/kes/a;

    .line 154
    .line 155
    const/4 v2, 0x0

    .line 156
    invoke-direct {v7, v1, v2}, Ltechnology/cariad/cat/genx/services/kes/a;-><init>(Ljava/lang/String;I)V

    .line 157
    .line 158
    .line 159
    new-instance v4, Lt51/j;

    .line 160
    .line 161
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object v9

    .line 165
    invoke-static {v10}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object v10

    .line 169
    const-string v5, "GenX"

    .line 170
    .line 171
    sget-object v6, Lt51/e;->a:Lt51/e;

    .line 172
    .line 173
    const/4 v8, 0x0

    .line 174
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 178
    .line 179
    .line 180
    return-void
.end method

.method private static final handleOuterAntennaKeyExchangeStatus$lambda$0(Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "handleOuterAntennaKeyExchangeStatus(): Received response = "

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
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

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

.method private static final handleOuterAntennaKeyExchangeStatus$lambda$1(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "handleOuterAntennaKeyExchangeStatus(): Failed to parse \'QRCodePairingStatus\' - "

    .line 2
    .line 3
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method private static final handleOuterAntennaKeyExchangeStatus$lambda$2$0(Ltechnology/cariad/cat/genx/KeyExchangeInformation;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeSucceeded;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeSucceeded;-><init>(Ltechnology/cariad/cat/genx/KeyExchangeInformation;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/lang/StringBuilder;

    .line 7
    .line 8
    const-string v1, "handleOuterAntennaKeyExchangeStatus(): Set KeyExchangeResult to "

    .line 9
    .line 10
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method private static final handleOuterAntennaKeyExchangeStatus$lambda$3(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Llx0/b0;
    .locals 3

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/f;

    .line 2
    .line 3
    const/16 v1, 0xe

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/services/kes/f;-><init>(I)V

    .line 6
    .line 7
    .line 8
    const-string v1, "GenX"

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    invoke-static {p0, v1, v2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->_result:Lyy0/j1;

    .line 15
    .line 16
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeFailed;

    .line 17
    .line 18
    sget-object v1, Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;

    .line 19
    .line 20
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeFailed;-><init>(Ltechnology/cariad/cat/genx/GenXError;)V

    .line 21
    .line 22
    .line 23
    check-cast p0, Lyy0/c2;

    .line 24
    .line 25
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, v2, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0
.end method

.method private static final handleOuterAntennaKeyExchangeStatus$lambda$3$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "handleOuterAntennaKeyExchangeStatus(): No KeyExchangeInformation for outer antenna present"

    .line 2
    .line 3
    return-object v0
.end method

.method private final handleStaticInfoResponse([BLjava/lang/String;)V
    .locals 9

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->Companion:Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse$Companion;->fromBytes([B)Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const-string v0, "getName(...)"

    .line 8
    .line 9
    if-nez p1, :cond_0

    .line 10
    .line 11
    new-instance v4, Ltechnology/cariad/cat/genx/services/kes/a;

    .line 12
    .line 13
    const/4 p1, 0x3

    .line 14
    invoke-direct {v4, p2, p1}, Ltechnology/cariad/cat/genx/services/kes/a;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    new-instance v1, Lt51/j;

    .line 18
    .line 19
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v6

    .line 23
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v7

    .line 27
    const-string v2, "GenX"

    .line 28
    .line 29
    sget-object v3, Lt51/e;->a:Lt51/e;

    .line 30
    .line 31
    const/4 v5, 0x0

    .line 32
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_0
    new-instance v5, Ltechnology/cariad/cat/genx/services/kes/d;

    .line 40
    .line 41
    const/4 v1, 0x1

    .line 42
    invoke-direct {v5, v1, p1, p2}, Ltechnology/cariad/cat/genx/services/kes/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    new-instance v2, Lt51/j;

    .line 46
    .line 47
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v7

    .line 51
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v8

    .line 55
    const-string v3, "GenX"

    .line 56
    .line 57
    sget-object v4, Lt51/g;->a:Lt51/g;

    .line 58
    .line 59
    const/4 v6, 0x0

    .line 60
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->getAreOuterAntennaKeysRequired()Z

    .line 67
    .line 68
    .line 69
    move-result p2

    .line 70
    sget-object v3, Lt51/f;->a:Lt51/f;

    .line 71
    .line 72
    if-nez p2, :cond_1

    .line 73
    .line 74
    new-instance v4, Ltechnology/cariad/cat/genx/services/kes/f;

    .line 75
    .line 76
    const/4 p1, 0x7

    .line 77
    invoke-direct {v4, p1}, Ltechnology/cariad/cat/genx/services/kes/f;-><init>(I)V

    .line 78
    .line 79
    .line 80
    new-instance v1, Lt51/j;

    .line 81
    .line 82
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v6

    .line 86
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v7

    .line 90
    const-string v2, "GenX"

    .line 91
    .line 92
    const/4 v5, 0x0

    .line 93
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 97
    .line 98
    .line 99
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->_result:Lyy0/j1;

    .line 100
    .line 101
    sget-object p1, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$NoOuterPairingRequired;->INSTANCE:Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$NoOuterPairingRequired;

    .line 102
    .line 103
    check-cast p0, Lyy0/c2;

    .line 104
    .line 105
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    return-void

    .line 109
    :cond_1
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;->getAreOuterAntennaKeysRequired()Z

    .line 110
    .line 111
    .line 112
    move-result p1

    .line 113
    if-eqz p1, :cond_2

    .line 114
    .line 115
    iget-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vehicle:Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 116
    .line 117
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/InternalVehicle;->getOuterAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Outer;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    if-eqz p1, :cond_2

    .line 122
    .line 123
    new-instance p1, Ltechnology/cariad/cat/genx/services/kes/g;

    .line 124
    .line 125
    const/16 p2, 0x9

    .line 126
    .line 127
    invoke-direct {p1, p0, p2}, Ltechnology/cariad/cat/genx/services/kes/g;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;I)V

    .line 128
    .line 129
    .line 130
    const/4 p2, 0x0

    .line 131
    const-string v0, "GenX"

    .line 132
    .line 133
    invoke-static {p0, v0, p2, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 134
    .line 135
    .line 136
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->sendVehicleKeyInfoRequest()V

    .line 137
    .line 138
    .line 139
    return-void

    .line 140
    :cond_2
    new-instance v4, Ltechnology/cariad/cat/genx/services/kes/f;

    .line 141
    .line 142
    const/16 p1, 0x8

    .line 143
    .line 144
    invoke-direct {v4, p1}, Ltechnology/cariad/cat/genx/services/kes/f;-><init>(I)V

    .line 145
    .line 146
    .line 147
    new-instance v1, Lt51/j;

    .line 148
    .line 149
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v6

    .line 153
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v7

    .line 157
    const-string v2, "GenX"

    .line 158
    .line 159
    const/4 v5, 0x0

    .line 160
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 164
    .line 165
    .line 166
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->sendVehicleKeyInfoRequest()V

    .line 167
    .line 168
    .line 169
    return-void
.end method

.method private static final handleStaticInfoResponse$lambda$0(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "handleStaticInfoResponse(): Failed to parse \'StaticInformationResponse\' - "

    .line 2
    .line 3
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method private static final handleStaticInfoResponse$lambda$1(Ltechnology/cariad/cat/genx/services/kes/StaticInformationResponse;Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "handleStaticInfoResponse(): Received response = "

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
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

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

.method private static final handleStaticInfoResponse$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "handleStaticInfoResponse(): Outer antenna pairing is not not requested -> Do not send \'VehicleKeyInfoRequest\'"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final handleStaticInfoResponse$lambda$3(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vehicle:Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 2
    .line 3
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/InternalVehicle;->getOuterAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Outer;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/VehicleAntenna;->getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    :goto_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    const-string v1, "handleStaticInfoResponse(): Outer antenna pairing is requested but outer antenna already paired with "

    .line 18
    .line 19
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string p0, " -> Send \'VehicleKeyInfoRequest\'"

    .line 26
    .line 27
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.method private static final handleStaticInfoResponse$lambda$4()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "handleStaticInfoResponse(): Outer antenna pairing is required but does not exist -> Send \'VehicleKeyInfoRequest\'"

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic j(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleOuterAntennaKeyExchangeStatus$lambda$1(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic k(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleStaticInfoResponse$lambda$3(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic k0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleStaticInfoResponse$lambda$4()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic l(Ltechnology/cariad/cat/genx/KeyExchangeInformation;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleOuterAntennaKeyExchangeStatus$lambda$2$0(Ltechnology/cariad/cat/genx/KeyExchangeInformation;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic l0(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connect$lambda$2$2$0(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic n0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleMessage$lambda$3(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final onConnectionDropped$lambda$0(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "onConnectionDropped(): "

    .line 6
    .line 7
    invoke-static {v0, p0}, Lp3/m;->m(Ljava/lang/String;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method private final onKESConnected(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/services/kes/e;

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    invoke-direct {v3, p1, v0}, Ltechnology/cariad/cat/genx/services/kes/e;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    new-instance v0, Lt51/j;

    .line 8
    .line 9
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v5

    .line 13
    const-string v1, "getName(...)"

    .line 14
    .line 15
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v6

    .line 19
    const-string v1, "GenX"

    .line 20
    .line 21
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 22
    .line 23
    const/4 v4, 0x0

    .line 24
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 28
    .line 29
    .line 30
    iget-boolean v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->isClosed:Z

    .line 31
    .line 32
    const/4 v1, 0x3

    .line 33
    const/4 v2, 0x0

    .line 34
    if-eqz v0, :cond_0

    .line 35
    .line 36
    new-instance p1, Ltechnology/cariad/cat/genx/services/kes/g;

    .line 37
    .line 38
    const/16 p2, 0xa

    .line 39
    .line 40
    invoke-direct {p1, p0, p2}, Ltechnology/cariad/cat/genx/services/kes/g;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;I)V

    .line 41
    .line 42
    .line 43
    const-string p2, "GenX"

    .line 44
    .line 45
    invoke-static {p0, p2, v2, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 46
    .line 47
    .line 48
    new-instance p1, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$3;

    .line 49
    .line 50
    invoke-direct {p1, p0, v2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$3;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Lkotlin/coroutines/Continuation;)V

    .line 51
    .line 52
    .line 53
    invoke-static {p0, v2, v2, p1, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;

    .line 58
    .line 59
    invoke-direct {v0, p1, p0, p2, v2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$onKESConnected$4;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;Lkotlin/coroutines/Continuation;)V

    .line 60
    .line 61
    .line 62
    invoke-static {p0, v2, v2, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 63
    .line 64
    .line 65
    return-void
.end method

.method private static final onKESConnected$lambda$0(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->getIdentifier()Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "onKESConnected(): transportIdentifier = "

    .line 6
    .line 7
    invoke-static {v0, p0}, Lp3/m;->m(Ljava/lang/String;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Identifier;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method private static final onKESConnected$lambda$1(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vin:Ljava/lang/String;

    .line 2
    .line 3
    const-string v0, "onKESConnected(): KeyExchangeServiceApp was closed, but connection was not closed for vehicle "

    .line 4
    .line 5
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public static synthetic q(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleMessage$lambda$2(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic q0(JLtechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleMessage$lambda$0(JLtechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic r0(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleOuterAntennaKeyExchangeResponse$lambda$2$0(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final sendKESCanceledMessageToVehicleAndCloseConnection$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "sendKESCanceledMessageToVehicleAndCloseConnection()"

    .line 2
    .line 3
    return-object v0
.end method

.method private final sendMessage-gIAlu-s$genx_release$$forInline(Ltechnology/cariad/cat/genx/protocol/Message;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0
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

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$getConnection$p(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Llx0/l;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Llx0/l;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 10
    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    invoke-interface {p0, p1, p2}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;->send-gIAlu-s(Ltechnology/cariad/cat/genx/protocol/Message;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Llx0/o;

    .line 18
    .line 19
    iget-object p0, p0, Llx0/o;->d:Ljava/lang/Object;

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_0
    sget-object p0, Ltechnology/cariad/cat/genx/GenXError$InvalidConnection;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$InvalidConnection;

    .line 23
    .line 24
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0
.end method

.method private final sendQPM1([B)V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/services/kes/d;

    .line 2
    .line 3
    const/4 v0, 0x4

    .line 4
    invoke-direct {v3, v0, p1, p0}, Ltechnology/cariad/cat/genx/services/kes/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    new-instance v0, Lt51/j;

    .line 8
    .line 9
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v5

    .line 13
    const-string v1, "getName(...)"

    .line 14
    .line 15
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v6

    .line 19
    const-string v1, "GenX"

    .line 20
    .line 21
    sget-object v2, Lt51/d;->a:Lt51/d;

    .line 22
    .line 23
    const/4 v4, 0x0

    .line 24
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 28
    .line 29
    .line 30
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendQPM1$2;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    invoke-direct {v0, p0, p1, v1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendQPM1$2;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;[BLkotlin/coroutines/Continuation;)V

    .line 34
    .line 35
    .line 36
    const/4 p1, 0x3

    .line 37
    invoke-static {p0, v1, v1, v0, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method private static final sendQPM1$lambda$0([BLtechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p1, p1, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vin:Ljava/lang/String;

    .line 6
    .line 7
    const-string v0, "sendQPM1(): qpm1 = "

    .line 8
    .line 9
    const-string v1, " - "

    .line 10
    .line 11
    invoke-static {v0, p0, v1, p1}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private final sendStaticInformationRequest()V
    .locals 15

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/services/kes/g;

    .line 2
    .line 3
    const/16 v0, 0xc

    .line 4
    .line 5
    invoke-direct {v3, p0, v0}, Ltechnology/cariad/cat/genx/services/kes/g;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;I)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lt51/j;

    .line 9
    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v5

    .line 14
    const-string v7, "getName(...)"

    .line 15
    .line 16
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    const-string v1, "GenX"

    .line 21
    .line 22
    sget-object v2, Lt51/d;->a:Lt51/d;

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vehicle:Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 32
    .line 33
    invoke-interface {v0}, Ltechnology/cariad/cat/genx/InternalVehicle;->getOuterAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Outer;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    if-eqz v0, :cond_0

    .line 38
    .line 39
    const/4 v0, 0x1

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    const/4 v0, 0x0

    .line 42
    :goto_0
    new-instance v11, Lfw0/n;

    .line 43
    .line 44
    const/16 v1, 0xa

    .line 45
    .line 46
    invoke-direct {v11, v1, v0}, Lfw0/n;-><init>(IZ)V

    .line 47
    .line 48
    .line 49
    new-instance v8, Lt51/j;

    .line 50
    .line 51
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v13

    .line 55
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v14

    .line 59
    const-string v9, "GenX"

    .line 60
    .line 61
    sget-object v10, Lt51/g;->a:Lt51/g;

    .line 62
    .line 63
    const/4 v12, 0x0

    .line 64
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 68
    .line 69
    .line 70
    new-instance v1, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;

    .line 71
    .line 72
    const/4 v2, 0x0

    .line 73
    invoke-direct {v1, p0, v0, v2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStaticInformationRequest$3;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;ZLkotlin/coroutines/Continuation;)V

    .line 74
    .line 75
    .line 76
    const/4 v0, 0x3

    .line 77
    invoke-static {p0, v2, v2, v1, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 78
    .line 79
    .line 80
    return-void
.end method

.method private static final sendStaticInformationRequest$lambda$0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vin:Ljava/lang/String;

    .line 2
    .line 3
    const-string v0, "sendStaticInformationRequest() - "

    .line 4
    .line 5
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static final sendStaticInformationRequest$lambda$1(Z)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "sendStaticInformationRequest(): Is outer antenna already paired = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

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

.method private final sendStatus(Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 13
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/b0;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    instance-of v0, p2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStatus$1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStatus$1;

    .line 7
    .line 8
    iget v1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStatus$1;->label:I

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
    iput v1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStatus$1;->label:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStatus$1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStatus$1;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStatus$1;->result:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStatus$1;->label:I

    .line 30
    .line 31
    const-string v3, "getName(...)"

    .line 32
    .line 33
    const/4 v4, 0x0

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v2, :cond_2

    .line 36
    .line 37
    if-ne v2, v5, :cond_1

    .line 38
    .line 39
    iget-object p1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStatus$1;->L$2:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p1, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 42
    .line 43
    iget-object p1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStatus$1;->L$1:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p1, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 46
    .line 47
    iget-object p1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStatus$1;->L$0:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast p1, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 50
    .line 51
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    check-cast p2, Llx0/o;

    .line 55
    .line 56
    iget-object p2, p2, Llx0/o;->d:Ljava/lang/Object;

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 60
    .line 61
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 62
    .line 63
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw p0

    .line 67
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    new-instance v9, Ltechnology/cariad/cat/genx/services/kes/e;

    .line 71
    .line 72
    const/4 p2, 0x3

    .line 73
    invoke-direct {v9, p1, p2}, Ltechnology/cariad/cat/genx/services/kes/e;-><init>(Ljava/lang/Object;I)V

    .line 74
    .line 75
    .line 76
    new-instance v6, Lt51/j;

    .line 77
    .line 78
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v11

    .line 82
    invoke-static {v3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v12

    .line 86
    const-string v7, "GenX"

    .line 87
    .line 88
    sget-object v8, Lt51/g;->a:Lt51/g;

    .line 89
    .line 90
    const/4 v10, 0x0

    .line 91
    invoke-direct/range {v6 .. v12}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    invoke-static {v6}, Lt51/a;->a(Lt51/j;)V

    .line 95
    .line 96
    .line 97
    new-instance p2, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 98
    .line 99
    sget-object v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->OUTER_ANTENNA_KEY_EXCHANGE_STATUS_SEND:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 100
    .line 101
    sget-object v6, Ltechnology/cariad/cat/genx/protocol/Priority;->HIGH:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 102
    .line 103
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->getByteArray()[B

    .line 104
    .line 105
    .line 106
    move-result-object v7

    .line 107
    invoke-direct {p2, v2, v6, v5, v7}, Ltechnology/cariad/cat/genx/protocol/Message;-><init>(Ltechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/genx/protocol/Priority;Z[B)V

    .line 108
    .line 109
    .line 110
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$getConnection$p(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Llx0/l;

    .line 111
    .line 112
    .line 113
    move-result-object v2

    .line 114
    if-eqz v2, :cond_3

    .line 115
    .line 116
    iget-object v2, v2, Llx0/l;->e:Ljava/lang/Object;

    .line 117
    .line 118
    check-cast v2, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 119
    .line 120
    if-eqz v2, :cond_3

    .line 121
    .line 122
    iput-object p1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStatus$1;->L$0:Ljava/lang/Object;

    .line 123
    .line 124
    iput-object v4, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStatus$1;->L$1:Ljava/lang/Object;

    .line 125
    .line 126
    iput-object v4, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStatus$1;->L$2:Ljava/lang/Object;

    .line 127
    .line 128
    const/4 v6, 0x0

    .line 129
    iput v6, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStatus$1;->I$0:I

    .line 130
    .line 131
    iput v5, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendStatus$1;->label:I

    .line 132
    .line 133
    invoke-interface {v2, p2, v0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;->send-gIAlu-s(Ltechnology/cariad/cat/genx/protocol/Message;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p2

    .line 137
    if-ne p2, v1, :cond_4

    .line 138
    .line 139
    return-object v1

    .line 140
    :cond_3
    sget-object p2, Ltechnology/cariad/cat/genx/GenXError$InvalidConnection;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$InvalidConnection;

    .line 141
    .line 142
    invoke-static {p2}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 143
    .line 144
    .line 145
    move-result-object p2

    .line 146
    :cond_4
    :goto_1
    invoke-static {p2}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 147
    .line 148
    .line 149
    move-result-object v9

    .line 150
    if-eqz v9, :cond_5

    .line 151
    .line 152
    new-instance v8, Ltechnology/cariad/cat/genx/services/kes/d;

    .line 153
    .line 154
    const/4 p2, 0x3

    .line 155
    invoke-direct {v8, p2, p1, p0}, Ltechnology/cariad/cat/genx/services/kes/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    new-instance v5, Lt51/j;

    .line 159
    .line 160
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v10

    .line 164
    invoke-static {v3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object v11

    .line 168
    const-string v6, "GenX"

    .line 169
    .line 170
    sget-object v7, Lt51/e;->a:Lt51/e;

    .line 171
    .line 172
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 176
    .line 177
    .line 178
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->_result:Lyy0/j1;

    .line 179
    .line 180
    new-instance p1, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeFailed;

    .line 181
    .line 182
    check-cast v9, Ltechnology/cariad/cat/genx/GenXError;

    .line 183
    .line 184
    invoke-direct {p1, v9}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeFailed;-><init>(Ltechnology/cariad/cat/genx/GenXError;)V

    .line 185
    .line 186
    .line 187
    check-cast p0, Lyy0/c2;

    .line 188
    .line 189
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 190
    .line 191
    .line 192
    invoke-virtual {p0, v4, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 193
    .line 194
    .line 195
    :cond_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 196
    .line 197
    return-object p0
.end method

.method private static final sendStatus$lambda$0(Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "sendStatus(): Send OuterAntennaKeyExchangeStatus = "

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

.method private static final sendStatus$lambda$1$0(Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p1, p1, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vin:Ljava/lang/String;

    .line 2
    .line 3
    new-instance v0, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v1, "sendStatus(): Failed to send Status "

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
    const-string p0, " - "

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

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

.method private final sendVehicleKeyInfoRequest()V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/services/kes/g;

    .line 2
    .line 3
    const/16 v0, 0xb

    .line 4
    .line 5
    invoke-direct {v3, p0, v0}, Ltechnology/cariad/cat/genx/services/kes/g;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;I)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lt51/j;

    .line 9
    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v5

    .line 14
    const-string v1, "getName(...)"

    .line 15
    .line 16
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    const-string v1, "GenX"

    .line 21
    .line 22
    sget-object v2, Lt51/d;->a:Lt51/d;

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 29
    .line 30
    .line 31
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    invoke-direct {v0, p0, v1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendVehicleKeyInfoRequest$2;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Lkotlin/coroutines/Continuation;)V

    .line 35
    .line 36
    .line 37
    const/4 v2, 0x3

    .line 38
    invoke-static {p0, v1, v1, v0, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method private static final sendVehicleKeyInfoRequest$lambda$0(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vin:Ljava/lang/String;

    .line 2
    .line 3
    const-string v0, "sendVehicleKeyInfoRequest() - "

    .line 4
    .line 5
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private final setupConnectionJobWithRetry()Lvy0/i1;
    .locals 3

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$setupConnectionJobWithRetry$1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$setupConnectionJobWithRetry$1;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Lkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    const/4 v2, 0x3

    .line 8
    invoke-static {p0, v1, v1, v0, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public static synthetic x0(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleStaticInfoResponse$lambda$0(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic y0(Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleOuterAntennaKeyExchangeStatus$lambda$0(Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic z0(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleOuterAntennaKeyExchangeResponse$lambda$0(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method


# virtual methods
.method public close()V
    .locals 4

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/g;

    .line 2
    .line 3
    const/16 v1, 0x10

    .line 4
    .line 5
    invoke-direct {v0, p0, v1}, Ltechnology/cariad/cat/genx/services/kes/g;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;I)V

    .line 6
    .line 7
    .line 8
    const-string v1, "GenX"

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    invoke-static {p0, v1, v2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 12
    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    iput-boolean v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->isClosed:Z

    .line 16
    .line 17
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->getKesCompleted()Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_0

    .line 22
    .line 23
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/f;

    .line 24
    .line 25
    const/16 v3, 0xb

    .line 26
    .line 27
    invoke-direct {v0, v3}, Ltechnology/cariad/cat/genx/services/kes/f;-><init>(I)V

    .line 28
    .line 29
    .line 30
    invoke-static {p0, v1, v2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 31
    .line 32
    .line 33
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->_result:Lyy0/j1;

    .line 34
    .line 35
    new-instance v1, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeFailed;

    .line 36
    .line 37
    sget-object v3, Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;

    .line 38
    .line 39
    invoke-direct {v1, v3}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeFailed;-><init>(Ltechnology/cariad/cat/genx/GenXError;)V

    .line 40
    .line 41
    .line 42
    check-cast v0, Lyy0/c2;

    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    :cond_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connectionJob:Lvy0/i1;

    .line 51
    .line 52
    if-eqz v0, :cond_1

    .line 53
    .line 54
    const-string v1, "close()"

    .line 55
    .line 56
    invoke-static {v1, v0}, Lvy0/e0;->k(Ljava/lang/String;Lvy0/i1;)V

    .line 57
    .line 58
    .line 59
    :cond_1
    iput-object v2, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connectionJob:Lvy0/i1;

    .line 60
    .line 61
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connection:Llx0/l;

    .line 62
    .line 63
    if-eqz v0, :cond_2

    .line 64
    .line 65
    iget-object v0, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 68
    .line 69
    if-eqz v0, :cond_2

    .line 70
    .line 71
    invoke-interface {v0}, Ljava/io/Closeable;->close()V

    .line 72
    .line 73
    .line 74
    :cond_2
    iput-object v2, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connection:Llx0/l;

    .line 75
    .line 76
    return-void
.end method

.method public final connect(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 18
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lvy0/h0;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    instance-of v2, v1, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;

    .line 11
    .line 12
    iget v3, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->label:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->label:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->result:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->label:I

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    const/4 v6, 0x2

    .line 37
    const/4 v7, 0x1

    .line 38
    const/4 v8, 0x0

    .line 39
    const-string v9, "getName(...)"

    .line 40
    .line 41
    sget-object v12, Lt51/g;->a:Lt51/g;

    .line 42
    .line 43
    if-eqz v4, :cond_4

    .line 44
    .line 45
    if-eq v4, v7, :cond_3

    .line 46
    .line 47
    if-eq v4, v6, :cond_2

    .line 48
    .line 49
    if-ne v4, v5, :cond_1

    .line 50
    .line 51
    iget-object v3, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->L$2:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v3, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 54
    .line 55
    iget-object v4, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->L$1:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v4, Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;

    .line 58
    .line 59
    iget-object v2, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->L$0:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast v2, Lvy0/q;

    .line 62
    .line 63
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    check-cast v1, Llx0/o;

    .line 67
    .line 68
    iget-object v1, v1, Llx0/o;->d:Ljava/lang/Object;

    .line 69
    .line 70
    goto/16 :goto_4

    .line 71
    .line 72
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 73
    .line 74
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 75
    .line 76
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    throw v0

    .line 80
    :cond_2
    iget v4, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->I$0:I

    .line 81
    .line 82
    iget-object v6, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->L$2:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v6, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 85
    .line 86
    iget-object v7, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->L$1:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast v7, Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;

    .line 89
    .line 90
    iget-object v7, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->L$0:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast v7, Lvy0/q;

    .line 93
    .line 94
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    move-object v1, v6

    .line 98
    goto/16 :goto_2

    .line 99
    .line 100
    :cond_3
    iget-object v4, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->L$1:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast v4, Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;

    .line 103
    .line 104
    iget-object v7, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->L$0:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast v7, Lvy0/q;

    .line 107
    .line 108
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    check-cast v1, Llx0/o;

    .line 112
    .line 113
    iget-object v1, v1, Llx0/o;->d:Ljava/lang/Object;

    .line 114
    .line 115
    goto :goto_1

    .line 116
    :cond_4
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    iget-object v1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connectionJob:Lvy0/i1;

    .line 120
    .line 121
    new-instance v4, Lvy0/r;

    .line 122
    .line 123
    invoke-direct {v4, v7}, Lvy0/p1;-><init>(Z)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v4, v1}, Lvy0/p1;->S(Lvy0/i1;)V

    .line 127
    .line 128
    .line 129
    new-instance v13, Ltechnology/cariad/cat/genx/services/kes/g;

    .line 130
    .line 131
    const/16 v1, 0x11

    .line 132
    .line 133
    invoke-direct {v13, v0, v1}, Ltechnology/cariad/cat/genx/services/kes/g;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;I)V

    .line 134
    .line 135
    .line 136
    new-instance v10, Lt51/j;

    .line 137
    .line 138
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object v15

    .line 142
    invoke-static {v9}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object v16

    .line 146
    const-string v11, "GenX"

    .line 147
    .line 148
    const/4 v14, 0x0

    .line 149
    invoke-direct/range {v10 .. v16}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    invoke-static {v10}, Lt51/a;->a(Lt51/j;)V

    .line 153
    .line 154
    .line 155
    iget-object v1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vehicle:Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 156
    .line 157
    invoke-interface {v1}, Ltechnology/cariad/cat/genx/InternalVehicle;->getInnerAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    if-nez v1, :cond_5

    .line 162
    .line 163
    sget-object v0, Ltechnology/cariad/cat/genx/GenXError$InvalidConnection;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$InvalidConnection;

    .line 164
    .line 165
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    new-instance v1, Llx0/o;

    .line 170
    .line 171
    invoke-direct {v1, v0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {v4, v1}, Lvy0/p1;->W(Ljava/lang/Object;)Z

    .line 175
    .line 176
    .line 177
    return-object v4

    .line 178
    :cond_5
    iput-object v4, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->L$0:Ljava/lang/Object;

    .line 179
    .line 180
    iput-object v1, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->L$1:Ljava/lang/Object;

    .line 181
    .line 182
    iput v7, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->label:I

    .line 183
    .line 184
    invoke-interface {v1, v2}, Ltechnology/cariad/cat/genx/VehicleAntenna$Inner;->bleTransport-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v7

    .line 188
    if-ne v7, v3, :cond_6

    .line 189
    .line 190
    goto/16 :goto_3

    .line 191
    .line 192
    :cond_6
    move-object/from16 v17, v4

    .line 193
    .line 194
    move-object v4, v1

    .line 195
    move-object v1, v7

    .line 196
    move-object/from16 v7, v17

    .line 197
    .line 198
    :goto_1
    invoke-static {v1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 199
    .line 200
    .line 201
    move-result-object v10

    .line 202
    if-nez v10, :cond_a

    .line 203
    .line 204
    check-cast v1, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 205
    .line 206
    new-instance v13, Ltechnology/cariad/cat/genx/services/kes/c;

    .line 207
    .line 208
    const/4 v4, 0x0

    .line 209
    invoke-direct {v13, v0, v1, v4}, Ltechnology/cariad/cat/genx/services/kes/c;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Ltechnology/cariad/cat/genx/VehicleAntennaTransport;I)V

    .line 210
    .line 211
    .line 212
    new-instance v10, Lt51/j;

    .line 213
    .line 214
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object v15

    .line 218
    invoke-static {v9}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 219
    .line 220
    .line 221
    move-result-object v16

    .line 222
    const-string v11, "GenX"

    .line 223
    .line 224
    const/4 v14, 0x0

    .line 225
    invoke-direct/range {v10 .. v16}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    invoke-static {v10}, Lt51/a;->a(Lt51/j;)V

    .line 229
    .line 230
    .line 231
    invoke-interface {v1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->getReachability()Lyy0/a2;

    .line 232
    .line 233
    .line 234
    move-result-object v4

    .line 235
    invoke-interface {v1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->getCar2PhoneMode()Lyy0/a2;

    .line 236
    .line 237
    .line 238
    move-result-object v10

    .line 239
    new-instance v11, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$2;

    .line 240
    .line 241
    invoke-direct {v11, v0, v8}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$2;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Lkotlin/coroutines/Continuation;)V

    .line 242
    .line 243
    .line 244
    new-instance v13, Lbn0/f;

    .line 245
    .line 246
    const/4 v14, 0x5

    .line 247
    invoke-direct {v13, v4, v10, v11, v14}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 248
    .line 249
    .line 250
    const-wide/16 v10, 0xc8

    .line 251
    .line 252
    invoke-static {v13, v10, v11}, Lyy0/u;->o(Lyy0/i;J)Lyy0/i;

    .line 253
    .line 254
    .line 255
    move-result-object v4

    .line 256
    new-instance v10, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$3;

    .line 257
    .line 258
    invoke-direct {v10, v8}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$3$3;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 259
    .line 260
    .line 261
    iput-object v7, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->L$0:Ljava/lang/Object;

    .line 262
    .line 263
    iput-object v8, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->L$1:Ljava/lang/Object;

    .line 264
    .line 265
    iput-object v1, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->L$2:Ljava/lang/Object;

    .line 266
    .line 267
    const/4 v11, 0x0

    .line 268
    iput v11, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->I$0:I

    .line 269
    .line 270
    iput v6, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->label:I

    .line 271
    .line 272
    invoke-static {v4, v10, v2}, Lyy0/u;->t(Lyy0/i;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v4

    .line 276
    if-ne v4, v3, :cond_7

    .line 277
    .line 278
    goto :goto_3

    .line 279
    :cond_7
    move v4, v11

    .line 280
    :goto_2
    new-instance v13, Ltechnology/cariad/cat/genx/services/kes/c;

    .line 281
    .line 282
    const/4 v6, 0x1

    .line 283
    invoke-direct {v13, v0, v1, v6}, Ltechnology/cariad/cat/genx/services/kes/c;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Ltechnology/cariad/cat/genx/VehicleAntennaTransport;I)V

    .line 284
    .line 285
    .line 286
    new-instance v10, Lt51/j;

    .line 287
    .line 288
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 289
    .line 290
    .line 291
    move-result-object v15

    .line 292
    invoke-static {v9}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 293
    .line 294
    .line 295
    move-result-object v16

    .line 296
    const-string v11, "GenX"

    .line 297
    .line 298
    const/4 v14, 0x0

    .line 299
    invoke-direct/range {v10 .. v16}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 300
    .line 301
    .line 302
    invoke-static {v10}, Lt51/a;->a(Lt51/j;)V

    .line 303
    .line 304
    .line 305
    sget-object v6, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->ADDRESSES:Ljava/util/Set;

    .line 306
    .line 307
    iput-object v7, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->L$0:Ljava/lang/Object;

    .line 308
    .line 309
    iput-object v8, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->L$1:Ljava/lang/Object;

    .line 310
    .line 311
    iput-object v1, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->L$2:Ljava/lang/Object;

    .line 312
    .line 313
    iput v4, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->I$0:I

    .line 314
    .line 315
    iput v5, v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$connect$1;->label:I

    .line 316
    .line 317
    invoke-interface {v1, v0, v6, v2}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->connect-0E7RQCE(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;Ljava/util/Set;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    move-result-object v2

    .line 321
    if-ne v2, v3, :cond_8

    .line 322
    .line 323
    :goto_3
    return-object v3

    .line 324
    :cond_8
    move-object v3, v1

    .line 325
    move-object v1, v2

    .line 326
    move-object v2, v7

    .line 327
    :goto_4
    invoke-static {v1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 328
    .line 329
    .line 330
    move-result-object v14

    .line 331
    if-nez v14, :cond_9

    .line 332
    .line 333
    check-cast v1, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 334
    .line 335
    new-instance v13, Ltechnology/cariad/cat/genx/services/kes/b;

    .line 336
    .line 337
    const/4 v4, 0x1

    .line 338
    invoke-direct {v13, v1, v4}, Ltechnology/cariad/cat/genx/services/kes/b;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;I)V

    .line 339
    .line 340
    .line 341
    new-instance v10, Lt51/j;

    .line 342
    .line 343
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 344
    .line 345
    .line 346
    move-result-object v15

    .line 347
    invoke-static {v9}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 348
    .line 349
    .line 350
    move-result-object v16

    .line 351
    const-string v11, "GenX"

    .line 352
    .line 353
    const/4 v14, 0x0

    .line 354
    invoke-direct/range {v10 .. v16}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 355
    .line 356
    .line 357
    invoke-static {v10}, Lt51/a;->a(Lt51/j;)V

    .line 358
    .line 359
    .line 360
    new-instance v0, Llx0/l;

    .line 361
    .line 362
    invoke-direct {v0, v3, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 363
    .line 364
    .line 365
    new-instance v1, Llx0/o;

    .line 366
    .line 367
    invoke-direct {v1, v0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 368
    .line 369
    .line 370
    move-object v0, v2

    .line 371
    check-cast v0, Lvy0/r;

    .line 372
    .line 373
    invoke-virtual {v0, v1}, Lvy0/p1;->W(Ljava/lang/Object;)Z

    .line 374
    .line 375
    .line 376
    return-object v2

    .line 377
    :cond_9
    new-instance v13, Ltechnology/cariad/cat/genx/services/kes/f;

    .line 378
    .line 379
    const/16 v1, 0xc

    .line 380
    .line 381
    invoke-direct {v13, v1}, Ltechnology/cariad/cat/genx/services/kes/f;-><init>(I)V

    .line 382
    .line 383
    .line 384
    new-instance v10, Lt51/j;

    .line 385
    .line 386
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 387
    .line 388
    .line 389
    move-result-object v15

    .line 390
    invoke-static {v9}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 391
    .line 392
    .line 393
    move-result-object v16

    .line 394
    const-string v11, "GenX"

    .line 395
    .line 396
    invoke-direct/range {v10 .. v16}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 397
    .line 398
    .line 399
    invoke-static {v10}, Lt51/a;->a(Lt51/j;)V

    .line 400
    .line 401
    .line 402
    invoke-static {v14}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 403
    .line 404
    .line 405
    move-result-object v0

    .line 406
    new-instance v1, Llx0/o;

    .line 407
    .line 408
    invoke-direct {v1, v0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 409
    .line 410
    .line 411
    move-object v0, v2

    .line 412
    check-cast v0, Lvy0/r;

    .line 413
    .line 414
    invoke-virtual {v0, v1}, Lvy0/p1;->W(Ljava/lang/Object;)Z

    .line 415
    .line 416
    .line 417
    return-object v2

    .line 418
    :cond_a
    new-instance v1, Ltechnology/cariad/cat/genx/services/kes/e;

    .line 419
    .line 420
    const/4 v2, 0x4

    .line 421
    invoke-direct {v1, v4, v2}, Ltechnology/cariad/cat/genx/services/kes/e;-><init>(Ljava/lang/Object;I)V

    .line 422
    .line 423
    .line 424
    const-string v2, "GenX"

    .line 425
    .line 426
    invoke-static {v0, v2, v10, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 427
    .line 428
    .line 429
    invoke-static {v10}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 430
    .line 431
    .line 432
    move-result-object v0

    .line 433
    new-instance v1, Llx0/o;

    .line 434
    .line 435
    invoke-direct {v1, v0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 436
    .line 437
    .line 438
    move-object v0, v7

    .line 439
    check-cast v0, Lvy0/r;

    .line 440
    .line 441
    invoke-virtual {v0, v1}, Lvy0/p1;->W(Ljava/lang/Object;)Z

    .line 442
    .line 443
    .line 444
    return-object v7
.end method

.method public final connectKES()V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/services/kes/f;

    .line 2
    .line 3
    const/4 v0, 0x6

    .line 4
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/services/kes/f;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v0, Lt51/j;

    .line 8
    .line 9
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v5

    .line 13
    const-string v1, "getName(...)"

    .line 14
    .line 15
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v6

    .line 19
    const-string v1, "GenX"

    .line 20
    .line 21
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 22
    .line 23
    const/4 v4, 0x0

    .line 24
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 28
    .line 29
    .line 30
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connectionJob:Lvy0/i1;

    .line 31
    .line 32
    const-string v1, "GenX"

    .line 33
    .line 34
    const/4 v2, 0x0

    .line 35
    if-eqz v0, :cond_0

    .line 36
    .line 37
    invoke-interface {v0}, Lvy0/i1;->a()Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    const/4 v3, 0x1

    .line 42
    if-ne v0, v3, :cond_0

    .line 43
    .line 44
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/f;

    .line 45
    .line 46
    const/16 v3, 0x9

    .line 47
    .line 48
    invoke-direct {v0, v3}, Ltechnology/cariad/cat/genx/services/kes/f;-><init>(I)V

    .line 49
    .line 50
    .line 51
    invoke-static {p0, v1, v2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :cond_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connection:Llx0/l;

    .line 56
    .line 57
    if-eqz v0, :cond_1

    .line 58
    .line 59
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/f;

    .line 60
    .line 61
    const/16 v3, 0xa

    .line 62
    .line 63
    invoke-direct {v0, v3}, Ltechnology/cariad/cat/genx/services/kes/f;-><init>(I)V

    .line 64
    .line 65
    .line 66
    invoke-static {p0, v1, v2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 67
    .line 68
    .line 69
    return-void

    .line 70
    :cond_1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->getKesCompleted()Z

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    if-eqz v0, :cond_2

    .line 75
    .line 76
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/f;

    .line 77
    .line 78
    const/16 v3, 0xd

    .line 79
    .line 80
    invoke-direct {v0, v3}, Ltechnology/cariad/cat/genx/services/kes/f;-><init>(I)V

    .line 81
    .line 82
    .line 83
    invoke-static {p0, v1, v2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 84
    .line 85
    .line 86
    return-void

    .line 87
    :cond_2
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->setupConnectionJobWithRetry()Lvy0/i1;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    iput-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connectionJob:Lvy0/i1;

    .line 92
    .line 93
    return-void
.end method

.method public getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->$$delegate_0:Lvy0/b0;

    .line 2
    .line 3
    invoke-interface {p0}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getKeyExchangeInformation()Ltechnology/cariad/cat/genx/KeyExchangeInformation;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->keyExchangeInformation:Ltechnology/cariad/cat/genx/KeyExchangeInformation;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getResult()Lyy0/i;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->result:Lyy0/i;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVehicle()Ltechnology/cariad/cat/genx/InternalVehicle;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vehicle:Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 2
    .line 3
    return-object p0
.end method

.method public final isConnected()Z
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connection:Llx0/l;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public onConnectionDropped(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;Ltechnology/cariad/cat/genx/GenXError;)V
    .locals 3

    .line 1
    const-string v0, "connection"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "error"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/b;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    invoke-direct {v0, p1, v1}, Ltechnology/cariad/cat/genx/services/kes/b;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;I)V

    .line 15
    .line 16
    .line 17
    const-string v1, "GenX"

    .line 18
    .line 19
    invoke-static {p0, v1, p2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 20
    .line 21
    .line 22
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->getKesCompleted()Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    const/4 v1, 0x0

    .line 27
    if-nez v0, :cond_0

    .line 28
    .line 29
    iget-object v0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->_result:Lyy0/j1;

    .line 30
    .line 31
    new-instance v2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeFailed;

    .line 32
    .line 33
    invoke-direct {v2, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result$KeyExchangeFailed;-><init>(Ltechnology/cariad/cat/genx/GenXError;)V

    .line 34
    .line 35
    .line 36
    check-cast v0, Lyy0/c2;

    .line 37
    .line 38
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    :cond_0
    iget-object p2, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connection:Llx0/l;

    .line 45
    .line 46
    if-eqz p2, :cond_1

    .line 47
    .line 48
    iget-object p2, p2, Llx0/l;->e:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast p2, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_1
    move-object p2, v1

    .line 54
    :goto_0
    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result p1

    .line 58
    if-eqz p1, :cond_3

    .line 59
    .line 60
    iget-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connection:Llx0/l;

    .line 61
    .line 62
    if-eqz p1, :cond_2

    .line 63
    .line 64
    iget-object p1, p1, Llx0/l;->e:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast p1, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 67
    .line 68
    if-eqz p1, :cond_2

    .line 69
    .line 70
    invoke-interface {p1}, Ljava/io/Closeable;->close()V

    .line 71
    .line 72
    .line 73
    :cond_2
    iput-object v1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connection:Llx0/l;

    .line 74
    .line 75
    :cond_3
    return-void
.end method

.method public onConnectionReceived(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;Ltechnology/cariad/cat/genx/protocol/Message;)V
    .locals 2

    .line 1
    const-string v0, "connection"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p1, "message"

    .line 7
    .line 8
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p2}, Ltechnology/cariad/cat/genx/protocol/Message;->getAddress()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 16
    .line 17
    .line 18
    move-result-wide v0

    .line 19
    invoke-virtual {p2}, Ltechnology/cariad/cat/genx/protocol/Message;->getData()[B

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-direct {p0, v0, v1, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->handleMessage(J[B)Z

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final sendKESCanceledMessageToVehicleAndCloseConnection(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 11
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
    instance-of v0, p1, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendKESCanceledMessageToVehicleAndCloseConnection$1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendKESCanceledMessageToVehicleAndCloseConnection$1;

    .line 7
    .line 8
    iget v1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendKESCanceledMessageToVehicleAndCloseConnection$1;->label:I

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
    iput v1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendKESCanceledMessageToVehicleAndCloseConnection$1;->label:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendKESCanceledMessageToVehicleAndCloseConnection$1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendKESCanceledMessageToVehicleAndCloseConnection$1;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendKESCanceledMessageToVehicleAndCloseConnection$1;->result:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendKESCanceledMessageToVehicleAndCloseConnection$1;->label:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    new-instance v7, Ltechnology/cariad/cat/genx/services/kes/f;

    .line 52
    .line 53
    const/16 p1, 0xf

    .line 54
    .line 55
    invoke-direct {v7, p1}, Ltechnology/cariad/cat/genx/services/kes/f;-><init>(I)V

    .line 56
    .line 57
    .line 58
    new-instance v4, Lt51/j;

    .line 59
    .line 60
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v9

    .line 64
    const-string p1, "getName(...)"

    .line 65
    .line 66
    invoke-static {p1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v10

    .line 70
    const-string v5, "GenX"

    .line 71
    .line 72
    sget-object v6, Lt51/d;->a:Lt51/d;

    .line 73
    .line 74
    const/4 v8, 0x0

    .line 75
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 79
    .line 80
    .line 81
    sget-object p1, Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;->CANCELED:Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;

    .line 82
    .line 83
    iput v3, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendKESCanceledMessageToVehicleAndCloseConnection$1;->label:I

    .line 84
    .line 85
    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->sendStatus(Ltechnology/cariad/cat/genx/services/kes/OuterAntennaKeyExchangeStatus;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    if-ne p1, v1, :cond_3

    .line 90
    .line 91
    return-object v1

    .line 92
    :cond_3
    :goto_1
    iget-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connection:Llx0/l;

    .line 93
    .line 94
    if-eqz p1, :cond_4

    .line 95
    .line 96
    iget-object p1, p1, Llx0/l;->e:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast p1, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 99
    .line 100
    if-eqz p1, :cond_4

    .line 101
    .line 102
    invoke-interface {p1}, Ljava/io/Closeable;->close()V

    .line 103
    .line 104
    .line 105
    :cond_4
    const/4 p1, 0x0

    .line 106
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->connection:Llx0/l;

    .line 107
    .line 108
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 109
    .line 110
    return-object p0
.end method

.method public final sendMessage-gIAlu-s$genx_release(Ltechnology/cariad/cat/genx/protocol/Message;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4
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

    .line 1
    instance-of v0, p2, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendMessage$1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendMessage$1;

    .line 7
    .line 8
    iget v1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendMessage$1;->label:I

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
    iput v1, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendMessage$1;->label:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendMessage$1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendMessage$1;-><init>(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendMessage$1;->result:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendMessage$1;->label:I

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
    iget-object p0, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendMessage$1;->L$0:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p0, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    check-cast p2, Llx0/o;

    .line 44
    .line 45
    iget-object p0, p2, Llx0/o;->d:Ljava/lang/Object;

    .line 46
    .line 47
    return-object p0

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    invoke-static {p0}, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->access$getConnection$p(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;)Llx0/l;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    if-eqz p0, :cond_4

    .line 64
    .line 65
    iget-object p0, p0, Llx0/l;->e:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 68
    .line 69
    if-eqz p0, :cond_4

    .line 70
    .line 71
    const/4 p2, 0x0

    .line 72
    iput-object p2, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendMessage$1;->L$0:Ljava/lang/Object;

    .line 73
    .line 74
    const/4 p2, 0x0

    .line 75
    iput p2, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendMessage$1;->I$0:I

    .line 76
    .line 77
    iput v3, v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$sendMessage$1;->label:I

    .line 78
    .line 79
    invoke-interface {p0, p1, v0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;->send-gIAlu-s(Ltechnology/cariad/cat/genx/protocol/Message;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    if-ne p0, v1, :cond_3

    .line 84
    .line 85
    return-object v1

    .line 86
    :cond_3
    return-object p0

    .line 87
    :cond_4
    sget-object p0, Ltechnology/cariad/cat/genx/GenXError$InvalidConnection;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$InvalidConnection;

    .line 88
    .line 89
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    return-object p0
.end method

.method public final setKeyExchangeInformation(Ltechnology/cariad/cat/genx/KeyExchangeInformation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->keyExchangeInformation:Ltechnology/cariad/cat/genx/KeyExchangeInformation;

    .line 2
    .line 3
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;->vin:Ljava/lang/String;

    .line 2
    .line 3
    const-string v0, "KeyExchangeServiceApp(vin="

    .line 4
    .line 5
    const-string v1, ")"

    .line 6
    .line 7
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
