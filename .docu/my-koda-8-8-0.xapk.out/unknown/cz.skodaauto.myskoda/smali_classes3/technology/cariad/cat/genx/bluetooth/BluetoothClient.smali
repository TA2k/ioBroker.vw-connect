.class public final Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/Client;
.implements Ljava/io/Closeable;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "MissingPermission"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00b4\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u0012\n\u0002\u0008\u000c\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0002\u0008\u0019\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\t\u0008\u0001\u0018\u00002\u00020\u00012\u00020\u0002:\u0001wBI\u0008\u0000\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0006\u001a\u00020\u0005\u0012\u0006\u0010\u0008\u001a\u00020\u0007\u0012\u0006\u0010\n\u001a\u00020\t\u0012\u0006\u0010\u000c\u001a\u00020\u000b\u0012\u0006\u0010\u000e\u001a\u00020\r\u0012\u0006\u0010\u0010\u001a\u00020\u000f\u0012\u0006\u0010\u0011\u001a\u00020\u000f\u00a2\u0006\u0004\u0008\u0012\u0010\u0013J\u000f\u0010\u0015\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008\u0015\u0010\u0016J\u000f\u0010\u0017\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008\u0017\u0010\u0016J\u000f\u0010\u0018\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008\u0018\u0010\u0016J\u000f\u0010\u0019\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008\u0019\u0010\u0016J\u0019\u0010\u001d\u001a\u0004\u0018\u00010\u001c2\u0006\u0010\u001b\u001a\u00020\u001aH\u0016\u00a2\u0006\u0004\u0008\u001d\u0010\u001eJ\u000f\u0010\u001f\u001a\u00020\u000fH\u0016\u00a2\u0006\u0004\u0008\u001f\u0010 J\u0017\u0010#\u001a\u00020\u00142\u0006\u0010\"\u001a\u00020!H\u0016\u00a2\u0006\u0004\u0008#\u0010$J\u0017\u0010)\u001a\u00020\u00142\u0006\u0010&\u001a\u00020%H\u0000\u00a2\u0006\u0004\u0008\'\u0010(J\u001f\u0010.\u001a\u00020\u00142\u0006\u0010\"\u001a\u00020!2\u0006\u0010+\u001a\u00020*H\u0000\u00a2\u0006\u0004\u0008,\u0010-J\u001f\u00102\u001a\u00020\u00142\u0006\u0010\"\u001a\u00020!2\u0006\u0010/\u001a\u00020\u000fH\u0000\u00a2\u0006\u0004\u00080\u00101J\u000f\u00104\u001a\u00020\u0014H\u0000\u00a2\u0006\u0004\u00083\u0010\u0016J\u000f\u00106\u001a\u00020\u0014H\u0000\u00a2\u0006\u0004\u00085\u0010\u0016J\u001f\u0010<\u001a\u0002092\u0006\u0010\u001b\u001a\u00020\u001a2\u0006\u00108\u001a\u000207H\u0000\u00a2\u0006\u0004\u0008:\u0010;J\u000f\u0010>\u001a\u00020=H\u0016\u00a2\u0006\u0004\u0008>\u0010?J\u0017\u0010@\u001a\u00020\u00142\u0006\u0010\"\u001a\u00020!H\u0002\u00a2\u0006\u0004\u0008@\u0010$R\u0017\u0010\u0006\u001a\u00020\u00058\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0006\u0010A\u001a\u0004\u0008B\u0010CR\u001a\u0010\u0008\u001a\u00020\u00078\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0008\u0010D\u001a\u0004\u0008E\u0010FR\u001a\u0010\n\u001a\u00020\t8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\n\u0010G\u001a\u0004\u0008H\u0010IR\u001a\u0010\u000c\u001a\u00020\u000b8\u0000X\u0080\u0004\u00a2\u0006\u000c\n\u0004\u0008\u000c\u0010J\u001a\u0004\u0008K\u0010LR\u001a\u0010\u000e\u001a\u00020\r8\u0000X\u0080\u0004\u00a2\u0006\u000c\n\u0004\u0008\u000e\u0010M\u001a\u0004\u0008N\u0010OR\u001a\u0010\u0010\u001a\u00020\u000f8\u0000X\u0080\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0010\u0010P\u001a\u0004\u0008Q\u0010 R\u001a\u0010\u0011\u001a\u00020\u000f8\u0000X\u0080\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0011\u0010P\u001a\u0004\u0008R\u0010 R\"\u0010S\u001a\u00020\u000f8\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008S\u0010P\u001a\u0004\u0008T\u0010 \"\u0004\u0008U\u0010VR\u001a\u0010X\u001a\u00020W8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008X\u0010Y\u001a\u0004\u0008Z\u0010[R\u0014\u0010]\u001a\u00020\\8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008]\u0010^R\u0014\u0010`\u001a\u00020_8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008`\u0010aR\u0018\u0010c\u001a\u00060bR\u00020\u00008\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008c\u0010dR$\u0010f\u001a\u0004\u0018\u00010e8\u0016@\u0016X\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008f\u0010g\u001a\u0004\u0008h\u0010i\"\u0004\u0008j\u0010kR\u0016\u0010m\u001a\u00020l8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008m\u0010nR\u0014\u0010p\u001a\u00020o8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008p\u0010qR\u001e\u0010s\u001a\n r*\u0004\u0018\u000107078\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008s\u0010tR\u0014\u0010v\u001a\u00020=8VX\u0096\u0004\u00a2\u0006\u0006\u001a\u0004\u0008u\u0010?\u00a8\u0006x"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;",
        "Ltechnology/cariad/cat/genx/Client;",
        "Ljava/io/Closeable;",
        "Landroid/content/Context;",
        "context",
        "Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;",
        "clientManager",
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "genXDispatcher",
        "Ltechnology/cariad/cat/genx/Antenna;",
        "antenna",
        "Ljava/util/UUID;",
        "serviceID",
        "Landroid/bluetooth/BluetoothDevice;",
        "bluetoothDevice",
        "",
        "bluetoothConnectRetryCount",
        "bluetoothConnectRetryDelay",
        "<init>",
        "(Landroid/content/Context;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ltechnology/cariad/cat/genx/GenXDispatcher;Ltechnology/cariad/cat/genx/Antenna;Ljava/util/UUID;Landroid/bluetooth/BluetoothDevice;II)V",
        "Llx0/b0;",
        "close",
        "()V",
        "connect",
        "disconnect",
        "remove",
        "Ltechnology/cariad/cat/genx/TypedFrame;",
        "typedFrame",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "send",
        "(Ltechnology/cariad/cat/genx/TypedFrame;)Ltechnology/cariad/cat/genx/GenXError;",
        "maximumATTPayloadSize",
        "()I",
        "Ltechnology/cariad/cat/genx/Channel;",
        "channel",
        "discoverChannel",
        "(Ltechnology/cariad/cat/genx/Channel;)V",
        "Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;",
        "channelConfig",
        "enableNotificationsIfNotEnabled$genx_release",
        "(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)V",
        "enableNotificationsIfNotEnabled",
        "",
        "data",
        "onChannelDataReceived$genx_release",
        "(Ltechnology/cariad/cat/genx/Channel;[B)V",
        "onChannelDataReceived",
        "status",
        "onChannelDiscoveryFailed$genx_release",
        "(Ltechnology/cariad/cat/genx/Channel;I)V",
        "onChannelDiscoveryFailed",
        "onDeviceConnected$genx_release",
        "onDeviceConnected",
        "onDeviceDisconnected$genx_release",
        "onDeviceDisconnected",
        "Ljava/time/Instant;",
        "timestamp",
        "",
        "updateAdvertisement$genx_release",
        "(Ltechnology/cariad/cat/genx/TypedFrame;Ljava/time/Instant;)Z",
        "updateAdvertisement",
        "",
        "toString",
        "()Ljava/lang/String;",
        "onChannelDiscovered",
        "Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;",
        "getClientManager",
        "()Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;",
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "getGenXDispatcher",
        "()Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "Ltechnology/cariad/cat/genx/Antenna;",
        "getAntenna",
        "()Ltechnology/cariad/cat/genx/Antenna;",
        "Ljava/util/UUID;",
        "getServiceID$genx_release",
        "()Ljava/util/UUID;",
        "Landroid/bluetooth/BluetoothDevice;",
        "getBluetoothDevice$genx_release",
        "()Landroid/bluetooth/BluetoothDevice;",
        "I",
        "getBluetoothConnectRetryCount$genx_release",
        "getBluetoothConnectRetryDelay$genx_release",
        "currentUsableMtu",
        "getCurrentUsableMtu",
        "setCurrentUsableMtu",
        "(I)V",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "transportType",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "getTransportType",
        "()Ltechnology/cariad/cat/genx/TransportType;",
        "Landroid/os/HandlerThread;",
        "bleManagerHandlerThread",
        "Landroid/os/HandlerThread;",
        "Landroid/os/Handler;",
        "bleManagerHandler",
        "Landroid/os/Handler;",
        "Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;",
        "bleManager",
        "Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;",
        "Ltechnology/cariad/cat/genx/ClientDelegate;",
        "delegate",
        "Ltechnology/cariad/cat/genx/ClientDelegate;",
        "getDelegate",
        "()Ltechnology/cariad/cat/genx/ClientDelegate;",
        "setDelegate",
        "(Ltechnology/cariad/cat/genx/ClientDelegate;)V",
        "Ljava/util/Timer;",
        "advertisementCheckTimer",
        "Ljava/util/Timer;",
        "Ljava/util/concurrent/locks/ReentrantLock;",
        "lastAdvertisementLock",
        "Ljava/util/concurrent/locks/ReentrantLock;",
        "kotlin.jvm.PlatformType",
        "lastAdvertisement",
        "Ljava/time/Instant;",
        "getIdentifier",
        "identifier",
        "Manager",
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


# instance fields
.field private advertisementCheckTimer:Ljava/util/Timer;

.field private final antenna:Ltechnology/cariad/cat/genx/Antenna;

.field private final bleManager:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;

.field private final bleManagerHandler:Landroid/os/Handler;

.field private final bleManagerHandlerThread:Landroid/os/HandlerThread;

.field private final bluetoothConnectRetryCount:I

.field private final bluetoothConnectRetryDelay:I

.field private final bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

.field private final clientManager:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

.field private volatile currentUsableMtu:I

.field private delegate:Ltechnology/cariad/cat/genx/ClientDelegate;

.field private final genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

.field private lastAdvertisement:Ljava/time/Instant;

.field private final lastAdvertisementLock:Ljava/util/concurrent/locks/ReentrantLock;

.field private final serviceID:Ljava/util/UUID;

.field private final transportType:Ltechnology/cariad/cat/genx/TransportType;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;Ltechnology/cariad/cat/genx/GenXDispatcher;Ltechnology/cariad/cat/genx/Antenna;Ljava/util/UUID;Landroid/bluetooth/BluetoothDevice;II)V
    .locals 7

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "clientManager"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "genXDispatcher"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "antenna"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "serviceID"

    .line 22
    .line 23
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v0, "bluetoothDevice"

    .line 27
    .line 28
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->clientManager:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 35
    .line 36
    iput-object p3, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 37
    .line 38
    iput-object p4, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->antenna:Ltechnology/cariad/cat/genx/Antenna;

    .line 39
    .line 40
    iput-object p5, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->serviceID:Ljava/util/UUID;

    .line 41
    .line 42
    iput-object p6, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

    .line 43
    .line 44
    iput p7, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothConnectRetryCount:I

    .line 45
    .line 46
    iput p8, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothConnectRetryDelay:I

    .line 47
    .line 48
    const/16 p2, 0x17

    .line 49
    .line 50
    iput p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->currentUsableMtu:I

    .line 51
    .line 52
    sget-object p2, Ltechnology/cariad/cat/genx/TransportType;->BLE:Ltechnology/cariad/cat/genx/TransportType;

    .line 53
    .line 54
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->transportType:Ltechnology/cariad/cat/genx/TransportType;

    .line 55
    .line 56
    new-instance p2, Landroid/os/HandlerThread;

    .line 57
    .line 58
    const-string p3, "BCManagerHandlerThread"

    .line 59
    .line 60
    invoke-direct {p2, p3}, Landroid/os/HandlerThread;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bleManagerHandlerThread:Landroid/os/HandlerThread;

    .line 64
    .line 65
    new-instance p3, Ljava/util/concurrent/locks/ReentrantLock;

    .line 66
    .line 67
    const/4 p4, 0x1

    .line 68
    invoke-direct {p3, p4}, Ljava/util/concurrent/locks/ReentrantLock;-><init>(Z)V

    .line 69
    .line 70
    .line 71
    iput-object p3, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->lastAdvertisementLock:Ljava/util/concurrent/locks/ReentrantLock;

    .line 72
    .line 73
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 74
    .line 75
    .line 76
    move-result-object p3

    .line 77
    iput-object p3, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->lastAdvertisement:Ljava/time/Instant;

    .line 78
    .line 79
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/n;

    .line 80
    .line 81
    const/4 p3, 0x7

    .line 82
    invoke-direct {v3, p0, p3}, Ltechnology/cariad/cat/genx/bluetooth/n;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 83
    .line 84
    .line 85
    new-instance v0, Lt51/j;

    .line 86
    .line 87
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 88
    .line 89
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v5

    .line 93
    const-string p3, "getName(...)"

    .line 94
    .line 95
    invoke-static {p3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v6

    .line 99
    const-string v1, "GenX"

    .line 100
    .line 101
    const/4 v4, 0x0

    .line 102
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {p2}, Ljava/lang/Thread;->start()V

    .line 109
    .line 110
    .line 111
    new-instance p3, Landroid/os/Handler;

    .line 112
    .line 113
    invoke-virtual {p2}, Landroid/os/HandlerThread;->getLooper()Landroid/os/Looper;

    .line 114
    .line 115
    .line 116
    move-result-object p2

    .line 117
    invoke-direct {p3, p2}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 118
    .line 119
    .line 120
    iput-object p3, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bleManagerHandler:Landroid/os/Handler;

    .line 121
    .line 122
    new-instance p2, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;

    .line 123
    .line 124
    invoke-direct {p2, p0, p1, p3}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/content/Context;Landroid/os/Handler;)V

    .line 125
    .line 126
    .line 127
    new-instance p1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;

    .line 128
    .line 129
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$2$1;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {p2, p1}, Lno/nordicsemi/android/ble/e;->setConnectionObserver(Lb01/b;)V

    .line 133
    .line 134
    .line 135
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bleManager:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;

    .line 136
    .line 137
    new-instance v0, Ljava/util/Timer;

    .line 138
    .line 139
    const-string p1, "BCAdvertisementCheckTimer"

    .line 140
    .line 141
    invoke-direct {v0, p1, p4}, Ljava/util/Timer;-><init>(Ljava/lang/String;Z)V

    .line 142
    .line 143
    .line 144
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$special$$inlined$fixedRateTimer$1;

    .line 145
    .line 146
    invoke-direct {v1, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$special$$inlined$fixedRateTimer$1;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)V

    .line 147
    .line 148
    .line 149
    const-wide/16 v2, 0x9c4

    .line 150
    .line 151
    const-wide/16 v4, 0x9c4

    .line 152
    .line 153
    invoke-virtual/range {v0 .. v5}, Ljava/util/Timer;->scheduleAtFixedRate(Ljava/util/TimerTask;JJ)V

    .line 154
    .line 155
    .line 156
    iput-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->advertisementCheckTimer:Ljava/util/Timer;

    .line 157
    .line 158
    return-void
.end method

.method public static synthetic A0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->disconnect$lambda$0$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic B(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->enableNotificationsIfNotEnabled$lambda$1(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic B0(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/Channel;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onChannelDiscovered$lambda$1$0(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/Channel;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic C0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->connect$lambda$0$1(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic D0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->close$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic E(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onChannelDiscovered$lambda$0(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic E0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->disconnect$lambda$0$1(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic F0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onChannelDataReceived$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic G0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->connect$lambda$0$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic H(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/TypedFrame;Ljava/util/UUID;Landroid/bluetooth/BluetoothDevice;I)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->send$lambda$0$1(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/TypedFrame;Ljava/util/UUID;Landroid/bluetooth/BluetoothDevice;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic H0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;I)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->connect$lambda$0$2(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic I0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/TypedFrame;Ljava/util/UUID;Landroid/bluetooth/BluetoothDevice;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->send$lambda$0$2(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/TypedFrame;Ljava/util/UUID;Landroid/bluetooth/BluetoothDevice;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic J0(Ltechnology/cariad/cat/genx/TypedFrame;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->send$lambda$1(Ltechnology/cariad/cat/genx/TypedFrame;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic K0(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onChannelDiscoveryFailed$lambda$1$0(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic L0(Ltechnology/cariad/cat/genx/TypedFrame;Landroid/bluetooth/BluetoothDevice;Ljava/util/UUID;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->send$lambda$0$2$0(Ltechnology/cariad/cat/genx/TypedFrame;Landroid/bluetooth/BluetoothDevice;Ljava/util/UUID;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic M(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;Ltechnology/cariad/cat/genx/TypedFrame;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->send$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;Ltechnology/cariad/cat/genx/TypedFrame;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic M0(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/Channel;[B)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onChannelDataReceived$lambda$1$0(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/Channel;[B)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic N0(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/TypedFrame;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->updateAdvertisement$lambda$1$0(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/TypedFrame;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic O0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onDeviceDisconnected$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic P0(Ltechnology/cariad/cat/genx/Channel;ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->enableNotificationsIfNotEnabled$lambda$0$2$0(Ltechnology/cariad/cat/genx/Channel;ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic Q0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onChannelDiscovered$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic R0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;Ltechnology/cariad/cat/genx/Channel;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->enableNotificationsIfNotEnabled$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;Ltechnology/cariad/cat/genx/Channel;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic T(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)V
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->connect$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic U(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->enableNotificationsIfNotEnabled$lambda$0$0(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic V(Ltechnology/cariad/cat/genx/TypedFrame;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ljava/util/UUID;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->send$lambda$0$0(Ltechnology/cariad/cat/genx/TypedFrame;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ljava/util/UUID;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic W(ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->connect$lambda$0$2$0(Landroid/bluetooth/BluetoothDevice;I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final _init_$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "init(): Bluetooth Client created "

    .line 8
    .line 9
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public static synthetic a(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;Ltechnology/cariad/cat/genx/Channel;Landroid/bluetooth/BluetoothDevice;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->enableNotificationsIfNotEnabled$lambda$0$1(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;Ltechnology/cariad/cat/genx/Channel;Landroid/bluetooth/BluetoothDevice;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static final synthetic access$getLastAdvertisement$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/time/Instant;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->lastAdvertisement:Ljava/time/Instant;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getLastAdvertisementLock$p(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/util/concurrent/locks/ReentrantLock;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->lastAdvertisementLock:Ljava/util/concurrent/locks/ReentrantLock;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic b()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onDeviceConnected$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final close$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getIdentifier()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "close(): "

    .line 6
    .line 7
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method private static final connect$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/n;

    .line 2
    .line 3
    const/4 v0, 0x5

    .line 4
    invoke-direct {v3, p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/n;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

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
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bleManager:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;

    .line 31
    .line 32
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

    .line 33
    .line 34
    invoke-virtual {v0, v1}, Lno/nordicsemi/android/ble/e;->connect(Landroid/bluetooth/BluetoothDevice;)Lno/nordicsemi/android/ble/x;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    iget v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothConnectRetryCount:I

    .line 39
    .line 40
    iget v2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothConnectRetryDelay:I

    .line 41
    .line 42
    iput v1, v0, Lno/nordicsemi/android/ble/x;->s:I

    .line 43
    .line 44
    iput v2, v0, Lno/nordicsemi/android/ble/x;->t:I

    .line 45
    .line 46
    const/4 v1, 0x0

    .line 47
    iput-boolean v1, v0, Lno/nordicsemi/android/ble/x;->u:Z

    .line 48
    .line 49
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/o;

    .line 50
    .line 51
    const/4 v2, 0x1

    .line 52
    invoke-direct {v1, p0, v2}, Ltechnology/cariad/cat/genx/bluetooth/o;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 53
    .line 54
    .line 55
    iput-object v1, v0, Lno/nordicsemi/android/ble/i0;->g:Lyz0/d;

    .line 56
    .line 57
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/o;

    .line 58
    .line 59
    const/4 v2, 0x2

    .line 60
    invoke-direct {v1, p0, v2}, Ltechnology/cariad/cat/genx/bluetooth/o;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 61
    .line 62
    .line 63
    iput-object v1, v0, Lno/nordicsemi/android/ble/i0;->h:Lyz0/c;

    .line 64
    .line 65
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/p0;->f()V

    .line 66
    .line 67
    .line 68
    return-void
.end method

.method private static final connect$lambda$0$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "connect(): Connecting to device \'"

    .line 8
    .line 9
    const-string v1, "\'..."

    .line 10
    .line 11
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final connect$lambda$0$1(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;)V
    .locals 8

    .line 1
    const-string v0, "device"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/c;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-direct {v4, v0, p1}, Ltechnology/cariad/cat/genx/bluetooth/c;-><init>(ILandroid/bluetooth/BluetoothDevice;)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string p0, "getName(...)"

    .line 19
    .line 20
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    const-string v2, "GenX"

    .line 25
    .line 26
    sget-object v3, Lt51/f;->a:Lt51/f;

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method private static final connect$lambda$0$1$0(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    const-string v0, "connect(): Successfully connected to device \'"

    .line 9
    .line 10
    const-string v1, "\'"

    .line 11
    .line 12
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method private static final connect$lambda$0$2(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;I)V
    .locals 8

    .line 1
    const-string v0, "device"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/i;

    .line 7
    .line 8
    const/4 v0, 0x2

    .line 9
    invoke-direct {v4, p2, v0, p1}, Ltechnology/cariad/cat/genx/bluetooth/i;-><init>(IILandroid/bluetooth/BluetoothDevice;)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string p0, "getName(...)"

    .line 19
    .line 20
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    const-string v2, "GenX"

    .line 25
    .line 26
    sget-object v3, Lt51/e;->a:Lt51/e;

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method private static final connect$lambda$0$2$0(Landroid/bluetooth/BluetoothDevice;I)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getFailReasonDescription(I)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    const-string v0, "connect(): Failed to connect to device \'"

    .line 13
    .line 14
    const-string v1, "\' with status = "

    .line 15
    .line 16
    invoke-static {v0, p0, v1, p1}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public static synthetic d(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->discoverChannel$lambda$0(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final disconnect$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/n;

    .line 2
    .line 3
    const/4 v0, 0x6

    .line 4
    invoke-direct {v3, p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/n;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

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
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bleManager:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;

    .line 31
    .line 32
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/e;->disconnect()Lno/nordicsemi/android/ble/a0;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/o;

    .line 37
    .line 38
    const/4 v2, 0x3

    .line 39
    invoke-direct {v1, p0, v2}, Ltechnology/cariad/cat/genx/bluetooth/o;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 40
    .line 41
    .line 42
    iput-object v1, v0, Lno/nordicsemi/android/ble/i0;->g:Lyz0/d;

    .line 43
    .line 44
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/o;

    .line 45
    .line 46
    const/4 v2, 0x4

    .line 47
    invoke-direct {v1, p0, v2}, Ltechnology/cariad/cat/genx/bluetooth/o;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 48
    .line 49
    .line 50
    iput-object v1, v0, Lno/nordicsemi/android/ble/i0;->h:Lyz0/c;

    .line 51
    .line 52
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/p0;->f()V

    .line 53
    .line 54
    .line 55
    return-void
.end method

.method private static final disconnect$lambda$0$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "disconnect(): Disconnecting from device \'"

    .line 8
    .line 9
    const-string v1, "\'..."

    .line 10
    .line 11
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final disconnect$lambda$0$1(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;)V
    .locals 8

    .line 1
    const-string v0, "device"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/c;

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    invoke-direct {v4, v0, p1}, Ltechnology/cariad/cat/genx/bluetooth/c;-><init>(ILandroid/bluetooth/BluetoothDevice;)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string p0, "getName(...)"

    .line 19
    .line 20
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    const-string v2, "GenX"

    .line 25
    .line 26
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method private static final disconnect$lambda$0$1$0(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    const-string v0, "disconnect(): Successfully disconnected device \'"

    .line 9
    .line 10
    const-string v1, "\'"

    .line 11
    .line 12
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method private static final disconnect$lambda$0$2(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;I)V
    .locals 8

    .line 1
    const-string v0, "device"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/i;

    .line 7
    .line 8
    const/4 v0, 0x3

    .line 9
    invoke-direct {v4, p2, v0, p1}, Ltechnology/cariad/cat/genx/bluetooth/i;-><init>(IILandroid/bluetooth/BluetoothDevice;)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string p0, "getName(...)"

    .line 19
    .line 20
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    const-string v2, "GenX"

    .line 25
    .line 26
    sget-object v3, Lt51/e;->a:Lt51/e;

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method private static final disconnect$lambda$0$2$0(Landroid/bluetooth/BluetoothDevice;I)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getFailReasonDescription(I)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    const-string v0, "disconnect(): Failed to disconnect device \'"

    .line 13
    .line 14
    const-string v1, "\' with status = "

    .line 15
    .line 16
    invoke-static {v0, p0, v1, p1}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method private static final discoverChannel$lambda$0(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p1, p1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v1, "discoverChannel(): Channel \'"

    .line 10
    .line 11
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p0, "\' has not be discovered yet -> Wait for service discovery to complete - device = "

    .line 18
    .line 19
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method private static final discoverChannel$lambda$1(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p1, p1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v1, "discoverChannel(): Channel \'"

    .line 10
    .line 11
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p0, "\' has been discovered already -> Enabled notifications if not enabled - device = "

    .line 18
    .line 19
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static synthetic e0(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->disconnect$lambda$0$1$0(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final enableNotificationsIfNotEnabled$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;Ltechnology/cariad/cat/genx/Channel;)V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/a;

    .line 2
    .line 3
    const/4 v0, 0x3

    .line 4
    invoke-direct {v3, p2, p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/a;-><init>(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

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
    sget-object v2, Lt51/f;->a:Lt51/f;

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
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bleManager:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;

    .line 31
    .line 32
    invoke-virtual {v0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->enableNotifications(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)Lno/nordicsemi/android/ble/v0;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    new-instance v1, Lbb/i;

    .line 37
    .line 38
    const/16 v2, 0xa

    .line 39
    .line 40
    invoke-direct {v1, p0, p1, p2, v2}, Lbb/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 41
    .line 42
    .line 43
    iput-object v1, v0, Lno/nordicsemi/android/ble/i0;->g:Lyz0/d;

    .line 44
    .line 45
    new-instance p1, Ltechnology/cariad/cat/genx/bluetooth/l;

    .line 46
    .line 47
    invoke-direct {p1, p0, p2}, Ltechnology/cariad/cat/genx/bluetooth/l;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    iput-object p1, v0, Lno/nordicsemi/android/ble/i0;->h:Lyz0/c;

    .line 51
    .line 52
    invoke-virtual {v0}, Lno/nordicsemi/android/ble/p0;->f()V

    .line 53
    .line 54
    .line 55
    return-void
.end method

.method private static final enableNotificationsIfNotEnabled$lambda$0$0(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p1, p1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v1, "enableNotificationsIfNotEnabled(): Notifications for channel \'"

    .line 10
    .line 11
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p0, "\' not enabled. -> Enable notifications - device = "

    .line 18
    .line 19
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method private static final enableNotificationsIfNotEnabled$lambda$0$1(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;Ltechnology/cariad/cat/genx/Channel;Landroid/bluetooth/BluetoothDevice;)V
    .locals 8

    .line 1
    const-string v0, "it"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/d;

    .line 7
    .line 8
    const/4 p3, 0x0

    .line 9
    invoke-direct {v4, p2, p3}, Ltechnology/cariad/cat/genx/bluetooth/d;-><init>(Ljava/lang/Object;I)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string p3, "getName(...)"

    .line 19
    .line 20
    invoke-static {p3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    const-string v2, "GenX"

    .line 25
    .line 26
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 27
    .line 28
    const/4 v5, 0x0

    .line 29
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->enabledNotifications$genx_release()V

    .line 36
    .line 37
    .line 38
    invoke-direct {p0, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onChannelDiscovered(Ltechnology/cariad/cat/genx/Channel;)V

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method private static final enableNotificationsIfNotEnabled$lambda$0$1$0(Ltechnology/cariad/cat/genx/Channel;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "enableNotificationsIfNotEnabled(): Successfully enabled notifications for channel \'"

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
    const-string p0, "\'"

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method private static final enableNotificationsIfNotEnabled$lambda$0$2(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/Channel;Landroid/bluetooth/BluetoothDevice;I)V
    .locals 8

    .line 1
    const-string v0, "device"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/e;

    .line 7
    .line 8
    invoke-direct {v4, p1, p3, p2}, Ltechnology/cariad/cat/genx/bluetooth/e;-><init>(Ltechnology/cariad/cat/genx/Channel;ILandroid/bluetooth/BluetoothDevice;)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Lt51/j;

    .line 12
    .line 13
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v6

    .line 17
    const-string p2, "getName(...)"

    .line 18
    .line 19
    invoke-static {p2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v7

    .line 23
    const-string v2, "GenX"

    .line 24
    .line 25
    sget-object v3, Lt51/e;->a:Lt51/e;

    .line 26
    .line 27
    const/4 v5, 0x0

    .line 28
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0, p1, p3}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onChannelDiscoveryFailed$genx_release(Ltechnology/cariad/cat/genx/Channel;I)V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method private static final enableNotificationsIfNotEnabled$lambda$0$2$0(Ltechnology/cariad/cat/genx/Channel;ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getFailReasonDescription(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-static {p2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    invoke-static {p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p2

    .line 12
    new-instance v0, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v1, "enableNotificationsIfNotEnabled(): Failed to enable notifications for channel \'"

    .line 15
    .line 16
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const-string p0, "\' with status = "

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string p0, ". - device = "

    .line 31
    .line 32
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method

.method private static final enableNotificationsIfNotEnabled$lambda$1(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p1, p1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v1, "enableNotificationsIfNotEnabled(): Channel \'"

    .line 10
    .line 11
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p0, "\' already discovered. -> Ignore - device = "

    .line 18
    .line 19
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static synthetic f(ILandroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p1, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->disconnect$lambda$0$2$0(Landroid/bluetooth/BluetoothDevice;I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onDeviceDisconnected$lambda$0$0(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic h(Ltechnology/cariad/cat/genx/ClientDelegate;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onDeviceConnected$lambda$0$0(Ltechnology/cariad/cat/genx/ClientDelegate;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic h0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->_init_$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic j(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/Channel;Landroid/bluetooth/BluetoothDevice;I)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->enableNotificationsIfNotEnabled$lambda$0$2(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/Channel;Landroid/bluetooth/BluetoothDevice;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic k(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onChannelDiscoveryFailed$lambda$0(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->updateAdvertisement$lambda$2$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic l()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onChannelDiscoveryFailed$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic l0(Ltechnology/cariad/cat/genx/Channel;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->enableNotificationsIfNotEnabled$lambda$0$1$0(Ltechnology/cariad/cat/genx/Channel;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic n0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)V
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->disconnect$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static final onChannelDataReceived$lambda$0([BLtechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p2, p2, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

    .line 6
    .line 7
    invoke-static {p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p2

    .line 11
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v1, "onChannelDataReceived(): Received data \'"

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string p0, "\' on channel \'"

    .line 22
    .line 23
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string p0, "\' - device = "

    .line 30
    .line 31
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0
.end method

.method private static final onChannelDataReceived$lambda$1$0(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/Channel;[B)Llx0/b0;
    .locals 1

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/TypedFrame;

    .line 2
    .line 3
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->toType(Ltechnology/cariad/cat/genx/Channel;)Ltechnology/cariad/cat/genx/TypedFrameType;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-direct {v0, p1, p2}, Ltechnology/cariad/cat/genx/TypedFrame;-><init>(Ltechnology/cariad/cat/genx/TypedFrameType;[B)V

    .line 8
    .line 9
    .line 10
    invoke-interface {p0, v0}, Ltechnology/cariad/cat/genx/ClientDelegate;->onClientReceivedTypedFrame(Ltechnology/cariad/cat/genx/TypedFrame;)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0
.end method

.method private static final onChannelDataReceived$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onChannelDataReceived(): No delegate"

    .line 2
    .line 3
    return-object v0
.end method

.method private final onChannelDiscovered(Ltechnology/cariad/cat/genx/Channel;)V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/a;

    .line 2
    .line 3
    const/4 v0, 0x2

    .line 4
    invoke-direct {v3, p1, p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/a;-><init>(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

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
    sget-object v2, Lt51/f;->a:Lt51/f;

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
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getDelegate()Ltechnology/cariad/cat/genx/ClientDelegate;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    if-eqz v0, :cond_0

    .line 35
    .line 36
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/b;

    .line 41
    .line 42
    const/4 v2, 0x0

    .line 43
    invoke-direct {v1, v0, p1, v2}, Ltechnology/cariad/cat/genx/bluetooth/b;-><init>(Ljava/io/Closeable;Ljava/lang/Object;I)V

    .line 44
    .line 45
    .line 46
    invoke-interface {p0, v1}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_0
    new-instance p1, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 51
    .line 52
    const/16 v0, 0x10

    .line 53
    .line 54
    invoke-direct {p1, v0}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 55
    .line 56
    .line 57
    const/4 v0, 0x0

    .line 58
    const-string v1, "GenX"

    .line 59
    .line 60
    invoke-static {p0, v1, v0, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 61
    .line 62
    .line 63
    return-void
.end method

.method private static final onChannelDiscovered$lambda$0(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p1, p1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v1, "onChannelDiscovered(): \'"

    .line 10
    .line 11
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p0, "\' - device = "

    .line 18
    .line 19
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method private static final onChannelDiscovered$lambda$1$0(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/Channel;)Llx0/b0;
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    const-string v1, ""

    .line 3
    .line 4
    invoke-interface {p0, p1, v0, v1}, Ltechnology/cariad/cat/genx/ClientDelegate;->onClientDiscoveredChannel(Ltechnology/cariad/cat/genx/Channel;ZLjava/lang/String;)V

    .line 5
    .line 6
    .line 7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    return-object p0
.end method

.method private static final onChannelDiscovered$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onChannelDiscovered(): No delegate"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onChannelDiscoveryFailed$lambda$0(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p1, p1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v1, "onChannelDiscoveryFailed(): \'"

    .line 10
    .line 11
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p0, "\' - device = "

    .line 18
    .line 19
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string p0, " - status = "

    .line 26
    .line 27
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method

.method private static final onChannelDiscoveryFailed$lambda$1$0(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)Llx0/b0;
    .locals 2

    .line 1
    iget-object p2, p2, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    invoke-static {p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v1, "Channel discovery failed for device = \'"

    .line 10
    .line 11
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p2, "\' with status code "

    .line 18
    .line 19
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p2

    .line 29
    const/4 p3, 0x0

    .line 30
    invoke-interface {p0, p1, p3, p2}, Ltechnology/cariad/cat/genx/ClientDelegate;->onClientDiscoveredChannel(Ltechnology/cariad/cat/genx/Channel;ZLjava/lang/String;)V

    .line 31
    .line 32
    .line 33
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    return-object p0
.end method

.method private static final onChannelDiscoveryFailed$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onChannelDiscoveryFailed(): No delegate"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onDeviceConnected$lambda$0$0(Ltechnology/cariad/cat/genx/ClientDelegate;)Llx0/b0;
    .locals 0

    .line 1
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/ClientDelegate;->onClientConnected()V

    .line 2
    .line 3
    .line 4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    return-object p0
.end method

.method private static final onDeviceConnected$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "updateAdvertisement(): No delegate"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onDeviceDisconnected$lambda$0$0(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Llx0/b0;
    .locals 0

    .line 1
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/ClientDelegate;->onClientDisconnected()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->clientManager:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->deviceDisconnected$genx_release(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method private static final onDeviceDisconnected$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "updateAdvertisement(): No delegate"

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic q(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->connect$lambda$0$1$0(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic q0([BLtechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onChannelDataReceived$lambda$0([BLtechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic r0(Ltechnology/cariad/cat/genx/TypedFrame;Landroid/bluetooth/BluetoothDevice;ILjava/util/UUID;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->send$lambda$0$1$0(Ltechnology/cariad/cat/genx/TypedFrame;Landroid/bluetooth/BluetoothDevice;ILjava/util/UUID;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final send$lambda$0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;Ltechnology/cariad/cat/genx/TypedFrame;)V
    .locals 8

    .line 1
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/g;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-direct {v4, p2, p0, v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Lt51/j;

    .line 12
    .line 13
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v6

    .line 17
    const-string v2, "getName(...)"

    .line 18
    .line 19
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v7

    .line 23
    const-string v2, "GenX"

    .line 24
    .line 25
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 26
    .line 27
    const/4 v5, 0x0

    .line 28
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 32
    .line 33
    .line 34
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bleManager:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;

    .line 35
    .line 36
    invoke-virtual {p2}, Ltechnology/cariad/cat/genx/TypedFrame;->getPayload()[B

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    invoke-virtual {v1, p1, v2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->sendData(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;[B)Lno/nordicsemi/android/ble/v0;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/h;

    .line 45
    .line 46
    invoke-direct {v1, p2, p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/h;-><init>(Ltechnology/cariad/cat/genx/TypedFrame;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ljava/util/UUID;)V

    .line 47
    .line 48
    .line 49
    iput-object v1, p1, Lno/nordicsemi/android/ble/i0;->h:Lyz0/c;

    .line 50
    .line 51
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/h;

    .line 52
    .line 53
    invoke-direct {v1, p2, p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/h;-><init>(Ltechnology/cariad/cat/genx/TypedFrame;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ljava/util/UUID;)V

    .line 54
    .line 55
    .line 56
    iput-object v1, p1, Lno/nordicsemi/android/ble/i0;->g:Lyz0/d;

    .line 57
    .line 58
    invoke-virtual {p1}, Lno/nordicsemi/android/ble/p0;->f()V

    .line 59
    .line 60
    .line 61
    return-void
.end method

.method private static final send$lambda$0$0(Ltechnology/cariad/cat/genx/TypedFrame;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ljava/util/UUID;)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/TypedFrame;->getPayload()[B

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/TypedFrame;->getType()Ltechnology/cariad/cat/genx/TypedFrameType;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    iget-object p1, p1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

    .line 14
    .line 15
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    new-instance v1, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    const-string v2, "send(): Sending \'"

    .line 22
    .line 23
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v0, "\' of type \'"

    .line 30
    .line 31
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const-string p0, "\' to device \'"

    .line 38
    .line 39
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string p0, "\' (uuid: "

    .line 46
    .line 47
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string p0, ")"

    .line 54
    .line 55
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0
.end method

.method private static final send$lambda$0$1(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/TypedFrame;Ljava/util/UUID;Landroid/bluetooth/BluetoothDevice;I)V
    .locals 8

    .line 1
    const-string v0, "device"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lh2/w4;

    .line 7
    .line 8
    const/4 v3, 0x3

    .line 9
    move-object v4, p1

    .line 10
    move-object v6, p2

    .line 11
    move-object v5, p3

    .line 12
    move v2, p4

    .line 13
    invoke-direct/range {v1 .. v6}, Lh2/w4;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    new-instance p1, Lt51/j;

    .line 17
    .line 18
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v6

    .line 22
    const-string p0, "getName(...)"

    .line 23
    .line 24
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v7

    .line 28
    const-string v2, "GenX"

    .line 29
    .line 30
    sget-object v3, Lt51/e;->a:Lt51/e;

    .line 31
    .line 32
    const/4 v5, 0x0

    .line 33
    move-object v4, v1

    .line 34
    move-object v1, p1

    .line 35
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method private static final send$lambda$0$1$0(Ltechnology/cariad/cat/genx/TypedFrame;Landroid/bluetooth/BluetoothDevice;ILjava/util/UUID;)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/TypedFrame;->getPayload()[B

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/TypedFrame;->getType()Ltechnology/cariad/cat/genx/TypedFrameType;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-static {p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getFailReasonDescription(I)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    new-instance v1, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    const-string v2, "send(): Failed to send \'"

    .line 27
    .line 28
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const-string v0, "\' of type \'"

    .line 35
    .line 36
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string p0, "\' to device \'"

    .line 43
    .line 44
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string p0, "\' with status = "

    .line 48
    .line 49
    const-string v0, " (uuid: "

    .line 50
    .line 51
    invoke-static {v1, p1, p0, p2, v0}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    const-string p0, ")"

    .line 58
    .line 59
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0
.end method

.method private static final send$lambda$0$2(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Ltechnology/cariad/cat/genx/TypedFrame;Ljava/util/UUID;Landroid/bluetooth/BluetoothDevice;)V
    .locals 8

    .line 1
    const-string v0, "device"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Lc41/b;

    .line 7
    .line 8
    const/16 v0, 0x1d

    .line 9
    .line 10
    invoke-direct {v4, p1, p3, p2, v0}, Lc41/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 11
    .line 12
    .line 13
    new-instance v1, Lt51/j;

    .line 14
    .line 15
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v6

    .line 19
    const-string p0, "getName(...)"

    .line 20
    .line 21
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v7

    .line 25
    const-string v2, "GenX"

    .line 26
    .line 27
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 28
    .line 29
    const/4 v5, 0x0

    .line 30
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 34
    .line 35
    .line 36
    return-void
.end method

.method private static final send$lambda$0$2$0(Ltechnology/cariad/cat/genx/TypedFrame;Landroid/bluetooth/BluetoothDevice;Ljava/util/UUID;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/TypedFrame;->getType()Ltechnology/cariad/cat/genx/TypedFrameType;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    new-instance v0, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v1, "send(): Successfully sent data of type \'"

    .line 15
    .line 16
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const-string p0, "\' to device \'"

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string p0, "\' (uuid: "

    .line 31
    .line 32
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    const-string p0, ")"

    .line 39
    .line 40
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0
.end method

.method private static final send$lambda$1(Ltechnology/cariad/cat/genx/TypedFrame;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/TypedFrame;->getPayload()[B

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/TypedFrame;->getType()Ltechnology/cariad/cat/genx/TypedFrameType;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    iget-object p1, p1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

    .line 14
    .line 15
    invoke-static {p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->getInfo(Landroid/bluetooth/BluetoothDevice;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    new-instance v1, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    const-string v2, "send(): Failed to send \'"

    .line 22
    .line 23
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v0, "\' of type \'"

    .line 30
    .line 31
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const-string p0, "\' to device \'"

    .line 38
    .line 39
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string p0, "\' because channel has not been found"

    .line 43
    .line 44
    invoke-static {v1, p1, p0}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method

.method private static final updateAdvertisement$lambda$0$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "updateAdvertisement(): Do not update outdated advertisements"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final updateAdvertisement$lambda$1$0(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/TypedFrame;)Llx0/b0;
    .locals 0

    .line 1
    invoke-interface {p0, p1}, Ltechnology/cariad/cat/genx/ClientDelegate;->onClientReceivedTypedFrame(Ltechnology/cariad/cat/genx/TypedFrame;)V

    .line 2
    .line 3
    .line 4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    return-object p0
.end method

.method private static final updateAdvertisement$lambda$2$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "updateAdvertisement(): No delegate"

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic x0(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->discoverChannel$lambda$1(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic y0(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;I)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->disconnect$lambda$0$2(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;Landroid/bluetooth/BluetoothDevice;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic z0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->updateAdvertisement$lambda$0$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method


# virtual methods
.method public close()V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/bluetooth/n;

    .line 2
    .line 3
    const/4 v0, 0x4

    .line 4
    invoke-direct {v3, p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/n;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

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
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bleManager:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;

    .line 31
    .line 32
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->close()V

    .line 33
    .line 34
    .line 35
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->advertisementCheckTimer:Ljava/util/Timer;

    .line 36
    .line 37
    invoke-virtual {v0}, Ljava/util/Timer;->cancel()V

    .line 38
    .line 39
    .line 40
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->advertisementCheckTimer:Ljava/util/Timer;

    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/util/Timer;->purge()I

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bleManagerHandlerThread:Landroid/os/HandlerThread;

    .line 46
    .line 47
    invoke-virtual {p0}, Landroid/os/HandlerThread;->quitSafely()Z

    .line 48
    .line 49
    .line 50
    return-void
.end method

.method public connect()V
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bleManagerHandler:Landroid/os/Handler;

    .line 2
    .line 3
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/f;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v1, p0, v2}, Ltechnology/cariad/cat/genx/bluetooth/f;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public disconnect()V
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bleManagerHandler:Landroid/os/Handler;

    .line 2
    .line 3
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/f;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    invoke-direct {v1, p0, v2}, Ltechnology/cariad/cat/genx/bluetooth/f;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public discoverChannel(Ltechnology/cariad/cat/genx/Channel;)V
    .locals 9

    .line 1
    const-string v0, "channel"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bleManager:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->channelConfig(Ltechnology/cariad/cat/genx/Channel;)Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    const-string v1, "getName(...)"

    .line 13
    .line 14
    sget-object v4, Lt51/f;->a:Lt51/f;

    .line 15
    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    new-instance v5, Ltechnology/cariad/cat/genx/bluetooth/a;

    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    invoke-direct {v5, p1, p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/a;-><init>(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 22
    .line 23
    .line 24
    new-instance v2, Lt51/j;

    .line 25
    .line 26
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v7

    .line 30
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v8

    .line 34
    const-string v3, "GenX"

    .line 35
    .line 36
    const/4 v6, 0x0

    .line 37
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 41
    .line 42
    .line 43
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bleManager:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;

    .line 44
    .line 45
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->discoverChannel(Ltechnology/cariad/cat/genx/Channel;)V

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :cond_0
    new-instance v5, Ltechnology/cariad/cat/genx/bluetooth/a;

    .line 50
    .line 51
    const/4 v2, 0x1

    .line 52
    invoke-direct {v5, p1, p0, v2}, Ltechnology/cariad/cat/genx/bluetooth/a;-><init>(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 53
    .line 54
    .line 55
    new-instance v2, Lt51/j;

    .line 56
    .line 57
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v7

    .line 61
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v8

    .line 65
    const-string v3, "GenX"

    .line 66
    .line 67
    const/4 v6, 0x0

    .line 68
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->enableNotificationsIfNotEnabled$genx_release(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)V

    .line 75
    .line 76
    .line 77
    return-void
.end method

.method public final enableNotificationsIfNotEnabled$genx_release(Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;)V
    .locals 11

    .line 1
    const-string v0, "channelConfig"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->getChannel()Ltechnology/cariad/cat/genx/Channel;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;->getNotifyCharacteristicEnabled()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bleManagerHandler:Landroid/os/Handler;

    .line 17
    .line 18
    new-instance v2, La8/y0;

    .line 19
    .line 20
    const/16 v3, 0x14

    .line 21
    .line 22
    invoke-direct {v2, p0, p1, v0, v3}, La8/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v1, v2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :cond_0
    new-instance v7, Ltechnology/cariad/cat/genx/bluetooth/a;

    .line 30
    .line 31
    const/4 p1, 0x4

    .line 32
    invoke-direct {v7, v0, p0, p1}, Ltechnology/cariad/cat/genx/bluetooth/a;-><init>(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 33
    .line 34
    .line 35
    new-instance v4, Lt51/j;

    .line 36
    .line 37
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v9

    .line 41
    const-string p1, "getName(...)"

    .line 42
    .line 43
    invoke-static {p1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v10

    .line 47
    const-string v5, "GenX"

    .line 48
    .line 49
    sget-object v6, Lt51/d;->a:Lt51/d;

    .line 50
    .line 51
    const/4 v8, 0x0

    .line 52
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 56
    .line 57
    .line 58
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->onChannelDiscovered(Ltechnology/cariad/cat/genx/Channel;)V

    .line 59
    .line 60
    .line 61
    return-void
.end method

.method public getAntenna()Ltechnology/cariad/cat/genx/Antenna;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->antenna:Ltechnology/cariad/cat/genx/Antenna;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getBluetoothConnectRetryCount$genx_release()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothConnectRetryCount:I

    .line 2
    .line 3
    return p0
.end method

.method public final getBluetoothConnectRetryDelay$genx_release()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothConnectRetryDelay:I

    .line 2
    .line 3
    return p0
.end method

.method public final getBluetoothDevice$genx_release()Landroid/bluetooth/BluetoothDevice;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getClientManager()Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->clientManager:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCurrentUsableMtu()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->currentUsableMtu:I

    .line 2
    .line 3
    return p0
.end method

.method public getDelegate()Ltechnology/cariad/cat/genx/ClientDelegate;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->delegate:Ltechnology/cariad/cat/genx/ClientDelegate;

    .line 2
    .line 3
    return-object p0
.end method

.method public getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 2
    .line 3
    return-object p0
.end method

.method public getIdentifier()Ljava/lang/String;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/bluetooth/BluetoothDevice;->getAddress()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "getAddress(...)"

    .line 8
    .line 9
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method

.method public final getServiceID$genx_release()Ljava/util/UUID;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->serviceID:Ljava/util/UUID;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTransportType()Ltechnology/cariad/cat/genx/TransportType;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->transportType:Ltechnology/cariad/cat/genx/TransportType;

    .line 2
    .line 3
    return-object p0
.end method

.method public maximumATTPayloadSize()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->currentUsableMtu:I

    .line 2
    .line 3
    return p0
.end method

.method public final onChannelDataReceived$genx_release(Ltechnology/cariad/cat/genx/Channel;[B)V
    .locals 8

    .line 1
    const-string v0, "channel"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "data"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v4, Lc41/b;

    .line 12
    .line 13
    const/16 v0, 0x1b

    .line 14
    .line 15
    invoke-direct {v4, p2, p1, p0, v0}, Lc41/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 16
    .line 17
    .line 18
    new-instance v1, Lt51/j;

    .line 19
    .line 20
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v6

    .line 24
    const-string v0, "getName(...)"

    .line 25
    .line 26
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v7

    .line 30
    const-string v2, "GenX"

    .line 31
    .line 32
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 33
    .line 34
    const/4 v5, 0x0

    .line 35
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getDelegate()Ltechnology/cariad/cat/genx/ClientDelegate;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    if-eqz v0, :cond_0

    .line 46
    .line 47
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    new-instance v1, Lc41/b;

    .line 52
    .line 53
    const/16 v2, 0x1c

    .line 54
    .line 55
    invoke-direct {v1, v0, p1, p2, v2}, Lc41/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 56
    .line 57
    .line 58
    invoke-interface {p0, v1}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 59
    .line 60
    .line 61
    return-void

    .line 62
    :cond_0
    new-instance p1, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 63
    .line 64
    const/16 p2, 0x12

    .line 65
    .line 66
    invoke-direct {p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 67
    .line 68
    .line 69
    const/4 p2, 0x0

    .line 70
    const-string v0, "GenX"

    .line 71
    .line 72
    invoke-static {p0, v0, p2, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 73
    .line 74
    .line 75
    return-void
.end method

.method public final onChannelDiscoveryFailed$genx_release(Ltechnology/cariad/cat/genx/Channel;I)V
    .locals 8

    .line 1
    const-string v0, "channel"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/bluetooth/e;

    .line 7
    .line 8
    invoke-direct {v4, p1, p0, p2}, Ltechnology/cariad/cat/genx/bluetooth/e;-><init>(Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Lt51/j;

    .line 12
    .line 13
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v6

    .line 17
    const-string v0, "getName(...)"

    .line 18
    .line 19
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v7

    .line 23
    const-string v2, "GenX"

    .line 24
    .line 25
    sget-object v3, Lt51/f;->a:Lt51/f;

    .line 26
    .line 27
    const/4 v5, 0x0

    .line 28
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getDelegate()Ltechnology/cariad/cat/genx/ClientDelegate;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    if-eqz v0, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    new-instance v2, Lh2/w4;

    .line 45
    .line 46
    invoke-direct {v2, v0, p1, p0, p2}, Lh2/w4;-><init>(Ltechnology/cariad/cat/genx/ClientDelegate;Ltechnology/cariad/cat/genx/Channel;Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;I)V

    .line 47
    .line 48
    .line 49
    invoke-interface {v1, v2}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 50
    .line 51
    .line 52
    return-void

    .line 53
    :cond_0
    new-instance p1, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 54
    .line 55
    const/16 p2, 0x15

    .line 56
    .line 57
    invoke-direct {p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 58
    .line 59
    .line 60
    const/4 p2, 0x0

    .line 61
    const-string v0, "GenX"

    .line 62
    .line 63
    invoke-static {p0, v0, p2, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 64
    .line 65
    .line 66
    return-void
.end method

.method public final onDeviceConnected$genx_release()V
    .locals 3

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getDelegate()Ltechnology/cariad/cat/genx/ClientDelegate;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/d;

    .line 12
    .line 13
    const/4 v2, 0x1

    .line 14
    invoke-direct {v1, v0, v2}, Ltechnology/cariad/cat/genx/bluetooth/d;-><init>(Ljava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    invoke-interface {p0, v1}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 22
    .line 23
    const/16 v1, 0x11

    .line 24
    .line 25
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 26
    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    const-string v2, "GenX"

    .line 30
    .line 31
    invoke-static {p0, v2, v1, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public final onDeviceDisconnected$genx_release()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getDelegate()Ltechnology/cariad/cat/genx/ClientDelegate;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    new-instance v2, Ltechnology/cariad/cat/genx/bluetooth/b;

    .line 12
    .line 13
    const/4 v3, 0x3

    .line 14
    invoke-direct {v2, v0, p0, v3}, Ltechnology/cariad/cat/genx/bluetooth/b;-><init>(Ljava/io/Closeable;Ljava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    invoke-interface {v1, v2}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 22
    .line 23
    const/16 v1, 0xf

    .line 24
    .line 25
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 26
    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    const-string v2, "GenX"

    .line 30
    .line 31
    invoke-static {p0, v2, v1, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public remove()V
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->clientManager:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;

    .line 2
    .line 3
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getIdentifier()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {v0, p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientManager;->removeClient(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public send(Ltechnology/cariad/cat/genx/TypedFrame;)Ltechnology/cariad/cat/genx/GenXError;
    .locals 5

    .line 1
    const-string v0, "typedFrame"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/TypedFrame;->getType()Ltechnology/cariad/cat/genx/TypedFrameType;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-static {v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClientKt;->toChannel(Ltechnology/cariad/cat/genx/TypedFrameType;)Ltechnology/cariad/cat/genx/Channel;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bleManager:Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;

    .line 15
    .line 16
    invoke-virtual {v1, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient$Manager;->channelConfig(Ltechnology/cariad/cat/genx/Channel;)Ltechnology/cariad/cat/genx/bluetooth/ChannelConfig;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    const/4 v2, 0x0

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bleManagerHandler:Landroid/os/Handler;

    .line 24
    .line 25
    new-instance v3, La8/y0;

    .line 26
    .line 27
    const/16 v4, 0x13

    .line 28
    .line 29
    invoke-direct {v3, p0, v1, p1, v4}, La8/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0, v3}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 33
    .line 34
    .line 35
    return-object v2

    .line 36
    :cond_0
    new-instance v1, Ltechnology/cariad/cat/genx/bluetooth/b;

    .line 37
    .line 38
    const/4 v3, 0x1

    .line 39
    invoke-direct {v1, p1, p0, v3}, Ltechnology/cariad/cat/genx/bluetooth/b;-><init>(Ljava/io/Closeable;Ljava/lang/Object;I)V

    .line 40
    .line 41
    .line 42
    const-string p1, "GenX"

    .line 43
    .line 44
    invoke-static {p0, p1, v2, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 45
    .line 46
    .line 47
    new-instance p0, Ltechnology/cariad/cat/genx/GenXError$Bluetooth;

    .line 48
    .line 49
    new-instance p1, Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$ChannelNotFound;

    .line 50
    .line 51
    invoke-direct {p1, v0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothError$ChannelNotFound;-><init>(Ltechnology/cariad/cat/genx/Channel;)V

    .line 52
    .line 53
    .line 54
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/GenXError$Bluetooth;-><init>(Ltechnology/cariad/cat/genx/bluetooth/BluetoothError;)V

    .line 55
    .line 56
    .line 57
    return-object p0
.end method

.method public final setCurrentUsableMtu(I)V
    .locals 0

    .line 1
    iput p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->currentUsableMtu:I

    .line 2
    .line 3
    return-void
.end method

.method public setDelegate(Ltechnology/cariad/cat/genx/ClientDelegate;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->delegate:Ltechnology/cariad/cat/genx/ClientDelegate;

    .line 2
    .line 3
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->bluetoothDevice:Landroid/bluetooth/BluetoothDevice;

    .line 2
    .line 3
    new-instance v0, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v1, "BluetoothClient(bluetoothDevice="

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
    const-string p0, ")"

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public final updateAdvertisement$genx_release(Ltechnology/cariad/cat/genx/TypedFrame;Ljava/time/Instant;)Z
    .locals 10

    .line 1
    const-string v0, "typedFrame"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "timestamp"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v1, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->lastAdvertisementLock:Ljava/util/concurrent/locks/ReentrantLock;

    .line 12
    .line 13
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 14
    .line 15
    .line 16
    :try_start_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->lastAdvertisement:Ljava/time/Instant;

    .line 17
    .line 18
    invoke-virtual {v0, p2}, Ljava/time/Instant;->compareTo(Ljava/time/Instant;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    const/4 v2, 0x1

    .line 23
    if-gez v0, :cond_1

    .line 24
    .line 25
    iput-object p2, p0, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->lastAdvertisement:Ljava/time/Instant;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 26
    .line 27
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getDelegate()Ltechnology/cariad/cat/genx/ClientDelegate;

    .line 31
    .line 32
    .line 33
    move-result-object p2

    .line 34
    if-eqz p2, :cond_0

    .line 35
    .line 36
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/bluetooth/BluetoothClient;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    new-instance v0, Ltechnology/cariad/cat/genx/bluetooth/b;

    .line 41
    .line 42
    const/4 v1, 0x2

    .line 43
    invoke-direct {v0, p2, p1, v1}, Ltechnology/cariad/cat/genx/bluetooth/b;-><init>(Ljava/io/Closeable;Ljava/lang/Object;I)V

    .line 44
    .line 45
    .line 46
    invoke-interface {p0, v0}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 47
    .line 48
    .line 49
    return v2

    .line 50
    :cond_0
    new-instance p1, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 51
    .line 52
    const/16 p2, 0x14

    .line 53
    .line 54
    invoke-direct {p1, p2}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 55
    .line 56
    .line 57
    const/4 p2, 0x0

    .line 58
    const-string v0, "GenX"

    .line 59
    .line 60
    invoke-static {p0, v0, p2, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 61
    .line 62
    .line 63
    const/4 p0, 0x0

    .line 64
    return p0

    .line 65
    :catchall_0
    move-exception v0

    .line 66
    move-object p0, v0

    .line 67
    goto :goto_0

    .line 68
    :cond_1
    :try_start_1
    new-instance v6, Ltechnology/cariad/cat/genx/bluetooth/m;

    .line 69
    .line 70
    const/16 p1, 0x13

    .line 71
    .line 72
    invoke-direct {v6, p1}, Ltechnology/cariad/cat/genx/bluetooth/m;-><init>(I)V

    .line 73
    .line 74
    .line 75
    const-string v4, "GenX"

    .line 76
    .line 77
    new-instance v3, Lt51/j;

    .line 78
    .line 79
    sget-object v5, Lt51/g;->a:Lt51/g;

    .line 80
    .line 81
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v8

    .line 85
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-virtual {p0}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v9

    .line 93
    const-string p0, "getName(...)"

    .line 94
    .line 95
    invoke-static {v9, p0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    const/4 v7, 0x0

    .line 99
    invoke-direct/range {v3 .. v9}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    invoke-static {v3}, Lt51/a;->a(Lt51/j;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 103
    .line 104
    .line 105
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 106
    .line 107
    .line 108
    return v2

    .line 109
    :goto_0
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->unlock()V

    .line 110
    .line 111
    .line 112
    throw p0
.end method
