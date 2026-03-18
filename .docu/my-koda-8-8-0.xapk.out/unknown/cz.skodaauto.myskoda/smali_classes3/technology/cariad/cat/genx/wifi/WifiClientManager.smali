.class public final Ltechnology/cariad/cat/genx/wifi/WifiClientManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/ClientManager;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000v\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0012\n\u0002\u0010\t\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0006\u0008\u0000\u0018\u00002\u00020\u0001B/\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0006\u0010\u0007\u001a\u00020\u0006\u0012\u0006\u0010\t\u001a\u00020\u0008\u0012\u0006\u0010\u000b\u001a\u00020\n\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u0011\u0010\u000f\u001a\u0004\u0018\u00010\u000eH\u0016\u00a2\u0006\u0004\u0008\u000f\u0010\u0010J\u0011\u0010\u0011\u001a\u0004\u0018\u00010\u000eH\u0016\u00a2\u0006\u0004\u0008\u0011\u0010\u0010J\u0017\u0010\u0015\u001a\u00020\u00142\u0006\u0010\u0013\u001a\u00020\u0012H\u0016\u00a2\u0006\u0004\u0008\u0015\u0010\u0016J\u000f\u0010\u0017\u001a\u00020\u0014H\u0016\u00a2\u0006\u0004\u0008\u0017\u0010\u0018R\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010\u0019\u001a\u0004\u0008\u001a\u0010\u001bR\u001a\u0010\u0005\u001a\u00020\u00048\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0005\u0010\u001c\u001a\u0004\u0008\u001d\u0010\u001eR\u0017\u0010\u0007\u001a\u00020\u00068\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0007\u0010\u001f\u001a\u0004\u0008 \u0010!R\u0014\u0010\t\u001a\u00020\u00088\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\t\u0010\"R\u001a\u0010\u000b\u001a\u00020\n8\u0000X\u0080\u0004\u00a2\u0006\u000c\n\u0004\u0008\u000b\u0010#\u001a\u0004\u0008$\u0010%R\u0014\u0010&\u001a\u00020\u00068\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008&\u0010\u001fR\"\u0010(\u001a\u00020\'8\u0016@\u0016X\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008(\u0010)\u001a\u0004\u0008*\u0010+\"\u0004\u0008,\u0010-R\u001a\u0010/\u001a\u00020.8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008/\u00100\u001a\u0004\u00081\u00102R$\u00104\u001a\u0004\u0018\u0001038\u0016@\u0016X\u0096\u000e\u00a2\u0006\u0012\n\u0004\u00084\u00105\u001a\u0004\u00086\u00107\"\u0004\u00088\u00109R\u0014\u0010;\u001a\u00020:8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008;\u0010<R\u0014\u0010>\u001a\u00020=8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008>\u0010?R\u0016\u0010A\u001a\u00020@8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008A\u0010BR\u0014\u0010D\u001a\u00020C8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008D\u0010ER\u0014\u0010F\u001a\u00020@8VX\u0096\u0004\u00a2\u0006\u0006\u001a\u0004\u0008F\u0010GR\u0014\u0010H\u001a\u00020@8VX\u0096\u0004\u00a2\u0006\u0006\u001a\u0004\u0008H\u0010G\u00a8\u0006I"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/wifi/WifiClientManager;",
        "Ltechnology/cariad/cat/genx/ClientManager;",
        "Landroid/content/Context;",
        "context",
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "genXDispatcher",
        "Lvy0/b0;",
        "coroutineScope",
        "Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;",
        "bonjourManager",
        "Ltechnology/cariad/cat/genx/wifi/WifiManager;",
        "wifiManager",
        "<init>",
        "(Landroid/content/Context;Ltechnology/cariad/cat/genx/GenXDispatcher;Lvy0/b0;Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;Ltechnology/cariad/cat/genx/wifi/WifiManager;)V",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "startScanningForClients",
        "()Ltechnology/cariad/cat/genx/GenXError;",
        "stopScanningForClients",
        "",
        "identifier",
        "Llx0/b0;",
        "removeClient",
        "(Ljava/lang/String;)V",
        "close",
        "()V",
        "Landroid/content/Context;",
        "getContext",
        "()Landroid/content/Context;",
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "getGenXDispatcher",
        "()Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "Lvy0/b0;",
        "getCoroutineScope",
        "()Lvy0/b0;",
        "Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;",
        "Ltechnology/cariad/cat/genx/wifi/WifiManager;",
        "getWifiManager$genx_release",
        "()Ltechnology/cariad/cat/genx/wifi/WifiManager;",
        "scope",
        "",
        "reference",
        "J",
        "getReference",
        "()J",
        "setReference",
        "(J)V",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "transportType",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "getTransportType",
        "()Ltechnology/cariad/cat/genx/TransportType;",
        "Ltechnology/cariad/cat/genx/ClientManagerDelegate;",
        "delegate",
        "Ltechnology/cariad/cat/genx/ClientManagerDelegate;",
        "getDelegate",
        "()Ltechnology/cariad/cat/genx/ClientManagerDelegate;",
        "setDelegate",
        "(Ltechnology/cariad/cat/genx/ClientManagerDelegate;)V",
        "Landroid/os/HandlerThread;",
        "wifiHandlerThread",
        "Landroid/os/HandlerThread;",
        "Landroid/os/Handler;",
        "wifiHandler",
        "Landroid/os/Handler;",
        "",
        "scanningWasRequested",
        "Z",
        "Lez0/a;",
        "startScanningMutex",
        "Lez0/a;",
        "isEnabled",
        "()Z",
        "isScanningRequired",
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
.field private final bonjourManager:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;

.field private final context:Landroid/content/Context;

.field private final coroutineScope:Lvy0/b0;

.field private delegate:Ltechnology/cariad/cat/genx/ClientManagerDelegate;

.field private final genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

.field private reference:J

.field private scanningWasRequested:Z

.field private final scope:Lvy0/b0;

.field private final startScanningMutex:Lez0/a;

.field private final transportType:Ltechnology/cariad/cat/genx/TransportType;

.field private final wifiHandler:Landroid/os/Handler;

.field private final wifiHandlerThread:Landroid/os/HandlerThread;

.field private final wifiManager:Ltechnology/cariad/cat/genx/wifi/WifiManager;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ltechnology/cariad/cat/genx/GenXDispatcher;Lvy0/b0;Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;Ltechnology/cariad/cat/genx/wifi/WifiManager;)V
    .locals 8

    .line 1
    const-string v0, "context"

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
    const-string v0, "bonjourManager"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "wifiManager"

    .line 22
    .line 23
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->context:Landroid/content/Context;

    .line 30
    .line 31
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 32
    .line 33
    iput-object p3, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->coroutineScope:Lvy0/b0;

    .line 34
    .line 35
    iput-object p4, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->bonjourManager:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;

    .line 36
    .line 37
    iput-object p5, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->wifiManager:Ltechnology/cariad/cat/genx/wifi/WifiManager;

    .line 38
    .line 39
    new-instance p2, Lvy0/a0;

    .line 40
    .line 41
    const-string v0, "WifiClientManager"

    .line 42
    .line 43
    invoke-direct {p2, v0}, Lvy0/a0;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    invoke-static {p3, p2}, Lvy0/e0;->H(Lvy0/b0;Lpx0/e;)Lpw0/a;

    .line 47
    .line 48
    .line 49
    move-result-object p2

    .line 50
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 51
    .line 52
    .line 53
    move-result-object p3

    .line 54
    invoke-static {p2, p3}, Lvy0/e0;->H(Lvy0/b0;Lpx0/e;)Lpw0/a;

    .line 55
    .line 56
    .line 57
    move-result-object p2

    .line 58
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->scope:Lvy0/b0;

    .line 59
    .line 60
    sget-object p3, Ltechnology/cariad/cat/genx/TransportType;->WiFi:Ltechnology/cariad/cat/genx/TransportType;

    .line 61
    .line 62
    iput-object p3, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->transportType:Ltechnology/cariad/cat/genx/TransportType;

    .line 63
    .line 64
    new-instance p3, Landroid/os/HandlerThread;

    .line 65
    .line 66
    const-string v0, "WifiHandlerThread"

    .line 67
    .line 68
    invoke-direct {p3, v0}, Landroid/os/HandlerThread;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    iput-object p3, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->wifiHandlerThread:Landroid/os/HandlerThread;

    .line 72
    .line 73
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    iput-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->startScanningMutex:Lez0/a;

    .line 78
    .line 79
    new-instance v4, Ltechnology/cariad/cat/genx/wifi/i;

    .line 80
    .line 81
    const/16 v0, 0x17

    .line 82
    .line 83
    invoke-direct {v4, v0}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 84
    .line 85
    .line 86
    new-instance v1, Lt51/j;

    .line 87
    .line 88
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v6

    .line 92
    const-string v0, "getName(...)"

    .line 93
    .line 94
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v7

    .line 98
    const-string v2, "GenX"

    .line 99
    .line 100
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 101
    .line 102
    const/4 v5, 0x0

    .line 103
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->getTransportType()Ltechnology/cariad/cat/genx/TransportType;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/TransportType;->getCgxValue$genx_release()B

    .line 114
    .line 115
    .line 116
    move-result v0

    .line 117
    invoke-static {p0, v0}, Ltechnology/cariad/cat/genx/ClientManagerKt;->nativeCreate(Ltechnology/cariad/cat/genx/ClientManager;B)J

    .line 118
    .line 119
    .line 120
    move-result-wide v0

    .line 121
    invoke-virtual {p0, v0, v1}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->setReference(J)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {p3}, Ljava/lang/Thread;->start()V

    .line 125
    .line 126
    .line 127
    new-instance v0, Landroid/os/Handler;

    .line 128
    .line 129
    invoke-virtual {p3}, Landroid/os/HandlerThread;->getLooper()Landroid/os/Looper;

    .line 130
    .line 131
    .line 132
    move-result-object p3

    .line 133
    invoke-direct {v0, p3}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 134
    .line 135
    .line 136
    iput-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->wifiHandler:Landroid/os/Handler;

    .line 137
    .line 138
    invoke-interface {p5, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManager;->registerBroadcastReceiver(Landroid/content/Context;)V

    .line 139
    .line 140
    .line 141
    invoke-interface {p5}, Ltechnology/cariad/cat/genx/wifi/WifiManager;->getWifiState()Lyy0/a2;

    .line 142
    .line 143
    .line 144
    move-result-object p1

    .line 145
    new-instance p3, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1;

    .line 146
    .line 147
    invoke-direct {p3, p1, p0}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$special$$inlined$map$1;-><init>(Lyy0/i;Ltechnology/cariad/cat/genx/wifi/WifiClientManager;)V

    .line 148
    .line 149
    .line 150
    invoke-static {p3}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    new-instance p3, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;

    .line 155
    .line 156
    const/4 p5, 0x0

    .line 157
    invoke-direct {p3, p0, p5}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;-><init>(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;Lkotlin/coroutines/Continuation;)V

    .line 158
    .line 159
    .line 160
    new-instance v0, Lne0/n;

    .line 161
    .line 162
    const/4 v1, 0x5

    .line 163
    invoke-direct {v0, p1, p3, v1}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 164
    .line 165
    .line 166
    invoke-static {v0, p2}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 167
    .line 168
    .line 169
    invoke-interface {p4}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;->getPotentialWifiClients()Lyy0/a2;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    new-instance p3, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$4;

    .line 174
    .line 175
    invoke-direct {p3, p0, p5}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$4;-><init>(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;Lkotlin/coroutines/Continuation;)V

    .line 176
    .line 177
    .line 178
    new-instance p0, Lne0/n;

    .line 179
    .line 180
    const/4 p4, 0x5

    .line 181
    invoke-direct {p0, p1, p3, p4}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 182
    .line 183
    .line 184
    invoke-static {p0, p2}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 185
    .line 186
    .line 187
    return-void
.end method

.method public static synthetic B()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->startScanningForClients$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final _init_$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "init(): Create WifiConnectionManager"

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic a()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->startScanningForClients$lambda$3$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static final synthetic access$getBonjourManager$p(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;)Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->bonjourManager:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getScanningWasRequested$p(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->scanningWasRequested:Z

    .line 2
    .line 3
    return p0
.end method

.method public static final synthetic access$getStartScanningMutex$p(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;)Lez0/a;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->startScanningMutex:Lez0/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic b()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->stopScanningForClients$lambda$1()Ljava/lang/String;

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

.method private static final close$lambda$1(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;)Llx0/b0;
    .locals 2

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/ClientManagerKt;->nativeDestroy(Ltechnology/cariad/cat/genx/ClientManager;)V

    .line 2
    .line 3
    .line 4
    const-wide/16 v0, 0x0

    .line 5
    .line 6
    invoke-virtual {p0, v0, v1}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->setReference(J)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    return-object p0
.end method

.method public static synthetic d()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->removeClient$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic f(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->close$lambda$1(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->close$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic h()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->startScanningForClients$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic j()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->_init_$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic k()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->startScanningForClients$lambda$4()Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->startScanningForClients$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic q()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->stopScanningForClients$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final removeClient$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "Not yet implemented"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startScanningForClients$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startScanningForClients()"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startScanningForClients$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startScanningForClients(): Cannot start Scanning yet, since Wifi is not enabled"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startScanningForClients$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startScanningForClients(): start bonjour discovery"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startScanningForClients$lambda$3$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startScanningForClients(): Failed to start bonjour discovery"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startScanningForClients$lambda$4()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startScanningForClients(): bonjour discovery already ongoing"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final stopScanningForClients$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "stopScanningForClients():"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final stopScanningForClients$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "stopScanningForClients(): stop bonjour discovery"

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public close()V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/wifi/i;

    .line 2
    .line 3
    const/16 v0, 0x15

    .line 4
    .line 5
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

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
    sget-object v2, Lt51/g;->a:Lt51/g;

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
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->wifiManager:Ltechnology/cariad/cat/genx/wifi/WifiManager;

    .line 32
    .line 33
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->context:Landroid/content/Context;

    .line 34
    .line 35
    invoke-interface {v0, v1}, Ltechnology/cariad/cat/genx/wifi/WifiManager;->unregisterBroadcastReceiver(Landroid/content/Context;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->stopScanningForClients()Ltechnology/cariad/cat/genx/GenXError;

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->getDelegate()Ltechnology/cariad/cat/genx/ClientManagerDelegate;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    if-eqz v0, :cond_0

    .line 46
    .line 47
    invoke-interface {v0}, Ljava/io/Closeable;->close()V

    .line 48
    .line 49
    .line 50
    :cond_0
    const/4 v0, 0x0

    .line 51
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->setDelegate(Ltechnology/cariad/cat/genx/ClientManagerDelegate;)V

    .line 52
    .line 53
    .line 54
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->wifiHandlerThread:Landroid/os/HandlerThread;

    .line 55
    .line 56
    invoke-virtual {v1}, Landroid/os/HandlerThread;->quitSafely()Z

    .line 57
    .line 58
    .line 59
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->scope:Lvy0/b0;

    .line 60
    .line 61
    invoke-static {v1, v0}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->getReference()J

    .line 65
    .line 66
    .line 67
    move-result-wide v0

    .line 68
    const-wide/16 v2, 0x0

    .line 69
    .line 70
    cmp-long v0, v0, v2

    .line 71
    .line 72
    if-eqz v0, :cond_1

    .line 73
    .line 74
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    new-instance v1, Ltechnology/cariad/cat/genx/wifi/m;

    .line 79
    .line 80
    const/4 v2, 0x2

    .line 81
    invoke-direct {v1, p0, v2}, Ltechnology/cariad/cat/genx/wifi/m;-><init>(Ljava/lang/Object;I)V

    .line 82
    .line 83
    .line 84
    invoke-interface {v0, v1}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 85
    .line 86
    .line 87
    :cond_1
    return-void
.end method

.method public final getContext()Landroid/content/Context;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->context:Landroid/content/Context;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getCoroutineScope()Lvy0/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->coroutineScope:Lvy0/b0;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDelegate()Ltechnology/cariad/cat/genx/ClientManagerDelegate;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->delegate:Ltechnology/cariad/cat/genx/ClientManagerDelegate;

    .line 2
    .line 3
    return-object p0
.end method

.method public getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->genXDispatcher:Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 2
    .line 3
    return-object p0
.end method

.method public getReference()J
    .locals 2

    .line 1
    iget-wide v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->reference:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getTransportType()Ltechnology/cariad/cat/genx/TransportType;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->transportType:Ltechnology/cariad/cat/genx/TransportType;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getWifiManager$genx_release()Ltechnology/cariad/cat/genx/wifi/WifiManager;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->wifiManager:Ltechnology/cariad/cat/genx/wifi/WifiManager;

    .line 2
    .line 3
    return-object p0
.end method

.method public isEnabled()Z
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->wifiManager:Ltechnology/cariad/cat/genx/wifi/WifiManager;

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->context:Landroid/content/Context;

    .line 4
    .line 5
    invoke-interface {v0, p0}, Ltechnology/cariad/cat/genx/wifi/WifiManager;->isWiFiEnabled(Landroid/content/Context;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public isScanningRequired()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public removeClient(Ljava/lang/String;)V
    .locals 8

    .line 1
    const-string v0, "identifier"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/wifi/i;

    .line 7
    .line 8
    const/16 p1, 0x16

    .line 9
    .line 10
    invoke-direct {v4, p1}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

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
    sget-object v3, Lt51/e;->a:Lt51/e;

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

.method public setDelegate(Ltechnology/cariad/cat/genx/ClientManagerDelegate;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->delegate:Ltechnology/cariad/cat/genx/ClientManagerDelegate;

    .line 2
    .line 3
    return-void
.end method

.method public setReference(J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->reference:J

    .line 2
    .line 3
    return-void
.end method

.method public startScanningForClients()Ltechnology/cariad/cat/genx/GenXError;
    .locals 15

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/wifi/i;

    .line 2
    .line 3
    const/16 v0, 0x1a

    .line 4
    .line 5
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

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
    sget-object v10, Lt51/g;->a:Lt51/g;

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    move-object v2, v10

    .line 26
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 30
    .line 31
    .line 32
    const/4 v0, 0x1

    .line 33
    iput-boolean v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->scanningWasRequested:Z

    .line 34
    .line 35
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->wifiManager:Ltechnology/cariad/cat/genx/wifi/WifiManager;

    .line 36
    .line 37
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->context:Landroid/content/Context;

    .line 38
    .line 39
    invoke-interface {v0, v1}, Ltechnology/cariad/cat/genx/wifi/WifiManager;->isWiFiEnabled(Landroid/content/Context;)Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-nez v0, :cond_0

    .line 44
    .line 45
    new-instance v11, Ltechnology/cariad/cat/genx/wifi/i;

    .line 46
    .line 47
    const/16 v0, 0x1b

    .line 48
    .line 49
    invoke-direct {v11, v0}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 50
    .line 51
    .line 52
    new-instance v8, Lt51/j;

    .line 53
    .line 54
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v13

    .line 58
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v14

    .line 62
    const-string v9, "GenX"

    .line 63
    .line 64
    const/4 v12, 0x0

    .line 65
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 69
    .line 70
    .line 71
    sget-object p0, Ltechnology/cariad/cat/genx/GenXError$Wifi$Disabled;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$Wifi$Disabled;

    .line 72
    .line 73
    return-object p0

    .line 74
    :cond_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->startScanningMutex:Lez0/a;

    .line 75
    .line 76
    invoke-interface {v0}, Lez0/a;->tryLock()Z

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    const/4 v1, 0x0

    .line 81
    if-eqz v0, :cond_3

    .line 82
    .line 83
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->bonjourManager:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;

    .line 84
    .line 85
    invoke-interface {v0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;->isBonjourScanningActive()Z

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    if-nez v0, :cond_1

    .line 90
    .line 91
    new-instance v11, Ltechnology/cariad/cat/genx/wifi/i;

    .line 92
    .line 93
    const/16 v0, 0x1c

    .line 94
    .line 95
    invoke-direct {v11, v0}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 96
    .line 97
    .line 98
    new-instance v8, Lt51/j;

    .line 99
    .line 100
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v13

    .line 104
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v14

    .line 108
    const-string v9, "GenX"

    .line 109
    .line 110
    const/4 v12, 0x0

    .line 111
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 115
    .line 116
    .line 117
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->bonjourManager:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;

    .line 118
    .line 119
    invoke-interface {v0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;->startBonjourDiscovery-d1pmJ48()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v0

    .line 123
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    if-eqz v0, :cond_2

    .line 128
    .line 129
    new-instance v2, Ltechnology/cariad/cat/genx/wifi/i;

    .line 130
    .line 131
    const/16 v3, 0x1d

    .line 132
    .line 133
    invoke-direct {v2, v3}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 134
    .line 135
    .line 136
    const-string v3, "GenX"

    .line 137
    .line 138
    invoke-static {p0, v3, v0, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 139
    .line 140
    .line 141
    instance-of p0, v0, Ltechnology/cariad/cat/genx/GenXError;

    .line 142
    .line 143
    if-eqz p0, :cond_3

    .line 144
    .line 145
    check-cast v0, Ltechnology/cariad/cat/genx/GenXError;

    .line 146
    .line 147
    return-object v0

    .line 148
    :cond_1
    new-instance v11, Ltechnology/cariad/cat/genx/wifi/g;

    .line 149
    .line 150
    const/4 v0, 0x0

    .line 151
    invoke-direct {v11, v0}, Ltechnology/cariad/cat/genx/wifi/g;-><init>(I)V

    .line 152
    .line 153
    .line 154
    new-instance v8, Lt51/j;

    .line 155
    .line 156
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object v13

    .line 160
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v14

    .line 164
    const-string v9, "GenX"

    .line 165
    .line 166
    const/4 v12, 0x0

    .line 167
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 171
    .line 172
    .line 173
    :cond_2
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->startScanningMutex:Lez0/a;

    .line 174
    .line 175
    invoke-interface {p0, v1}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    :cond_3
    return-object v1
.end method

.method public stopScanningForClients()Ltechnology/cariad/cat/genx/GenXError;
    .locals 15

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/wifi/i;

    .line 2
    .line 3
    const/16 v0, 0x18

    .line 4
    .line 5
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

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
    sget-object v2, Lt51/g;->a:Lt51/g;

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
    const/4 v0, 0x0

    .line 32
    iput-boolean v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->scanningWasRequested:Z

    .line 33
    .line 34
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->bonjourManager:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;

    .line 35
    .line 36
    invoke-interface {v0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;->isBonjourScanningActive()Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-eqz v0, :cond_0

    .line 41
    .line 42
    new-instance v11, Ltechnology/cariad/cat/genx/wifi/i;

    .line 43
    .line 44
    const/16 v0, 0x19

    .line 45
    .line 46
    invoke-direct {v11, v0}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

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
    const/4 v12, 0x0

    .line 62
    move-object v10, v2

    .line 63
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 67
    .line 68
    .line 69
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->bonjourManager:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;

    .line 70
    .line 71
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;->stopBonjourDiscovery()V

    .line 72
    .line 73
    .line 74
    :cond_0
    const/4 p0, 0x0

    .line 75
    return-object p0
.end method
