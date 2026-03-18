.class public final Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/wifi/WifiManager;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$WhenMappings;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000i\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0008\n\u0002\u0018\u0002\n\u0002\u0008\u000c\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\t\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0004*\u0001<\u0008\u0000\u0018\u00002\u00020\u0001B#\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0004\u0012\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\u0017\u0010\r\u001a\u00020\u000c2\u0006\u0010\u000b\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\r\u0010\u000eJ\u0017\u0010\u000f\u001a\u00020\u000c2\u0006\u0010\u000b\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u000f\u0010\u000eJ\u0017\u0010\u0010\u001a\u00020\u000c2\u0006\u0010\u000b\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u0010\u0010\u000eJ\u0017\u0010\u0012\u001a\u00020\u00112\u0006\u0010\u000b\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u0012\u0010\u0013J\u0017\u0010\u0014\u001a\u00020\u00112\u0006\u0010\u000b\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u0014\u0010\u0013J\u001a\u0010\u0018\u001a\u0004\u0018\u00010\u00152\u0006\u0010\u000b\u001a\u00020\nH\u0080@\u00a2\u0006\u0004\u0008\u0016\u0010\u0017J!\u0010\u001d\u001a\u0004\u0018\u00010\u00152\u0006\u0010\u000b\u001a\u00020\n2\u0006\u0010\u001a\u001a\u00020\u0019H\u0000\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ\u0019\u0010!\u001a\u00020\u00112\u0008\u0010\u001e\u001a\u0004\u0018\u00010\u0015H\u0000\u00a2\u0006\u0004\u0008\u001f\u0010 J!\u0010#\u001a\u0004\u0018\u00010\"2\u0006\u0010\u000b\u001a\u00020\n2\u0006\u0010\u001a\u001a\u00020\u0019H\u0003\u00a2\u0006\u0004\u0008#\u0010$J\u0019\u0010%\u001a\u0004\u0018\u00010\"2\u0006\u0010\u000b\u001a\u00020\nH\u0002\u00a2\u0006\u0004\u0008%\u0010&J\u000f\u0010\'\u001a\u00020\u0011H\u0002\u00a2\u0006\u0004\u0008\'\u0010(J\u0019\u0010)\u001a\u00020\u000c2\u0008\u0010\u001e\u001a\u0004\u0018\u00010\u0015H\u0002\u00a2\u0006\u0004\u0008)\u0010*R\u0017\u0010+\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008+\u0010,\u001a\u0004\u0008-\u0010.R\u001c\u00100\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00150/8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00080\u00101R\"\u0010\u0018\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u0015028\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0018\u00103\u001a\u0004\u00084\u00105R\u001a\u00106\u001a\u0008\u0012\u0004\u0012\u00020\u00040/8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00086\u00101R \u00107\u001a\u0008\u0012\u0004\u0012\u00020\u0004028\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u00087\u00103\u001a\u0004\u00088\u00105R\u001a\u00109\u001a\u0008\u0012\u0004\u0012\u00020\u00060/8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00089\u00101R \u0010:\u001a\u0008\u0012\u0004\u0012\u00020\u0006028\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008:\u00103\u001a\u0004\u0008;\u00105R\u0014\u0010=\u001a\u00020<8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008=\u0010>R\u0016\u0010?\u001a\u00020\u000c8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008?\u0010@R\u0018\u0010B\u001a\u0004\u0018\u00010A8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008B\u0010CR\u0016\u0010D\u001a\u00020\u000c8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008D\u0010@\u00a8\u0006E"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;",
        "Ltechnology/cariad/cat/genx/wifi/WifiManager;",
        "Lvy0/b0;",
        "coroutineScope",
        "Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;",
        "initialWifiState",
        "Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;",
        "initialAccessPointState",
        "<init>",
        "(Lvy0/b0;Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;)V",
        "Landroid/content/Context;",
        "context",
        "",
        "isWiFiSupported",
        "(Landroid/content/Context;)Z",
        "isWiFiDirectSupported",
        "isWiFiEnabled",
        "Llx0/b0;",
        "registerBroadcastReceiver",
        "(Landroid/content/Context;)V",
        "unregisterBroadcastReceiver",
        "Ltechnology/cariad/cat/genx/wifi/Wifi;",
        "connectedWifi$genx_release",
        "(Landroid/content/Context;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "connectedWifi",
        "Landroid/net/Network;",
        "network",
        "wifiForNetwork$genx_release",
        "(Landroid/content/Context;Landroid/net/Network;)Ltechnology/cariad/cat/genx/wifi/Wifi;",
        "wifiForNetwork",
        "wifi",
        "updateWifiIfChanged$genx_release",
        "(Ltechnology/cariad/cat/genx/wifi/Wifi;)V",
        "updateWifiIfChanged",
        "Landroid/net/wifi/WifiInfo;",
        "wifiInfoFromWifiNetwork",
        "(Landroid/content/Context;Landroid/net/Network;)Landroid/net/wifi/WifiInfo;",
        "wifiInfoFromConnectionInfo",
        "(Landroid/content/Context;)Landroid/net/wifi/WifiInfo;",
        "onWifiDisconnected",
        "()V",
        "hasWifiInfoChanged",
        "(Ltechnology/cariad/cat/genx/wifi/Wifi;)Z",
        "scope",
        "Lvy0/b0;",
        "getScope",
        "()Lvy0/b0;",
        "Lyy0/j1;",
        "_connectedWifi",
        "Lyy0/j1;",
        "Lyy0/a2;",
        "Lyy0/a2;",
        "getConnectedWifi",
        "()Lyy0/a2;",
        "_wifiState",
        "wifiState",
        "getWifiState",
        "_accessPointState",
        "accessPointState",
        "getAccessPointState",
        "technology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1",
        "wifiBroadcastReceiver",
        "Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;",
        "isBroadcastReceiverRegistered",
        "Z",
        "Landroid/net/ConnectivityManager$NetworkCallback;",
        "networkCallback",
        "Landroid/net/ConnectivityManager$NetworkCallback;",
        "isNetworkCallbackRegistered",
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
.field private final _accessPointState:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _connectedWifi:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final _wifiState:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final accessPointState:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final connectedWifi:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private isBroadcastReceiverRegistered:Z

.field private isNetworkCallbackRegistered:Z

.field private networkCallback:Landroid/net/ConnectivityManager$NetworkCallback;

.field private final scope:Lvy0/b0;

.field private final wifiBroadcastReceiver:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;

.field private final wifiState:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lvy0/b0;Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;)V
    .locals 2

    const-string v0, "coroutineScope"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "initialWifiState"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "initialAccessPointState"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Lvy0/a0;

    const-string v1, "WifiManager"

    invoke-direct {v0, v1}, Lvy0/a0;-><init>(Ljava/lang/String;)V

    invoke-static {p1, v0}, Lvy0/e0;->H(Lvy0/b0;Lpx0/e;)Lpw0/a;

    move-result-object p1

    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    move-result-object v0

    invoke-static {p1, v0}, Lvy0/e0;->H(Lvy0/b0;Lpx0/e;)Lpw0/a;

    move-result-object p1

    .line 3
    new-instance v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$special$$inlined$CoroutineExceptionHandler$1;

    sget-object v1, Lvy0/y;->d:Lvy0/y;

    invoke-direct {v0, v1, p0}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$special$$inlined$CoroutineExceptionHandler$1;-><init>(Lvy0/y;Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;)V

    .line 4
    invoke-static {p1, v0}, Lvy0/e0;->H(Lvy0/b0;Lpx0/e;)Lpw0/a;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->scope:Lvy0/b0;

    const/4 p1, 0x0

    .line 5
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->_connectedWifi:Lyy0/j1;

    .line 6
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 7
    iput-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->connectedWifi:Lyy0/a2;

    .line 8
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->_wifiState:Lyy0/j1;

    .line 9
    new-instance p2, Lyy0/l1;

    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 10
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->wifiState:Lyy0/a2;

    .line 11
    invoke-static {p3}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->_accessPointState:Lyy0/j1;

    .line 12
    new-instance p2, Lyy0/l1;

    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 13
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->accessPointState:Lyy0/a2;

    .line 14
    new-instance p1, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;

    invoke-direct {p1, p0}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;-><init>(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;)V

    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->wifiBroadcastReceiver:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;

    return-void
.end method

.method public synthetic constructor <init>(Lvy0/b0;Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p5, p4, 0x2

    if-eqz p5, :cond_0

    .line 15
    sget-object p2, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->UNKNOWN:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    :cond_0
    and-int/lit8 p4, p4, 0x4

    if-eqz p4, :cond_1

    .line 16
    sget-object p3, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;->UNKNOWN:Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;

    .line 17
    :cond_1
    invoke-direct {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;-><init>(Lvy0/b0;Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;)V

    return-void
.end method

.method public static synthetic a(Ltechnology/cariad/cat/genx/wifi/Wifi;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->updateWifiIfChanged$lambda$0(Ltechnology/cariad/cat/genx/wifi/Wifi;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final synthetic access$get_accessPointState$p(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;)Lyy0/j1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->_accessPointState:Lyy0/j1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$get_wifiState$p(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;)Lyy0/j1;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->_wifiState:Lyy0/j1;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic b()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->connectedWifi$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic c()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->isWiFiEnabled$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final connectedWifi$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "connectedWifi(): Wi-Fi is disabled -> Returning \'null\'"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final connectedWifi$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "connectedWifi(): Wi-Fi check timed out. -> Returning \'null\'"

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic d()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->unregisterBroadcastReceiver$lambda$1$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic e(Ltechnology/cariad/cat/genx/wifi/Wifi;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->onWifiDisconnected$lambda$0$0(Ltechnology/cariad/cat/genx/wifi/Wifi;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->unregisterBroadcastReceiver$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic g()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->unregisterBroadcastReceiver$lambda$1$1$0()Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->registerBroadcastReceiver$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private final hasWifiInfoChanged(Ltechnology/cariad/cat/genx/wifi/Wifi;)Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->getConnectedWifi()Lyy0/a2;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Ltechnology/cariad/cat/genx/wifi/Wifi;

    .line 10
    .line 11
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_3

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/Wifi;->getBssid()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    move-object p0, v0

    .line 26
    :goto_0
    if-eqz p1, :cond_1

    .line 27
    .line 28
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/wifi/Wifi;->getBssid()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    :cond_1
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    if-nez p0, :cond_2

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_2
    const/4 p0, 0x0

    .line 40
    return p0

    .line 41
    :cond_3
    :goto_1
    const/4 p0, 0x1

    .line 42
    return p0
.end method

.method public static synthetic i()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->connectedWifi$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final isWiFiEnabled$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "isWiFiEnabled(): Update wifi state"

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic j()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->registerBroadcastReceiver$lambda$2$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic k(Landroid/net/ConnectivityManager$NetworkCallback;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->unregisterBroadcastReceiver$lambda$1$1$1(Landroid/net/ConnectivityManager$NetworkCallback;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private final onWifiDisconnected()V
    .locals 8

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->getConnectedWifi()Lyy0/a2;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Ltechnology/cariad/cat/genx/wifi/Wifi;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    new-instance v4, Ltechnology/cariad/cat/genx/wifi/k;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-direct {v4, v0, v1}, Ltechnology/cariad/cat/genx/wifi/k;-><init>(Ltechnology/cariad/cat/genx/wifi/Wifi;I)V

    .line 17
    .line 18
    .line 19
    new-instance v1, Lt51/j;

    .line 20
    .line 21
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v6

    .line 25
    const-string v0, "getName(...)"

    .line 26
    .line 27
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v7

    .line 31
    const-string v2, "GenX"

    .line 32
    .line 33
    sget-object v3, Lt51/f;->a:Lt51/f;

    .line 34
    .line 35
    const/4 v5, 0x0

    .line 36
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 40
    .line 41
    .line 42
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->_connectedWifi:Lyy0/j1;

    .line 43
    .line 44
    const/4 v0, 0x0

    .line 45
    check-cast p0, Lyy0/c2;

    .line 46
    .line 47
    invoke-virtual {p0, v0}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    return-void
.end method

.method private static final onWifiDisconnected$lambda$0$0(Ltechnology/cariad/cat/genx/wifi/Wifi;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onWifiDisconnected(): Disconnected from "

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

.method private static final registerBroadcastReceiver$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "registerBroadcastReceiver()"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final registerBroadcastReceiver$lambda$2$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "registerBroadcastReceiver(): \'ConnectivityManager\' not available"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final unregisterBroadcastReceiver$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "unregisterBroadcastReceiver()"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final unregisterBroadcastReceiver$lambda$1$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "unregisterBroadcastReceiver(): Cannot unregister Wifi BroadcastReceiver"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final unregisterBroadcastReceiver$lambda$1$1$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "unregisterBroadcastReceiver(): \'ConnectivityManager\' not available"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final unregisterBroadcastReceiver$lambda$1$1$1(Landroid/net/ConnectivityManager$NetworkCallback;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "unregisterBroadcastReceiver(): Cannot unregister NetworkCallback "

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

.method private static final updateWifiIfChanged$lambda$0(Ltechnology/cariad/cat/genx/wifi/Wifi;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "updateWifiIfChanged(): Connected to \'"

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

.method private final wifiInfoFromConnectionInfo(Landroid/content/Context;)Landroid/net/wifi/WifiInfo;
    .locals 0

    .line 1
    invoke-static {p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerKt;->getWifiManager(Landroid/content/Context;)Landroid/net/wifi/WifiManager;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/net/wifi/WifiManager;->getConnectionInfo()Landroid/net/wifi/WifiInfo;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method private final wifiInfoFromWifiNetwork(Landroid/content/Context;Landroid/net/Network;)Landroid/net/wifi/WifiInfo;
    .locals 0

    .line 1
    invoke-static {p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerKt;->getConnectivityManager(Landroid/content/Context;)Landroid/net/ConnectivityManager;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const/4 p1, 0x0

    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    invoke-virtual {p0, p2}, Landroid/net/ConnectivityManager;->getNetworkCapabilities(Landroid/net/Network;)Landroid/net/NetworkCapabilities;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    if-eqz p0, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0}, Landroid/net/NetworkCapabilities;->getTransportInfo()Landroid/net/TransportInfo;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move-object p0, p1

    .line 20
    :goto_0
    instance-of p2, p0, Landroid/net/wifi/WifiInfo;

    .line 21
    .line 22
    if-eqz p2, :cond_1

    .line 23
    .line 24
    check-cast p0, Landroid/net/wifi/WifiInfo;

    .line 25
    .line 26
    return-object p0

    .line 27
    :cond_1
    return-object p1
.end method


# virtual methods
.method public final connectedWifi$genx_release(Landroid/content/Context;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 13
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/content/Context;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/wifi/Wifi;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    instance-of v0, p2, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$1;

    .line 7
    .line 8
    iget v1, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$1;->label:I

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
    iput v1, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$1;->label:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$1;-><init>(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$1;->result:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$1;->label:I

    .line 30
    .line 31
    const-string v3, "getName(...)"

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    const/4 v5, 0x0

    .line 35
    if-eqz v2, :cond_2

    .line 36
    .line 37
    if-ne v2, v4, :cond_1

    .line 38
    .line 39
    iget-object p1, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$1;->L$1:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p1, Landroid/net/ConnectivityManager;

    .line 42
    .line 43
    iget-object p1, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$1;->L$0:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p1, Landroid/content/Context;

    .line 46
    .line 47
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0

    .line 48
    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    invoke-static {p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerKt;->getConnectivityManager(Landroid/content/Context;)Landroid/net/ConnectivityManager;

    .line 63
    .line 64
    .line 65
    move-result-object p2

    .line 66
    if-nez p2, :cond_3

    .line 67
    .line 68
    return-object v5

    .line 69
    :cond_3
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->isWiFiEnabled(Landroid/content/Context;)Z

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    if-nez v2, :cond_4

    .line 74
    .line 75
    new-instance v9, Ltechnology/cariad/cat/genx/wifi/g;

    .line 76
    .line 77
    const/4 p1, 0x3

    .line 78
    invoke-direct {v9, p1}, Ltechnology/cariad/cat/genx/wifi/g;-><init>(I)V

    .line 79
    .line 80
    .line 81
    new-instance v6, Lt51/j;

    .line 82
    .line 83
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v11

    .line 87
    invoke-static {v3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v12

    .line 91
    const-string v7, "GenX"

    .line 92
    .line 93
    sget-object v8, Lt51/d;->a:Lt51/d;

    .line 94
    .line 95
    const/4 v10, 0x0

    .line 96
    invoke-direct/range {v6 .. v12}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    invoke-static {v6}, Lt51/a;->a(Lt51/j;)V

    .line 100
    .line 101
    .line 102
    return-object v5

    .line 103
    :cond_4
    :try_start_1
    new-instance v2, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;

    .line 104
    .line 105
    invoke-direct {v2, p2, p0, p1, v5}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;-><init>(Landroid/net/ConnectivityManager;Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;Landroid/content/Context;Lkotlin/coroutines/Continuation;)V

    .line 106
    .line 107
    .line 108
    iput-object v5, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$1;->L$0:Ljava/lang/Object;

    .line 109
    .line 110
    iput-object v5, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$1;->L$1:Ljava/lang/Object;

    .line 111
    .line 112
    iput v4, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$1;->label:I

    .line 113
    .line 114
    const-wide/16 p1, 0x64

    .line 115
    .line 116
    invoke-static {p1, p2, v2, v0}, Lvy0/e0;->S(JLay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object p2

    .line 120
    if-ne p2, v1, :cond_5

    .line 121
    .line 122
    return-object v1

    .line 123
    :cond_5
    :goto_1
    check-cast p2, Ltechnology/cariad/cat/genx/wifi/Wifi;
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_0

    .line 124
    .line 125
    return-object p2

    .line 126
    :catch_0
    new-instance v9, Ltechnology/cariad/cat/genx/wifi/g;

    .line 127
    .line 128
    const/4 p1, 0x5

    .line 129
    invoke-direct {v9, p1}, Ltechnology/cariad/cat/genx/wifi/g;-><init>(I)V

    .line 130
    .line 131
    .line 132
    new-instance v6, Lt51/j;

    .line 133
    .line 134
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v11

    .line 138
    invoke-static {v3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object v12

    .line 142
    const-string v7, "GenX"

    .line 143
    .line 144
    sget-object v8, Lt51/g;->a:Lt51/g;

    .line 145
    .line 146
    const/4 v10, 0x0

    .line 147
    invoke-direct/range {v6 .. v12}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    invoke-static {v6}, Lt51/a;->a(Lt51/j;)V

    .line 151
    .line 152
    .line 153
    return-object v5
.end method

.method public getAccessPointState()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->accessPointState:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getConnectedWifi()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->connectedWifi:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getScope()Lvy0/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->scope:Lvy0/b0;

    .line 2
    .line 3
    return-object p0
.end method

.method public getWifiState()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->wifiState:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public isWiFiDirectSupported(Landroid/content/Context;)Z
    .locals 0

    .line 1
    const-string p0, "context"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    const-string p1, "android.hardware.wifi.direct"

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0
.end method

.method public isWiFiEnabled(Landroid/content/Context;)Z
    .locals 8

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerKt;->getWifiManager(Landroid/content/Context;)Landroid/net/wifi/WifiManager;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    invoke-virtual {p1}, Landroid/net/wifi/WifiManager;->getWifiState()I

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    sget-object v0, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->Companion:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState$Companion;

    .line 17
    .line 18
    invoke-virtual {v0, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState$Companion;->byStateInt$genx_release(I)Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    if-nez p1, :cond_1

    .line 23
    .line 24
    :cond_0
    sget-object p1, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->UNKNOWN:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 25
    .line 26
    :cond_1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->_wifiState:Lyy0/j1;

    .line 27
    .line 28
    check-cast v0, Lyy0/c2;

    .line 29
    .line 30
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    if-eq p1, v0, :cond_2

    .line 35
    .line 36
    new-instance v4, Ltechnology/cariad/cat/genx/wifi/g;

    .line 37
    .line 38
    const/4 v0, 0x6

    .line 39
    invoke-direct {v4, v0}, Ltechnology/cariad/cat/genx/wifi/g;-><init>(I)V

    .line 40
    .line 41
    .line 42
    new-instance v1, Lt51/j;

    .line 43
    .line 44
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v6

    .line 48
    const-string v0, "getName(...)"

    .line 49
    .line 50
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v7

    .line 54
    const-string v2, "GenX"

    .line 55
    .line 56
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 57
    .line 58
    const/4 v5, 0x0

    .line 59
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 63
    .line 64
    .line 65
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->_wifiState:Lyy0/j1;

    .line 66
    .line 67
    check-cast p0, Lyy0/c2;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    :cond_2
    sget-object p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$WhenMappings;->$EnumSwitchMapping$0:[I

    .line 73
    .line 74
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 75
    .line 76
    .line 77
    move-result p1

    .line 78
    aget p0, p0, p1

    .line 79
    .line 80
    const/4 p1, 0x1

    .line 81
    if-eq p0, p1, :cond_3

    .line 82
    .line 83
    const/4 v0, 0x2

    .line 84
    if-eq p0, v0, :cond_3

    .line 85
    .line 86
    const/4 p0, 0x0

    .line 87
    return p0

    .line 88
    :cond_3
    return p1
.end method

.method public isWiFiSupported(Landroid/content/Context;)Z
    .locals 0

    .line 1
    const-string p0, "context"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    const-string p1, "android.hardware.wifi"

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0
.end method

.method public registerBroadcastReceiver(Landroid/content/Context;)V
    .locals 8

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/wifi/g;

    .line 7
    .line 8
    const/16 v0, 0xa

    .line 9
    .line 10
    invoke-direct {v4, v0}, Ltechnology/cariad/cat/genx/wifi/g;-><init>(I)V

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
    const-string v0, "getName(...)"

    .line 20
    .line 21
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

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
    iget-boolean v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->isBroadcastReceiverRegistered:Z

    .line 37
    .line 38
    const/4 v1, 0x0

    .line 39
    if-eqz v0, :cond_0

    .line 40
    .line 41
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->wifiBroadcastReceiver:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;

    .line 42
    .line 43
    invoke-virtual {p1, v0}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 44
    .line 45
    .line 46
    iput-boolean v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->isBroadcastReceiverRegistered:Z

    .line 47
    .line 48
    :cond_0
    iget-boolean v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->isNetworkCallbackRegistered:Z

    .line 49
    .line 50
    if-eqz v0, :cond_2

    .line 51
    .line 52
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->networkCallback:Landroid/net/ConnectivityManager$NetworkCallback;

    .line 53
    .line 54
    if-eqz v0, :cond_1

    .line 55
    .line 56
    invoke-static {p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerKt;->getConnectivityManager(Landroid/content/Context;)Landroid/net/ConnectivityManager;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    if-eqz v2, :cond_1

    .line 61
    .line 62
    invoke-virtual {v2, v0}, Landroid/net/ConnectivityManager;->unregisterNetworkCallback(Landroid/net/ConnectivityManager$NetworkCallback;)V

    .line 63
    .line 64
    .line 65
    :cond_1
    iput-boolean v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->isNetworkCallbackRegistered:Z

    .line 66
    .line 67
    :cond_2
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->wifiBroadcastReceiver:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;

    .line 68
    .line 69
    new-instance v1, Landroid/content/IntentFilter;

    .line 70
    .line 71
    const-string v2, "android.net.wifi.STATE_CHANGE"

    .line 72
    .line 73
    invoke-direct {v1, v2}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    const-string v2, "android.permission.ACCESS_NETWORK_STATE"

    .line 77
    .line 78
    const/4 v3, 0x0

    .line 79
    invoke-virtual {p1, v0, v1, v2, v3}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;

    .line 80
    .line 81
    .line 82
    new-instance v1, Landroid/content/IntentFilter;

    .line 83
    .line 84
    const-string v4, "android.net.wifi.WIFI_STATE_CHANGED"

    .line 85
    .line 86
    invoke-direct {v1, v4}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {p1, v0, v1, v2, v3}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;

    .line 90
    .line 91
    .line 92
    new-instance v1, Landroid/content/IntentFilter;

    .line 93
    .line 94
    const-string v4, "android.net.wifi.WIFI_AP_STATE_CHANGED"

    .line 95
    .line 96
    invoke-direct {v1, v4}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {p1, v0, v1, v2, v3}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;

    .line 100
    .line 101
    .line 102
    const/4 v0, 0x1

    .line 103
    iput-boolean v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->isBroadcastReceiverRegistered:Z

    .line 104
    .line 105
    new-instance v1, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$registerBroadcastReceiver$3$newNetworkCallback$1;

    .line 106
    .line 107
    invoke-direct {v1, p0, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$registerBroadcastReceiver$3$newNetworkCallback$1;-><init>(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;Landroid/content/Context;)V

    .line 108
    .line 109
    .line 110
    new-instance v2, Landroid/net/NetworkRequest$Builder;

    .line 111
    .line 112
    invoke-direct {v2}, Landroid/net/NetworkRequest$Builder;-><init>()V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v2, v0}, Landroid/net/NetworkRequest$Builder;->addTransportType(I)Landroid/net/NetworkRequest$Builder;

    .line 116
    .line 117
    .line 118
    move-result-object v2

    .line 119
    invoke-virtual {v2}, Landroid/net/NetworkRequest$Builder;->build()Landroid/net/NetworkRequest;

    .line 120
    .line 121
    .line 122
    move-result-object v2

    .line 123
    invoke-static {p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerKt;->getConnectivityManager(Landroid/content/Context;)Landroid/net/ConnectivityManager;

    .line 124
    .line 125
    .line 126
    move-result-object p1

    .line 127
    if-eqz p1, :cond_3

    .line 128
    .line 129
    invoke-virtual {p1, v2, v1}, Landroid/net/ConnectivityManager;->registerNetworkCallback(Landroid/net/NetworkRequest;Landroid/net/ConnectivityManager$NetworkCallback;)V

    .line 130
    .line 131
    .line 132
    iput-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->networkCallback:Landroid/net/ConnectivityManager$NetworkCallback;

    .line 133
    .line 134
    iput-boolean v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->isNetworkCallbackRegistered:Z

    .line 135
    .line 136
    return-void

    .line 137
    :cond_3
    new-instance p1, Ltechnology/cariad/cat/genx/wifi/g;

    .line 138
    .line 139
    const/4 v0, 0x4

    .line 140
    invoke-direct {p1, v0}, Ltechnology/cariad/cat/genx/wifi/g;-><init>(I)V

    .line 141
    .line 142
    .line 143
    const-string v0, "GenX"

    .line 144
    .line 145
    invoke-static {p0, v0, v3, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 146
    .line 147
    .line 148
    return-void
.end method

.method public unregisterBroadcastReceiver(Landroid/content/Context;)V
    .locals 11

    .line 1
    sget-object v2, Lt51/e;->a:Lt51/e;

    .line 2
    .line 3
    const-string v0, "context"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    new-instance v6, Ltechnology/cariad/cat/genx/wifi/g;

    .line 9
    .line 10
    const/4 v0, 0x7

    .line 11
    invoke-direct {v6, v0}, Ltechnology/cariad/cat/genx/wifi/g;-><init>(I)V

    .line 12
    .line 13
    .line 14
    new-instance v3, Lt51/j;

    .line 15
    .line 16
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v8

    .line 20
    const-string v10, "getName(...)"

    .line 21
    .line 22
    invoke-static {v10}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v9

    .line 26
    const-string v4, "GenX"

    .line 27
    .line 28
    sget-object v5, Lt51/g;->a:Lt51/g;

    .line 29
    .line 30
    const/4 v7, 0x0

    .line 31
    invoke-direct/range {v3 .. v9}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-static {v3}, Lt51/a;->a(Lt51/j;)V

    .line 35
    .line 36
    .line 37
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->wifiBroadcastReceiver:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;

    .line 38
    .line 39
    :try_start_0
    invoke-virtual {p1, v0}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :catch_0
    move-exception v0

    .line 44
    move-object v4, v0

    .line 45
    new-instance v3, Ltechnology/cariad/cat/genx/wifi/g;

    .line 46
    .line 47
    const/16 v0, 0x8

    .line 48
    .line 49
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/wifi/g;-><init>(I)V

    .line 50
    .line 51
    .line 52
    new-instance v0, Lt51/j;

    .line 53
    .line 54
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v5

    .line 58
    invoke-static {v10}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v6

    .line 62
    const-string v1, "GenX"

    .line 63
    .line 64
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    sget-object v1, Lt51/a;->a:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 68
    .line 69
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 70
    .line 71
    .line 72
    :goto_0
    const/4 v7, 0x0

    .line 73
    iput-boolean v7, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->isBroadcastReceiverRegistered:Z

    .line 74
    .line 75
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->networkCallback:Landroid/net/ConnectivityManager$NetworkCallback;

    .line 76
    .line 77
    if-eqz v1, :cond_1

    .line 78
    .line 79
    const/4 v8, 0x0

    .line 80
    :try_start_1
    invoke-static {p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerKt;->getConnectivityManager(Landroid/content/Context;)Landroid/net/ConnectivityManager;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    if-eqz p1, :cond_0

    .line 85
    .line 86
    invoke-virtual {p1, v1}, Landroid/net/ConnectivityManager;->unregisterNetworkCallback(Landroid/net/ConnectivityManager$NetworkCallback;)V

    .line 87
    .line 88
    .line 89
    goto :goto_2

    .line 90
    :catch_1
    move-exception v0

    .line 91
    move-object p1, v0

    .line 92
    move-object v4, p1

    .line 93
    goto :goto_1

    .line 94
    :cond_0
    new-instance p1, Ltechnology/cariad/cat/genx/wifi/g;

    .line 95
    .line 96
    const/16 v0, 0x9

    .line 97
    .line 98
    invoke-direct {p1, v0}, Ltechnology/cariad/cat/genx/wifi/g;-><init>(I)V

    .line 99
    .line 100
    .line 101
    const-string v0, "GenX"

    .line 102
    .line 103
    invoke-static {p0, v0, v8, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 104
    .line 105
    .line 106
    goto :goto_2

    .line 107
    :goto_1
    new-instance v3, Ltechnology/cariad/cat/genx/wifi/m;

    .line 108
    .line 109
    const/4 p1, 0x4

    .line 110
    invoke-direct {v3, v1, p1}, Ltechnology/cariad/cat/genx/wifi/m;-><init>(Ljava/lang/Object;I)V

    .line 111
    .line 112
    .line 113
    new-instance v0, Lt51/j;

    .line 114
    .line 115
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v5

    .line 119
    invoke-static {v10}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object v6

    .line 123
    const-string v1, "GenX"

    .line 124
    .line 125
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 129
    .line 130
    .line 131
    :goto_2
    iput-object v8, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->networkCallback:Landroid/net/ConnectivityManager$NetworkCallback;

    .line 132
    .line 133
    :cond_1
    iput-boolean v7, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->isNetworkCallbackRegistered:Z

    .line 134
    .line 135
    return-void
.end method

.method public final updateWifiIfChanged$genx_release(Ltechnology/cariad/cat/genx/wifi/Wifi;)V
    .locals 8

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->hasWifiInfoChanged(Ltechnology/cariad/cat/genx/wifi/Wifi;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->_connectedWifi:Lyy0/j1;

    .line 8
    .line 9
    check-cast v0, Lyy0/c2;

    .line 10
    .line 11
    invoke-virtual {v0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    if-eqz p1, :cond_0

    .line 15
    .line 16
    new-instance v4, Ltechnology/cariad/cat/genx/wifi/k;

    .line 17
    .line 18
    const/4 v0, 0x1

    .line 19
    invoke-direct {v4, p1, v0}, Ltechnology/cariad/cat/genx/wifi/k;-><init>(Ltechnology/cariad/cat/genx/wifi/Wifi;I)V

    .line 20
    .line 21
    .line 22
    new-instance v1, Lt51/j;

    .line 23
    .line 24
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v6

    .line 28
    const-string p0, "getName(...)"

    .line 29
    .line 30
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v7

    .line 34
    const-string v2, "GenX"

    .line 35
    .line 36
    sget-object v3, Lt51/f;->a:Lt51/f;

    .line 37
    .line 38
    const/4 v5, 0x0

    .line 39
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 43
    .line 44
    .line 45
    return-void

    .line 46
    :cond_0
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->onWifiDisconnected()V

    .line 47
    .line 48
    .line 49
    :cond_1
    return-void
.end method

.method public final wifiForNetwork$genx_release(Landroid/content/Context;Landroid/net/Network;)Ltechnology/cariad/cat/genx/wifi/Wifi;
    .locals 2

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "network"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerKt;->getConnectivityManager(Landroid/content/Context;)Landroid/net/ConnectivityManager;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    invoke-virtual {v0, p2}, Landroid/net/ConnectivityManager;->getLinkProperties(Landroid/net/Network;)Landroid/net/LinkProperties;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move-object v0, v1

    .line 24
    :goto_0
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->wifiInfoFromWifiNetwork(Landroid/content/Context;Landroid/net/Network;)Landroid/net/wifi/WifiInfo;

    .line 25
    .line 26
    .line 27
    move-result-object p2

    .line 28
    if-nez p2, :cond_1

    .line 29
    .line 30
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->wifiInfoFromConnectionInfo(Landroid/content/Context;)Landroid/net/wifi/WifiInfo;

    .line 31
    .line 32
    .line 33
    move-result-object p2

    .line 34
    :cond_1
    if-eqz p2, :cond_2

    .line 35
    .line 36
    invoke-static {p2, v0}, Ltechnology/cariad/cat/genx/wifi/WifiInfoExtensionKt;->wifi(Landroid/net/wifi/WifiInfo;Landroid/net/LinkProperties;)Ltechnology/cariad/cat/genx/wifi/Wifi;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :cond_2
    return-object v1
.end method
