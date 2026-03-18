.class public final Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceCallback;,
        Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00a7\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0002\n\u0002\u0010\u0012\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u000c\n\u0002\u0010%\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010$\n\u0002\u0008\t*\u0001F\u0008\u0000\u0018\u00002\u00020\u0001:\u0002WXB\u001f\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0006\u0010\u0007\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\u000f\u0010\r\u001a\u00020\nH\u0000\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\u0017\u0010\u0012\u001a\u00020\n2\u0006\u0010\u000f\u001a\u00020\u000eH\u0000\u00a2\u0006\u0004\u0008\u0010\u0010\u0011J\u0017\u0010\u0015\u001a\u00020\n2\u0006\u0010\u0013\u001a\u00020\u000eH\u0000\u00a2\u0006\u0004\u0008\u0014\u0010\u0011J\u0015\u0010\u0019\u001a\u0008\u0012\u0004\u0012\u00020\n0\u0016H\u0016\u00a2\u0006\u0004\u0008\u0017\u0010\u0018J\u000f\u0010\u001a\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u001a\u0010\u000cJ\u000f\u0010\u001b\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u001b\u0010\u000cJQ\u0010)\u001a\u00020\n2\u000c\u0010\u001e\u001a\u0008\u0012\u0004\u0012\u00020\u001d0\u001c2\u0006\u0010 \u001a\u00020\u001f2\u0006\u0010!\u001a\u00020\u001f2\u0006\u0010#\u001a\u00020\"2\u0008\u0010%\u001a\u0004\u0018\u00010$2\u0008\u0010&\u001a\u0004\u0018\u00010$2\u0006\u0010(\u001a\u00020\'H\u0002\u00a2\u0006\u0004\u0008)\u0010*R\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010+\u001a\u0004\u0008,\u0010-R\u0017\u0010\u0005\u001a\u00020\u00048\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0005\u0010.\u001a\u0004\u0008/\u00100R\u0017\u0010\u0007\u001a\u00020\u00068\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0007\u00101\u001a\u0004\u00082\u00103R$\u00106\u001a\u0012\u0012\u0004\u0012\u00020\u000e\u0012\u0008\u0012\u000605R\u00020\u0000048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u00086\u00107R$\u00108\u001a\u0010\u0012\u0004\u0012\u00020\u000e\u0012\u0006\u0012\u0004\u0018\u00010\u000e048\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u00088\u00107R \u0010;\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020:0\u001c098\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008;\u0010<R&\u0010>\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020:0\u001c0=8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008>\u0010?\u001a\u0004\u0008@\u0010AR\u001c\u0010D\u001a\n C*\u0004\u0018\u00010B0B8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008D\u0010ER\u0014\u0010G\u001a\u00020F8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008G\u0010HR\u001a\u0010K\u001a\u0008\u0018\u00010IR\u00020J8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008K\u0010LR\u0014\u0010N\u001a\u00020M8VX\u0096\u0004\u00a2\u0006\u0006\u001a\u0004\u0008N\u0010OR$\u0010S\u001a\u000e\u0012\u0004\u0012\u00020\u001f\u0012\u0004\u0012\u00020\u001f0P*\u00020\u000e8BX\u0082\u0004\u00a2\u0006\u0006\u001a\u0004\u0008Q\u0010RR\u001e\u0010V\u001a\u0008\u0012\u0004\u0012\u00020\u001d0\u001c*\u00020\u000e8BX\u0082\u0004\u00a2\u0006\u0006\u001a\u0004\u0008T\u0010U\u00a8\u0006Y"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;",
        "Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;",
        "Landroid/content/Context;",
        "context",
        "Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;",
        "nsdManager",
        "Ltechnology/cariad/cat/genx/wifi/WifiManager;",
        "wifiManager",
        "<init>",
        "(Landroid/content/Context;Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;Ltechnology/cariad/cat/genx/wifi/WifiManager;)V",
        "Llx0/b0;",
        "resetNsdServiceInfoCallbacksAndFoundServices$genx_release",
        "()V",
        "resetNsdServiceInfoCallbacksAndFoundServices",
        "Landroid/net/nsd/NsdServiceInfo;",
        "serviceInfo",
        "onC2PServiceFound$genx_release",
        "(Landroid/net/nsd/NsdServiceInfo;)V",
        "onC2PServiceFound",
        "nsdServiceInfo",
        "onC2PServiceLost$genx_release",
        "onC2PServiceLost",
        "Llx0/o;",
        "startBonjourDiscovery-d1pmJ48",
        "()Ljava/lang/Object;",
        "startBonjourDiscovery",
        "stopBonjourDiscovery",
        "close",
        "",
        "Ljava/net/Inet4Address;",
        "addresses",
        "",
        "serviceName",
        "vin",
        "",
        "advertisement",
        "Ljava/net/InetAddress;",
        "hostIPAddress",
        "guestIPAddress",
        "",
        "port",
        "updatePotentialWifiClient",
        "(Ljava/util/List;Ljava/lang/String;Ljava/lang/String;[BLjava/net/InetAddress;Ljava/net/InetAddress;I)V",
        "Landroid/content/Context;",
        "getContext",
        "()Landroid/content/Context;",
        "Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;",
        "getNsdManager",
        "()Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;",
        "Ltechnology/cariad/cat/genx/wifi/WifiManager;",
        "getWifiManager",
        "()Ltechnology/cariad/cat/genx/wifi/WifiManager;",
        "",
        "Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceCallback;",
        "c2pServiceCallbacks",
        "Ljava/util/Map;",
        "resolvedC2PServices",
        "Lyy0/j1;",
        "Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;",
        "_potentialWifiClients",
        "Lyy0/j1;",
        "Lyy0/a2;",
        "potentialWifiClients",
        "Lyy0/a2;",
        "getPotentialWifiClients",
        "()Lyy0/a2;",
        "Ljava/util/concurrent/ExecutorService;",
        "kotlin.jvm.PlatformType",
        "executor",
        "Ljava/util/concurrent/ExecutorService;",
        "technology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1",
        "discoveryListener",
        "Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;",
        "Landroid/net/wifi/WifiManager$MulticastLock;",
        "Landroid/net/wifi/WifiManager;",
        "multiCastLock",
        "Landroid/net/wifi/WifiManager$MulticastLock;",
        "",
        "isBonjourScanningActive",
        "()Z",
        "",
        "getAttributesAsStrings",
        "(Landroid/net/nsd/NsdServiceInfo;)Ljava/util/Map;",
        "attributesAsStrings",
        "getInet4hostAddresses",
        "(Landroid/net/nsd/NsdServiceInfo;)Ljava/util/List;",
        "inet4hostAddresses",
        "ServiceInfoListener",
        "ServiceCallback",
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
.field private final _potentialWifiClients:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final c2pServiceCallbacks:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Landroid/net/nsd/NsdServiceInfo;",
            "Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceCallback;",
            ">;"
        }
    .end annotation
.end field

.field private final context:Landroid/content/Context;

.field private final discoveryListener:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;

.field private final executor:Ljava/util/concurrent/ExecutorService;

.field private final multiCastLock:Landroid/net/wifi/WifiManager$MulticastLock;

.field private final nsdManager:Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;

.field private final potentialWifiClients:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private resolvedC2PServices:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Landroid/net/nsd/NsdServiceInfo;",
            "Landroid/net/nsd/NsdServiceInfo;",
            ">;"
        }
    .end annotation
.end field

.field private final wifiManager:Ltechnology/cariad/cat/genx/wifi/WifiManager;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;Ltechnology/cariad/cat/genx/wifi/WifiManager;)V
    .locals 1

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "nsdManager"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "wifiManager"

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
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->context:Landroid/content/Context;

    .line 20
    .line 21
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->nsdManager:Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;

    .line 22
    .line 23
    iput-object p3, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->wifiManager:Ltechnology/cariad/cat/genx/wifi/WifiManager;

    .line 24
    .line 25
    new-instance p2, Ljava/util/LinkedHashMap;

    .line 26
    .line 27
    invoke-direct {p2}, Ljava/util/LinkedHashMap;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->c2pServiceCallbacks:Ljava/util/Map;

    .line 31
    .line 32
    new-instance p2, Ljava/util/LinkedHashMap;

    .line 33
    .line 34
    invoke-direct {p2}, Ljava/util/LinkedHashMap;-><init>()V

    .line 35
    .line 36
    .line 37
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->resolvedC2PServices:Ljava/util/Map;

    .line 38
    .line 39
    sget-object p2, Lmx0/s;->d:Lmx0/s;

    .line 40
    .line 41
    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 42
    .line 43
    .line 44
    move-result-object p2

    .line 45
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->_potentialWifiClients:Lyy0/j1;

    .line 46
    .line 47
    new-instance p3, Lyy0/l1;

    .line 48
    .line 49
    invoke-direct {p3, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 50
    .line 51
    .line 52
    iput-object p3, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->potentialWifiClients:Lyy0/a2;

    .line 53
    .line 54
    invoke-static {}, Ljava/util/concurrent/Executors;->newSingleThreadExecutor()Ljava/util/concurrent/ExecutorService;

    .line 55
    .line 56
    .line 57
    move-result-object p2

    .line 58
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->executor:Ljava/util/concurrent/ExecutorService;

    .line 59
    .line 60
    new-instance p2, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;

    .line 61
    .line 62
    invoke-direct {p2, p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;-><init>(Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;)V

    .line 63
    .line 64
    .line 65
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->discoveryListener:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;

    .line 66
    .line 67
    const-class p2, Landroid/net/wifi/WifiManager;

    .line 68
    .line 69
    invoke-virtual {p1, p2}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    check-cast p1, Landroid/net/wifi/WifiManager;

    .line 74
    .line 75
    if-eqz p1, :cond_0

    .line 76
    .line 77
    const-string p2, "ServiceDiscoveryLock"

    .line 78
    .line 79
    invoke-virtual {p1, p2}, Landroid/net/wifi/WifiManager;->createMulticastLock(Ljava/lang/String;)Landroid/net/wifi/WifiManager$MulticastLock;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    if-eqz p1, :cond_0

    .line 84
    .line 85
    const/4 p2, 0x1

    .line 86
    invoke-virtual {p1, p2}, Landroid/net/wifi/WifiManager$MulticastLock;->setReferenceCounted(Z)V

    .line 87
    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_0
    const/4 p1, 0x0

    .line 91
    :goto_0
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->multiCastLock:Landroid/net/wifi/WifiManager$MulticastLock;

    .line 92
    .line 93
    return-void
.end method

.method public static synthetic B(Ljava/util/List;Ljava/lang/String;Ljava/lang/String;[BLjava/net/InetAddress;Ljava/net/InetAddress;I)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static/range {p0 .. p6}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->updatePotentialWifiClient$lambda$0(Ljava/util/List;Ljava/lang/String;Ljava/lang/String;[BLjava/net/InetAddress;Ljava/net/InetAddress;I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic E(Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->onC2PServiceLost$lambda$0(Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic H(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->onC2PServiceFound$lambda$1$0(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic M(Ljava/util/List;Ljava/lang/String;Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->onC2PServiceFound$lambda$2(Ljava/util/List;Ljava/lang/String;Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic T(Ljava/util/List;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->updatePotentialWifiClient$lambda$3(Ljava/util/List;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic a()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->updatePotentialWifiClient$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static final synthetic access$getC2pServiceCallbacks$p(Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;)Ljava/util/Map;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->c2pServiceCallbacks:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getExecutor$p(Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;)Ljava/util/concurrent/ExecutorService;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->executor:Ljava/util/concurrent/ExecutorService;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getResolvedC2PServices$p(Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;)Ljava/util/Map;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->resolvedC2PServices:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic b()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->stopBonjourDiscovery$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic d()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->resetNsdServiceInfoCallbacksAndFoundServices$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic f(Ljava/util/ArrayList;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->onC2PServiceLost$lambda$3(Ljava/util/List;)Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->startBonjourDiscovery_d1pmJ48$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private final getAttributesAsStrings(Landroid/net/nsd/NsdServiceInfo;)Ljava/util/Map;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/net/nsd/NsdServiceInfo;",
            ")",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-virtual {p1}, Landroid/net/nsd/NsdServiceInfo;->getAttributes()Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string p1, "getAttributes(...)"

    .line 6
    .line 7
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    new-instance p1, Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-interface {p0}, Ljava/util/Map;->size()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 17
    .line 18
    .line 19
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    check-cast v0, Ljava/util/Map$Entry;

    .line 38
    .line 39
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    const-string v2, "<get-value>(...)"

    .line 48
    .line 49
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    check-cast v0, [B

    .line 53
    .line 54
    sget-object v2, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 55
    .line 56
    new-instance v3, Ljava/lang/String;

    .line 57
    .line 58
    invoke-direct {v3, v0, v2}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 59
    .line 60
    .line 61
    new-instance v0, Llx0/l;

    .line 62
    .line 63
    invoke-direct {v0, v1, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    invoke-interface {p1, v0}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_0
    invoke-static {p1}, Lmx0/x;->t(Ljava/lang/Iterable;)Ljava/util/Map;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0
.end method

.method private final getInet4hostAddresses(Landroid/net/nsd/NsdServiceInfo;)Ljava/util/List;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/net/nsd/NsdServiceInfo;",
            ")",
            "Ljava/util/List<",
            "Ljava/net/Inet4Address;",
            ">;"
        }
    .end annotation

    .line 1
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v0, 0x1e

    .line 4
    .line 5
    if-lt p0, v0, :cond_2

    .line 6
    .line 7
    invoke-static {}, Ln01/a;->a()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    const/4 v0, 0x7

    .line 12
    if-lt p0, v0, :cond_2

    .line 13
    .line 14
    invoke-static {p1}, Lt51/b;->n(Landroid/net/nsd/NsdServiceInfo;)Ljava/util/List;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    const-string p1, "getHostAddresses(...)"

    .line 19
    .line 20
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    check-cast p0, Ljava/lang/Iterable;

    .line 24
    .line 25
    new-instance p1, Ljava/util/ArrayList;

    .line 26
    .line 27
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 28
    .line 29
    .line 30
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-eqz v0, :cond_1

    .line 39
    .line 40
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    instance-of v1, v0, Ljava/net/Inet4Address;

    .line 45
    .line 46
    if-eqz v1, :cond_0

    .line 47
    .line 48
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_1
    return-object p1

    .line 53
    :cond_2
    invoke-virtual {p1}, Landroid/net/nsd/NsdServiceInfo;->getHost()Ljava/net/InetAddress;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    instance-of p1, p0, Ljava/net/Inet4Address;

    .line 58
    .line 59
    if-eqz p1, :cond_3

    .line 60
    .line 61
    check-cast p0, Ljava/net/Inet4Address;

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_3
    const/4 p0, 0x0

    .line 65
    :goto_1
    invoke-static {p0}, Ljp/k1;->k(Ljava/lang/Object;)Ljava/util/List;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    return-object p0
.end method

.method public static synthetic h()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->startBonjourDiscovery_d1pmJ48$lambda$2()Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->stopBonjourDiscovery$lambda$0()Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->startBonjourDiscovery_d1pmJ48$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic l(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->onC2PServiceFound$lambda$0$0(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final onC2PServiceFound$lambda$0$0(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onC2PServiceFound(): Failed to resolve Inet4Address for "

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

.method private static final onC2PServiceFound$lambda$1$0(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onC2PServiceFound(): Failed to resolve Inet4Address for "

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

.method private static final onC2PServiceFound$lambda$2(Ljava/util/List;Ljava/lang/String;Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;
    .locals 6

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Ljava/lang/Iterable;

    .line 3
    .line 4
    const/4 v4, 0x0

    .line 5
    const/16 v5, 0x3f

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x0

    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-direct {p2, p3}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->getAttributesAsStrings(Landroid/net/nsd/NsdServiceInfo;)Ljava/util/Map;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    const-string p3, ", serviceName = "

    .line 19
    .line 20
    const-string v0, ", attributes = "

    .line 21
    .line 22
    const-string v1, "onC2PServiceFound(): Cannot retrieve required information for C2PService, addresses = "

    .line 23
    .line 24
    invoke-static {v1, p0, p3, p1, v0}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0
.end method

.method private static final onC2PServiceLost$lambda$0(Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onC2PServiceLost(): serviceInfo = "

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

.method private static final onC2PServiceLost$lambda$3(Ljava/util/List;)Ljava/lang/String;
    .locals 6

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Ljava/lang/Iterable;

    .line 3
    .line 4
    const/4 v4, 0x0

    .line 5
    const/16 v5, 0x3f

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x0

    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const-string v0, "onC2PServiceLost(): Removed "

    .line 15
    .line 16
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public static synthetic q()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->updatePotentialWifiClient$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final resetNsdServiceInfoCallbacksAndFoundServices$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "resetNsdServiceInfoCallbacksAndFoundServices()"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startBonjourDiscovery_d1pmJ48$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startBonjourDiscovery()"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startBonjourDiscovery_d1pmJ48$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startBonjourDiscovery(): Failed to start bonjour discovery due to missing MulticastLock"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final startBonjourDiscovery_d1pmJ48$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startBonjourDiscovery(): Failed start service discovery for _car2phone._tcp."

    .line 2
    .line 3
    return-object v0
.end method

.method private static final stopBonjourDiscovery$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "stopBonjourDiscovery"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final stopBonjourDiscovery$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "stopBonjourDiscovery(): Failed stop service discovery for _car2phone._tcp."

    .line 2
    .line 3
    return-object v0
.end method

.method private final updatePotentialWifiClient(Ljava/util/List;Ljava/lang/String;Ljava/lang/String;[BLjava/net/InetAddress;Ljava/net/InetAddress;I)V
    .locals 22
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/net/Inet4Address;",
            ">;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "[B",
            "Ljava/net/InetAddress;",
            "Ljava/net/InetAddress;",
            "I)V"
        }
    .end annotation

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Ltechnology/cariad/cat/genx/wifi/b;

    .line 4
    .line 5
    move-object/from16 v2, p1

    .line 6
    .line 7
    move-object/from16 v3, p2

    .line 8
    .line 9
    move-object/from16 v4, p3

    .line 10
    .line 11
    move-object/from16 v5, p4

    .line 12
    .line 13
    move-object/from16 v6, p5

    .line 14
    .line 15
    move-object/from16 v7, p6

    .line 16
    .line 17
    move/from16 v8, p7

    .line 18
    .line 19
    invoke-direct/range {v1 .. v8}, Ltechnology/cariad/cat/genx/wifi/b;-><init>(Ljava/util/List;Ljava/lang/String;Ljava/lang/String;[BLjava/net/InetAddress;Ljava/net/InetAddress;I)V

    .line 20
    .line 21
    .line 22
    move-object v9, v4

    .line 23
    move-object v10, v5

    .line 24
    move-object v11, v6

    .line 25
    move-object v12, v7

    .line 26
    move v13, v8

    .line 27
    move-object v8, v2

    .line 28
    new-instance v2, Lt51/j;

    .line 29
    .line 30
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v6

    .line 34
    const-string v14, "getName(...)"

    .line 35
    .line 36
    invoke-static {v14}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v7

    .line 40
    move-object v4, v1

    .line 41
    move-object v1, v2

    .line 42
    const-string v2, "GenX"

    .line 43
    .line 44
    sget-object v3, Lt51/g;->a:Lt51/g;

    .line 45
    .line 46
    const/4 v5, 0x0

    .line 47
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 51
    .line 52
    .line 53
    iget-object v1, v0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->wifiManager:Ltechnology/cariad/cat/genx/wifi/WifiManager;

    .line 54
    .line 55
    invoke-interface {v1}, Ltechnology/cariad/cat/genx/wifi/WifiManager;->getConnectedWifi()Lyy0/a2;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    invoke-interface {v1}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    check-cast v1, Ltechnology/cariad/cat/genx/wifi/Wifi;

    .line 64
    .line 65
    const/4 v2, 0x0

    .line 66
    if-eqz v1, :cond_0

    .line 67
    .line 68
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/wifi/Wifi;->getIpAddress()Ljava/net/Inet4Address;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    if-eqz v1, :cond_0

    .line 73
    .line 74
    invoke-virtual {v1}, Ljava/net/Inet4Address;->getHostAddress()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v1

    .line 78
    if-eqz v1, :cond_0

    .line 79
    .line 80
    invoke-static {v1, v1}, Lly0/p;->i0(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    goto :goto_0

    .line 85
    :cond_0
    move-object v1, v2

    .line 86
    :goto_0
    if-eqz v12, :cond_1

    .line 87
    .line 88
    invoke-virtual {v12}, Ljava/net/InetAddress;->getHostAddress()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    if-eqz v3, :cond_1

    .line 93
    .line 94
    invoke-static {v3, v3}, Lly0/p;->i0(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v3

    .line 98
    goto :goto_1

    .line 99
    :cond_1
    move-object v3, v2

    .line 100
    :goto_1
    if-eqz v12, :cond_2

    .line 101
    .line 102
    invoke-virtual {v12}, Ljava/net/InetAddress;->getHostAddress()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object v4

    .line 106
    if-eqz v4, :cond_2

    .line 107
    .line 108
    invoke-static {v4, v4}, Lly0/p;->i0(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v2

    .line 112
    :cond_2
    iget-object v4, v0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->wifiManager:Ltechnology/cariad/cat/genx/wifi/WifiManager;

    .line 113
    .line 114
    invoke-interface {v4}, Ltechnology/cariad/cat/genx/wifi/WifiManager;->getAccessPointState()Lyy0/a2;

    .line 115
    .line 116
    .line 117
    move-result-object v4

    .line 118
    invoke-interface {v4}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v4

    .line 122
    sget-object v5, Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;->ENABLED:Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;

    .line 123
    .line 124
    sget-object v17, Lt51/d;->a:Lt51/d;

    .line 125
    .line 126
    if-ne v4, v5, :cond_3

    .line 127
    .line 128
    if-eqz v12, :cond_3

    .line 129
    .line 130
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v3

    .line 134
    if-eqz v3, :cond_3

    .line 135
    .line 136
    new-instance v1, Ltechnology/cariad/cat/genx/wifi/i;

    .line 137
    .line 138
    const/4 v2, 0x5

    .line 139
    invoke-direct {v1, v2}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 140
    .line 141
    .line 142
    new-instance v15, Lt51/j;

    .line 143
    .line 144
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v20

    .line 148
    invoke-static {v14}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v21

    .line 152
    const-string v16, "GenX"

    .line 153
    .line 154
    const/16 v19, 0x0

    .line 155
    .line 156
    move-object/from16 v18, v1

    .line 157
    .line 158
    invoke-direct/range {v15 .. v21}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    invoke-static {v15}, Lt51/a;->a(Lt51/j;)V

    .line 162
    .line 163
    .line 164
    new-instance v1, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;

    .line 165
    .line 166
    invoke-direct {v1, v12, v13, v9, v10}, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;-><init>(Ljava/net/InetAddress;ILjava/lang/String;[B)V

    .line 167
    .line 168
    .line 169
    invoke-static {v1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 170
    .line 171
    .line 172
    move-result-object v1

    .line 173
    goto/16 :goto_3

    .line 174
    .line 175
    :cond_3
    iget-object v3, v0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->wifiManager:Ltechnology/cariad/cat/genx/wifi/WifiManager;

    .line 176
    .line 177
    invoke-interface {v3}, Ltechnology/cariad/cat/genx/wifi/WifiManager;->getAccessPointState()Lyy0/a2;

    .line 178
    .line 179
    .line 180
    move-result-object v3

    .line 181
    invoke-interface {v3}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v3

    .line 185
    if-eq v3, v5, :cond_4

    .line 186
    .line 187
    if-eqz v11, :cond_4

    .line 188
    .line 189
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    move-result v1

    .line 193
    if-eqz v1, :cond_4

    .line 194
    .line 195
    new-instance v1, Ltechnology/cariad/cat/genx/wifi/i;

    .line 196
    .line 197
    const/4 v2, 0x6

    .line 198
    invoke-direct {v1, v2}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 199
    .line 200
    .line 201
    new-instance v15, Lt51/j;

    .line 202
    .line 203
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object v20

    .line 207
    invoke-static {v14}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 208
    .line 209
    .line 210
    move-result-object v21

    .line 211
    const-string v16, "GenX"

    .line 212
    .line 213
    const/16 v19, 0x0

    .line 214
    .line 215
    move-object/from16 v18, v1

    .line 216
    .line 217
    invoke-direct/range {v15 .. v21}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 218
    .line 219
    .line 220
    invoke-static {v15}, Lt51/a;->a(Lt51/j;)V

    .line 221
    .line 222
    .line 223
    new-instance v1, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;

    .line 224
    .line 225
    invoke-direct {v1, v11, v13, v9, v10}, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;-><init>(Ljava/net/InetAddress;ILjava/lang/String;[B)V

    .line 226
    .line 227
    .line 228
    invoke-static {v1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 229
    .line 230
    .line 231
    move-result-object v1

    .line 232
    goto :goto_3

    .line 233
    :cond_4
    new-instance v1, Ltechnology/cariad/cat/genx/wifi/j;

    .line 234
    .line 235
    const/4 v2, 0x1

    .line 236
    invoke-direct {v1, v8, v2}, Ltechnology/cariad/cat/genx/wifi/j;-><init>(Ljava/util/List;I)V

    .line 237
    .line 238
    .line 239
    new-instance v15, Lt51/j;

    .line 240
    .line 241
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object v20

    .line 245
    invoke-static {v14}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 246
    .line 247
    .line 248
    move-result-object v21

    .line 249
    const-string v16, "GenX"

    .line 250
    .line 251
    const/16 v19, 0x0

    .line 252
    .line 253
    move-object/from16 v18, v1

    .line 254
    .line 255
    invoke-direct/range {v15 .. v21}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 256
    .line 257
    .line 258
    invoke-static {v15}, Lt51/a;->a(Lt51/j;)V

    .line 259
    .line 260
    .line 261
    move-object v1, v8

    .line 262
    check-cast v1, Ljava/lang/Iterable;

    .line 263
    .line 264
    new-instance v2, Ljava/util/ArrayList;

    .line 265
    .line 266
    const/16 v3, 0xa

    .line 267
    .line 268
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 269
    .line 270
    .line 271
    move-result v3

    .line 272
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 273
    .line 274
    .line 275
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 276
    .line 277
    .line 278
    move-result-object v1

    .line 279
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 280
    .line 281
    .line 282
    move-result v3

    .line 283
    if-eqz v3, :cond_5

    .line 284
    .line 285
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v3

    .line 289
    check-cast v3, Ljava/net/Inet4Address;

    .line 290
    .line 291
    new-instance v4, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;

    .line 292
    .line 293
    invoke-direct {v4, v3, v13, v9, v10}, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;-><init>(Ljava/net/InetAddress;ILjava/lang/String;[B)V

    .line 294
    .line 295
    .line 296
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 297
    .line 298
    .line 299
    goto :goto_2

    .line 300
    :cond_5
    move-object v1, v2

    .line 301
    :goto_3
    iget-object v2, v0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->_potentialWifiClients:Lyy0/j1;

    .line 302
    .line 303
    check-cast v2, Lyy0/c2;

    .line 304
    .line 305
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 306
    .line 307
    .line 308
    move-result-object v2

    .line 309
    check-cast v2, Ljava/lang/Iterable;

    .line 310
    .line 311
    new-instance v3, Ljava/util/ArrayList;

    .line 312
    .line 313
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 314
    .line 315
    .line 316
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 317
    .line 318
    .line 319
    move-result-object v2

    .line 320
    :cond_6
    :goto_4
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 321
    .line 322
    .line 323
    move-result v4

    .line 324
    if-eqz v4, :cond_7

    .line 325
    .line 326
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 327
    .line 328
    .line 329
    move-result-object v4

    .line 330
    move-object v5, v4

    .line 331
    check-cast v5, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;

    .line 332
    .line 333
    invoke-virtual {v5}, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->getVin()Ljava/lang/String;

    .line 334
    .line 335
    .line 336
    move-result-object v5

    .line 337
    invoke-static {v5, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 338
    .line 339
    .line 340
    move-result v5

    .line 341
    if-eqz v5, :cond_6

    .line 342
    .line 343
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 344
    .line 345
    .line 346
    goto :goto_4

    .line 347
    :cond_7
    invoke-static {v3}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 348
    .line 349
    .line 350
    move-result-object v2

    .line 351
    iget-object v0, v0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->_potentialWifiClients:Lyy0/j1;

    .line 352
    .line 353
    :cond_8
    move-object v3, v0

    .line 354
    check-cast v3, Lyy0/c2;

    .line 355
    .line 356
    invoke-virtual {v3}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 357
    .line 358
    .line 359
    move-result-object v4

    .line 360
    move-object v5, v4

    .line 361
    check-cast v5, Ljava/util/List;

    .line 362
    .line 363
    check-cast v5, Ljava/lang/Iterable;

    .line 364
    .line 365
    move-object v6, v2

    .line 366
    check-cast v6, Ljava/lang/Iterable;

    .line 367
    .line 368
    invoke-static {v5, v6}, Lmx0/q;->X(Ljava/lang/Iterable;Ljava/lang/Iterable;)Ljava/util/List;

    .line 369
    .line 370
    .line 371
    move-result-object v5

    .line 372
    check-cast v5, Ljava/util/Collection;

    .line 373
    .line 374
    move-object v6, v1

    .line 375
    check-cast v6, Ljava/lang/Iterable;

    .line 376
    .line 377
    invoke-static {v6, v5}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 378
    .line 379
    .line 380
    move-result-object v5

    .line 381
    invoke-virtual {v3, v4, v5}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 382
    .line 383
    .line 384
    move-result v3

    .line 385
    if-eqz v3, :cond_8

    .line 386
    .line 387
    return-void
.end method

.method private static final updatePotentialWifiClient$lambda$0(Ljava/util/List;Ljava/lang/String;Ljava/lang/String;[BLjava/net/InetAddress;Ljava/net/InetAddress;I)Ljava/lang/String;
    .locals 6

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Ljava/lang/Iterable;

    .line 3
    .line 4
    const/4 v4, 0x0

    .line 5
    const/16 v5, 0x3f

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x0

    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-static {p3}, Lly0/d;->l([B)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p3

    .line 18
    const-string v0, ", serviceName = "

    .line 19
    .line 20
    const-string v1, ", vin = "

    .line 21
    .line 22
    const-string v2, "updatePotentialWifiClient(): serviceAddresses = "

    .line 23
    .line 24
    invoke-static {v2, p0, v0, p1, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    const-string p1, ", advertisement = "

    .line 29
    .line 30
    const-string v0, ", hostIPAddress = "

    .line 31
    .line 32
    invoke-static {p0, p2, p1, p3, v0}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    const-string p1, ", guestIPAddress = "

    .line 39
    .line 40
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0, p5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string p1, ", port = "

    .line 47
    .line 48
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0, p6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0
.end method

.method private static final updatePotentialWifiClient$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "updatePotentialWifiClient(): Use provided guestIPAddress, since it matches the current clients network address range"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final updatePotentialWifiClient$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "updatePotentialWifiClient(): Use provided hostIPAddress, since it matches the current clients network address range"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final updatePotentialWifiClient$lambda$3(Ljava/util/List;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "updatePotentialWifiClient(): Use provided "

    .line 2
    .line 3
    const-string v1, ", since hostIPAddress and guestIPAddress do not match"

    .line 4
    .line 5
    invoke-static {v0, v1, p0}, Lp3/m;->l(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method


# virtual methods
.method public close()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->stopBonjourDiscovery()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final getContext()Landroid/content/Context;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->context:Landroid/content/Context;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getNsdManager()Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->nsdManager:Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;

    .line 2
    .line 3
    return-object p0
.end method

.method public getPotentialWifiClients()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->potentialWifiClients:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getWifiManager()Ltechnology/cariad/cat/genx/wifi/WifiManager;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->wifiManager:Ltechnology/cariad/cat/genx/wifi/WifiManager;

    .line 2
    .line 3
    return-object p0
.end method

.method public isBonjourScanningActive()Z
    .locals 2

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->multiCastLock:Landroid/net/wifi/WifiManager$MulticastLock;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p0, :cond_0

    .line 5
    .line 6
    invoke-virtual {p0}, Landroid/net/wifi/WifiManager$MulticastLock;->isHeld()Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/4 v1, 0x1

    .line 11
    if-ne p0, v1, :cond_0

    .line 12
    .line 13
    return v1

    .line 14
    :cond_0
    return v0
.end method

.method public final onC2PServiceFound$genx_release(Landroid/net/nsd/NsdServiceInfo;)V
    .locals 12

    .line 1
    const-string v0, "serviceInfo"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->resolvedC2PServices:Ljava/util/Map;

    .line 7
    .line 8
    invoke-interface {v0, p1, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->getInet4hostAddresses(Landroid/net/nsd/NsdServiceInfo;)Ljava/util/List;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    invoke-virtual {p1}, Landroid/net/nsd/NsdServiceInfo;->getServiceName()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->getAttributesAsStrings(Landroid/net/nsd/NsdServiceInfo;)Ljava/util/Map;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const-string v1, "VIN"

    .line 24
    .line 25
    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    move-object v4, v0

    .line 30
    check-cast v4, Ljava/lang/String;

    .line 31
    .line 32
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->getAttributesAsStrings(Landroid/net/nsd/NsdServiceInfo;)Ljava/util/Map;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    const-string v1, "advertisement"

    .line 37
    .line 38
    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    check-cast v0, Ljava/lang/String;

    .line 43
    .line 44
    const/4 v1, 0x0

    .line 45
    if-eqz v0, :cond_0

    .line 46
    .line 47
    invoke-static {v0}, Lly0/d;->d(Ljava/lang/String;)[B

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    move-object v5, v0

    .line 52
    goto :goto_0

    .line 53
    :cond_0
    move-object v5, v1

    .line 54
    :goto_0
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->getAttributesAsStrings(Landroid/net/nsd/NsdServiceInfo;)Ljava/util/Map;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    const-string v6, "port"

    .line 59
    .line 60
    invoke-interface {v0, v6}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    check-cast v0, Ljava/lang/String;

    .line 65
    .line 66
    if-eqz v0, :cond_1

    .line 67
    .line 68
    invoke-static {v0}, Lly0/w;->y(Ljava/lang/String;)Ljava/lang/Integer;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    if-eqz v0, :cond_1

    .line 73
    .line 74
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    :goto_1
    move v8, v0

    .line 79
    goto :goto_2

    .line 80
    :cond_1
    const v0, 0xa8f2

    .line 81
    .line 82
    .line 83
    goto :goto_1

    .line 84
    :goto_2
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->getAttributesAsStrings(Landroid/net/nsd/NsdServiceInfo;)Ljava/util/Map;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    const-string v6, "car2PhoneHotspotIP"

    .line 89
    .line 90
    invoke-interface {v0, v6}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    move-object v6, v0

    .line 95
    check-cast v6, Ljava/lang/String;

    .line 96
    .line 97
    const-string v7, "GenX"

    .line 98
    .line 99
    if-eqz v6, :cond_2

    .line 100
    .line 101
    :try_start_0
    invoke-static {v6}, Ljava/net/InetAddress;->getByName(Ljava/lang/String;)Ljava/net/InetAddress;

    .line 102
    .line 103
    .line 104
    move-result-object v0
    :try_end_0
    .catch Ljava/net/UnknownHostException; {:try_start_0 .. :try_end_0} :catch_0

    .line 105
    goto :goto_3

    .line 106
    :catch_0
    move-exception v0

    .line 107
    new-instance v9, Ltechnology/cariad/cat/genx/wifi/a;

    .line 108
    .line 109
    const/4 v10, 0x0

    .line 110
    invoke-direct {v9, v6, v10}, Ltechnology/cariad/cat/genx/wifi/a;-><init>(Ljava/lang/String;I)V

    .line 111
    .line 112
    .line 113
    invoke-static {p0, v7, v0, v9}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 114
    .line 115
    .line 116
    move-object v0, v1

    .line 117
    :goto_3
    move-object v6, v0

    .line 118
    goto :goto_4

    .line 119
    :cond_2
    move-object v6, v1

    .line 120
    :goto_4
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->getAttributesAsStrings(Landroid/net/nsd/NsdServiceInfo;)Ljava/util/Map;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    const-string v9, "car2PhoneGuestIP"

    .line 125
    .line 126
    invoke-interface {v0, v9}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v0

    .line 130
    move-object v9, v0

    .line 131
    check-cast v9, Ljava/lang/String;

    .line 132
    .line 133
    if-eqz v9, :cond_3

    .line 134
    .line 135
    :try_start_1
    invoke-static {v9}, Ljava/net/InetAddress;->getByName(Ljava/lang/String;)Ljava/net/InetAddress;

    .line 136
    .line 137
    .line 138
    move-result-object v1
    :try_end_1
    .catch Ljava/net/UnknownHostException; {:try_start_1 .. :try_end_1} :catch_1

    .line 139
    goto :goto_5

    .line 140
    :catch_1
    move-exception v0

    .line 141
    new-instance v10, Ltechnology/cariad/cat/genx/wifi/a;

    .line 142
    .line 143
    const/4 v11, 0x1

    .line 144
    invoke-direct {v10, v9, v11}, Ltechnology/cariad/cat/genx/wifi/a;-><init>(Ljava/lang/String;I)V

    .line 145
    .line 146
    .line 147
    invoke-static {p0, v7, v0, v10}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 148
    .line 149
    .line 150
    :cond_3
    :goto_5
    move-object v7, v1

    .line 151
    if-eqz v4, :cond_4

    .line 152
    .line 153
    if-eqz v5, :cond_4

    .line 154
    .line 155
    array-length v0, v5

    .line 156
    if-nez v0, :cond_5

    .line 157
    .line 158
    :cond_4
    move-object v1, p0

    .line 159
    goto :goto_6

    .line 160
    :cond_5
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    move-object v1, p0

    .line 164
    invoke-direct/range {v1 .. v8}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->updatePotentialWifiClient(Ljava/util/List;Ljava/lang/String;Ljava/lang/String;[BLjava/net/InetAddress;Ljava/net/InetAddress;I)V

    .line 165
    .line 166
    .line 167
    goto :goto_7

    .line 168
    :goto_6
    new-instance v7, Lal/i;

    .line 169
    .line 170
    const/16 v6, 0xf

    .line 171
    .line 172
    move-object v5, p1

    .line 173
    move-object v4, v1

    .line 174
    move-object v1, v7

    .line 175
    invoke-direct/range {v1 .. v6}, Lal/i;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 176
    .line 177
    .line 178
    move-object v1, v4

    .line 179
    new-instance v4, Lt51/j;

    .line 180
    .line 181
    invoke-static {v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v9

    .line 185
    const-string p0, "getName(...)"

    .line 186
    .line 187
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object v10

    .line 191
    const-string v5, "GenX"

    .line 192
    .line 193
    sget-object v6, Lt51/g;->a:Lt51/g;

    .line 194
    .line 195
    const/4 v8, 0x0

    .line 196
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 200
    .line 201
    .line 202
    :goto_7
    return-void
.end method

.method public final onC2PServiceLost$genx_release(Landroid/net/nsd/NsdServiceInfo;)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-string v2, "nsdServiceInfo"

    .line 6
    .line 7
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    new-instance v6, Ltechnology/cariad/cat/genx/wifi/c;

    .line 11
    .line 12
    const/4 v2, 0x2

    .line 13
    invoke-direct {v6, v1, v2}, Ltechnology/cariad/cat/genx/wifi/c;-><init>(Landroid/net/nsd/NsdServiceInfo;I)V

    .line 14
    .line 15
    .line 16
    new-instance v3, Lt51/j;

    .line 17
    .line 18
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v8

    .line 22
    const-string v2, "getName(...)"

    .line 23
    .line 24
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v9

    .line 28
    const-string v4, "GenX"

    .line 29
    .line 30
    sget-object v5, Lt51/g;->a:Lt51/g;

    .line 31
    .line 32
    const/4 v7, 0x0

    .line 33
    invoke-direct/range {v3 .. v9}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-static {v3}, Lt51/a;->a(Lt51/j;)V

    .line 37
    .line 38
    .line 39
    iget-object v3, v0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->_potentialWifiClients:Lyy0/j1;

    .line 40
    .line 41
    check-cast v3, Lyy0/c2;

    .line 42
    .line 43
    invoke-virtual {v3}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v3

    .line 47
    check-cast v3, Ljava/lang/Iterable;

    .line 48
    .line 49
    new-instance v4, Ljava/util/ArrayList;

    .line 50
    .line 51
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 52
    .line 53
    .line 54
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 55
    .line 56
    .line 57
    move-result-object v3

    .line 58
    :cond_0
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 59
    .line 60
    .line 61
    move-result v6

    .line 62
    if-eqz v6, :cond_1

    .line 63
    .line 64
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v6

    .line 68
    move-object v7, v6

    .line 69
    check-cast v7, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;

    .line 70
    .line 71
    invoke-direct/range {p0 .. p1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->getInet4hostAddresses(Landroid/net/nsd/NsdServiceInfo;)Ljava/util/List;

    .line 72
    .line 73
    .line 74
    move-result-object v8

    .line 75
    check-cast v8, Ljava/lang/Iterable;

    .line 76
    .line 77
    invoke-virtual {v7}, Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;->getAddress()Ljava/net/InetAddress;

    .line 78
    .line 79
    .line 80
    move-result-object v7

    .line 81
    invoke-static {v8, v7}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v7

    .line 85
    if-eqz v7, :cond_0

    .line 86
    .line 87
    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_1
    iget-object v3, v0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->_potentialWifiClients:Lyy0/j1;

    .line 92
    .line 93
    :cond_2
    move-object v6, v3

    .line 94
    check-cast v6, Lyy0/c2;

    .line 95
    .line 96
    invoke-virtual {v6}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v7

    .line 100
    move-object v8, v7

    .line 101
    check-cast v8, Ljava/util/List;

    .line 102
    .line 103
    check-cast v8, Ljava/lang/Iterable;

    .line 104
    .line 105
    invoke-static {v4}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 106
    .line 107
    .line 108
    move-result-object v9

    .line 109
    check-cast v9, Ljava/lang/Iterable;

    .line 110
    .line 111
    invoke-static {v8, v9}, Lmx0/q;->X(Ljava/lang/Iterable;Ljava/lang/Iterable;)Ljava/util/List;

    .line 112
    .line 113
    .line 114
    move-result-object v8

    .line 115
    invoke-virtual {v6, v7, v8}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v6

    .line 119
    if-eqz v6, :cond_2

    .line 120
    .line 121
    iget-object v3, v0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->resolvedC2PServices:Ljava/util/Map;

    .line 122
    .line 123
    invoke-interface {v3, v1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    new-instance v13, Ltechnology/cariad/cat/genx/wifi/m;

    .line 127
    .line 128
    const/4 v1, 0x1

    .line 129
    invoke-direct {v13, v4, v1}, Ltechnology/cariad/cat/genx/wifi/m;-><init>(Ljava/lang/Object;I)V

    .line 130
    .line 131
    .line 132
    new-instance v10, Lt51/j;

    .line 133
    .line 134
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v15

    .line 138
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object v16

    .line 142
    const-string v11, "GenX"

    .line 143
    .line 144
    const/4 v14, 0x0

    .line 145
    move-object v12, v5

    .line 146
    invoke-direct/range {v10 .. v16}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    invoke-static {v10}, Lt51/a;->a(Lt51/j;)V

    .line 150
    .line 151
    .line 152
    return-void
.end method

.method public final resetNsdServiceInfoCallbacksAndFoundServices$genx_release()V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/wifi/i;

    .line 2
    .line 3
    const/16 v0, 0xc

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
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 32
    .line 33
    const/16 v1, 0x1e

    .line 34
    .line 35
    if-lt v0, v1, :cond_0

    .line 36
    .line 37
    invoke-static {}, Ln01/a;->a()I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    const/4 v1, 0x7

    .line 42
    if-lt v0, v1, :cond_0

    .line 43
    .line 44
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->c2pServiceCallbacks:Ljava/util/Map;

    .line 45
    .line 46
    invoke-interface {v0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    check-cast v0, Ljava/lang/Iterable;

    .line 51
    .line 52
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    if-eqz v1, :cond_0

    .line 61
    .line 62
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    check-cast v1, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceCallback;

    .line 67
    .line 68
    iget-object v2, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->nsdManager:Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;

    .line 69
    .line 70
    invoke-static {v1}, Lt51/b;->g(Ljava/lang/Object;)Landroid/net/nsd/NsdManager$ServiceInfoCallback;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    invoke-interface {v2, v1}, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;->unregisterServiceInfoCallback(Landroid/net/nsd/NsdManager$ServiceInfoCallback;)V

    .line 75
    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->c2pServiceCallbacks:Ljava/util/Map;

    .line 79
    .line 80
    invoke-interface {v0}, Ljava/util/Map;->clear()V

    .line 81
    .line 82
    .line 83
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->resolvedC2PServices:Ljava/util/Map;

    .line 84
    .line 85
    invoke-interface {v0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    check-cast v0, Ljava/lang/Iterable;

    .line 90
    .line 91
    invoke-static {v0}, Lmx0/q;->H(Ljava/lang/Iterable;)Ljava/util/ArrayList;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 96
    .line 97
    .line 98
    move-result-object v0

    .line 99
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    if-eqz v1, :cond_1

    .line 104
    .line 105
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    check-cast v1, Landroid/net/nsd/NsdServiceInfo;

    .line 110
    .line 111
    invoke-virtual {p0, v1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->onC2PServiceLost$genx_release(Landroid/net/nsd/NsdServiceInfo;)V

    .line 112
    .line 113
    .line 114
    goto :goto_1

    .line 115
    :cond_1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->resolvedC2PServices:Ljava/util/Map;

    .line 116
    .line 117
    invoke-interface {v0}, Ljava/util/Map;->clear()V

    .line 118
    .line 119
    .line 120
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->_potentialWifiClients:Lyy0/j1;

    .line 121
    .line 122
    :cond_2
    move-object v0, p0

    .line 123
    check-cast v0, Lyy0/c2;

    .line 124
    .line 125
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v1

    .line 129
    move-object v2, v1

    .line 130
    check-cast v2, Ljava/util/List;

    .line 131
    .line 132
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 133
    .line 134
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    move-result v0

    .line 138
    if-eqz v0, :cond_2

    .line 139
    .line 140
    return-void
.end method

.method public startBonjourDiscovery-d1pmJ48()Ljava/lang/Object;
    .locals 15

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/wifi/i;

    .line 2
    .line 3
    const/16 v0, 0x9

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
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->multiCastLock:Landroid/net/wifi/WifiManager$MulticastLock;

    .line 32
    .line 33
    if-nez v0, :cond_0

    .line 34
    .line 35
    new-instance v0, Ltechnology/cariad/cat/genx/wifi/i;

    .line 36
    .line 37
    const/16 v1, 0xa

    .line 38
    .line 39
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 40
    .line 41
    .line 42
    const-string v1, "GenX"

    .line 43
    .line 44
    const/4 v2, 0x0

    .line 45
    invoke-static {p0, v1, v2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 46
    .line 47
    .line 48
    new-instance p0, Ltechnology/cariad/cat/genx/GenXError$Wifi$BonjourFailed;

    .line 49
    .line 50
    const-string v0, "MulticastLock missing"

    .line 51
    .line 52
    invoke-direct {p0, v2, v0}, Ltechnology/cariad/cat/genx/GenXError$Wifi$BonjourFailed;-><init>(Ljava/lang/Throwable;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    :cond_0
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->isBonjourScanningActive()Z

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    if-nez v0, :cond_1

    .line 67
    .line 68
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->resetNsdServiceInfoCallbacksAndFoundServices$genx_release()V

    .line 69
    .line 70
    .line 71
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->multiCastLock:Landroid/net/wifi/WifiManager$MulticastLock;

    .line 72
    .line 73
    invoke-virtual {v0}, Landroid/net/wifi/WifiManager$MulticastLock;->acquire()V

    .line 74
    .line 75
    .line 76
    :try_start_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->nsdManager:Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;

    .line 77
    .line 78
    const-string v2, "_car2phone._tcp."

    .line 79
    .line 80
    iget-object v3, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->discoveryListener:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;

    .line 81
    .line 82
    const/4 v4, 0x1

    .line 83
    invoke-interface {v0, v2, v4, v3}, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;->discoverServices(Ljava/lang/String;ILandroid/net/nsd/NsdManager$DiscoveryListener;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 84
    .line 85
    .line 86
    return-object v1

    .line 87
    :catch_0
    move-exception v0

    .line 88
    move-object v12, v0

    .line 89
    new-instance v11, Ltechnology/cariad/cat/genx/wifi/i;

    .line 90
    .line 91
    const/16 v0, 0xb

    .line 92
    .line 93
    invoke-direct {v11, v0}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 94
    .line 95
    .line 96
    new-instance v8, Lt51/j;

    .line 97
    .line 98
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object v13

    .line 102
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object v14

    .line 106
    const-string v9, "GenX"

    .line 107
    .line 108
    sget-object v10, Lt51/e;->a:Lt51/e;

    .line 109
    .line 110
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->resetNsdServiceInfoCallbacksAndFoundServices$genx_release()V

    .line 117
    .line 118
    .line 119
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->multiCastLock:Landroid/net/wifi/WifiManager$MulticastLock;

    .line 120
    .line 121
    invoke-virtual {p0}, Landroid/net/wifi/WifiManager$MulticastLock;->release()V

    .line 122
    .line 123
    .line 124
    new-instance p0, Ltechnology/cariad/cat/genx/GenXError$Wifi$BonjourFailed;

    .line 125
    .line 126
    const-string v0, "Failed to start service discovery for _car2phone._tcp."

    .line 127
    .line 128
    invoke-direct {p0, v12, v0}, Ltechnology/cariad/cat/genx/GenXError$Wifi$BonjourFailed;-><init>(Ljava/lang/Throwable;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    return-object p0

    .line 136
    :cond_1
    return-object v1
.end method

.method public stopBonjourDiscovery()V
    .locals 15

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/wifi/i;

    .line 2
    .line 3
    const/4 v0, 0x7

    .line 4
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

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
    const-string v7, "getName(...)"

    .line 14
    .line 15
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

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
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->isBonjourScanningActive()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_1

    .line 35
    .line 36
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->multiCastLock:Landroid/net/wifi/WifiManager$MulticastLock;

    .line 37
    .line 38
    if-eqz v0, :cond_0

    .line 39
    .line 40
    invoke-virtual {v0}, Landroid/net/wifi/WifiManager$MulticastLock;->isHeld()Z

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    const/4 v1, 0x1

    .line 45
    if-ne v0, v1, :cond_0

    .line 46
    .line 47
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->multiCastLock:Landroid/net/wifi/WifiManager$MulticastLock;

    .line 48
    .line 49
    invoke-virtual {v0}, Landroid/net/wifi/WifiManager$MulticastLock;->release()V

    .line 50
    .line 51
    .line 52
    :cond_0
    :try_start_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->nsdManager:Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;

    .line 53
    .line 54
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->discoveryListener:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;

    .line 55
    .line 56
    invoke-interface {v0, v1}, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;->stopServiceDiscovery(Landroid/net/nsd/NsdManager$DiscoveryListener;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :catch_0
    move-exception v0

    .line 61
    move-object v12, v0

    .line 62
    new-instance v11, Ltechnology/cariad/cat/genx/wifi/i;

    .line 63
    .line 64
    const/16 v0, 0x8

    .line 65
    .line 66
    invoke-direct {v11, v0}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 67
    .line 68
    .line 69
    new-instance v8, Lt51/j;

    .line 70
    .line 71
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v13

    .line 75
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v14

    .line 79
    const-string v9, "GenX"

    .line 80
    .line 81
    sget-object v10, Lt51/e;->a:Lt51/e;

    .line 82
    .line 83
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 87
    .line 88
    .line 89
    :cond_1
    :goto_0
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->resetNsdServiceInfoCallbacksAndFoundServices$genx_release()V

    .line 90
    .line 91
    .line 92
    return-void
.end method
