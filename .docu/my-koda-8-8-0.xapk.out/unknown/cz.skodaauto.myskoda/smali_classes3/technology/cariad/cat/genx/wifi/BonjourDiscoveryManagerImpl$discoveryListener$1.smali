.class public final Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/net/nsd/NsdManager$DiscoveryListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;-><init>(Landroid/content/Context;Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;Ltechnology/cariad/cat/genx/wifi/WifiManager;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000%\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\n*\u0001\u0000\u0008\n\u0018\u00002\u00020\u0001J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0002\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\u0017\u0010\u0007\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0003\u00a2\u0006\u0004\u0008\u0007\u0010\u0006J\u001f\u0010\u000c\u001a\u00020\u00042\u0006\u0010\t\u001a\u00020\u00082\u0006\u0010\u000b\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u001f\u0010\u000e\u001a\u00020\u00042\u0006\u0010\t\u001a\u00020\u00082\u0006\u0010\u000b\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u000e\u0010\rJ\u0017\u0010\u000f\u001a\u00020\u00042\u0006\u0010\t\u001a\u00020\u0008H\u0016\u00a2\u0006\u0004\u0008\u000f\u0010\u0010J\u0017\u0010\u0011\u001a\u00020\u00042\u0006\u0010\t\u001a\u00020\u0008H\u0016\u00a2\u0006\u0004\u0008\u0011\u0010\u0010J\u0017\u0010\u0012\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0016\u00a2\u0006\u0004\u0008\u0012\u0010\u0006J\u0017\u0010\u0013\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0017\u00a2\u0006\u0004\u0008\u0013\u0010\u0006\u00a8\u0006\u0014"
    }
    d2 = {
        "technology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1",
        "Landroid/net/nsd/NsdManager$DiscoveryListener;",
        "Landroid/net/nsd/NsdServiceInfo;",
        "serviceInfo",
        "Llx0/b0;",
        "resolveServiceAPI34AndBelow",
        "(Landroid/net/nsd/NsdServiceInfo;)V",
        "resolveService35AndHigher",
        "",
        "serviceType",
        "",
        "errorCode",
        "onStartDiscoveryFailed",
        "(Ljava/lang/String;I)V",
        "onStopDiscoveryFailed",
        "onDiscoveryStarted",
        "(Ljava/lang/String;)V",
        "onDiscoveryStopped",
        "onServiceFound",
        "onServiceLost",
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
.field final synthetic this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static synthetic a()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->onServiceLost$lambda$15()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic b(Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->onServiceLost$lambda$12(Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic c(I)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->onStopDiscoveryFailed$lambda$2(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->onDiscoveryStarted$lambda$3()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic e(Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->onServiceFound$lambda$5(Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->onDiscoveryStopped$lambda$4()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic g(Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->resolveService35AndHigher$lambda$9(Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic h()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->resolveServiceAPI34AndBelow$lambda$7()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic i(Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->resolveService35AndHigher$lambda$10(Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic j(I)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->onStartDiscoveryFailed$lambda$0(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic k()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->onServiceLost$lambda$13()Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->resolveServiceAPI34AndBelow$lambda$6()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic m()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->resolveService35AndHigher$lambda$8()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic n()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->resolveService35AndHigher$lambda$11()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final onDiscoveryStarted$lambda$3()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onDiscoveryStarted(): Started service discovery"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onDiscoveryStopped$lambda$4()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onDiscoveryStopped(): Stopped service discovery"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onServiceFound$lambda$5(Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onServiceFound(): Found service: "

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

.method private static final onServiceLost$lambda$12(Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onServiceLost(): Lost service: "

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

.method private static final onServiceLost$lambda$13()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onServiceLost(): Lost _car2phone._tcp, unregister ServiceInfoCallback"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onServiceLost$lambda$15()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onServiceFound(): Failed to register ServiceInfoCallback"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final onStartDiscoveryFailed$lambda$0(I)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onStartDiscoveryFailed(): Failed to start mainUnit service discovery. errorCode = "

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method private static final onStopDiscoveryFailed$lambda$2(I)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onStopDiscoveryFailed(): Failed to stop mainUnit service discovery. errorCode = "

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method private final resolveService35AndHigher(Landroid/net/nsd/NsdServiceInfo;)V
    .locals 8

    .line 1
    invoke-virtual {p1}, Landroid/net/nsd/NsdServiceInfo;->getServiceType()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "_car2phone._tcp."

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    new-instance v4, Ltechnology/cariad/cat/genx/wifi/i;

    .line 14
    .line 15
    const/16 v0, 0x12

    .line 16
    .line 17
    invoke-direct {v4, v0}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 18
    .line 19
    .line 20
    new-instance v1, Lt51/j;

    .line 21
    .line 22
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v6

    .line 26
    const-string v0, "getName(...)"

    .line 27
    .line 28
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v7

    .line 32
    const-string v2, "GenX"

    .line 33
    .line 34
    sget-object v3, Lt51/f;->a:Lt51/f;

    .line 35
    .line 36
    const/4 v5, 0x0

    .line 37
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 41
    .line 42
    .line 43
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 44
    .line 45
    invoke-static {v0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->access$getC2pServiceCallbacks$p(Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;)Ljava/util/Map;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    check-cast v0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceCallback;

    .line 54
    .line 55
    const-string v1, "GenX"

    .line 56
    .line 57
    if-eqz v0, :cond_0

    .line 58
    .line 59
    new-instance v2, Ltechnology/cariad/cat/genx/wifi/c;

    .line 60
    .line 61
    const/4 v3, 0x5

    .line 62
    invoke-direct {v2, p1, v3}, Ltechnology/cariad/cat/genx/wifi/c;-><init>(Landroid/net/nsd/NsdServiceInfo;I)V

    .line 63
    .line 64
    .line 65
    const/4 v3, 0x0

    .line 66
    invoke-static {p0, v1, v3, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 67
    .line 68
    .line 69
    :try_start_0
    iget-object v2, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 70
    .line 71
    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->getNsdManager()Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    invoke-static {v0}, Lt51/b;->g(Ljava/lang/Object;)Landroid/net/nsd/NsdManager$ServiceInfoCallback;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    invoke-interface {v2, v0}, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;->unregisterServiceInfoCallback(Landroid/net/nsd/NsdManager$ServiceInfoCallback;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 80
    .line 81
    .line 82
    goto :goto_0

    .line 83
    :catch_0
    move-exception v0

    .line 84
    new-instance v2, Ltechnology/cariad/cat/genx/wifi/c;

    .line 85
    .line 86
    const/4 v3, 0x6

    .line 87
    invoke-direct {v2, p1, v3}, Ltechnology/cariad/cat/genx/wifi/c;-><init>(Landroid/net/nsd/NsdServiceInfo;I)V

    .line 88
    .line 89
    .line 90
    invoke-static {p0, v1, v0, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 91
    .line 92
    .line 93
    :goto_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 94
    .line 95
    invoke-static {v0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->access$getResolvedC2PServices$p(Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;)Ljava/util/Map;

    .line 96
    .line 97
    .line 98
    move-result-object v0

    .line 99
    invoke-interface {v0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceCallback;

    .line 103
    .line 104
    iget-object v2, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 105
    .line 106
    invoke-direct {v0, v2, p1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceCallback;-><init>(Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;Landroid/net/nsd/NsdServiceInfo;)V

    .line 107
    .line 108
    .line 109
    :try_start_1
    iget-object v2, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 110
    .line 111
    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->getNsdManager()Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    iget-object v3, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 116
    .line 117
    invoke-static {v3}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->access$getExecutor$p(Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;)Ljava/util/concurrent/ExecutorService;

    .line 118
    .line 119
    .line 120
    move-result-object v3

    .line 121
    const-string v4, "access$getExecutor$p(...)"

    .line 122
    .line 123
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    invoke-static {v0}, Lt51/b;->g(Ljava/lang/Object;)Landroid/net/nsd/NsdManager$ServiceInfoCallback;

    .line 127
    .line 128
    .line 129
    move-result-object v4

    .line 130
    invoke-interface {v2, p1, v3, v4}, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;->registerServiceInfoCallback(Landroid/net/nsd/NsdServiceInfo;Ljava/util/concurrent/ExecutorService;Landroid/net/nsd/NsdManager$ServiceInfoCallback;)V

    .line 131
    .line 132
    .line 133
    iget-object v2, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 134
    .line 135
    invoke-static {v2}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->access$getC2pServiceCallbacks$p(Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;)Ljava/util/Map;

    .line 136
    .line 137
    .line 138
    move-result-object v2

    .line 139
    invoke-interface {v2, p1, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 140
    .line 141
    .line 142
    goto :goto_1

    .line 143
    :catch_1
    move-exception v0

    .line 144
    move-object p1, v0

    .line 145
    new-instance v0, Ltechnology/cariad/cat/genx/wifi/i;

    .line 146
    .line 147
    const/16 v2, 0x13

    .line 148
    .line 149
    invoke-direct {v0, v2}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 150
    .line 151
    .line 152
    invoke-static {p0, v1, p1, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 153
    .line 154
    .line 155
    :cond_1
    :goto_1
    return-void
.end method

.method private static final resolveService35AndHigher$lambda$10(Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "resolveService35AndHigher(): Failed to unregister previous ServiceInfoCallback of this NsdServiceInfo: "

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

.method private static final resolveService35AndHigher$lambda$11()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "resolveService35AndHigher(): Failed to register ServiceInfoCallback"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final resolveService35AndHigher$lambda$8()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "resolveService35AndHigher(): Found _car2phone._tcp., register ServiceInfoCallback"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final resolveService35AndHigher$lambda$9(Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "resolveService35AndHigher(): Unregister previous ServiceInfoCallback of this NsdServiceInfo: "

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

.method private final resolveServiceAPI34AndBelow(Landroid/net/nsd/NsdServiceInfo;)V
    .locals 8

    .line 1
    invoke-virtual {p1}, Landroid/net/nsd/NsdServiceInfo;->getServiceType()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "_car2phone._tcp."

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    new-instance v4, Ltechnology/cariad/cat/genx/wifi/i;

    .line 14
    .line 15
    const/16 v0, 0xd

    .line 16
    .line 17
    invoke-direct {v4, v0}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 18
    .line 19
    .line 20
    new-instance v1, Lt51/j;

    .line 21
    .line 22
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v6

    .line 26
    const-string v0, "getName(...)"

    .line 27
    .line 28
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v7

    .line 32
    const-string v2, "GenX"

    .line 33
    .line 34
    sget-object v3, Lt51/f;->a:Lt51/f;

    .line 35
    .line 36
    const/4 v5, 0x0

    .line 37
    invoke-direct/range {v1 .. v7}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    invoke-static {v1}, Lt51/a;->a(Lt51/j;)V

    .line 41
    .line 42
    .line 43
    :try_start_0
    new-instance v0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;

    .line 44
    .line 45
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 46
    .line 47
    invoke-direct {v0, v1, p1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;-><init>(Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;Landroid/net/nsd/NsdServiceInfo;)V

    .line 48
    .line 49
    .line 50
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 51
    .line 52
    const/16 v2, 0x1e

    .line 53
    .line 54
    if-lt v1, v2, :cond_0

    .line 55
    .line 56
    invoke-static {}, Ln01/a;->a()I

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    const/4 v2, 0x3

    .line 61
    if-lt v1, v2, :cond_0

    .line 62
    .line 63
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 64
    .line 65
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->getNsdManager()Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    iget-object v2, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 70
    .line 71
    invoke-static {v2}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->access$getExecutor$p(Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;)Ljava/util/concurrent/ExecutorService;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    const-string v3, "access$getExecutor$p(...)"

    .line 76
    .line 77
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    invoke-interface {v1, p1, v2, v0}, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;->resolveService(Landroid/net/nsd/NsdServiceInfo;Ljava/util/concurrent/ExecutorService;Landroid/net/nsd/NsdManager$ResolveListener;)V

    .line 81
    .line 82
    .line 83
    return-void

    .line 84
    :catch_0
    move-exception v0

    .line 85
    move-object p1, v0

    .line 86
    goto :goto_0

    .line 87
    :cond_0
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 88
    .line 89
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->getNsdManager()Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    invoke-interface {v1, p1, v0}, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;->resolveService(Landroid/net/nsd/NsdServiceInfo;Landroid/net/nsd/NsdManager$ResolveListener;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 94
    .line 95
    .line 96
    return-void

    .line 97
    :goto_0
    new-instance v0, Ltechnology/cariad/cat/genx/wifi/i;

    .line 98
    .line 99
    const/16 v1, 0xe

    .line 100
    .line 101
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 102
    .line 103
    .line 104
    const-string v1, "GenX"

    .line 105
    .line 106
    invoke-static {p0, v1, p1, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 107
    .line 108
    .line 109
    :cond_1
    return-void
.end method

.method private static final resolveServiceAPI34AndBelow$lambda$6()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "resolveServiceAPI34AndBelow(): Found _car2phone._tcp., register ServiceInfoListener"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final resolveServiceAPI34AndBelow$lambda$7()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "resolveServiceAPI34AndBelow(): Failed to register ServiceInfoListener"

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public onDiscoveryStarted(Ljava/lang/String;)V
    .locals 8

    .line 1
    const-string v0, "serviceType"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/wifi/i;

    .line 7
    .line 8
    const/16 p1, 0xf

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
    sget-object v3, Lt51/d;->a:Lt51/d;

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

.method public onDiscoveryStopped(Ljava/lang/String;)V
    .locals 8

    .line 1
    const-string v0, "serviceType"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/wifi/i;

    .line 7
    .line 8
    const/16 p1, 0x14

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
    sget-object v3, Lt51/d;->a:Lt51/d;

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

.method public onServiceFound(Landroid/net/nsd/NsdServiceInfo;)V
    .locals 8

    .line 1
    const-string v0, "serviceInfo"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/wifi/c;

    .line 7
    .line 8
    const/4 v0, 0x4

    .line 9
    invoke-direct {v4, p1, v0}, Ltechnology/cariad/cat/genx/wifi/c;-><init>(Landroid/net/nsd/NsdServiceInfo;I)V

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
    const-string v0, "getName(...)"

    .line 19
    .line 20
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

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
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 36
    .line 37
    const/16 v1, 0x1e

    .line 38
    .line 39
    if-lt v0, v1, :cond_0

    .line 40
    .line 41
    invoke-static {}, Ln01/a;->a()I

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    const/4 v1, 0x7

    .line 46
    if-lt v0, v1, :cond_0

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->resolveService35AndHigher(Landroid/net/nsd/NsdServiceInfo;)V

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    :cond_0
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->resolveServiceAPI34AndBelow(Landroid/net/nsd/NsdServiceInfo;)V

    .line 53
    .line 54
    .line 55
    return-void
.end method

.method public onServiceLost(Landroid/net/nsd/NsdServiceInfo;)V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    const-string v2, "serviceInfo"

    .line 6
    .line 7
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    new-instance v6, Ltechnology/cariad/cat/genx/wifi/c;

    .line 11
    .line 12
    const/4 v2, 0x3

    .line 13
    invoke-direct {v6, v0, v2}, Ltechnology/cariad/cat/genx/wifi/c;-><init>(Landroid/net/nsd/NsdServiceInfo;I)V

    .line 14
    .line 15
    .line 16
    new-instance v3, Lt51/j;

    .line 17
    .line 18
    invoke-static {v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

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
    invoke-virtual {v0}, Landroid/net/nsd/NsdServiceInfo;->getServiceType()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    const-string v4, "_car2phone._tcp"

    .line 44
    .line 45
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    if-eqz v3, :cond_0

    .line 50
    .line 51
    new-instance v13, Ltechnology/cariad/cat/genx/wifi/i;

    .line 52
    .line 53
    const/16 v3, 0x10

    .line 54
    .line 55
    invoke-direct {v13, v3}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 56
    .line 57
    .line 58
    new-instance v10, Lt51/j;

    .line 59
    .line 60
    invoke-static {v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v15

    .line 64
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v16

    .line 68
    const-string v11, "GenX"

    .line 69
    .line 70
    const/4 v14, 0x0

    .line 71
    move-object v12, v5

    .line 72
    invoke-direct/range {v10 .. v16}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    invoke-static {v10}, Lt51/a;->a(Lt51/j;)V

    .line 76
    .line 77
    .line 78
    :try_start_0
    iget-object v2, v1, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 79
    .line 80
    invoke-static {v2}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->access$getC2pServiceCallbacks$p(Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;)Ljava/util/Map;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    invoke-interface {v2, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    check-cast v2, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceCallback;

    .line 89
    .line 90
    if-eqz v2, :cond_0

    .line 91
    .line 92
    iget-object v3, v1, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 93
    .line 94
    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->getNsdManager()Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;

    .line 95
    .line 96
    .line 97
    move-result-object v4

    .line 98
    invoke-static {v2}, Lt51/b;->g(Ljava/lang/Object;)Landroid/net/nsd/NsdManager$ServiceInfoCallback;

    .line 99
    .line 100
    .line 101
    move-result-object v2

    .line 102
    invoke-interface {v4, v2}, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;->unregisterServiceInfoCallback(Landroid/net/nsd/NsdManager$ServiceInfoCallback;)V

    .line 103
    .line 104
    .line 105
    invoke-static {v3}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->access$getC2pServiceCallbacks$p(Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;)Ljava/util/Map;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    invoke-interface {v2, v0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    invoke-static {v3}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->access$getResolvedC2PServices$p(Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;)Ljava/util/Map;

    .line 113
    .line 114
    .line 115
    move-result-object v2

    .line 116
    invoke-interface {v2, v0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    check-cast v0, Landroid/net/nsd/NsdServiceInfo;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 121
    .line 122
    return-void

    .line 123
    :catch_0
    move-exception v0

    .line 124
    new-instance v2, Ltechnology/cariad/cat/genx/wifi/i;

    .line 125
    .line 126
    const/16 v3, 0x11

    .line 127
    .line 128
    invoke-direct {v2, v3}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 129
    .line 130
    .line 131
    const-string v3, "GenX"

    .line 132
    .line 133
    invoke-static {v1, v3, v0, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 134
    .line 135
    .line 136
    :cond_0
    return-void
.end method

.method public onStartDiscoveryFailed(Ljava/lang/String;I)V
    .locals 8

    .line 1
    const-string v0, "serviceType"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Le1/h1;

    .line 7
    .line 8
    const/16 v0, 0x9

    .line 9
    .line 10
    invoke-direct {v4, p2, v0}, Le1/h1;-><init>(II)V

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
    const-string p2, "getName(...)"

    .line 20
    .line 21
    invoke-static {p2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

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
    iget-object p2, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 37
    .line 38
    invoke-static {p2}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->access$getResolvedC2PServices$p(Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;)Ljava/util/Map;

    .line 39
    .line 40
    .line 41
    move-result-object p2

    .line 42
    invoke-interface {p2}, Ljava/util/Map;->isEmpty()Z

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    if-eqz v0, :cond_0

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    invoke-interface {p2}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 50
    .line 51
    .line 52
    move-result-object p2

    .line 53
    invoke-interface {p2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    :cond_1
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    if-eqz v0, :cond_2

    .line 62
    .line 63
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    check-cast v0, Ljava/util/Map$Entry;

    .line 68
    .line 69
    const-string v0, "_car2phone._tcp"

    .line 70
    .line 71
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v0

    .line 75
    if-eqz v0, :cond_1

    .line 76
    .line 77
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 78
    .line 79
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->resetNsdServiceInfoCallbacksAndFoundServices$genx_release()V

    .line 80
    .line 81
    .line 82
    :cond_2
    :goto_0
    return-void
.end method

.method public onStopDiscoveryFailed(Ljava/lang/String;I)V
    .locals 8

    .line 1
    const-string v0, "serviceType"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Le1/h1;

    .line 7
    .line 8
    const/16 p1, 0xa

    .line 9
    .line 10
    invoke-direct {v4, p2, p1}, Le1/h1;-><init>(II)V

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
    const-string p1, "getName(...)"

    .line 20
    .line 21
    invoke-static {p1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

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
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$discoveryListener$1;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 37
    .line 38
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->resetNsdServiceInfoCallbacksAndFoundServices$genx_release()V

    .line 39
    .line 40
    .line 41
    return-void
.end method
