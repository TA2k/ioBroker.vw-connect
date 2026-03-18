.class public final Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$registerBroadcastReceiver$3$newNetworkCallback$1;
.super Landroid/net/ConnectivityManager$NetworkCallback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->registerBroadcastReceiver(Landroid/content/Context;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0017\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0006*\u0001\u0000\u0008\n\u0018\u00002\u00020\u0001J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0016\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\u0017\u0010\u0007\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0016\u00a2\u0006\u0004\u0008\u0007\u0010\u0006J\u000f\u0010\u0008\u001a\u00020\u0004H\u0016\u00a2\u0006\u0004\u0008\u0008\u0010\t\u00a8\u0006\n"
    }
    d2 = {
        "technology/cariad/cat/genx/wifi/WifiManagerImpl$registerBroadcastReceiver$3$newNetworkCallback$1",
        "Landroid/net/ConnectivityManager$NetworkCallback;",
        "Landroid/net/Network;",
        "network",
        "Llx0/b0;",
        "onAvailable",
        "(Landroid/net/Network;)V",
        "onLost",
        "onUnavailable",
        "()V",
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
.field final synthetic $context:Landroid/content/Context;

.field final synthetic this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;Landroid/content/Context;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$registerBroadcastReceiver$3$newNetworkCallback$1;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$registerBroadcastReceiver$3$newNetworkCallback$1;->$context:Landroid/content/Context;

    .line 4
    .line 5
    invoke-direct {p0}, Landroid/net/ConnectivityManager$NetworkCallback;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public static synthetic a(Landroid/net/Network;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$registerBroadcastReceiver$3$newNetworkCallback$1;->onLost$lambda$1(Landroid/net/Network;)Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$registerBroadcastReceiver$3$newNetworkCallback$1;->onUnavailable$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic c(Landroid/net/Network;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$registerBroadcastReceiver$3$newNetworkCallback$1;->onAvailable$lambda$0(Landroid/net/Network;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final onAvailable$lambda$0(Landroid/net/Network;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "networkCallback.onAvailable(): Network = "

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

.method private static final onLost$lambda$1(Landroid/net/Network;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "networkCallback.onLost(): Network = "

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

.method private static final onUnavailable$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "networkCallback.onUnavailable()"

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public onAvailable(Landroid/net/Network;)V
    .locals 8

    .line 1
    const-string v0, "network"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/wifi/l;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-direct {v4, p1, v0}, Ltechnology/cariad/cat/genx/wifi/l;-><init>(Landroid/net/Network;I)V

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
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$registerBroadcastReceiver$3$newNetworkCallback$1;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 36
    .line 37
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$registerBroadcastReceiver$3$newNetworkCallback$1;->$context:Landroid/content/Context;

    .line 38
    .line 39
    invoke-virtual {v0, v1, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->wifiForNetwork$genx_release(Landroid/content/Context;Landroid/net/Network;)Ltechnology/cariad/cat/genx/wifi/Wifi;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$registerBroadcastReceiver$3$newNetworkCallback$1;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 44
    .line 45
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->updateWifiIfChanged$genx_release(Ltechnology/cariad/cat/genx/wifi/Wifi;)V

    .line 46
    .line 47
    .line 48
    return-void
.end method

.method public onLost(Landroid/net/Network;)V
    .locals 8

    .line 1
    const-string v0, "network"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v4, Ltechnology/cariad/cat/genx/wifi/l;

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    invoke-direct {v4, p1, v0}, Ltechnology/cariad/cat/genx/wifi/l;-><init>(Landroid/net/Network;I)V

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
    const-string p1, "getName(...)"

    .line 19
    .line 20
    invoke-static {p1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

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
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$registerBroadcastReceiver$3$newNetworkCallback$1;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 36
    .line 37
    const/4 p1, 0x0

    .line 38
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->updateWifiIfChanged$genx_release(Ltechnology/cariad/cat/genx/wifi/Wifi;)V

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public onUnavailable()V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/wifi/g;

    .line 2
    .line 3
    const/16 v0, 0xb

    .line 4
    .line 5
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/wifi/g;-><init>(I)V

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
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$registerBroadcastReceiver$3$newNetworkCallback$1;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 32
    .line 33
    const/4 v0, 0x0

    .line 34
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->updateWifiIfChanged$genx_release(Ltechnology/cariad/cat/genx/wifi/Wifi;)V

    .line 35
    .line 36
    .line 37
    return-void
.end method
