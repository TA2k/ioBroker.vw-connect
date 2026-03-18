.class public final Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;
.super Landroid/net/ConnectivityManager$NetworkCallback;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\'\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0010\u000b\n\u0002\u0008\n*\u0001\u0000\u0008\n\u0018\u00002\u00020\u0001J\u0019\u0010\u0005\u001a\u00020\u00042\u0008\u0010\u0003\u001a\u0004\u0018\u00010\u0002H\u0002\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\u0017\u0010\t\u001a\u00020\u00042\u0006\u0010\u0008\u001a\u00020\u0007H\u0016\u00a2\u0006\u0004\u0008\t\u0010\nJ\u0017\u0010\u000b\u001a\u00020\u00042\u0006\u0010\u0008\u001a\u00020\u0007H\u0016\u00a2\u0006\u0004\u0008\u000b\u0010\nJ\u000f\u0010\u000c\u001a\u00020\u0004H\u0016\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\r\u0010\u000e\u001a\u00020\u0004\u00a2\u0006\u0004\u0008\u000e\u0010\rR\"\u0010\u0010\u001a\u00020\u000f8\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0010\u0010\u0011\u001a\u0004\u0008\u0012\u0010\u0013\"\u0004\u0008\u0014\u0010\u0015R\"\u0010\u0016\u001a\u00020\u000f8\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0016\u0010\u0011\u001a\u0004\u0008\u0017\u0010\u0013\"\u0004\u0008\u0018\u0010\u0015\u00a8\u0006\u0019"
    }
    d2 = {
        "technology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1",
        "Landroid/net/ConnectivityManager$NetworkCallback;",
        "Ltechnology/cariad/cat/genx/wifi/Wifi;",
        "wifi",
        "Llx0/b0;",
        "unregisterAndResumeContinuationOnceWith",
        "(Ltechnology/cariad/cat/genx/wifi/Wifi;)V",
        "Landroid/net/Network;",
        "network",
        "onAvailable",
        "(Landroid/net/Network;)V",
        "onLost",
        "onUnavailable",
        "()V",
        "unregisterIfStillRegistered",
        "",
        "resumed",
        "Z",
        "getResumed",
        "()Z",
        "setResumed",
        "(Z)V",
        "unregistered",
        "getUnregistered",
        "setUnregistered",
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
.field final synthetic $connectivityManager:Landroid/net/ConnectivityManager;

.field final synthetic $context:Landroid/content/Context;

.field final synthetic $continuation:Lvy0/k;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lvy0/k;"
        }
    .end annotation
.end field

.field private resumed:Z

.field final synthetic this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

.field private unregistered:Z


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;Landroid/content/Context;Lvy0/k;Landroid/net/ConnectivityManager;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;",
            "Landroid/content/Context;",
            "Lvy0/k;",
            "Landroid/net/ConnectivityManager;",
            ")V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->$context:Landroid/content/Context;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->$continuation:Lvy0/k;

    .line 6
    .line 7
    iput-object p4, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->$connectivityManager:Landroid/net/ConnectivityManager;

    .line 8
    .line 9
    invoke-direct {p0}, Landroid/net/ConnectivityManager$NetworkCallback;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method private final unregisterAndResumeContinuationOnceWith(Ltechnology/cariad/cat/genx/wifi/Wifi;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->unregisterIfStillRegistered()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 5
    .line 6
    invoke-virtual {v0, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->updateWifiIfChanged$genx_release(Ltechnology/cariad/cat/genx/wifi/Wifi;)V

    .line 7
    .line 8
    .line 9
    iget-boolean v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->resumed:Z

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    const/4 v0, 0x1

    .line 14
    iput-boolean v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->resumed:Z

    .line 15
    .line 16
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->$continuation:Lvy0/k;

    .line 17
    .line 18
    invoke-interface {p0, p1}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void
.end method


# virtual methods
.method public final getResumed()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->resumed:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getUnregistered()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->unregistered:Z

    .line 2
    .line 3
    return p0
.end method

.method public onAvailable(Landroid/net/Network;)V
    .locals 2

    .line 1
    const-string v0, "network"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 7
    .line 8
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->$context:Landroid/content/Context;

    .line 9
    .line 10
    invoke-virtual {v0, v1, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->wifiForNetwork$genx_release(Landroid/content/Context;Landroid/net/Network;)Ltechnology/cariad/cat/genx/wifi/Wifi;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->unregisterAndResumeContinuationOnceWith(Ltechnology/cariad/cat/genx/wifi/Wifi;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public onLost(Landroid/net/Network;)V
    .locals 1

    .line 1
    const-string v0, "network"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->unregisterAndResumeContinuationOnceWith(Ltechnology/cariad/cat/genx/wifi/Wifi;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public onUnavailable()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->unregisterAndResumeContinuationOnceWith(Ltechnology/cariad/cat/genx/wifi/Wifi;)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final setResumed(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->resumed:Z

    .line 2
    .line 3
    return-void
.end method

.method public final setUnregistered(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->unregistered:Z

    .line 2
    .line 3
    return-void
.end method

.method public final unregisterIfStillRegistered()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->unregistered:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    iput-boolean v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->unregistered:Z

    .line 7
    .line 8
    :try_start_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;->$connectivityManager:Landroid/net/ConnectivityManager;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Landroid/net/ConnectivityManager;->unregisterNetworkCallback(Landroid/net/ConnectivityManager$NetworkCallback;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 11
    .line 12
    .line 13
    :catch_0
    :cond_0
    return-void
.end method
