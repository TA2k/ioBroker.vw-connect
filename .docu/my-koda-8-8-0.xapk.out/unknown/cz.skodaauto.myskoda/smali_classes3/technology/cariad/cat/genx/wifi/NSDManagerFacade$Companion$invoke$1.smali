.class public final Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion$invoke$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion;->invoke(Landroid/content/Context;)Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000G\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0004*\u0001\u0000\u0008\n\u0018\u00002\u00020\u0001J\'\u0010\t\u001a\u00020\u00082\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u0006H\u0017\u00a2\u0006\u0004\u0008\t\u0010\nJ\u001f\u0010\t\u001a\u00020\u00082\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0007\u001a\u00020\u0006H\u0016\u00a2\u0006\u0004\u0008\t\u0010\u000bJ\u0017\u0010\u000e\u001a\u00020\u00082\u0006\u0010\r\u001a\u00020\u000cH\u0017\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ\'\u0010\u0011\u001a\u00020\u00082\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0010\u001a\u00020\u000cH\u0017\u00a2\u0006\u0004\u0008\u0011\u0010\u0012J\'\u0010\u0019\u001a\u00020\u00082\u0006\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0016\u001a\u00020\u00152\u0006\u0010\u0018\u001a\u00020\u0017H\u0016\u00a2\u0006\u0004\u0008\u0019\u0010\u001aJ\u0017\u0010\u001b\u001a\u00020\u00082\u0006\u0010\u0018\u001a\u00020\u0017H\u0016\u00a2\u0006\u0004\u0008\u001b\u0010\u001cR\u0016\u0010 \u001a\u0004\u0018\u00010\u001d8VX\u0096\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u001e\u0010\u001f\u00a8\u0006!"
    }
    d2 = {
        "technology/cariad/cat/genx/wifi/NSDManagerFacade$Companion$invoke$1",
        "Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;",
        "Landroid/net/nsd/NsdServiceInfo;",
        "serviceInfo",
        "Ljava/util/concurrent/ExecutorService;",
        "executor",
        "Landroid/net/nsd/NsdManager$ResolveListener;",
        "newResolveListener",
        "Llx0/b0;",
        "resolveService",
        "(Landroid/net/nsd/NsdServiceInfo;Ljava/util/concurrent/ExecutorService;Landroid/net/nsd/NsdManager$ResolveListener;)V",
        "(Landroid/net/nsd/NsdServiceInfo;Landroid/net/nsd/NsdManager$ResolveListener;)V",
        "Landroid/net/nsd/NsdManager$ServiceInfoCallback;",
        "listener",
        "unregisterServiceInfoCallback",
        "(Landroid/net/nsd/NsdManager$ServiceInfoCallback;)V",
        "newServiceCallback",
        "registerServiceInfoCallback",
        "(Landroid/net/nsd/NsdServiceInfo;Ljava/util/concurrent/ExecutorService;Landroid/net/nsd/NsdManager$ServiceInfoCallback;)V",
        "",
        "serviceType",
        "",
        "protocolDnsSd",
        "Landroid/net/nsd/NsdManager$DiscoveryListener;",
        "discoveryListener",
        "discoverServices",
        "(Ljava/lang/String;ILandroid/net/nsd/NsdManager$DiscoveryListener;)V",
        "stopServiceDiscovery",
        "(Landroid/net/nsd/NsdManager$DiscoveryListener;)V",
        "Landroid/net/nsd/NsdManager;",
        "getNsdManager",
        "()Landroid/net/nsd/NsdManager;",
        "nsdManager",
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


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion$invoke$1;->$context:Landroid/content/Context;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public discoverServices(Ljava/lang/String;ILandroid/net/nsd/NsdManager$DiscoveryListener;)V
    .locals 1

    .line 1
    const-string v0, "serviceType"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "discoveryListener"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion$invoke$1;->getNsdManager()Landroid/net/nsd/NsdManager;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    invoke-virtual {p0, p1, p2, p3}, Landroid/net/nsd/NsdManager;->discoverServices(Ljava/lang/String;ILandroid/net/nsd/NsdManager$DiscoveryListener;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    return-void
.end method

.method public getNsdManager()Landroid/net/nsd/NsdManager;
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion$invoke$1;->$context:Landroid/content/Context;

    .line 2
    .line 3
    const-string v0, "servicediscovery"

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    instance-of v0, p0, Landroid/net/nsd/NsdManager;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    check-cast p0, Landroid/net/nsd/NsdManager;

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    return-object p0
.end method

.method public registerServiceInfoCallback(Landroid/net/nsd/NsdServiceInfo;Ljava/util/concurrent/ExecutorService;Landroid/net/nsd/NsdManager$ServiceInfoCallback;)V
    .locals 1

    .line 1
    const-string v0, "serviceInfo"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "executor"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "newServiceCallback"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion$invoke$1;->getNsdManager()Landroid/net/nsd/NsdManager;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    invoke-static {p0, p1, p2, p3}, Lt51/b;->s(Landroid/net/nsd/NsdManager;Landroid/net/nsd/NsdServiceInfo;Ljava/util/concurrent/ExecutorService;Landroid/net/nsd/NsdManager$ServiceInfoCallback;)V

    .line 23
    .line 24
    .line 25
    :cond_0
    return-void
.end method

.method public resolveService(Landroid/net/nsd/NsdServiceInfo;Landroid/net/nsd/NsdManager$ResolveListener;)V
    .locals 1

    const-string v0, "serviceInfo"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "newResolveListener"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion$invoke$1;->getNsdManager()Landroid/net/nsd/NsdManager;

    move-result-object p0

    if-eqz p0, :cond_0

    invoke-virtual {p0, p1, p2}, Landroid/net/nsd/NsdManager;->resolveService(Landroid/net/nsd/NsdServiceInfo;Landroid/net/nsd/NsdManager$ResolveListener;)V

    :cond_0
    return-void
.end method

.method public resolveService(Landroid/net/nsd/NsdServiceInfo;Ljava/util/concurrent/ExecutorService;Landroid/net/nsd/NsdManager$ResolveListener;)V
    .locals 1

    const-string v0, "serviceInfo"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "executor"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "newResolveListener"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion$invoke$1;->getNsdManager()Landroid/net/nsd/NsdManager;

    move-result-object p0

    if-eqz p0, :cond_0

    invoke-static {p0, p1, p2, p3}, Li2/p0;->l(Landroid/net/nsd/NsdManager;Landroid/net/nsd/NsdServiceInfo;Ljava/util/concurrent/ExecutorService;Landroid/net/nsd/NsdManager$ResolveListener;)V

    :cond_0
    return-void
.end method

.method public stopServiceDiscovery(Landroid/net/nsd/NsdManager$DiscoveryListener;)V
    .locals 1

    .line 1
    const-string v0, "discoveryListener"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion$invoke$1;->getNsdManager()Landroid/net/nsd/NsdManager;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Landroid/net/nsd/NsdManager;->stopServiceDiscovery(Landroid/net/nsd/NsdManager$DiscoveryListener;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void
.end method

.method public unregisterServiceInfoCallback(Landroid/net/nsd/NsdManager$ServiceInfoCallback;)V
    .locals 1

    .line 1
    const-string v0, "listener"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion$invoke$1;->getNsdManager()Landroid/net/nsd/NsdManager;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    invoke-static {p0, p1}, Lt51/b;->r(Landroid/net/nsd/NsdManager;Landroid/net/nsd/NsdManager$ServiceInfoCallback;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void
.end method
