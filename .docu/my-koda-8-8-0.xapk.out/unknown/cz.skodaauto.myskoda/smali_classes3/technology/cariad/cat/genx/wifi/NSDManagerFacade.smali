.class public interface abstract Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000H\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008`\u0018\u0000 !2\u00020\u0001:\u0001!J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\'\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\'\u0010\u000c\u001a\u00020\u00042\u0006\u0010\u0008\u001a\u00020\u00072\u0006\u0010\n\u001a\u00020\t2\u0006\u0010\u000b\u001a\u00020\u0002H\'\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\'\u0010\u0010\u001a\u00020\u00042\u0006\u0010\u0008\u001a\u00020\u00072\u0006\u0010\n\u001a\u00020\t2\u0006\u0010\u000f\u001a\u00020\u000eH\'\u00a2\u0006\u0004\u0008\u0010\u0010\u0011J\u001f\u0010\u0010\u001a\u00020\u00042\u0006\u0010\u0008\u001a\u00020\u00072\u0006\u0010\u000f\u001a\u00020\u000eH&\u00a2\u0006\u0004\u0008\u0010\u0010\u0012J\'\u0010\u0019\u001a\u00020\u00042\u0006\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0016\u001a\u00020\u00152\u0006\u0010\u0018\u001a\u00020\u0017H&\u00a2\u0006\u0004\u0008\u0019\u0010\u001aJ\u0017\u0010\u001b\u001a\u00020\u00042\u0006\u0010\u0018\u001a\u00020\u0017H&\u00a2\u0006\u0004\u0008\u001b\u0010\u001cR\u0016\u0010 \u001a\u0004\u0018\u00010\u001d8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u001e\u0010\u001f\u00a8\u0006\"\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;",
        "",
        "Landroid/net/nsd/NsdManager$ServiceInfoCallback;",
        "listener",
        "Llx0/b0;",
        "unregisterServiceInfoCallback",
        "(Landroid/net/nsd/NsdManager$ServiceInfoCallback;)V",
        "Landroid/net/nsd/NsdServiceInfo;",
        "serviceInfo",
        "Ljava/util/concurrent/ExecutorService;",
        "executor",
        "newServiceCallback",
        "registerServiceInfoCallback",
        "(Landroid/net/nsd/NsdServiceInfo;Ljava/util/concurrent/ExecutorService;Landroid/net/nsd/NsdManager$ServiceInfoCallback;)V",
        "Landroid/net/nsd/NsdManager$ResolveListener;",
        "newResolveListener",
        "resolveService",
        "(Landroid/net/nsd/NsdServiceInfo;Ljava/util/concurrent/ExecutorService;Landroid/net/nsd/NsdManager$ResolveListener;)V",
        "(Landroid/net/nsd/NsdServiceInfo;Landroid/net/nsd/NsdManager$ResolveListener;)V",
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
        "Companion",
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
.field public static final Companion:Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion;->$$INSTANCE:Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion;

    .line 2
    .line 3
    sput-object v0, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;->Companion:Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion;

    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public abstract discoverServices(Ljava/lang/String;ILandroid/net/nsd/NsdManager$DiscoveryListener;)V
.end method

.method public abstract getNsdManager()Landroid/net/nsd/NsdManager;
.end method

.method public abstract registerServiceInfoCallback(Landroid/net/nsd/NsdServiceInfo;Ljava/util/concurrent/ExecutorService;Landroid/net/nsd/NsdManager$ServiceInfoCallback;)V
.end method

.method public abstract resolveService(Landroid/net/nsd/NsdServiceInfo;Landroid/net/nsd/NsdManager$ResolveListener;)V
.end method

.method public abstract resolveService(Landroid/net/nsd/NsdServiceInfo;Ljava/util/concurrent/ExecutorService;Landroid/net/nsd/NsdManager$ResolveListener;)V
.end method

.method public abstract stopServiceDiscovery(Landroid/net/nsd/NsdManager$DiscoveryListener;)V
.end method

.method public abstract unregisterServiceInfoCallback(Landroid/net/nsd/NsdManager$ServiceInfoCallback;)V
.end method
