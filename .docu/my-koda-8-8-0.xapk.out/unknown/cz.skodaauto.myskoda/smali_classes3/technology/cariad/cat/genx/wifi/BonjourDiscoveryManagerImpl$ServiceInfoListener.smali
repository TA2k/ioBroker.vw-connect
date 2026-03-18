.class final Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/net/nsd/NsdManager$ResolveListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x11
    name = "ServiceInfoListener"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0008\u0008\u0082\u0004\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J!\u0010\n\u001a\u00020\t2\u0008\u0010\u0006\u001a\u0004\u0018\u00010\u00022\u0006\u0010\u0008\u001a\u00020\u0007H\u0016\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\u0019\u0010\u000c\u001a\u00020\t2\u0008\u0010\u0006\u001a\u0004\u0018\u00010\u0002H\u0016\u00a2\u0006\u0004\u0008\u000c\u0010\rR\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010\u000e\u001a\u0004\u0008\u000f\u0010\u0010\u00a8\u0006\u0011"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;",
        "Landroid/net/nsd/NsdManager$ResolveListener;",
        "Landroid/net/nsd/NsdServiceInfo;",
        "originalNsdServiceInfo",
        "<init>",
        "(Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;Landroid/net/nsd/NsdServiceInfo;)V",
        "serviceInfo",
        "",
        "errorCode",
        "Llx0/b0;",
        "onResolveFailed",
        "(Landroid/net/nsd/NsdServiceInfo;I)V",
        "onServiceResolved",
        "(Landroid/net/nsd/NsdServiceInfo;)V",
        "Landroid/net/nsd/NsdServiceInfo;",
        "getOriginalNsdServiceInfo",
        "()Landroid/net/nsd/NsdServiceInfo;",
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
.field private final originalNsdServiceInfo:Landroid/net/nsd/NsdServiceInfo;

.field final synthetic this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;Landroid/net/nsd/NsdServiceInfo;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/net/nsd/NsdServiceInfo;",
            ")V"
        }
    .end annotation

    .line 1
    const-string v0, "originalNsdServiceInfo"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;->originalNsdServiceInfo:Landroid/net/nsd/NsdServiceInfo;

    .line 12
    .line 13
    return-void
.end method

.method public static synthetic a(Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;->onServiceResolved$lambda$0(Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(ILtechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;->onResolveFailed$lambda$0(ILtechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final onResolveFailed$lambda$0(ILtechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p1, p1, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;->originalNsdServiceInfo:Landroid/net/nsd/NsdServiceInfo;

    .line 2
    .line 3
    new-instance v0, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v1, "onResolveFailed(): errorCode = "

    .line 6
    .line 7
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, ", originalNsdServiceInfo = "

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string p0, ", serviceInfo = "

    .line 22
    .line 23
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0
.end method

.method private static final onServiceResolved$lambda$0(Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onServiceResolved(): serviceInfo = "

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


# virtual methods
.method public final getOriginalNsdServiceInfo()Landroid/net/nsd/NsdServiceInfo;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;->originalNsdServiceInfo:Landroid/net/nsd/NsdServiceInfo;

    .line 2
    .line 3
    return-object p0
.end method

.method public onResolveFailed(Landroid/net/nsd/NsdServiceInfo;I)V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/wifi/f;

    .line 2
    .line 3
    invoke-direct {v3, p2, p0, p1}, Ltechnology/cariad/cat/genx/wifi/f;-><init>(ILtechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;Landroid/net/nsd/NsdServiceInfo;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lt51/j;

    .line 7
    .line 8
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v5

    .line 12
    const-string p0, "getName(...)"

    .line 13
    .line 14
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v6

    .line 18
    const-string v1, "GenX"

    .line 19
    .line 20
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 21
    .line 22
    const/4 v4, 0x0

    .line 23
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public onServiceResolved(Landroid/net/nsd/NsdServiceInfo;)V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/wifi/c;

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    invoke-direct {v3, p1, v0}, Ltechnology/cariad/cat/genx/wifi/c;-><init>(Landroid/net/nsd/NsdServiceInfo;I)V

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
    if-eqz p1, :cond_0

    .line 31
    .line 32
    invoke-virtual {p1}, Landroid/net/nsd/NsdServiceInfo;->getServiceType()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/4 v0, 0x0

    .line 38
    :goto_0
    const-string v1, "_car2phone._tcp"

    .line 39
    .line 40
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-eqz v0, :cond_1

    .line 45
    .line 46
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;->this$0:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;

    .line 47
    .line 48
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl;->onC2PServiceFound$genx_release(Landroid/net/nsd/NsdServiceInfo;)V

    .line 49
    .line 50
    .line 51
    :cond_1
    return-void
.end method
