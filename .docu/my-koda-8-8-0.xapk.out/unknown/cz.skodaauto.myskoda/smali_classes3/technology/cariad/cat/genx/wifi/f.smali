.class public final synthetic Ltechnology/cariad/cat/genx/wifi/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;

.field public final synthetic f:Landroid/net/nsd/NsdServiceInfo;


# direct methods
.method public synthetic constructor <init>(ILtechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;Landroid/net/nsd/NsdServiceInfo;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Ltechnology/cariad/cat/genx/wifi/f;->d:I

    .line 5
    .line 6
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/f;->e:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;

    .line 7
    .line 8
    iput-object p3, p0, Ltechnology/cariad/cat/genx/wifi/f;->f:Landroid/net/nsd/NsdServiceInfo;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/f;->e:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/f;->f:Landroid/net/nsd/NsdServiceInfo;

    .line 4
    .line 5
    iget p0, p0, Ltechnology/cariad/cat/genx/wifi/f;->d:I

    .line 6
    .line 7
    invoke-static {p0, v0, v1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;->b(ILtechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceInfoListener;Landroid/net/nsd/NsdServiceInfo;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
