.class public final synthetic Ltechnology/cariad/cat/genx/wifi/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceCallback;


# direct methods
.method public synthetic constructor <init>(ILtechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceCallback;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Ltechnology/cariad/cat/genx/wifi/e;->d:I

    .line 5
    .line 6
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/e;->e:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceCallback;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/wifi/e;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/e;->e:Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceCallback;

    .line 4
    .line 5
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceCallback;->a(ILtechnology/cariad/cat/genx/wifi/BonjourDiscoveryManagerImpl$ServiceCallback;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
