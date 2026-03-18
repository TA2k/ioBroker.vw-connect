.class public final Lorg/altbeacon/beacon/RegionViewModel;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0005\n\u0002\u0010\u001e\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003R!\u0010\n\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u00048FX\u0086\u0084\u0002\u00a2\u0006\u000c\n\u0004\u0008\u0006\u0010\u0007\u001a\u0004\u0008\u0008\u0010\tR\'\u0010\u000f\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\u000c0\u000b0\u00048FX\u0086\u0084\u0002\u00a2\u0006\u000c\n\u0004\u0008\r\u0010\u0007\u001a\u0004\u0008\u000e\u0010\t\u00a8\u0006\u0010"
    }
    d2 = {
        "Lorg/altbeacon/beacon/RegionViewModel;",
        "Landroidx/lifecycle/b1;",
        "<init>",
        "()V",
        "Landroidx/lifecycle/i0;",
        "",
        "regionState$delegate",
        "Llx0/i;",
        "getRegionState",
        "()Landroidx/lifecycle/i0;",
        "regionState",
        "",
        "Lorg/altbeacon/beacon/Beacon;",
        "rangedBeacons$delegate",
        "getRangedBeacons",
        "rangedBeacons",
        "android-beacon-library_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x8,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final rangedBeacons$delegate:Llx0/i;

.field private final regionState$delegate:Llx0/i;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lorg/altbeacon/beacon/RegionViewModel$regionState$2;->INSTANCE:Lorg/altbeacon/beacon/RegionViewModel$regionState$2;

    .line 5
    .line 6
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iput-object v0, p0, Lorg/altbeacon/beacon/RegionViewModel;->regionState$delegate:Llx0/i;

    .line 11
    .line 12
    sget-object v0, Lorg/altbeacon/beacon/RegionViewModel$rangedBeacons$2;->INSTANCE:Lorg/altbeacon/beacon/RegionViewModel$rangedBeacons$2;

    .line 13
    .line 14
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iput-object v0, p0, Lorg/altbeacon/beacon/RegionViewModel;->rangedBeacons$delegate:Llx0/i;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final getRangedBeacons()Landroidx/lifecycle/i0;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Landroidx/lifecycle/i0;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/RegionViewModel;->rangedBeacons$delegate:Llx0/i;

    .line 2
    .line 3
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Landroidx/lifecycle/i0;

    .line 8
    .line 9
    return-object p0
.end method

.method public final getRegionState()Landroidx/lifecycle/i0;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Landroidx/lifecycle/i0;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/RegionViewModel;->regionState$delegate:Llx0/i;

    .line 2
    .line 3
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Landroidx/lifecycle/i0;

    .line 8
    .line 9
    return-object p0
.end method
