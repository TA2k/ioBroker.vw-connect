.class final Lorg/altbeacon/beacon/RegionViewModel$rangedBeacons$2;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lorg/altbeacon/beacon/RegionViewModel;-><init>()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lkotlin/jvm/internal/n;",
        "Lay0/a;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u001e\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0010\u0005\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\u00020\u00010\u0000H\n\u00a2\u0006\u0004\u0008\u0003\u0010\u0004"
    }
    d2 = {
        "Landroidx/lifecycle/i0;",
        "",
        "Lorg/altbeacon/beacon/Beacon;",
        "invoke",
        "()Landroidx/lifecycle/i0;",
        "<anonymous>"
    }
    k = 0x3
    mv = {
        0x1,
        0x8,
        0x0
    }
.end annotation


# static fields
.field public static final INSTANCE:Lorg/altbeacon/beacon/RegionViewModel$rangedBeacons$2;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lorg/altbeacon/beacon/RegionViewModel$rangedBeacons$2;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/altbeacon/beacon/RegionViewModel$rangedBeacons$2;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lorg/altbeacon/beacon/RegionViewModel$rangedBeacons$2;->INSTANCE:Lorg/altbeacon/beacon/RegionViewModel$rangedBeacons$2;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 3
    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public final invoke()Landroidx/lifecycle/i0;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Landroidx/lifecycle/i0;"
        }
    .end annotation

    .line 2
    new-instance p0, Landroidx/lifecycle/i0;

    .line 3
    invoke-direct {p0}, Landroidx/lifecycle/g0;-><init>()V

    return-object p0
.end method

.method public bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/RegionViewModel$rangedBeacons$2;->invoke()Landroidx/lifecycle/i0;

    move-result-object p0

    return-object p0
.end method
