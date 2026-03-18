.class public final Ll2/j2;
.super Lv2/v;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public c:F


# direct methods
.method public constructor <init>(JF)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lv2/v;-><init>(J)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Ll2/j2;->c:F

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lv2/v;)V
    .locals 1

    .line 1
    const-string v0, "null cannot be cast to non-null type androidx.compose.runtime.SnapshotMutableFloatStateImpl.FloatStateStateRecord"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/j2;

    .line 7
    .line 8
    iget p1, p1, Ll2/j2;->c:F

    .line 9
    .line 10
    iput p1, p0, Ll2/j2;->c:F

    .line 11
    .line 12
    return-void
.end method

.method public final b(J)Lv2/v;
    .locals 1

    .line 1
    new-instance v0, Ll2/j2;

    .line 2
    .line 3
    iget p0, p0, Ll2/j2;->c:F

    .line 4
    .line 5
    invoke-direct {v0, p1, p2, p0}, Ll2/j2;-><init>(JF)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method
