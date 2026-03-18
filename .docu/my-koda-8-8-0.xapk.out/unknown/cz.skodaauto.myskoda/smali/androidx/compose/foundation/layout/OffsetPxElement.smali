.class final Landroidx/compose/foundation/layout/OffsetPxElement;
.super Lv3/z0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lv3/z0;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0002\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Landroidx/compose/foundation/layout/OffsetPxElement;",
        "Lv3/z0;",
        "Lk1/x0;",
        "foundation-layout"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final b:Lay0/k;


# direct methods
.method public constructor <init>(Lay0/k;Li50/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/compose/foundation/layout/OffsetPxElement;->b:Lay0/k;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Landroidx/compose/foundation/layout/OffsetPxElement;

    .line 6
    .line 7
    if-eqz v1, :cond_1

    .line 8
    .line 9
    check-cast p1, Landroidx/compose/foundation/layout/OffsetPxElement;

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_1
    const/4 p1, 0x0

    .line 13
    :goto_0
    if-nez p1, :cond_2

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_2
    iget-object p0, p0, Landroidx/compose/foundation/layout/OffsetPxElement;->b:Lay0/k;

    .line 17
    .line 18
    iget-object p1, p1, Landroidx/compose/foundation/layout/OffsetPxElement;->b:Lay0/k;

    .line 19
    .line 20
    if-ne p0, p1, :cond_3

    .line 21
    .line 22
    return v0

    .line 23
    :cond_3
    :goto_1
    const/4 p0, 0x0

    .line 24
    return p0
.end method

.method public final h()Lx2/r;
    .locals 1

    .line 1
    new-instance v0, Lk1/x0;

    .line 2
    .line 3
    invoke-direct {v0}, Lx2/r;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/compose/foundation/layout/OffsetPxElement;->b:Lay0/k;

    .line 7
    .line 8
    iput-object p0, v0, Lk1/x0;->r:Lay0/k;

    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    iput-boolean p0, v0, Lk1/x0;->s:Z

    .line 12
    .line 13
    return-object v0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object p0, p0, Landroidx/compose/foundation/layout/OffsetPxElement;->b:Lay0/k;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    mul-int/lit8 p0, p0, 0x1f

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    add-int/2addr v0, p0

    .line 15
    return v0
.end method

.method public final j(Lx2/r;)V
    .locals 3

    .line 1
    check-cast p1, Lk1/x0;

    .line 2
    .line 3
    iget-object v0, p1, Lk1/x0;->r:Lay0/k;

    .line 4
    .line 5
    iget-object p0, p0, Landroidx/compose/foundation/layout/OffsetPxElement;->b:Lay0/k;

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    if-ne v0, p0, :cond_0

    .line 9
    .line 10
    iget-boolean v0, p1, Lk1/x0;->s:Z

    .line 11
    .line 12
    if-eq v0, v1, :cond_1

    .line 13
    .line 14
    :cond_0
    invoke-static {p1}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v0, v2}, Lv3/h0;->X(Z)V

    .line 20
    .line 21
    .line 22
    :cond_1
    iput-object p0, p1, Lk1/x0;->r:Lay0/k;

    .line 23
    .line 24
    iput-boolean v1, p1, Lk1/x0;->s:Z

    .line 25
    .line 26
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "OffsetPxModifier(offset="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Landroidx/compose/foundation/layout/OffsetPxElement;->b:Lay0/k;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, ", rtlAware=true)"

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
