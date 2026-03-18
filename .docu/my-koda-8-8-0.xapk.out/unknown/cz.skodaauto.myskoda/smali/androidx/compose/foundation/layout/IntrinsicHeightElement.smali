.class final Landroidx/compose/foundation/layout/IntrinsicHeightElement;
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
        "Landroidx/compose/foundation/layout/IntrinsicHeightElement;",
        "Lv3/z0;",
        "Lk1/q0;",
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
.field public final b:Lk1/r0;


# direct methods
.method public constructor <init>(Lk1/r0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/compose/foundation/layout/IntrinsicHeightElement;->b:Lk1/r0;

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
    instance-of v1, p1, Landroidx/compose/foundation/layout/IntrinsicHeightElement;

    .line 6
    .line 7
    if-eqz v1, :cond_1

    .line 8
    .line 9
    check-cast p1, Landroidx/compose/foundation/layout/IntrinsicHeightElement;

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
    iget-object p0, p0, Landroidx/compose/foundation/layout/IntrinsicHeightElement;->b:Lk1/r0;

    .line 17
    .line 18
    iget-object p1, p1, Landroidx/compose/foundation/layout/IntrinsicHeightElement;->b:Lk1/r0;

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
    .locals 2

    .line 1
    new-instance v0, Lk1/q0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Lb1/z0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Landroidx/compose/foundation/layout/IntrinsicHeightElement;->b:Lk1/r0;

    .line 8
    .line 9
    iput-object p0, v0, Lk1/q0;->s:Lk1/r0;

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    iput-boolean p0, v0, Lk1/q0;->t:Z

    .line 13
    .line 14
    return-object v0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object p0, p0, Landroidx/compose/foundation/layout/IntrinsicHeightElement;->b:Lk1/r0;

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
    .locals 0

    .line 1
    check-cast p1, Lk1/q0;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/compose/foundation/layout/IntrinsicHeightElement;->b:Lk1/r0;

    .line 4
    .line 5
    iput-object p0, p1, Lk1/q0;->s:Lk1/r0;

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    iput-boolean p0, p1, Lk1/q0;->t:Z

    .line 9
    .line 10
    return-void
.end method
