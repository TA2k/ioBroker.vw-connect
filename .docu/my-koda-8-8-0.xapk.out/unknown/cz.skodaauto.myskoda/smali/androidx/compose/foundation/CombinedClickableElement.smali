.class final Landroidx/compose/foundation/CombinedClickableElement;
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
        "Landroidx/compose/foundation/CombinedClickableElement;",
        "Lv3/z0;",
        "Le1/a0;",
        "foundation_release"
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
.field public final b:Li1/l;

.field public final c:Z

.field public final d:Lay0/a;


# direct methods
.method public constructor <init>(Lay0/a;Li1/l;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Landroidx/compose/foundation/CombinedClickableElement;->b:Li1/l;

    .line 5
    .line 6
    iput-boolean p3, p0, Landroidx/compose/foundation/CombinedClickableElement;->c:Z

    .line 7
    .line 8
    iput-object p1, p0, Landroidx/compose/foundation/CombinedClickableElement;->d:Lay0/a;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    if-nez p1, :cond_1

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_1
    const-class v1, Landroidx/compose/foundation/CombinedClickableElement;

    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    if-eq v1, v2, :cond_2

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_2
    check-cast p1, Landroidx/compose/foundation/CombinedClickableElement;

    .line 18
    .line 19
    iget-object v1, p0, Landroidx/compose/foundation/CombinedClickableElement;->b:Li1/l;

    .line 20
    .line 21
    iget-object v2, p1, Landroidx/compose/foundation/CombinedClickableElement;->b:Li1/l;

    .line 22
    .line 23
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-nez v1, :cond_3

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_3
    iget-boolean v1, p0, Landroidx/compose/foundation/CombinedClickableElement;->c:Z

    .line 31
    .line 32
    iget-boolean v2, p1, Landroidx/compose/foundation/CombinedClickableElement;->c:Z

    .line 33
    .line 34
    if-eq v1, v2, :cond_4

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_4
    iget-object p0, p0, Landroidx/compose/foundation/CombinedClickableElement;->d:Lay0/a;

    .line 38
    .line 39
    iget-object p1, p1, Landroidx/compose/foundation/CombinedClickableElement;->d:Lay0/a;

    .line 40
    .line 41
    if-eq p0, p1, :cond_5

    .line 42
    .line 43
    :goto_0
    const/4 p0, 0x0

    .line 44
    return p0

    .line 45
    :cond_5
    return v0
.end method

.method public final h()Lx2/r;
    .locals 3

    .line 1
    new-instance v0, Le1/a0;

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/compose/foundation/CombinedClickableElement;->b:Li1/l;

    .line 4
    .line 5
    iget-boolean v2, p0, Landroidx/compose/foundation/CombinedClickableElement;->c:Z

    .line 6
    .line 7
    iget-object p0, p0, Landroidx/compose/foundation/CombinedClickableElement;->d:Lay0/a;

    .line 8
    .line 9
    invoke-direct {v0, p0, v1, v2}, Le1/a0;-><init>(Lay0/a;Li1/l;Z)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/compose/foundation/CombinedClickableElement;->b:Li1/l;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 v0, 0x0

    .line 11
    :goto_0
    mul-int/lit16 v0, v0, 0x3c1

    .line 12
    .line 13
    iget-boolean v1, p0, Landroidx/compose/foundation/CombinedClickableElement;->c:Z

    .line 14
    .line 15
    const/16 v2, 0x1f

    .line 16
    .line 17
    invoke-static {v0, v2, v1}, La7/g0;->e(IIZ)I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    const/16 v1, 0x745f

    .line 22
    .line 23
    const/4 v2, 0x1

    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object p0, p0, Landroidx/compose/foundation/CombinedClickableElement;->d:Lay0/a;

    .line 29
    .line 30
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    add-int/2addr p0, v0

    .line 35
    const v0, 0xe1781

    .line 36
    .line 37
    .line 38
    mul-int/2addr p0, v0

    .line 39
    invoke-static {v2}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    add-int/2addr v0, p0

    .line 44
    return v0
.end method

.method public final j(Lx2/r;)V
    .locals 8

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Le1/a0;

    .line 3
    .line 4
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 5
    .line 6
    .line 7
    iget-boolean p1, v0, Le1/h;->y:Z

    .line 8
    .line 9
    const/4 v4, 0x1

    .line 10
    if-eq p1, v4, :cond_0

    .line 11
    .line 12
    const/4 p1, 0x1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p1, 0x0

    .line 15
    :goto_0
    iget-object v1, p0, Landroidx/compose/foundation/CombinedClickableElement;->b:Li1/l;

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    iget-boolean v3, p0, Landroidx/compose/foundation/CombinedClickableElement;->c:Z

    .line 19
    .line 20
    const/4 v5, 0x0

    .line 21
    const/4 v6, 0x0

    .line 22
    iget-object v7, p0, Landroidx/compose/foundation/CombinedClickableElement;->d:Lay0/a;

    .line 23
    .line 24
    invoke-virtual/range {v0 .. v7}, Le1/h;->j1(Li1/l;Le1/s0;ZZLjava/lang/String;Ld4/i;Lay0/a;)V

    .line 25
    .line 26
    .line 27
    if-eqz p1, :cond_1

    .line 28
    .line 29
    iget-object p0, v0, Le1/h;->C:Lp3/j0;

    .line 30
    .line 31
    if-eqz p0, :cond_1

    .line 32
    .line 33
    invoke-virtual {p0}, Lp3/j0;->Z0()V

    .line 34
    .line 35
    .line 36
    :cond_1
    return-void
.end method
