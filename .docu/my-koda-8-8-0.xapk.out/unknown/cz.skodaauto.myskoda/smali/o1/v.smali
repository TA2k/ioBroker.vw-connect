.class public final Lo1/v;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/p;


# instance fields
.field public r:Landroidx/compose/foundation/lazy/layout/b;


# virtual methods
.method public final C0(Lv3/j0;)V
    .locals 14

    .line 1
    iget-object v0, p1, Lv3/j0;->d:Lg3/b;

    .line 2
    .line 3
    iget-object p0, p0, Lo1/v;->r:Landroidx/compose/foundation/lazy/layout/b;

    .line 4
    .line 5
    iget-object p0, p0, Landroidx/compose/foundation/lazy/layout/b;->i:Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    const/4 v2, 0x0

    .line 12
    :goto_0
    if-ge v2, v1, :cond_1

    .line 13
    .line 14
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    check-cast v3, Lo1/t;

    .line 19
    .line 20
    iget-object v4, v3, Lo1/t;->n:Lh3/c;

    .line 21
    .line 22
    if-nez v4, :cond_0

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_0
    iget-wide v5, v3, Lo1/t;->m:J

    .line 26
    .line 27
    const/16 v3, 0x20

    .line 28
    .line 29
    shr-long v7, v5, v3

    .line 30
    .line 31
    long-to-int v7, v7

    .line 32
    int-to-float v7, v7

    .line 33
    const-wide v8, 0xffffffffL

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    and-long/2addr v5, v8

    .line 39
    long-to-int v5, v5

    .line 40
    int-to-float v5, v5

    .line 41
    iget-wide v10, v4, Lh3/c;->t:J

    .line 42
    .line 43
    shr-long v12, v10, v3

    .line 44
    .line 45
    long-to-int v3, v12

    .line 46
    int-to-float v3, v3

    .line 47
    sub-float/2addr v7, v3

    .line 48
    and-long/2addr v8, v10

    .line 49
    long-to-int v3, v8

    .line 50
    int-to-float v3, v3

    .line 51
    sub-float/2addr v5, v3

    .line 52
    iget-object v3, v0, Lg3/b;->e:Lgw0/c;

    .line 53
    .line 54
    iget-object v3, v3, Lgw0/c;->e:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v3, Lbu/c;

    .line 57
    .line 58
    invoke-virtual {v3, v7, v5}, Lbu/c;->B(FF)V

    .line 59
    .line 60
    .line 61
    :try_start_0
    invoke-virtual {p1}, Lv3/j0;->x0()Lgw0/c;

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    invoke-virtual {v3}, Lgw0/c;->h()Le3/r;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    invoke-virtual {p1}, Lv3/j0;->x0()Lgw0/c;

    .line 70
    .line 71
    .line 72
    move-result-object v6

    .line 73
    iget-object v6, v6, Lgw0/c;->f:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v6, Lh3/c;

    .line 76
    .line 77
    invoke-virtual {v4, v3, v6}, Lh3/c;->c(Le3/r;Lh3/c;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 78
    .line 79
    .line 80
    iget-object v3, v0, Lg3/b;->e:Lgw0/c;

    .line 81
    .line 82
    iget-object v3, v3, Lgw0/c;->e:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v3, Lbu/c;

    .line 85
    .line 86
    neg-float v4, v7

    .line 87
    neg-float v5, v5

    .line 88
    invoke-virtual {v3, v4, v5}, Lbu/c;->B(FF)V

    .line 89
    .line 90
    .line 91
    :goto_1
    add-int/lit8 v2, v2, 0x1

    .line 92
    .line 93
    goto :goto_0

    .line 94
    :catchall_0
    move-exception p0

    .line 95
    iget-object p1, v0, Lg3/b;->e:Lgw0/c;

    .line 96
    .line 97
    iget-object p1, p1, Lgw0/c;->e:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast p1, Lbu/c;

    .line 100
    .line 101
    neg-float v0, v7

    .line 102
    neg-float v1, v5

    .line 103
    invoke-virtual {p1, v0, v1}, Lbu/c;->B(FF)V

    .line 104
    .line 105
    .line 106
    throw p0

    .line 107
    :cond_1
    invoke-virtual {p1}, Lv3/j0;->b()V

    .line 108
    .line 109
    .line 110
    return-void
.end method

.method public final P0()V
    .locals 1

    .line 1
    iget-object v0, p0, Lo1/v;->r:Landroidx/compose/foundation/lazy/layout/b;

    .line 2
    .line 3
    iput-object p0, v0, Landroidx/compose/foundation/lazy/layout/b;->j:Lo1/v;

    .line 4
    .line 5
    return-void
.end method

.method public final Q0()V
    .locals 1

    .line 1
    iget-object p0, p0, Lo1/v;->r:Landroidx/compose/foundation/lazy/layout/b;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroidx/compose/foundation/lazy/layout/b;->e()V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    iput-object v0, p0, Landroidx/compose/foundation/lazy/layout/b;->b:Lbb/g0;

    .line 8
    .line 9
    const/4 v0, -0x1

    .line 10
    iput v0, p0, Landroidx/compose/foundation/lazy/layout/b;->c:I

    .line 11
    .line 12
    return-void
.end method

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
    instance-of v1, p1, Lo1/v;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lo1/v;

    .line 12
    .line 13
    iget-object p0, p0, Lo1/v;->r:Landroidx/compose/foundation/lazy/layout/b;

    .line 14
    .line 15
    iget-object p1, p1, Lo1/v;->r:Landroidx/compose/foundation/lazy/layout/b;

    .line 16
    .line 17
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-nez p0, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    return v0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/v;->r:Landroidx/compose/foundation/lazy/layout/b;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "DisplayingDisappearingItemsNode(animator="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lo1/v;->r:Landroidx/compose/foundation/lazy/layout/b;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const/16 p0, 0x29

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

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
