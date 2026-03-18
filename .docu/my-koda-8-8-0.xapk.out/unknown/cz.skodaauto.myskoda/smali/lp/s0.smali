.class public abstract Llp/s0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lhc/a;Ll2/o;I)V
    .locals 5

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, 0x78a435a

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p1, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v1, 0x2

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v0, v1

    .line 19
    :goto_0
    or-int/2addr v0, p2

    .line 20
    and-int/lit8 v2, v0, 0x3

    .line 21
    .line 22
    if-eq v2, v1, :cond_1

    .line 23
    .line 24
    const/4 v1, 0x1

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    const/4 v1, 0x0

    .line 27
    :goto_1
    and-int/lit8 v2, v0, 0x1

    .line 28
    .line 29
    invoke-virtual {p1, v2, v1}, Ll2/t;->O(IZ)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_4

    .line 34
    .line 35
    sget-object v1, Lzb/x;->b:Ll2/u2;

    .line 36
    .line 37
    invoke-virtual {p1, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    const-string v2, "null cannot be cast to non-null type cariad.charging.multicharge.common.presentation.consent.ConsentsUi"

    .line 42
    .line 43
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    check-cast v1, Lcc/a;

    .line 47
    .line 48
    sget-object v2, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 49
    .line 50
    invoke-virtual {p1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v2

    .line 54
    check-cast v2, Landroid/content/Context;

    .line 55
    .line 56
    invoke-virtual {p1, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v4

    .line 64
    if-nez v3, :cond_2

    .line 65
    .line 66
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 67
    .line 68
    if-ne v4, v3, :cond_3

    .line 69
    .line 70
    :cond_2
    new-instance v4, Laa/y;

    .line 71
    .line 72
    const/4 v3, 0x1

    .line 73
    invoke-direct {v4, v2, v3}, Laa/y;-><init>(Landroid/content/Context;I)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p1, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    :cond_3
    check-cast v4, Lay0/k;

    .line 80
    .line 81
    and-int/lit8 v0, v0, 0xe

    .line 82
    .line 83
    invoke-interface {v1, p0, v4, p1, v0}, Lcc/a;->s(Lhc/a;Lay0/k;Ll2/o;I)V

    .line 84
    .line 85
    .line 86
    goto :goto_2

    .line 87
    :cond_4
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 88
    .line 89
    .line 90
    :goto_2
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    if-eqz p1, :cond_5

    .line 95
    .line 96
    new-instance v0, Ld90/h;

    .line 97
    .line 98
    const/4 v1, 0x3

    .line 99
    invoke-direct {v0, p0, p2, v1}, Ld90/h;-><init>(Ljava/lang/Object;II)V

    .line 100
    .line 101
    .line 102
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 103
    .line 104
    :cond_5
    return-void
.end method

.method public static final b(Ltz/j1;Ltz/i1;)Z
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltz/j1;->b:Ljava/util/List;

    .line 7
    .line 8
    check-cast p0, Ljava/lang/Iterable;

    .line 9
    .line 10
    instance-of v0, p0, Ljava/util/Collection;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    move-object v0, p0

    .line 15
    check-cast v0, Ljava/util/Collection;

    .line 16
    .line 17
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    :cond_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_2

    .line 33
    .line 34
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    check-cast v0, Lrd0/h;

    .line 39
    .line 40
    invoke-static {v0}, Llp/r0;->h(Lrd0/h;)Ltz/i1;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    if-ne v0, p1, :cond_1

    .line 45
    .line 46
    const/4 p0, 0x1

    .line 47
    return p0

    .line 48
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 49
    return p0
.end method
