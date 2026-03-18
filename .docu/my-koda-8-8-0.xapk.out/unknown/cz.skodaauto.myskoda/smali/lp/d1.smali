.class public abstract Llp/d1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 10

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, 0x59b99e89

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    const/4 v1, 0x1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move v1, v0

    .line 15
    :goto_0
    and-int/lit8 v2, p1, 0x1

    .line 16
    .line 17
    invoke-virtual {p0, v2, v1}, Ll2/t;->O(IZ)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_4

    .line 22
    .line 23
    const v1, -0x6040e0aa

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0, v1}, Ll2/t;->Y(I)V

    .line 27
    .line 28
    .line 29
    invoke-static {p0}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    if-eqz v1, :cond_3

    .line 34
    .line 35
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    invoke-static {p0}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 40
    .line 41
    .line 42
    move-result-object v7

    .line 43
    const-class v2, Lt20/b;

    .line 44
    .line 45
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 46
    .line 47
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 52
    .line 53
    .line 54
    move-result-object v3

    .line 55
    const/4 v4, 0x0

    .line 56
    const/4 v6, 0x0

    .line 57
    const/4 v8, 0x0

    .line 58
    invoke-static/range {v2 .. v8}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    invoke-virtual {p0, v0}, Ll2/t;->q(Z)V

    .line 63
    .line 64
    .line 65
    move-object v4, v1

    .line 66
    check-cast v4, Lt20/b;

    .line 67
    .line 68
    invoke-virtual {p0, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    if-nez v1, :cond_1

    .line 77
    .line 78
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 79
    .line 80
    if-ne v2, v1, :cond_2

    .line 81
    .line 82
    :cond_1
    new-instance v2, Lt90/c;

    .line 83
    .line 84
    const/4 v8, 0x0

    .line 85
    const/16 v9, 0xb

    .line 86
    .line 87
    const/4 v3, 0x0

    .line 88
    const-class v5, Lt20/b;

    .line 89
    .line 90
    const-string v6, "onUpdate"

    .line 91
    .line 92
    const-string v7, "onUpdate()V"

    .line 93
    .line 94
    invoke-direct/range {v2 .. v9}, Lt90/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {p0, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    :cond_2
    check-cast v2, Lhy0/g;

    .line 101
    .line 102
    check-cast v2, Lay0/a;

    .line 103
    .line 104
    invoke-static {v2, p0, v0}, Llp/d1;->b(Lay0/a;Ll2/o;I)V

    .line 105
    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 109
    .line 110
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 111
    .line 112
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    throw p0

    .line 116
    :cond_4
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 117
    .line 118
    .line 119
    :goto_1
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    if-eqz p0, :cond_5

    .line 124
    .line 125
    new-instance v0, Ltf0/a;

    .line 126
    .line 127
    const/16 v1, 0x13

    .line 128
    .line 129
    invoke-direct {v0, p1, v1}, Ltf0/a;-><init>(II)V

    .line 130
    .line 131
    .line 132
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 133
    .line 134
    :cond_5
    return-void
.end method

.method public static final b(Lay0/a;Ll2/o;I)V
    .locals 12

    .line 1
    move-object v9, p1

    .line 2
    check-cast v9, Ll2/t;

    .line 3
    .line 4
    const p1, 0x2b52263d

    .line 5
    .line 6
    .line 7
    invoke-virtual {v9, p1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v9, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    const/4 v0, 0x2

    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    const/4 p1, 0x4

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move p1, v0

    .line 20
    :goto_0
    or-int/2addr p1, p2

    .line 21
    and-int/lit8 v1, p1, 0x3

    .line 22
    .line 23
    if-eq v1, v0, :cond_1

    .line 24
    .line 25
    const/4 v0, 0x1

    .line 26
    goto :goto_1

    .line 27
    :cond_1
    const/4 v0, 0x0

    .line 28
    :goto_1
    and-int/lit8 v1, p1, 0x1

    .line 29
    .line 30
    invoke-virtual {v9, v1, v0}, Ll2/t;->O(IZ)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_2

    .line 35
    .line 36
    const v0, 0x7f1201a0

    .line 37
    .line 38
    .line 39
    invoke-static {v9, v0}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    const v0, 0x7f12019e

    .line 44
    .line 45
    .line 46
    invoke-static {v9, v0}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    const v0, 0x7f12019f

    .line 51
    .line 52
    .line 53
    invoke-static {v9, v0}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    shl-int/lit8 p1, p1, 0xf

    .line 58
    .line 59
    const/high16 v0, 0x70000

    .line 60
    .line 61
    and-int v10, p1, v0

    .line 62
    .line 63
    const/16 v11, 0x151

    .line 64
    .line 65
    const/4 v0, 0x0

    .line 66
    const/4 v4, 0x0

    .line 67
    const/4 v6, 0x0

    .line 68
    const v7, 0x7f12019f

    .line 69
    .line 70
    .line 71
    const/4 v8, 0x0

    .line 72
    move-object v5, p0

    .line 73
    invoke-static/range {v0 .. v11}, Lxf0/i0;->v(Lx2/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/a;Lay0/a;ILjava/lang/Integer;Ll2/o;II)V

    .line 74
    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_2
    move-object v5, p0

    .line 78
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 79
    .line 80
    .line 81
    :goto_2
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    if-eqz p0, :cond_3

    .line 86
    .line 87
    new-instance p1, Lt10/d;

    .line 88
    .line 89
    const/4 v0, 0x6

    .line 90
    invoke-direct {p1, v5, p2, v0}, Lt10/d;-><init>(Lay0/a;II)V

    .line 91
    .line 92
    .line 93
    iput-object p1, p0, Ll2/u1;->d:Lay0/n;

    .line 94
    .line 95
    :cond_3
    return-void
.end method

.method public static final c(J)Lpw/d;
    .locals 1

    .line 1
    new-instance v0, Lpw/d;

    .line 2
    .line 3
    invoke-static {p0, p1}, Le3/j0;->z(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    const/4 p1, 0x0

    .line 8
    invoke-direct {v0, p0, p1}, Lpw/d;-><init>(ILsw/a;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method
