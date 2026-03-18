.class public abstract Llp/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lvv/m0;Ljava/lang/String;Ll2/o;I)V
    .locals 11

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    move-object v8, p2

    .line 7
    check-cast v8, Ll2/t;

    .line 8
    .line 9
    const p2, -0x9e57deb

    .line 10
    .line 11
    .line 12
    invoke-virtual {v8, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v8, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    if-eqz p2, :cond_0

    .line 20
    .line 21
    const/4 p2, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 p2, 0x2

    .line 24
    :goto_0
    or-int/2addr p2, p3

    .line 25
    invoke-virtual {v8, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    const/16 v1, 0x10

    .line 30
    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    const/16 v0, 0x20

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    move v0, v1

    .line 37
    :goto_1
    or-int/2addr p2, v0

    .line 38
    and-int/lit8 v0, p2, 0x5b

    .line 39
    .line 40
    const/16 v2, 0x12

    .line 41
    .line 42
    if-ne v0, v2, :cond_3

    .line 43
    .line 44
    invoke-virtual {v8}, Ll2/t;->A()Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-nez v0, :cond_2

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 52
    .line 53
    .line 54
    move-object v1, p0

    .line 55
    goto :goto_3

    .line 56
    :cond_3
    :goto_2
    const v0, 0x44faf204

    .line 57
    .line 58
    .line 59
    invoke-virtual {v8, v0}, Ll2/t;->Z(I)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v8, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    if-nez v0, :cond_4

    .line 71
    .line 72
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 73
    .line 74
    if-ne v2, v0, :cond_5

    .line 75
    .line 76
    :cond_4
    new-instance v0, Lg4/d;

    .line 77
    .line 78
    invoke-direct {v0, v1}, Lg4/d;-><init>(I)V

    .line 79
    .line 80
    .line 81
    new-instance v1, Ljava/util/LinkedHashMap;

    .line 82
    .line 83
    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 84
    .line 85
    .line 86
    new-instance v2, Ld4/o;

    .line 87
    .line 88
    const/4 v3, 0x1

    .line 89
    invoke-direct {v2, p1, v3}, Ld4/o;-><init>(Ljava/lang/String;I)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v2, v0}, Ld4/o;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    new-instance v2, Lxv/o;

    .line 96
    .line 97
    invoke-virtual {v0}, Lg4/d;->j()Lg4/g;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    invoke-static {v1}, Lmx0/x;->u(Ljava/util/Map;)Ljava/util/Map;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    invoke-direct {v2, v0, v1}, Lxv/o;-><init>(Lg4/g;Ljava/util/Map;)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v8, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    :cond_5
    const/4 v0, 0x0

    .line 112
    invoke-virtual {v8, v0}, Ll2/t;->q(Z)V

    .line 113
    .line 114
    .line 115
    check-cast v2, Lxv/o;

    .line 116
    .line 117
    and-int/lit8 v9, p2, 0xe

    .line 118
    .line 119
    const/16 v10, 0x3e

    .line 120
    .line 121
    const/4 v3, 0x0

    .line 122
    const/4 v4, 0x0

    .line 123
    const/4 v5, 0x0

    .line 124
    const/4 v6, 0x0

    .line 125
    const/4 v7, 0x0

    .line 126
    move-object v1, p0

    .line 127
    invoke-static/range {v1 .. v10}, Llp/ff;->a(Lvv/m0;Lxv/o;Lx2/s;Lay0/k;ZIILl2/o;II)V

    .line 128
    .line 129
    .line 130
    :goto_3
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    if-eqz p0, :cond_6

    .line 135
    .line 136
    new-instance p2, Lkn/i0;

    .line 137
    .line 138
    const/4 v0, 0x2

    .line 139
    invoke-direct {p2, p3, v0, v1, p1}, Lkn/i0;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    iput-object p2, p0, Ll2/u1;->d:Lay0/n;

    .line 143
    .line 144
    :cond_6
    return-void
.end method

.method public static final b(Lqp0/b0;Ljava/util/List;)Lh50/w0;
    .locals 5

    .line 1
    const-string v0, "allWaypoints"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Ljp/eg;->e(Lqp0/b0;)Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    sget-object p0, Lh50/t0;->a:Lh50/t0;

    .line 13
    .line 14
    return-object p0

    .line 15
    :cond_0
    invoke-static {p0}, Ljp/eg;->f(Lqp0/b0;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_5

    .line 20
    .line 21
    new-instance p1, Lh50/u0;

    .line 22
    .line 23
    iget-object p0, p0, Lqp0/b0;->k:Lqp0/a0;

    .line 24
    .line 25
    if-eqz p0, :cond_1

    .line 26
    .line 27
    iget-object p0, p0, Lqp0/a0;->c:Lqp0/f;

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    const/4 p0, 0x0

    .line 31
    :goto_0
    const/4 v0, -0x1

    .line 32
    if-nez p0, :cond_2

    .line 33
    .line 34
    move p0, v0

    .line 35
    goto :goto_1

    .line 36
    :cond_2
    sget-object v1, Lh50/x0;->a:[I

    .line 37
    .line 38
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    aget p0, v1, p0

    .line 43
    .line 44
    :goto_1
    const v1, 0x7f0802dc

    .line 45
    .line 46
    .line 47
    if-eq p0, v0, :cond_4

    .line 48
    .line 49
    const/4 v0, 0x1

    .line 50
    if-eq p0, v0, :cond_4

    .line 51
    .line 52
    const/4 v0, 0x2

    .line 53
    if-ne p0, v0, :cond_3

    .line 54
    .line 55
    const v1, 0x7f0802d9

    .line 56
    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_3
    new-instance p0, La8/r0;

    .line 60
    .line 61
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 62
    .line 63
    .line 64
    throw p0

    .line 65
    :cond_4
    :goto_2
    invoke-direct {p1, v1}, Lh50/u0;-><init>(I)V

    .line 66
    .line 67
    .line 68
    return-object p1

    .line 69
    :cond_5
    new-instance v0, Lh50/v0;

    .line 70
    .line 71
    check-cast p1, Ljava/lang/Iterable;

    .line 72
    .line 73
    new-instance v1, Ljava/util/ArrayList;

    .line 74
    .line 75
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 76
    .line 77
    .line 78
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    :cond_6
    :goto_3
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    if-eqz v2, :cond_8

    .line 87
    .line 88
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    move-object v3, v2

    .line 93
    check-cast v3, Lqp0/b0;

    .line 94
    .line 95
    invoke-static {v3}, Ljp/eg;->e(Lqp0/b0;)Z

    .line 96
    .line 97
    .line 98
    move-result v4

    .line 99
    if-nez v4, :cond_6

    .line 100
    .line 101
    invoke-static {v3}, Ljp/eg;->f(Lqp0/b0;)Z

    .line 102
    .line 103
    .line 104
    move-result v3

    .line 105
    if-eqz v3, :cond_7

    .line 106
    .line 107
    goto :goto_3

    .line 108
    :cond_7
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_8
    invoke-virtual {v1, p0}, Ljava/util/ArrayList;->indexOf(Ljava/lang/Object;)I

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    add-int/lit8 p0, p0, 0x41

    .line 117
    .line 118
    int-to-char p0, p0

    .line 119
    invoke-direct {v0, p0}, Lh50/v0;-><init>(C)V

    .line 120
    .line 121
    .line 122
    return-object v0
.end method
