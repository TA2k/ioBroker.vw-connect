.class public abstract Ljp/tc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 14

    .line 1
    move-object v3, p0

    .line 2
    check-cast v3, Ll2/t;

    .line 3
    .line 4
    const p0, -0x1f7b6b4c

    .line 5
    .line 6
    .line 7
    invoke-virtual {v3, p0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    const/4 v6, 0x0

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    move v0, p0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v0, v6

    .line 17
    :goto_0
    and-int/lit8 v1, p1, 0x1

    .line 18
    .line 19
    invoke-virtual {v3, v1, v0}, Ll2/t;->O(IZ)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_5

    .line 24
    .line 25
    const v0, -0x6040e0aa

    .line 26
    .line 27
    .line 28
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 29
    .line 30
    .line 31
    invoke-static {v3}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    if-eqz v0, :cond_4

    .line 36
    .line 37
    invoke-static {v0}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 38
    .line 39
    .line 40
    move-result-object v10

    .line 41
    invoke-static {v3}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 42
    .line 43
    .line 44
    move-result-object v12

    .line 45
    const-class v1, Lb40/i;

    .line 46
    .line 47
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 48
    .line 49
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 50
    .line 51
    .line 52
    move-result-object v7

    .line 53
    invoke-interface {v0}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 54
    .line 55
    .line 56
    move-result-object v8

    .line 57
    const/4 v9, 0x0

    .line 58
    const/4 v11, 0x0

    .line 59
    const/4 v13, 0x0

    .line 60
    invoke-static/range {v7 .. v13}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 65
    .line 66
    .line 67
    check-cast v0, Lb40/i;

    .line 68
    .line 69
    iget-object v1, v0, Lql0/j;->g:Lyy0/l1;

    .line 70
    .line 71
    const/4 v2, 0x0

    .line 72
    invoke-static {v1, v2, v3, p0}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    check-cast p0, Lb40/h;

    .line 81
    .line 82
    iget-object p0, p0, Lb40/h;->a:Lql0/g;

    .line 83
    .line 84
    if-nez p0, :cond_1

    .line 85
    .line 86
    const p0, 0x64972b87

    .line 87
    .line 88
    .line 89
    invoke-virtual {v3, p0}, Ll2/t;->Y(I)V

    .line 90
    .line 91
    .line 92
    :goto_1
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 93
    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_1
    const v1, 0x64972b88

    .line 97
    .line 98
    .line 99
    invoke-virtual {v3, v1}, Ll2/t;->Y(I)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v3, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v1

    .line 106
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v2

    .line 110
    if-nez v1, :cond_2

    .line 111
    .line 112
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 113
    .line 114
    if-ne v2, v1, :cond_3

    .line 115
    .line 116
    :cond_2
    new-instance v2, La2/e;

    .line 117
    .line 118
    const/16 v1, 0x9

    .line 119
    .line 120
    invoke-direct {v2, v0, v1}, La2/e;-><init>(Ljava/lang/Object;I)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v3, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    :cond_3
    move-object v1, v2

    .line 127
    check-cast v1, Lay0/k;

    .line 128
    .line 129
    const/4 v4, 0x0

    .line 130
    const/4 v5, 0x4

    .line 131
    const/4 v2, 0x0

    .line 132
    move-object v0, p0

    .line 133
    invoke-static/range {v0 .. v5}, Lyg0/a;->a(Lql0/g;Lay0/k;Lay0/k;Ll2/o;II)V

    .line 134
    .line 135
    .line 136
    goto :goto_1

    .line 137
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 138
    .line 139
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 140
    .line 141
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    throw p0

    .line 145
    :cond_5
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 146
    .line 147
    .line 148
    :goto_2
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    if-eqz p0, :cond_6

    .line 153
    .line 154
    new-instance v0, Lb60/b;

    .line 155
    .line 156
    const/16 v1, 0x18

    .line 157
    .line 158
    invoke-direct {v0, p1, v1}, Lb60/b;-><init>(II)V

    .line 159
    .line 160
    .line 161
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 162
    .line 163
    :cond_6
    return-void
.end method

.method public static final b(Low0/n;)Low0/x;
    .locals 8

    .line 1
    new-instance v0, Low0/n;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Low0/n;-><init>(I)V

    .line 5
    .line 6
    .line 7
    iget-object v1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v1, Ljava/util/Map;

    .line 10
    .line 11
    invoke-interface {v1}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Ljava/lang/Iterable;

    .line 16
    .line 17
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_2

    .line 26
    .line 27
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    check-cast v2, Ljava/lang/String;

    .line 32
    .line 33
    invoke-virtual {p0, v2}, Lap0/o;->A(Ljava/lang/String;)Ljava/util/List;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    if-nez v3, :cond_0

    .line 38
    .line 39
    sget-object v3, Lmx0/s;->d:Lmx0/s;

    .line 40
    .line 41
    :cond_0
    const/16 v4, 0xf

    .line 42
    .line 43
    const/4 v5, 0x0

    .line 44
    invoke-static {v5, v5, v4, v2}, Low0/a;->d(IIILjava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    check-cast v3, Ljava/lang/Iterable;

    .line 49
    .line 50
    new-instance v4, Ljava/util/ArrayList;

    .line 51
    .line 52
    const/16 v6, 0xa

    .line 53
    .line 54
    invoke-static {v3, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 55
    .line 56
    .line 57
    move-result v6

    .line 58
    invoke-direct {v4, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 59
    .line 60
    .line 61
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 66
    .line 67
    .line 68
    move-result v6

    .line 69
    if-eqz v6, :cond_1

    .line 70
    .line 71
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v6

    .line 75
    check-cast v6, Ljava/lang/String;

    .line 76
    .line 77
    const/16 v7, 0xb

    .line 78
    .line 79
    invoke-static {v5, v5, v7, v6}, Low0/a;->d(IIILjava/lang/String;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v6

    .line 83
    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_1
    invoke-virtual {v0, v2, v4}, Lap0/o;->i(Ljava/lang/String;Ljava/lang/Iterable;)V

    .line 88
    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_2
    new-instance p0, Low0/y;

    .line 92
    .line 93
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v0, Ljava/util/Map;

    .line 96
    .line 97
    const-string v1, "values"

    .line 98
    .line 99
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    const/4 v1, 0x1

    .line 103
    invoke-direct {p0, v0, v1}, Lvw0/l;-><init>(Ljava/util/Map;Z)V

    .line 104
    .line 105
    .line 106
    return-object p0
.end method
