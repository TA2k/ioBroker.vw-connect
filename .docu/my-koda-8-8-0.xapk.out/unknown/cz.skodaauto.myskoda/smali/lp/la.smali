.class public abstract Llp/la;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 10

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, 0x5685af4d

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    const/4 v1, 0x0

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    move v2, v0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v2, v1

    .line 16
    :goto_0
    and-int/lit8 v3, p1, 0x1

    .line 17
    .line 18
    invoke-virtual {p0, v3, v2}, Ll2/t;->O(IZ)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_4

    .line 23
    .line 24
    invoke-static {p0}, Lxf0/y1;->F(Ll2/o;)Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-eqz v2, :cond_1

    .line 29
    .line 30
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    if-eqz p0, :cond_5

    .line 35
    .line 36
    new-instance v0, Li91/i0;

    .line 37
    .line 38
    const/16 v1, 0xc

    .line 39
    .line 40
    invoke-direct {v0, p1, v1}, Li91/i0;-><init>(II)V

    .line 41
    .line 42
    .line 43
    :goto_1
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 44
    .line 45
    return-void

    .line 46
    :cond_1
    const v2, -0x6040e0aa

    .line 47
    .line 48
    .line 49
    invoke-virtual {p0, v2}, Ll2/t;->Y(I)V

    .line 50
    .line 51
    .line 52
    invoke-static {p0}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    if-eqz v2, :cond_3

    .line 57
    .line 58
    invoke-static {v2}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 59
    .line 60
    .line 61
    move-result-object v6

    .line 62
    invoke-static {p0}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 63
    .line 64
    .line 65
    move-result-object v8

    .line 66
    const-class v3, Lhk0/c;

    .line 67
    .line 68
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 69
    .line 70
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    invoke-interface {v2}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    const/4 v5, 0x0

    .line 79
    const/4 v7, 0x0

    .line 80
    const/4 v9, 0x0

    .line 81
    invoke-static/range {v3 .. v9}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 86
    .line 87
    .line 88
    check-cast v2, Lql0/j;

    .line 89
    .line 90
    const/16 v3, 0x8

    .line 91
    .line 92
    invoke-static {v2, p0, v3, v0}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 93
    .line 94
    .line 95
    check-cast v2, Lhk0/c;

    .line 96
    .line 97
    iget-object v2, v2, Lql0/j;->g:Lyy0/l1;

    .line 98
    .line 99
    const/4 v3, 0x0

    .line 100
    invoke-static {v2, v3, p0, v0}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    check-cast v2, Lhk0/b;

    .line 109
    .line 110
    iget-boolean v2, v2, Lhk0/b;->a:Z

    .line 111
    .line 112
    if-eqz v2, :cond_2

    .line 113
    .line 114
    const v2, -0x50f18ad0

    .line 115
    .line 116
    .line 117
    invoke-virtual {p0, v2}, Ll2/t;->Y(I)V

    .line 118
    .line 119
    .line 120
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    check-cast v0, Lhk0/b;

    .line 125
    .line 126
    invoke-static {v0, p0, v1}, Llp/la;->b(Lhk0/b;Ll2/o;I)V

    .line 127
    .line 128
    .line 129
    :goto_2
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 130
    .line 131
    .line 132
    goto :goto_3

    .line 133
    :cond_2
    const v0, -0x5102c90b

    .line 134
    .line 135
    .line 136
    invoke-virtual {p0, v0}, Ll2/t;->Y(I)V

    .line 137
    .line 138
    .line 139
    goto :goto_2

    .line 140
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 141
    .line 142
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 143
    .line 144
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    throw p0

    .line 148
    :cond_4
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 149
    .line 150
    .line 151
    :goto_3
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    if-eqz p0, :cond_5

    .line 156
    .line 157
    new-instance v0, Li91/i0;

    .line 158
    .line 159
    const/16 v1, 0xd

    .line 160
    .line 161
    invoke-direct {v0, p1, v1}, Li91/i0;-><init>(II)V

    .line 162
    .line 163
    .line 164
    goto :goto_1

    .line 165
    :cond_5
    return-void
.end method

.method public static final b(Lhk0/b;Ll2/o;I)V
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p1

    .line 6
    .line 7
    check-cast v2, Ll2/t;

    .line 8
    .line 9
    const v3, -0x6bd8b008

    .line 10
    .line 11
    .line 12
    invoke-virtual {v2, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v2, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    const/4 v4, 0x2

    .line 20
    const/4 v5, 0x4

    .line 21
    if-eqz v3, :cond_0

    .line 22
    .line 23
    move v3, v5

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    move v3, v4

    .line 26
    :goto_0
    or-int/2addr v3, v1

    .line 27
    and-int/lit8 v6, v3, 0x3

    .line 28
    .line 29
    const/4 v7, 0x1

    .line 30
    if-eq v6, v4, :cond_1

    .line 31
    .line 32
    move v4, v7

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    const/4 v4, 0x0

    .line 35
    :goto_1
    and-int/2addr v3, v7

    .line 36
    invoke-virtual {v2, v3, v4}, Ll2/t;->O(IZ)Z

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    if-eqz v3, :cond_2

    .line 41
    .line 42
    iget v3, v0, Lhk0/b;->b:F

    .line 43
    .line 44
    iget v4, v0, Lhk0/b;->c:I

    .line 45
    .line 46
    iget v6, v0, Lhk0/b;->d:I

    .line 47
    .line 48
    new-instance v7, Ljava/lang/StringBuilder;

    .line 49
    .line 50
    const-string v8, "Zoom Level : "

    .line 51
    .line 52
    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    const-string v3, "\nRadius[m] : "

    .line 59
    .line 60
    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    invoke-virtual {v7, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string v3, "\nPoi count : "

    .line 67
    .line 68
    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    invoke-virtual {v7, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v3

    .line 78
    sget-object v4, Lj91/j;->a:Ll2/u2;

    .line 79
    .line 80
    invoke-virtual {v2, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    check-cast v4, Lj91/f;

    .line 85
    .line 86
    invoke-virtual {v4}, Lj91/f;->a()Lg4/p0;

    .line 87
    .line 88
    .line 89
    move-result-object v4

    .line 90
    sget-object v6, Lj91/a;->a:Ll2/u2;

    .line 91
    .line 92
    invoke-virtual {v2, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v6

    .line 96
    check-cast v6, Lj91/c;

    .line 97
    .line 98
    iget v6, v6, Lj91/c;->j:F

    .line 99
    .line 100
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 101
    .line 102
    invoke-static {v7, v6}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 103
    .line 104
    .line 105
    move-result-object v6

    .line 106
    int-to-float v5, v5

    .line 107
    invoke-static {v5}, Ls1/f;->b(F)Ls1/e;

    .line 108
    .line 109
    .line 110
    move-result-object v7

    .line 111
    invoke-static {v6, v7}, Ljp/ba;->c(Lx2/s;Le3/n0;)Lx2/s;

    .line 112
    .line 113
    .line 114
    move-result-object v6

    .line 115
    sget-object v7, Lj91/h;->a:Ll2/u2;

    .line 116
    .line 117
    invoke-virtual {v2, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v7

    .line 121
    check-cast v7, Lj91/e;

    .line 122
    .line 123
    invoke-virtual {v7}, Lj91/e;->h()J

    .line 124
    .line 125
    .line 126
    move-result-wide v7

    .line 127
    sget-object v9, Le3/j0;->a:Le3/i0;

    .line 128
    .line 129
    invoke-static {v6, v7, v8, v9}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 130
    .line 131
    .line 132
    move-result-object v6

    .line 133
    invoke-static {v6, v5}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 134
    .line 135
    .line 136
    move-result-object v5

    .line 137
    const/16 v22, 0x0

    .line 138
    .line 139
    const v23, 0xfff8

    .line 140
    .line 141
    .line 142
    move-object/from16 v20, v2

    .line 143
    .line 144
    move-object v2, v3

    .line 145
    move-object v3, v4

    .line 146
    move-object v4, v5

    .line 147
    const-wide/16 v5, 0x0

    .line 148
    .line 149
    const-wide/16 v7, 0x0

    .line 150
    .line 151
    const/4 v9, 0x0

    .line 152
    const-wide/16 v10, 0x0

    .line 153
    .line 154
    const/4 v12, 0x0

    .line 155
    const/4 v13, 0x0

    .line 156
    const-wide/16 v14, 0x0

    .line 157
    .line 158
    const/16 v16, 0x0

    .line 159
    .line 160
    const/16 v17, 0x0

    .line 161
    .line 162
    const/16 v18, 0x0

    .line 163
    .line 164
    const/16 v19, 0x0

    .line 165
    .line 166
    const/16 v21, 0x0

    .line 167
    .line 168
    invoke-static/range {v2 .. v23}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 169
    .line 170
    .line 171
    goto :goto_2

    .line 172
    :cond_2
    move-object/from16 v20, v2

    .line 173
    .line 174
    invoke-virtual/range {v20 .. v20}, Ll2/t;->R()V

    .line 175
    .line 176
    .line 177
    :goto_2
    invoke-virtual/range {v20 .. v20}, Ll2/t;->s()Ll2/u1;

    .line 178
    .line 179
    .line 180
    move-result-object v2

    .line 181
    if-eqz v2, :cond_3

    .line 182
    .line 183
    new-instance v3, Lh2/y5;

    .line 184
    .line 185
    const/16 v4, 0x12

    .line 186
    .line 187
    invoke-direct {v3, v0, v1, v4}, Lh2/y5;-><init>(Ljava/lang/Object;II)V

    .line 188
    .line 189
    .line 190
    iput-object v3, v2, Ll2/u1;->d:Lay0/n;

    .line 191
    .line 192
    :cond_3
    return-void
.end method
