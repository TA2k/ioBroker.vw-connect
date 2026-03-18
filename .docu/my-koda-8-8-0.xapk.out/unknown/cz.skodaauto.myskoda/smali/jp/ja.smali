.class public abstract Ljp/ja;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 12

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, 0x72e694a1

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
    if-eqz v2, :cond_6

    .line 23
    .line 24
    const v2, -0x6040e0aa

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, v2}, Ll2/t;->Y(I)V

    .line 28
    .line 29
    .line 30
    invoke-static {p0}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    if-eqz v2, :cond_5

    .line 35
    .line 36
    invoke-static {v2}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 37
    .line 38
    .line 39
    move-result-object v6

    .line 40
    invoke-static {p0}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 41
    .line 42
    .line 43
    move-result-object v8

    .line 44
    const-class v3, La60/j;

    .line 45
    .line 46
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 47
    .line 48
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    invoke-interface {v2}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    const/4 v5, 0x0

    .line 57
    const/4 v7, 0x0

    .line 58
    const/4 v9, 0x0

    .line 59
    invoke-static/range {v3 .. v9}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 64
    .line 65
    .line 66
    check-cast v2, Lql0/j;

    .line 67
    .line 68
    invoke-static {v2, p0, v1, v0}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 69
    .line 70
    .line 71
    move-object v5, v2

    .line 72
    check-cast v5, La60/j;

    .line 73
    .line 74
    iget-object v2, v5, Lql0/j;->g:Lyy0/l1;

    .line 75
    .line 76
    const/4 v3, 0x0

    .line 77
    invoke-static {v2, v3, p0, v0}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    check-cast v0, La60/i;

    .line 86
    .line 87
    invoke-virtual {p0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v2

    .line 91
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 96
    .line 97
    if-nez v2, :cond_1

    .line 98
    .line 99
    if-ne v3, v11, :cond_2

    .line 100
    .line 101
    :cond_1
    new-instance v3, Laf/b;

    .line 102
    .line 103
    const/4 v9, 0x0

    .line 104
    const/4 v10, 0x6

    .line 105
    const/4 v4, 0x1

    .line 106
    const-class v6, La60/j;

    .line 107
    .line 108
    const-string v7, "onAction"

    .line 109
    .line 110
    const-string v8, "onAction(Ljava/lang/String;)V"

    .line 111
    .line 112
    invoke-direct/range {v3 .. v10}, Laf/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {p0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    :cond_2
    check-cast v3, Lhy0/g;

    .line 119
    .line 120
    move-object v2, v3

    .line 121
    check-cast v2, Lay0/k;

    .line 122
    .line 123
    invoke-virtual {p0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result v3

    .line 127
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v4

    .line 131
    if-nez v3, :cond_3

    .line 132
    .line 133
    if-ne v4, v11, :cond_4

    .line 134
    .line 135
    :cond_3
    new-instance v3, La71/z;

    .line 136
    .line 137
    const/4 v9, 0x0

    .line 138
    const/16 v10, 0x14

    .line 139
    .line 140
    const/4 v4, 0x0

    .line 141
    const-class v6, La60/j;

    .line 142
    .line 143
    const-string v7, "onGoBack"

    .line 144
    .line 145
    const-string v8, "onGoBack()V"

    .line 146
    .line 147
    invoke-direct/range {v3 .. v10}, La71/z;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {p0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    move-object v4, v3

    .line 154
    :cond_4
    check-cast v4, Lhy0/g;

    .line 155
    .line 156
    check-cast v4, Lay0/a;

    .line 157
    .line 158
    invoke-static {v0, v2, v4, p0, v1}, Ljp/ja;->b(La60/i;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 159
    .line 160
    .line 161
    goto :goto_1

    .line 162
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 163
    .line 164
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 165
    .line 166
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    throw p0

    .line 170
    :cond_6
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 171
    .line 172
    .line 173
    :goto_1
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    if-eqz p0, :cond_7

    .line 178
    .line 179
    new-instance v0, Lb60/b;

    .line 180
    .line 181
    const/4 v1, 0x3

    .line 182
    invoke-direct {v0, p1, v1}, Lb60/b;-><init>(II)V

    .line 183
    .line 184
    .line 185
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 186
    .line 187
    :cond_7
    return-void
.end method

.method public static final b(La60/i;Lay0/k;Lay0/a;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    move-object/from16 v4, p1

    .line 4
    .line 5
    move-object/from16 v5, p2

    .line 6
    .line 7
    move-object/from16 v0, p3

    .line 8
    .line 9
    check-cast v0, Ll2/t;

    .line 10
    .line 11
    const v1, -0x60f6345

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    const/4 v1, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v1, 0x2

    .line 26
    :goto_0
    or-int v1, p4, v1

    .line 27
    .line 28
    invoke-virtual {v0, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-eqz v2, :cond_1

    .line 33
    .line 34
    const/16 v2, 0x20

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v2, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v1, v2

    .line 40
    invoke-virtual {v0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    if-eqz v2, :cond_2

    .line 45
    .line 46
    const/16 v2, 0x100

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v2, 0x80

    .line 50
    .line 51
    :goto_2
    or-int/2addr v1, v2

    .line 52
    and-int/lit16 v2, v1, 0x93

    .line 53
    .line 54
    const/16 v6, 0x92

    .line 55
    .line 56
    const/4 v7, 0x1

    .line 57
    if-eq v2, v6, :cond_3

    .line 58
    .line 59
    move v2, v7

    .line 60
    goto :goto_3

    .line 61
    :cond_3
    const/4 v2, 0x0

    .line 62
    :goto_3
    and-int/2addr v1, v7

    .line 63
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    if-eqz v1, :cond_4

    .line 68
    .line 69
    new-instance v1, Lb60/d;

    .line 70
    .line 71
    const/4 v2, 0x1

    .line 72
    invoke-direct {v1, v5, v2}, Lb60/d;-><init>(Lay0/a;I)V

    .line 73
    .line 74
    .line 75
    const v2, -0x15339a89

    .line 76
    .line 77
    .line 78
    invoke-static {v2, v0, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 79
    .line 80
    .line 81
    move-result-object v7

    .line 82
    new-instance v1, Laa/m;

    .line 83
    .line 84
    const/16 v2, 0xd

    .line 85
    .line 86
    invoke-direct {v1, v2, v3, v4}, Laa/m;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    const v2, -0x77f7832a

    .line 90
    .line 91
    .line 92
    invoke-static {v2, v0, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 93
    .line 94
    .line 95
    move-result-object v8

    .line 96
    new-instance v1, Lb50/c;

    .line 97
    .line 98
    const/4 v2, 0x1

    .line 99
    invoke-direct {v1, v3, v2}, Lb50/c;-><init>(Ljava/lang/Object;I)V

    .line 100
    .line 101
    .line 102
    const v2, -0x4cb71634

    .line 103
    .line 104
    .line 105
    invoke-static {v2, v0, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 106
    .line 107
    .line 108
    move-result-object v17

    .line 109
    const v19, 0x300001b0

    .line 110
    .line 111
    .line 112
    const/16 v20, 0x1f9

    .line 113
    .line 114
    const/4 v6, 0x0

    .line 115
    const/4 v9, 0x0

    .line 116
    const/4 v10, 0x0

    .line 117
    const/4 v11, 0x0

    .line 118
    const-wide/16 v12, 0x0

    .line 119
    .line 120
    const-wide/16 v14, 0x0

    .line 121
    .line 122
    const/16 v16, 0x0

    .line 123
    .line 124
    move-object/from16 v18, v0

    .line 125
    .line 126
    invoke-static/range {v6 .. v20}, Lh2/c8;->a(Lx2/s;Lay0/n;Lay0/n;Lay0/n;Lay0/n;IJJLk1/q1;Lay0/o;Ll2/o;II)V

    .line 127
    .line 128
    .line 129
    goto :goto_4

    .line 130
    :cond_4
    move-object/from16 v18, v0

    .line 131
    .line 132
    invoke-virtual/range {v18 .. v18}, Ll2/t;->R()V

    .line 133
    .line 134
    .line 135
    :goto_4
    invoke-virtual/range {v18 .. v18}, Ll2/t;->s()Ll2/u1;

    .line 136
    .line 137
    .line 138
    move-result-object v6

    .line 139
    if-eqz v6, :cond_5

    .line 140
    .line 141
    new-instance v0, Laa/w;

    .line 142
    .line 143
    const/4 v2, 0x5

    .line 144
    move/from16 v1, p4

    .line 145
    .line 146
    invoke-direct/range {v0 .. v5}, Laa/w;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 150
    .line 151
    :cond_5
    return-void
.end method

.method public static final c(Lxh/e;Ll2/o;I)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v7, p1

    .line 6
    .line 7
    check-cast v7, Ll2/t;

    .line 8
    .line 9
    const v2, -0x698e468d

    .line 10
    .line 11
    .line 12
    invoke-virtual {v7, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v2, v1, 0x6

    .line 16
    .line 17
    const/4 v3, 0x2

    .line 18
    const/4 v4, 0x4

    .line 19
    if-nez v2, :cond_1

    .line 20
    .line 21
    invoke-virtual {v7, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_0

    .line 26
    .line 27
    move v2, v4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move v2, v3

    .line 30
    :goto_0
    or-int/2addr v2, v1

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v2, v1

    .line 33
    :goto_1
    and-int/lit8 v5, v2, 0x3

    .line 34
    .line 35
    const/4 v6, 0x1

    .line 36
    const/4 v8, 0x0

    .line 37
    if-eq v5, v3, :cond_2

    .line 38
    .line 39
    move v3, v6

    .line 40
    goto :goto_2

    .line 41
    :cond_2
    move v3, v8

    .line 42
    :goto_2
    and-int/lit8 v5, v2, 0x1

    .line 43
    .line 44
    invoke-virtual {v7, v5, v3}, Ll2/t;->O(IZ)Z

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    if-eqz v3, :cond_b

    .line 49
    .line 50
    and-int/lit8 v2, v2, 0xe

    .line 51
    .line 52
    if-ne v2, v4, :cond_3

    .line 53
    .line 54
    goto :goto_3

    .line 55
    :cond_3
    move v6, v8

    .line 56
    :goto_3
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    sget-object v9, Ll2/n;->a:Ll2/x0;

    .line 61
    .line 62
    if-nez v6, :cond_4

    .line 63
    .line 64
    if-ne v2, v9, :cond_5

    .line 65
    .line 66
    :cond_4
    new-instance v2, Lbi/b;

    .line 67
    .line 68
    const/4 v3, 0x3

    .line 69
    invoke-direct {v2, v0, v3}, Lbi/b;-><init>(Lxh/e;I)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v7, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    :cond_5
    check-cast v2, Lay0/k;

    .line 76
    .line 77
    sget-object v3, Lw3/q1;->a:Ll2/u2;

    .line 78
    .line 79
    invoke-virtual {v7, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    check-cast v3, Ljava/lang/Boolean;

    .line 84
    .line 85
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 86
    .line 87
    .line 88
    move-result v3

    .line 89
    if-eqz v3, :cond_6

    .line 90
    .line 91
    const v3, -0x105bcaaa

    .line 92
    .line 93
    .line 94
    invoke-virtual {v7, v3}, Ll2/t;->Y(I)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v7, v8}, Ll2/t;->q(Z)V

    .line 98
    .line 99
    .line 100
    const/4 v3, 0x0

    .line 101
    goto :goto_4

    .line 102
    :cond_6
    const v3, 0x31054eee

    .line 103
    .line 104
    .line 105
    invoke-virtual {v7, v3}, Ll2/t;->Y(I)V

    .line 106
    .line 107
    .line 108
    sget-object v3, Lzb/x;->a:Ll2/u2;

    .line 109
    .line 110
    invoke-virtual {v7, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v3

    .line 114
    check-cast v3, Lhi/a;

    .line 115
    .line 116
    invoke-virtual {v7, v8}, Ll2/t;->q(Z)V

    .line 117
    .line 118
    .line 119
    :goto_4
    new-instance v5, Lnd/e;

    .line 120
    .line 121
    const/4 v4, 0x0

    .line 122
    invoke-direct {v5, v3, v2, v4}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 123
    .line 124
    .line 125
    invoke-static {v7}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 126
    .line 127
    .line 128
    move-result-object v3

    .line 129
    if-eqz v3, :cond_a

    .line 130
    .line 131
    instance-of v2, v3, Landroidx/lifecycle/k;

    .line 132
    .line 133
    if-eqz v2, :cond_7

    .line 134
    .line 135
    move-object v2, v3

    .line 136
    check-cast v2, Landroidx/lifecycle/k;

    .line 137
    .line 138
    invoke-interface {v2}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 139
    .line 140
    .line 141
    move-result-object v2

    .line 142
    :goto_5
    move-object v6, v2

    .line 143
    goto :goto_6

    .line 144
    :cond_7
    sget-object v2, Lp7/a;->b:Lp7/a;

    .line 145
    .line 146
    goto :goto_5

    .line 147
    :goto_6
    const-class v2, Lnd/l;

    .line 148
    .line 149
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 150
    .line 151
    invoke-virtual {v4, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 152
    .line 153
    .line 154
    move-result-object v2

    .line 155
    const/4 v4, 0x0

    .line 156
    invoke-static/range {v2 .. v7}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 157
    .line 158
    .line 159
    move-result-object v2

    .line 160
    move-object v12, v2

    .line 161
    check-cast v12, Lnd/l;

    .line 162
    .line 163
    sget-object v2, Lzb/x;->b:Ll2/u2;

    .line 164
    .line 165
    invoke-virtual {v7, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v2

    .line 169
    const-string v3, "null cannot be cast to non-null type cariad.charging.multicharge.kitten.charginghistory.presentation.PublicChargingHistoryUi"

    .line 170
    .line 171
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    check-cast v2, Lfd/c;

    .line 175
    .line 176
    iget-object v3, v12, Lnd/l;->i:Lyy0/l1;

    .line 177
    .line 178
    invoke-static {v3, v7}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 179
    .line 180
    .line 181
    move-result-object v3

    .line 182
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v3

    .line 186
    check-cast v3, Llc/q;

    .line 187
    .line 188
    invoke-virtual {v7, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    move-result v4

    .line 192
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v5

    .line 196
    if-nez v4, :cond_8

    .line 197
    .line 198
    if-ne v5, v9, :cond_9

    .line 199
    .line 200
    :cond_8
    new-instance v10, Ln70/x;

    .line 201
    .line 202
    const/16 v16, 0x0

    .line 203
    .line 204
    const/16 v17, 0x9

    .line 205
    .line 206
    const/4 v11, 0x1

    .line 207
    const-class v13, Lnd/l;

    .line 208
    .line 209
    const-string v14, "onUiEvent"

    .line 210
    .line 211
    const-string v15, "onUiEvent(Lcariad/charging/multicharge/kitten/charginghistory/presentation/pub/overview/PublicChargingHistoryUiEvent;)V"

    .line 212
    .line 213
    invoke-direct/range {v10 .. v17}, Ln70/x;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 214
    .line 215
    .line 216
    invoke-virtual {v7, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 217
    .line 218
    .line 219
    move-object v5, v10

    .line 220
    :cond_9
    check-cast v5, Lhy0/g;

    .line 221
    .line 222
    check-cast v5, Lay0/k;

    .line 223
    .line 224
    const/16 v4, 0x8

    .line 225
    .line 226
    invoke-interface {v2, v3, v5, v7, v4}, Lfd/c;->V(Llc/q;Lay0/k;Ll2/o;I)V

    .line 227
    .line 228
    .line 229
    goto :goto_7

    .line 230
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 231
    .line 232
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 233
    .line 234
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    throw v0

    .line 238
    :cond_b
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 239
    .line 240
    .line 241
    :goto_7
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 242
    .line 243
    .line 244
    move-result-object v2

    .line 245
    if-eqz v2, :cond_c

    .line 246
    .line 247
    new-instance v3, Ld90/h;

    .line 248
    .line 249
    const/16 v4, 0xb

    .line 250
    .line 251
    invoke-direct {v3, v0, v1, v4}, Ld90/h;-><init>(Ljava/lang/Object;II)V

    .line 252
    .line 253
    .line 254
    iput-object v3, v2, Ll2/u1;->d:Lay0/n;

    .line 255
    .line 256
    :cond_c
    return-void
.end method
