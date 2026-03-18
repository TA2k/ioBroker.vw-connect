.class public abstract Lkp/v9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 13

    .line 1
    move-object v4, p0

    .line 2
    check-cast v4, Ll2/t;

    .line 3
    .line 4
    const p0, -0x438c26a6

    .line 5
    .line 6
    .line 7
    invoke-virtual {v4, p0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    const/4 v0, 0x0

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    move v1, p0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v1, v0

    .line 17
    :goto_0
    and-int/lit8 v2, p1, 0x1

    .line 18
    .line 19
    invoke-virtual {v4, v2, v1}, Ll2/t;->O(IZ)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_8

    .line 24
    .line 25
    const v1, -0x6040e0aa

    .line 26
    .line 27
    .line 28
    invoke-virtual {v4, v1}, Ll2/t;->Y(I)V

    .line 29
    .line 30
    .line 31
    invoke-static {v4}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    if-eqz v1, :cond_7

    .line 36
    .line 37
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 38
    .line 39
    .line 40
    move-result-object v8

    .line 41
    invoke-static {v4}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 42
    .line 43
    .line 44
    move-result-object v10

    .line 45
    const-class v2, Lsa0/s;

    .line 46
    .line 47
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 48
    .line 49
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 54
    .line 55
    .line 56
    move-result-object v6

    .line 57
    const/4 v7, 0x0

    .line 58
    const/4 v9, 0x0

    .line 59
    const/4 v11, 0x0

    .line 60
    invoke-static/range {v5 .. v11}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-virtual {v4, v0}, Ll2/t;->q(Z)V

    .line 65
    .line 66
    .line 67
    check-cast v1, Lql0/j;

    .line 68
    .line 69
    invoke-static {v1, v4, v0, p0}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 70
    .line 71
    .line 72
    move-object v7, v1

    .line 73
    check-cast v7, Lsa0/s;

    .line 74
    .line 75
    iget-object v0, v7, Lql0/j;->g:Lyy0/l1;

    .line 76
    .line 77
    const/4 v1, 0x0

    .line 78
    invoke-static {v0, v1, v4, p0}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    move-object v0, p0

    .line 87
    check-cast v0, Lsa0/p;

    .line 88
    .line 89
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result p0

    .line 93
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 98
    .line 99
    if-nez p0, :cond_1

    .line 100
    .line 101
    if-ne v1, v2, :cond_2

    .line 102
    .line 103
    :cond_1
    new-instance v5, Lt90/c;

    .line 104
    .line 105
    const/4 v11, 0x0

    .line 106
    const/16 v12, 0x8

    .line 107
    .line 108
    const/4 v6, 0x0

    .line 109
    const-class v8, Lsa0/s;

    .line 110
    .line 111
    const-string v9, "onGoBack"

    .line 112
    .line 113
    const-string v10, "onGoBack()V"

    .line 114
    .line 115
    invoke-direct/range {v5 .. v12}, Lt90/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    move-object v1, v5

    .line 122
    :cond_2
    check-cast v1, Lhy0/g;

    .line 123
    .line 124
    check-cast v1, Lay0/a;

    .line 125
    .line 126
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result p0

    .line 130
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v3

    .line 134
    if-nez p0, :cond_3

    .line 135
    .line 136
    if-ne v3, v2, :cond_4

    .line 137
    .line 138
    :cond_3
    new-instance v5, Lt10/k;

    .line 139
    .line 140
    const/4 v11, 0x0

    .line 141
    const/4 v12, 0x6

    .line 142
    const/4 v6, 0x1

    .line 143
    const-class v8, Lsa0/s;

    .line 144
    .line 145
    const-string v9, "onWakeUpChecked"

    .line 146
    .line 147
    const-string v10, "onWakeUpChecked(Z)V"

    .line 148
    .line 149
    invoke-direct/range {v5 .. v12}, Lt10/k;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    move-object v3, v5

    .line 156
    :cond_4
    check-cast v3, Lhy0/g;

    .line 157
    .line 158
    check-cast v3, Lay0/k;

    .line 159
    .line 160
    invoke-virtual {v4, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result p0

    .line 164
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v5

    .line 168
    if-nez p0, :cond_5

    .line 169
    .line 170
    if-ne v5, v2, :cond_6

    .line 171
    .line 172
    :cond_5
    new-instance v5, Lt10/k;

    .line 173
    .line 174
    const/4 v11, 0x0

    .line 175
    const/4 v12, 0x7

    .line 176
    const/4 v6, 0x1

    .line 177
    const-class v8, Lsa0/s;

    .line 178
    .line 179
    const-string v9, "onPredictiveWakeUpChecked"

    .line 180
    .line 181
    const-string v10, "onPredictiveWakeUpChecked(Z)V"

    .line 182
    .line 183
    invoke-direct/range {v5 .. v12}, Lt10/k;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 184
    .line 185
    .line 186
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 187
    .line 188
    .line 189
    :cond_6
    check-cast v5, Lhy0/g;

    .line 190
    .line 191
    check-cast v5, Lay0/k;

    .line 192
    .line 193
    move-object v2, v3

    .line 194
    move-object v3, v5

    .line 195
    const/4 v5, 0x0

    .line 196
    invoke-static/range {v0 .. v5}, Lkp/v9;->b(Lsa0/p;Lay0/a;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 197
    .line 198
    .line 199
    goto :goto_1

    .line 200
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 201
    .line 202
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 203
    .line 204
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    throw p0

    .line 208
    :cond_8
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 209
    .line 210
    .line 211
    :goto_1
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 212
    .line 213
    .line 214
    move-result-object p0

    .line 215
    if-eqz p0, :cond_9

    .line 216
    .line 217
    new-instance v0, Lt10/b;

    .line 218
    .line 219
    const/16 v1, 0x1d

    .line 220
    .line 221
    invoke-direct {v0, p1, v1}, Lt10/b;-><init>(II)V

    .line 222
    .line 223
    .line 224
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 225
    .line 226
    :cond_9
    return-void
.end method

.method public static final b(Lsa0/p;Lay0/a;Lay0/k;Lay0/k;Ll2/o;I)V
    .locals 20

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    move-object/from16 v4, p3

    .line 8
    .line 9
    move-object/from16 v0, p4

    .line 10
    .line 11
    check-cast v0, Ll2/t;

    .line 12
    .line 13
    const v5, -0x1193041f

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, v5}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v5

    .line 23
    if-eqz v5, :cond_0

    .line 24
    .line 25
    const/4 v5, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v5, 0x2

    .line 28
    :goto_0
    or-int v5, p5, v5

    .line 29
    .line 30
    invoke-virtual {v0, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v6

    .line 34
    if-eqz v6, :cond_1

    .line 35
    .line 36
    const/16 v6, 0x20

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/16 v6, 0x10

    .line 40
    .line 41
    :goto_1
    or-int/2addr v5, v6

    .line 42
    invoke-virtual {v0, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v6

    .line 46
    if-eqz v6, :cond_2

    .line 47
    .line 48
    const/16 v6, 0x100

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    const/16 v6, 0x80

    .line 52
    .line 53
    :goto_2
    or-int/2addr v5, v6

    .line 54
    invoke-virtual {v0, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v6

    .line 58
    if-eqz v6, :cond_3

    .line 59
    .line 60
    const/16 v6, 0x800

    .line 61
    .line 62
    goto :goto_3

    .line 63
    :cond_3
    const/16 v6, 0x400

    .line 64
    .line 65
    :goto_3
    or-int/2addr v5, v6

    .line 66
    and-int/lit16 v6, v5, 0x493

    .line 67
    .line 68
    const/16 v7, 0x492

    .line 69
    .line 70
    const/4 v8, 0x1

    .line 71
    if-eq v6, v7, :cond_4

    .line 72
    .line 73
    move v6, v8

    .line 74
    goto :goto_4

    .line 75
    :cond_4
    const/4 v6, 0x0

    .line 76
    :goto_4
    and-int/2addr v5, v8

    .line 77
    invoke-virtual {v0, v5, v6}, Ll2/t;->O(IZ)Z

    .line 78
    .line 79
    .line 80
    move-result v5

    .line 81
    if-eqz v5, :cond_5

    .line 82
    .line 83
    new-instance v5, Lt10/d;

    .line 84
    .line 85
    const/4 v6, 0x5

    .line 86
    invoke-direct {v5, v2, v6}, Lt10/d;-><init>(Lay0/a;I)V

    .line 87
    .line 88
    .line 89
    const v6, -0x1268af5b

    .line 90
    .line 91
    .line 92
    invoke-static {v6, v0, v5}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 93
    .line 94
    .line 95
    move-result-object v6

    .line 96
    new-instance v5, Lt10/f;

    .line 97
    .line 98
    const/4 v7, 0x1

    .line 99
    invoke-direct {v5, v1, v3, v4, v7}, Lt10/f;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 100
    .line 101
    .line 102
    const v7, -0xdddd090

    .line 103
    .line 104
    .line 105
    invoke-static {v7, v0, v5}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 106
    .line 107
    .line 108
    move-result-object v16

    .line 109
    const v18, 0x30000030

    .line 110
    .line 111
    .line 112
    const/16 v19, 0x1fd

    .line 113
    .line 114
    const/4 v5, 0x0

    .line 115
    const/4 v7, 0x0

    .line 116
    const/4 v8, 0x0

    .line 117
    const/4 v9, 0x0

    .line 118
    const/4 v10, 0x0

    .line 119
    const-wide/16 v11, 0x0

    .line 120
    .line 121
    const-wide/16 v13, 0x0

    .line 122
    .line 123
    const/4 v15, 0x0

    .line 124
    move-object/from16 v17, v0

    .line 125
    .line 126
    invoke-static/range {v5 .. v19}, Lh2/c8;->a(Lx2/s;Lay0/n;Lay0/n;Lay0/n;Lay0/n;IJJLk1/q1;Lay0/o;Ll2/o;II)V

    .line 127
    .line 128
    .line 129
    goto :goto_5

    .line 130
    :cond_5
    move-object/from16 v17, v0

    .line 131
    .line 132
    invoke-virtual/range {v17 .. v17}, Ll2/t;->R()V

    .line 133
    .line 134
    .line 135
    :goto_5
    invoke-virtual/range {v17 .. v17}, Ll2/t;->s()Ll2/u1;

    .line 136
    .line 137
    .line 138
    move-result-object v7

    .line 139
    if-eqz v7, :cond_6

    .line 140
    .line 141
    new-instance v0, Lo50/p;

    .line 142
    .line 143
    const/16 v6, 0x10

    .line 144
    .line 145
    move/from16 v5, p5

    .line 146
    .line 147
    invoke-direct/range {v0 .. v6}, Lo50/p;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Llx0/e;II)V

    .line 148
    .line 149
    .line 150
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 151
    .line 152
    :cond_6
    return-void
.end method
