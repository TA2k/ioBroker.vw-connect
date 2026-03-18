.class public abstract Ljp/pa;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lay0/a;Lay0/a;Lnh/r;Ll2/o;I)V
    .locals 11

    .line 1
    move-object v0, p3

    .line 2
    check-cast v0, Ll2/t;

    .line 3
    .line 4
    const v1, -0x65eb1793

    .line 5
    .line 6
    .line 7
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    const/4 v1, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 v1, 0x2

    .line 19
    :goto_0
    or-int/2addr v1, p4

    .line 20
    invoke-virtual {v0, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    const/16 v2, 0x20

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    const/16 v2, 0x10

    .line 30
    .line 31
    :goto_1
    or-int/2addr v1, v2

    .line 32
    invoke-virtual {v0, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    const/16 v6, 0x100

    .line 37
    .line 38
    if-eqz v2, :cond_2

    .line 39
    .line 40
    move v2, v6

    .line 41
    goto :goto_2

    .line 42
    :cond_2
    const/16 v2, 0x80

    .line 43
    .line 44
    :goto_2
    or-int/2addr v1, v2

    .line 45
    and-int/lit16 v2, v1, 0x93

    .line 46
    .line 47
    const/16 v7, 0x92

    .line 48
    .line 49
    const/4 v8, 0x0

    .line 50
    const/4 v9, 0x1

    .line 51
    if-eq v2, v7, :cond_3

    .line 52
    .line 53
    move v2, v9

    .line 54
    goto :goto_3

    .line 55
    :cond_3
    move v2, v8

    .line 56
    :goto_3
    and-int/lit8 v7, v1, 0x1

    .line 57
    .line 58
    invoke-virtual {v0, v7, v2}, Ll2/t;->O(IZ)Z

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    if-eqz v2, :cond_7

    .line 63
    .line 64
    invoke-static {p0, v0}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 65
    .line 66
    .line 67
    move-result-object v7

    .line 68
    move v2, v8

    .line 69
    invoke-static {p1, v0}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 70
    .line 71
    .line 72
    move-result-object v8

    .line 73
    and-int/lit16 v1, v1, 0x380

    .line 74
    .line 75
    if-eq v1, v6, :cond_4

    .line 76
    .line 77
    goto :goto_4

    .line 78
    :cond_4
    move v2, v9

    .line 79
    :goto_4
    invoke-virtual {v0, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    or-int/2addr v1, v2

    .line 84
    invoke-virtual {v0, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result v2

    .line 88
    or-int/2addr v1, v2

    .line 89
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v2

    .line 93
    if-nez v1, :cond_5

    .line 94
    .line 95
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 96
    .line 97
    if-ne v2, v1, :cond_6

    .line 98
    .line 99
    :cond_5
    new-instance v5, Laa/s;

    .line 100
    .line 101
    const/4 v9, 0x0

    .line 102
    const/16 v10, 0x17

    .line 103
    .line 104
    move-object v6, p2

    .line 105
    invoke-direct/range {v5 .. v10}, Laa/s;-><init>(Ljava/lang/Object;Ll2/b1;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v0, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    move-object v2, v5

    .line 112
    :cond_6
    check-cast v2, Lay0/n;

    .line 113
    .line 114
    invoke-static {v2, p2, v0}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 115
    .line 116
    .line 117
    goto :goto_5

    .line 118
    :cond_7
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 119
    .line 120
    .line 121
    :goto_5
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 122
    .line 123
    .line 124
    move-result-object v7

    .line 125
    if-eqz v7, :cond_8

    .line 126
    .line 127
    new-instance v0, Li91/k3;

    .line 128
    .line 129
    const/16 v2, 0x15

    .line 130
    .line 131
    move-object v3, p0

    .line 132
    move-object v4, p1

    .line 133
    move-object v5, p2

    .line 134
    move v1, p4

    .line 135
    invoke-direct/range {v0 .. v5}, Li91/k3;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 139
    .line 140
    :cond_8
    return-void
.end method

.method public static final b(Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    const-string v3, "onIntermediarySeasonSuccess"

    .line 8
    .line 9
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v3, "goToSecondSeason"

    .line 13
    .line 14
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v9, p2

    .line 18
    .line 19
    check-cast v9, Ll2/t;

    .line 20
    .line 21
    const v3, -0x7161606

    .line 22
    .line 23
    .line 24
    invoke-virtual {v9, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v9, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    const/4 v4, 0x4

    .line 32
    if-eqz v3, :cond_0

    .line 33
    .line 34
    move v3, v4

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v3, 0x2

    .line 37
    :goto_0
    or-int/2addr v3, v2

    .line 38
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v5

    .line 42
    const/16 v6, 0x20

    .line 43
    .line 44
    if-eqz v5, :cond_1

    .line 45
    .line 46
    move v5, v6

    .line 47
    goto :goto_1

    .line 48
    :cond_1
    const/16 v5, 0x10

    .line 49
    .line 50
    :goto_1
    or-int/2addr v3, v5

    .line 51
    and-int/lit8 v5, v3, 0x13

    .line 52
    .line 53
    const/16 v7, 0x12

    .line 54
    .line 55
    const/4 v8, 0x1

    .line 56
    const/4 v10, 0x0

    .line 57
    if-eq v5, v7, :cond_2

    .line 58
    .line 59
    move v5, v8

    .line 60
    goto :goto_2

    .line 61
    :cond_2
    move v5, v10

    .line 62
    :goto_2
    and-int/lit8 v7, v3, 0x1

    .line 63
    .line 64
    invoke-virtual {v9, v7, v5}, Ll2/t;->O(IZ)Z

    .line 65
    .line 66
    .line 67
    move-result v5

    .line 68
    if-eqz v5, :cond_c

    .line 69
    .line 70
    and-int/lit8 v5, v3, 0xe

    .line 71
    .line 72
    if-ne v5, v4, :cond_3

    .line 73
    .line 74
    move v4, v8

    .line 75
    goto :goto_3

    .line 76
    :cond_3
    move v4, v10

    .line 77
    :goto_3
    and-int/lit8 v3, v3, 0x70

    .line 78
    .line 79
    if-ne v3, v6, :cond_4

    .line 80
    .line 81
    goto :goto_4

    .line 82
    :cond_4
    move v8, v10

    .line 83
    :goto_4
    or-int v3, v4, v8

    .line 84
    .line 85
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v4

    .line 89
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 90
    .line 91
    if-nez v3, :cond_5

    .line 92
    .line 93
    if-ne v4, v11, :cond_6

    .line 94
    .line 95
    :cond_5
    new-instance v4, Lbf/a;

    .line 96
    .line 97
    const/4 v3, 0x0

    .line 98
    invoke-direct {v4, v0, v1, v3}, Lbf/a;-><init>(Lay0/a;Lay0/a;I)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v9, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    :cond_6
    check-cast v4, Lay0/k;

    .line 105
    .line 106
    sget-object v3, Lw3/q1;->a:Ll2/u2;

    .line 107
    .line 108
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v3

    .line 112
    check-cast v3, Ljava/lang/Boolean;

    .line 113
    .line 114
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 115
    .line 116
    .line 117
    move-result v3

    .line 118
    if-eqz v3, :cond_7

    .line 119
    .line 120
    const v3, -0x105bcaaa

    .line 121
    .line 122
    .line 123
    invoke-virtual {v9, v3}, Ll2/t;->Y(I)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 127
    .line 128
    .line 129
    const/4 v3, 0x0

    .line 130
    goto :goto_5

    .line 131
    :cond_7
    const v3, 0x31054eee

    .line 132
    .line 133
    .line 134
    invoke-virtual {v9, v3}, Ll2/t;->Y(I)V

    .line 135
    .line 136
    .line 137
    sget-object v3, Lzb/x;->a:Ll2/u2;

    .line 138
    .line 139
    invoke-virtual {v9, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v3

    .line 143
    check-cast v3, Lhi/a;

    .line 144
    .line 145
    invoke-virtual {v9, v10}, Ll2/t;->q(Z)V

    .line 146
    .line 147
    .line 148
    :goto_5
    new-instance v7, Laf/a;

    .line 149
    .line 150
    const/4 v5, 0x3

    .line 151
    invoke-direct {v7, v3, v4, v5}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 152
    .line 153
    .line 154
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 155
    .line 156
    .line 157
    move-result-object v5

    .line 158
    if-eqz v5, :cond_b

    .line 159
    .line 160
    instance-of v3, v5, Landroidx/lifecycle/k;

    .line 161
    .line 162
    if-eqz v3, :cond_8

    .line 163
    .line 164
    move-object v3, v5

    .line 165
    check-cast v3, Landroidx/lifecycle/k;

    .line 166
    .line 167
    invoke-interface {v3}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 168
    .line 169
    .line 170
    move-result-object v3

    .line 171
    :goto_6
    move-object v8, v3

    .line 172
    goto :goto_7

    .line 173
    :cond_8
    sget-object v3, Lp7/a;->b:Lp7/a;

    .line 174
    .line 175
    goto :goto_6

    .line 176
    :goto_7
    const-class v3, Lbf/d;

    .line 177
    .line 178
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 179
    .line 180
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 181
    .line 182
    .line 183
    move-result-object v4

    .line 184
    const/4 v6, 0x0

    .line 185
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 186
    .line 187
    .line 188
    move-result-object v3

    .line 189
    move-object v14, v3

    .line 190
    check-cast v14, Lbf/d;

    .line 191
    .line 192
    iget-object v3, v14, Lbf/d;->g:Lyy0/l1;

    .line 193
    .line 194
    invoke-static {v3, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 195
    .line 196
    .line 197
    invoke-static {v9}, Llp/nf;->a(Ll2/o;)Lle/c;

    .line 198
    .line 199
    .line 200
    move-result-object v3

    .line 201
    invoke-virtual {v9, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 202
    .line 203
    .line 204
    move-result v4

    .line 205
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v5

    .line 209
    if-nez v4, :cond_9

    .line 210
    .line 211
    if-ne v5, v11, :cond_a

    .line 212
    .line 213
    :cond_9
    new-instance v12, Laf/b;

    .line 214
    .line 215
    const/16 v18, 0x0

    .line 216
    .line 217
    const/16 v19, 0x7

    .line 218
    .line 219
    const/4 v13, 0x1

    .line 220
    const-class v15, Lbf/d;

    .line 221
    .line 222
    const-string v16, "onUiEvent"

    .line 223
    .line 224
    const-string v17, "onUiEvent(Lcariad/charging/multicharge/kitten/kola/presentation/wizard/multiplefixedrate/intermediateseasonsuccess/IntermediateSeasonSuccessUiEvent;)V"

    .line 225
    .line 226
    invoke-direct/range {v12 .. v19}, Laf/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 227
    .line 228
    .line 229
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 230
    .line 231
    .line 232
    move-object v5, v12

    .line 233
    :cond_a
    check-cast v5, Lhy0/g;

    .line 234
    .line 235
    check-cast v5, Lay0/k;

    .line 236
    .line 237
    invoke-interface {v3, v5, v9, v10}, Lle/c;->x0(Lay0/k;Ll2/o;I)V

    .line 238
    .line 239
    .line 240
    goto :goto_8

    .line 241
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 242
    .line 243
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 244
    .line 245
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 246
    .line 247
    .line 248
    throw v0

    .line 249
    :cond_c
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 250
    .line 251
    .line 252
    :goto_8
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 253
    .line 254
    .line 255
    move-result-object v3

    .line 256
    if-eqz v3, :cond_d

    .line 257
    .line 258
    new-instance v4, Lbf/b;

    .line 259
    .line 260
    const/4 v5, 0x0

    .line 261
    invoke-direct {v4, v0, v1, v2, v5}, Lbf/b;-><init>(Lay0/a;Lay0/a;II)V

    .line 262
    .line 263
    .line 264
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 265
    .line 266
    :cond_d
    return-void
.end method

.method public static final c(Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    const-string v3, "goNextStep"

    .line 8
    .line 9
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v3, "goBack"

    .line 13
    .line 14
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v9, p2

    .line 18
    .line 19
    check-cast v9, Ll2/t;

    .line 20
    .line 21
    const v3, -0x2c5e71f7

    .line 22
    .line 23
    .line 24
    invoke-virtual {v9, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v9, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    if-eqz v3, :cond_0

    .line 32
    .line 33
    const/4 v3, 0x4

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const/4 v3, 0x2

    .line 36
    :goto_0
    or-int/2addr v3, v2

    .line 37
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    if-eqz v4, :cond_1

    .line 42
    .line 43
    const/16 v4, 0x20

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    const/16 v4, 0x10

    .line 47
    .line 48
    :goto_1
    or-int/2addr v3, v4

    .line 49
    and-int/lit8 v4, v3, 0x13

    .line 50
    .line 51
    const/16 v5, 0x12

    .line 52
    .line 53
    const/4 v10, 0x1

    .line 54
    const/4 v11, 0x0

    .line 55
    if-eq v4, v5, :cond_2

    .line 56
    .line 57
    move v4, v10

    .line 58
    goto :goto_2

    .line 59
    :cond_2
    move v4, v11

    .line 60
    :goto_2
    and-int/lit8 v5, v3, 0x1

    .line 61
    .line 62
    invoke-virtual {v9, v5, v4}, Ll2/t;->O(IZ)Z

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    if-eqz v4, :cond_b

    .line 67
    .line 68
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v4

    .line 72
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 73
    .line 74
    if-ne v4, v12, :cond_3

    .line 75
    .line 76
    new-instance v4, Lnh/i;

    .line 77
    .line 78
    const/4 v5, 0x0

    .line 79
    invoke-direct {v4, v5}, Lnh/i;-><init>(I)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v9, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    :cond_3
    check-cast v4, Lay0/k;

    .line 86
    .line 87
    sget-object v5, Lw3/q1;->a:Ll2/u2;

    .line 88
    .line 89
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v5

    .line 93
    check-cast v5, Ljava/lang/Boolean;

    .line 94
    .line 95
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 96
    .line 97
    .line 98
    move-result v5

    .line 99
    if-eqz v5, :cond_4

    .line 100
    .line 101
    const v5, -0x105bcaaa

    .line 102
    .line 103
    .line 104
    invoke-virtual {v9, v5}, Ll2/t;->Y(I)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v9, v11}, Ll2/t;->q(Z)V

    .line 108
    .line 109
    .line 110
    const/4 v5, 0x0

    .line 111
    goto :goto_3

    .line 112
    :cond_4
    const v5, 0x31054eee

    .line 113
    .line 114
    .line 115
    invoke-virtual {v9, v5}, Ll2/t;->Y(I)V

    .line 116
    .line 117
    .line 118
    sget-object v5, Lzb/x;->a:Ll2/u2;

    .line 119
    .line 120
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v5

    .line 124
    check-cast v5, Lhi/a;

    .line 125
    .line 126
    invoke-virtual {v9, v11}, Ll2/t;->q(Z)V

    .line 127
    .line 128
    .line 129
    :goto_3
    new-instance v7, Lnd/e;

    .line 130
    .line 131
    const/4 v6, 0x3

    .line 132
    invoke-direct {v7, v5, v4, v6}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 133
    .line 134
    .line 135
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 136
    .line 137
    .line 138
    move-result-object v5

    .line 139
    if-eqz v5, :cond_a

    .line 140
    .line 141
    instance-of v4, v5, Landroidx/lifecycle/k;

    .line 142
    .line 143
    if-eqz v4, :cond_5

    .line 144
    .line 145
    move-object v4, v5

    .line 146
    check-cast v4, Landroidx/lifecycle/k;

    .line 147
    .line 148
    invoke-interface {v4}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 149
    .line 150
    .line 151
    move-result-object v4

    .line 152
    :goto_4
    move-object v8, v4

    .line 153
    goto :goto_5

    .line 154
    :cond_5
    sget-object v4, Lp7/a;->b:Lp7/a;

    .line 155
    .line 156
    goto :goto_4

    .line 157
    :goto_5
    const-class v4, Lnh/u;

    .line 158
    .line 159
    sget-object v6, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 160
    .line 161
    invoke-virtual {v6, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 162
    .line 163
    .line 164
    move-result-object v4

    .line 165
    const/4 v6, 0x0

    .line 166
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 167
    .line 168
    .line 169
    move-result-object v4

    .line 170
    move-object v15, v4

    .line 171
    check-cast v15, Lnh/u;

    .line 172
    .line 173
    iget-object v4, v15, Lnh/u;->g:Lyy0/l1;

    .line 174
    .line 175
    invoke-static {v4, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 176
    .line 177
    .line 178
    move-result-object v4

    .line 179
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v5

    .line 183
    check-cast v5, Lnh/r;

    .line 184
    .line 185
    and-int/lit8 v3, v3, 0x7e

    .line 186
    .line 187
    invoke-static {v0, v1, v5, v9, v3}, Ljp/pa;->a(Lay0/a;Lay0/a;Lnh/r;Ll2/o;I)V

    .line 188
    .line 189
    .line 190
    invoke-static {v9}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 191
    .line 192
    .line 193
    move-result-object v3

    .line 194
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v4

    .line 198
    check-cast v4, Lnh/r;

    .line 199
    .line 200
    invoke-virtual {v9, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 201
    .line 202
    .line 203
    move-result v5

    .line 204
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v6

    .line 208
    if-nez v5, :cond_6

    .line 209
    .line 210
    if-ne v6, v12, :cond_7

    .line 211
    .line 212
    :cond_6
    new-instance v13, Ln70/x;

    .line 213
    .line 214
    const/16 v19, 0x0

    .line 215
    .line 216
    const/16 v20, 0xc

    .line 217
    .line 218
    const/4 v14, 0x1

    .line 219
    const-class v16, Lnh/u;

    .line 220
    .line 221
    const-string v17, "onUiEvent"

    .line 222
    .line 223
    const-string v18, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/onboarding/addchargingcard/WallboxAddChargingCardUiEvent;)V"

    .line 224
    .line 225
    invoke-direct/range {v13 .. v20}, Ln70/x;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 226
    .line 227
    .line 228
    invoke-virtual {v9, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 229
    .line 230
    .line 231
    move-object v6, v13

    .line 232
    :cond_7
    check-cast v6, Lhy0/g;

    .line 233
    .line 234
    check-cast v6, Lay0/k;

    .line 235
    .line 236
    invoke-interface {v3, v4, v6, v9, v11}, Leh/n;->E(Lnh/r;Lay0/k;Ll2/o;I)V

    .line 237
    .line 238
    .line 239
    invoke-virtual {v9, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 240
    .line 241
    .line 242
    move-result v3

    .line 243
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    move-result-object v4

    .line 247
    if-nez v3, :cond_8

    .line 248
    .line 249
    if-ne v4, v12, :cond_9

    .line 250
    .line 251
    :cond_8
    new-instance v4, Lmc/e;

    .line 252
    .line 253
    const/16 v3, 0xc

    .line 254
    .line 255
    invoke-direct {v4, v15, v3}, Lmc/e;-><init>(Ljava/lang/Object;I)V

    .line 256
    .line 257
    .line 258
    invoke-virtual {v9, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 259
    .line 260
    .line 261
    :cond_9
    check-cast v4, Lay0/a;

    .line 262
    .line 263
    invoke-static {v11, v4, v9, v11, v10}, Ljp/tb;->a(ZLay0/a;Ll2/o;II)V

    .line 264
    .line 265
    .line 266
    goto :goto_6

    .line 267
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 268
    .line 269
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 270
    .line 271
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    throw v0

    .line 275
    :cond_b
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 276
    .line 277
    .line 278
    :goto_6
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 279
    .line 280
    .line 281
    move-result-object v3

    .line 282
    if-eqz v3, :cond_c

    .line 283
    .line 284
    new-instance v4, Lbf/b;

    .line 285
    .line 286
    const/16 v5, 0xe

    .line 287
    .line 288
    invoke-direct {v4, v0, v1, v2, v5}, Lbf/b;-><init>(Lay0/a;Lay0/a;II)V

    .line 289
    .line 290
    .line 291
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 292
    .line 293
    :cond_c
    return-void
.end method
