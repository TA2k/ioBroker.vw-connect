.class public abstract Ljp/c1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ldd/f;Lzb/s0;Ll2/o;I)V
    .locals 19

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
    move-object/from16 v8, p2

    .line 8
    .line 9
    check-cast v8, Ll2/t;

    .line 10
    .line 11
    const v3, 0x284bc7d2

    .line 12
    .line 13
    .line 14
    invoke-virtual {v8, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v8, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    if-eqz v3, :cond_0

    .line 22
    .line 23
    const/4 v3, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v3, 0x2

    .line 26
    :goto_0
    or-int/2addr v3, v2

    .line 27
    invoke-virtual {v8, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    const/16 v5, 0x20

    .line 32
    .line 33
    if-eqz v4, :cond_1

    .line 34
    .line 35
    move v4, v5

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v4, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v3, v4

    .line 40
    and-int/lit8 v4, v3, 0x13

    .line 41
    .line 42
    const/16 v6, 0x12

    .line 43
    .line 44
    const/4 v7, 0x1

    .line 45
    const/4 v9, 0x0

    .line 46
    if-eq v4, v6, :cond_2

    .line 47
    .line 48
    move v4, v7

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    move v4, v9

    .line 51
    :goto_2
    and-int/lit8 v6, v3, 0x1

    .line 52
    .line 53
    invoke-virtual {v8, v6, v4}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    if-eqz v4, :cond_b

    .line 58
    .line 59
    invoke-virtual {v8, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    and-int/lit8 v3, v3, 0x70

    .line 64
    .line 65
    if-ne v3, v5, :cond_3

    .line 66
    .line 67
    goto :goto_3

    .line 68
    :cond_3
    move v7, v9

    .line 69
    :goto_3
    or-int v3, v4, v7

    .line 70
    .line 71
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v4

    .line 75
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 76
    .line 77
    if-nez v3, :cond_4

    .line 78
    .line 79
    if-ne v4, v10, :cond_5

    .line 80
    .line 81
    :cond_4
    new-instance v4, Ll2/v1;

    .line 82
    .line 83
    const/16 v3, 0xe

    .line 84
    .line 85
    invoke-direct {v4, v3, v0, v1}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {v8, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    :cond_5
    check-cast v4, Lay0/k;

    .line 92
    .line 93
    sget-object v3, Lw3/q1;->a:Ll2/u2;

    .line 94
    .line 95
    invoke-virtual {v8, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v3

    .line 99
    check-cast v3, Ljava/lang/Boolean;

    .line 100
    .line 101
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 102
    .line 103
    .line 104
    move-result v3

    .line 105
    if-eqz v3, :cond_6

    .line 106
    .line 107
    const v3, -0x105bcaaa

    .line 108
    .line 109
    .line 110
    invoke-virtual {v8, v3}, Ll2/t;->Y(I)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v8, v9}, Ll2/t;->q(Z)V

    .line 114
    .line 115
    .line 116
    const/4 v3, 0x0

    .line 117
    goto :goto_4

    .line 118
    :cond_6
    const v3, 0x31054eee

    .line 119
    .line 120
    .line 121
    invoke-virtual {v8, v3}, Ll2/t;->Y(I)V

    .line 122
    .line 123
    .line 124
    sget-object v3, Lzb/x;->a:Ll2/u2;

    .line 125
    .line 126
    invoke-virtual {v8, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v3

    .line 130
    check-cast v3, Lhi/a;

    .line 131
    .line 132
    invoke-virtual {v8, v9}, Ll2/t;->q(Z)V

    .line 133
    .line 134
    .line 135
    :goto_4
    new-instance v6, Laf/a;

    .line 136
    .line 137
    const/16 v5, 0x1a

    .line 138
    .line 139
    invoke-direct {v6, v3, v4, v5}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 140
    .line 141
    .line 142
    invoke-static {v8}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 143
    .line 144
    .line 145
    move-result-object v4

    .line 146
    if-eqz v4, :cond_a

    .line 147
    .line 148
    instance-of v3, v4, Landroidx/lifecycle/k;

    .line 149
    .line 150
    if-eqz v3, :cond_7

    .line 151
    .line 152
    move-object v3, v4

    .line 153
    check-cast v3, Landroidx/lifecycle/k;

    .line 154
    .line 155
    invoke-interface {v3}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 156
    .line 157
    .line 158
    move-result-object v3

    .line 159
    :goto_5
    move-object v7, v3

    .line 160
    goto :goto_6

    .line 161
    :cond_7
    sget-object v3, Lp7/a;->b:Lp7/a;

    .line 162
    .line 163
    goto :goto_5

    .line 164
    :goto_6
    const-class v3, Lmd/c;

    .line 165
    .line 166
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 167
    .line 168
    invoke-virtual {v5, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 169
    .line 170
    .line 171
    move-result-object v3

    .line 172
    const/4 v5, 0x0

    .line 173
    invoke-static/range {v3 .. v8}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 174
    .line 175
    .line 176
    move-result-object v3

    .line 177
    move-object v13, v3

    .line 178
    check-cast v13, Lmd/c;

    .line 179
    .line 180
    sget-object v3, Lzb/x;->b:Ll2/u2;

    .line 181
    .line 182
    invoke-virtual {v8, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v3

    .line 186
    const-string v4, "null cannot be cast to non-null type cariad.charging.multicharge.kitten.charginghistory.presentation.PublicChargingHistoryUi"

    .line 187
    .line 188
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    check-cast v3, Lfd/c;

    .line 192
    .line 193
    iget-object v4, v13, Lmd/c;->e:Lyy0/c2;

    .line 194
    .line 195
    invoke-static {v4, v8}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 196
    .line 197
    .line 198
    move-result-object v4

    .line 199
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v4

    .line 203
    check-cast v4, Lmd/b;

    .line 204
    .line 205
    invoke-virtual {v8, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    move-result v5

    .line 209
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v6

    .line 213
    if-nez v5, :cond_8

    .line 214
    .line 215
    if-ne v6, v10, :cond_9

    .line 216
    .line 217
    :cond_8
    new-instance v11, Ll20/g;

    .line 218
    .line 219
    const/16 v17, 0x0

    .line 220
    .line 221
    const/16 v18, 0xb

    .line 222
    .line 223
    const/4 v12, 0x1

    .line 224
    const-class v14, Lmd/c;

    .line 225
    .line 226
    const-string v15, "onUiEvent"

    .line 227
    .line 228
    const-string v16, "onUiEvent(Lcariad/charging/multicharge/kitten/charginghistory/presentation/pub/detail/PublicChargingHistoryDetailUIEvent;)V"

    .line 229
    .line 230
    invoke-direct/range {v11 .. v18}, Ll20/g;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 231
    .line 232
    .line 233
    invoke-virtual {v8, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 234
    .line 235
    .line 236
    move-object v6, v11

    .line 237
    :cond_9
    check-cast v6, Lhy0/g;

    .line 238
    .line 239
    check-cast v6, Lay0/k;

    .line 240
    .line 241
    invoke-interface {v3, v4, v6, v8, v9}, Lfd/c;->t0(Lmd/b;Lay0/k;Ll2/o;I)V

    .line 242
    .line 243
    .line 244
    goto :goto_7

    .line 245
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 246
    .line 247
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 248
    .line 249
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 250
    .line 251
    .line 252
    throw v0

    .line 253
    :cond_b
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 254
    .line 255
    .line 256
    :goto_7
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 257
    .line 258
    .line 259
    move-result-object v3

    .line 260
    if-eqz v3, :cond_c

    .line 261
    .line 262
    new-instance v4, Ll2/u;

    .line 263
    .line 264
    const/4 v5, 0x4

    .line 265
    invoke-direct {v4, v2, v5, v0, v1}, Ll2/u;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 269
    .line 270
    :cond_c
    return-void
.end method

.method public static final b(Lx40/j;Lxh/e;Lzb/d;Lxh/e;Lxh/e;Lxh/e;Ljava/lang/String;Ll2/o;I)V
    .locals 17

    .line 1
    move-object/from16 v5, p7

    .line 2
    .line 3
    check-cast v5, Ll2/t;

    .line 4
    .line 5
    const v0, 0x4ff90ca3

    .line 6
    .line 7
    .line 8
    invoke-virtual {v5, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    move-object/from16 v7, p0

    .line 12
    .line 13
    invoke-virtual {v5, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v1, 0x4

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    move v0, v1

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x2

    .line 23
    :goto_0
    or-int v0, p8, v0

    .line 24
    .line 25
    move-object/from16 v8, p1

    .line 26
    .line 27
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    const/16 v3, 0x20

    .line 32
    .line 33
    if-eqz v2, :cond_1

    .line 34
    .line 35
    move v2, v3

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v2, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v0, v2

    .line 40
    move-object/from16 v9, p2

    .line 41
    .line 42
    invoke-virtual {v5, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    const/16 v4, 0x100

    .line 47
    .line 48
    if-eqz v2, :cond_2

    .line 49
    .line 50
    move v2, v4

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v2, 0x80

    .line 53
    .line 54
    :goto_2
    or-int/2addr v0, v2

    .line 55
    move-object/from16 v10, p3

    .line 56
    .line 57
    invoke-virtual {v5, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v2

    .line 61
    if-eqz v2, :cond_3

    .line 62
    .line 63
    const/16 v2, 0x800

    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_3
    const/16 v2, 0x400

    .line 67
    .line 68
    :goto_3
    or-int/2addr v0, v2

    .line 69
    move-object/from16 v11, p4

    .line 70
    .line 71
    invoke-virtual {v5, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v2

    .line 75
    if-eqz v2, :cond_4

    .line 76
    .line 77
    const/16 v2, 0x4000

    .line 78
    .line 79
    goto :goto_4

    .line 80
    :cond_4
    const/16 v2, 0x2000

    .line 81
    .line 82
    :goto_4
    or-int/2addr v0, v2

    .line 83
    move-object/from16 v2, p5

    .line 84
    .line 85
    invoke-virtual {v5, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v13

    .line 89
    const/high16 v14, 0x20000

    .line 90
    .line 91
    if-eqz v13, :cond_5

    .line 92
    .line 93
    move v13, v14

    .line 94
    goto :goto_5

    .line 95
    :cond_5
    const/high16 v13, 0x10000

    .line 96
    .line 97
    :goto_5
    or-int/2addr v0, v13

    .line 98
    move-object/from16 v13, p6

    .line 99
    .line 100
    invoke-virtual {v5, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v15

    .line 104
    if-eqz v15, :cond_6

    .line 105
    .line 106
    const/high16 v15, 0x100000

    .line 107
    .line 108
    goto :goto_6

    .line 109
    :cond_6
    const/high16 v15, 0x80000

    .line 110
    .line 111
    :goto_6
    or-int/2addr v0, v15

    .line 112
    const v15, 0x92493

    .line 113
    .line 114
    .line 115
    and-int/2addr v15, v0

    .line 116
    const v12, 0x92492

    .line 117
    .line 118
    .line 119
    const/16 v16, 0x1

    .line 120
    .line 121
    const/4 v6, 0x0

    .line 122
    if-eq v15, v12, :cond_7

    .line 123
    .line 124
    move/from16 v12, v16

    .line 125
    .line 126
    goto :goto_7

    .line 127
    :cond_7
    move v12, v6

    .line 128
    :goto_7
    and-int/lit8 v15, v0, 0x1

    .line 129
    .line 130
    invoke-virtual {v5, v15, v12}, Ll2/t;->O(IZ)Z

    .line 131
    .line 132
    .line 133
    move-result v12

    .line 134
    if-eqz v12, :cond_16

    .line 135
    .line 136
    and-int/lit8 v12, v0, 0xe

    .line 137
    .line 138
    if-ne v12, v1, :cond_8

    .line 139
    .line 140
    move/from16 v1, v16

    .line 141
    .line 142
    goto :goto_8

    .line 143
    :cond_8
    move v1, v6

    .line 144
    :goto_8
    and-int/lit8 v12, v0, 0x70

    .line 145
    .line 146
    if-ne v12, v3, :cond_9

    .line 147
    .line 148
    move/from16 v3, v16

    .line 149
    .line 150
    goto :goto_9

    .line 151
    :cond_9
    move v3, v6

    .line 152
    :goto_9
    or-int/2addr v1, v3

    .line 153
    and-int/lit16 v3, v0, 0x380

    .line 154
    .line 155
    if-ne v3, v4, :cond_a

    .line 156
    .line 157
    move/from16 v3, v16

    .line 158
    .line 159
    goto :goto_a

    .line 160
    :cond_a
    move v3, v6

    .line 161
    :goto_a
    or-int/2addr v1, v3

    .line 162
    const/high16 v3, 0x70000

    .line 163
    .line 164
    and-int/2addr v3, v0

    .line 165
    if-ne v3, v14, :cond_b

    .line 166
    .line 167
    move/from16 v3, v16

    .line 168
    .line 169
    goto :goto_b

    .line 170
    :cond_b
    move v3, v6

    .line 171
    :goto_b
    or-int/2addr v1, v3

    .line 172
    and-int/lit16 v3, v0, 0x1c00

    .line 173
    .line 174
    const/16 v4, 0x800

    .line 175
    .line 176
    if-ne v3, v4, :cond_c

    .line 177
    .line 178
    move/from16 v3, v16

    .line 179
    .line 180
    goto :goto_c

    .line 181
    :cond_c
    move v3, v6

    .line 182
    :goto_c
    or-int/2addr v1, v3

    .line 183
    const v3, 0xe000

    .line 184
    .line 185
    .line 186
    and-int/2addr v3, v0

    .line 187
    const/16 v4, 0x4000

    .line 188
    .line 189
    if-ne v3, v4, :cond_d

    .line 190
    .line 191
    move/from16 v3, v16

    .line 192
    .line 193
    goto :goto_d

    .line 194
    :cond_d
    move v3, v6

    .line 195
    :goto_d
    or-int/2addr v1, v3

    .line 196
    const/high16 v3, 0x380000

    .line 197
    .line 198
    and-int/2addr v0, v3

    .line 199
    const/high16 v3, 0x100000

    .line 200
    .line 201
    if-ne v0, v3, :cond_e

    .line 202
    .line 203
    goto :goto_e

    .line 204
    :cond_e
    move/from16 v16, v6

    .line 205
    .line 206
    :goto_e
    or-int v0, v1, v16

    .line 207
    .line 208
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v1

    .line 212
    sget-object v15, Ll2/n;->a:Ll2/x0;

    .line 213
    .line 214
    if-nez v0, :cond_f

    .line 215
    .line 216
    if-ne v1, v15, :cond_10

    .line 217
    .line 218
    :cond_f
    move v0, v6

    .line 219
    goto :goto_f

    .line 220
    :cond_10
    move v0, v6

    .line 221
    goto :goto_10

    .line 222
    :goto_f
    new-instance v6, Laa/d0;

    .line 223
    .line 224
    const/4 v14, 0x1

    .line 225
    move-object v12, v11

    .line 226
    move-object v11, v10

    .line 227
    move-object v10, v2

    .line 228
    invoke-direct/range {v6 .. v14}, Laa/d0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Llx0/e;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 229
    .line 230
    .line 231
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    move-object v1, v6

    .line 235
    :goto_10
    check-cast v1, Lay0/k;

    .line 236
    .line 237
    sget-object v2, Lw3/q1;->a:Ll2/u2;

    .line 238
    .line 239
    invoke-virtual {v5, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v2

    .line 243
    check-cast v2, Ljava/lang/Boolean;

    .line 244
    .line 245
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 246
    .line 247
    .line 248
    move-result v2

    .line 249
    if-eqz v2, :cond_11

    .line 250
    .line 251
    const v2, -0x105bcaaa

    .line 252
    .line 253
    .line 254
    invoke-virtual {v5, v2}, Ll2/t;->Y(I)V

    .line 255
    .line 256
    .line 257
    invoke-virtual {v5, v0}, Ll2/t;->q(Z)V

    .line 258
    .line 259
    .line 260
    const/4 v0, 0x0

    .line 261
    goto :goto_11

    .line 262
    :cond_11
    const v2, 0x31054eee

    .line 263
    .line 264
    .line 265
    invoke-virtual {v5, v2}, Ll2/t;->Y(I)V

    .line 266
    .line 267
    .line 268
    sget-object v2, Lzb/x;->a:Ll2/u2;

    .line 269
    .line 270
    invoke-virtual {v5, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v2

    .line 274
    check-cast v2, Lhi/a;

    .line 275
    .line 276
    invoke-virtual {v5, v0}, Ll2/t;->q(Z)V

    .line 277
    .line 278
    .line 279
    move-object v0, v2

    .line 280
    :goto_11
    new-instance v3, Laf/a;

    .line 281
    .line 282
    const/4 v2, 0x2

    .line 283
    invoke-direct {v3, v0, v1, v2}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 284
    .line 285
    .line 286
    invoke-static {v5}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 287
    .line 288
    .line 289
    move-result-object v1

    .line 290
    if-eqz v1, :cond_15

    .line 291
    .line 292
    instance-of v0, v1, Landroidx/lifecycle/k;

    .line 293
    .line 294
    if-eqz v0, :cond_12

    .line 295
    .line 296
    move-object v0, v1

    .line 297
    check-cast v0, Landroidx/lifecycle/k;

    .line 298
    .line 299
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 300
    .line 301
    .line 302
    move-result-object v0

    .line 303
    :goto_12
    move-object v4, v0

    .line 304
    goto :goto_13

    .line 305
    :cond_12
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 306
    .line 307
    goto :goto_12

    .line 308
    :goto_13
    const-class v0, Lai/l;

    .line 309
    .line 310
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 311
    .line 312
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 313
    .line 314
    .line 315
    move-result-object v0

    .line 316
    const/4 v2, 0x0

    .line 317
    invoke-static/range {v0 .. v5}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 318
    .line 319
    .line 320
    move-result-object v0

    .line 321
    move-object v8, v0

    .line 322
    check-cast v8, Lai/l;

    .line 323
    .line 324
    invoke-static {v5}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 325
    .line 326
    .line 327
    move-result-object v0

    .line 328
    iget-object v1, v8, Lai/l;->k:Lyy0/c2;

    .line 329
    .line 330
    invoke-static {v1, v5}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 331
    .line 332
    .line 333
    move-result-object v1

    .line 334
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 335
    .line 336
    .line 337
    move-result-object v1

    .line 338
    check-cast v1, Llc/q;

    .line 339
    .line 340
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 341
    .line 342
    .line 343
    move-result v2

    .line 344
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 345
    .line 346
    .line 347
    move-result-object v3

    .line 348
    if-nez v2, :cond_13

    .line 349
    .line 350
    if-ne v3, v15, :cond_14

    .line 351
    .line 352
    :cond_13
    new-instance v6, Laf/b;

    .line 353
    .line 354
    const/4 v12, 0x0

    .line 355
    const/4 v13, 0x1

    .line 356
    const/4 v7, 0x1

    .line 357
    const-class v9, Lai/l;

    .line 358
    .line 359
    const-string v10, "onUiEvent"

    .line 360
    .line 361
    const-string v11, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/overview2/WallboxesOverviewUiEvent;)V"

    .line 362
    .line 363
    invoke-direct/range {v6 .. v13}, Laf/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 364
    .line 365
    .line 366
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 367
    .line 368
    .line 369
    move-object v3, v6

    .line 370
    :cond_14
    check-cast v3, Lhy0/g;

    .line 371
    .line 372
    check-cast v3, Lay0/k;

    .line 373
    .line 374
    const/16 v2, 0x8

    .line 375
    .line 376
    invoke-interface {v0, v1, v3, v5, v2}, Leh/n;->m(Llc/q;Lay0/k;Ll2/o;I)V

    .line 377
    .line 378
    .line 379
    goto :goto_14

    .line 380
    :cond_15
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 381
    .line 382
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 383
    .line 384
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 385
    .line 386
    .line 387
    throw v0

    .line 388
    :cond_16
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 389
    .line 390
    .line 391
    :goto_14
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 392
    .line 393
    .line 394
    move-result-object v0

    .line 395
    if-eqz v0, :cond_17

    .line 396
    .line 397
    new-instance v6, Lai/c;

    .line 398
    .line 399
    move-object/from16 v7, p0

    .line 400
    .line 401
    move-object/from16 v8, p1

    .line 402
    .line 403
    move-object/from16 v9, p2

    .line 404
    .line 405
    move-object/from16 v10, p3

    .line 406
    .line 407
    move-object/from16 v11, p4

    .line 408
    .line 409
    move-object/from16 v12, p5

    .line 410
    .line 411
    move-object/from16 v13, p6

    .line 412
    .line 413
    move/from16 v14, p8

    .line 414
    .line 415
    invoke-direct/range {v6 .. v14}, Lai/c;-><init>(Lx40/j;Lxh/e;Lzb/d;Lxh/e;Lxh/e;Lxh/e;Ljava/lang/String;I)V

    .line 416
    .line 417
    .line 418
    iput-object v6, v0, Ll2/u1;->d:Lay0/n;

    .line 419
    .line 420
    :cond_17
    return-void
.end method

.method public static final c(Ldh/u;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lai/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lai/f;

    .line 7
    .line 8
    iget v1, v0, Lai/f;->e:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lai/f;->e:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lai/f;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lai/f;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lai/f;->e:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    check-cast p2, Llx0/o;

    .line 40
    .line 41
    iget-object p0, p2, Llx0/o;->d:Ljava/lang/Object;

    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    iput v3, v0, Lai/f;->e:I

    .line 56
    .line 57
    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 58
    .line 59
    invoke-virtual {p0, p1, p2, v0}, Ldh/u;->h(Ljava/lang/String;Ljava/lang/Boolean;Lrx0/c;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    if-ne p0, v1, :cond_3

    .line 64
    .line 65
    return-object v1

    .line 66
    :cond_3
    return-object p0
.end method

.method public static final d(Ljava/time/DayOfWeek;)Ljava/lang/String;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ljava/time/format/TextStyle;->FULL:Ljava/time/format/TextStyle;

    .line 7
    .line 8
    invoke-static {}, Lh/n;->b()Ly5/c;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-virtual {v1, v2}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    if-nez v1, :cond_0

    .line 18
    .line 19
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    const-string v3, "getDefault(...)"

    .line 24
    .line 25
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    :cond_0
    invoke-virtual {p0, v0, v1}, Ljava/time/DayOfWeek;->getDisplayName(Ljava/time/format/TextStyle;Ljava/util/Locale;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    const-string v0, "getDisplayName(...)"

    .line 33
    .line 34
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-lez v0, :cond_1

    .line 42
    .line 43
    new-instance v0, Ljava/lang/StringBuilder;

    .line 44
    .line 45
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    invoke-static {v1}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    const-string v2, "null cannot be cast to non-null type java.lang.String"

    .line 57
    .line 58
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    sget-object v2, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 62
    .line 63
    invoke-virtual {v1, v2}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    const-string v2, "toUpperCase(...)"

    .line 68
    .line 69
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    const/4 v1, 0x1

    .line 76
    invoke-virtual {p0, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    const-string v1, "substring(...)"

    .line 81
    .line 82
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    :cond_1
    return-object p0
.end method

.method public static final e(Ljava/time/DayOfWeek;)Ljava/lang/String;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ljava/time/format/TextStyle;->SHORT:Ljava/time/format/TextStyle;

    .line 7
    .line 8
    invoke-static {}, Lh/n;->b()Ly5/c;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-virtual {v1, v2}, Ly5/c;->b(I)Ljava/util/Locale;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    if-nez v1, :cond_0

    .line 18
    .line 19
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    const-string v3, "getDefault(...)"

    .line 24
    .line 25
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    :cond_0
    invoke-virtual {p0, v0, v1}, Ljava/time/DayOfWeek;->getDisplayName(Ljava/time/format/TextStyle;Ljava/util/Locale;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    const-string v0, "getDisplayName(...)"

    .line 33
    .line 34
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-lez v0, :cond_1

    .line 42
    .line 43
    new-instance v0, Ljava/lang/StringBuilder;

    .line 44
    .line 45
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    invoke-static {v1}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    const-string v2, "null cannot be cast to non-null type java.lang.String"

    .line 57
    .line 58
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    sget-object v2, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 62
    .line 63
    invoke-virtual {v1, v2}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    const-string v2, "toUpperCase(...)"

    .line 68
    .line 69
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    const/4 v1, 0x1

    .line 76
    invoke-virtual {p0, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    const-string v1, "substring(...)"

    .line 81
    .line 82
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    :cond_1
    return-object p0
.end method
