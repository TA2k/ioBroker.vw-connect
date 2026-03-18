.class public abstract Lkp/y7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lff/f;Lle/a;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 11

    .line 1
    move/from16 v7, p5

    .line 2
    .line 3
    move-object v8, p4

    .line 4
    check-cast v8, Ll2/t;

    .line 5
    .line 6
    const v0, -0x299762fe

    .line 7
    .line 8
    .line 9
    invoke-virtual {v8, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 10
    .line 11
    .line 12
    and-int/lit8 v0, v7, 0x6

    .line 13
    .line 14
    const/4 v2, 0x4

    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    invoke-virtual {v8, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    move v0, v2

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v0, 0x2

    .line 26
    :goto_0
    or-int/2addr v0, v7

    .line 27
    goto :goto_1

    .line 28
    :cond_1
    move v0, v7

    .line 29
    :goto_1
    and-int/lit8 v3, v7, 0x30

    .line 30
    .line 31
    if-nez v3, :cond_3

    .line 32
    .line 33
    invoke-virtual {v8, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    if-eqz v3, :cond_2

    .line 38
    .line 39
    const/16 v3, 0x20

    .line 40
    .line 41
    goto :goto_2

    .line 42
    :cond_2
    const/16 v3, 0x10

    .line 43
    .line 44
    :goto_2
    or-int/2addr v0, v3

    .line 45
    :cond_3
    and-int/lit16 v3, v7, 0x180

    .line 46
    .line 47
    if-nez v3, :cond_5

    .line 48
    .line 49
    invoke-virtual {v8, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    if-eqz v3, :cond_4

    .line 54
    .line 55
    const/16 v3, 0x100

    .line 56
    .line 57
    goto :goto_3

    .line 58
    :cond_4
    const/16 v3, 0x80

    .line 59
    .line 60
    :goto_3
    or-int/2addr v0, v3

    .line 61
    :cond_5
    and-int/lit16 v3, v7, 0xc00

    .line 62
    .line 63
    const/16 v4, 0x800

    .line 64
    .line 65
    if-nez v3, :cond_7

    .line 66
    .line 67
    move-object v3, p3

    .line 68
    invoke-virtual {v8, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v5

    .line 72
    if-eqz v5, :cond_6

    .line 73
    .line 74
    move v5, v4

    .line 75
    goto :goto_4

    .line 76
    :cond_6
    const/16 v5, 0x400

    .line 77
    .line 78
    :goto_4
    or-int/2addr v0, v5

    .line 79
    goto :goto_5

    .line 80
    :cond_7
    move-object v3, p3

    .line 81
    :goto_5
    and-int/lit16 v5, v0, 0x493

    .line 82
    .line 83
    const/16 v6, 0x492

    .line 84
    .line 85
    const/4 v9, 0x0

    .line 86
    const/4 v10, 0x1

    .line 87
    if-eq v5, v6, :cond_8

    .line 88
    .line 89
    move v5, v10

    .line 90
    goto :goto_6

    .line 91
    :cond_8
    move v5, v9

    .line 92
    :goto_6
    and-int/lit8 v6, v0, 0x1

    .line 93
    .line 94
    invoke-virtual {v8, v6, v5}, Ll2/t;->O(IZ)Z

    .line 95
    .line 96
    .line 97
    move-result v5

    .line 98
    if-eqz v5, :cond_d

    .line 99
    .line 100
    invoke-static {p1, v8}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 101
    .line 102
    .line 103
    move-result-object v3

    .line 104
    invoke-static {p2, v8}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 105
    .line 106
    .line 107
    move-result-object v5

    .line 108
    and-int/lit8 v6, v0, 0xe

    .line 109
    .line 110
    if-ne v6, v2, :cond_9

    .line 111
    .line 112
    move v2, v10

    .line 113
    goto :goto_7

    .line 114
    :cond_9
    move v2, v9

    .line 115
    :goto_7
    invoke-virtual {v8, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v6

    .line 119
    or-int/2addr v2, v6

    .line 120
    and-int/lit16 v0, v0, 0x1c00

    .line 121
    .line 122
    if-ne v0, v4, :cond_a

    .line 123
    .line 124
    move v9, v10

    .line 125
    :cond_a
    or-int v0, v2, v9

    .line 126
    .line 127
    invoke-virtual {v8, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v2

    .line 131
    or-int/2addr v0, v2

    .line 132
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v2

    .line 136
    if-nez v0, :cond_b

    .line 137
    .line 138
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 139
    .line 140
    if-ne v2, v0, :cond_c

    .line 141
    .line 142
    :cond_b
    new-instance v0, Lff/a;

    .line 143
    .line 144
    move-object v4, v5

    .line 145
    const/4 v5, 0x0

    .line 146
    const/4 v6, 0x0

    .line 147
    move-object v1, p0

    .line 148
    move-object v2, p3

    .line 149
    invoke-direct/range {v0 .. v6}, Lff/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v8, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    move-object v2, v0

    .line 156
    :cond_c
    check-cast v2, Lay0/n;

    .line 157
    .line 158
    invoke-static {v2, p0, v8}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 159
    .line 160
    .line 161
    goto :goto_8

    .line 162
    :cond_d
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 163
    .line 164
    .line 165
    :goto_8
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 166
    .line 167
    .line 168
    move-result-object v8

    .line 169
    if-eqz v8, :cond_e

    .line 170
    .line 171
    new-instance v0, La71/e;

    .line 172
    .line 173
    const/16 v6, 0xc

    .line 174
    .line 175
    move-object v1, p0

    .line 176
    move-object v2, p1

    .line 177
    move-object v3, p2

    .line 178
    move-object v4, p3

    .line 179
    move v5, v7

    .line 180
    invoke-direct/range {v0 .. v6}, La71/e;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 181
    .line 182
    .line 183
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 184
    .line 185
    :cond_e
    return-void
.end method

.method public static final b(Lle/a;Lay0/a;Ll2/o;I)V
    .locals 23

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move/from16 v6, p3

    .line 6
    .line 7
    const-string v0, "noSeasonSelect"

    .line 8
    .line 9
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    move-object/from16 v12, p2

    .line 13
    .line 14
    check-cast v12, Ll2/t;

    .line 15
    .line 16
    const v0, 0x22ddb760

    .line 17
    .line 18
    .line 19
    invoke-virtual {v12, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v12, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    const/4 v0, 0x4

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 v0, 0x2

    .line 31
    :goto_0
    or-int/2addr v0, v6

    .line 32
    invoke-virtual {v12, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    if-eqz v3, :cond_1

    .line 37
    .line 38
    const/16 v3, 0x20

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    const/16 v3, 0x10

    .line 42
    .line 43
    :goto_1
    or-int/2addr v0, v3

    .line 44
    and-int/lit8 v3, v0, 0x13

    .line 45
    .line 46
    const/16 v4, 0x12

    .line 47
    .line 48
    const/4 v13, 0x0

    .line 49
    if-eq v3, v4, :cond_2

    .line 50
    .line 51
    const/4 v3, 0x1

    .line 52
    goto :goto_2

    .line 53
    :cond_2
    move v3, v13

    .line 54
    :goto_2
    and-int/lit8 v4, v0, 0x1

    .line 55
    .line 56
    invoke-virtual {v12, v4, v3}, Ll2/t;->O(IZ)Z

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    if-eqz v3, :cond_b

    .line 61
    .line 62
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    sget-object v14, Ll2/n;->a:Ll2/x0;

    .line 67
    .line 68
    if-ne v3, v14, :cond_3

    .line 69
    .line 70
    new-instance v3, Lf31/n;

    .line 71
    .line 72
    const/4 v4, 0x6

    .line 73
    invoke-direct {v3, v4}, Lf31/n;-><init>(I)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v12, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    :cond_3
    check-cast v3, Lay0/k;

    .line 80
    .line 81
    sget-object v4, Lw3/q1;->a:Ll2/u2;

    .line 82
    .line 83
    invoke-virtual {v12, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v4

    .line 87
    check-cast v4, Ljava/lang/Boolean;

    .line 88
    .line 89
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 90
    .line 91
    .line 92
    move-result v4

    .line 93
    if-eqz v4, :cond_4

    .line 94
    .line 95
    const v4, -0x105bcaaa

    .line 96
    .line 97
    .line 98
    invoke-virtual {v12, v4}, Ll2/t;->Y(I)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v12, v13}, Ll2/t;->q(Z)V

    .line 102
    .line 103
    .line 104
    const/4 v4, 0x0

    .line 105
    goto :goto_3

    .line 106
    :cond_4
    const v4, 0x31054eee

    .line 107
    .line 108
    .line 109
    invoke-virtual {v12, v4}, Ll2/t;->Y(I)V

    .line 110
    .line 111
    .line 112
    sget-object v4, Lzb/x;->a:Ll2/u2;

    .line 113
    .line 114
    invoke-virtual {v12, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v4

    .line 118
    check-cast v4, Lhi/a;

    .line 119
    .line 120
    invoke-virtual {v12, v13}, Ll2/t;->q(Z)V

    .line 121
    .line 122
    .line 123
    :goto_3
    new-instance v10, Laf/a;

    .line 124
    .line 125
    const/16 v5, 0xb

    .line 126
    .line 127
    invoke-direct {v10, v4, v3, v5}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 128
    .line 129
    .line 130
    invoke-static {v12}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 131
    .line 132
    .line 133
    move-result-object v8

    .line 134
    if-eqz v8, :cond_a

    .line 135
    .line 136
    instance-of v3, v8, Landroidx/lifecycle/k;

    .line 137
    .line 138
    if-eqz v3, :cond_5

    .line 139
    .line 140
    move-object v3, v8

    .line 141
    check-cast v3, Landroidx/lifecycle/k;

    .line 142
    .line 143
    invoke-interface {v3}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 144
    .line 145
    .line 146
    move-result-object v3

    .line 147
    :goto_4
    move-object v11, v3

    .line 148
    goto :goto_5

    .line 149
    :cond_5
    sget-object v3, Lp7/a;->b:Lp7/a;

    .line 150
    .line 151
    goto :goto_4

    .line 152
    :goto_5
    const-class v3, Lff/g;

    .line 153
    .line 154
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 155
    .line 156
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 157
    .line 158
    .line 159
    move-result-object v7

    .line 160
    const/4 v9, 0x0

    .line 161
    invoke-static/range {v7 .. v12}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 162
    .line 163
    .line 164
    move-result-object v3

    .line 165
    move-object v7, v3

    .line 166
    check-cast v7, Lff/g;

    .line 167
    .line 168
    iget-object v3, v7, Lff/g;->e:Lyy0/l1;

    .line 169
    .line 170
    invoke-static {v3, v12}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 171
    .line 172
    .line 173
    move-result-object v3

    .line 174
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v3

    .line 178
    check-cast v3, Lff/f;

    .line 179
    .line 180
    invoke-virtual {v12, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 181
    .line 182
    .line 183
    move-result v4

    .line 184
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v5

    .line 188
    if-nez v4, :cond_6

    .line 189
    .line 190
    if-ne v5, v14, :cond_7

    .line 191
    .line 192
    :cond_6
    new-instance v5, Ld2/g;

    .line 193
    .line 194
    const/16 v4, 0xd

    .line 195
    .line 196
    invoke-direct {v5, v7, v4}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 197
    .line 198
    .line 199
    invoke-virtual {v12, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 200
    .line 201
    .line 202
    :cond_7
    check-cast v5, Lay0/a;

    .line 203
    .line 204
    shl-int/lit8 v0, v0, 0x3

    .line 205
    .line 206
    and-int/lit16 v0, v0, 0x3f0

    .line 207
    .line 208
    move-object v4, v5

    .line 209
    move v5, v0

    .line 210
    move-object v0, v3

    .line 211
    move-object v3, v4

    .line 212
    move-object v4, v12

    .line 213
    invoke-static/range {v0 .. v5}, Lkp/y7;->a(Lff/f;Lle/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 214
    .line 215
    .line 216
    invoke-static {v12}, Llp/nf;->a(Ll2/o;)Lle/c;

    .line 217
    .line 218
    .line 219
    move-result-object v0

    .line 220
    invoke-virtual {v12, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 221
    .line 222
    .line 223
    move-result v3

    .line 224
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v4

    .line 228
    if-nez v3, :cond_8

    .line 229
    .line 230
    if-ne v4, v14, :cond_9

    .line 231
    .line 232
    :cond_8
    new-instance v15, Lei/a;

    .line 233
    .line 234
    const/16 v21, 0x0

    .line 235
    .line 236
    const/16 v22, 0xe

    .line 237
    .line 238
    const/16 v16, 0x1

    .line 239
    .line 240
    const-class v18, Lff/g;

    .line 241
    .line 242
    const-string v19, "onUiEvent"

    .line 243
    .line 244
    const-string v20, "onUiEvent(Lcariad/charging/multicharge/kitten/kola/presentation/wizard/multiplefixedrate/seasonselection/KolaWizardSeasonSelectionUiEvent;)V"

    .line 245
    .line 246
    move-object/from16 v17, v7

    .line 247
    .line 248
    invoke-direct/range {v15 .. v22}, Lei/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 249
    .line 250
    .line 251
    invoke-virtual {v12, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 252
    .line 253
    .line 254
    move-object v4, v15

    .line 255
    :cond_9
    check-cast v4, Lhy0/g;

    .line 256
    .line 257
    check-cast v4, Lay0/k;

    .line 258
    .line 259
    invoke-interface {v0, v4, v12, v13}, Lle/c;->O(Lay0/k;Ll2/o;I)V

    .line 260
    .line 261
    .line 262
    goto :goto_6

    .line 263
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 264
    .line 265
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 266
    .line 267
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 268
    .line 269
    .line 270
    throw v0

    .line 271
    :cond_b
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 272
    .line 273
    .line 274
    :goto_6
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 275
    .line 276
    .line 277
    move-result-object v0

    .line 278
    if-eqz v0, :cond_c

    .line 279
    .line 280
    new-instance v3, Ld90/m;

    .line 281
    .line 282
    const/16 v4, 0xe

    .line 283
    .line 284
    invoke-direct {v3, v6, v4, v1, v2}, Ld90/m;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 285
    .line 286
    .line 287
    iput-object v3, v0, Ll2/u1;->d:Lay0/n;

    .line 288
    .line 289
    :cond_c
    return-void
.end method

.method public static final c(Ljava/lang/String;Lxh/e;Ll2/o;I)V
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
    const v3, 0x54a5b3c4

    .line 12
    .line 13
    .line 14
    invoke-virtual {v8, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v8, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    const/4 v4, 0x4

    .line 22
    if-eqz v3, :cond_0

    .line 23
    .line 24
    move v3, v4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v3, 0x2

    .line 27
    :goto_0
    or-int/2addr v3, v2

    .line 28
    invoke-virtual {v8, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    const/16 v6, 0x20

    .line 33
    .line 34
    if-eqz v5, :cond_1

    .line 35
    .line 36
    move v5, v6

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/16 v5, 0x10

    .line 39
    .line 40
    :goto_1
    or-int/2addr v3, v5

    .line 41
    and-int/lit8 v5, v3, 0x13

    .line 42
    .line 43
    const/16 v7, 0x12

    .line 44
    .line 45
    const/4 v9, 0x0

    .line 46
    const/4 v10, 0x1

    .line 47
    if-eq v5, v7, :cond_2

    .line 48
    .line 49
    move v5, v10

    .line 50
    goto :goto_2

    .line 51
    :cond_2
    move v5, v9

    .line 52
    :goto_2
    and-int/lit8 v7, v3, 0x1

    .line 53
    .line 54
    invoke-virtual {v8, v7, v5}, Ll2/t;->O(IZ)Z

    .line 55
    .line 56
    .line 57
    move-result v5

    .line 58
    if-eqz v5, :cond_c

    .line 59
    .line 60
    and-int/lit8 v5, v3, 0x70

    .line 61
    .line 62
    if-ne v5, v6, :cond_3

    .line 63
    .line 64
    move v5, v10

    .line 65
    goto :goto_3

    .line 66
    :cond_3
    move v5, v9

    .line 67
    :goto_3
    and-int/lit8 v3, v3, 0xe

    .line 68
    .line 69
    if-ne v3, v4, :cond_4

    .line 70
    .line 71
    goto :goto_4

    .line 72
    :cond_4
    move v10, v9

    .line 73
    :goto_4
    or-int v3, v5, v10

    .line 74
    .line 75
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 80
    .line 81
    if-nez v3, :cond_5

    .line 82
    .line 83
    if-ne v4, v10, :cond_6

    .line 84
    .line 85
    :cond_5
    new-instance v4, Lsg/j;

    .line 86
    .line 87
    invoke-direct {v4, v1, v0}, Lsg/j;-><init>(Lxh/e;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v8, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    :cond_6
    check-cast v4, Lay0/k;

    .line 94
    .line 95
    sget-object v3, Lw3/q1;->a:Ll2/u2;

    .line 96
    .line 97
    invoke-virtual {v8, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v3

    .line 101
    check-cast v3, Ljava/lang/Boolean;

    .line 102
    .line 103
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 104
    .line 105
    .line 106
    move-result v3

    .line 107
    if-eqz v3, :cond_7

    .line 108
    .line 109
    const v3, -0x105bcaaa

    .line 110
    .line 111
    .line 112
    invoke-virtual {v8, v3}, Ll2/t;->Y(I)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v8, v9}, Ll2/t;->q(Z)V

    .line 116
    .line 117
    .line 118
    const/4 v3, 0x0

    .line 119
    goto :goto_5

    .line 120
    :cond_7
    const v3, 0x31054eee

    .line 121
    .line 122
    .line 123
    invoke-virtual {v8, v3}, Ll2/t;->Y(I)V

    .line 124
    .line 125
    .line 126
    sget-object v3, Lzb/x;->a:Ll2/u2;

    .line 127
    .line 128
    invoke-virtual {v8, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v3

    .line 132
    check-cast v3, Lhi/a;

    .line 133
    .line 134
    invoke-virtual {v8, v9}, Ll2/t;->q(Z)V

    .line 135
    .line 136
    .line 137
    :goto_5
    new-instance v6, Lnd/e;

    .line 138
    .line 139
    const/16 v5, 0x15

    .line 140
    .line 141
    invoke-direct {v6, v3, v4, v5}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 142
    .line 143
    .line 144
    invoke-static {v8}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 145
    .line 146
    .line 147
    move-result-object v4

    .line 148
    if-eqz v4, :cond_b

    .line 149
    .line 150
    instance-of v3, v4, Landroidx/lifecycle/k;

    .line 151
    .line 152
    if-eqz v3, :cond_8

    .line 153
    .line 154
    move-object v3, v4

    .line 155
    check-cast v3, Landroidx/lifecycle/k;

    .line 156
    .line 157
    invoke-interface {v3}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 158
    .line 159
    .line 160
    move-result-object v3

    .line 161
    :goto_6
    move-object v7, v3

    .line 162
    goto :goto_7

    .line 163
    :cond_8
    sget-object v3, Lp7/a;->b:Lp7/a;

    .line 164
    .line 165
    goto :goto_6

    .line 166
    :goto_7
    const-class v3, Lsg/p;

    .line 167
    .line 168
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 169
    .line 170
    invoke-virtual {v5, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 171
    .line 172
    .line 173
    move-result-object v3

    .line 174
    const/4 v5, 0x0

    .line 175
    invoke-static/range {v3 .. v8}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 176
    .line 177
    .line 178
    move-result-object v3

    .line 179
    move-object v13, v3

    .line 180
    check-cast v13, Lsg/p;

    .line 181
    .line 182
    invoke-static {v8}, Lmg/a;->c(Ll2/o;)Lmg/k;

    .line 183
    .line 184
    .line 185
    move-result-object v3

    .line 186
    iget-object v4, v13, Lsg/p;->h:Lyy0/c2;

    .line 187
    .line 188
    invoke-static {v4, v8}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 189
    .line 190
    .line 191
    move-result-object v4

    .line 192
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v4

    .line 196
    check-cast v4, Llc/q;

    .line 197
    .line 198
    invoke-virtual {v8, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 199
    .line 200
    .line 201
    move-result v5

    .line 202
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object v6

    .line 206
    if-nez v5, :cond_9

    .line 207
    .line 208
    if-ne v6, v10, :cond_a

    .line 209
    .line 210
    :cond_9
    new-instance v11, Ls60/h;

    .line 211
    .line 212
    const/16 v17, 0x0

    .line 213
    .line 214
    const/16 v18, 0x16

    .line 215
    .line 216
    const/4 v12, 0x1

    .line 217
    const-class v14, Lsg/p;

    .line 218
    .line 219
    const-string v15, "onUiEvent"

    .line 220
    .line 221
    const-string v16, "onUiEvent(Lcariad/charging/multicharge/kitten/subscription/presentation/tariff/selection/TariffSelectionUiEvent;)V"

    .line 222
    .line 223
    invoke-direct/range {v11 .. v18}, Ls60/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 224
    .line 225
    .line 226
    invoke-virtual {v8, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 227
    .line 228
    .line 229
    move-object v6, v11

    .line 230
    :cond_a
    check-cast v6, Lhy0/g;

    .line 231
    .line 232
    check-cast v6, Lay0/k;

    .line 233
    .line 234
    const/16 v5, 0x8

    .line 235
    .line 236
    invoke-interface {v3, v4, v6, v8, v5}, Lmg/k;->W(Llc/q;Lay0/k;Ll2/o;I)V

    .line 237
    .line 238
    .line 239
    goto :goto_8

    .line 240
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 241
    .line 242
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 243
    .line 244
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    throw v0

    .line 248
    :cond_c
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 249
    .line 250
    .line 251
    :goto_8
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 252
    .line 253
    .line 254
    move-result-object v3

    .line 255
    if-eqz v3, :cond_d

    .line 256
    .line 257
    new-instance v4, Lsg/k;

    .line 258
    .line 259
    const/4 v5, 0x1

    .line 260
    invoke-direct {v4, v0, v1, v2, v5}, Lsg/k;-><init>(Ljava/lang/String;Lxh/e;II)V

    .line 261
    .line 262
    .line 263
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 264
    .line 265
    :cond_d
    return-void
.end method
