.class public abstract Ljp/sb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(ILay0/a;Lay0/a;Ll2/o;Z)V
    .locals 11

    .line 1
    move v3, p4

    .line 2
    move-object v6, p3

    .line 3
    check-cast v6, Ll2/t;

    .line 4
    .line 5
    const v0, 0x721784bd

    .line 6
    .line 7
    .line 8
    invoke-virtual {v6, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v6, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/4 v2, 0x4

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    move v0, v2

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 v0, 0x2

    .line 21
    :goto_0
    or-int/2addr v0, p0

    .line 22
    invoke-virtual {v6, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    if-eqz v4, :cond_1

    .line 27
    .line 28
    const/16 v4, 0x20

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_1
    const/16 v4, 0x10

    .line 32
    .line 33
    :goto_1
    or-int/2addr v0, v4

    .line 34
    invoke-virtual {v6, p4}, Ll2/t;->h(Z)Z

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    const/16 v5, 0x100

    .line 39
    .line 40
    if-eqz v4, :cond_2

    .line 41
    .line 42
    move v4, v5

    .line 43
    goto :goto_2

    .line 44
    :cond_2
    const/16 v4, 0x80

    .line 45
    .line 46
    :goto_2
    or-int/2addr v0, v4

    .line 47
    and-int/lit16 v4, v0, 0x93

    .line 48
    .line 49
    const/16 v7, 0x92

    .line 50
    .line 51
    const/4 v8, 0x0

    .line 52
    const/4 v9, 0x1

    .line 53
    if-eq v4, v7, :cond_3

    .line 54
    .line 55
    move v4, v9

    .line 56
    goto :goto_3

    .line 57
    :cond_3
    move v4, v8

    .line 58
    :goto_3
    and-int/lit8 v7, v0, 0x1

    .line 59
    .line 60
    invoke-virtual {v6, v7, v4}, Ll2/t;->O(IZ)Z

    .line 61
    .line 62
    .line 63
    move-result v4

    .line 64
    if-eqz v4, :cond_8

    .line 65
    .line 66
    invoke-static {p2, v6}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 67
    .line 68
    .line 69
    move-result-object v4

    .line 70
    invoke-static {p4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 71
    .line 72
    .line 73
    move-result-object v7

    .line 74
    and-int/lit16 v10, v0, 0x380

    .line 75
    .line 76
    if-ne v10, v5, :cond_4

    .line 77
    .line 78
    move v5, v9

    .line 79
    goto :goto_4

    .line 80
    :cond_4
    move v5, v8

    .line 81
    :goto_4
    invoke-virtual {v6, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v10

    .line 85
    or-int/2addr v5, v10

    .line 86
    and-int/lit8 v0, v0, 0xe

    .line 87
    .line 88
    if-ne v0, v2, :cond_5

    .line 89
    .line 90
    move v8, v9

    .line 91
    :cond_5
    or-int v0, v5, v8

    .line 92
    .line 93
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    if-nez v0, :cond_6

    .line 98
    .line 99
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 100
    .line 101
    if-ne v2, v0, :cond_7

    .line 102
    .line 103
    :cond_6
    new-instance v0, Lbc/g;

    .line 104
    .line 105
    move-object v2, v4

    .line 106
    const/4 v4, 0x0

    .line 107
    const/4 v5, 0x3

    .line 108
    move-object v1, p1

    .line 109
    invoke-direct/range {v0 .. v5}, Lbc/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 110
    .line 111
    .line 112
    invoke-virtual {v6, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    move-object v2, v0

    .line 116
    :cond_7
    check-cast v2, Lay0/n;

    .line 117
    .line 118
    invoke-static {v2, v7, v6}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 119
    .line 120
    .line 121
    goto :goto_5

    .line 122
    :cond_8
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 123
    .line 124
    .line 125
    :goto_5
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    if-eqz v0, :cond_9

    .line 130
    .line 131
    new-instance v2, La71/p;

    .line 132
    .line 133
    invoke-direct {v2, p0, p1, p2, p4}, La71/p;-><init>(ILay0/a;Lay0/a;Z)V

    .line 134
    .line 135
    .line 136
    iput-object v2, v0, Ll2/u1;->d:Lay0/n;

    .line 137
    .line 138
    :cond_9
    return-void
.end method

.method public static final b(Lpe/b;Lay0/a;Ll2/o;I)V
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
    const-string v3, "rateType"

    .line 8
    .line 9
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v3, "goToOverviewSelect"

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
    const v3, 0x2f6c49e2

    .line 22
    .line 23
    .line 24
    invoke-virtual {v9, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    invoke-virtual {v9, v3}, Ll2/t;->e(I)Z

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    if-eqz v3, :cond_0

    .line 36
    .line 37
    const/4 v3, 0x4

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 v3, 0x2

    .line 40
    :goto_0
    or-int/2addr v3, v2

    .line 41
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v4

    .line 45
    if-eqz v4, :cond_1

    .line 46
    .line 47
    const/16 v4, 0x20

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    const/16 v4, 0x10

    .line 51
    .line 52
    :goto_1
    or-int/2addr v3, v4

    .line 53
    and-int/lit8 v4, v3, 0x13

    .line 54
    .line 55
    const/16 v5, 0x12

    .line 56
    .line 57
    const/4 v10, 0x1

    .line 58
    const/4 v11, 0x0

    .line 59
    if-eq v4, v5, :cond_2

    .line 60
    .line 61
    move v4, v10

    .line 62
    goto :goto_2

    .line 63
    :cond_2
    move v4, v11

    .line 64
    :goto_2
    and-int/lit8 v5, v3, 0x1

    .line 65
    .line 66
    invoke-virtual {v9, v5, v4}, Ll2/t;->O(IZ)Z

    .line 67
    .line 68
    .line 69
    move-result v4

    .line 70
    if-eqz v4, :cond_d

    .line 71
    .line 72
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v4

    .line 76
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 77
    .line 78
    if-ne v4, v12, :cond_3

    .line 79
    .line 80
    new-instance v4, Lod0/g;

    .line 81
    .line 82
    const/16 v5, 0xb

    .line 83
    .line 84
    invoke-direct {v4, v5}, Lod0/g;-><init>(I)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v9, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    :cond_3
    check-cast v4, Lay0/k;

    .line 91
    .line 92
    sget-object v5, Lw3/q1;->a:Ll2/u2;

    .line 93
    .line 94
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v5

    .line 98
    check-cast v5, Ljava/lang/Boolean;

    .line 99
    .line 100
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 101
    .line 102
    .line 103
    move-result v5

    .line 104
    if-eqz v5, :cond_4

    .line 105
    .line 106
    const v5, -0x105bcaaa

    .line 107
    .line 108
    .line 109
    invoke-virtual {v9, v5}, Ll2/t;->Y(I)V

    .line 110
    .line 111
    .line 112
    invoke-virtual {v9, v11}, Ll2/t;->q(Z)V

    .line 113
    .line 114
    .line 115
    const/4 v5, 0x0

    .line 116
    goto :goto_3

    .line 117
    :cond_4
    const v5, 0x31054eee

    .line 118
    .line 119
    .line 120
    invoke-virtual {v9, v5}, Ll2/t;->Y(I)V

    .line 121
    .line 122
    .line 123
    sget-object v5, Lzb/x;->a:Ll2/u2;

    .line 124
    .line 125
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v5

    .line 129
    check-cast v5, Lhi/a;

    .line 130
    .line 131
    invoke-virtual {v9, v11}, Ll2/t;->q(Z)V

    .line 132
    .line 133
    .line 134
    :goto_3
    new-instance v7, Lnd/e;

    .line 135
    .line 136
    const/4 v6, 0x4

    .line 137
    invoke-direct {v7, v5, v4, v6}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 138
    .line 139
    .line 140
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 141
    .line 142
    .line 143
    move-result-object v5

    .line 144
    if-eqz v5, :cond_c

    .line 145
    .line 146
    instance-of v4, v5, Landroidx/lifecycle/k;

    .line 147
    .line 148
    if-eqz v4, :cond_5

    .line 149
    .line 150
    move-object v4, v5

    .line 151
    check-cast v4, Landroidx/lifecycle/k;

    .line 152
    .line 153
    invoke-interface {v4}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 154
    .line 155
    .line 156
    move-result-object v4

    .line 157
    :goto_4
    move-object v8, v4

    .line 158
    goto :goto_5

    .line 159
    :cond_5
    sget-object v4, Lp7/a;->b:Lp7/a;

    .line 160
    .line 161
    goto :goto_4

    .line 162
    :goto_5
    const-class v4, Loe/h;

    .line 163
    .line 164
    sget-object v6, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 165
    .line 166
    invoke-virtual {v6, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 167
    .line 168
    .line 169
    move-result-object v4

    .line 170
    const/4 v6, 0x0

    .line 171
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 172
    .line 173
    .line 174
    move-result-object v4

    .line 175
    move-object v15, v4

    .line 176
    check-cast v15, Loe/h;

    .line 177
    .line 178
    iget-object v4, v15, Loe/h;->e:Lyy0/l1;

    .line 179
    .line 180
    invoke-static {v4, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 181
    .line 182
    .line 183
    move-result-object v4

    .line 184
    invoke-virtual {v9, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 185
    .line 186
    .line 187
    move-result v5

    .line 188
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v6

    .line 192
    if-nez v5, :cond_6

    .line 193
    .line 194
    if-ne v6, v12, :cond_7

    .line 195
    .line 196
    :cond_6
    new-instance v6, Loe/a;

    .line 197
    .line 198
    const/4 v5, 0x0

    .line 199
    invoke-direct {v6, v15, v5}, Loe/a;-><init>(Loe/h;I)V

    .line 200
    .line 201
    .line 202
    invoke-virtual {v9, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 203
    .line 204
    .line 205
    :cond_7
    check-cast v6, Lay0/a;

    .line 206
    .line 207
    invoke-static {v11, v6, v9, v11, v10}, Ljp/tb;->a(ZLay0/a;Ll2/o;II)V

    .line 208
    .line 209
    .line 210
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v4

    .line 214
    check-cast v4, Loe/f;

    .line 215
    .line 216
    iget-boolean v4, v4, Loe/f;->a:Z

    .line 217
    .line 218
    invoke-virtual {v9, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 219
    .line 220
    .line 221
    move-result v5

    .line 222
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object v6

    .line 226
    if-nez v5, :cond_8

    .line 227
    .line 228
    if-ne v6, v12, :cond_9

    .line 229
    .line 230
    :cond_8
    new-instance v6, Loe/a;

    .line 231
    .line 232
    const/4 v5, 0x1

    .line 233
    invoke-direct {v6, v15, v5}, Loe/a;-><init>(Loe/h;I)V

    .line 234
    .line 235
    .line 236
    invoke-virtual {v9, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    :cond_9
    check-cast v6, Lay0/a;

    .line 240
    .line 241
    and-int/lit8 v5, v3, 0x70

    .line 242
    .line 243
    invoke-static {v5, v6, v1, v9, v4}, Ljp/sb;->a(ILay0/a;Lay0/a;Ll2/o;Z)V

    .line 244
    .line 245
    .line 246
    invoke-static {v9}, Llp/nf;->a(Ll2/o;)Lle/c;

    .line 247
    .line 248
    .line 249
    move-result-object v4

    .line 250
    invoke-virtual {v9, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 251
    .line 252
    .line 253
    move-result v5

    .line 254
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v6

    .line 258
    if-nez v5, :cond_a

    .line 259
    .line 260
    if-ne v6, v12, :cond_b

    .line 261
    .line 262
    :cond_a
    new-instance v13, Lo90/f;

    .line 263
    .line 264
    const/16 v19, 0x0

    .line 265
    .line 266
    const/16 v20, 0x3

    .line 267
    .line 268
    const/4 v14, 0x1

    .line 269
    const-class v16, Loe/h;

    .line 270
    .line 271
    const-string v17, "onUiEvent"

    .line 272
    .line 273
    const-string v18, "onUiEvent(Lcariad/charging/multicharge/kitten/kola/presentation/success/KolaWizardSuccessUiEvent;)V"

    .line 274
    .line 275
    invoke-direct/range {v13 .. v20}, Lo90/f;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 276
    .line 277
    .line 278
    invoke-virtual {v9, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 279
    .line 280
    .line 281
    move-object v6, v13

    .line 282
    :cond_b
    check-cast v6, Lhy0/g;

    .line 283
    .line 284
    check-cast v6, Lay0/k;

    .line 285
    .line 286
    and-int/lit8 v3, v3, 0xe

    .line 287
    .line 288
    invoke-interface {v4, v0, v6, v9, v3}, Lle/c;->d0(Lpe/b;Lay0/k;Ll2/o;I)V

    .line 289
    .line 290
    .line 291
    goto :goto_6

    .line 292
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 293
    .line 294
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 295
    .line 296
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 297
    .line 298
    .line 299
    throw v0

    .line 300
    :cond_d
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 301
    .line 302
    .line 303
    :goto_6
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 304
    .line 305
    .line 306
    move-result-object v3

    .line 307
    if-eqz v3, :cond_e

    .line 308
    .line 309
    new-instance v4, Lo50/b;

    .line 310
    .line 311
    const/4 v5, 0x3

    .line 312
    invoke-direct {v4, v0, v1, v2, v5}, Lo50/b;-><init>(Ljava/lang/Object;Lay0/a;II)V

    .line 313
    .line 314
    .line 315
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 316
    .line 317
    :cond_e
    return-void
.end method

.method public static final c(Lf/a;Lay0/k;Ll2/o;)Lc/k;
    .locals 12

    .line 1
    invoke-static {p0, p2}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 2
    .line 3
    .line 4
    invoke-static {p1, p2}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 5
    .line 6
    .line 7
    move-result-object v5

    .line 8
    const/4 p1, 0x0

    .line 9
    new-array v6, p1, [Ljava/lang/Object;

    .line 10
    .line 11
    move-object v9, p2

    .line 12
    check-cast v9, Ll2/t;

    .line 13
    .line 14
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 19
    .line 20
    if-ne p1, p2, :cond_0

    .line 21
    .line 22
    new-instance p1, Lay/b;

    .line 23
    .line 24
    const/16 v0, 0x14

    .line 25
    .line 26
    invoke-direct {p1, v0}, Lay/b;-><init>(I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v9, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    :cond_0
    move-object v8, p1

    .line 33
    check-cast v8, Lay0/a;

    .line 34
    .line 35
    const/16 v10, 0xc00

    .line 36
    .line 37
    const/4 v11, 0x6

    .line 38
    const/4 v7, 0x0

    .line 39
    invoke-static/range {v6 .. v11}, Lu2/m;->e([Ljava/lang/Object;Lu2/k;Lay0/a;Ll2/o;II)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    move-object v3, p1

    .line 44
    check-cast v3, Ljava/lang/String;

    .line 45
    .line 46
    invoke-static {v9}, Lc/i;->a(Ll2/o;)Le/i;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    if-eqz p1, :cond_7

    .line 51
    .line 52
    invoke-interface {p1}, Le/i;->getActivityResultRegistry()Le/h;

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    if-ne p1, p2, :cond_1

    .line 61
    .line 62
    new-instance p1, Lc/a;

    .line 63
    .line 64
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 65
    .line 66
    .line 67
    invoke-virtual {v9, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    :cond_1
    move-object v1, p1

    .line 71
    check-cast v1, Lc/a;

    .line 72
    .line 73
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    if-ne p1, p2, :cond_2

    .line 78
    .line 79
    new-instance p1, Lc/k;

    .line 80
    .line 81
    invoke-direct {p1, v1}, Lc/k;-><init>(Lc/a;)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v9, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    :cond_2
    check-cast p1, Lc/k;

    .line 88
    .line 89
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    invoke-virtual {v9, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v4

    .line 97
    or-int/2addr v0, v4

    .line 98
    invoke-virtual {v9, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v4

    .line 102
    or-int/2addr v0, v4

    .line 103
    invoke-virtual {v9, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result v4

    .line 107
    or-int/2addr v0, v4

    .line 108
    invoke-virtual {v9, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v4

    .line 112
    or-int/2addr v0, v4

    .line 113
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v4

    .line 117
    if-nez v0, :cond_4

    .line 118
    .line 119
    if-ne v4, p2, :cond_3

    .line 120
    .line 121
    goto :goto_0

    .line 122
    :cond_3
    move-object v0, v4

    .line 123
    move-object v4, p0

    .line 124
    goto :goto_1

    .line 125
    :cond_4
    :goto_0
    new-instance v0, Lc/b;

    .line 126
    .line 127
    const/4 v6, 0x0

    .line 128
    move-object v4, p0

    .line 129
    invoke-direct/range {v0 .. v6}, Lc/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v9, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    :goto_1
    check-cast v0, Lay0/k;

    .line 136
    .line 137
    invoke-virtual {v9, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    move-result p0

    .line 141
    invoke-virtual {v9, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    move-result v1

    .line 145
    or-int/2addr p0, v1

    .line 146
    invoke-virtual {v9, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 147
    .line 148
    .line 149
    move-result v1

    .line 150
    or-int/2addr p0, v1

    .line 151
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v1

    .line 155
    if-nez p0, :cond_5

    .line 156
    .line 157
    if-ne v1, p2, :cond_6

    .line 158
    .line 159
    :cond_5
    new-instance v1, Ll2/i0;

    .line 160
    .line 161
    invoke-direct {v1, v0}, Ll2/i0;-><init>(Lay0/k;)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {v9, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    :cond_6
    check-cast v1, Ll2/i0;

    .line 168
    .line 169
    return-object p1

    .line 170
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 171
    .line 172
    const-string p1, "No ActivityResultRegistryOwner was provided via LocalActivityResultRegistryOwner"

    .line 173
    .line 174
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    throw p0
.end method
