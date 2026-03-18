.class public abstract Ljp/g1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lxh/e;Lxh/e;Lxh/e;Lxh/e;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v5, p4

    .line 2
    .line 3
    check-cast v5, Ll2/t;

    .line 4
    .line 5
    const v0, -0x59ac228b

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
    or-int v0, p5, v0

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
    const/16 v6, 0x800

    .line 62
    .line 63
    if-eqz v2, :cond_3

    .line 64
    .line 65
    move v2, v6

    .line 66
    goto :goto_3

    .line 67
    :cond_3
    const/16 v2, 0x400

    .line 68
    .line 69
    :goto_3
    or-int/2addr v0, v2

    .line 70
    and-int/lit16 v2, v0, 0x493

    .line 71
    .line 72
    const/16 v11, 0x492

    .line 73
    .line 74
    const/4 v12, 0x1

    .line 75
    const/4 v13, 0x0

    .line 76
    if-eq v2, v11, :cond_4

    .line 77
    .line 78
    move v2, v12

    .line 79
    goto :goto_4

    .line 80
    :cond_4
    move v2, v13

    .line 81
    :goto_4
    and-int/lit8 v11, v0, 0x1

    .line 82
    .line 83
    invoke-virtual {v5, v11, v2}, Ll2/t;->O(IZ)Z

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    if-eqz v2, :cond_10

    .line 88
    .line 89
    and-int/lit8 v2, v0, 0xe

    .line 90
    .line 91
    if-ne v2, v1, :cond_5

    .line 92
    .line 93
    move v1, v12

    .line 94
    goto :goto_5

    .line 95
    :cond_5
    move v1, v13

    .line 96
    :goto_5
    and-int/lit8 v2, v0, 0x70

    .line 97
    .line 98
    if-ne v2, v3, :cond_6

    .line 99
    .line 100
    move v2, v12

    .line 101
    goto :goto_6

    .line 102
    :cond_6
    move v2, v13

    .line 103
    :goto_6
    or-int/2addr v1, v2

    .line 104
    and-int/lit16 v2, v0, 0x380

    .line 105
    .line 106
    if-ne v2, v4, :cond_7

    .line 107
    .line 108
    move v2, v12

    .line 109
    goto :goto_7

    .line 110
    :cond_7
    move v2, v13

    .line 111
    :goto_7
    or-int/2addr v1, v2

    .line 112
    and-int/lit16 v0, v0, 0x1c00

    .line 113
    .line 114
    if-ne v0, v6, :cond_8

    .line 115
    .line 116
    goto :goto_8

    .line 117
    :cond_8
    move v12, v13

    .line 118
    :goto_8
    or-int v0, v1, v12

    .line 119
    .line 120
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v1

    .line 124
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 125
    .line 126
    if-nez v0, :cond_9

    .line 127
    .line 128
    if-ne v1, v12, :cond_a

    .line 129
    .line 130
    :cond_9
    new-instance v6, Lbg/a;

    .line 131
    .line 132
    const/16 v11, 0x1b

    .line 133
    .line 134
    invoke-direct/range {v6 .. v11}, Lbg/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 135
    .line 136
    .line 137
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    move-object v1, v6

    .line 141
    :cond_a
    check-cast v1, Lay0/k;

    .line 142
    .line 143
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 144
    .line 145
    invoke-virtual {v5, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v0

    .line 149
    check-cast v0, Ljava/lang/Boolean;

    .line 150
    .line 151
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 152
    .line 153
    .line 154
    move-result v0

    .line 155
    if-eqz v0, :cond_b

    .line 156
    .line 157
    const v0, -0x105bcaaa

    .line 158
    .line 159
    .line 160
    invoke-virtual {v5, v0}, Ll2/t;->Y(I)V

    .line 161
    .line 162
    .line 163
    invoke-virtual {v5, v13}, Ll2/t;->q(Z)V

    .line 164
    .line 165
    .line 166
    const/4 v0, 0x0

    .line 167
    goto :goto_9

    .line 168
    :cond_b
    const v0, 0x31054eee

    .line 169
    .line 170
    .line 171
    invoke-virtual {v5, v0}, Ll2/t;->Y(I)V

    .line 172
    .line 173
    .line 174
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 175
    .line 176
    invoke-virtual {v5, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v0

    .line 180
    check-cast v0, Lhi/a;

    .line 181
    .line 182
    invoke-virtual {v5, v13}, Ll2/t;->q(Z)V

    .line 183
    .line 184
    .line 185
    :goto_9
    new-instance v3, Lvh/i;

    .line 186
    .line 187
    const/16 v2, 0xc

    .line 188
    .line 189
    invoke-direct {v3, v2, v0, v1}, Lvh/i;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    invoke-static {v5}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 193
    .line 194
    .line 195
    move-result-object v1

    .line 196
    if-eqz v1, :cond_f

    .line 197
    .line 198
    instance-of v0, v1, Landroidx/lifecycle/k;

    .line 199
    .line 200
    if-eqz v0, :cond_c

    .line 201
    .line 202
    move-object v0, v1

    .line 203
    check-cast v0, Landroidx/lifecycle/k;

    .line 204
    .line 205
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 206
    .line 207
    .line 208
    move-result-object v0

    .line 209
    :goto_a
    move-object v4, v0

    .line 210
    goto :goto_b

    .line 211
    :cond_c
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 212
    .line 213
    goto :goto_a

    .line 214
    :goto_b
    const-class v0, Lzh/m;

    .line 215
    .line 216
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 217
    .line 218
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 219
    .line 220
    .line 221
    move-result-object v0

    .line 222
    const/4 v2, 0x0

    .line 223
    invoke-static/range {v0 .. v5}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 224
    .line 225
    .line 226
    move-result-object v0

    .line 227
    move-object v15, v0

    .line 228
    check-cast v15, Lzh/m;

    .line 229
    .line 230
    invoke-static {v5}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 231
    .line 232
    .line 233
    move-result-object v0

    .line 234
    iget-object v1, v15, Lzh/m;->o:Lyy0/c2;

    .line 235
    .line 236
    invoke-static {v1, v5}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 237
    .line 238
    .line 239
    move-result-object v1

    .line 240
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object v1

    .line 244
    check-cast v1, Llc/q;

    .line 245
    .line 246
    invoke-virtual {v5, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 247
    .line 248
    .line 249
    move-result v2

    .line 250
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v3

    .line 254
    if-nez v2, :cond_d

    .line 255
    .line 256
    if-ne v3, v12, :cond_e

    .line 257
    .line 258
    :cond_d
    new-instance v13, Lz70/u;

    .line 259
    .line 260
    const/16 v19, 0x0

    .line 261
    .line 262
    const/16 v20, 0xa

    .line 263
    .line 264
    const/4 v14, 0x1

    .line 265
    const-class v16, Lzh/m;

    .line 266
    .line 267
    const-string v17, "onUiEvent"

    .line 268
    .line 269
    const-string v18, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/overview/WallboxesOverviewUiEvent;)V"

    .line 270
    .line 271
    invoke-direct/range {v13 .. v20}, Lz70/u;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 272
    .line 273
    .line 274
    invoke-virtual {v5, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 275
    .line 276
    .line 277
    move-object v3, v13

    .line 278
    :cond_e
    check-cast v3, Lhy0/g;

    .line 279
    .line 280
    check-cast v3, Lay0/k;

    .line 281
    .line 282
    const/16 v2, 0x8

    .line 283
    .line 284
    invoke-interface {v0, v1, v3, v5, v2}, Leh/n;->T(Llc/q;Lay0/k;Ll2/o;I)V

    .line 285
    .line 286
    .line 287
    goto :goto_c

    .line 288
    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 289
    .line 290
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 291
    .line 292
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 293
    .line 294
    .line 295
    throw v0

    .line 296
    :cond_10
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 297
    .line 298
    .line 299
    :goto_c
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 300
    .line 301
    .line 302
    move-result-object v0

    .line 303
    if-eqz v0, :cond_11

    .line 304
    .line 305
    new-instance v6, Lx40/c;

    .line 306
    .line 307
    const/16 v12, 0xf

    .line 308
    .line 309
    move-object/from16 v7, p0

    .line 310
    .line 311
    move-object/from16 v8, p1

    .line 312
    .line 313
    move-object/from16 v9, p2

    .line 314
    .line 315
    move-object/from16 v10, p3

    .line 316
    .line 317
    move/from16 v11, p5

    .line 318
    .line 319
    invoke-direct/range {v6 .. v12}, Lx40/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 320
    .line 321
    .line 322
    iput-object v6, v0, Ll2/u1;->d:Lay0/n;

    .line 323
    .line 324
    :cond_11
    return-void
.end method

.method public static final b(Lv3/j0;Le3/n0;JLmn/a;FLe3/g0;Lt4/m;Ld3/e;)Le3/g0;
    .locals 13

    .line 1
    move-object/from16 v11, p4

    .line 2
    .line 3
    move-object/from16 v1, p8

    .line 4
    .line 5
    sget-object v2, Le3/j0;->a:Le3/i0;

    .line 6
    .line 7
    const/4 v12, 0x0

    .line 8
    if-ne p1, v2, :cond_1

    .line 9
    .line 10
    const/4 v9, 0x0

    .line 11
    const/16 v10, 0x7e

    .line 12
    .line 13
    const-wide/16 v3, 0x0

    .line 14
    .line 15
    const-wide/16 v5, 0x0

    .line 16
    .line 17
    const/4 v7, 0x0

    .line 18
    const/4 v8, 0x0

    .line 19
    move-object v0, p0

    .line 20
    move-wide v1, p2

    .line 21
    invoke-static/range {v0 .. v10}, Lg3/d;->r0(Lg3/d;JJJFLg3/h;Le3/m;I)V

    .line 22
    .line 23
    .line 24
    if-eqz v11, :cond_0

    .line 25
    .line 26
    invoke-virtual {p0}, Lv3/j0;->e()J

    .line 27
    .line 28
    .line 29
    iget-object v1, v11, Lmn/a;->c:Le3/p0;

    .line 30
    .line 31
    const/4 v8, 0x0

    .line 32
    const/16 v9, 0x76

    .line 33
    .line 34
    const-wide/16 v2, 0x0

    .line 35
    .line 36
    const-wide/16 v4, 0x0

    .line 37
    .line 38
    const/4 v7, 0x0

    .line 39
    move-object v0, p0

    .line 40
    move/from16 v6, p5

    .line 41
    .line 42
    invoke-static/range {v0 .. v9}, Lg3/d;->i0(Lg3/d;Le3/p;JJFLg3/e;II)V

    .line 43
    .line 44
    .line 45
    :cond_0
    return-object v12

    .line 46
    :cond_1
    iget-object v3, p0, Lv3/j0;->d:Lg3/b;

    .line 47
    .line 48
    invoke-interface {v3}, Lg3/d;->e()J

    .line 49
    .line 50
    .line 51
    move-result-wide v3

    .line 52
    if-nez v1, :cond_2

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_2
    iget-wide v5, v1, Ld3/e;->a:J

    .line 56
    .line 57
    cmp-long v1, v3, v5

    .line 58
    .line 59
    if-eqz v1, :cond_3

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_3
    invoke-virtual {p0}, Lv3/j0;->getLayoutDirection()Lt4/m;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    move-object/from16 v3, p7

    .line 67
    .line 68
    if-ne v1, v3, :cond_4

    .line 69
    .line 70
    move-object/from16 v12, p6

    .line 71
    .line 72
    :cond_4
    :goto_0
    if-nez v12, :cond_5

    .line 73
    .line 74
    iget-object v1, p0, Lv3/j0;->d:Lg3/b;

    .line 75
    .line 76
    invoke-interface {v1}, Lg3/d;->e()J

    .line 77
    .line 78
    .line 79
    move-result-wide v3

    .line 80
    invoke-virtual {p0}, Lv3/j0;->getLayoutDirection()Lt4/m;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    invoke-interface {p1, v3, v4, v1, p0}, Le3/n0;->a(JLt4/m;Lt4/c;)Le3/g0;

    .line 85
    .line 86
    .line 87
    move-result-object v12

    .line 88
    :cond_5
    move-wide v0, p2

    .line 89
    invoke-static {p0, v12, v0, v1}, Le3/j0;->o(Lg3/d;Le3/g0;J)V

    .line 90
    .line 91
    .line 92
    if-eqz v11, :cond_6

    .line 93
    .line 94
    invoke-virtual {p0}, Lv3/j0;->e()J

    .line 95
    .line 96
    .line 97
    iget-object v0, v11, Lmn/a;->c:Le3/p0;

    .line 98
    .line 99
    move/from16 v6, p5

    .line 100
    .line 101
    invoke-static {p0, v12, v0, v6}, Le3/j0;->n(Lg3/d;Le3/g0;Le3/p;F)V

    .line 102
    .line 103
    .line 104
    :cond_6
    return-object v12
.end method

.method public static c(Landroid/content/Context;I)I
    .locals 1

    .line 1
    const v0, 0x1030001

    .line 2
    .line 3
    .line 4
    filled-new-array {p1}, [I

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    invoke-virtual {p0, v0, p1}, Landroid/content/Context;->obtainStyledAttributes(I[I)Landroid/content/res/TypedArray;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const/4 p1, 0x0

    .line 13
    const/4 v0, -0x1

    .line 14
    invoke-virtual {p0, p1, v0}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    invoke-virtual {p0}, Landroid/content/res/TypedArray;->recycle()V

    .line 19
    .line 20
    .line 21
    return p1
.end method
