.class public abstract Lsr/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lyj/b;Lyj/b;Ly1/i;Ll2/o;I)V
    .locals 22

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
    move-object/from16 v11, p3

    .line 8
    .line 9
    check-cast v11, Ll2/t;

    .line 10
    .line 11
    const v0, -0x6db01547    # -6.5607E-28f

    .line 12
    .line 13
    .line 14
    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v11, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    const/4 v1, 0x4

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    move v0, v1

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v0, 0x2

    .line 27
    :goto_0
    or-int v0, p4, v0

    .line 28
    .line 29
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    const/16 v6, 0x20

    .line 34
    .line 35
    if-eqz v2, :cond_1

    .line 36
    .line 37
    move v2, v6

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/16 v2, 0x10

    .line 40
    .line 41
    :goto_1
    or-int/2addr v0, v2

    .line 42
    invoke-virtual {v11, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    const/16 v7, 0x100

    .line 47
    .line 48
    if-eqz v2, :cond_2

    .line 49
    .line 50
    move v2, v7

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
    and-int/lit16 v2, v0, 0x93

    .line 56
    .line 57
    const/16 v8, 0x92

    .line 58
    .line 59
    const/4 v12, 0x1

    .line 60
    const/4 v13, 0x0

    .line 61
    if-eq v2, v8, :cond_3

    .line 62
    .line 63
    move v2, v12

    .line 64
    goto :goto_3

    .line 65
    :cond_3
    move v2, v13

    .line 66
    :goto_3
    and-int/lit8 v8, v0, 0x1

    .line 67
    .line 68
    invoke-virtual {v11, v8, v2}, Ll2/t;->O(IZ)Z

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    if-eqz v2, :cond_10

    .line 73
    .line 74
    and-int/lit8 v2, v0, 0xe

    .line 75
    .line 76
    if-ne v2, v1, :cond_4

    .line 77
    .line 78
    move v1, v12

    .line 79
    goto :goto_4

    .line 80
    :cond_4
    move v1, v13

    .line 81
    :goto_4
    and-int/lit8 v2, v0, 0x70

    .line 82
    .line 83
    if-ne v2, v6, :cond_5

    .line 84
    .line 85
    move v2, v12

    .line 86
    goto :goto_5

    .line 87
    :cond_5
    move v2, v13

    .line 88
    :goto_5
    or-int/2addr v1, v2

    .line 89
    and-int/lit16 v0, v0, 0x380

    .line 90
    .line 91
    if-ne v0, v7, :cond_6

    .line 92
    .line 93
    move v0, v12

    .line 94
    goto :goto_6

    .line 95
    :cond_6
    move v0, v13

    .line 96
    :goto_6
    or-int/2addr v0, v1

    .line 97
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 102
    .line 103
    if-nez v0, :cond_7

    .line 104
    .line 105
    if-ne v1, v2, :cond_8

    .line 106
    .line 107
    :cond_7
    new-instance v1, Lxc/b;

    .line 108
    .line 109
    const/4 v0, 0x4

    .line 110
    invoke-direct {v1, v3, v4, v5, v0}, Lxc/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v11, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    :cond_8
    check-cast v1, Lay0/k;

    .line 117
    .line 118
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 119
    .line 120
    invoke-virtual {v11, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    check-cast v0, Ljava/lang/Boolean;

    .line 125
    .line 126
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 127
    .line 128
    .line 129
    move-result v0

    .line 130
    if-eqz v0, :cond_9

    .line 131
    .line 132
    const v0, -0x105bcaaa

    .line 133
    .line 134
    .line 135
    invoke-virtual {v11, v0}, Ll2/t;->Y(I)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v11, v13}, Ll2/t;->q(Z)V

    .line 139
    .line 140
    .line 141
    const/4 v0, 0x0

    .line 142
    goto :goto_7

    .line 143
    :cond_9
    const v0, 0x31054eee

    .line 144
    .line 145
    .line 146
    invoke-virtual {v11, v0}, Ll2/t;->Y(I)V

    .line 147
    .line 148
    .line 149
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 150
    .line 151
    invoke-virtual {v11, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v0

    .line 155
    check-cast v0, Lhi/a;

    .line 156
    .line 157
    invoke-virtual {v11, v13}, Ll2/t;->q(Z)V

    .line 158
    .line 159
    .line 160
    :goto_7
    new-instance v9, Lvh/i;

    .line 161
    .line 162
    const/4 v6, 0x6

    .line 163
    invoke-direct {v9, v6, v0, v1}, Lvh/i;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    invoke-static {v11}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 167
    .line 168
    .line 169
    move-result-object v7

    .line 170
    if-eqz v7, :cond_f

    .line 171
    .line 172
    instance-of v0, v7, Landroidx/lifecycle/k;

    .line 173
    .line 174
    if-eqz v0, :cond_a

    .line 175
    .line 176
    move-object v0, v7

    .line 177
    check-cast v0, Landroidx/lifecycle/k;

    .line 178
    .line 179
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 180
    .line 181
    .line 182
    move-result-object v0

    .line 183
    :goto_8
    move-object v10, v0

    .line 184
    goto :goto_9

    .line 185
    :cond_a
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 186
    .line 187
    goto :goto_8

    .line 188
    :goto_9
    const-class v0, Lyd/u;

    .line 189
    .line 190
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 191
    .line 192
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 193
    .line 194
    .line 195
    move-result-object v6

    .line 196
    const/4 v8, 0x0

    .line 197
    invoke-static/range {v6 .. v11}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 198
    .line 199
    .line 200
    move-result-object v0

    .line 201
    check-cast v0, Lyd/u;

    .line 202
    .line 203
    invoke-virtual {v11, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 204
    .line 205
    .line 206
    move-result v1

    .line 207
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v6

    .line 211
    if-nez v1, :cond_b

    .line 212
    .line 213
    if-ne v6, v2, :cond_c

    .line 214
    .line 215
    :cond_b
    new-instance v6, Ly1/i;

    .line 216
    .line 217
    const/4 v1, 0x6

    .line 218
    invoke-direct {v6, v0, v1}, Ly1/i;-><init>(Ljava/lang/Object;I)V

    .line 219
    .line 220
    .line 221
    invoke-virtual {v11, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    :cond_c
    check-cast v6, Lay0/a;

    .line 225
    .line 226
    invoke-static {v13, v6, v11, v13, v12}, Ljp/tb;->a(ZLay0/a;Ll2/o;II)V

    .line 227
    .line 228
    .line 229
    sget-object v1, Lzb/x;->b:Ll2/u2;

    .line 230
    .line 231
    invoke-virtual {v11, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v1

    .line 235
    const-string v6, "null cannot be cast to non-null type cariad.charging.multicharge.kitten.coupons.presentation.CouponsUi"

    .line 236
    .line 237
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 238
    .line 239
    .line 240
    check-cast v1, Lxd/a;

    .line 241
    .line 242
    iget-object v6, v0, Lyd/u;->m:Lyy0/l1;

    .line 243
    .line 244
    invoke-static {v6, v11}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 245
    .line 246
    .line 247
    move-result-object v6

    .line 248
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v6

    .line 252
    check-cast v6, Llc/q;

    .line 253
    .line 254
    invoke-virtual {v11, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 255
    .line 256
    .line 257
    move-result v7

    .line 258
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    move-result-object v8

    .line 262
    if-nez v7, :cond_d

    .line 263
    .line 264
    if-ne v8, v2, :cond_e

    .line 265
    .line 266
    :cond_d
    new-instance v14, Ly21/d;

    .line 267
    .line 268
    const/16 v20, 0x0

    .line 269
    .line 270
    const/16 v21, 0x6

    .line 271
    .line 272
    const/4 v15, 0x1

    .line 273
    const-class v17, Lyd/u;

    .line 274
    .line 275
    const-string v18, "onUiEvent"

    .line 276
    .line 277
    const-string v19, "onUiEvent(Lcariad/charging/multicharge/kitten/coupons/presentation/overview/CouponOverviewUiEvent;)V"

    .line 278
    .line 279
    move-object/from16 v16, v0

    .line 280
    .line 281
    invoke-direct/range {v14 .. v21}, Ly21/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 282
    .line 283
    .line 284
    invoke-virtual {v11, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 285
    .line 286
    .line 287
    move-object v8, v14

    .line 288
    :cond_e
    check-cast v8, Lhy0/g;

    .line 289
    .line 290
    check-cast v8, Lay0/k;

    .line 291
    .line 292
    const/16 v0, 0x8

    .line 293
    .line 294
    invoke-interface {v1, v6, v8, v11, v0}, Lxd/a;->u0(Llc/q;Lay0/k;Ll2/o;I)V

    .line 295
    .line 296
    .line 297
    goto :goto_a

    .line 298
    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 299
    .line 300
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 301
    .line 302
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 303
    .line 304
    .line 305
    throw v0

    .line 306
    :cond_10
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 307
    .line 308
    .line 309
    :goto_a
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 310
    .line 311
    .line 312
    move-result-object v6

    .line 313
    if-eqz v6, :cond_11

    .line 314
    .line 315
    new-instance v0, Luj/j0;

    .line 316
    .line 317
    const/16 v2, 0x17

    .line 318
    .line 319
    move/from16 v1, p4

    .line 320
    .line 321
    invoke-direct/range {v0 .. v5}, Luj/j0;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 322
    .line 323
    .line 324
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 325
    .line 326
    :cond_11
    return-void
.end method

.method public static final b(Ljava/lang/String;)Z
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    move v1, v0

    .line 3
    :goto_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 4
    .line 5
    .line 6
    move-result v2

    .line 7
    if-ge v1, v2, :cond_2

    .line 8
    .line 9
    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    const/16 v3, 0x80

    .line 14
    .line 15
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->g(II)I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    if-gez v3, :cond_1

    .line 20
    .line 21
    invoke-static {v2}, Ljava/lang/Character;->isLetter(C)Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_0

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    :goto_1
    const/4 p0, 0x1

    .line 32
    return p0

    .line 33
    :cond_2
    return v0
.end method
