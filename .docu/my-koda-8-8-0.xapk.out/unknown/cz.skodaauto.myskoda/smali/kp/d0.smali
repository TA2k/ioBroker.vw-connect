.class public abstract Lkp/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lkg/p0;Lyj/b;Lxh/e;Lh2/d6;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    const-string v0, "tariff"

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    move-object/from16 v6, p4

    .line 9
    .line 10
    check-cast v6, Ll2/t;

    .line 11
    .line 12
    const v0, -0x4b0cf870

    .line 13
    .line 14
    .line 15
    invoke-virtual {v6, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v6, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    const/4 v0, 0x4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v0, 0x2

    .line 27
    :goto_0
    or-int v0, p5, v0

    .line 28
    .line 29
    move-object/from16 v2, p1

    .line 30
    .line 31
    invoke-virtual {v6, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    const/16 v4, 0x20

    .line 36
    .line 37
    if-eqz v3, :cond_1

    .line 38
    .line 39
    move v3, v4

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
    move-object/from16 v3, p2

    .line 45
    .line 46
    invoke-virtual {v6, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    const/16 v7, 0x100

    .line 51
    .line 52
    if-eqz v5, :cond_2

    .line 53
    .line 54
    move v5, v7

    .line 55
    goto :goto_2

    .line 56
    :cond_2
    const/16 v5, 0x80

    .line 57
    .line 58
    :goto_2
    or-int/2addr v0, v5

    .line 59
    move-object/from16 v5, p3

    .line 60
    .line 61
    invoke-virtual {v6, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v8

    .line 65
    const/16 v9, 0x800

    .line 66
    .line 67
    if-eqz v8, :cond_3

    .line 68
    .line 69
    move v8, v9

    .line 70
    goto :goto_3

    .line 71
    :cond_3
    const/16 v8, 0x400

    .line 72
    .line 73
    :goto_3
    or-int/2addr v0, v8

    .line 74
    and-int/lit16 v8, v0, 0x493

    .line 75
    .line 76
    const/16 v10, 0x492

    .line 77
    .line 78
    const/4 v11, 0x1

    .line 79
    const/4 v12, 0x0

    .line 80
    if-eq v8, v10, :cond_4

    .line 81
    .line 82
    move v8, v11

    .line 83
    goto :goto_4

    .line 84
    :cond_4
    move v8, v12

    .line 85
    :goto_4
    and-int/lit8 v10, v0, 0x1

    .line 86
    .line 87
    invoke-virtual {v6, v10, v8}, Ll2/t;->O(IZ)Z

    .line 88
    .line 89
    .line 90
    move-result v8

    .line 91
    if-eqz v8, :cond_f

    .line 92
    .line 93
    invoke-virtual {v6, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v8

    .line 97
    and-int/lit8 v10, v0, 0x70

    .line 98
    .line 99
    if-ne v10, v4, :cond_5

    .line 100
    .line 101
    move v4, v11

    .line 102
    goto :goto_5

    .line 103
    :cond_5
    move v4, v12

    .line 104
    :goto_5
    or-int/2addr v4, v8

    .line 105
    and-int/lit16 v8, v0, 0x380

    .line 106
    .line 107
    if-ne v8, v7, :cond_6

    .line 108
    .line 109
    move v7, v11

    .line 110
    goto :goto_6

    .line 111
    :cond_6
    move v7, v12

    .line 112
    :goto_6
    or-int/2addr v4, v7

    .line 113
    and-int/lit16 v0, v0, 0x1c00

    .line 114
    .line 115
    if-ne v0, v9, :cond_7

    .line 116
    .line 117
    goto :goto_7

    .line 118
    :cond_7
    move v11, v12

    .line 119
    :goto_7
    or-int v0, v4, v11

    .line 120
    .line 121
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v4

    .line 125
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 126
    .line 127
    if-nez v0, :cond_8

    .line 128
    .line 129
    if-ne v4, v7, :cond_9

    .line 130
    .line 131
    :cond_8
    new-instance v0, Lbg/a;

    .line 132
    .line 133
    const/16 v5, 0x11

    .line 134
    .line 135
    move-object/from16 v4, p3

    .line 136
    .line 137
    invoke-direct/range {v0 .. v5}, Lbg/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {v6, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    move-object v4, v0

    .line 144
    :cond_9
    check-cast v4, Lay0/k;

    .line 145
    .line 146
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 147
    .line 148
    invoke-virtual {v6, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    check-cast v0, Ljava/lang/Boolean;

    .line 153
    .line 154
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 155
    .line 156
    .line 157
    move-result v0

    .line 158
    if-eqz v0, :cond_a

    .line 159
    .line 160
    const v0, -0x105bcaaa

    .line 161
    .line 162
    .line 163
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {v6, v12}, Ll2/t;->q(Z)V

    .line 167
    .line 168
    .line 169
    const/4 v0, 0x0

    .line 170
    goto :goto_8

    .line 171
    :cond_a
    const v0, 0x31054eee

    .line 172
    .line 173
    .line 174
    invoke-virtual {v6, v0}, Ll2/t;->Y(I)V

    .line 175
    .line 176
    .line 177
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 178
    .line 179
    invoke-virtual {v6, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v0

    .line 183
    check-cast v0, Lhi/a;

    .line 184
    .line 185
    invoke-virtual {v6, v12}, Ll2/t;->q(Z)V

    .line 186
    .line 187
    .line 188
    :goto_8
    new-instance v1, Lnd/e;

    .line 189
    .line 190
    const/16 v2, 0xf

    .line 191
    .line 192
    invoke-direct {v1, v0, v4, v2}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 193
    .line 194
    .line 195
    invoke-static {v6}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 196
    .line 197
    .line 198
    move-result-object v2

    .line 199
    if-eqz v2, :cond_e

    .line 200
    .line 201
    instance-of v0, v2, Landroidx/lifecycle/k;

    .line 202
    .line 203
    if-eqz v0, :cond_b

    .line 204
    .line 205
    move-object v0, v2

    .line 206
    check-cast v0, Landroidx/lifecycle/k;

    .line 207
    .line 208
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 209
    .line 210
    .line 211
    move-result-object v0

    .line 212
    :goto_9
    move-object v5, v0

    .line 213
    goto :goto_a

    .line 214
    :cond_b
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 215
    .line 216
    goto :goto_9

    .line 217
    :goto_a
    const-class v0, Lrg/d;

    .line 218
    .line 219
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 220
    .line 221
    invoke-virtual {v3, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 222
    .line 223
    .line 224
    move-result-object v0

    .line 225
    const/4 v3, 0x0

    .line 226
    move-object v4, v1

    .line 227
    move-object v1, v0

    .line 228
    invoke-static/range {v1 .. v6}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 229
    .line 230
    .line 231
    move-result-object v0

    .line 232
    move-object v15, v0

    .line 233
    check-cast v15, Lrg/d;

    .line 234
    .line 235
    invoke-static {v6}, Lmg/a;->c(Ll2/o;)Lmg/k;

    .line 236
    .line 237
    .line 238
    move-result-object v0

    .line 239
    iget-object v1, v15, Lrg/d;->h:Lyy0/c2;

    .line 240
    .line 241
    invoke-static {v1, v6}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 242
    .line 243
    .line 244
    move-result-object v1

    .line 245
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v1

    .line 249
    check-cast v1, Lug/b;

    .line 250
    .line 251
    invoke-virtual {v6, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 252
    .line 253
    .line 254
    move-result v2

    .line 255
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v3

    .line 259
    if-nez v2, :cond_c

    .line 260
    .line 261
    if-ne v3, v7, :cond_d

    .line 262
    .line 263
    :cond_c
    new-instance v13, Lo90/f;

    .line 264
    .line 265
    const/16 v19, 0x0

    .line 266
    .line 267
    const/16 v20, 0x16

    .line 268
    .line 269
    const/4 v14, 0x1

    .line 270
    const-class v16, Lrg/d;

    .line 271
    .line 272
    const-string v17, "onUiEvent"

    .line 273
    .line 274
    const-string v18, "onUiEvent(Lcariad/charging/multicharge/kitten/subscription/presentation/tariff/details/TariffDetailsUiEvent;)V"

    .line 275
    .line 276
    invoke-direct/range {v13 .. v20}, Lo90/f;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 277
    .line 278
    .line 279
    invoke-virtual {v6, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 280
    .line 281
    .line 282
    move-object v3, v13

    .line 283
    :cond_d
    check-cast v3, Lhy0/g;

    .line 284
    .line 285
    check-cast v3, Lay0/k;

    .line 286
    .line 287
    invoke-interface {v0, v1, v3, v6, v12}, Lmg/k;->c0(Lug/b;Lay0/k;Ll2/o;I)V

    .line 288
    .line 289
    .line 290
    goto :goto_b

    .line 291
    :cond_e
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 292
    .line 293
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 294
    .line 295
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 296
    .line 297
    .line 298
    throw v0

    .line 299
    :cond_f
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 300
    .line 301
    .line 302
    :goto_b
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 303
    .line 304
    .line 305
    move-result-object v7

    .line 306
    if-eqz v7, :cond_10

    .line 307
    .line 308
    new-instance v0, Lo50/p;

    .line 309
    .line 310
    const/4 v6, 0x4

    .line 311
    move-object/from16 v1, p0

    .line 312
    .line 313
    move-object/from16 v2, p1

    .line 314
    .line 315
    move-object/from16 v3, p2

    .line 316
    .line 317
    move-object/from16 v4, p3

    .line 318
    .line 319
    move/from16 v5, p5

    .line 320
    .line 321
    invoke-direct/range {v0 .. v6}, Lo50/p;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 322
    .line 323
    .line 324
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 325
    .line 326
    :cond_10
    return-void
.end method
