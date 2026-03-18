.class public abstract Ljp/ff;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lay0/k;Lx2/s;Lqb/c;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lt2/b;Ll2/o;I)V
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v4, p3

    .line 4
    .line 5
    move-object/from16 v3, p4

    .line 6
    .line 7
    move-object/from16 v0, p7

    .line 8
    .line 9
    move/from16 v10, p9

    .line 10
    .line 11
    sget-object v2, Lqb/a;->e:Lqb/a;

    .line 12
    .line 13
    const-string v2, "onResult"

    .line 14
    .line 15
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    const-string v2, "onDeniedAfterSettingsResult"

    .line 19
    .line 20
    invoke-static {v4, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    const-string v2, "onDenied"

    .line 24
    .line 25
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    move-object/from16 v8, p8

    .line 29
    .line 30
    check-cast v8, Ll2/t;

    .line 31
    .line 32
    const v2, 0x719d426f

    .line 33
    .line 34
    .line 35
    invoke-virtual {v8, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 36
    .line 37
    .line 38
    and-int/lit8 v2, v10, 0x6

    .line 39
    .line 40
    const/4 v5, 0x0

    .line 41
    if-nez v2, :cond_1

    .line 42
    .line 43
    invoke-virtual {v8, v5}, Ll2/t;->e(I)Z

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    if-eqz v2, :cond_0

    .line 48
    .line 49
    const/4 v2, 0x4

    .line 50
    goto :goto_0

    .line 51
    :cond_0
    const/4 v2, 0x2

    .line 52
    :goto_0
    or-int/2addr v2, v10

    .line 53
    goto :goto_1

    .line 54
    :cond_1
    move v2, v10

    .line 55
    :goto_1
    and-int/lit8 v6, v10, 0x30

    .line 56
    .line 57
    if-nez v6, :cond_3

    .line 58
    .line 59
    invoke-virtual {v8, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v6

    .line 63
    if-eqz v6, :cond_2

    .line 64
    .line 65
    const/16 v6, 0x20

    .line 66
    .line 67
    goto :goto_2

    .line 68
    :cond_2
    const/16 v6, 0x10

    .line 69
    .line 70
    :goto_2
    or-int/2addr v2, v6

    .line 71
    :cond_3
    or-int/lit16 v6, v2, 0x180

    .line 72
    .line 73
    and-int/lit16 v7, v10, 0xc00

    .line 74
    .line 75
    if-nez v7, :cond_4

    .line 76
    .line 77
    or-int/lit16 v6, v2, 0x580

    .line 78
    .line 79
    :cond_4
    and-int/lit16 v2, v10, 0x6000

    .line 80
    .line 81
    if-nez v2, :cond_6

    .line 82
    .line 83
    invoke-virtual {v8, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    if-eqz v2, :cond_5

    .line 88
    .line 89
    const/16 v2, 0x4000

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_5
    const/16 v2, 0x2000

    .line 93
    .line 94
    :goto_3
    or-int/2addr v6, v2

    .line 95
    :cond_6
    const/high16 v2, 0x30000

    .line 96
    .line 97
    and-int v7, v10, v2

    .line 98
    .line 99
    if-nez v7, :cond_8

    .line 100
    .line 101
    invoke-virtual {v8, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v7

    .line 105
    if-eqz v7, :cond_7

    .line 106
    .line 107
    const/high16 v7, 0x20000

    .line 108
    .line 109
    goto :goto_4

    .line 110
    :cond_7
    const/high16 v7, 0x10000

    .line 111
    .line 112
    :goto_4
    or-int/2addr v6, v7

    .line 113
    :cond_8
    const/high16 v7, 0x180000

    .line 114
    .line 115
    and-int/2addr v7, v10

    .line 116
    if-nez v7, :cond_a

    .line 117
    .line 118
    move-object/from16 v7, p5

    .line 119
    .line 120
    invoke-virtual {v8, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result v9

    .line 124
    if-eqz v9, :cond_9

    .line 125
    .line 126
    const/high16 v9, 0x100000

    .line 127
    .line 128
    goto :goto_5

    .line 129
    :cond_9
    const/high16 v9, 0x80000

    .line 130
    .line 131
    :goto_5
    or-int/2addr v6, v9

    .line 132
    goto :goto_6

    .line 133
    :cond_a
    move-object/from16 v7, p5

    .line 134
    .line 135
    :goto_6
    const/high16 v9, 0xc00000

    .line 136
    .line 137
    and-int/2addr v9, v10

    .line 138
    if-nez v9, :cond_b

    .line 139
    .line 140
    const/high16 v9, 0x400000

    .line 141
    .line 142
    or-int/2addr v6, v9

    .line 143
    :cond_b
    const/high16 v9, 0x6000000

    .line 144
    .line 145
    and-int/2addr v9, v10

    .line 146
    if-nez v9, :cond_d

    .line 147
    .line 148
    invoke-virtual {v8, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result v9

    .line 152
    if-eqz v9, :cond_c

    .line 153
    .line 154
    const/high16 v9, 0x4000000

    .line 155
    .line 156
    goto :goto_7

    .line 157
    :cond_c
    const/high16 v9, 0x2000000

    .line 158
    .line 159
    :goto_7
    or-int/2addr v6, v9

    .line 160
    :cond_d
    const v9, 0x2492493

    .line 161
    .line 162
    .line 163
    and-int/2addr v9, v6

    .line 164
    const v11, 0x2492492

    .line 165
    .line 166
    .line 167
    const/4 v12, 0x1

    .line 168
    if-eq v9, v11, :cond_e

    .line 169
    .line 170
    move v9, v12

    .line 171
    goto :goto_8

    .line 172
    :cond_e
    move v9, v5

    .line 173
    :goto_8
    and-int/lit8 v11, v6, 0x1

    .line 174
    .line 175
    invoke-virtual {v8, v11, v9}, Ll2/t;->O(IZ)Z

    .line 176
    .line 177
    .line 178
    move-result v9

    .line 179
    if-eqz v9, :cond_12

    .line 180
    .line 181
    invoke-virtual {v8}, Ll2/t;->T()V

    .line 182
    .line 183
    .line 184
    and-int/lit8 v9, v10, 0x1

    .line 185
    .line 186
    const v11, -0x1c01c01

    .line 187
    .line 188
    .line 189
    if-eqz v9, :cond_10

    .line 190
    .line 191
    invoke-virtual {v8}, Ll2/t;->y()Z

    .line 192
    .line 193
    .line 194
    move-result v9

    .line 195
    if-eqz v9, :cond_f

    .line 196
    .line 197
    goto :goto_9

    .line 198
    :cond_f
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 199
    .line 200
    .line 201
    and-int/2addr v6, v11

    .line 202
    move-object/from16 v11, p1

    .line 203
    .line 204
    move-object/from16 v13, p2

    .line 205
    .line 206
    move-object/from16 v4, p6

    .line 207
    .line 208
    goto :goto_a

    .line 209
    :cond_10
    :goto_9
    invoke-static {v8}, Ljp/gf;->b(Ll2/o;)Lqb/c;

    .line 210
    .line 211
    .line 212
    move-result-object v9

    .line 213
    and-int/2addr v6, v11

    .line 214
    sget-object v11, Lx2/p;->b:Lx2/p;

    .line 215
    .line 216
    move-object v4, v3

    .line 217
    move-object v13, v9

    .line 218
    :goto_a
    invoke-virtual {v8}, Ll2/t;->r()V

    .line 219
    .line 220
    .line 221
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v9

    .line 225
    sget-object v14, Ll2/n;->a:Ll2/x0;

    .line 226
    .line 227
    if-ne v9, v14, :cond_11

    .line 228
    .line 229
    new-instance v9, Lrb/b;

    .line 230
    .line 231
    new-instance v14, Lj1/a;

    .line 232
    .line 233
    const/16 v15, 0x19

    .line 234
    .line 235
    invoke-direct {v14, v15, v5}, Lj1/a;-><init>(IZ)V

    .line 236
    .line 237
    .line 238
    invoke-direct {v9, v14, v1}, Lrb/b;-><init>(Lj1/a;Lay0/k;)V

    .line 239
    .line 240
    .line 241
    invoke-virtual {v8, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 242
    .line 243
    .line 244
    :cond_11
    check-cast v9, Lrb/b;

    .line 245
    .line 246
    iget-object v5, v13, Lqb/c;->b:Lyy0/c2;

    .line 247
    .line 248
    const/4 v14, 0x0

    .line 249
    invoke-static {v5, v14, v8, v12}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 250
    .line 251
    .line 252
    move-result-object v5

    .line 253
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v5

    .line 257
    check-cast v5, Lqb/e;

    .line 258
    .line 259
    new-instance v12, Li91/k3;

    .line 260
    .line 261
    const/16 v14, 0x1d

    .line 262
    .line 263
    invoke-direct {v12, v11, v9, v0, v14}, Li91/k3;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 264
    .line 265
    .line 266
    const v9, 0x3b20b11a

    .line 267
    .line 268
    .line 269
    invoke-static {v9, v8, v12}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 270
    .line 271
    .line 272
    move-result-object v9

    .line 273
    shr-int/lit8 v12, v6, 0xc

    .line 274
    .line 275
    and-int/lit8 v12, v12, 0x70

    .line 276
    .line 277
    or-int/2addr v2, v12

    .line 278
    shr-int/lit8 v12, v6, 0x3

    .line 279
    .line 280
    and-int/lit16 v12, v12, 0x1c00

    .line 281
    .line 282
    or-int/2addr v2, v12

    .line 283
    const v12, 0xe000

    .line 284
    .line 285
    .line 286
    shr-int/lit8 v6, v6, 0x6

    .line 287
    .line 288
    and-int/2addr v6, v12

    .line 289
    or-int/2addr v2, v6

    .line 290
    move-object v6, v7

    .line 291
    move-object v7, v9

    .line 292
    move v9, v2

    .line 293
    move-object v2, v5

    .line 294
    move-object/from16 v5, p3

    .line 295
    .line 296
    invoke-static/range {v2 .. v9}, Ljp/gf;->a(Lqb/e;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lt2/b;Ll2/o;I)V

    .line 297
    .line 298
    .line 299
    move-object v7, v4

    .line 300
    move-object v2, v11

    .line 301
    move-object v3, v13

    .line 302
    goto :goto_b

    .line 303
    :cond_12
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 304
    .line 305
    .line 306
    move-object/from16 v2, p1

    .line 307
    .line 308
    move-object/from16 v3, p2

    .line 309
    .line 310
    move-object/from16 v7, p6

    .line 311
    .line 312
    :goto_b
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 313
    .line 314
    .line 315
    move-result-object v11

    .line 316
    if-eqz v11, :cond_13

    .line 317
    .line 318
    new-instance v0, Lkv0/c;

    .line 319
    .line 320
    move-object/from16 v4, p3

    .line 321
    .line 322
    move-object/from16 v5, p4

    .line 323
    .line 324
    move-object/from16 v6, p5

    .line 325
    .line 326
    move-object/from16 v8, p7

    .line 327
    .line 328
    move v9, v10

    .line 329
    invoke-direct/range {v0 .. v9}, Lkv0/c;-><init>(Lay0/k;Lx2/s;Lqb/c;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lt2/b;I)V

    .line 330
    .line 331
    .line 332
    iput-object v0, v11, Ll2/u1;->d:Lay0/n;

    .line 333
    .line 334
    :cond_13
    return-void
.end method

.method public static final b(Le31/p0;)Li31/f;
    .locals 6

    .line 1
    iget-object v0, p0, Le31/p0;->a:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Le31/p0;->b:Ljava/lang/Double;

    .line 4
    .line 5
    if-eqz v0, :cond_2

    .line 6
    .line 7
    invoke-static {v0}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    if-eqz v1, :cond_2

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/lang/Double;->doubleValue()D

    .line 17
    .line 18
    .line 19
    move-result-wide v2

    .line 20
    const-wide/16 v4, 0x0

    .line 21
    .line 22
    cmpg-double v0, v2, v4

    .line 23
    .line 24
    if-gez v0, :cond_1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    new-instance v0, Li31/f;

    .line 28
    .line 29
    iget-object p0, p0, Le31/p0;->a:Ljava/lang/String;

    .line 30
    .line 31
    invoke-virtual {v1}, Ljava/lang/Double;->doubleValue()D

    .line 32
    .line 33
    .line 34
    move-result-wide v1

    .line 35
    invoke-direct {v0, v1, v2, p0}, Li31/f;-><init>(DLjava/lang/String;)V

    .line 36
    .line 37
    .line 38
    return-object v0

    .line 39
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 40
    return-object p0
.end method
