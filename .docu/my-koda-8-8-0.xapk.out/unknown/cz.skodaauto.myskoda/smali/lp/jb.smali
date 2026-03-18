.class public abstract Llp/jb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 21

    .line 1
    move/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v10, p0

    .line 4
    .line 5
    check-cast v10, Ll2/t;

    .line 6
    .line 7
    const v1, 0x680e5430

    .line 8
    .line 9
    .line 10
    invoke-virtual {v10, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    const/4 v2, 0x1

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v2, v1

    .line 19
    :goto_0
    and-int/lit8 v3, v0, 0x1

    .line 20
    .line 21
    invoke-virtual {v10, v3, v2}, Ll2/t;->O(IZ)Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_f

    .line 26
    .line 27
    const-string v2, "ChargingCardFlowScreen"

    .line 28
    .line 29
    invoke-static {v2, v10}, Lzb/b;->C(Ljava/lang/String;Ll2/o;)Lzb/v0;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    new-array v3, v1, [Ljava/lang/Object;

    .line 34
    .line 35
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 40
    .line 41
    if-ne v4, v5, :cond_1

    .line 42
    .line 43
    new-instance v4, Lu41/u;

    .line 44
    .line 45
    const/16 v6, 0x19

    .line 46
    .line 47
    invoke-direct {v4, v6}, Lu41/u;-><init>(I)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v10, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    :cond_1
    check-cast v4, Lay0/a;

    .line 54
    .line 55
    const/16 v6, 0x30

    .line 56
    .line 57
    invoke-static {v3, v4, v10, v6}, Lu2/m;->c([Ljava/lang/Object;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v3

    .line 61
    check-cast v3, Ll2/b1;

    .line 62
    .line 63
    new-array v1, v1, [Ljava/lang/Object;

    .line 64
    .line 65
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v4

    .line 69
    if-ne v4, v5, :cond_2

    .line 70
    .line 71
    new-instance v4, Lu41/u;

    .line 72
    .line 73
    const/16 v7, 0x1a

    .line 74
    .line 75
    invoke-direct {v4, v7}, Lu41/u;-><init>(I)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v10, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    :cond_2
    check-cast v4, Lay0/a;

    .line 82
    .line 83
    invoke-static {v1, v4, v10, v6}, Lu2/m;->c([Ljava/lang/Object;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    move-object v14, v1

    .line 88
    check-cast v14, Ll2/b1;

    .line 89
    .line 90
    invoke-virtual {v10, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v4

    .line 98
    if-nez v1, :cond_3

    .line 99
    .line 100
    if-ne v4, v5, :cond_4

    .line 101
    .line 102
    :cond_3
    new-instance v4, Lqf/c;

    .line 103
    .line 104
    const/4 v1, 0x4

    .line 105
    invoke-direct {v4, v14, v1}, Lqf/c;-><init>(Ll2/b1;I)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v10, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    :cond_4
    check-cast v4, Lay0/n;

    .line 112
    .line 113
    invoke-virtual {v2, v4}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 114
    .line 115
    .line 116
    move-result-object v12

    .line 117
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v1

    .line 121
    if-ne v1, v5, :cond_5

    .line 122
    .line 123
    new-instance v1, Lv50/l;

    .line 124
    .line 125
    const/16 v4, 0x10

    .line 126
    .line 127
    invoke-direct {v1, v4}, Lv50/l;-><init>(I)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v10, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    :cond_5
    check-cast v1, Lay0/n;

    .line 134
    .line 135
    invoke-virtual {v2, v1}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 136
    .line 137
    .line 138
    move-result-object v1

    .line 139
    invoke-virtual {v10, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    move-result v4

    .line 143
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v6

    .line 147
    if-nez v4, :cond_6

    .line 148
    .line 149
    if-ne v6, v5, :cond_7

    .line 150
    .line 151
    :cond_6
    new-instance v6, Lqf/c;

    .line 152
    .line 153
    const/4 v4, 0x5

    .line 154
    invoke-direct {v6, v3, v4}, Lqf/c;-><init>(Ll2/b1;I)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v10, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    :cond_7
    check-cast v6, Lay0/n;

    .line 161
    .line 162
    invoke-virtual {v2, v6}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 163
    .line 164
    .line 165
    move-result-object v13

    .line 166
    invoke-virtual {v10, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v4

    .line 170
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v6

    .line 174
    if-nez v4, :cond_8

    .line 175
    .line 176
    if-ne v6, v5, :cond_9

    .line 177
    .line 178
    :cond_8
    new-instance v6, Lle/b;

    .line 179
    .line 180
    const/16 v4, 0xf

    .line 181
    .line 182
    invoke-direct {v6, v3, v4}, Lle/b;-><init>(Ll2/b1;I)V

    .line 183
    .line 184
    .line 185
    invoke-virtual {v10, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    :cond_9
    check-cast v6, Lay0/k;

    .line 189
    .line 190
    invoke-virtual {v2, v6}, Lzb/v0;->f(Lay0/k;)Lyj/b;

    .line 191
    .line 192
    .line 193
    move-result-object v4

    .line 194
    invoke-virtual {v10, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    move-result v6

    .line 198
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v7

    .line 202
    if-nez v6, :cond_a

    .line 203
    .line 204
    if-ne v7, v5, :cond_b

    .line 205
    .line 206
    :cond_a
    new-instance v7, Lle/b;

    .line 207
    .line 208
    const/16 v6, 0x10

    .line 209
    .line 210
    invoke-direct {v7, v3, v6}, Lle/b;-><init>(Ll2/b1;I)V

    .line 211
    .line 212
    .line 213
    invoke-virtual {v10, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 214
    .line 215
    .line 216
    :cond_b
    check-cast v7, Lay0/k;

    .line 217
    .line 218
    invoke-virtual {v2, v7}, Lzb/v0;->f(Lay0/k;)Lyj/b;

    .line 219
    .line 220
    .line 221
    move-result-object v15

    .line 222
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object v6

    .line 226
    if-ne v6, v5, :cond_c

    .line 227
    .line 228
    new-instance v6, Lvb/a;

    .line 229
    .line 230
    const/4 v7, 0x1

    .line 231
    invoke-direct {v6, v7}, Lvb/a;-><init>(I)V

    .line 232
    .line 233
    .line 234
    invoke-virtual {v10, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 235
    .line 236
    .line 237
    :cond_c
    check-cast v6, Lay0/k;

    .line 238
    .line 239
    invoke-virtual {v2, v6}, Lzb/v0;->f(Lay0/k;)Lyj/b;

    .line 240
    .line 241
    .line 242
    move-result-object v6

    .line 243
    invoke-virtual {v2}, Lzb/v0;->b()Lz9/y;

    .line 244
    .line 245
    .line 246
    move-result-object v2

    .line 247
    invoke-virtual {v10, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 248
    .line 249
    .line 250
    move-result v7

    .line 251
    invoke-virtual {v10, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 252
    .line 253
    .line 254
    move-result v8

    .line 255
    or-int/2addr v7, v8

    .line 256
    invoke-virtual {v10, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 257
    .line 258
    .line 259
    move-result v8

    .line 260
    or-int/2addr v7, v8

    .line 261
    invoke-virtual {v10, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 262
    .line 263
    .line 264
    move-result v8

    .line 265
    or-int/2addr v7, v8

    .line 266
    invoke-virtual {v10, v15}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 267
    .line 268
    .line 269
    move-result v8

    .line 270
    or-int/2addr v7, v8

    .line 271
    invoke-virtual {v10, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 272
    .line 273
    .line 274
    move-result v8

    .line 275
    or-int/2addr v7, v8

    .line 276
    invoke-virtual {v10, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 277
    .line 278
    .line 279
    move-result v8

    .line 280
    or-int/2addr v7, v8

    .line 281
    invoke-virtual {v10, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 282
    .line 283
    .line 284
    move-result v8

    .line 285
    or-int/2addr v7, v8

    .line 286
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 287
    .line 288
    .line 289
    move-result-object v8

    .line 290
    if-nez v7, :cond_d

    .line 291
    .line 292
    if-ne v8, v5, :cond_e

    .line 293
    .line 294
    :cond_d
    new-instance v11, Lh2/d1;

    .line 295
    .line 296
    const/16 v20, 0x5

    .line 297
    .line 298
    move-object/from16 v16, v1

    .line 299
    .line 300
    move-object/from16 v19, v3

    .line 301
    .line 302
    move-object/from16 v17, v4

    .line 303
    .line 304
    move-object/from16 v18, v6

    .line 305
    .line 306
    invoke-direct/range {v11 .. v20}, Lh2/d1;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 307
    .line 308
    .line 309
    invoke-virtual {v10, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 310
    .line 311
    .line 312
    move-object v8, v11

    .line 313
    :cond_e
    move-object v9, v8

    .line 314
    check-cast v9, Lay0/k;

    .line 315
    .line 316
    const/4 v12, 0x0

    .line 317
    const/16 v13, 0x3fc

    .line 318
    .line 319
    move-object v1, v2

    .line 320
    const-string v2, "/overview"

    .line 321
    .line 322
    const/4 v3, 0x0

    .line 323
    const/4 v4, 0x0

    .line 324
    const/4 v5, 0x0

    .line 325
    const/4 v6, 0x0

    .line 326
    const/4 v7, 0x0

    .line 327
    const/4 v8, 0x0

    .line 328
    const/16 v11, 0x30

    .line 329
    .line 330
    invoke-static/range {v1 .. v13}, Ljp/w0;->b(Lz9/y;Ljava/lang/String;Lx2/s;Lx2/e;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Ll2/o;III)V

    .line 331
    .line 332
    .line 333
    goto :goto_1

    .line 334
    :cond_f
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 335
    .line 336
    .line 337
    :goto_1
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 338
    .line 339
    .line 340
    move-result-object v1

    .line 341
    if-eqz v1, :cond_10

    .line 342
    .line 343
    new-instance v2, Lv50/l;

    .line 344
    .line 345
    const/16 v3, 0x11

    .line 346
    .line 347
    invoke-direct {v2, v0, v3}, Lv50/l;-><init>(II)V

    .line 348
    .line 349
    .line 350
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 351
    .line 352
    :cond_10
    return-void
.end method
