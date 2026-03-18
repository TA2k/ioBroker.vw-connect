.class public final synthetic Le2/n0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Le2/w0;


# direct methods
.method public synthetic constructor <init>(Le2/w0;I)V
    .locals 0

    .line 1
    iput p2, p0, Le2/n0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Le2/n0;->e:Le2/w0;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Le2/n0;->d:I

    .line 4
    .line 5
    iget-object v0, v0, Le2/n0;->e:Le2/w0;

    .line 6
    .line 7
    packed-switch v1, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    move-object/from16 v1, p1

    .line 11
    .line 12
    check-cast v1, Ld3/b;

    .line 13
    .line 14
    invoke-virtual {v0}, Le2/w0;->q()V

    .line 15
    .line 16
    .line 17
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 18
    .line 19
    return-object v0

    .line 20
    :pswitch_0
    move-object/from16 v1, p1

    .line 21
    .line 22
    check-cast v1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 23
    .line 24
    new-instance v1, La2/j;

    .line 25
    .line 26
    const/16 v2, 0xe

    .line 27
    .line 28
    invoke-direct {v1, v0, v2}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 29
    .line 30
    .line 31
    return-object v1

    .line 32
    :pswitch_1
    move-object/from16 v1, p1

    .line 33
    .line 34
    check-cast v1, Lt3/y;

    .line 35
    .line 36
    iget-object v2, v0, Le2/w0;->d:Lt1/p0;

    .line 37
    .line 38
    sget-object v3, Ld3/c;->e:Ld3/c;

    .line 39
    .line 40
    if-eqz v2, :cond_7

    .line 41
    .line 42
    iget-boolean v5, v2, Lt1/p0;->p:Z

    .line 43
    .line 44
    if-nez v5, :cond_0

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    const/4 v2, 0x0

    .line 48
    :goto_0
    if-eqz v2, :cond_7

    .line 49
    .line 50
    iget-object v5, v0, Le2/w0;->b:Ll4/p;

    .line 51
    .line 52
    invoke-virtual {v0}, Le2/w0;->m()Ll4/v;

    .line 53
    .line 54
    .line 55
    move-result-object v6

    .line 56
    iget-wide v6, v6, Ll4/v;->b:J

    .line 57
    .line 58
    sget v8, Lg4/o0;->c:I

    .line 59
    .line 60
    const/16 v8, 0x20

    .line 61
    .line 62
    shr-long/2addr v6, v8

    .line 63
    long-to-int v6, v6

    .line 64
    invoke-interface {v5, v6}, Ll4/p;->R(I)I

    .line 65
    .line 66
    .line 67
    move-result v5

    .line 68
    iget-object v6, v0, Le2/w0;->b:Ll4/p;

    .line 69
    .line 70
    invoke-virtual {v0}, Le2/w0;->m()Ll4/v;

    .line 71
    .line 72
    .line 73
    move-result-object v7

    .line 74
    iget-wide v9, v7, Ll4/v;->b:J

    .line 75
    .line 76
    const-wide v11, 0xffffffffL

    .line 77
    .line 78
    .line 79
    .line 80
    .line 81
    and-long/2addr v9, v11

    .line 82
    long-to-int v7, v9

    .line 83
    invoke-interface {v6, v7}, Ll4/p;->R(I)I

    .line 84
    .line 85
    .line 86
    move-result v6

    .line 87
    iget-object v7, v0, Le2/w0;->d:Lt1/p0;

    .line 88
    .line 89
    const-wide/16 v9, 0x0

    .line 90
    .line 91
    if-eqz v7, :cond_1

    .line 92
    .line 93
    invoke-virtual {v7}, Lt1/p0;->c()Lt3/y;

    .line 94
    .line 95
    .line 96
    move-result-object v7

    .line 97
    if-eqz v7, :cond_1

    .line 98
    .line 99
    const/4 v13, 0x1

    .line 100
    invoke-virtual {v0, v13}, Le2/w0;->k(Z)J

    .line 101
    .line 102
    .line 103
    move-result-wide v13

    .line 104
    invoke-interface {v7, v13, v14}, Lt3/y;->R(J)J

    .line 105
    .line 106
    .line 107
    move-result-wide v13

    .line 108
    goto :goto_1

    .line 109
    :cond_1
    move-wide v13, v9

    .line 110
    :goto_1
    iget-object v7, v0, Le2/w0;->d:Lt1/p0;

    .line 111
    .line 112
    if-eqz v7, :cond_2

    .line 113
    .line 114
    invoke-virtual {v7}, Lt1/p0;->c()Lt3/y;

    .line 115
    .line 116
    .line 117
    move-result-object v7

    .line 118
    if-eqz v7, :cond_2

    .line 119
    .line 120
    const/4 v9, 0x0

    .line 121
    invoke-virtual {v0, v9}, Le2/w0;->k(Z)J

    .line 122
    .line 123
    .line 124
    move-result-wide v9

    .line 125
    invoke-interface {v7, v9, v10}, Lt3/y;->R(J)J

    .line 126
    .line 127
    .line 128
    move-result-wide v9

    .line 129
    :cond_2
    iget-object v7, v0, Le2/w0;->d:Lt1/p0;

    .line 130
    .line 131
    const/4 v15, 0x0

    .line 132
    if-eqz v7, :cond_4

    .line 133
    .line 134
    invoke-virtual {v7}, Lt1/p0;->c()Lt3/y;

    .line 135
    .line 136
    .line 137
    move-result-object v7

    .line 138
    if-eqz v7, :cond_4

    .line 139
    .line 140
    invoke-virtual {v2}, Lt1/p0;->d()Lt1/j1;

    .line 141
    .line 142
    .line 143
    move-result-object v4

    .line 144
    if-eqz v4, :cond_3

    .line 145
    .line 146
    iget-object v4, v4, Lt1/j1;->a:Lg4/l0;

    .line 147
    .line 148
    invoke-virtual {v4, v5}, Lg4/l0;->c(I)Ld3/c;

    .line 149
    .line 150
    .line 151
    move-result-object v4

    .line 152
    iget v4, v4, Ld3/c;->b:F

    .line 153
    .line 154
    goto :goto_2

    .line 155
    :cond_3
    move v4, v15

    .line 156
    :goto_2
    invoke-static {v15}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 157
    .line 158
    .line 159
    move-result v5

    .line 160
    move/from16 p1, v8

    .line 161
    .line 162
    move-wide/from16 v16, v9

    .line 163
    .line 164
    int-to-long v8, v5

    .line 165
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 166
    .line 167
    .line 168
    move-result v4

    .line 169
    int-to-long v4, v4

    .line 170
    shl-long v8, v8, p1

    .line 171
    .line 172
    and-long/2addr v4, v11

    .line 173
    or-long/2addr v4, v8

    .line 174
    invoke-interface {v7, v4, v5}, Lt3/y;->R(J)J

    .line 175
    .line 176
    .line 177
    move-result-wide v4

    .line 178
    and-long/2addr v4, v11

    .line 179
    long-to-int v4, v4

    .line 180
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 181
    .line 182
    .line 183
    move-result v4

    .line 184
    goto :goto_3

    .line 185
    :cond_4
    move/from16 p1, v8

    .line 186
    .line 187
    move-wide/from16 v16, v9

    .line 188
    .line 189
    move v4, v15

    .line 190
    :goto_3
    iget-object v5, v0, Le2/w0;->d:Lt1/p0;

    .line 191
    .line 192
    if-eqz v5, :cond_6

    .line 193
    .line 194
    invoke-virtual {v5}, Lt1/p0;->c()Lt3/y;

    .line 195
    .line 196
    .line 197
    move-result-object v5

    .line 198
    if-eqz v5, :cond_6

    .line 199
    .line 200
    invoke-virtual {v2}, Lt1/p0;->d()Lt1/j1;

    .line 201
    .line 202
    .line 203
    move-result-object v7

    .line 204
    if-eqz v7, :cond_5

    .line 205
    .line 206
    iget-object v7, v7, Lt1/j1;->a:Lg4/l0;

    .line 207
    .line 208
    invoke-virtual {v7, v6}, Lg4/l0;->c(I)Ld3/c;

    .line 209
    .line 210
    .line 211
    move-result-object v6

    .line 212
    iget v6, v6, Ld3/c;->b:F

    .line 213
    .line 214
    goto :goto_4

    .line 215
    :cond_5
    move v6, v15

    .line 216
    :goto_4
    invoke-static {v15}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 217
    .line 218
    .line 219
    move-result v7

    .line 220
    int-to-long v7, v7

    .line 221
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 222
    .line 223
    .line 224
    move-result v6

    .line 225
    int-to-long v9, v6

    .line 226
    shl-long v6, v7, p1

    .line 227
    .line 228
    and-long v8, v9, v11

    .line 229
    .line 230
    or-long/2addr v6, v8

    .line 231
    invoke-interface {v5, v6, v7}, Lt3/y;->R(J)J

    .line 232
    .line 233
    .line 234
    move-result-wide v5

    .line 235
    and-long/2addr v5, v11

    .line 236
    long-to-int v5, v5

    .line 237
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 238
    .line 239
    .line 240
    move-result v15

    .line 241
    :cond_6
    shr-long v5, v13, p1

    .line 242
    .line 243
    long-to-int v5, v5

    .line 244
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 245
    .line 246
    .line 247
    move-result v6

    .line 248
    shr-long v7, v16, p1

    .line 249
    .line 250
    long-to-int v7, v7

    .line 251
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 252
    .line 253
    .line 254
    move-result v8

    .line 255
    invoke-static {v6, v8}, Ljava/lang/Math;->min(FF)F

    .line 256
    .line 257
    .line 258
    move-result v6

    .line 259
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 260
    .line 261
    .line 262
    move-result v5

    .line 263
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 264
    .line 265
    .line 266
    move-result v7

    .line 267
    invoke-static {v5, v7}, Ljava/lang/Math;->max(FF)F

    .line 268
    .line 269
    .line 270
    move-result v5

    .line 271
    invoke-static {v4, v15}, Ljava/lang/Math;->min(FF)F

    .line 272
    .line 273
    .line 274
    move-result v4

    .line 275
    and-long v7, v13, v11

    .line 276
    .line 277
    long-to-int v7, v7

    .line 278
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 279
    .line 280
    .line 281
    move-result v7

    .line 282
    and-long v8, v16, v11

    .line 283
    .line 284
    long-to-int v8, v8

    .line 285
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 286
    .line 287
    .line 288
    move-result v8

    .line 289
    invoke-static {v7, v8}, Ljava/lang/Math;->max(FF)F

    .line 290
    .line 291
    .line 292
    move-result v7

    .line 293
    const/16 v8, 0x19

    .line 294
    .line 295
    int-to-float v8, v8

    .line 296
    iget-object v2, v2, Lt1/p0;->a:Lt1/v0;

    .line 297
    .line 298
    iget-object v2, v2, Lt1/v0;->g:Lt4/c;

    .line 299
    .line 300
    invoke-interface {v2}, Lt4/c;->a()F

    .line 301
    .line 302
    .line 303
    move-result v2

    .line 304
    mul-float/2addr v2, v8

    .line 305
    add-float/2addr v2, v7

    .line 306
    new-instance v7, Ld3/c;

    .line 307
    .line 308
    invoke-direct {v7, v6, v4, v5, v2}, Ld3/c;-><init>(FFFF)V

    .line 309
    .line 310
    .line 311
    goto :goto_5

    .line 312
    :cond_7
    move-object v7, v3

    .line 313
    :goto_5
    iget-object v0, v0, Le2/w0;->d:Lt1/p0;

    .line 314
    .line 315
    if-eqz v0, :cond_8

    .line 316
    .line 317
    invoke-virtual {v0}, Lt1/p0;->c()Lt3/y;

    .line 318
    .line 319
    .line 320
    move-result-object v4

    .line 321
    goto :goto_6

    .line 322
    :cond_8
    const/4 v4, 0x0

    .line 323
    :goto_6
    if-eqz v4, :cond_b

    .line 324
    .line 325
    invoke-interface {v4}, Lt3/y;->g()Z

    .line 326
    .line 327
    .line 328
    move-result v0

    .line 329
    if-eqz v0, :cond_a

    .line 330
    .line 331
    invoke-interface {v1}, Lt3/y;->g()Z

    .line 332
    .line 333
    .line 334
    move-result v0

    .line 335
    if-nez v0, :cond_9

    .line 336
    .line 337
    goto :goto_7

    .line 338
    :cond_9
    invoke-virtual {v7}, Ld3/c;->d()J

    .line 339
    .line 340
    .line 341
    move-result-wide v2

    .line 342
    invoke-static {v4}, Lt3/k1;->i(Lt3/y;)Lt3/y;

    .line 343
    .line 344
    .line 345
    move-result-object v0

    .line 346
    invoke-interface {v1, v0, v2, v3}, Lt3/y;->Z(Lt3/y;J)J

    .line 347
    .line 348
    .line 349
    move-result-wide v0

    .line 350
    invoke-virtual {v7}, Ld3/c;->c()J

    .line 351
    .line 352
    .line 353
    move-result-wide v2

    .line 354
    invoke-static {v0, v1, v2, v3}, Ljp/cf;->c(JJ)Ld3/c;

    .line 355
    .line 356
    .line 357
    move-result-object v3

    .line 358
    :cond_a
    :goto_7
    return-object v3

    .line 359
    :cond_b
    const-string v0, "Required value was null."

    .line 360
    .line 361
    invoke-static {v0}, Lj1/b;->d(Ljava/lang/String;)Ljava/lang/Void;

    .line 362
    .line 363
    .line 364
    new-instance v0, La8/r0;

    .line 365
    .line 366
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 367
    .line 368
    .line 369
    throw v0

    .line 370
    nop

    .line 371
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
