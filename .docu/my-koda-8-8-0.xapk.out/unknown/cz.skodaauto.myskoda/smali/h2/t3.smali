.class public final Lh2/t3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:J


# direct methods
.method public synthetic constructor <init>(JLjava/lang/String;I)V
    .locals 0

    .line 1
    iput p4, p0, Lh2/t3;->d:I

    iput-object p3, p0, Lh2/t3;->e:Ljava/lang/Object;

    iput-wide p1, p0, Lh2/t3;->f:J

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(JLx2/s;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lh2/t3;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Lh2/t3;->f:J

    iput-object p3, p0, Lh2/t3;->e:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh2/t3;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    and-int/lit8 v3, v2, 0x3

    .line 21
    .line 22
    const/4 v4, 0x2

    .line 23
    const/4 v5, 0x1

    .line 24
    const/4 v6, 0x0

    .line 25
    if-eq v3, v4, :cond_0

    .line 26
    .line 27
    move v3, v5

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move v3, v6

    .line 30
    :goto_0
    and-int/2addr v2, v5

    .line 31
    check-cast v1, Ll2/t;

    .line 32
    .line 33
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-eqz v2, :cond_5

    .line 38
    .line 39
    const-wide v2, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 40
    .line 41
    .line 42
    .line 43
    .line 44
    iget-wide v7, v0, Lh2/t3;->f:J

    .line 45
    .line 46
    cmp-long v2, v7, v2

    .line 47
    .line 48
    if-eqz v2, :cond_4

    .line 49
    .line 50
    const v2, -0x4a262578

    .line 51
    .line 52
    .line 53
    invoke-virtual {v1, v2}, Ll2/t;->Y(I)V

    .line 54
    .line 55
    .line 56
    iget-object v0, v0, Lh2/t3;->e:Ljava/lang/Object;

    .line 57
    .line 58
    move-object v9, v0

    .line 59
    check-cast v9, Lx2/s;

    .line 60
    .line 61
    invoke-static {v7, v8}, Lt4/h;->c(J)F

    .line 62
    .line 63
    .line 64
    move-result v10

    .line 65
    invoke-static {v7, v8}, Lt4/h;->b(J)F

    .line 66
    .line 67
    .line 68
    move-result v11

    .line 69
    const/4 v13, 0x0

    .line 70
    const/16 v14, 0xc

    .line 71
    .line 72
    const/4 v12, 0x0

    .line 73
    invoke-static/range {v9 .. v14}, Landroidx/compose/foundation/layout/d;->l(Lx2/s;FFFFI)Lx2/s;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    sget-object v2, Lx2/c;->e:Lx2/j;

    .line 78
    .line 79
    invoke-static {v2, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    iget-wide v3, v1, Ll2/t;->T:J

    .line 84
    .line 85
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 86
    .line 87
    .line 88
    move-result v3

    .line 89
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 90
    .line 91
    .line 92
    move-result-object v4

    .line 93
    invoke-static {v1, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 98
    .line 99
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 100
    .line 101
    .line 102
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 103
    .line 104
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 105
    .line 106
    .line 107
    iget-boolean v8, v1, Ll2/t;->S:Z

    .line 108
    .line 109
    if-eqz v8, :cond_1

    .line 110
    .line 111
    invoke-virtual {v1, v7}, Ll2/t;->l(Lay0/a;)V

    .line 112
    .line 113
    .line 114
    goto :goto_1

    .line 115
    :cond_1
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 116
    .line 117
    .line 118
    :goto_1
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 119
    .line 120
    invoke-static {v7, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 121
    .line 122
    .line 123
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 124
    .line 125
    invoke-static {v2, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 126
    .line 127
    .line 128
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 129
    .line 130
    iget-boolean v4, v1, Ll2/t;->S:Z

    .line 131
    .line 132
    if-nez v4, :cond_2

    .line 133
    .line 134
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v4

    .line 138
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 139
    .line 140
    .line 141
    move-result-object v7

    .line 142
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 143
    .line 144
    .line 145
    move-result v4

    .line 146
    if-nez v4, :cond_3

    .line 147
    .line 148
    :cond_2
    invoke-static {v3, v1, v3, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 149
    .line 150
    .line 151
    :cond_3
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 152
    .line 153
    invoke-static {v2, v0, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 154
    .line 155
    .line 156
    const/4 v0, 0x0

    .line 157
    invoke-static {v6, v5, v1, v0}, Lt1/b;->b(IILl2/o;Lx2/s;)V

    .line 158
    .line 159
    .line 160
    invoke-virtual {v1, v5}, Ll2/t;->q(Z)V

    .line 161
    .line 162
    .line 163
    invoke-virtual {v1, v6}, Ll2/t;->q(Z)V

    .line 164
    .line 165
    .line 166
    goto :goto_2

    .line 167
    :cond_4
    const v2, -0x4a2083ba

    .line 168
    .line 169
    .line 170
    invoke-virtual {v1, v2}, Ll2/t;->Y(I)V

    .line 171
    .line 172
    .line 173
    iget-object v0, v0, Lh2/t3;->e:Ljava/lang/Object;

    .line 174
    .line 175
    check-cast v0, Lx2/s;

    .line 176
    .line 177
    invoke-static {v6, v6, v1, v0}, Lt1/b;->b(IILl2/o;Lx2/s;)V

    .line 178
    .line 179
    .line 180
    invoke-virtual {v1, v6}, Ll2/t;->q(Z)V

    .line 181
    .line 182
    .line 183
    goto :goto_2

    .line 184
    :cond_5
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 185
    .line 186
    .line 187
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 188
    .line 189
    return-object v0

    .line 190
    :pswitch_0
    move-object/from16 v1, p1

    .line 191
    .line 192
    check-cast v1, Ll2/o;

    .line 193
    .line 194
    move-object/from16 v2, p2

    .line 195
    .line 196
    check-cast v2, Ljava/lang/Number;

    .line 197
    .line 198
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 199
    .line 200
    .line 201
    move-result v2

    .line 202
    and-int/lit8 v3, v2, 0x3

    .line 203
    .line 204
    const/4 v4, 0x2

    .line 205
    const/4 v5, 0x1

    .line 206
    if-eq v3, v4, :cond_6

    .line 207
    .line 208
    move v3, v5

    .line 209
    goto :goto_3

    .line 210
    :cond_6
    const/4 v3, 0x0

    .line 211
    :goto_3
    and-int/2addr v2, v5

    .line 212
    check-cast v1, Ll2/t;

    .line 213
    .line 214
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 215
    .line 216
    .line 217
    move-result v2

    .line 218
    if-eqz v2, :cond_7

    .line 219
    .line 220
    iget-object v2, v0, Lh2/t3;->e:Ljava/lang/Object;

    .line 221
    .line 222
    move-object v4, v2

    .line 223
    check-cast v4, Ljava/lang/String;

    .line 224
    .line 225
    const/16 v25, 0x0

    .line 226
    .line 227
    const v26, 0x3fffa

    .line 228
    .line 229
    .line 230
    const/4 v5, 0x0

    .line 231
    iget-wide v6, v0, Lh2/t3;->f:J

    .line 232
    .line 233
    const-wide/16 v8, 0x0

    .line 234
    .line 235
    const/4 v10, 0x0

    .line 236
    const-wide/16 v11, 0x0

    .line 237
    .line 238
    const/4 v13, 0x0

    .line 239
    const/4 v14, 0x0

    .line 240
    const-wide/16 v15, 0x0

    .line 241
    .line 242
    const/16 v17, 0x0

    .line 243
    .line 244
    const/16 v18, 0x0

    .line 245
    .line 246
    const/16 v19, 0x0

    .line 247
    .line 248
    const/16 v20, 0x0

    .line 249
    .line 250
    const/16 v21, 0x0

    .line 251
    .line 252
    const/16 v22, 0x0

    .line 253
    .line 254
    const/16 v24, 0x0

    .line 255
    .line 256
    move-object/from16 v23, v1

    .line 257
    .line 258
    invoke-static/range {v4 .. v26}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 259
    .line 260
    .line 261
    goto :goto_4

    .line 262
    :cond_7
    move-object/from16 v23, v1

    .line 263
    .line 264
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 265
    .line 266
    .line 267
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 268
    .line 269
    return-object v0

    .line 270
    :pswitch_1
    move-object/from16 v1, p1

    .line 271
    .line 272
    check-cast v1, Ll2/o;

    .line 273
    .line 274
    move-object/from16 v2, p2

    .line 275
    .line 276
    check-cast v2, Ljava/lang/Number;

    .line 277
    .line 278
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 279
    .line 280
    .line 281
    move-result v2

    .line 282
    and-int/lit8 v3, v2, 0x3

    .line 283
    .line 284
    const/4 v4, 0x2

    .line 285
    const/4 v5, 0x1

    .line 286
    if-eq v3, v4, :cond_8

    .line 287
    .line 288
    move v3, v5

    .line 289
    goto :goto_5

    .line 290
    :cond_8
    const/4 v3, 0x0

    .line 291
    :goto_5
    and-int/2addr v2, v5

    .line 292
    check-cast v1, Ll2/t;

    .line 293
    .line 294
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 295
    .line 296
    .line 297
    move-result v2

    .line 298
    if-eqz v2, :cond_9

    .line 299
    .line 300
    iget-object v2, v0, Lh2/t3;->e:Ljava/lang/Object;

    .line 301
    .line 302
    move-object v4, v2

    .line 303
    check-cast v4, Ljava/lang/String;

    .line 304
    .line 305
    const/16 v25, 0x0

    .line 306
    .line 307
    const v26, 0x3fffa

    .line 308
    .line 309
    .line 310
    const/4 v5, 0x0

    .line 311
    iget-wide v6, v0, Lh2/t3;->f:J

    .line 312
    .line 313
    const-wide/16 v8, 0x0

    .line 314
    .line 315
    const/4 v10, 0x0

    .line 316
    const-wide/16 v11, 0x0

    .line 317
    .line 318
    const/4 v13, 0x0

    .line 319
    const/4 v14, 0x0

    .line 320
    const-wide/16 v15, 0x0

    .line 321
    .line 322
    const/16 v17, 0x0

    .line 323
    .line 324
    const/16 v18, 0x0

    .line 325
    .line 326
    const/16 v19, 0x0

    .line 327
    .line 328
    const/16 v20, 0x0

    .line 329
    .line 330
    const/16 v21, 0x0

    .line 331
    .line 332
    const/16 v22, 0x0

    .line 333
    .line 334
    const/16 v24, 0x0

    .line 335
    .line 336
    move-object/from16 v23, v1

    .line 337
    .line 338
    invoke-static/range {v4 .. v26}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 339
    .line 340
    .line 341
    goto :goto_6

    .line 342
    :cond_9
    move-object/from16 v23, v1

    .line 343
    .line 344
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 345
    .line 346
    .line 347
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 348
    .line 349
    return-object v0

    .line 350
    nop

    .line 351
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
