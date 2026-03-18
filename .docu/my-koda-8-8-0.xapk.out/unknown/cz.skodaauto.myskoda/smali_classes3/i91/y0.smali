.class public final Li91/y0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# static fields
.field public static final b:Li91/y0;

.field public static final c:Li91/y0;


# instance fields
.field public final synthetic a:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Li91/y0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Li91/y0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Li91/y0;->b:Li91/y0;

    .line 8
    .line 9
    new-instance v0, Li91/y0;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Li91/y0;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Li91/y0;->c:Li91/y0;

    .line 16
    .line 17
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Li91/y0;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 16

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p0

    .line 6
    .line 7
    iget v2, v2, Li91/y0;->a:I

    .line 8
    .line 9
    packed-switch v2, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    const-string v2, "$this$Layout"

    .line 13
    .line 14
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v2, "measurables"

    .line 18
    .line 19
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    check-cast v4, Lt3/p0;

    .line 32
    .line 33
    const/16 v5, 0x18

    .line 34
    .line 35
    int-to-float v5, v5

    .line 36
    invoke-interface {v0, v5}, Lt4/c;->Q(F)I

    .line 37
    .line 38
    .line 39
    move-result v6

    .line 40
    invoke-interface {v0, v5}, Lt4/c;->Q(F)I

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    const/4 v7, 0x1

    .line 45
    if-ltz v6, :cond_0

    .line 46
    .line 47
    move v8, v7

    .line 48
    goto :goto_0

    .line 49
    :cond_0
    move v8, v2

    .line 50
    :goto_0
    if-ltz v5, :cond_1

    .line 51
    .line 52
    move v9, v7

    .line 53
    goto :goto_1

    .line 54
    :cond_1
    move v9, v2

    .line 55
    :goto_1
    and-int/2addr v8, v9

    .line 56
    if-nez v8, :cond_2

    .line 57
    .line 58
    const-string v8, "width and height must be >= 0"

    .line 59
    .line 60
    invoke-static {v8}, Lt4/i;->a(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    :cond_2
    invoke-static {v6, v6, v5, v5}, Lt4/b;->h(IIII)J

    .line 64
    .line 65
    .line 66
    move-result-wide v5

    .line 67
    invoke-interface {v4, v5, v6}, Lt3/p0;->L(J)Lt3/e1;

    .line 68
    .line 69
    .line 70
    move-result-object v9

    .line 71
    iget v4, v9, Lt3/e1;->d:I

    .line 72
    .line 73
    const/16 v5, 0x8

    .line 74
    .line 75
    int-to-float v5, v5

    .line 76
    invoke-interface {v0, v5}, Lt4/c;->Q(F)I

    .line 77
    .line 78
    .line 79
    move-result v5

    .line 80
    add-int v12, v5, v4

    .line 81
    .line 82
    invoke-static/range {p3 .. p4}, Lt4/a;->h(J)I

    .line 83
    .line 84
    .line 85
    move-result v4

    .line 86
    sub-int/2addr v4, v12

    .line 87
    const/16 v5, 0xd

    .line 88
    .line 89
    invoke-static {v4, v2, v5}, Lt4/b;->b(III)J

    .line 90
    .line 91
    .line 92
    move-result-wide v4

    .line 93
    invoke-interface {v1, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    check-cast v2, Lt3/p0;

    .line 98
    .line 99
    invoke-interface {v2, v4, v5}, Lt3/p0;->L(J)Lt3/e1;

    .line 100
    .line 101
    .line 102
    move-result-object v11

    .line 103
    const/4 v2, 0x2

    .line 104
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    check-cast v1, Lt3/p0;

    .line 109
    .line 110
    invoke-interface {v1, v4, v5}, Lt3/p0;->L(J)Lt3/e1;

    .line 111
    .line 112
    .line 113
    move-result-object v14

    .line 114
    iget v1, v9, Lt3/e1;->e:I

    .line 115
    .line 116
    iget v4, v11, Lt3/e1;->e:I

    .line 117
    .line 118
    sub-int/2addr v1, v4

    .line 119
    invoke-static {v1}, Ljava/lang/Math;->abs(I)I

    .line 120
    .line 121
    .line 122
    move-result v1

    .line 123
    div-int/2addr v1, v2

    .line 124
    iget v2, v9, Lt3/e1;->e:I

    .line 125
    .line 126
    iget v4, v11, Lt3/e1;->e:I

    .line 127
    .line 128
    if-le v2, v4, :cond_3

    .line 129
    .line 130
    new-instance v2, Llx0/l;

    .line 131
    .line 132
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    invoke-direct {v2, v1, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    goto :goto_2

    .line 140
    :cond_3
    new-instance v2, Llx0/l;

    .line 141
    .line 142
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    invoke-direct {v2, v3, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    :goto_2
    iget-object v1, v2, Llx0/l;->d:Ljava/lang/Object;

    .line 150
    .line 151
    check-cast v1, Ljava/lang/Number;

    .line 152
    .line 153
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 154
    .line 155
    .line 156
    move-result v13

    .line 157
    iget-object v1, v2, Llx0/l;->e:Ljava/lang/Object;

    .line 158
    .line 159
    check-cast v1, Ljava/lang/Number;

    .line 160
    .line 161
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 162
    .line 163
    .line 164
    move-result v10

    .line 165
    iget v1, v11, Lt3/e1;->e:I

    .line 166
    .line 167
    add-int v15, v13, v1

    .line 168
    .line 169
    iget v2, v9, Lt3/e1;->e:I

    .line 170
    .line 171
    invoke-static {v2, v1}, Ljava/lang/Math;->max(II)I

    .line 172
    .line 173
    .line 174
    move-result v1

    .line 175
    iget v2, v14, Lt3/e1;->e:I

    .line 176
    .line 177
    add-int/2addr v1, v2

    .line 178
    invoke-static/range {p3 .. p4}, Lt4/a;->h(J)I

    .line 179
    .line 180
    .line 181
    move-result v2

    .line 182
    new-instance v8, Li91/z0;

    .line 183
    .line 184
    invoke-direct/range {v8 .. v15}, Li91/z0;-><init>(Lt3/e1;ILt3/e1;IILt3/e1;I)V

    .line 185
    .line 186
    .line 187
    sget-object v3, Lmx0/t;->d:Lmx0/t;

    .line 188
    .line 189
    invoke-interface {v0, v2, v1, v3, v8}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 190
    .line 191
    .line 192
    move-result-object v0

    .line 193
    return-object v0

    .line 194
    :pswitch_0
    const-string v2, "$this$Layout"

    .line 195
    .line 196
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    const-string v2, "measurables"

    .line 200
    .line 201
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 202
    .line 203
    .line 204
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 205
    .line 206
    .line 207
    move-result v2

    .line 208
    sget-object v3, Lmx0/t;->d:Lmx0/t;

    .line 209
    .line 210
    const/4 v4, 0x1

    .line 211
    if-gt v2, v4, :cond_7

    .line 212
    .line 213
    invoke-static {v1}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v1

    .line 217
    check-cast v1, Lt3/p0;

    .line 218
    .line 219
    move-wide/from16 v5, p3

    .line 220
    .line 221
    if-eqz v1, :cond_4

    .line 222
    .line 223
    invoke-interface {v1, v5, v6}, Lt3/p0;->L(J)Lt3/e1;

    .line 224
    .line 225
    .line 226
    move-result-object v1

    .line 227
    goto :goto_3

    .line 228
    :cond_4
    const/4 v1, 0x0

    .line 229
    :goto_3
    if-eqz v1, :cond_5

    .line 230
    .line 231
    iget v2, v1, Lt3/e1;->d:I

    .line 232
    .line 233
    goto :goto_4

    .line 234
    :cond_5
    invoke-static {v5, v6}, Lt4/a;->h(J)I

    .line 235
    .line 236
    .line 237
    move-result v2

    .line 238
    :goto_4
    if-eqz v1, :cond_6

    .line 239
    .line 240
    iget v4, v1, Lt3/e1;->e:I

    .line 241
    .line 242
    goto :goto_5

    .line 243
    :cond_6
    invoke-static {v5, v6}, Lt4/a;->i(J)I

    .line 244
    .line 245
    .line 246
    move-result v4

    .line 247
    :goto_5
    new-instance v5, Lam/a;

    .line 248
    .line 249
    const/16 v6, 0x9

    .line 250
    .line 251
    invoke-direct {v5, v1, v6}, Lam/a;-><init>(Lt3/e1;I)V

    .line 252
    .line 253
    .line 254
    invoke-interface {v0, v2, v4, v3, v5}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 255
    .line 256
    .line 257
    move-result-object v0

    .line 258
    goto :goto_6

    .line 259
    :cond_7
    move-wide/from16 v5, p3

    .line 260
    .line 261
    const/16 v2, 0x8

    .line 262
    .line 263
    int-to-float v2, v2

    .line 264
    invoke-interface {v0, v2}, Lt4/c;->Q(F)I

    .line 265
    .line 266
    .line 267
    move-result v2

    .line 268
    invoke-interface {v1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    move-result-object v4

    .line 272
    move-object v11, v4

    .line 273
    check-cast v11, Lt3/p0;

    .line 274
    .line 275
    invoke-static {v5, v6}, Lt4/a;->h(J)I

    .line 276
    .line 277
    .line 278
    move-result v4

    .line 279
    div-int/lit8 v7, v4, 0x2

    .line 280
    .line 281
    const/4 v9, 0x0

    .line 282
    const/16 v10, 0xc

    .line 283
    .line 284
    const/4 v6, 0x0

    .line 285
    const/4 v8, 0x0

    .line 286
    move-wide/from16 v4, p3

    .line 287
    .line 288
    invoke-static/range {v4 .. v10}, Lt4/a;->a(JIIIII)J

    .line 289
    .line 290
    .line 291
    move-result-wide v6

    .line 292
    invoke-interface {v11, v6, v7}, Lt3/p0;->L(J)Lt3/e1;

    .line 293
    .line 294
    .line 295
    move-result-object v11

    .line 296
    invoke-static/range {p3 .. p4}, Lt4/a;->h(J)I

    .line 297
    .line 298
    .line 299
    move-result v4

    .line 300
    iget v5, v11, Lt3/e1;->d:I

    .line 301
    .line 302
    sub-int/2addr v4, v5

    .line 303
    sub-int/2addr v4, v2

    .line 304
    const/4 v5, 0x0

    .line 305
    invoke-static {v5, v4}, Ljava/lang/Math;->max(II)I

    .line 306
    .line 307
    .line 308
    move-result v6

    .line 309
    invoke-interface {v1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    move-result-object v1

    .line 313
    check-cast v1, Lt3/p0;

    .line 314
    .line 315
    move v7, v6

    .line 316
    move-wide/from16 v4, p3

    .line 317
    .line 318
    invoke-static/range {v4 .. v10}, Lt4/a;->a(JIIIII)J

    .line 319
    .line 320
    .line 321
    move-result-wide v6

    .line 322
    invoke-interface {v1, v6, v7}, Lt3/p0;->L(J)Lt3/e1;

    .line 323
    .line 324
    .line 325
    move-result-object v1

    .line 326
    iget v4, v11, Lt3/e1;->e:I

    .line 327
    .line 328
    iget v5, v1, Lt3/e1;->e:I

    .line 329
    .line 330
    invoke-static/range {p3 .. p4}, Lt4/a;->i(J)I

    .line 331
    .line 332
    .line 333
    move-result v6

    .line 334
    invoke-static {v5, v6}, Ljava/lang/Math;->max(II)I

    .line 335
    .line 336
    .line 337
    move-result v5

    .line 338
    invoke-static {v4, v5}, Ljava/lang/Math;->max(II)I

    .line 339
    .line 340
    .line 341
    move-result v4

    .line 342
    iget v5, v11, Lt3/e1;->e:I

    .line 343
    .line 344
    sub-int v5, v4, v5

    .line 345
    .line 346
    div-int/lit8 v5, v5, 0x2

    .line 347
    .line 348
    invoke-static/range {p3 .. p4}, Lt4/a;->h(J)I

    .line 349
    .line 350
    .line 351
    move-result v6

    .line 352
    new-instance v7, Li91/x0;

    .line 353
    .line 354
    invoke-direct {v7, v1, v11, v2, v5}, Li91/x0;-><init>(Lt3/e1;Lt3/e1;II)V

    .line 355
    .line 356
    .line 357
    invoke-interface {v0, v6, v4, v3, v7}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 358
    .line 359
    .line 360
    move-result-object v0

    .line 361
    :goto_6
    return-object v0

    .line 362
    nop

    .line 363
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
