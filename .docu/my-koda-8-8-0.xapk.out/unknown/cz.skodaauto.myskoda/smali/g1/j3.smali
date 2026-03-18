.class public final synthetic Lg1/j3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(FLjava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, Lg1/j3;->d:I

    iput p1, p0, Lg1/j3;->e:F

    iput-object p2, p0, Lg1/j3;->f:Ljava/lang/Object;

    iput-object p3, p0, Lg1/j3;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lg1/l3;FLay0/k;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lg1/j3;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lg1/j3;->f:Ljava/lang/Object;

    iput p2, p0, Lg1/j3;->e:F

    iput-object p3, p0, Lg1/j3;->g:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lg1/j3;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lg1/j3;->e:F

    .line 7
    .line 8
    iget-object v1, p0, Lg1/j3;->f:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v3, v1

    .line 11
    check-cast v3, Le3/f;

    .line 12
    .line 13
    iget-object p0, p0, Lg1/j3;->g:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v7, p0

    .line 16
    check-cast v7, Le3/m;

    .line 17
    .line 18
    move-object v2, p1

    .line 19
    check-cast v2, Lv3/j0;

    .line 20
    .line 21
    invoke-virtual {v2}, Lv3/j0;->b()V

    .line 22
    .line 23
    .line 24
    iget-object p0, v2, Lv3/j0;->d:Lg3/b;

    .line 25
    .line 26
    iget-object p0, p0, Lg3/b;->e:Lgw0/c;

    .line 27
    .line 28
    invoke-virtual {p0}, Lgw0/c;->o()J

    .line 29
    .line 30
    .line 31
    move-result-wide v9

    .line 32
    invoke-virtual {p0}, Lgw0/c;->h()Le3/r;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    invoke-interface {p1}, Le3/r;->o()V

    .line 37
    .line 38
    .line 39
    :try_start_0
    iget-object p1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p1, Lbu/c;

    .line 42
    .line 43
    const/4 v1, 0x0

    .line 44
    invoke-virtual {p1, v0, v1}, Lbu/c;->B(FF)V

    .line 45
    .line 46
    .line 47
    const/high16 v0, 0x42340000    # 45.0f

    .line 48
    .line 49
    const-wide/16 v4, 0x0

    .line 50
    .line 51
    invoke-virtual {p1, v4, v5, v0}, Lbu/c;->z(JF)V

    .line 52
    .line 53
    .line 54
    const/4 v6, 0x0

    .line 55
    const/16 v8, 0x2e

    .line 56
    .line 57
    const-wide/16 v4, 0x0

    .line 58
    .line 59
    invoke-static/range {v2 .. v8}, Lg3/d;->v(Lg3/d;Le3/f;JFLe3/m;I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 60
    .line 61
    .line 62
    invoke-static {p0, v9, v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 63
    .line 64
    .line 65
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 66
    .line 67
    return-object p0

    .line 68
    :catchall_0
    move-exception v0

    .line 69
    move-object p1, v0

    .line 70
    invoke-static {p0, v9, v10}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 71
    .line 72
    .line 73
    throw p1

    .line 74
    :pswitch_0
    iget-object v0, p0, Lg1/j3;->f:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v0, Lkotlin/jvm/internal/c0;

    .line 77
    .line 78
    iget-object v1, p0, Lg1/j3;->g:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v1, Lm1/p;

    .line 81
    .line 82
    check-cast p1, Lc1/i;

    .line 83
    .line 84
    iget p0, p0, Lg1/j3;->e:F

    .line 85
    .line 86
    const/4 v2, 0x0

    .line 87
    cmpl-float v3, p0, v2

    .line 88
    .line 89
    if-lez v3, :cond_1

    .line 90
    .line 91
    iget-object v2, p1, Lc1/i;->e:Ll2/j1;

    .line 92
    .line 93
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    check-cast v2, Ljava/lang/Number;

    .line 98
    .line 99
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 100
    .line 101
    .line 102
    move-result v2

    .line 103
    cmpl-float v3, v2, p0

    .line 104
    .line 105
    if-lez v3, :cond_0

    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_0
    move p0, v2

    .line 109
    :goto_1
    move v2, p0

    .line 110
    goto :goto_2

    .line 111
    :cond_1
    cmpg-float v3, p0, v2

    .line 112
    .line 113
    if-gez v3, :cond_2

    .line 114
    .line 115
    iget-object v2, p1, Lc1/i;->e:Ll2/j1;

    .line 116
    .line 117
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v2

    .line 121
    check-cast v2, Ljava/lang/Number;

    .line 122
    .line 123
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 124
    .line 125
    .line 126
    move-result v2

    .line 127
    cmpg-float v3, v2, p0

    .line 128
    .line 129
    if-gez v3, :cond_0

    .line 130
    .line 131
    goto :goto_1

    .line 132
    :cond_2
    :goto_2
    iget p0, v0, Lkotlin/jvm/internal/c0;->d:F

    .line 133
    .line 134
    sub-float p0, v2, p0

    .line 135
    .line 136
    invoke-interface {v1, p0}, Lg1/e2;->a(F)F

    .line 137
    .line 138
    .line 139
    move-result v1

    .line 140
    cmpg-float v1, p0, v1

    .line 141
    .line 142
    if-nez v1, :cond_3

    .line 143
    .line 144
    iget-object v1, p1, Lc1/i;->e:Ll2/j1;

    .line 145
    .line 146
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v1

    .line 150
    check-cast v1, Ljava/lang/Number;

    .line 151
    .line 152
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 153
    .line 154
    .line 155
    move-result v1

    .line 156
    cmpg-float v1, v2, v1

    .line 157
    .line 158
    if-nez v1, :cond_3

    .line 159
    .line 160
    goto :goto_3

    .line 161
    :cond_3
    invoke-virtual {p1}, Lc1/i;->a()V

    .line 162
    .line 163
    .line 164
    :goto_3
    iget p1, v0, Lkotlin/jvm/internal/c0;->d:F

    .line 165
    .line 166
    add-float/2addr p1, p0

    .line 167
    iput p1, v0, Lkotlin/jvm/internal/c0;->d:F

    .line 168
    .line 169
    goto :goto_0

    .line 170
    :pswitch_1
    iget-object v0, p0, Lg1/j3;->f:Ljava/lang/Object;

    .line 171
    .line 172
    check-cast v0, Ll2/b1;

    .line 173
    .line 174
    iget-object v1, p0, Lg1/j3;->g:Ljava/lang/Object;

    .line 175
    .line 176
    check-cast v1, Lt4/m;

    .line 177
    .line 178
    check-cast p1, Lt3/y;

    .line 179
    .line 180
    const-string v2, "coordinates"

    .line 181
    .line 182
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    invoke-interface {p1}, Lt3/y;->O()Lt3/y;

    .line 186
    .line 187
    .line 188
    move-result-object p1

    .line 189
    iget p0, p0, Lg1/j3;->e:F

    .line 190
    .line 191
    if-eqz p1, :cond_4

    .line 192
    .line 193
    invoke-static {p1}, Lt3/k1;->i(Lt3/y;)Lt3/y;

    .line 194
    .line 195
    .line 196
    move-result-object v2

    .line 197
    const/4 v3, 0x1

    .line 198
    invoke-interface {v2, p1, v3}, Lt3/y;->P(Lt3/y;Z)Ld3/c;

    .line 199
    .line 200
    .line 201
    move-result-object p1

    .line 202
    iget v2, p1, Ld3/c;->d:F

    .line 203
    .line 204
    iget p1, p1, Ld3/c;->b:F

    .line 205
    .line 206
    sub-float/2addr v2, p1

    .line 207
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 208
    .line 209
    .line 210
    move-result-object p1

    .line 211
    invoke-static {p1}, Lxf0/i0;->N(Ljava/lang/Number;)F

    .line 212
    .line 213
    .line 214
    move-result p1

    .line 215
    goto :goto_4

    .line 216
    :cond_4
    move p1, p0

    .line 217
    :goto_4
    cmpl-float v2, p1, p0

    .line 218
    .line 219
    if-lez v2, :cond_5

    .line 220
    .line 221
    goto :goto_5

    .line 222
    :cond_5
    move p0, p1

    .line 223
    :goto_5
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object p1

    .line 227
    check-cast p1, Lk1/z0;

    .line 228
    .line 229
    sget v2, Li50/s;->c:F

    .line 230
    .line 231
    add-float/2addr p0, v2

    .line 232
    const/16 v2, 0xe

    .line 233
    .line 234
    const/4 v3, 0x0

    .line 235
    invoke-static {p1, v1, v3, p0, v2}, Lxf0/y1;->z(Lk1/z0;Lt4/m;FFI)Lk1/a1;

    .line 236
    .line 237
    .line 238
    move-result-object p0

    .line 239
    invoke-interface {v0, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 240
    .line 241
    .line 242
    goto/16 :goto_0

    .line 243
    .line 244
    :pswitch_2
    iget-object v0, p0, Lg1/j3;->f:Ljava/lang/Object;

    .line 245
    .line 246
    check-cast v0, Lg1/l3;

    .line 247
    .line 248
    iget-object v1, p0, Lg1/j3;->g:Ljava/lang/Object;

    .line 249
    .line 250
    check-cast v1, Lay0/k;

    .line 251
    .line 252
    check-cast p1, Ljava/lang/Long;

    .line 253
    .line 254
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 255
    .line 256
    .line 257
    move-result-wide v2

    .line 258
    iget-wide v4, v0, Lg1/l3;->b:J

    .line 259
    .line 260
    const-wide/high16 v6, -0x8000000000000000L

    .line 261
    .line 262
    cmp-long p1, v4, v6

    .line 263
    .line 264
    if-nez p1, :cond_6

    .line 265
    .line 266
    iput-wide v2, v0, Lg1/l3;->b:J

    .line 267
    .line 268
    :cond_6
    new-instance v7, Lc1/l;

    .line 269
    .line 270
    iget p1, v0, Lg1/l3;->e:F

    .line 271
    .line 272
    invoke-direct {v7, p1}, Lc1/l;-><init>(F)V

    .line 273
    .line 274
    .line 275
    const/4 v4, 0x0

    .line 276
    iget p0, p0, Lg1/j3;->e:F

    .line 277
    .line 278
    cmpg-float v4, p0, v4

    .line 279
    .line 280
    sget-object v8, Lg1/l3;->f:Lc1/l;

    .line 281
    .line 282
    if-nez v4, :cond_7

    .line 283
    .line 284
    iget-object p0, v0, Lg1/l3;->a:Lc1/d2;

    .line 285
    .line 286
    new-instance v4, Lc1/l;

    .line 287
    .line 288
    invoke-direct {v4, p1}, Lc1/l;-><init>(F)V

    .line 289
    .line 290
    .line 291
    iget-object p1, v0, Lg1/l3;->c:Lc1/l;

    .line 292
    .line 293
    invoke-interface {p0, v4, v8, p1}, Lc1/d2;->h(Lc1/p;Lc1/p;Lc1/p;)J

    .line 294
    .line 295
    .line 296
    move-result-wide p0

    .line 297
    :goto_6
    move-wide v5, p0

    .line 298
    goto :goto_7

    .line 299
    :cond_7
    iget-wide v4, v0, Lg1/l3;->b:J

    .line 300
    .line 301
    sub-long v4, v2, v4

    .line 302
    .line 303
    long-to-float p1, v4

    .line 304
    div-float/2addr p1, p0

    .line 305
    float-to-double p0, p1

    .line 306
    invoke-static {p0, p1}, Lcy0/a;->j(D)J

    .line 307
    .line 308
    .line 309
    move-result-wide p0

    .line 310
    goto :goto_6

    .line 311
    :goto_7
    iget-object v4, v0, Lg1/l3;->a:Lc1/d2;

    .line 312
    .line 313
    iget-object v9, v0, Lg1/l3;->c:Lc1/l;

    .line 314
    .line 315
    invoke-interface/range {v4 .. v9}, Lc1/d2;->t(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;

    .line 316
    .line 317
    .line 318
    move-result-object p0

    .line 319
    check-cast p0, Lc1/l;

    .line 320
    .line 321
    iget p0, p0, Lc1/l;->a:F

    .line 322
    .line 323
    iget-object v4, v0, Lg1/l3;->a:Lc1/d2;

    .line 324
    .line 325
    iget-object v9, v0, Lg1/l3;->c:Lc1/l;

    .line 326
    .line 327
    invoke-interface/range {v4 .. v9}, Lc1/d2;->D(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;

    .line 328
    .line 329
    .line 330
    move-result-object p1

    .line 331
    check-cast p1, Lc1/l;

    .line 332
    .line 333
    iput-object p1, v0, Lg1/l3;->c:Lc1/l;

    .line 334
    .line 335
    iput-wide v2, v0, Lg1/l3;->b:J

    .line 336
    .line 337
    iget p1, v0, Lg1/l3;->e:F

    .line 338
    .line 339
    sub-float/2addr p1, p0

    .line 340
    iput p0, v0, Lg1/l3;->e:F

    .line 341
    .line 342
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 343
    .line 344
    .line 345
    move-result-object p0

    .line 346
    invoke-interface {v1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    goto/16 :goto_0

    .line 350
    .line 351
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
