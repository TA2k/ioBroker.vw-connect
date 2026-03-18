.class public final synthetic Lh1/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:Lkotlin/jvm/internal/c0;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(FLkotlin/jvm/internal/c0;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p5, p0, Lh1/h;->d:I

    .line 2
    .line 3
    iput p1, p0, Lh1/h;->e:F

    .line 4
    .line 5
    iput-object p2, p0, Lh1/h;->f:Lkotlin/jvm/internal/c0;

    .line 6
    .line 7
    iput-object p3, p0, Lh1/h;->g:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Lh1/h;->h:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lh1/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh1/h;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lg1/p;

    .line 9
    .line 10
    iget-object v1, p0, Lh1/h;->h:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lkotlin/jvm/internal/c0;

    .line 13
    .line 14
    check-cast p1, Lc1/i;

    .line 15
    .line 16
    iget-object v2, p1, Lc1/i;->e:Ll2/j1;

    .line 17
    .line 18
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    check-cast v3, Ljava/lang/Number;

    .line 23
    .line 24
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    iget v4, p0, Lh1/h;->e:F

    .line 29
    .line 30
    cmpg-float v3, v3, v4

    .line 31
    .line 32
    iget-object p0, p0, Lh1/h;->f:Lkotlin/jvm/internal/c0;

    .line 33
    .line 34
    if-gez v3, :cond_0

    .line 35
    .line 36
    iget v3, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 37
    .line 38
    cmpl-float v3, v3, v4

    .line 39
    .line 40
    if-gtz v3, :cond_1

    .line 41
    .line 42
    :cond_0
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    check-cast v3, Ljava/lang/Number;

    .line 47
    .line 48
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 49
    .line 50
    .line 51
    move-result v3

    .line 52
    cmpl-float v3, v3, v4

    .line 53
    .line 54
    if-lez v3, :cond_6

    .line 55
    .line 56
    iget v3, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 57
    .line 58
    cmpg-float v3, v3, v4

    .line 59
    .line 60
    if-gez v3, :cond_6

    .line 61
    .line 62
    :cond_1
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    check-cast v2, Ljava/lang/Number;

    .line 67
    .line 68
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    const/4 v3, 0x0

    .line 73
    cmpg-float v5, v4, v3

    .line 74
    .line 75
    if-nez v5, :cond_2

    .line 76
    .line 77
    move v4, v3

    .line 78
    goto :goto_0

    .line 79
    :cond_2
    cmpl-float v5, v4, v3

    .line 80
    .line 81
    if-lez v5, :cond_3

    .line 82
    .line 83
    cmpl-float v5, v2, v4

    .line 84
    .line 85
    if-lez v5, :cond_4

    .line 86
    .line 87
    goto :goto_0

    .line 88
    :cond_3
    cmpg-float v5, v2, v4

    .line 89
    .line 90
    if-gez v5, :cond_4

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_4
    move v4, v2

    .line 94
    :goto_0
    invoke-virtual {p1}, Lc1/i;->b()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    check-cast v2, Ljava/lang/Number;

    .line 99
    .line 100
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 101
    .line 102
    .line 103
    move-result v2

    .line 104
    invoke-virtual {v0, v4, v2}, Lg1/p;->a(FF)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {p1}, Lc1/i;->b()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    check-cast v0, Ljava/lang/Number;

    .line 112
    .line 113
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 114
    .line 115
    .line 116
    move-result v0

    .line 117
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 118
    .line 119
    .line 120
    move-result v0

    .line 121
    if-eqz v0, :cond_5

    .line 122
    .line 123
    goto :goto_1

    .line 124
    :cond_5
    invoke-virtual {p1}, Lc1/i;->b()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    check-cast v0, Ljava/lang/Number;

    .line 129
    .line 130
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 131
    .line 132
    .line 133
    move-result v3

    .line 134
    :goto_1
    iput v3, v1, Lkotlin/jvm/internal/c0;->d:F

    .line 135
    .line 136
    iput v4, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 137
    .line 138
    invoke-virtual {p1}, Lc1/i;->a()V

    .line 139
    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_6
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v3

    .line 146
    check-cast v3, Ljava/lang/Number;

    .line 147
    .line 148
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 149
    .line 150
    .line 151
    move-result v3

    .line 152
    invoke-virtual {p1}, Lc1/i;->b()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v4

    .line 156
    check-cast v4, Ljava/lang/Number;

    .line 157
    .line 158
    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    .line 159
    .line 160
    .line 161
    move-result v4

    .line 162
    invoke-virtual {v0, v3, v4}, Lg1/p;->a(FF)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {p1}, Lc1/i;->b()Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object p1

    .line 169
    check-cast p1, Ljava/lang/Number;

    .line 170
    .line 171
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 172
    .line 173
    .line 174
    move-result p1

    .line 175
    iput p1, v1, Lkotlin/jvm/internal/c0;->d:F

    .line 176
    .line 177
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object p1

    .line 181
    check-cast p1, Ljava/lang/Number;

    .line 182
    .line 183
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 184
    .line 185
    .line 186
    move-result p1

    .line 187
    iput p1, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 188
    .line 189
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 190
    .line 191
    return-object p0

    .line 192
    :pswitch_0
    iget-object v0, p0, Lh1/h;->g:Ljava/lang/Object;

    .line 193
    .line 194
    check-cast v0, Lg1/e2;

    .line 195
    .line 196
    iget-object v1, p0, Lh1/h;->h:Ljava/lang/Object;

    .line 197
    .line 198
    check-cast v1, Lay0/k;

    .line 199
    .line 200
    check-cast p1, Lc1/i;

    .line 201
    .line 202
    iget-object v2, p1, Lc1/i;->e:Ll2/j1;

    .line 203
    .line 204
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v2

    .line 208
    check-cast v2, Ljava/lang/Number;

    .line 209
    .line 210
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 211
    .line 212
    .line 213
    move-result v2

    .line 214
    iget v3, p0, Lh1/h;->e:F

    .line 215
    .line 216
    invoke-static {v2, v3}, Lh1/k;->d(FF)F

    .line 217
    .line 218
    .line 219
    move-result v2

    .line 220
    iget-object p0, p0, Lh1/h;->f:Lkotlin/jvm/internal/c0;

    .line 221
    .line 222
    iget v3, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 223
    .line 224
    sub-float v3, v2, v3

    .line 225
    .line 226
    :try_start_0
    invoke-interface {v0, v3}, Lg1/e2;->a(F)F

    .line 227
    .line 228
    .line 229
    move-result v0
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0

    .line 230
    goto :goto_3

    .line 231
    :catch_0
    invoke-virtual {p1}, Lc1/i;->a()V

    .line 232
    .line 233
    .line 234
    const/4 v0, 0x0

    .line 235
    :goto_3
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 236
    .line 237
    .line 238
    move-result-object v4

    .line 239
    invoke-interface {v1, v4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    sub-float/2addr v3, v0

    .line 243
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    .line 244
    .line 245
    .line 246
    move-result v1

    .line 247
    const/high16 v3, 0x3f000000    # 0.5f

    .line 248
    .line 249
    cmpl-float v1, v1, v3

    .line 250
    .line 251
    if-gtz v1, :cond_7

    .line 252
    .line 253
    iget-object v1, p1, Lc1/i;->e:Ll2/j1;

    .line 254
    .line 255
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v1

    .line 259
    check-cast v1, Ljava/lang/Number;

    .line 260
    .line 261
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 262
    .line 263
    .line 264
    move-result v1

    .line 265
    cmpg-float v1, v2, v1

    .line 266
    .line 267
    if-nez v1, :cond_7

    .line 268
    .line 269
    goto :goto_4

    .line 270
    :cond_7
    invoke-virtual {p1}, Lc1/i;->a()V

    .line 271
    .line 272
    .line 273
    :goto_4
    iget p1, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 274
    .line 275
    add-float/2addr p1, v0

    .line 276
    iput p1, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 277
    .line 278
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 279
    .line 280
    return-object p0

    .line 281
    :pswitch_1
    iget-object v0, p0, Lh1/h;->g:Ljava/lang/Object;

    .line 282
    .line 283
    check-cast v0, Lg1/e2;

    .line 284
    .line 285
    iget-object v1, p0, Lh1/h;->h:Ljava/lang/Object;

    .line 286
    .line 287
    check-cast v1, Lay0/k;

    .line 288
    .line 289
    check-cast p1, Lc1/i;

    .line 290
    .line 291
    iget-object v2, p1, Lc1/i;->e:Ll2/j1;

    .line 292
    .line 293
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 294
    .line 295
    .line 296
    move-result-object v3

    .line 297
    check-cast v3, Ljava/lang/Number;

    .line 298
    .line 299
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 300
    .line 301
    .line 302
    move-result v3

    .line 303
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    .line 304
    .line 305
    .line 306
    move-result v3

    .line 307
    iget v4, p0, Lh1/h;->e:F

    .line 308
    .line 309
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    .line 310
    .line 311
    .line 312
    move-result v5

    .line 313
    cmpl-float v3, v3, v5

    .line 314
    .line 315
    iget-object p0, p0, Lh1/h;->f:Lkotlin/jvm/internal/c0;

    .line 316
    .line 317
    if-ltz v3, :cond_8

    .line 318
    .line 319
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 320
    .line 321
    .line 322
    move-result-object v2

    .line 323
    check-cast v2, Ljava/lang/Number;

    .line 324
    .line 325
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 326
    .line 327
    .line 328
    move-result v2

    .line 329
    invoke-static {v2, v4}, Lh1/k;->d(FF)F

    .line 330
    .line 331
    .line 332
    move-result v2

    .line 333
    iget v3, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 334
    .line 335
    sub-float v3, v2, v3

    .line 336
    .line 337
    invoke-static {p1, v0, v1, v3}, Lh1/k;->c(Lc1/i;Lg1/e2;Lay0/k;F)V

    .line 338
    .line 339
    .line 340
    invoke-virtual {p1}, Lc1/i;->a()V

    .line 341
    .line 342
    .line 343
    iput v2, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 344
    .line 345
    goto :goto_5

    .line 346
    :cond_8
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    move-result-object v3

    .line 350
    check-cast v3, Ljava/lang/Number;

    .line 351
    .line 352
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 353
    .line 354
    .line 355
    move-result v3

    .line 356
    iget v4, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 357
    .line 358
    sub-float/2addr v3, v4

    .line 359
    invoke-static {p1, v0, v1, v3}, Lh1/k;->c(Lc1/i;Lg1/e2;Lay0/k;F)V

    .line 360
    .line 361
    .line 362
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 363
    .line 364
    .line 365
    move-result-object p1

    .line 366
    check-cast p1, Ljava/lang/Number;

    .line 367
    .line 368
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 369
    .line 370
    .line 371
    move-result p1

    .line 372
    iput p1, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 373
    .line 374
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 375
    .line 376
    return-object p0

    .line 377
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
