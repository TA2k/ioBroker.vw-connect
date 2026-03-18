.class public final Lc4/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/ScrollCaptureCallback;


# instance fields
.field public final a:Ld4/q;

.field public final b:Lt4/k;

.field public final c:Laq/a;

.field public final d:Lw3/t;

.field public final e:Lpw0/a;

.field public final f:Lc4/h;


# direct methods
.method public constructor <init>(Ld4/q;Lt4/k;Lpw0/a;Laq/a;Lw3/t;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc4/e;->a:Ld4/q;

    .line 5
    .line 6
    iput-object p2, p0, Lc4/e;->b:Lt4/k;

    .line 7
    .line 8
    iput-object p4, p0, Lc4/e;->c:Laq/a;

    .line 9
    .line 10
    iput-object p5, p0, Lc4/e;->d:Lw3/t;

    .line 11
    .line 12
    sget-object p1, Lc4/f;->d:Lc4/f;

    .line 13
    .line 14
    invoke-static {p3, p1}, Lvy0/e0;->H(Lvy0/b0;Lpx0/e;)Lpw0/a;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iput-object p1, p0, Lc4/e;->e:Lpw0/a;

    .line 19
    .line 20
    new-instance p1, Lc4/h;

    .line 21
    .line 22
    invoke-virtual {p2}, Lt4/k;->b()I

    .line 23
    .line 24
    .line 25
    move-result p2

    .line 26
    new-instance p3, Lc4/d;

    .line 27
    .line 28
    const/4 p4, 0x0

    .line 29
    invoke-direct {p3, p0, p4}, Lc4/d;-><init>(Lc4/e;Lkotlin/coroutines/Continuation;)V

    .line 30
    .line 31
    .line 32
    invoke-direct {p1, p2, p3}, Lc4/h;-><init>(ILc4/d;)V

    .line 33
    .line 34
    .line 35
    iput-object p1, p0, Lc4/e;->f:Lc4/h;

    .line 36
    .line 37
    return-void
.end method

.method public static final a(Lc4/e;Landroid/view/ScrollCaptureSession;Lt4/k;Lrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p3, Lc4/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lc4/b;

    .line 7
    .line 8
    iget v1, v0, Lc4/b;->j:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lc4/b;->j:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lc4/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lc4/b;-><init>(Lc4/e;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lc4/b;->h:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lc4/b;->j:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    iget p1, v0, Lc4/b;->g:I

    .line 40
    .line 41
    iget p2, v0, Lc4/b;->f:I

    .line 42
    .line 43
    iget-object v1, v0, Lc4/b;->e:Lt4/k;

    .line 44
    .line 45
    iget-object v0, v0, Lc4/b;->d:Ljava/lang/Object;

    .line 46
    .line 47
    invoke-static {v0}, Lb8/h;->m(Ljava/lang/Object;)Landroid/view/ScrollCaptureSession;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    goto/16 :goto_6

    .line 55
    .line 56
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 57
    .line 58
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 59
    .line 60
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    throw p0

    .line 64
    :cond_2
    iget p1, v0, Lc4/b;->g:I

    .line 65
    .line 66
    iget p2, v0, Lc4/b;->f:I

    .line 67
    .line 68
    iget-object v2, v0, Lc4/b;->e:Lt4/k;

    .line 69
    .line 70
    iget-object v4, v0, Lc4/b;->d:Ljava/lang/Object;

    .line 71
    .line 72
    invoke-static {v4}, Lb8/h;->m(Ljava/lang/Object;)Landroid/view/ScrollCaptureSession;

    .line 73
    .line 74
    .line 75
    move-result-object v4

    .line 76
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    move p3, p2

    .line 80
    move-object p2, v2

    .line 81
    move v2, p1

    .line 82
    move-object p1, v4

    .line 83
    goto :goto_4

    .line 84
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    iget p3, p2, Lt4/k;->b:I

    .line 88
    .line 89
    iget v2, p2, Lt4/k;->d:I

    .line 90
    .line 91
    iget-object v5, p0, Lc4/e;->f:Lc4/h;

    .line 92
    .line 93
    iput-object p1, v0, Lc4/b;->d:Ljava/lang/Object;

    .line 94
    .line 95
    iput-object p2, v0, Lc4/b;->e:Lt4/k;

    .line 96
    .line 97
    iput p3, v0, Lc4/b;->f:I

    .line 98
    .line 99
    iput v2, v0, Lc4/b;->g:I

    .line 100
    .line 101
    iput v4, v0, Lc4/b;->j:I

    .line 102
    .line 103
    iget v4, v5, Lc4/h;->a:I

    .line 104
    .line 105
    if-gt p3, v2, :cond_c

    .line 106
    .line 107
    sub-int v6, v2, p3

    .line 108
    .line 109
    if-gt v6, v4, :cond_b

    .line 110
    .line 111
    int-to-float v6, p3

    .line 112
    iget v7, v5, Lc4/h;->b:F

    .line 113
    .line 114
    cmpl-float v8, v6, v7

    .line 115
    .line 116
    sget-object v9, Llx0/b0;->a:Llx0/b0;

    .line 117
    .line 118
    if-ltz v8, :cond_4

    .line 119
    .line 120
    int-to-float v8, v2

    .line 121
    int-to-float v10, v4

    .line 122
    add-float/2addr v10, v7

    .line 123
    cmpg-float v8, v8, v10

    .line 124
    .line 125
    if-gtz v8, :cond_4

    .line 126
    .line 127
    goto :goto_3

    .line 128
    :cond_4
    cmpg-float v6, v6, v7

    .line 129
    .line 130
    if-gez v6, :cond_5

    .line 131
    .line 132
    move v4, p3

    .line 133
    goto :goto_1

    .line 134
    :cond_5
    sub-int v4, v2, v4

    .line 135
    .line 136
    :goto_1
    int-to-float v4, v4

    .line 137
    sub-float/2addr v4, v7

    .line 138
    invoke-virtual {v5, v4, v0}, Lc4/h;->b(FLrx0/c;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v4

    .line 142
    if-ne v4, v1, :cond_6

    .line 143
    .line 144
    goto :goto_2

    .line 145
    :cond_6
    move-object v4, v9

    .line 146
    :goto_2
    if-ne v4, v1, :cond_7

    .line 147
    .line 148
    move-object v9, v4

    .line 149
    :cond_7
    :goto_3
    if-ne v9, v1, :cond_8

    .line 150
    .line 151
    goto :goto_5

    .line 152
    :cond_8
    :goto_4
    sget-object v4, Lc4/c;->g:Lc4/c;

    .line 153
    .line 154
    iput-object p1, v0, Lc4/b;->d:Ljava/lang/Object;

    .line 155
    .line 156
    iput-object p2, v0, Lc4/b;->e:Lt4/k;

    .line 157
    .line 158
    iput p3, v0, Lc4/b;->f:I

    .line 159
    .line 160
    iput v2, v0, Lc4/b;->g:I

    .line 161
    .line 162
    iput v3, v0, Lc4/b;->j:I

    .line 163
    .line 164
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 165
    .line 166
    .line 167
    move-result-object v3

    .line 168
    invoke-static {v3}, Ll2/b;->k(Lpx0/g;)Ll2/y0;

    .line 169
    .line 170
    .line 171
    move-result-object v3

    .line 172
    invoke-interface {v3, v4, v0}, Ll2/y0;->q(Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v0

    .line 176
    if-ne v0, v1, :cond_9

    .line 177
    .line 178
    :goto_5
    return-object v1

    .line 179
    :cond_9
    move-object v0, p1

    .line 180
    move-object v1, p2

    .line 181
    move p2, p3

    .line 182
    move p1, v2

    .line 183
    :goto_6
    iget-object p3, p0, Lc4/e;->f:Lc4/h;

    .line 184
    .line 185
    iget v2, p3, Lc4/h;->b:F

    .line 186
    .line 187
    invoke-static {v2}, Lcy0/a;->i(F)I

    .line 188
    .line 189
    .line 190
    move-result v2

    .line 191
    sub-int/2addr p2, v2

    .line 192
    iget p3, p3, Lc4/h;->a:I

    .line 193
    .line 194
    const/4 v2, 0x0

    .line 195
    invoke-static {p2, v2, p3}, Lkp/r9;->e(III)I

    .line 196
    .line 197
    .line 198
    move-result p2

    .line 199
    iget-object p3, p0, Lc4/e;->f:Lc4/h;

    .line 200
    .line 201
    iget v3, p3, Lc4/h;->b:F

    .line 202
    .line 203
    invoke-static {v3}, Lcy0/a;->i(F)I

    .line 204
    .line 205
    .line 206
    move-result v3

    .line 207
    sub-int/2addr p1, v3

    .line 208
    iget p3, p3, Lc4/h;->a:I

    .line 209
    .line 210
    invoke-static {p1, v2, p3}, Lkp/r9;->e(III)I

    .line 211
    .line 212
    .line 213
    move-result p1

    .line 214
    iget p3, v1, Lt4/k;->a:I

    .line 215
    .line 216
    iget v1, v1, Lt4/k;->c:I

    .line 217
    .line 218
    if-ne p2, p1, :cond_a

    .line 219
    .line 220
    sget-object p0, Lt4/k;->e:Lt4/k;

    .line 221
    .line 222
    return-object p0

    .line 223
    :cond_a
    invoke-static {v0}, Lc4/a;->p(Landroid/view/ScrollCaptureSession;)Landroid/view/Surface;

    .line 224
    .line 225
    .line 226
    move-result-object v2

    .line 227
    invoke-virtual {v2}, Landroid/view/Surface;->lockHardwareCanvas()Landroid/graphics/Canvas;

    .line 228
    .line 229
    .line 230
    move-result-object v2

    .line 231
    :try_start_0
    invoke-virtual {v2}, Landroid/graphics/Canvas;->save()I

    .line 232
    .line 233
    .line 234
    int-to-float v3, p3

    .line 235
    neg-float v3, v3

    .line 236
    int-to-float v4, p2

    .line 237
    neg-float v4, v4

    .line 238
    invoke-virtual {v2, v3, v4}, Landroid/graphics/Canvas;->translate(FF)V

    .line 239
    .line 240
    .line 241
    iget-object v3, p0, Lc4/e;->b:Lt4/k;

    .line 242
    .line 243
    iget v4, v3, Lt4/k;->a:I

    .line 244
    .line 245
    int-to-float v4, v4

    .line 246
    neg-float v4, v4

    .line 247
    iget v3, v3, Lt4/k;->b:I

    .line 248
    .line 249
    int-to-float v3, v3

    .line 250
    neg-float v3, v3

    .line 251
    invoke-virtual {v2, v4, v3}, Landroid/graphics/Canvas;->translate(FF)V

    .line 252
    .line 253
    .line 254
    iget-object v3, p0, Lc4/e;->d:Lw3/t;

    .line 255
    .line 256
    invoke-virtual {v3}, Landroid/view/View;->getRootView()Landroid/view/View;

    .line 257
    .line 258
    .line 259
    move-result-object v3

    .line 260
    invoke-virtual {v3, v2}, Landroid/view/View;->draw(Landroid/graphics/Canvas;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 261
    .line 262
    .line 263
    invoke-static {v0}, Lc4/a;->p(Landroid/view/ScrollCaptureSession;)Landroid/view/Surface;

    .line 264
    .line 265
    .line 266
    move-result-object v0

    .line 267
    invoke-virtual {v0, v2}, Landroid/view/Surface;->unlockCanvasAndPost(Landroid/graphics/Canvas;)V

    .line 268
    .line 269
    .line 270
    iget-object p0, p0, Lc4/e;->f:Lc4/h;

    .line 271
    .line 272
    iget p0, p0, Lc4/h;->b:F

    .line 273
    .line 274
    invoke-static {p0}, Lcy0/a;->i(F)I

    .line 275
    .line 276
    .line 277
    move-result p0

    .line 278
    new-instance v0, Lt4/k;

    .line 279
    .line 280
    add-int/2addr p2, p0

    .line 281
    add-int/2addr p1, p0

    .line 282
    invoke-direct {v0, p3, p2, v1, p1}, Lt4/k;-><init>(IIII)V

    .line 283
    .line 284
    .line 285
    return-object v0

    .line 286
    :catchall_0
    move-exception p0

    .line 287
    invoke-static {v0}, Lc4/a;->p(Landroid/view/ScrollCaptureSession;)Landroid/view/Surface;

    .line 288
    .line 289
    .line 290
    move-result-object p1

    .line 291
    invoke-virtual {p1, v2}, Landroid/view/Surface;->unlockCanvasAndPost(Landroid/graphics/Canvas;)V

    .line 292
    .line 293
    .line 294
    throw p0

    .line 295
    :cond_b
    const-string p0, "Expected range ("

    .line 296
    .line 297
    const-string p1, ") to be \u2264 viewportSize="

    .line 298
    .line 299
    invoke-static {p0, p1, v6, v4}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 300
    .line 301
    .line 302
    move-result-object p0

    .line 303
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 304
    .line 305
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 306
    .line 307
    .line 308
    move-result-object p0

    .line 309
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    throw p1

    .line 313
    :cond_c
    const-string p0, "Expected min="

    .line 314
    .line 315
    const-string p1, " \u2264 max="

    .line 316
    .line 317
    invoke-static {p0, p1, p3, v2}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 318
    .line 319
    .line 320
    move-result-object p0

    .line 321
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 322
    .line 323
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 324
    .line 325
    .line 326
    move-result-object p0

    .line 327
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 328
    .line 329
    .line 330
    throw p1
.end method


# virtual methods
.method public final onScrollCaptureEnd(Ljava/lang/Runnable;)V
    .locals 4

    .line 1
    sget-object v0, Lvy0/t1;->d:Lvy0/t1;

    .line 2
    .line 3
    new-instance v1, La50/c;

    .line 4
    .line 5
    const/16 v2, 0x1a

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    invoke-direct {v1, v2, p0, p1, v3}, La50/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    const/4 p1, 0x2

    .line 12
    iget-object p0, p0, Lc4/e;->e:Lpw0/a;

    .line 13
    .line 14
    invoke-static {p0, v0, v3, v1, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public final onScrollCaptureImageRequest(Landroid/view/ScrollCaptureSession;Landroid/os/CancellationSignal;Landroid/graphics/Rect;Ljava/util/function/Consumer;)V
    .locals 7

    .line 1
    new-instance v0, La7/k;

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    const/16 v6, 0xe

    .line 5
    .line 6
    move-object v1, p0

    .line 7
    move-object v2, p1

    .line 8
    move-object v3, p3

    .line 9
    move-object v4, p4

    .line 10
    invoke-direct/range {v0 .. v6}, La7/k;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    const/4 p1, 0x3

    .line 15
    iget-object p3, v1, Lc4/e;->e:Lpw0/a;

    .line 16
    .line 17
    invoke-static {p3, p0, p0, v0, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    new-instance p1, La3/f;

    .line 22
    .line 23
    const/16 p3, 0xb

    .line 24
    .line 25
    invoke-direct {p1, p2, p3}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, p1}, Lvy0/p1;->E(Lay0/k;)Lvy0/r0;

    .line 29
    .line 30
    .line 31
    new-instance p1, Lc2/i;

    .line 32
    .line 33
    const/4 p3, 0x1

    .line 34
    invoke-direct {p1, p0, p3}, Lc2/i;-><init>(Ljava/lang/Object;I)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p2, p1}, Landroid/os/CancellationSignal;->setOnCancelListener(Landroid/os/CancellationSignal$OnCancelListener;)V

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public final onScrollCaptureSearch(Landroid/os/CancellationSignal;Ljava/util/function/Consumer;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lc4/e;->b:Lt4/k;

    .line 2
    .line 3
    invoke-static {p0}, Le3/j0;->w(Lt4/k;)Landroid/graphics/Rect;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p2, p0}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final onScrollCaptureStart(Landroid/view/ScrollCaptureSession;Landroid/os/CancellationSignal;Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    iget-object p1, p0, Lc4/e;->f:Lc4/h;

    .line 2
    .line 3
    const/4 p2, 0x0

    .line 4
    iput p2, p1, Lc4/h;->b:F

    .line 5
    .line 6
    iget-object p0, p0, Lc4/e;->c:Laq/a;

    .line 7
    .line 8
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Ll2/j1;

    .line 11
    .line 12
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-interface {p3}, Ljava/lang/Runnable;->run()V

    .line 18
    .line 19
    .line 20
    return-void
.end method
