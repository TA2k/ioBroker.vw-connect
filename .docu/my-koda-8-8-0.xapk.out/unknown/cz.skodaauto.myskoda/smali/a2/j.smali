.class public final La2/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/j0;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, La2/j;->a:I

    .line 2
    .line 3
    iput-object p1, p0, La2/j;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final dispose()V
    .locals 5

    .line 1
    iget v0, p0, La2/j;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lzb/v0;

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    iput-object v0, p0, Lzb/v0;->e:Lzb/u0;

    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Ly1/f;

    .line 17
    .line 18
    iget-object v0, p0, Ly1/f;->e:Lv2/r;

    .line 19
    .line 20
    iget-object v1, v0, Lv2/r;->h:Lrx/b;

    .line 21
    .line 22
    if-eqz v1, :cond_0

    .line 23
    .line 24
    invoke-virtual {v1}, Lrx/b;->d()V

    .line 25
    .line 26
    .line 27
    :cond_0
    invoke-virtual {v0}, Lv2/r;->a()V

    .line 28
    .line 29
    .line 30
    iget-object v0, p0, Ly1/f;->h:Landroid/view/ActionMode;

    .line 31
    .line 32
    if-eqz v0, :cond_1

    .line 33
    .line 34
    invoke-virtual {v0}, Landroid/view/ActionMode;->finish()V

    .line 35
    .line 36
    .line 37
    :cond_1
    const/4 v0, 0x0

    .line 38
    iput-object v0, p0, Ly1/f;->h:Landroid/view/ActionMode;

    .line 39
    .line 40
    return-void

    .line 41
    :pswitch_1
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast p0, Landroid/app/Activity;

    .line 44
    .line 45
    const/16 v0, 0x21

    .line 46
    .line 47
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 48
    .line 49
    if-lt v1, v0, :cond_2

    .line 50
    .line 51
    invoke-static {p0}, Li2/p0;->n(Landroid/app/Activity;)V

    .line 52
    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_2
    invoke-virtual {p0}, Landroid/app/Activity;->getWindow()Landroid/view/Window;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    const/16 v0, 0x2000

    .line 60
    .line 61
    invoke-virtual {p0, v0}, Landroid/view/Window;->clearFlags(I)V

    .line 62
    .line 63
    .line 64
    :goto_0
    return-void

    .line 65
    :pswitch_2
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast p0, Lx4/t;

    .line 68
    .line 69
    invoke-virtual {p0}, Lw3/a;->d()V

    .line 70
    .line 71
    .line 72
    const/4 v0, 0x0

    .line 73
    invoke-static {p0, v0}, Landroidx/lifecycle/v0;->l(Landroid/view/View;Landroidx/lifecycle/x;)V

    .line 74
    .line 75
    .line 76
    iget-object v0, p0, Lx4/t;->q:Landroid/view/WindowManager;

    .line 77
    .line 78
    invoke-interface {v0, p0}, Landroid/view/WindowManager;->removeViewImmediate(Landroid/view/View;)V

    .line 79
    .line 80
    .line 81
    return-void

    .line 82
    :pswitch_3
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast p0, Lx4/r;

    .line 85
    .line 86
    invoke-virtual {p0}, Landroid/app/Dialog;->dismiss()V

    .line 87
    .line 88
    .line 89
    iget-object p0, p0, Lx4/r;->j:Lx4/o;

    .line 90
    .line 91
    invoke-virtual {p0}, Lw3/a;->d()V

    .line 92
    .line 93
    .line 94
    return-void

    .line 95
    :pswitch_4
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 96
    .line 97
    check-cast p0, Lw3/j1;

    .line 98
    .line 99
    iget-object p0, p0, Lw3/j1;->e:Lw3/k1;

    .line 100
    .line 101
    invoke-virtual {p0}, Lw3/k1;->invoke()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    return-void

    .line 105
    :pswitch_5
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast p0, Lv00/i;

    .line 108
    .line 109
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 110
    .line 111
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 112
    .line 113
    .line 114
    move-result-object v1

    .line 115
    new-instance v2, Ltz/o2;

    .line 116
    .line 117
    const/16 v3, 0x17

    .line 118
    .line 119
    const/4 v4, 0x0

    .line 120
    invoke-direct {v2, v3, v0, p0, v4}, Ltz/o2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 121
    .line 122
    .line 123
    const/4 p0, 0x3

    .line 124
    invoke-static {v1, v4, v4, v2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 125
    .line 126
    .line 127
    return-void

    .line 128
    :pswitch_6
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 129
    .line 130
    check-cast p0, Lqu/c;

    .line 131
    .line 132
    iget-object v0, p0, Lqu/c;->g:Lap0/o;

    .line 133
    .line 134
    invoke-virtual {v0}, Lap0/o;->M()V

    .line 135
    .line 136
    .line 137
    :try_start_0
    invoke-interface {v0}, Lru/a;->g()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 138
    .line 139
    .line 140
    invoke-virtual {v0}, Lap0/o;->X()V

    .line 141
    .line 142
    .line 143
    invoke-virtual {p0}, Lqu/c;->c()V

    .line 144
    .line 145
    .line 146
    return-void

    .line 147
    :catchall_0
    move-exception p0

    .line 148
    invoke-virtual {v0}, Lap0/o;->X()V

    .line 149
    .line 150
    .line 151
    throw p0

    .line 152
    :pswitch_7
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast p0, Le2/w0;

    .line 155
    .line 156
    invoke-virtual {p0}, Le2/w0;->n()V

    .line 157
    .line 158
    .line 159
    return-void

    .line 160
    :pswitch_8
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 161
    .line 162
    check-cast p0, Lk0/b;

    .line 163
    .line 164
    invoke-virtual {p0}, Lk0/b;->get()Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    check-cast p0, Lv0/f;

    .line 169
    .line 170
    iget-object p0, p0, Lv0/f;->a:Lcom/google/android/material/datepicker/d;

    .line 171
    .line 172
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/d;->h()V

    .line 173
    .line 174
    .line 175
    return-void

    .line 176
    :pswitch_9
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    .line 179
    .line 180
    const/4 v0, 0x0

    .line 181
    invoke-static {p0, v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->access$setContext$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;Landroid/content/Context;)V

    .line 182
    .line 183
    .line 184
    return-void

    .line 185
    :pswitch_a
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 186
    .line 187
    check-cast p0, Lo1/h0;

    .line 188
    .line 189
    const/4 v0, 0x1

    .line 190
    iput-boolean v0, p0, Lo1/h0;->f:Z

    .line 191
    .line 192
    return-void

    .line 193
    :pswitch_b
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 194
    .line 195
    check-cast p0, Lo1/l0;

    .line 196
    .line 197
    iget-object v0, p0, Lo1/l0;->c:La8/b;

    .line 198
    .line 199
    if-eqz v0, :cond_3

    .line 200
    .line 201
    const/4 v1, 0x0

    .line 202
    iput-boolean v1, v0, La8/b;->e:Z

    .line 203
    .line 204
    :cond_3
    const/4 v0, 0x0

    .line 205
    iput-object v0, p0, Lo1/l0;->c:La8/b;

    .line 206
    .line 207
    return-void

    .line 208
    :pswitch_c
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 209
    .line 210
    check-cast p0, Lo1/z;

    .line 211
    .line 212
    const/4 v0, 0x0

    .line 213
    iput-object v0, p0, Lo1/z;->d:Lt2/b;

    .line 214
    .line 215
    return-void

    .line 216
    :pswitch_d
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 217
    .line 218
    check-cast p0, Landroidx/media3/exoplayer/ExoPlayer;

    .line 219
    .line 220
    check-cast p0, La8/i0;

    .line 221
    .line 222
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 223
    .line 224
    .line 225
    const/4 v0, 0x0

    .line 226
    invoke-virtual {p0, v0}, La8/i0;->G0(La8/o;)V

    .line 227
    .line 228
    .line 229
    new-instance v0, Lv7/c;

    .line 230
    .line 231
    sget-object v1, Lhr/x0;->h:Lhr/x0;

    .line 232
    .line 233
    iget-object v2, p0, La8/i0;->y1:La8/i1;

    .line 234
    .line 235
    iget-wide v2, v2, La8/i1;->s:J

    .line 236
    .line 237
    invoke-direct {v0, v1}, Lv7/c;-><init>(Ljava/util/List;)V

    .line 238
    .line 239
    .line 240
    iput-object v0, p0, La8/i0;->s1:Lv7/c;

    .line 241
    .line 242
    invoke-virtual {p0}, La8/i0;->x0()V

    .line 243
    .line 244
    .line 245
    return-void

    .line 246
    :pswitch_e
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 247
    .line 248
    check-cast p0, Lh2/yb;

    .line 249
    .line 250
    iget-object p0, p0, Lh2/yb;->c:Lvy0/l;

    .line 251
    .line 252
    if-eqz p0, :cond_4

    .line 253
    .line 254
    const/4 v0, 0x0

    .line 255
    invoke-virtual {p0, v0}, Lvy0/l;->c(Ljava/lang/Throwable;)Z

    .line 256
    .line 257
    .line 258
    :cond_4
    return-void

    .line 259
    :pswitch_f
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 260
    .line 261
    check-cast p0, Lh2/w5;

    .line 262
    .line 263
    invoke-virtual {p0}, Landroid/app/Dialog;->dismiss()V

    .line 264
    .line 265
    .line 266
    iget-object p0, p0, Lh2/w5;->k:Lh2/s5;

    .line 267
    .line 268
    invoke-virtual {p0}, Lw3/a;->d()V

    .line 269
    .line 270
    .line 271
    return-void

    .line 272
    :pswitch_10
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 273
    .line 274
    check-cast p0, Lh2/a5;

    .line 275
    .line 276
    iget-object v0, p0, Lh2/a5;->e:Landroid/view/View;

    .line 277
    .line 278
    iget-boolean v1, p0, Lh2/a5;->d:Z

    .line 279
    .line 280
    if-nez v1, :cond_5

    .line 281
    .line 282
    goto :goto_1

    .line 283
    :cond_5
    invoke-virtual {v0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 284
    .line 285
    .line 286
    move-result-object v1

    .line 287
    invoke-virtual {v1, p0}, Landroid/view/ViewTreeObserver;->removeOnGlobalLayoutListener(Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;)V

    .line 288
    .line 289
    .line 290
    const/4 v1, 0x0

    .line 291
    iput-boolean v1, p0, Lh2/a5;->d:Z

    .line 292
    .line 293
    :goto_1
    invoke-virtual {v0, p0}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 294
    .line 295
    .line 296
    return-void

    .line 297
    :pswitch_11
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 298
    .line 299
    check-cast p0, Lew/i;

    .line 300
    .line 301
    const/4 v0, 0x0

    .line 302
    iput-object v0, p0, Lew/i;->h:Lkw/g;

    .line 303
    .line 304
    iput-object v0, p0, Lew/i;->i:Lkw/i;

    .line 305
    .line 306
    iput-object v0, p0, Lew/i;->j:Landroid/graphics/RectF;

    .line 307
    .line 308
    return-void

    .line 309
    :pswitch_12
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 310
    .line 311
    check-cast p0, Lc/l;

    .line 312
    .line 313
    invoke-virtual {p0}, Lb/a0;->remove()V

    .line 314
    .line 315
    .line 316
    return-void

    .line 317
    :pswitch_13
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 318
    .line 319
    check-cast p0, Lc/f;

    .line 320
    .line 321
    invoke-virtual {p0}, Lb/a0;->remove()V

    .line 322
    .line 323
    .line 324
    return-void

    .line 325
    :pswitch_14
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 326
    .line 327
    check-cast p0, Lc/a;

    .line 328
    .line 329
    iget-object p0, p0, Lc/a;->a:Le/g;

    .line 330
    .line 331
    if-eqz p0, :cond_6

    .line 332
    .line 333
    invoke-virtual {p0}, Le/g;->b()V

    .line 334
    .line 335
    .line 336
    return-void

    .line 337
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 338
    .line 339
    const-string v0, "Launcher has not been initialized"

    .line 340
    .line 341
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 342
    .line 343
    .line 344
    throw p0

    .line 345
    :pswitch_15
    iget-object p0, p0, La2/j;->b:Ljava/lang/Object;

    .line 346
    .line 347
    check-cast p0, La2/d;

    .line 348
    .line 349
    iget-object p0, p0, La2/d;->c:Ll2/j1;

    .line 350
    .line 351
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 352
    .line 353
    .line 354
    move-result-object p0

    .line 355
    check-cast p0, La2/b;

    .line 356
    .line 357
    if-eqz p0, :cond_7

    .line 358
    .line 359
    invoke-virtual {p0}, La2/b;->close()V

    .line 360
    .line 361
    .line 362
    :cond_7
    return-void

    .line 363
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
