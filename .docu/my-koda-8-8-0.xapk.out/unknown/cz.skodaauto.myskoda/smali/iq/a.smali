.class public final Liq/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p2, p0, Liq/a;->d:I

    iput-object p3, p0, Liq/a;->g:Ljava/lang/Object;

    iput p1, p0, Liq/a;->e:I

    iput-object p4, p0, Liq/a;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroid/widget/TextView;Landroid/graphics/Typeface;I)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Liq/a;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Liq/a;->f:Ljava/lang/Object;

    iput-object p2, p0, Liq/a;->g:Ljava/lang/Object;

    iput p3, p0, Liq/a;->e:I

    return-void
.end method

.method public constructor <init>(Lcom/google/android/material/bottomsheet/BottomSheetBehavior;Landroid/view/View;I)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Liq/a;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Liq/a;->g:Ljava/lang/Object;

    iput-object p2, p0, Liq/a;->f:Ljava/lang/Object;

    iput p3, p0, Liq/a;->e:I

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 11

    .line 1
    iget v0, p0, Liq/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Liq/a;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lq/k;

    .line 9
    .line 10
    iget-object v0, v0, Lq/k;->e:Lq/s;

    .line 11
    .line 12
    iget-object v1, v0, Lq/s;->e:Ljp/he;

    .line 13
    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    new-instance v1, Lq/o;

    .line 17
    .line 18
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 19
    .line 20
    .line 21
    iput-object v1, v0, Lq/s;->e:Ljp/he;

    .line 22
    .line 23
    :cond_0
    iget-object v0, v0, Lq/s;->e:Ljp/he;

    .line 24
    .line 25
    iget-object v1, p0, Liq/a;->f:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v1, Ljava/lang/CharSequence;

    .line 28
    .line 29
    iget p0, p0, Liq/a;->e:I

    .line 30
    .line 31
    invoke-virtual {v0, p0, v1}, Ljp/he;->e(ILjava/lang/CharSequence;)V

    .line 32
    .line 33
    .line 34
    return-void

    .line 35
    :pswitch_0
    iget-object v0, p0, Liq/a;->f:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v0, Landroid/widget/TextView;

    .line 38
    .line 39
    iget-object v1, p0, Liq/a;->g:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v1, Landroid/graphics/Typeface;

    .line 42
    .line 43
    iget p0, p0, Liq/a;->e:I

    .line 44
    .line 45
    invoke-virtual {v0, v1, p0}, Landroid/widget/TextView;->setTypeface(Landroid/graphics/Typeface;I)V

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :pswitch_1
    iget-object v0, p0, Liq/a;->g:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v0, Lk0/k;

    .line 52
    .line 53
    iget v1, p0, Liq/a;->e:I

    .line 54
    .line 55
    iget-object p0, p0, Liq/a;->f:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p0, Lcom/google/common/util/concurrent/ListenableFuture;

    .line 58
    .line 59
    iget-boolean v2, v0, Lk0/k;->f:Z

    .line 60
    .line 61
    const-string v3, "Less than 0 remaining futures"

    .line 62
    .line 63
    iget-object v4, v0, Lk0/k;->g:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 64
    .line 65
    iget-object v5, v0, Lk0/k;->e:Ljava/util/ArrayList;

    .line 66
    .line 67
    invoke-virtual {v0}, Lk0/k;->isDone()Z

    .line 68
    .line 69
    .line 70
    move-result v6

    .line 71
    if-nez v6, :cond_e

    .line 72
    .line 73
    if-nez v5, :cond_1

    .line 74
    .line 75
    goto/16 :goto_d

    .line 76
    .line 77
    :cond_1
    const/4 v6, 0x0

    .line 78
    const/4 v7, 0x1

    .line 79
    const/4 v8, 0x0

    .line 80
    :try_start_0
    invoke-interface {p0}, Ljava/util/concurrent/Future;->isDone()Z

    .line 81
    .line 82
    .line 83
    move-result v9

    .line 84
    const-string v10, "Tried to set value from future which is not done"

    .line 85
    .line 86
    invoke-static {v10, v9}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 87
    .line 88
    .line 89
    invoke-static {p0}, Lk0/h;->b(Ljava/util/concurrent/Future;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    invoke-virtual {v5, v1, p0}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_3
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/Error; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 94
    .line 95
    .line 96
    invoke-virtual {v4}, Ljava/util/concurrent/atomic/AtomicInteger;->decrementAndGet()I

    .line 97
    .line 98
    .line 99
    move-result p0

    .line 100
    if-ltz p0, :cond_2

    .line 101
    .line 102
    goto :goto_0

    .line 103
    :cond_2
    move v7, v8

    .line 104
    :goto_0
    invoke-static {v3, v7}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 105
    .line 106
    .line 107
    if-nez p0, :cond_f

    .line 108
    .line 109
    iget-object p0, v0, Lk0/k;->e:Ljava/util/ArrayList;

    .line 110
    .line 111
    if-eqz p0, :cond_3

    .line 112
    .line 113
    iget-object v0, v0, Lk0/k;->i:Ly4/h;

    .line 114
    .line 115
    new-instance v1, Ljava/util/ArrayList;

    .line 116
    .line 117
    invoke-direct {v1, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 118
    .line 119
    .line 120
    :goto_1
    invoke-virtual {v0, v1}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    goto/16 :goto_e

    .line 124
    .line 125
    :cond_3
    invoke-virtual {v0}, Lk0/k;->isDone()Z

    .line 126
    .line 127
    .line 128
    move-result p0

    .line 129
    invoke-static {v6, p0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 130
    .line 131
    .line 132
    goto/16 :goto_e

    .line 133
    .line 134
    :catchall_0
    move-exception p0

    .line 135
    goto/16 :goto_8

    .line 136
    .line 137
    :catch_0
    move-exception p0

    .line 138
    goto :goto_2

    .line 139
    :catch_1
    move-exception p0

    .line 140
    goto :goto_4

    .line 141
    :catch_2
    move-exception p0

    .line 142
    goto :goto_6

    .line 143
    :goto_2
    :try_start_1
    iget-object v1, v0, Lk0/k;->i:Ly4/h;

    .line 144
    .line 145
    invoke-virtual {v1, p0}, Ly4/h;->d(Ljava/lang/Throwable;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 146
    .line 147
    .line 148
    invoke-virtual {v4}, Ljava/util/concurrent/atomic/AtomicInteger;->decrementAndGet()I

    .line 149
    .line 150
    .line 151
    move-result p0

    .line 152
    if-ltz p0, :cond_4

    .line 153
    .line 154
    goto :goto_3

    .line 155
    :cond_4
    move v7, v8

    .line 156
    :goto_3
    invoke-static {v3, v7}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 157
    .line 158
    .line 159
    if-nez p0, :cond_f

    .line 160
    .line 161
    iget-object p0, v0, Lk0/k;->e:Ljava/util/ArrayList;

    .line 162
    .line 163
    if-eqz p0, :cond_3

    .line 164
    .line 165
    iget-object v0, v0, Lk0/k;->i:Ly4/h;

    .line 166
    .line 167
    new-instance v1, Ljava/util/ArrayList;

    .line 168
    .line 169
    invoke-direct {v1, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 170
    .line 171
    .line 172
    goto :goto_1

    .line 173
    :goto_4
    if-eqz v2, :cond_5

    .line 174
    .line 175
    :try_start_2
    iget-object v1, v0, Lk0/k;->i:Ly4/h;

    .line 176
    .line 177
    invoke-virtual {v1, p0}, Ly4/h;->d(Ljava/lang/Throwable;)Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 178
    .line 179
    .line 180
    :cond_5
    invoke-virtual {v4}, Ljava/util/concurrent/atomic/AtomicInteger;->decrementAndGet()I

    .line 181
    .line 182
    .line 183
    move-result p0

    .line 184
    if-ltz p0, :cond_6

    .line 185
    .line 186
    goto :goto_5

    .line 187
    :cond_6
    move v7, v8

    .line 188
    :goto_5
    invoke-static {v3, v7}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 189
    .line 190
    .line 191
    if-nez p0, :cond_f

    .line 192
    .line 193
    iget-object p0, v0, Lk0/k;->e:Ljava/util/ArrayList;

    .line 194
    .line 195
    if-eqz p0, :cond_3

    .line 196
    .line 197
    iget-object v0, v0, Lk0/k;->i:Ly4/h;

    .line 198
    .line 199
    new-instance v1, Ljava/util/ArrayList;

    .line 200
    .line 201
    invoke-direct {v1, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 202
    .line 203
    .line 204
    goto :goto_1

    .line 205
    :goto_6
    if-eqz v2, :cond_7

    .line 206
    .line 207
    :try_start_3
    iget-object v1, v0, Lk0/k;->i:Ly4/h;

    .line 208
    .line 209
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 210
    .line 211
    .line 212
    move-result-object p0

    .line 213
    invoke-virtual {v1, p0}, Ly4/h;->d(Ljava/lang/Throwable;)Z
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 214
    .line 215
    .line 216
    :cond_7
    invoke-virtual {v4}, Ljava/util/concurrent/atomic/AtomicInteger;->decrementAndGet()I

    .line 217
    .line 218
    .line 219
    move-result p0

    .line 220
    if-ltz p0, :cond_8

    .line 221
    .line 222
    goto :goto_7

    .line 223
    :cond_8
    move v7, v8

    .line 224
    :goto_7
    invoke-static {v3, v7}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 225
    .line 226
    .line 227
    if-nez p0, :cond_f

    .line 228
    .line 229
    iget-object p0, v0, Lk0/k;->e:Ljava/util/ArrayList;

    .line 230
    .line 231
    if-eqz p0, :cond_3

    .line 232
    .line 233
    iget-object v0, v0, Lk0/k;->i:Ly4/h;

    .line 234
    .line 235
    new-instance v1, Ljava/util/ArrayList;

    .line 236
    .line 237
    invoke-direct {v1, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 238
    .line 239
    .line 240
    goto :goto_1

    .line 241
    :catch_3
    if-eqz v2, :cond_c

    .line 242
    .line 243
    :try_start_4
    invoke-virtual {v0, v8}, Lk0/k;->cancel(Z)Z
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 244
    .line 245
    .line 246
    goto :goto_b

    .line 247
    :goto_8
    invoke-virtual {v4}, Ljava/util/concurrent/atomic/AtomicInteger;->decrementAndGet()I

    .line 248
    .line 249
    .line 250
    move-result v1

    .line 251
    if-ltz v1, :cond_9

    .line 252
    .line 253
    goto :goto_9

    .line 254
    :cond_9
    move v7, v8

    .line 255
    :goto_9
    invoke-static {v3, v7}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 256
    .line 257
    .line 258
    if-nez v1, :cond_b

    .line 259
    .line 260
    iget-object v1, v0, Lk0/k;->e:Ljava/util/ArrayList;

    .line 261
    .line 262
    if-eqz v1, :cond_a

    .line 263
    .line 264
    iget-object v0, v0, Lk0/k;->i:Ly4/h;

    .line 265
    .line 266
    new-instance v2, Ljava/util/ArrayList;

    .line 267
    .line 268
    invoke-direct {v2, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 269
    .line 270
    .line 271
    invoke-virtual {v0, v2}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 272
    .line 273
    .line 274
    goto :goto_a

    .line 275
    :cond_a
    invoke-virtual {v0}, Lk0/k;->isDone()Z

    .line 276
    .line 277
    .line 278
    move-result v0

    .line 279
    invoke-static {v6, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 280
    .line 281
    .line 282
    :cond_b
    :goto_a
    throw p0

    .line 283
    :cond_c
    :goto_b
    invoke-virtual {v4}, Ljava/util/concurrent/atomic/AtomicInteger;->decrementAndGet()I

    .line 284
    .line 285
    .line 286
    move-result p0

    .line 287
    if-ltz p0, :cond_d

    .line 288
    .line 289
    goto :goto_c

    .line 290
    :cond_d
    move v7, v8

    .line 291
    :goto_c
    invoke-static {v3, v7}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 292
    .line 293
    .line 294
    if-nez p0, :cond_f

    .line 295
    .line 296
    iget-object p0, v0, Lk0/k;->e:Ljava/util/ArrayList;

    .line 297
    .line 298
    if-eqz p0, :cond_3

    .line 299
    .line 300
    iget-object v0, v0, Lk0/k;->i:Ly4/h;

    .line 301
    .line 302
    new-instance v1, Ljava/util/ArrayList;

    .line 303
    .line 304
    invoke-direct {v1, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 305
    .line 306
    .line 307
    goto/16 :goto_1

    .line 308
    .line 309
    :cond_e
    :goto_d
    const-string p0, "Future was done before all dependencies completed"

    .line 310
    .line 311
    invoke-static {p0, v2}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 312
    .line 313
    .line 314
    :cond_f
    :goto_e
    return-void

    .line 315
    :pswitch_2
    iget-object v0, p0, Liq/a;->g:Ljava/lang/Object;

    .line 316
    .line 317
    check-cast v0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;

    .line 318
    .line 319
    iget-object v1, p0, Liq/a;->f:Ljava/lang/Object;

    .line 320
    .line 321
    check-cast v1, Landroid/view/View;

    .line 322
    .line 323
    iget p0, p0, Liq/a;->e:I

    .line 324
    .line 325
    const/4 v2, 0x0

    .line 326
    invoke-virtual {v0, v1, p0, v2}, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->E(Landroid/view/View;IZ)V

    .line 327
    .line 328
    .line 329
    return-void

    .line 330
    nop

    .line 331
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
