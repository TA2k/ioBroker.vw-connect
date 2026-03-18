.class public final synthetic La8/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, La8/z;->d:I

    iput-object p2, p0, La8/z;->e:Ljava/lang/Object;

    iput-object p3, p0, La8/z;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lay0/n;Ljava/lang/String;)V
    .locals 1

    .line 2
    const/16 v0, 0x15

    iput v0, p0, La8/z;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    check-cast p1, Lkotlin/jvm/internal/k;

    iput-object p1, p0, La8/z;->e:Ljava/lang/Object;

    iput-object p2, p0, La8/z;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lb81/d;Lt7/o;La8/h;)V
    .locals 0

    .line 3
    const/16 p3, 0xf

    iput p3, p0, La8/z;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La8/z;->e:Ljava/lang/Object;

    iput-object p2, p0, La8/z;->f:Ljava/lang/Object;

    return-void
.end method

.method private final a()V
    .locals 3

    .line 1
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lgs/q;

    .line 4
    .line 5
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lgt/b;

    .line 8
    .line 9
    iget-object v1, v0, Lgs/q;->b:Lgt/b;

    .line 10
    .line 11
    sget-object v2, Lgs/q;->d:Lcom/google/firebase/messaging/l;

    .line 12
    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    monitor-enter v0

    .line 16
    :try_start_0
    iget-object v1, v0, Lgs/q;->a:Lgt/a;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    iput-object v2, v0, Lgs/q;->a:Lgt/a;

    .line 20
    .line 21
    iput-object p0, v0, Lgs/q;->b:Lgt/b;

    .line 22
    .line 23
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 24
    invoke-interface {v1, p0}, Lgt/a;->b(Lgt/b;)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :catchall_0
    move-exception p0

    .line 29
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 30
    throw p0

    .line 31
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 32
    .line 33
    const-string v0, "provide() can be called only once."

    .line 34
    .line 35
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0
.end method

.method private final b()V
    .locals 2

    .line 1
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lgs/p;

    .line 4
    .line 5
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lgt/b;

    .line 8
    .line 9
    monitor-enter v0

    .line 10
    :try_start_0
    iget-object v1, v0, Lgs/p;->b:Ljava/util/Set;

    .line 11
    .line 12
    if-nez v1, :cond_0

    .line 13
    .line 14
    iget-object v1, v0, Lgs/p;->a:Ljava/util/Set;

    .line 15
    .line 16
    invoke-interface {v1, p0}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    goto :goto_0

    .line 20
    :catchall_0
    move-exception p0

    .line 21
    goto :goto_1

    .line 22
    :cond_0
    iget-object v1, v0, Lgs/p;->b:Ljava/util/Set;

    .line 23
    .line 24
    invoke-interface {p0}, Lgt/b;->get()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-interface {v1, p0}, Ljava/util/Set;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    .line 30
    .line 31
    :goto_0
    monitor-exit v0

    .line 32
    return-void

    .line 33
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 34
    throw p0
.end method


# virtual methods
.method public final run()V
    .locals 13

    .line 1
    iget v0, p0, La8/z;->d:I

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x1

    .line 5
    const/4 v3, 0x0

    .line 6
    const/4 v4, 0x0

    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Lh0/z;

    .line 13
    .line 14
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Lh0/c0;

    .line 17
    .line 18
    invoke-interface {v0}, Lh0/z;->c()Landroidx/lifecycle/g0;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-virtual {v0, p0}, Landroidx/lifecycle/g0;->f(Landroidx/lifecycle/j0;)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :pswitch_0
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v0, Lh0/b0;

    .line 29
    .line 30
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Landroidx/lifecycle/j0;

    .line 33
    .line 34
    invoke-interface {v0}, Lh0/b0;->l()Lh0/z;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    invoke-interface {v0}, Lh0/z;->c()Landroidx/lifecycle/g0;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    invoke-virtual {v0, p0}, Landroidx/lifecycle/g0;->i(Landroidx/lifecycle/j0;)V

    .line 43
    .line 44
    .line 45
    return-void

    .line 46
    :pswitch_1
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 47
    .line 48
    move-object v1, v0

    .line 49
    check-cast v1, Lfv/o;

    .line 50
    .line 51
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast p0, Ljava/lang/Runnable;

    .line 54
    .line 55
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 56
    .line 57
    .line 58
    :try_start_0
    invoke-interface {p0}, Ljava/lang/Runnable;->run()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 59
    .line 60
    .line 61
    invoke-virtual {v1}, Lfv/o;->a()V

    .line 62
    .line 63
    .line 64
    return-void

    .line 65
    :catchall_0
    move-exception v0

    .line 66
    move-object p0, v0

    .line 67
    invoke-virtual {v1}, Lfv/o;->a()V

    .line 68
    .line 69
    .line 70
    throw p0

    .line 71
    :pswitch_2
    invoke-direct {p0}, La8/z;->b()V

    .line 72
    .line 73
    .line 74
    return-void

    .line 75
    :pswitch_3
    invoke-direct {p0}, La8/z;->a()V

    .line 76
    .line 77
    .line 78
    return-void

    .line 79
    :pswitch_4
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v0, Lgb/d;

    .line 82
    .line 83
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast p0, Lfb/j;

    .line 86
    .line 87
    iget-object v0, v0, Lgb/d;->c:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast v0, Lb81/b;

    .line 90
    .line 91
    const/4 v1, 0x3

    .line 92
    invoke-virtual {v0, p0, v1}, Lb81/b;->z(Lfb/j;I)V

    .line 93
    .line 94
    .line 95
    return-void

    .line 96
    :pswitch_5
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v0, Lfb/e;

    .line 99
    .line 100
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast p0, Lmb/i;

    .line 103
    .line 104
    iget-object v1, v0, Lfb/e;->k:Ljava/lang/Object;

    .line 105
    .line 106
    monitor-enter v1

    .line 107
    :try_start_1
    iget-object v0, v0, Lfb/e;->j:Ljava/util/ArrayList;

    .line 108
    .line 109
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    if-eqz v2, :cond_0

    .line 118
    .line 119
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v2

    .line 123
    check-cast v2, Lfb/b;

    .line 124
    .line 125
    invoke-interface {v2, p0, v3}, Lfb/b;->b(Lmb/i;Z)V

    .line 126
    .line 127
    .line 128
    goto :goto_0

    .line 129
    :catchall_1
    move-exception v0

    .line 130
    move-object p0, v0

    .line 131
    goto :goto_1

    .line 132
    :cond_0
    monitor-exit v1

    .line 133
    return-void

    .line 134
    :goto_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 135
    throw p0

    .line 136
    :pswitch_6
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast v0, Ldz0/f;

    .line 139
    .line 140
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast p0, Ldz0/b;

    .line 143
    .line 144
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 145
    .line 146
    check-cast v0, Ldz0/e;

    .line 147
    .line 148
    invoke-virtual {v0, p0, v1}, Ldz0/e;->h(Ljava/lang/Object;Ljava/lang/Object;)I

    .line 149
    .line 150
    .line 151
    return-void

    .line 152
    :pswitch_7
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast v0, Lkotlin/jvm/internal/k;

    .line 155
    .line 156
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast p0, Ljava/lang/String;

    .line 159
    .line 160
    const-string v1, "$observer"

    .line 161
    .line 162
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    invoke-interface {v0, v4, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    return-void

    .line 169
    :pswitch_8
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 170
    .line 171
    check-cast v0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;

    .line 172
    .line 173
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 174
    .line 175
    check-cast p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;

    .line 176
    .line 177
    invoke-static {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;->a(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V

    .line 178
    .line 179
    .line 180
    return-void

    .line 181
    :pswitch_9
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 182
    .line 183
    check-cast v0, Lcom/salesforce/marketingcloud/push/h;

    .line 184
    .line 185
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 186
    .line 187
    check-cast p0, Ljava/util/List;

    .line 188
    .line 189
    invoke-static {v0, p0}, Lcom/salesforce/marketingcloud/push/h;->b(Lcom/salesforce/marketingcloud/push/h;Ljava/util/List;)V

    .line 190
    .line 191
    .line 192
    return-void

    .line 193
    :pswitch_a
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 194
    .line 195
    check-cast v0, Lcom/google/firebase/messaging/q;

    .line 196
    .line 197
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 198
    .line 199
    check-cast p0, Laq/k;

    .line 200
    .line 201
    :try_start_2
    invoke-virtual {v0}, Lcom/google/firebase/messaging/q;->a()Landroid/graphics/Bitmap;

    .line 202
    .line 203
    .line 204
    move-result-object v0

    .line 205
    invoke-virtual {p0, v0}, Laq/k;->b(Ljava/lang/Object;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 206
    .line 207
    .line 208
    goto :goto_2

    .line 209
    :catch_0
    move-exception v0

    .line 210
    invoke-virtual {p0, v0}, Laq/k;->a(Ljava/lang/Exception;)V

    .line 211
    .line 212
    .line 213
    :goto_2
    return-void

    .line 214
    :pswitch_b
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 215
    .line 216
    check-cast v0, Lcom/google/android/material/datepicker/f;

    .line 217
    .line 218
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 219
    .line 220
    check-cast p0, Ljava/lang/String;

    .line 221
    .line 222
    iget-object v1, v0, Lcom/google/android/material/datepicker/f;->d:Lcom/google/android/material/textfield/TextInputLayout;

    .line 223
    .line 224
    iget-object v2, v0, Lcom/google/android/material/datepicker/f;->f:Ljava/text/SimpleDateFormat;

    .line 225
    .line 226
    invoke-virtual {v1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 227
    .line 228
    .line 229
    move-result-object v3

    .line 230
    const v4, 0x7f1207d9

    .line 231
    .line 232
    .line 233
    invoke-virtual {v3, v4}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 234
    .line 235
    .line 236
    move-result-object v4

    .line 237
    const v5, 0x7f1207db

    .line 238
    .line 239
    .line 240
    invoke-virtual {v3, v5}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 241
    .line 242
    .line 243
    move-result-object v5

    .line 244
    const/16 v6, 0x20

    .line 245
    .line 246
    const/16 v7, 0xa0

    .line 247
    .line 248
    invoke-virtual {p0, v6, v7}, Ljava/lang/String;->replace(CC)Ljava/lang/String;

    .line 249
    .line 250
    .line 251
    move-result-object p0

    .line 252
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    move-result-object p0

    .line 256
    invoke-static {v5, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 257
    .line 258
    .line 259
    move-result-object p0

    .line 260
    const v5, 0x7f1207da

    .line 261
    .line 262
    .line 263
    invoke-virtual {v3, v5}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 264
    .line 265
    .line 266
    move-result-object v3

    .line 267
    new-instance v5, Ljava/util/Date;

    .line 268
    .line 269
    invoke-static {}, Lcom/google/android/material/datepicker/n0;->f()Ljava/util/Calendar;

    .line 270
    .line 271
    .line 272
    move-result-object v8

    .line 273
    invoke-virtual {v8}, Ljava/util/Calendar;->getTimeInMillis()J

    .line 274
    .line 275
    .line 276
    move-result-wide v8

    .line 277
    invoke-direct {v5, v8, v9}, Ljava/util/Date;-><init>(J)V

    .line 278
    .line 279
    .line 280
    invoke-virtual {v2, v5}, Ljava/text/DateFormat;->format(Ljava/util/Date;)Ljava/lang/String;

    .line 281
    .line 282
    .line 283
    move-result-object v2

    .line 284
    invoke-virtual {v2, v6, v7}, Ljava/lang/String;->replace(CC)Ljava/lang/String;

    .line 285
    .line 286
    .line 287
    move-result-object v2

    .line 288
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 289
    .line 290
    .line 291
    move-result-object v2

    .line 292
    invoke-static {v3, v2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 293
    .line 294
    .line 295
    move-result-object v2

    .line 296
    new-instance v3, Ljava/lang/StringBuilder;

    .line 297
    .line 298
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 299
    .line 300
    .line 301
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 302
    .line 303
    .line 304
    const-string v4, "\n"

    .line 305
    .line 306
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 307
    .line 308
    .line 309
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 310
    .line 311
    .line 312
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 313
    .line 314
    .line 315
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 316
    .line 317
    .line 318
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 319
    .line 320
    .line 321
    move-result-object p0

    .line 322
    invoke-virtual {v1, p0}, Lcom/google/android/material/textfield/TextInputLayout;->setError(Ljava/lang/CharSequence;)V

    .line 323
    .line 324
    .line 325
    invoke-virtual {v0}, Lcom/google/android/material/datepicker/f;->a()V

    .line 326
    .line 327
    .line 328
    return-void

    .line 329
    :pswitch_c
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 330
    .line 331
    check-cast v0, Laq/a;

    .line 332
    .line 333
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 334
    .line 335
    check-cast p0, Lc8/j;

    .line 336
    .line 337
    iget-object v0, v0, Laq/a;->e:Ljava/lang/Object;

    .line 338
    .line 339
    check-cast v0, Lc8/a0;

    .line 340
    .line 341
    iget-object v0, v0, Lc8/a0;->Q1:Lb81/d;

    .line 342
    .line 343
    iget-object v2, v0, Lb81/d;->e:Ljava/lang/Object;

    .line 344
    .line 345
    check-cast v2, Landroid/os/Handler;

    .line 346
    .line 347
    if-eqz v2, :cond_1

    .line 348
    .line 349
    new-instance v3, Lc8/i;

    .line 350
    .line 351
    invoke-direct {v3, v0, p0, v1}, Lc8/i;-><init>(Lb81/d;Ljava/lang/Object;I)V

    .line 352
    .line 353
    .line 354
    invoke-virtual {v2, v3}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 355
    .line 356
    .line 357
    :cond_1
    return-void

    .line 358
    :pswitch_d
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 359
    .line 360
    check-cast v0, Lb81/d;

    .line 361
    .line 362
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 363
    .line 364
    check-cast p0, Lt7/o;

    .line 365
    .line 366
    iget-object v0, v0, Lb81/d;->f:Ljava/lang/Object;

    .line 367
    .line 368
    check-cast v0, La8/f0;

    .line 369
    .line 370
    sget-object v1, Lw7/w;->a:Ljava/lang/String;

    .line 371
    .line 372
    iget-object v0, v0, La8/f0;->d:La8/i0;

    .line 373
    .line 374
    iput-object p0, v0, La8/i0;->X:Lt7/o;

    .line 375
    .line 376
    iget-object p0, v0, La8/i0;->w:Lb8/e;

    .line 377
    .line 378
    invoke-virtual {p0}, Lb8/e;->L()Lb8/a;

    .line 379
    .line 380
    .line 381
    move-result-object v0

    .line 382
    new-instance v1, Lb8/b;

    .line 383
    .line 384
    const/16 v2, 0xc

    .line 385
    .line 386
    invoke-direct {v1, v2}, Lb8/b;-><init>(I)V

    .line 387
    .line 388
    .line 389
    const/16 v2, 0x3f1

    .line 390
    .line 391
    invoke-virtual {p0, v0, v2, v1}, Lb8/e;->M(Lb8/a;ILw7/j;)V

    .line 392
    .line 393
    .line 394
    return-void

    .line 395
    :pswitch_e
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 396
    .line 397
    check-cast v0, Lb81/d;

    .line 398
    .line 399
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 400
    .line 401
    check-cast p0, La8/g;

    .line 402
    .line 403
    monitor-enter p0

    .line 404
    monitor-exit p0

    .line 405
    iget-object p0, v0, Lb81/d;->f:Ljava/lang/Object;

    .line 406
    .line 407
    check-cast p0, La8/f0;

    .line 408
    .line 409
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 410
    .line 411
    iget-object p0, p0, La8/f0;->d:La8/i0;

    .line 412
    .line 413
    iget-object v0, p0, La8/i0;->w:Lb8/e;

    .line 414
    .line 415
    iget-object v1, v0, Lb8/e;->g:Lin/z1;

    .line 416
    .line 417
    iget-object v1, v1, Lin/z1;->e:Ljava/lang/Object;

    .line 418
    .line 419
    check-cast v1, Lh8/b0;

    .line 420
    .line 421
    invoke-virtual {v0, v1}, Lb8/e;->I(Lh8/b0;)Lb8/a;

    .line 422
    .line 423
    .line 424
    move-result-object v1

    .line 425
    new-instance v2, Lb8/b;

    .line 426
    .line 427
    const/4 v3, 0x6

    .line 428
    invoke-direct {v2, v3}, Lb8/b;-><init>(I)V

    .line 429
    .line 430
    .line 431
    const/16 v3, 0x3f5

    .line 432
    .line 433
    invoke-virtual {v0, v1, v3, v2}, Lb8/e;->M(Lb8/a;ILw7/j;)V

    .line 434
    .line 435
    .line 436
    iput-object v4, p0, La8/i0;->X:Lt7/o;

    .line 437
    .line 438
    return-void

    .line 439
    :pswitch_f
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 440
    .line 441
    check-cast v0, Lb8/j;

    .line 442
    .line 443
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 444
    .line 445
    check-cast p0, Landroid/media/metrics/PlaybackStateEvent;

    .line 446
    .line 447
    iget-object v0, v0, Lb8/j;->d:Landroid/media/metrics/PlaybackSession;

    .line 448
    .line 449
    invoke-static {v0, p0}, Lb8/h;->s(Landroid/media/metrics/PlaybackSession;Landroid/media/metrics/PlaybackStateEvent;)V

    .line 450
    .line 451
    .line 452
    return-void

    .line 453
    :pswitch_10
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 454
    .line 455
    check-cast v0, Lb8/j;

    .line 456
    .line 457
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 458
    .line 459
    check-cast p0, Landroid/media/metrics/PlaybackMetrics;

    .line 460
    .line 461
    iget-object v0, v0, Lb8/j;->d:Landroid/media/metrics/PlaybackSession;

    .line 462
    .line 463
    invoke-static {v0, p0}, Lb8/h;->r(Landroid/media/metrics/PlaybackSession;Landroid/media/metrics/PlaybackMetrics;)V

    .line 464
    .line 465
    .line 466
    return-void

    .line 467
    :pswitch_11
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 468
    .line 469
    check-cast v0, Lb8/j;

    .line 470
    .line 471
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 472
    .line 473
    check-cast p0, Landroid/media/metrics/PlaybackErrorEvent;

    .line 474
    .line 475
    iget-object v0, v0, Lb8/j;->d:Landroid/media/metrics/PlaybackSession;

    .line 476
    .line 477
    invoke-static {v0, p0}, Lb8/h;->q(Landroid/media/metrics/PlaybackSession;Landroid/media/metrics/PlaybackErrorEvent;)V

    .line 478
    .line 479
    .line 480
    return-void

    .line 481
    :pswitch_12
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 482
    .line 483
    check-cast v0, Lb8/j;

    .line 484
    .line 485
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 486
    .line 487
    check-cast p0, Landroid/media/metrics/NetworkEvent;

    .line 488
    .line 489
    iget-object v0, v0, Lb8/j;->d:Landroid/media/metrics/PlaybackSession;

    .line 490
    .line 491
    invoke-static {v0, p0}, Lb8/h;->p(Landroid/media/metrics/PlaybackSession;Landroid/media/metrics/NetworkEvent;)V

    .line 492
    .line 493
    .line 494
    return-void

    .line 495
    :pswitch_13
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 496
    .line 497
    check-cast v0, Lb8/j;

    .line 498
    .line 499
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 500
    .line 501
    check-cast p0, Landroid/media/metrics/TrackChangeEvent;

    .line 502
    .line 503
    iget-object v0, v0, Lb8/j;->d:Landroid/media/metrics/PlaybackSession;

    .line 504
    .line 505
    invoke-static {v0, p0}, Lb8/h;->t(Landroid/media/metrics/PlaybackSession;Landroid/media/metrics/TrackChangeEvent;)V

    .line 506
    .line 507
    .line 508
    return-void

    .line 509
    :pswitch_14
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 510
    .line 511
    check-cast v0, Lb0/j1;

    .line 512
    .line 513
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 514
    .line 515
    check-cast p0, Lb0/x1;

    .line 516
    .line 517
    invoke-interface {v0, p0}, Lb0/j1;->h(Lb0/x1;)V

    .line 518
    .line 519
    .line 520
    return-void

    .line 521
    :pswitch_15
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 522
    .line 523
    check-cast v0, Lb0/f1;

    .line 524
    .line 525
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 526
    .line 527
    check-cast p0, Lh0/b1;

    .line 528
    .line 529
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 530
    .line 531
    .line 532
    invoke-interface {p0, v0}, Lh0/b1;->c(Lh0/c1;)V

    .line 533
    .line 534
    .line 535
    return-void

    .line 536
    :pswitch_16
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 537
    .line 538
    check-cast v0, Lb0/n1;

    .line 539
    .line 540
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 541
    .line 542
    check-cast p0, Lb0/n1;

    .line 543
    .line 544
    invoke-virtual {v0}, Lb0/n1;->r()V

    .line 545
    .line 546
    .line 547
    if-eqz p0, :cond_2

    .line 548
    .line 549
    invoke-virtual {p0}, Lb0/n1;->r()V

    .line 550
    .line 551
    .line 552
    :cond_2
    return-void

    .line 553
    :pswitch_17
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 554
    .line 555
    check-cast v0, Lb0/u;

    .line 556
    .line 557
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 558
    .line 559
    check-cast p0, Ly4/h;

    .line 560
    .line 561
    iget-object v1, v0, Lb0/u;->g:Lu/n;

    .line 562
    .line 563
    iget-object v2, v1, Lu/n;->b:Lz/a;

    .line 564
    .line 565
    iget-object v5, v2, Lz/a;->a:Ljava/lang/Object;

    .line 566
    .line 567
    monitor-enter v5

    .line 568
    :try_start_3
    iget-object v6, v2, Lz/a;->c:Ljava/util/ArrayList;

    .line 569
    .line 570
    invoke-virtual {v6}, Ljava/util/ArrayList;->clear()V

    .line 571
    .line 572
    .line 573
    iget-object v6, v2, Lz/a;->d:Ljava/util/HashMap;

    .line 574
    .line 575
    invoke-virtual {v6}, Ljava/util/HashMap;->clear()V

    .line 576
    .line 577
    .line 578
    iget-object v6, v2, Lz/a;->f:Ljava/util/ArrayList;

    .line 579
    .line 580
    invoke-virtual {v6}, Ljava/util/ArrayList;->clear()V

    .line 581
    .line 582
    .line 583
    iget-object v6, v2, Lz/a;->e:Ljava/util/HashSet;

    .line 584
    .line 585
    invoke-virtual {v6}, Ljava/util/HashSet;->clear()V

    .line 586
    .line 587
    .line 588
    iput v3, v2, Lz/a;->g:I

    .line 589
    .line 590
    monitor-exit v5
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 591
    iget-object v1, v1, Lu/n;->j:Lb0/d1;

    .line 592
    .line 593
    invoke-virtual {v1}, Lb0/d1;->i()V

    .line 594
    .line 595
    .line 596
    iget-object v1, v0, Lb0/u;->f:Landroid/os/HandlerThread;

    .line 597
    .line 598
    if-eqz v1, :cond_5

    .line 599
    .line 600
    iget-object v1, v0, Lb0/u;->d:Ljava/util/concurrent/Executor;

    .line 601
    .line 602
    instance-of v2, v1, Lb0/o;

    .line 603
    .line 604
    if-eqz v2, :cond_4

    .line 605
    .line 606
    check-cast v1, Lb0/o;

    .line 607
    .line 608
    iget-object v2, v1, Lb0/o;->d:Ljava/lang/Object;

    .line 609
    .line 610
    monitor-enter v2

    .line 611
    :try_start_4
    iget-object v3, v1, Lb0/o;->e:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 612
    .line 613
    invoke-virtual {v3}, Ljava/util/concurrent/ThreadPoolExecutor;->isShutdown()Z

    .line 614
    .line 615
    .line 616
    move-result v3

    .line 617
    if-nez v3, :cond_3

    .line 618
    .line 619
    iget-object v1, v1, Lb0/o;->e:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 620
    .line 621
    invoke-virtual {v1}, Ljava/util/concurrent/ThreadPoolExecutor;->shutdown()V

    .line 622
    .line 623
    .line 624
    goto :goto_3

    .line 625
    :catchall_2
    move-exception v0

    .line 626
    move-object p0, v0

    .line 627
    goto :goto_4

    .line 628
    :cond_3
    :goto_3
    monitor-exit v2

    .line 629
    goto :goto_5

    .line 630
    :goto_4
    monitor-exit v2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 631
    throw p0

    .line 632
    :cond_4
    :goto_5
    iget-object v0, v0, Lb0/u;->f:Landroid/os/HandlerThread;

    .line 633
    .line 634
    invoke-virtual {v0}, Landroid/os/HandlerThread;->quit()Z

    .line 635
    .line 636
    .line 637
    :cond_5
    invoke-virtual {p0, v4}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 638
    .line 639
    .line 640
    return-void

    .line 641
    :catchall_3
    move-exception v0

    .line 642
    move-object p0, v0

    .line 643
    :try_start_5
    monitor-exit v5
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 644
    throw p0

    .line 645
    :pswitch_18
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 646
    .line 647
    check-cast v0, Lcom/google/android/gms/internal/measurement/i4;

    .line 648
    .line 649
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 650
    .line 651
    check-cast p0, Lh0/b1;

    .line 652
    .line 653
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 654
    .line 655
    .line 656
    invoke-interface {p0, v0}, Lh0/b1;->c(Lh0/c1;)V

    .line 657
    .line 658
    .line 659
    return-void

    .line 660
    :pswitch_19
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 661
    .line 662
    check-cast v0, Lb/r;

    .line 663
    .line 664
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 665
    .line 666
    check-cast p0, Lb/h0;

    .line 667
    .line 668
    invoke-virtual {v0}, Lb/r;->getLifecycle()Landroidx/lifecycle/r;

    .line 669
    .line 670
    .line 671
    move-result-object v1

    .line 672
    new-instance v2, Lb/g;

    .line 673
    .line 674
    invoke-direct {v2, v3, p0, v0}, Lb/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 675
    .line 676
    .line 677
    invoke-virtual {v1, v2}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 678
    .line 679
    .line 680
    return-void

    .line 681
    :pswitch_1a
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 682
    .line 683
    check-cast v0, Las/d;

    .line 684
    .line 685
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 686
    .line 687
    check-cast p0, Las/b;

    .line 688
    .line 689
    iget-object v0, v0, Las/d;->e:Las/g;

    .line 690
    .line 691
    const-string v1, "com.google.firebase.appcheck.TOKEN_TYPE"

    .line 692
    .line 693
    const-string v2, "com.google.firebase.appcheck.APP_CHECK_TOKEN"

    .line 694
    .line 695
    iget-object v0, v0, Las/g;->a:Lgs/o;

    .line 696
    .line 697
    instance-of v3, p0, Las/b;

    .line 698
    .line 699
    if-eqz v3, :cond_6

    .line 700
    .line 701
    invoke-virtual {v0}, Lgs/o;->get()Ljava/lang/Object;

    .line 702
    .line 703
    .line 704
    move-result-object v0

    .line 705
    check-cast v0, Landroid/content/SharedPreferences;

    .line 706
    .line 707
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 708
    .line 709
    .line 710
    move-result-object v3

    .line 711
    :try_start_6
    new-instance v0, Lorg/json/JSONObject;

    .line 712
    .line 713
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 714
    .line 715
    .line 716
    const-string v5, "token"

    .line 717
    .line 718
    iget-object v6, p0, Las/b;->a:Ljava/lang/String;

    .line 719
    .line 720
    invoke-virtual {v0, v5, v6}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 721
    .line 722
    .line 723
    const-string v5, "receivedAt"

    .line 724
    .line 725
    iget-wide v6, p0, Las/b;->b:J

    .line 726
    .line 727
    invoke-virtual {v0, v5, v6, v7}, Lorg/json/JSONObject;->put(Ljava/lang/String;J)Lorg/json/JSONObject;

    .line 728
    .line 729
    .line 730
    const-string v5, "expiresIn"

    .line 731
    .line 732
    iget-wide v6, p0, Las/b;->c:J

    .line 733
    .line 734
    invoke-virtual {v0, v5, v6, v7}, Lorg/json/JSONObject;->put(Ljava/lang/String;J)Lorg/json/JSONObject;

    .line 735
    .line 736
    .line 737
    invoke-virtual {v0}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    .line 738
    .line 739
    .line 740
    move-result-object v4
    :try_end_6
    .catch Lorg/json/JSONException; {:try_start_6 .. :try_end_6} :catch_1

    .line 741
    goto :goto_6

    .line 742
    :catch_1
    move-exception v0

    .line 743
    move-object p0, v0

    .line 744
    const-string v0, "as.b"

    .line 745
    .line 746
    new-instance v5, Ljava/lang/StringBuilder;

    .line 747
    .line 748
    const-string v6, "Could not serialize token: "

    .line 749
    .line 750
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 751
    .line 752
    .line 753
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 754
    .line 755
    .line 756
    move-result-object p0

    .line 757
    invoke-virtual {v5, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 758
    .line 759
    .line 760
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 761
    .line 762
    .line 763
    move-result-object p0

    .line 764
    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 765
    .line 766
    .line 767
    :goto_6
    invoke-interface {v3, v2, v4}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 768
    .line 769
    .line 770
    move-result-object p0

    .line 771
    const-string v0, "DEFAULT_APP_CHECK_TOKEN"

    .line 772
    .line 773
    invoke-interface {p0, v1, v0}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 774
    .line 775
    .line 776
    move-result-object p0

    .line 777
    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 778
    .line 779
    .line 780
    goto :goto_7

    .line 781
    :cond_6
    invoke-virtual {v0}, Lgs/o;->get()Ljava/lang/Object;

    .line 782
    .line 783
    .line 784
    move-result-object v0

    .line 785
    check-cast v0, Landroid/content/SharedPreferences;

    .line 786
    .line 787
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 788
    .line 789
    .line 790
    move-result-object v0

    .line 791
    iget-object p0, p0, Las/b;->a:Ljava/lang/String;

    .line 792
    .line 793
    invoke-interface {v0, v2, p0}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 794
    .line 795
    .line 796
    move-result-object p0

    .line 797
    const-string v0, "UNKNOWN_APP_CHECK_TOKEN"

    .line 798
    .line 799
    invoke-interface {p0, v1, v0}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 800
    .line 801
    .line 802
    move-result-object p0

    .line 803
    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 804
    .line 805
    .line 806
    :goto_7
    return-void

    .line 807
    :pswitch_1b
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 808
    .line 809
    move-object v3, v0

    .line 810
    check-cast v3, Las/d;

    .line 811
    .line 812
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 813
    .line 814
    check-cast p0, Laq/k;

    .line 815
    .line 816
    iget-object v0, v3, Las/d;->e:Las/g;

    .line 817
    .line 818
    sget-object v5, Las/g;->b:Lj51/i;

    .line 819
    .line 820
    iget-object v5, v5, Lj51/i;->b:Ljava/lang/String;

    .line 821
    .line 822
    iget-object v6, v0, Las/g;->a:Lgs/o;

    .line 823
    .line 824
    invoke-virtual {v6}, Lgs/o;->get()Ljava/lang/Object;

    .line 825
    .line 826
    .line 827
    move-result-object v0

    .line 828
    check-cast v0, Landroid/content/SharedPreferences;

    .line 829
    .line 830
    const-string v7, "com.google.firebase.appcheck.TOKEN_TYPE"

    .line 831
    .line 832
    invoke-interface {v0, v7, v4}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 833
    .line 834
    .line 835
    move-result-object v8

    .line 836
    invoke-virtual {v6}, Lgs/o;->get()Ljava/lang/Object;

    .line 837
    .line 838
    .line 839
    move-result-object v0

    .line 840
    check-cast v0, Landroid/content/SharedPreferences;

    .line 841
    .line 842
    const-string v9, "com.google.firebase.appcheck.APP_CHECK_TOKEN"

    .line 843
    .line 844
    invoke-interface {v0, v9, v4}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 845
    .line 846
    .line 847
    move-result-object v0

    .line 848
    if-eqz v8, :cond_9

    .line 849
    .line 850
    if-nez v0, :cond_7

    .line 851
    .line 852
    goto :goto_9

    .line 853
    :cond_7
    if-eqz v8, :cond_d

    .line 854
    .line 855
    :try_start_7
    const-string v10, "DEFAULT_APP_CHECK_TOKEN"

    .line 856
    .line 857
    invoke-virtual {v8, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 858
    .line 859
    .line 860
    move-result v10

    .line 861
    if-eqz v10, :cond_8

    .line 862
    .line 863
    move v1, v2

    .line 864
    goto :goto_8

    .line 865
    :cond_8
    const-string v10, "UNKNOWN_APP_CHECK_TOKEN"

    .line 866
    .line 867
    invoke-virtual {v8, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 868
    .line 869
    .line 870
    move-result v10

    .line 871
    if-eqz v10, :cond_c

    .line 872
    .line 873
    :goto_8
    invoke-static {v1}, Lu/w;->o(I)I

    .line 874
    .line 875
    .line 876
    move-result v1
    :try_end_7
    .catch Ljava/lang/IllegalArgumentException; {:try_start_7 .. :try_end_7} :catch_2

    .line 877
    if-eqz v1, :cond_b

    .line 878
    .line 879
    if-eq v1, v2, :cond_a

    .line 880
    .line 881
    const-string v0, "Reached unreachable section in #retrieveAppCheckToken()"

    .line 882
    .line 883
    invoke-static {v5, v0, v4}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 884
    .line 885
    .line 886
    :cond_9
    :goto_9
    move-object v0, v4

    .line 887
    goto :goto_b

    .line 888
    :cond_a
    :try_start_8
    invoke-static {v0}, Las/b;->a(Ljava/lang/String;)Las/b;

    .line 889
    .line 890
    .line 891
    move-result-object v0

    .line 892
    goto :goto_b

    .line 893
    :catch_2
    move-exception v0

    .line 894
    goto :goto_a

    .line 895
    :cond_b
    invoke-static {v0}, Las/b;->b(Ljava/lang/String;)Las/b;

    .line 896
    .line 897
    .line 898
    move-result-object v0

    .line 899
    goto :goto_b

    .line 900
    :cond_c
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 901
    .line 902
    const-string v1, "No enum constant com.google.firebase.appcheck.internal.StorageHelper.TokenType."

    .line 903
    .line 904
    invoke-virtual {v1, v8}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 905
    .line 906
    .line 907
    move-result-object v1

    .line 908
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 909
    .line 910
    .line 911
    throw v0

    .line 912
    :cond_d
    new-instance v0, Ljava/lang/NullPointerException;

    .line 913
    .line 914
    const-string v1, "Name is null"

    .line 915
    .line 916
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 917
    .line 918
    .line 919
    throw v0
    :try_end_8
    .catch Ljava/lang/IllegalArgumentException; {:try_start_8 .. :try_end_8} :catch_2

    .line 920
    :goto_a
    const-string v1, "Failed to parse TokenType of stored token  with type ["

    .line 921
    .line 922
    const-string v2, "] with exception: "

    .line 923
    .line 924
    invoke-static {v1, v8, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 925
    .line 926
    .line 927
    move-result-object v1

    .line 928
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 929
    .line 930
    .line 931
    move-result-object v0

    .line 932
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 933
    .line 934
    .line 935
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 936
    .line 937
    .line 938
    move-result-object v0

    .line 939
    invoke-static {v5, v0, v4}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 940
    .line 941
    .line 942
    invoke-virtual {v6}, Lgs/o;->get()Ljava/lang/Object;

    .line 943
    .line 944
    .line 945
    move-result-object v0

    .line 946
    check-cast v0, Landroid/content/SharedPreferences;

    .line 947
    .line 948
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 949
    .line 950
    .line 951
    move-result-object v0

    .line 952
    invoke-interface {v0, v9}, Landroid/content/SharedPreferences$Editor;->remove(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 953
    .line 954
    .line 955
    move-result-object v0

    .line 956
    invoke-interface {v0, v7}, Landroid/content/SharedPreferences$Editor;->remove(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 957
    .line 958
    .line 959
    move-result-object v0

    .line 960
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 961
    .line 962
    .line 963
    goto :goto_9

    .line 964
    :goto_b
    if-eqz v0, :cond_e

    .line 965
    .line 966
    iput-object v0, v3, Las/d;->m:Las/b;

    .line 967
    .line 968
    :cond_e
    invoke-virtual {p0, v4}, Laq/k;->b(Ljava/lang/Object;)V

    .line 969
    .line 970
    .line 971
    return-void

    .line 972
    :pswitch_1c
    iget-object v0, p0, La8/z;->e:Ljava/lang/Object;

    .line 973
    .line 974
    move-object v4, v0

    .line 975
    check-cast v4, La8/i0;

    .line 976
    .line 977
    iget-object p0, p0, La8/z;->f:Ljava/lang/Object;

    .line 978
    .line 979
    check-cast p0, La8/n0;

    .line 980
    .line 981
    iget v0, v4, La8/i0;->M:I

    .line 982
    .line 983
    iget v1, p0, La8/n0;->b:I

    .line 984
    .line 985
    sub-int/2addr v0, v1

    .line 986
    iput v0, v4, La8/i0;->M:I

    .line 987
    .line 988
    iget-boolean v1, p0, La8/n0;->e:Z

    .line 989
    .line 990
    if-eqz v1, :cond_f

    .line 991
    .line 992
    iget v1, p0, La8/n0;->c:I

    .line 993
    .line 994
    iput v1, v4, La8/i0;->N:I

    .line 995
    .line 996
    iput-boolean v2, v4, La8/i0;->O:Z

    .line 997
    .line 998
    :cond_f
    if-nez v0, :cond_19

    .line 999
    .line 1000
    iget-object v0, p0, La8/n0;->f:Ljava/lang/Object;

    .line 1001
    .line 1002
    check-cast v0, La8/i1;

    .line 1003
    .line 1004
    iget-object v0, v0, La8/i1;->a:Lt7/p0;

    .line 1005
    .line 1006
    iget-object v1, v4, La8/i0;->y1:La8/i1;

    .line 1007
    .line 1008
    iget-object v1, v1, La8/i1;->a:Lt7/p0;

    .line 1009
    .line 1010
    invoke-virtual {v1}, Lt7/p0;->p()Z

    .line 1011
    .line 1012
    .line 1013
    move-result v1

    .line 1014
    if-nez v1, :cond_10

    .line 1015
    .line 1016
    invoke-virtual {v0}, Lt7/p0;->p()Z

    .line 1017
    .line 1018
    .line 1019
    move-result v1

    .line 1020
    if-eqz v1, :cond_10

    .line 1021
    .line 1022
    const/4 v1, -0x1

    .line 1023
    iput v1, v4, La8/i0;->z1:I

    .line 1024
    .line 1025
    const-wide/16 v5, 0x0

    .line 1026
    .line 1027
    iput-wide v5, v4, La8/i0;->A1:J

    .line 1028
    .line 1029
    :cond_10
    invoke-virtual {v0}, Lt7/p0;->p()Z

    .line 1030
    .line 1031
    .line 1032
    move-result v1

    .line 1033
    if-nez v1, :cond_12

    .line 1034
    .line 1035
    move-object v1, v0

    .line 1036
    check-cast v1, La8/n1;

    .line 1037
    .line 1038
    iget-object v1, v1, La8/n1;->h:[Lt7/p0;

    .line 1039
    .line 1040
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 1041
    .line 1042
    .line 1043
    move-result-object v1

    .line 1044
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 1045
    .line 1046
    .line 1047
    move-result v5

    .line 1048
    iget-object v6, v4, La8/i0;->t:Ljava/util/ArrayList;

    .line 1049
    .line 1050
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 1051
    .line 1052
    .line 1053
    move-result v6

    .line 1054
    if-ne v5, v6, :cond_11

    .line 1055
    .line 1056
    move v5, v2

    .line 1057
    goto :goto_c

    .line 1058
    :cond_11
    move v5, v3

    .line 1059
    :goto_c
    invoke-static {v5}, Lw7/a;->j(Z)V

    .line 1060
    .line 1061
    .line 1062
    move v5, v3

    .line 1063
    :goto_d
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 1064
    .line 1065
    .line 1066
    move-result v6

    .line 1067
    if-ge v5, v6, :cond_12

    .line 1068
    .line 1069
    iget-object v6, v4, La8/i0;->t:Ljava/util/ArrayList;

    .line 1070
    .line 1071
    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1072
    .line 1073
    .line 1074
    move-result-object v6

    .line 1075
    check-cast v6, La8/h0;

    .line 1076
    .line 1077
    invoke-interface {v1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1078
    .line 1079
    .line 1080
    move-result-object v7

    .line 1081
    check-cast v7, Lt7/p0;

    .line 1082
    .line 1083
    iput-object v7, v6, La8/h0;->b:Lt7/p0;

    .line 1084
    .line 1085
    add-int/lit8 v5, v5, 0x1

    .line 1086
    .line 1087
    goto :goto_d

    .line 1088
    :cond_12
    iget-boolean v1, v4, La8/i0;->O:Z

    .line 1089
    .line 1090
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 1091
    .line 1092
    .line 1093
    .line 1094
    .line 1095
    if-eqz v1, :cond_18

    .line 1096
    .line 1097
    iget-object v1, p0, La8/n0;->f:Ljava/lang/Object;

    .line 1098
    .line 1099
    check-cast v1, La8/i1;

    .line 1100
    .line 1101
    iget-object v1, v1, La8/i1;->b:Lh8/b0;

    .line 1102
    .line 1103
    iget-object v7, v4, La8/i0;->y1:La8/i1;

    .line 1104
    .line 1105
    iget-object v7, v7, La8/i1;->b:Lh8/b0;

    .line 1106
    .line 1107
    invoke-virtual {v1, v7}, Lh8/b0;->equals(Ljava/lang/Object;)Z

    .line 1108
    .line 1109
    .line 1110
    move-result v1

    .line 1111
    if-eqz v1, :cond_14

    .line 1112
    .line 1113
    iget-object v1, p0, La8/n0;->f:Ljava/lang/Object;

    .line 1114
    .line 1115
    check-cast v1, La8/i1;

    .line 1116
    .line 1117
    iget-wide v7, v1, La8/i1;->d:J

    .line 1118
    .line 1119
    iget-object v1, v4, La8/i0;->y1:La8/i1;

    .line 1120
    .line 1121
    iget-wide v9, v1, La8/i1;->s:J

    .line 1122
    .line 1123
    cmp-long v1, v7, v9

    .line 1124
    .line 1125
    if-eqz v1, :cond_13

    .line 1126
    .line 1127
    goto :goto_e

    .line 1128
    :cond_13
    move v2, v3

    .line 1129
    :cond_14
    :goto_e
    if-eqz v2, :cond_17

    .line 1130
    .line 1131
    invoke-virtual {v0}, Lt7/p0;->p()Z

    .line 1132
    .line 1133
    .line 1134
    move-result v1

    .line 1135
    if-nez v1, :cond_16

    .line 1136
    .line 1137
    iget-object v1, p0, La8/n0;->f:Ljava/lang/Object;

    .line 1138
    .line 1139
    check-cast v1, La8/i1;

    .line 1140
    .line 1141
    iget-object v1, v1, La8/i1;->b:Lh8/b0;

    .line 1142
    .line 1143
    invoke-virtual {v1}, Lh8/b0;->b()Z

    .line 1144
    .line 1145
    .line 1146
    move-result v1

    .line 1147
    if-eqz v1, :cond_15

    .line 1148
    .line 1149
    goto :goto_f

    .line 1150
    :cond_15
    iget-object v1, p0, La8/n0;->f:Ljava/lang/Object;

    .line 1151
    .line 1152
    check-cast v1, La8/i1;

    .line 1153
    .line 1154
    iget-object v5, v1, La8/i1;->b:Lh8/b0;

    .line 1155
    .line 1156
    iget-wide v6, v1, La8/i1;->d:J

    .line 1157
    .line 1158
    iget-object v1, v5, Lh8/b0;->a:Ljava/lang/Object;

    .line 1159
    .line 1160
    iget-object v5, v4, La8/i0;->s:Lt7/n0;

    .line 1161
    .line 1162
    invoke-virtual {v0, v1, v5}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 1163
    .line 1164
    .line 1165
    iget-wide v0, v5, Lt7/n0;->e:J

    .line 1166
    .line 1167
    add-long/2addr v6, v0

    .line 1168
    move-wide v5, v6

    .line 1169
    goto :goto_10

    .line 1170
    :cond_16
    :goto_f
    iget-object v0, p0, La8/n0;->f:Ljava/lang/Object;

    .line 1171
    .line 1172
    check-cast v0, La8/i1;

    .line 1173
    .line 1174
    iget-wide v0, v0, La8/i1;->d:J

    .line 1175
    .line 1176
    move-wide v5, v0

    .line 1177
    :cond_17
    :goto_10
    move v7, v2

    .line 1178
    :goto_11
    move-wide v9, v5

    .line 1179
    goto :goto_12

    .line 1180
    :cond_18
    move v7, v3

    .line 1181
    goto :goto_11

    .line 1182
    :goto_12
    iput-boolean v3, v4, La8/i0;->O:Z

    .line 1183
    .line 1184
    iget-object p0, p0, La8/n0;->f:Ljava/lang/Object;

    .line 1185
    .line 1186
    move-object v5, p0

    .line 1187
    check-cast v5, La8/i1;

    .line 1188
    .line 1189
    iget v8, v4, La8/i0;->N:I

    .line 1190
    .line 1191
    const/4 v11, -0x1

    .line 1192
    const/4 v12, 0x0

    .line 1193
    const/4 v6, 0x1

    .line 1194
    invoke-virtual/range {v4 .. v12}, La8/i0;->J0(La8/i1;IZIJIZ)V

    .line 1195
    .line 1196
    .line 1197
    :cond_19
    return-void

    .line 1198
    nop

    .line 1199
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
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
