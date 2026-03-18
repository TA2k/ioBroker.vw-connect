.class public final Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;
.super Lcom/google/firebase/messaging/FirebaseMessagingService;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ly11/a;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0000\u0018\u00002\u00020\u00012\u00020\u0002B\u0007\u00a2\u0006\u0004\u0008\u0003\u0010\u0004\u00a8\u0006\u0005"
    }
    d2 = {
        "Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;",
        "Lcom/google/firebase/messaging/FirebaseMessagingService;",
        "Ly11/a;",
        "<init>",
        "()V",
        "push-notifications_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final synthetic j:I


# instance fields
.field public final d:Ljava/lang/Object;

.field public final e:Ljava/lang/Object;

.field public final f:Ljava/lang/Object;

.field public final g:Ljava/lang/Object;

.field public final h:Ljava/lang/Object;

.field public final i:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Lcom/google/firebase/messaging/FirebaseMessagingService;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Llx0/j;->d:Llx0/j;

    .line 5
    .line 6
    new-instance v1, Lbp0/h;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    invoke-direct {v1, p0, v2}, Lbp0/h;-><init>(Ly11/a;I)V

    .line 10
    .line 11
    .line 12
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    iput-object v1, p0, Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;->d:Ljava/lang/Object;

    .line 17
    .line 18
    new-instance v1, Lbp0/h;

    .line 19
    .line 20
    const/4 v2, 0x1

    .line 21
    invoke-direct {v1, p0, v2}, Lbp0/h;-><init>(Ly11/a;I)V

    .line 22
    .line 23
    .line 24
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    iput-object v1, p0, Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;->e:Ljava/lang/Object;

    .line 29
    .line 30
    new-instance v1, Lbp0/h;

    .line 31
    .line 32
    const/4 v2, 0x2

    .line 33
    invoke-direct {v1, p0, v2}, Lbp0/h;-><init>(Ly11/a;I)V

    .line 34
    .line 35
    .line 36
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    iput-object v1, p0, Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;->f:Ljava/lang/Object;

    .line 41
    .line 42
    new-instance v1, Lbp0/h;

    .line 43
    .line 44
    const/4 v2, 0x3

    .line 45
    invoke-direct {v1, p0, v2}, Lbp0/h;-><init>(Ly11/a;I)V

    .line 46
    .line 47
    .line 48
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    iput-object v1, p0, Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;->g:Ljava/lang/Object;

    .line 53
    .line 54
    new-instance v1, Lbp0/h;

    .line 55
    .line 56
    const/4 v2, 0x4

    .line 57
    invoke-direct {v1, p0, v2}, Lbp0/h;-><init>(Ly11/a;I)V

    .line 58
    .line 59
    .line 60
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    iput-object v1, p0, Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;->h:Ljava/lang/Object;

    .line 65
    .line 66
    new-instance v1, Lbp0/h;

    .line 67
    .line 68
    const/4 v2, 0x5

    .line 69
    invoke-direct {v1, p0, v2}, Lbp0/h;-><init>(Ly11/a;I)V

    .line 70
    .line 71
    .line 72
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    iput-object v0, p0, Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;->i:Ljava/lang/Object;

    .line 77
    .line 78
    return-void
.end method

.method public static final c(Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;Lcom/google/firebase/messaging/v;Lrx0/c;)Ljava/lang/Object;
    .locals 30

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    instance-of v3, v2, Lbp0/f;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Lbp0/f;

    .line 13
    .line 14
    iget v4, v3, Lbp0/f;->p:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lbp0/f;->p:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lbp0/f;

    .line 27
    .line 28
    invoke-direct {v3, v1, v2}, Lbp0/f;-><init>(Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Lbp0/f;->n:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lbp0/f;->p:I

    .line 36
    .line 37
    const-string v6, "groupId"

    .line 38
    .line 39
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    const/4 v8, 0x2

    .line 42
    const/4 v9, 0x1

    .line 43
    if-eqz v5, :cond_3

    .line 44
    .line 45
    if-eq v5, v9, :cond_2

    .line 46
    .line 47
    if-ne v5, v8, :cond_1

    .line 48
    .line 49
    iget-object v0, v3, Lbp0/f;->e:Lcom/google/firebase/messaging/v;

    .line 50
    .line 51
    check-cast v0, Lap0/f;

    .line 52
    .line 53
    :try_start_0
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 54
    .line 55
    .line 56
    goto/16 :goto_e

    .line 57
    .line 58
    :catchall_0
    move-exception v0

    .line 59
    goto/16 :goto_f

    .line 60
    .line 61
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 62
    .line 63
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 64
    .line 65
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw v0

    .line 69
    :cond_2
    iget v0, v3, Lbp0/f;->m:I

    .line 70
    .line 71
    iget v5, v3, Lbp0/f;->l:I

    .line 72
    .line 73
    iget-object v9, v3, Lbp0/f;->k:Lcom/google/firebase/messaging/v;

    .line 74
    .line 75
    iget-object v12, v3, Lbp0/f;->j:Ljava/lang/String;

    .line 76
    .line 77
    iget-object v13, v3, Lbp0/f;->i:Ljava/lang/String;

    .line 78
    .line 79
    iget-object v14, v3, Lbp0/f;->h:Lap0/o;

    .line 80
    .line 81
    iget-object v15, v3, Lbp0/f;->g:Lap0/a;

    .line 82
    .line 83
    iget-object v8, v3, Lbp0/f;->f:Ljava/lang/String;

    .line 84
    .line 85
    iget-object v11, v3, Lbp0/f;->e:Lcom/google/firebase/messaging/v;

    .line 86
    .line 87
    iget-object v10, v3, Lbp0/f;->d:Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;

    .line 88
    .line 89
    :try_start_1
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 90
    .line 91
    .line 92
    move-object/from16 v29, v2

    .line 93
    .line 94
    move v2, v0

    .line 95
    move-object v0, v9

    .line 96
    move-object v9, v8

    .line 97
    move v8, v5

    .line 98
    move-object/from16 v5, v29

    .line 99
    .line 100
    goto/16 :goto_5

    .line 101
    .line 102
    :cond_3
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    :try_start_2
    sget-object v2, Lap0/a;->e:Ldv/a;

    .line 106
    .line 107
    invoke-virtual {v0}, Lcom/google/firebase/messaging/v;->x0()Ljava/util/Map;

    .line 108
    .line 109
    .line 110
    move-result-object v5

    .line 111
    invoke-interface {v5, v6}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v5

    .line 115
    check-cast v5, Ljava/lang/String;

    .line 116
    .line 117
    if-eqz v5, :cond_19

    .line 118
    .line 119
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 120
    .line 121
    .line 122
    sget-object v2, Lap0/a;->i:Lsx0/b;

    .line 123
    .line 124
    invoke-virtual {v2}, Lmx0/e;->iterator()Ljava/util/Iterator;

    .line 125
    .line 126
    .line 127
    move-result-object v2

    .line 128
    :cond_4
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 129
    .line 130
    .line 131
    move-result v8

    .line 132
    if-eqz v8, :cond_5

    .line 133
    .line 134
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v8

    .line 138
    move-object v10, v8

    .line 139
    check-cast v10, Lap0/a;

    .line 140
    .line 141
    iget-object v10, v10, Lap0/a;->d:Ljava/lang/String;

    .line 142
    .line 143
    invoke-virtual {v10, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result v10

    .line 147
    if-eqz v10, :cond_4

    .line 148
    .line 149
    goto :goto_1

    .line 150
    :cond_5
    const/4 v8, 0x0

    .line 151
    :goto_1
    check-cast v8, Lap0/a;

    .line 152
    .line 153
    if-nez v8, :cond_6

    .line 154
    .line 155
    sget-object v2, Lap0/a;->g:Lap0/a;

    .line 156
    .line 157
    move-object v15, v2

    .line 158
    goto :goto_2

    .line 159
    :cond_6
    move-object v15, v8

    .line 160
    :goto_2
    invoke-static {v0}, Ljp/bb;->g(Lcom/google/firebase/messaging/v;)Lap0/o;

    .line 161
    .line 162
    .line 163
    move-result-object v2

    .line 164
    sget-object v5, Lap0/m;->f:Lap0/m;

    .line 165
    .line 166
    invoke-virtual {v2, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v2

    .line 170
    if-eqz v2, :cond_7

    .line 171
    .line 172
    invoke-virtual {v15}, Ljava/lang/Enum;->ordinal()I

    .line 173
    .line 174
    .line 175
    move-result v2

    .line 176
    goto :goto_3

    .line 177
    :cond_7
    new-instance v2, Ljava/security/SecureRandom;

    .line 178
    .line 179
    invoke-direct {v2}, Ljava/security/SecureRandom;-><init>()V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v2}, Ljava/util/Random;->nextInt()I

    .line 183
    .line 184
    .line 185
    move-result v2

    .line 186
    :goto_3
    iget-object v8, v0, Lcom/google/firebase/messaging/v;->d:Landroid/os/Bundle;

    .line 187
    .line 188
    const-string v10, "google.message_id"

    .line 189
    .line 190
    invoke-virtual {v8, v10}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 191
    .line 192
    .line 193
    move-result-object v10

    .line 194
    if-nez v10, :cond_8

    .line 195
    .line 196
    const-string v10, "message_id"

    .line 197
    .line 198
    invoke-virtual {v8, v10}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object v8

    .line 202
    goto :goto_4

    .line 203
    :cond_8
    move-object v8, v10

    .line 204
    :goto_4
    invoke-static {v0}, Ljp/bb;->g(Lcom/google/firebase/messaging/v;)Lap0/o;

    .line 205
    .line 206
    .line 207
    move-result-object v14

    .line 208
    invoke-virtual {v0}, Lcom/google/firebase/messaging/v;->x0()Ljava/util/Map;

    .line 209
    .line 210
    .line 211
    move-result-object v10

    .line 212
    const-string v11, "version"

    .line 213
    .line 214
    invoke-interface {v10, v11}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v10

    .line 218
    move-object v13, v10

    .line 219
    check-cast v13, Ljava/lang/String;

    .line 220
    .line 221
    if-eqz v13, :cond_18

    .line 222
    .line 223
    invoke-virtual {v0}, Lcom/google/firebase/messaging/v;->x0()Ljava/util/Map;

    .line 224
    .line 225
    .line 226
    move-result-object v10

    .line 227
    const-string v11, "traceId"

    .line 228
    .line 229
    invoke-interface {v10, v11}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object v10

    .line 233
    move-object v12, v10

    .line 234
    check-cast v12, Ljava/lang/String;

    .line 235
    .line 236
    if-eqz v12, :cond_17

    .line 237
    .line 238
    invoke-static {v0}, Ljp/bb;->g(Lcom/google/firebase/messaging/v;)Lap0/o;

    .line 239
    .line 240
    .line 241
    move-result-object v10

    .line 242
    invoke-virtual {v10, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 243
    .line 244
    .line 245
    move-result v5

    .line 246
    if-eqz v5, :cond_d

    .line 247
    .line 248
    invoke-static {v0}, Ljp/bb;->f(Lcom/google/firebase/messaging/v;)Ljava/time/OffsetDateTime;

    .line 249
    .line 250
    .line 251
    move-result-object v5

    .line 252
    if-eqz v5, :cond_c

    .line 253
    .line 254
    iget-object v10, v1, Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;->i:Ljava/lang/Object;

    .line 255
    .line 256
    invoke-interface {v10}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object v10

    .line 260
    check-cast v10, Lzo0/a;

    .line 261
    .line 262
    iput-object v1, v3, Lbp0/f;->d:Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;

    .line 263
    .line 264
    iput-object v0, v3, Lbp0/f;->e:Lcom/google/firebase/messaging/v;

    .line 265
    .line 266
    iput-object v8, v3, Lbp0/f;->f:Ljava/lang/String;

    .line 267
    .line 268
    iput-object v15, v3, Lbp0/f;->g:Lap0/a;

    .line 269
    .line 270
    iput-object v14, v3, Lbp0/f;->h:Lap0/o;

    .line 271
    .line 272
    iput-object v13, v3, Lbp0/f;->i:Ljava/lang/String;

    .line 273
    .line 274
    iput-object v12, v3, Lbp0/f;->j:Ljava/lang/String;

    .line 275
    .line 276
    iput-object v0, v3, Lbp0/f;->k:Lcom/google/firebase/messaging/v;

    .line 277
    .line 278
    const/4 v11, 0x0

    .line 279
    iput v11, v3, Lbp0/f;->l:I

    .line 280
    .line 281
    iput v2, v3, Lbp0/f;->m:I

    .line 282
    .line 283
    iput v9, v3, Lbp0/f;->p:I

    .line 284
    .line 285
    iget-object v10, v10, Lzo0/a;->a:Lzo0/k;

    .line 286
    .line 287
    check-cast v10, Lwo0/a;

    .line 288
    .line 289
    iget-object v11, v10, Lwo0/a;->a:Ljava/time/OffsetDateTime;

    .line 290
    .line 291
    iput-object v5, v10, Lwo0/a;->a:Ljava/time/OffsetDateTime;

    .line 292
    .line 293
    if-eqz v11, :cond_9

    .line 294
    .line 295
    invoke-virtual {v11, v5}, Ljava/time/OffsetDateTime;->isBefore(Ljava/time/OffsetDateTime;)Z

    .line 296
    .line 297
    .line 298
    move-result v9

    .line 299
    :cond_9
    invoke-static {v9}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 300
    .line 301
    .line 302
    move-result-object v5

    .line 303
    if-ne v5, v4, :cond_a

    .line 304
    .line 305
    goto/16 :goto_d

    .line 306
    .line 307
    :cond_a
    move-object v11, v0

    .line 308
    move-object v10, v1

    .line 309
    move-object v9, v8

    .line 310
    const/4 v8, 0x0

    .line 311
    :goto_5
    check-cast v5, Ljava/lang/Boolean;

    .line 312
    .line 313
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 314
    .line 315
    .line 316
    move-result v5

    .line 317
    if-eqz v5, :cond_b

    .line 318
    .line 319
    move v5, v8

    .line 320
    move-object v8, v9

    .line 321
    goto :goto_6

    .line 322
    :cond_b
    invoke-static {v0}, Ljp/bb;->f(Lcom/google/firebase/messaging/v;)Ljava/time/OffsetDateTime;

    .line 323
    .line 324
    .line 325
    move-result-object v0

    .line 326
    new-instance v2, Ljava/lang/StringBuilder;

    .line 327
    .line 328
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 329
    .line 330
    .line 331
    const-string v3, "obsolete triggerTimestamp: "

    .line 332
    .line 333
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 334
    .line 335
    .line 336
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 337
    .line 338
    .line 339
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 340
    .line 341
    .line 342
    move-result-object v0

    .line 343
    new-instance v2, Ljava/lang/IllegalArgumentException;

    .line 344
    .line 345
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 346
    .line 347
    .line 348
    move-result-object v0

    .line 349
    invoke-direct {v2, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 350
    .line 351
    .line 352
    throw v2

    .line 353
    :cond_c
    const-string v5, "FCM"

    .line 354
    .line 355
    new-instance v9, Lay/b;

    .line 356
    .line 357
    const/16 v10, 0xb

    .line 358
    .line 359
    invoke-direct {v9, v10}, Lay/b;-><init>(I)V

    .line 360
    .line 361
    .line 362
    invoke-static {v5, v0, v9}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 363
    .line 364
    .line 365
    move-object v11, v0

    .line 366
    move-object v10, v1

    .line 367
    const/4 v5, 0x0

    .line 368
    :goto_6
    invoke-static {v0}, Ljp/bb;->b(Lcom/google/firebase/messaging/v;)Lap0/b;

    .line 369
    .line 370
    .line 371
    move-result-object v0

    .line 372
    move-object/from16 v25, v0

    .line 373
    .line 374
    move-object v0, v11

    .line 375
    move v11, v5

    .line 376
    :goto_7
    move/from16 v17, v2

    .line 377
    .line 378
    move-object/from16 v18, v8

    .line 379
    .line 380
    move-object/from16 v21, v12

    .line 381
    .line 382
    move-object/from16 v20, v13

    .line 383
    .line 384
    move-object/from16 v19, v14

    .line 385
    .line 386
    move-object/from16 v23, v15

    .line 387
    .line 388
    goto :goto_8

    .line 389
    :cond_d
    invoke-static {v0}, Ljp/bb;->c(Lcom/google/firebase/messaging/v;)Lap0/c;

    .line 390
    .line 391
    .line 392
    move-result-object v5

    .line 393
    move-object v10, v1

    .line 394
    move-object/from16 v25, v5

    .line 395
    .line 396
    const/4 v11, 0x0

    .line 397
    goto :goto_7

    .line 398
    :goto_8
    invoke-virtual {v0}, Lcom/google/firebase/messaging/v;->x0()Ljava/util/Map;

    .line 399
    .line 400
    .line 401
    move-result-object v2

    .line 402
    const-string v5, "campaignId"

    .line 403
    .line 404
    invoke-interface {v2, v5}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 405
    .line 406
    .line 407
    move-result-object v2

    .line 408
    move-object/from16 v26, v2

    .line 409
    .line 410
    check-cast v26, Ljava/lang/String;

    .line 411
    .line 412
    invoke-virtual {v0}, Lcom/google/firebase/messaging/v;->x0()Ljava/util/Map;

    .line 413
    .line 414
    .line 415
    move-result-object v2

    .line 416
    const-string v5, "trackingUrl"

    .line 417
    .line 418
    invoke-interface {v2, v5}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 419
    .line 420
    .line 421
    move-result-object v2

    .line 422
    move-object/from16 v27, v2

    .line 423
    .line 424
    check-cast v27, Ljava/lang/String;

    .line 425
    .line 426
    invoke-static {v0}, Ljp/bb;->f(Lcom/google/firebase/messaging/v;)Ljava/time/OffsetDateTime;

    .line 427
    .line 428
    .line 429
    move-result-object v24

    .line 430
    invoke-virtual {v0}, Lcom/google/firebase/messaging/v;->x0()Ljava/util/Map;

    .line 431
    .line 432
    .line 433
    move-result-object v2

    .line 434
    invoke-interface {v2, v6}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 435
    .line 436
    .line 437
    move-result-object v2

    .line 438
    check-cast v2, Ljava/lang/String;

    .line 439
    .line 440
    if-eqz v2, :cond_13

    .line 441
    .line 442
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 443
    .line 444
    .line 445
    move-result v5

    .line 446
    const v6, 0x1a1b9

    .line 447
    .line 448
    .line 449
    if-eq v5, v6, :cond_11

    .line 450
    .line 451
    const v6, 0x1bbe2

    .line 452
    .line 453
    .line 454
    if-eq v5, v6, :cond_f

    .line 455
    .line 456
    const v6, 0x585f139

    .line 457
    .line 458
    .line 459
    if-eq v5, v6, :cond_e

    .line 460
    .line 461
    goto :goto_a

    .line 462
    :cond_e
    const-string v5, "adhoc"

    .line 463
    .line 464
    invoke-virtual {v2, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 465
    .line 466
    .line 467
    move-result v2

    .line 468
    if-eqz v2, :cond_13

    .line 469
    .line 470
    const/16 v2, 0x3e9

    .line 471
    .line 472
    :goto_9
    move/from16 v22, v2

    .line 473
    .line 474
    goto :goto_b

    .line 475
    :cond_f
    const-string v5, "sap"

    .line 476
    .line 477
    invoke-virtual {v2, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 478
    .line 479
    .line 480
    move-result v2

    .line 481
    if-nez v2, :cond_10

    .line 482
    .line 483
    goto :goto_a

    .line 484
    :cond_10
    const/16 v2, 0x3eb

    .line 485
    .line 486
    goto :goto_9

    .line 487
    :cond_11
    const-string v5, "lbo"

    .line 488
    .line 489
    invoke-virtual {v2, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 490
    .line 491
    .line 492
    move-result v2

    .line 493
    if-nez v2, :cond_12

    .line 494
    .line 495
    goto :goto_a

    .line 496
    :cond_12
    const/16 v2, 0x3ea

    .line 497
    .line 498
    goto :goto_9

    .line 499
    :cond_13
    :goto_a
    const/16 v2, 0x3e8

    .line 500
    .line 501
    goto :goto_9

    .line 502
    :goto_b
    invoke-virtual {v0}, Lcom/google/firebase/messaging/v;->x0()Ljava/util/Map;

    .line 503
    .line 504
    .line 505
    move-result-object v0

    .line 506
    const-string v2, "defaultDeeplink"

    .line 507
    .line 508
    invoke-interface {v0, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 509
    .line 510
    .line 511
    move-result-object v0

    .line 512
    check-cast v0, Ljava/lang/String;

    .line 513
    .line 514
    if-eqz v0, :cond_14

    .line 515
    .line 516
    const-string v2, "myskoda://app"

    .line 517
    .line 518
    const/4 v5, 0x0

    .line 519
    invoke-static {v0, v2, v5}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 520
    .line 521
    .line 522
    move-result v2

    .line 523
    if-eqz v2, :cond_14

    .line 524
    .line 525
    goto :goto_c

    .line 526
    :cond_14
    const/4 v0, 0x0

    .line 527
    :goto_c
    if-nez v0, :cond_15

    .line 528
    .line 529
    const-string v0, "myskoda://app/home"

    .line 530
    .line 531
    :cond_15
    move-object/from16 v28, v0

    .line 532
    .line 533
    new-instance v16, Lap0/f;

    .line 534
    .line 535
    invoke-direct/range {v16 .. v28}, Lap0/f;-><init>(ILjava/lang/String;Lap0/o;Ljava/lang/String;Ljava/lang/String;ILap0/a;Ljava/time/OffsetDateTime;Lap0/b;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 536
    .line 537
    .line 538
    move-object/from16 v0, v16

    .line 539
    .line 540
    iget-object v2, v10, Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;->g:Ljava/lang/Object;

    .line 541
    .line 542
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 543
    .line 544
    .line 545
    move-result-object v2

    .line 546
    check-cast v2, Lbp0/o;

    .line 547
    .line 548
    const/4 v5, 0x0

    .line 549
    iput-object v5, v3, Lbp0/f;->d:Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;

    .line 550
    .line 551
    iput-object v5, v3, Lbp0/f;->e:Lcom/google/firebase/messaging/v;

    .line 552
    .line 553
    iput-object v5, v3, Lbp0/f;->f:Ljava/lang/String;

    .line 554
    .line 555
    iput-object v5, v3, Lbp0/f;->g:Lap0/a;

    .line 556
    .line 557
    iput-object v5, v3, Lbp0/f;->h:Lap0/o;

    .line 558
    .line 559
    iput-object v5, v3, Lbp0/f;->i:Ljava/lang/String;

    .line 560
    .line 561
    iput-object v5, v3, Lbp0/f;->j:Ljava/lang/String;

    .line 562
    .line 563
    iput-object v5, v3, Lbp0/f;->k:Lcom/google/firebase/messaging/v;

    .line 564
    .line 565
    iput v11, v3, Lbp0/f;->l:I

    .line 566
    .line 567
    const/4 v5, 0x2

    .line 568
    iput v5, v3, Lbp0/f;->p:I

    .line 569
    .line 570
    invoke-virtual {v2, v10, v0, v3}, Lbp0/o;->a(Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;Lap0/f;Lrx0/c;)Ljava/lang/Object;

    .line 571
    .line 572
    .line 573
    move-result-object v0

    .line 574
    if-ne v0, v4, :cond_16

    .line 575
    .line 576
    :goto_d
    return-object v4

    .line 577
    :cond_16
    :goto_e
    move-object v0, v7

    .line 578
    goto :goto_10

    .line 579
    :cond_17
    const-string v0, "Required value `traceId` was null."

    .line 580
    .line 581
    new-instance v2, Ljava/lang/IllegalArgumentException;

    .line 582
    .line 583
    invoke-direct {v2, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 584
    .line 585
    .line 586
    throw v2

    .line 587
    :cond_18
    const-string v0, "Required value `version` was null."

    .line 588
    .line 589
    new-instance v2, Ljava/lang/IllegalArgumentException;

    .line 590
    .line 591
    invoke-direct {v2, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 592
    .line 593
    .line 594
    throw v2

    .line 595
    :cond_19
    const-string v0, "Required value `groupId` was null."

    .line 596
    .line 597
    new-instance v2, Ljava/lang/IllegalArgumentException;

    .line 598
    .line 599
    invoke-direct {v2, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 600
    .line 601
    .line 602
    throw v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 603
    :goto_f
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 604
    .line 605
    .line 606
    move-result-object v0

    .line 607
    :goto_10
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 608
    .line 609
    .line 610
    move-result-object v0

    .line 611
    if-eqz v0, :cond_1a

    .line 612
    .line 613
    new-instance v2, Lbp0/e;

    .line 614
    .line 615
    const/4 v3, 0x0

    .line 616
    invoke-direct {v2, v0, v3}, Lbp0/e;-><init>(Ljava/lang/Throwable;I)V

    .line 617
    .line 618
    .line 619
    invoke-static {v1, v2}, Llp/nd;->e(Ljava/lang/Object;Lay0/a;)V

    .line 620
    .line 621
    .line 622
    :cond_1a
    return-object v7
.end method


# virtual methods
.method public final bridge b()Landroidx/lifecycle/c1;
    .locals 0

    .line 1
    invoke-static {}, Llp/qf;->a()Landroidx/lifecycle/c1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final onMessageReceived(Lcom/google/firebase/messaging/v;)V
    .locals 10

    .line 1
    invoke-static {p1}, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->isMarketingCloudPush(Lcom/google/firebase/messaging/v;)Z

    .line 2
    .line 3
    .line 4
    move-result v3

    .line 5
    invoke-virtual {p1}, Lcom/google/firebase/messaging/v;->x0()Ljava/util/Map;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const-string v1, "getData(...)"

    .line 10
    .line 11
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    new-instance v4, Ljava/util/ArrayList;

    .line 15
    .line 16
    invoke-interface {v0}, Ljava/util/Map;->size()I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    invoke-direct {v4, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 21
    .line 22
    .line 23
    invoke-interface {v0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_0

    .line 36
    .line 37
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    check-cast v1, Ljava/util/Map$Entry;

    .line 42
    .line 43
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    new-instance v5, Ljava/lang/StringBuilder;

    .line 52
    .line 53
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v2, ": "

    .line 60
    .line 61
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_0
    const/4 v8, 0x0

    .line 76
    const/16 v9, 0x3e

    .line 77
    .line 78
    const-string v5, "\n"

    .line 79
    .line 80
    const/4 v6, 0x0

    .line 81
    const/4 v7, 0x0

    .line 82
    invoke-static/range {v4 .. v9}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    new-instance v1, Laa/k;

    .line 87
    .line 88
    const/16 v2, 0x9

    .line 89
    .line 90
    invoke-direct {v1, v2, p1, v0}, Laa/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    const-string v0, "FCM"

    .line 94
    .line 95
    invoke-static {v0, p1, v1}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 96
    .line 97
    .line 98
    sget-object v6, Lge0/a;->d:Lge0/a;

    .line 99
    .line 100
    new-instance v0, Lbp0/g;

    .line 101
    .line 102
    const/4 v5, 0x0

    .line 103
    const/4 v4, 0x0

    .line 104
    move-object v1, p0

    .line 105
    move-object v2, p1

    .line 106
    invoke-direct/range {v0 .. v5}, Lbp0/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 107
    .line 108
    .line 109
    const/4 p0, 0x3

    .line 110
    invoke-static {v6, v4, v4, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 111
    .line 112
    .line 113
    if-eqz v3, :cond_1

    .line 114
    .line 115
    iget-object p0, v1, Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;->f:Ljava/lang/Object;

    .line 116
    .line 117
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    check-cast p0, Lbp0/m;

    .line 122
    .line 123
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 124
    .line 125
    .line 126
    iget-object p0, p0, Lbp0/m;->a:Lyy0/q1;

    .line 127
    .line 128
    invoke-virtual {p0, v2}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    return-void

    .line 132
    :cond_1
    new-instance p0, La50/c;

    .line 133
    .line 134
    const/16 p1, 0xd

    .line 135
    .line 136
    invoke-direct {p0, p1, v1, v2, v4}, La50/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 137
    .line 138
    .line 139
    invoke-static {p0}, Lvy0/e0;->L(Lay0/n;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    return-void
.end method

.method public final onNewToken(Ljava/lang/String;)V
    .locals 2

    .line 1
    const-string v0, "token"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lac0/a;

    .line 7
    .line 8
    const/16 v1, 0xc

    .line 9
    .line 10
    invoke-direct {v0, p1, v1}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 11
    .line 12
    .line 13
    const-string v1, "FCM"

    .line 14
    .line 15
    invoke-static {v1, p0, v0}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 16
    .line 17
    .line 18
    iget-object v0, p0, Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;->d:Ljava/lang/Object;

    .line 19
    .line 20
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    check-cast v0, Lxo0/a;

    .line 25
    .line 26
    iget-object v0, v0, Lxo0/a;->d:Lyy0/q1;

    .line 27
    .line 28
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    iget-object p0, p0, Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;->e:Ljava/lang/Object;

    .line 34
    .line 35
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    check-cast p0, Lzo0/n;

    .line 40
    .line 41
    check-cast p0, Lup0/a;

    .line 42
    .line 43
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    new-instance v0, Lup0/b;

    .line 47
    .line 48
    invoke-direct {v0, p1}, Lup0/b;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    iget-object p0, p0, Lup0/a;->a:Lyy0/q1;

    .line 52
    .line 53
    invoke-virtual {p0, v0}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    return-void
.end method
