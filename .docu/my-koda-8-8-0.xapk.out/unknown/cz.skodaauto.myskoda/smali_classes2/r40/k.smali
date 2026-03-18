.class public final Lr40/k;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:J

.field public e:I

.field public f:Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;

.field public g:I

.field public final synthetic h:J

.field public final synthetic i:Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;


# direct methods
.method public constructor <init>(JLcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lr40/k;->h:J

    .line 2
    .line 3
    iput-object p3, p0, Lr40/k;->i:Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    new-instance p1, Lr40/k;

    .line 2
    .line 3
    iget-wide v0, p0, Lr40/k;->h:J

    .line 4
    .line 5
    iget-object p0, p0, Lr40/k;->i:Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;

    .line 6
    .line 7
    invoke-direct {p1, v0, v1, p0, p2}, Lr40/k;-><init>(JLcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lr40/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lr40/k;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lr40/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v2, v0, Lr40/k;->i:Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;

    .line 4
    .line 5
    iget-object v7, v2, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->g:Ljava/lang/Object;

    .line 6
    .line 7
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    iget v1, v0, Lr40/k;->g:I

    .line 10
    .line 11
    sget-object v9, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    const/4 v10, 0x3

    .line 14
    const/4 v11, 0x2

    .line 15
    const/4 v5, 0x0

    .line 16
    const/4 v12, 0x1

    .line 17
    if-eqz v1, :cond_3

    .line 18
    .line 19
    if-eq v1, v12, :cond_2

    .line 20
    .line 21
    if-eq v1, v11, :cond_1

    .line 22
    .line 23
    if-ne v1, v10, :cond_0

    .line 24
    .line 25
    iget v1, v0, Lr40/k;->e:I

    .line 26
    .line 27
    iget-wide v3, v0, Lr40/k;->d:J

    .line 28
    .line 29
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    move-wide v14, v3

    .line 33
    move v4, v12

    .line 34
    goto/16 :goto_5

    .line 35
    .line 36
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 39
    .line 40
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw v0

    .line 44
    :cond_1
    iget v1, v0, Lr40/k;->e:I

    .line 45
    .line 46
    iget-wide v3, v0, Lr40/k;->d:J

    .line 47
    .line 48
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    iget v1, v0, Lr40/k;->e:I

    .line 53
    .line 54
    iget-wide v3, v0, Lr40/k;->d:J

    .line 55
    .line 56
    iget-object v6, v0, Lr40/k;->f:Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;

    .line 57
    .line 58
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    move-object v13, v6

    .line 62
    move-object/from16 v6, p1

    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_3
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    iget-wide v3, v0, Lr40/k;->h:J

    .line 69
    .line 70
    const/4 v1, 0x0

    .line 71
    :goto_0
    add-int/2addr v1, v12

    .line 72
    rem-int/lit8 v6, v1, 0x5

    .line 73
    .line 74
    if-nez v6, :cond_6

    .line 75
    .line 76
    iget-object v6, v2, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->d:Ljava/lang/Object;

    .line 77
    .line 78
    invoke-interface {v6}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v6

    .line 82
    check-cast v6, Lo40/d;

    .line 83
    .line 84
    iput-object v2, v0, Lr40/k;->f:Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;

    .line 85
    .line 86
    iput-wide v3, v0, Lr40/k;->d:J

    .line 87
    .line 88
    iput v1, v0, Lr40/k;->e:I

    .line 89
    .line 90
    iput v12, v0, Lr40/k;->g:I

    .line 91
    .line 92
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 93
    .line 94
    .line 95
    iget-object v6, v6, Lo40/d;->a:Lln0/g;

    .line 96
    .line 97
    iget-object v6, v6, Lln0/g;->d:Ljava/lang/String;

    .line 98
    .line 99
    if-ne v6, v8, :cond_4

    .line 100
    .line 101
    goto/16 :goto_4

    .line 102
    .line 103
    :cond_4
    move-object v13, v2

    .line 104
    :goto_1
    check-cast v6, Ljava/lang/String;

    .line 105
    .line 106
    iput-object v5, v0, Lr40/k;->f:Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;

    .line 107
    .line 108
    iput-wide v3, v0, Lr40/k;->d:J

    .line 109
    .line 110
    iput v1, v0, Lr40/k;->e:I

    .line 111
    .line 112
    iput v11, v0, Lr40/k;->g:I

    .line 113
    .line 114
    iget-object v14, v13, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->k:Lvy0/x1;

    .line 115
    .line 116
    if-eqz v14, :cond_5

    .line 117
    .line 118
    invoke-virtual {v14, v5}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 119
    .line 120
    .line 121
    :cond_5
    sget-object v14, Lge0/b;->c:Lcz0/d;

    .line 122
    .line 123
    invoke-static {v14}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 124
    .line 125
    .line 126
    move-result-object v14

    .line 127
    new-instance v15, Lna/e;

    .line 128
    .line 129
    const/16 v11, 0x1d

    .line 130
    .line 131
    invoke-direct {v15, v11, v13, v6, v5}, Lna/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 132
    .line 133
    .line 134
    invoke-static {v14, v5, v5, v15, v10}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 135
    .line 136
    .line 137
    move-result-object v6

    .line 138
    iput-object v6, v13, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->k:Lvy0/x1;

    .line 139
    .line 140
    if-ne v9, v8, :cond_6

    .line 141
    .line 142
    goto/16 :goto_4

    .line 143
    .line 144
    :cond_6
    :goto_2
    move v11, v1

    .line 145
    const-wide/16 v13, 0x0

    .line 146
    .line 147
    invoke-static {v3, v4, v13, v14}, Lmy0/c;->d(JJ)Z

    .line 148
    .line 149
    .line 150
    move-result v1

    .line 151
    const-string v13, "curNotification"

    .line 152
    .line 153
    if-eqz v1, :cond_8

    .line 154
    .line 155
    sget v1, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->p:I

    .line 156
    .line 157
    invoke-interface {v7}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    check-cast v1, Landroid/app/NotificationManager;

    .line 162
    .line 163
    iget-object v6, v2, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->m:Landroidx/core/app/x;

    .line 164
    .line 165
    if-eqz v6, :cond_7

    .line 166
    .line 167
    const v13, 0x7f120e42

    .line 168
    .line 169
    .line 170
    invoke-virtual {v2, v13}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object v13

    .line 174
    invoke-static {v13}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 175
    .line 176
    .line 177
    move-result-object v13

    .line 178
    iput-object v13, v6, Landroidx/core/app/x;->f:Ljava/lang/CharSequence;

    .line 179
    .line 180
    invoke-virtual {v6}, Landroidx/core/app/x;->a()Landroid/app/Notification;

    .line 181
    .line 182
    .line 183
    move-result-object v6

    .line 184
    invoke-virtual {v1, v12, v6}, Landroid/app/NotificationManager;->notify(ILandroid/app/Notification;)V

    .line 185
    .line 186
    .line 187
    move-wide v14, v3

    .line 188
    move v4, v12

    .line 189
    goto :goto_3

    .line 190
    :cond_7
    invoke-static {v13}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    throw v5

    .line 194
    :cond_8
    sget-wide v14, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->o:J

    .line 195
    .line 196
    invoke-static {v3, v4, v14, v15}, Lmy0/c;->j(JJ)J

    .line 197
    .line 198
    .line 199
    move-result-wide v14

    .line 200
    invoke-static {v14, v15}, Lmy0/c;->e(J)J

    .line 201
    .line 202
    .line 203
    move-result-wide v3

    .line 204
    sget-object v1, Lge0/b;->c:Lcz0/d;

    .line 205
    .line 206
    invoke-static {v1}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 207
    .line 208
    .line 209
    move-result-object v1

    .line 210
    move-object v6, v1

    .line 211
    new-instance v1, Le2/f0;

    .line 212
    .line 213
    move-object/from16 v16, v6

    .line 214
    .line 215
    const/4 v6, 0x5

    .line 216
    move-object/from16 v12, v16

    .line 217
    .line 218
    invoke-direct/range {v1 .. v6}, Le2/f0;-><init>(Ljava/lang/Object;JLkotlin/coroutines/Continuation;I)V

    .line 219
    .line 220
    .line 221
    invoke-static {v12, v5, v5, v1, v10}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 222
    .line 223
    .line 224
    iget-object v1, v2, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->m:Landroidx/core/app/x;

    .line 225
    .line 226
    if-eqz v1, :cond_b

    .line 227
    .line 228
    invoke-static {v14, v15}, Ljp/d1;->e(J)Ljava/lang/String;

    .line 229
    .line 230
    .line 231
    move-result-object v3

    .line 232
    invoke-static {v3}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 233
    .line 234
    .line 235
    move-result-object v3

    .line 236
    iput-object v3, v1, Landroidx/core/app/x;->f:Ljava/lang/CharSequence;

    .line 237
    .line 238
    invoke-interface {v7}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v3

    .line 242
    check-cast v3, Landroid/app/NotificationManager;

    .line 243
    .line 244
    invoke-virtual {v1}, Landroidx/core/app/x;->a()Landroid/app/Notification;

    .line 245
    .line 246
    .line 247
    move-result-object v1

    .line 248
    const/4 v4, 0x1

    .line 249
    invoke-virtual {v3, v4, v1}, Landroid/app/NotificationManager;->notify(ILandroid/app/Notification;)V

    .line 250
    .line 251
    .line 252
    :goto_3
    sget-wide v12, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->o:J

    .line 253
    .line 254
    invoke-static {v12, v13}, Lmy0/c;->e(J)J

    .line 255
    .line 256
    .line 257
    move-result-wide v12

    .line 258
    iput-wide v14, v0, Lr40/k;->d:J

    .line 259
    .line 260
    iput v11, v0, Lr40/k;->e:I

    .line 261
    .line 262
    iput v10, v0, Lr40/k;->g:I

    .line 263
    .line 264
    invoke-static {v12, v13, v0}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    move-result-object v1

    .line 268
    if-ne v1, v8, :cond_9

    .line 269
    .line 270
    :goto_4
    return-object v8

    .line 271
    :cond_9
    move v1, v11

    .line 272
    :goto_5
    iget-boolean v3, v2, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;->l:Z

    .line 273
    .line 274
    if-nez v3, :cond_a

    .line 275
    .line 276
    return-object v9

    .line 277
    :cond_a
    move v12, v4

    .line 278
    move-wide v3, v14

    .line 279
    const/4 v11, 0x2

    .line 280
    goto/16 :goto_0

    .line 281
    .line 282
    :cond_b
    invoke-static {v13}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 283
    .line 284
    .line 285
    throw v5
.end method
