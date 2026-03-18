.class public final La7/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/util/concurrent/atomic/AtomicBoolean;

.field public final c:Lxy0/j;

.field public final d:La7/m0;

.field public final e:La7/c;

.field public final f:Li7/a;

.field public final g:La7/a2;

.field public final h:Z

.field public final i:Ll2/j1;

.field public final j:Ll2/j1;

.field public k:Ljava/lang/Object;

.field public final l:Lvy0/k1;

.field public final m:Lyy0/c2;


# direct methods
.method public constructor <init>(La7/m0;La7/c;Landroid/os/Bundle;I)V
    .locals 5

    .line 1
    and-int/lit8 p4, p4, 0x4

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p4, :cond_0

    .line 5
    .line 6
    move-object p3, v0

    .line 7
    :cond_0
    sget-object p4, Li7/f;->a:Li7/f;

    .line 8
    .line 9
    move-object v1, p1

    .line 10
    check-cast v1, Lza0/q;

    .line 11
    .line 12
    iget-object v1, v1, Lza0/q;->c:La7/y1;

    .line 13
    .line 14
    iget v2, p2, La7/c;->a:I

    .line 15
    .line 16
    invoke-static {v2}, Lcy0/a;->f(I)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v2, p0, La7/n;->a:Ljava/lang/String;

    .line 24
    .line 25
    new-instance v2, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 26
    .line 27
    const/4 v3, 0x1

    .line 28
    invoke-direct {v2, v3}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 29
    .line 30
    .line 31
    iput-object v2, p0, La7/n;->b:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 32
    .line 33
    const/4 v2, 0x0

    .line 34
    const/4 v3, 0x6

    .line 35
    const v4, 0x7fffffff

    .line 36
    .line 37
    .line 38
    invoke-static {v4, v3, v2}, Llp/jf;->a(IILxy0/a;)Lxy0/j;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    iput-object v2, p0, La7/n;->c:Lxy0/j;

    .line 43
    .line 44
    iput-object p1, p0, La7/n;->d:La7/m0;

    .line 45
    .line 46
    iput-object p2, p0, La7/n;->e:La7/c;

    .line 47
    .line 48
    iput-object p4, p0, La7/n;->f:Li7/a;

    .line 49
    .line 50
    iput-object v1, p0, La7/n;->g:La7/a2;

    .line 51
    .line 52
    const/4 p1, 0x1

    .line 53
    iput-boolean p1, p0, La7/n;->h:Z

    .line 54
    .line 55
    iget p1, p2, La7/c;->a:I

    .line 56
    .line 57
    const/high16 p2, -0x80000000

    .line 58
    .line 59
    if-gt p2, p1, :cond_2

    .line 60
    .line 61
    const/4 p2, -0x1

    .line 62
    if-lt p1, p2, :cond_1

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 66
    .line 67
    const-string p1, "If the AppWidgetSession is not created for a bound widget, you must provide a lambda action receiver"

    .line 68
    .line 69
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw p0

    .line 73
    :cond_2
    :goto_0
    sget-object p1, Ll2/x0;->f:Ll2/x0;

    .line 74
    .line 75
    new-instance p2, Ll2/j1;

    .line 76
    .line 77
    invoke-direct {p2, v0, p1}, Ll2/j1;-><init>(Ljava/lang/Object;Ll2/n2;)V

    .line 78
    .line 79
    .line 80
    iput-object p2, p0, La7/n;->i:Ll2/j1;

    .line 81
    .line 82
    new-instance p2, Ll2/j1;

    .line 83
    .line 84
    invoke-direct {p2, p3, p1}, Ll2/j1;-><init>(Ljava/lang/Object;Ll2/n2;)V

    .line 85
    .line 86
    .line 87
    iput-object p2, p0, La7/n;->j:Ll2/j1;

    .line 88
    .line 89
    sget-object p1, Lmx0/t;->d:Lmx0/t;

    .line 90
    .line 91
    iput-object p1, p0, La7/n;->k:Ljava/lang/Object;

    .line 92
    .line 93
    invoke-static {}, Lvy0/e0;->d()Lvy0/k1;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    iput-object p1, p0, La7/n;->l:Lvy0/k1;

    .line 98
    .line 99
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    iput-object p1, p0, La7/n;->m:Lyy0/c2;

    .line 104
    .line 105
    return-void
.end method


# virtual methods
.method public final a(Landroid/content/Context;Ljava/lang/Throwable;)V
    .locals 2

    .line 1
    const-string v0, "GlanceAppWidget"

    .line 2
    .line 3
    const-string v1, "Error in Glance App Widget"

    .line 4
    .line 5
    invoke-static {v0, v1, p2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 6
    .line 7
    .line 8
    iget-boolean v0, p0, La7/n;->h:Z

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-object p2, p0, La7/n;->e:La7/c;

    .line 13
    .line 14
    iget p2, p2, La7/c;->a:I

    .line 15
    .line 16
    iget-object p0, p0, La7/n;->d:La7/m0;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    new-instance p0, Landroid/widget/RemoteViews;

    .line 22
    .line 23
    invoke-virtual {p1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    const v1, 0x7f0d0194

    .line 28
    .line 29
    .line 30
    invoke-direct {p0, v0, v1}, Landroid/widget/RemoteViews;-><init>(Ljava/lang/String;I)V

    .line 31
    .line 32
    .line 33
    invoke-static {p1}, Landroid/appwidget/AppWidgetManager;->getInstance(Landroid/content/Context;)Landroid/appwidget/AppWidgetManager;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-virtual {p1, p2, p0}, Landroid/appwidget/AppWidgetManager;->updateAppWidget(ILandroid/widget/RemoteViews;)V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :cond_0
    throw p2
.end method

.method public final b(Landroid/content/Context;Ly6/n;Lrx0/c;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    const-string v4, "No app widget info for "

    .line 10
    .line 11
    instance-of v5, v3, La7/h;

    .line 12
    .line 13
    if-eqz v5, :cond_0

    .line 14
    .line 15
    move-object v5, v3

    .line 16
    check-cast v5, La7/h;

    .line 17
    .line 18
    iget v6, v5, La7/h;->i:I

    .line 19
    .line 20
    const/high16 v7, -0x80000000

    .line 21
    .line 22
    and-int v8, v6, v7

    .line 23
    .line 24
    if-eqz v8, :cond_0

    .line 25
    .line 26
    sub-int/2addr v6, v7

    .line 27
    iput v6, v5, La7/h;->i:I

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    new-instance v5, La7/h;

    .line 31
    .line 32
    invoke-direct {v5, v0, v3}, La7/h;-><init>(La7/n;Lrx0/c;)V

    .line 33
    .line 34
    .line 35
    :goto_0
    iget-object v3, v5, La7/h;->g:Ljava/lang/Object;

    .line 36
    .line 37
    sget-object v6, Lqx0/a;->d:Lqx0/a;

    .line 38
    .line 39
    iget v7, v5, La7/h;->i:I

    .line 40
    .line 41
    const/4 v8, 0x5

    .line 42
    const/4 v9, 0x4

    .line 43
    const/4 v10, 0x3

    .line 44
    const/4 v11, 0x2

    .line 45
    const/4 v12, 0x1

    .line 46
    if-eqz v7, :cond_4

    .line 47
    .line 48
    if-eq v7, v12, :cond_3

    .line 49
    .line 50
    if-eq v7, v11, :cond_2

    .line 51
    .line 52
    if-eq v7, v10, :cond_2

    .line 53
    .line 54
    if-eq v7, v9, :cond_2

    .line 55
    .line 56
    if-eq v7, v8, :cond_1

    .line 57
    .line 58
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 59
    .line 60
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 61
    .line 62
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    throw v0

    .line 66
    :cond_1
    iget-object v0, v5, La7/h;->d:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v0, Ljava/lang/Throwable;

    .line 69
    .line 70
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    goto/16 :goto_6

    .line 74
    .line 75
    :cond_2
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    goto/16 :goto_4

    .line 79
    .line 80
    :cond_3
    iget-object v0, v5, La7/h;->f:Ly6/n;

    .line 81
    .line 82
    iget-object v1, v5, La7/h;->e:Landroid/content/Context;

    .line 83
    .line 84
    iget-object v2, v5, La7/h;->d:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast v2, La7/n;

    .line 87
    .line 88
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    :goto_1
    move-object v12, v1

    .line 92
    goto :goto_2

    .line 93
    :cond_4
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    invoke-static {v2}, Li0/d;->e(Ly6/l;)Z

    .line 97
    .line 98
    .line 99
    move-result v3

    .line 100
    if-eqz v3, :cond_5

    .line 101
    .line 102
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 103
    .line 104
    return-object v0

    .line 105
    :cond_5
    const-string v3, "null cannot be cast to non-null type androidx.glance.appwidget.RemoteViewsRoot"

    .line 106
    .line 107
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    move-object v3, v2

    .line 111
    check-cast v3, La7/q1;

    .line 112
    .line 113
    iget-object v3, v0, La7/n;->e:La7/c;

    .line 114
    .line 115
    iget v3, v3, La7/c;->a:I

    .line 116
    .line 117
    iput-object v0, v5, La7/h;->d:Ljava/lang/Object;

    .line 118
    .line 119
    iput-object v1, v5, La7/h;->e:Landroid/content/Context;

    .line 120
    .line 121
    iput-object v2, v5, La7/h;->f:Ly6/n;

    .line 122
    .line 123
    iput v12, v5, La7/h;->i:I

    .line 124
    .line 125
    sget-object v7, La7/f1;->g:La7/a0;

    .line 126
    .line 127
    invoke-virtual {v7, v1, v3, v5}, La7/a0;->b(Landroid/content/Context;ILrx0/c;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v3

    .line 131
    if-ne v3, v6, :cond_6

    .line 132
    .line 133
    goto/16 :goto_7

    .line 134
    .line 135
    :cond_6
    move-object v12, v2

    .line 136
    move-object v2, v0

    .line 137
    move-object v0, v12

    .line 138
    goto :goto_1

    .line 139
    :goto_2
    move-object v15, v3

    .line 140
    check-cast v15, La7/f1;

    .line 141
    .line 142
    const-string v1, "appwidget"

    .line 143
    .line 144
    invoke-virtual {v12, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    const-string v3, "null cannot be cast to non-null type android.appwidget.AppWidgetManager"

    .line 149
    .line 150
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    check-cast v1, Landroid/appwidget/AppWidgetManager;

    .line 154
    .line 155
    const/4 v3, 0x0

    .line 156
    :try_start_0
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 157
    .line 158
    .line 159
    iget-object v7, v2, La7/n;->e:La7/c;

    .line 160
    .line 161
    :try_start_1
    iget v13, v7, La7/c;->a:I

    .line 162
    .line 163
    invoke-virtual {v1, v13}, Landroid/appwidget/AppWidgetManager;->getAppWidgetInfo(I)Landroid/appwidget/AppWidgetProviderInfo;

    .line 164
    .line 165
    .line 166
    move-result-object v13

    .line 167
    if-eqz v13, :cond_9

    .line 168
    .line 169
    iget-object v4, v13, Landroid/appwidget/AppWidgetProviderInfo;->provider:Landroid/content/ComponentName;

    .line 170
    .line 171
    move-object v13, v0

    .line 172
    check-cast v13, La7/q1;

    .line 173
    .line 174
    invoke-static {v13}, Lim/g;->d(La7/q1;)V

    .line 175
    .line 176
    .line 177
    invoke-static {v0}, Lim/g;->j(Ly6/n;)Ljava/util/LinkedHashMap;

    .line 178
    .line 179
    .line 180
    move-result-object v13

    .line 181
    iput-object v13, v2, La7/n;->k:Ljava/lang/Object;

    .line 182
    .line 183
    iget v13, v7, La7/c;->a:I

    .line 184
    .line 185
    move-object v14, v0

    .line 186
    check-cast v14, La7/q1;

    .line 187
    .line 188
    invoke-virtual {v15, v0}, La7/f1;->a(Ly6/n;)I

    .line 189
    .line 190
    .line 191
    move-result v16

    .line 192
    move-object/from16 v17, v4

    .line 193
    .line 194
    invoke-static/range {v12 .. v17}, Lip/t;->f(Landroid/content/Context;ILa7/q1;La7/f1;ILandroid/content/ComponentName;)Landroid/widget/RemoteViews;

    .line 195
    .line 196
    .line 197
    move-result-object v0

    .line 198
    iget-boolean v4, v2, La7/n;->h:Z

    .line 199
    .line 200
    if-eqz v4, :cond_7

    .line 201
    .line 202
    iget v4, v7, La7/c;->a:I

    .line 203
    .line 204
    invoke-virtual {v1, v4, v0}, Landroid/appwidget/AppWidgetManager;->updateAppWidget(ILandroid/widget/RemoteViews;)V

    .line 205
    .line 206
    .line 207
    goto :goto_3

    .line 208
    :catchall_0
    move-exception v0

    .line 209
    goto :goto_5

    .line 210
    :cond_7
    :goto_3
    iget-object v1, v2, La7/n;->m:Lyy0/c2;

    .line 211
    .line 212
    invoke-virtual {v1, v0}, Lyy0/c2;->j(Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 213
    .line 214
    .line 215
    iput-object v3, v5, La7/h;->d:Ljava/lang/Object;

    .line 216
    .line 217
    iput-object v3, v5, La7/h;->e:Landroid/content/Context;

    .line 218
    .line 219
    iput-object v3, v5, La7/h;->f:Ly6/n;

    .line 220
    .line 221
    iput v11, v5, La7/h;->i:I

    .line 222
    .line 223
    invoke-virtual {v15, v5}, La7/f1;->b(La7/h;)Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v0

    .line 227
    if-ne v0, v6, :cond_8

    .line 228
    .line 229
    goto :goto_7

    .line 230
    :cond_8
    :goto_4
    invoke-static {}, La7/c2;->a()V

    .line 231
    .line 232
    .line 233
    goto :goto_8

    .line 234
    :cond_9
    :try_start_2
    new-instance v0, Ljava/lang/StringBuilder;

    .line 235
    .line 236
    invoke-direct {v0, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 237
    .line 238
    .line 239
    iget v1, v7, La7/c;->a:I

    .line 240
    .line 241
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 242
    .line 243
    .line 244
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 245
    .line 246
    .line 247
    move-result-object v0

    .line 248
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 249
    .line 250
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 251
    .line 252
    .line 253
    move-result-object v0

    .line 254
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 255
    .line 256
    .line 257
    throw v1
    :try_end_2
    .catch Ljava/util/concurrent/CancellationException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 258
    :goto_5
    :try_start_3
    invoke-virtual {v2, v12, v0}, La7/n;->a(Landroid/content/Context;Ljava/lang/Throwable;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 259
    .line 260
    .line 261
    iput-object v3, v5, La7/h;->d:Ljava/lang/Object;

    .line 262
    .line 263
    iput-object v3, v5, La7/h;->e:Landroid/content/Context;

    .line 264
    .line 265
    iput-object v3, v5, La7/h;->f:Ly6/n;

    .line 266
    .line 267
    iput v9, v5, La7/h;->i:I

    .line 268
    .line 269
    invoke-virtual {v15, v5}, La7/f1;->b(La7/h;)Ljava/lang/Object;

    .line 270
    .line 271
    .line 272
    move-result-object v0

    .line 273
    if-ne v0, v6, :cond_8

    .line 274
    .line 275
    goto :goto_7

    .line 276
    :catchall_1
    move-exception v0

    .line 277
    iput-object v0, v5, La7/h;->d:Ljava/lang/Object;

    .line 278
    .line 279
    iput-object v3, v5, La7/h;->e:Landroid/content/Context;

    .line 280
    .line 281
    iput-object v3, v5, La7/h;->f:Ly6/n;

    .line 282
    .line 283
    iput v8, v5, La7/h;->i:I

    .line 284
    .line 285
    invoke-virtual {v15, v5}, La7/f1;->b(La7/h;)Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v1

    .line 289
    if-ne v1, v6, :cond_a

    .line 290
    .line 291
    goto :goto_7

    .line 292
    :cond_a
    :goto_6
    invoke-static {}, La7/c2;->a()V

    .line 293
    .line 294
    .line 295
    throw v0

    .line 296
    :catch_0
    iput-object v3, v5, La7/h;->d:Ljava/lang/Object;

    .line 297
    .line 298
    iput-object v3, v5, La7/h;->e:Landroid/content/Context;

    .line 299
    .line 300
    iput-object v3, v5, La7/h;->f:Ly6/n;

    .line 301
    .line 302
    iput v10, v5, La7/h;->i:I

    .line 303
    .line 304
    invoke-virtual {v15, v5}, La7/f1;->b(La7/h;)Ljava/lang/Object;

    .line 305
    .line 306
    .line 307
    move-result-object v0

    .line 308
    if-ne v0, v6, :cond_8

    .line 309
    .line 310
    :goto_7
    return-object v6

    .line 311
    :goto_8
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 312
    .line 313
    return-object v0
.end method

.method public final c(Landroid/content/Context;Ljava/lang/Object;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p3, La7/i;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, La7/i;

    .line 7
    .line 8
    iget v1, v0, La7/i;->g:I

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
    iput v1, v0, La7/i;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, La7/i;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, La7/i;-><init>(La7/n;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, La7/i;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, La7/i;->g:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const-string v4, "Cannot create a mutable snapshot of an read-only snapshot"

    .line 34
    .line 35
    const/4 v5, 0x1

    .line 36
    const/4 v6, 0x0

    .line 37
    if-eqz v2, :cond_2

    .line 38
    .line 39
    if-ne v2, v5, :cond_1

    .line 40
    .line 41
    iget-object p0, v0, La7/i;->d:La7/n;

    .line 42
    .line 43
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    instance-of p3, p2, La7/f;

    .line 59
    .line 60
    iget-object v2, p0, La7/n;->a:Ljava/lang/String;

    .line 61
    .line 62
    if-eqz p3, :cond_7

    .line 63
    .line 64
    iget-object p2, p0, La7/n;->d:La7/m0;

    .line 65
    .line 66
    iget-object p2, p2, La7/m0;->b:Li7/h;

    .line 67
    .line 68
    if-eqz p2, :cond_3

    .line 69
    .line 70
    iput-object p0, v0, La7/i;->d:La7/n;

    .line 71
    .line 72
    iput v5, v0, La7/i;->g:I

    .line 73
    .line 74
    iget-object p3, p0, La7/n;->f:Li7/a;

    .line 75
    .line 76
    check-cast p3, Li7/f;

    .line 77
    .line 78
    invoke-virtual {p3, p1, p2, v2, v0}, Li7/f;->c(Landroid/content/Context;Li7/g;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p3

    .line 82
    if-ne p3, v1, :cond_4

    .line 83
    .line 84
    return-object v1

    .line 85
    :cond_3
    move-object p3, v6

    .line 86
    :cond_4
    :goto_1
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    instance-of p2, p1, Lv2/b;

    .line 91
    .line 92
    if-eqz p2, :cond_5

    .line 93
    .line 94
    check-cast p1, Lv2/b;

    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_5
    move-object p1, v6

    .line 98
    :goto_2
    if-eqz p1, :cond_6

    .line 99
    .line 100
    invoke-virtual {p1, v6, v6}, Lv2/b;->C(Lay0/k;Lay0/k;)Lv2/b;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    if-eqz p1, :cond_6

    .line 105
    .line 106
    :try_start_0
    invoke-virtual {p1}, Lv2/f;->j()Lv2/f;

    .line 107
    .line 108
    .line 109
    move-result-object p2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 110
    :try_start_1
    iget-object p0, p0, La7/n;->i:Ll2/j1;

    .line 111
    .line 112
    invoke-virtual {p0, p3}, Ll2/j1;->setValue(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 113
    .line 114
    .line 115
    :try_start_2
    invoke-static {p2}, Lv2/f;->q(Lv2/f;)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {p1}, Lv2/b;->w()Lv2/p;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    invoke-virtual {p0}, Lv2/p;->d()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 123
    .line 124
    .line 125
    invoke-virtual {p1}, Lv2/b;->c()V

    .line 126
    .line 127
    .line 128
    return-object v3

    .line 129
    :catchall_0
    move-exception p0

    .line 130
    goto :goto_3

    .line 131
    :catchall_1
    move-exception p0

    .line 132
    :try_start_3
    invoke-static {p2}, Lv2/f;->q(Lv2/f;)V

    .line 133
    .line 134
    .line 135
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 136
    :goto_3
    invoke-virtual {p1}, Lv2/b;->c()V

    .line 137
    .line 138
    .line 139
    throw p0

    .line 140
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 141
    .line 142
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    throw p0

    .line 146
    :cond_7
    instance-of p1, p2, La7/e;

    .line 147
    .line 148
    if-eqz p1, :cond_a

    .line 149
    .line 150
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    instance-of p3, p1, Lv2/b;

    .line 155
    .line 156
    if-eqz p3, :cond_8

    .line 157
    .line 158
    check-cast p1, Lv2/b;

    .line 159
    .line 160
    goto :goto_4

    .line 161
    :cond_8
    move-object p1, v6

    .line 162
    :goto_4
    if-eqz p1, :cond_9

    .line 163
    .line 164
    invoke-virtual {p1, v6, v6}, Lv2/b;->C(Lay0/k;Lay0/k;)Lv2/b;

    .line 165
    .line 166
    .line 167
    move-result-object p1

    .line 168
    if-eqz p1, :cond_9

    .line 169
    .line 170
    :try_start_4
    invoke-virtual {p1}, Lv2/f;->j()Lv2/f;

    .line 171
    .line 172
    .line 173
    move-result-object p3
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 174
    :try_start_5
    check-cast p2, La7/e;

    .line 175
    .line 176
    iget-object p2, p2, La7/e;->a:Landroid/os/Bundle;

    .line 177
    .line 178
    iget-object p0, p0, La7/n;->j:Ll2/j1;

    .line 179
    .line 180
    invoke-virtual {p0, p2}, Ll2/j1;->setValue(Ljava/lang/Object;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 181
    .line 182
    .line 183
    :try_start_6
    invoke-static {p3}, Lv2/f;->q(Lv2/f;)V

    .line 184
    .line 185
    .line 186
    invoke-virtual {p1}, Lv2/b;->w()Lv2/p;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    invoke-virtual {p0}, Lv2/p;->d()V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 191
    .line 192
    .line 193
    invoke-virtual {p1}, Lv2/b;->c()V

    .line 194
    .line 195
    .line 196
    return-object v3

    .line 197
    :catchall_2
    move-exception p0

    .line 198
    goto :goto_5

    .line 199
    :catchall_3
    move-exception p0

    .line 200
    :try_start_7
    invoke-static {p3}, Lv2/f;->q(Lv2/f;)V

    .line 201
    .line 202
    .line 203
    throw p0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 204
    :goto_5
    invoke-virtual {p1}, Lv2/b;->c()V

    .line 205
    .line 206
    .line 207
    throw p0

    .line 208
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 209
    .line 210
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    throw p0

    .line 214
    :cond_a
    instance-of p1, p2, La7/d;

    .line 215
    .line 216
    if-eqz p1, :cond_f

    .line 217
    .line 218
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 219
    .line 220
    .line 221
    move-result-object p1

    .line 222
    instance-of p3, p1, Lv2/b;

    .line 223
    .line 224
    if-eqz p3, :cond_b

    .line 225
    .line 226
    check-cast p1, Lv2/b;

    .line 227
    .line 228
    goto :goto_6

    .line 229
    :cond_b
    move-object p1, v6

    .line 230
    :goto_6
    if-eqz p1, :cond_e

    .line 231
    .line 232
    invoke-virtual {p1, v6, v6}, Lv2/b;->C(Lay0/k;Lay0/k;)Lv2/b;

    .line 233
    .line 234
    .line 235
    move-result-object p1

    .line 236
    if-eqz p1, :cond_e

    .line 237
    .line 238
    :try_start_8
    invoke-virtual {p1}, Lv2/f;->j()Lv2/f;

    .line 239
    .line 240
    .line 241
    move-result-object p3
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_5

    .line 242
    :try_start_9
    iget-object p0, p0, La7/n;->k:Ljava/lang/Object;

    .line 243
    .line 244
    move-object v0, p2

    .line 245
    check-cast v0, La7/d;

    .line 246
    .line 247
    iget-object v0, v0, La7/d;->a:Ljava/lang/String;

    .line 248
    .line 249
    invoke-interface {p0, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 250
    .line 251
    .line 252
    move-result-object p0

    .line 253
    check-cast p0, Ljava/util/List;

    .line 254
    .line 255
    if-eqz p0, :cond_d

    .line 256
    .line 257
    check-cast p0, Ljava/lang/Iterable;

    .line 258
    .line 259
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 260
    .line 261
    .line 262
    move-result-object p0

    .line 263
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 264
    .line 265
    .line 266
    move-result v0

    .line 267
    if-nez v0, :cond_c

    .line 268
    .line 269
    move-object v6, v3

    .line 270
    goto :goto_7

    .line 271
    :cond_c
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object p0

    .line 275
    check-cast p0, Lz6/e;

    .line 276
    .line 277
    throw v6
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_4

    .line 278
    :catchall_4
    move-exception p0

    .line 279
    goto :goto_8

    .line 280
    :cond_d
    :goto_7
    :try_start_a
    invoke-static {p3}, Lv2/f;->q(Lv2/f;)V

    .line 281
    .line 282
    .line 283
    invoke-virtual {p1}, Lv2/b;->w()Lv2/p;

    .line 284
    .line 285
    .line 286
    move-result-object p0

    .line 287
    invoke-virtual {p0}, Lv2/p;->d()V
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_5

    .line 288
    .line 289
    .line 290
    invoke-virtual {p1}, Lv2/b;->c()V

    .line 291
    .line 292
    .line 293
    if-nez v6, :cond_10

    .line 294
    .line 295
    new-instance p0, Ljava/lang/StringBuilder;

    .line 296
    .line 297
    const-string p1, "Triggering Action("

    .line 298
    .line 299
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 300
    .line 301
    .line 302
    check-cast p2, La7/d;

    .line 303
    .line 304
    iget-object p1, p2, La7/d;->a:Ljava/lang/String;

    .line 305
    .line 306
    const-string p2, ") for session("

    .line 307
    .line 308
    const-string p3, ") failed"

    .line 309
    .line 310
    invoke-static {p0, p1, p2, v2, p3}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 311
    .line 312
    .line 313
    move-result-object p0

    .line 314
    const-string p1, "AppWidgetSession"

    .line 315
    .line 316
    invoke-static {p1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 317
    .line 318
    .line 319
    move-result p0

    .line 320
    new-instance p1, Ljava/lang/Integer;

    .line 321
    .line 322
    invoke-direct {p1, p0}, Ljava/lang/Integer;-><init>(I)V

    .line 323
    .line 324
    .line 325
    return-object v3

    .line 326
    :catchall_5
    move-exception p0

    .line 327
    goto :goto_9

    .line 328
    :goto_8
    :try_start_b
    invoke-static {p3}, Lv2/f;->q(Lv2/f;)V

    .line 329
    .line 330
    .line 331
    throw p0
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_5

    .line 332
    :goto_9
    invoke-virtual {p1}, Lv2/b;->c()V

    .line 333
    .line 334
    .line 335
    throw p0

    .line 336
    :cond_e
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 337
    .line 338
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 339
    .line 340
    .line 341
    throw p0

    .line 342
    :cond_f
    instance-of p0, p2, La7/g;

    .line 343
    .line 344
    if-eqz p0, :cond_11

    .line 345
    .line 346
    check-cast p2, La7/g;

    .line 347
    .line 348
    iget-object p0, p2, La7/g;->a:Lvy0/k1;

    .line 349
    .line 350
    invoke-virtual {p0}, Lvy0/p1;->a()Z

    .line 351
    .line 352
    .line 353
    move-result p1

    .line 354
    if-eqz p1, :cond_10

    .line 355
    .line 356
    invoke-virtual {p0}, Lvy0/k1;->l0()Z

    .line 357
    .line 358
    .line 359
    :cond_10
    return-object v3

    .line 360
    :cond_11
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 361
    .line 362
    new-instance p1, Ljava/lang/StringBuilder;

    .line 363
    .line 364
    const-string p3, "Sent unrecognized event type "

    .line 365
    .line 366
    invoke-direct {p1, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 367
    .line 368
    .line 369
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 370
    .line 371
    .line 372
    move-result-object p2

    .line 373
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 374
    .line 375
    .line 376
    const-string p2, " to AppWidgetSession"

    .line 377
    .line 378
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 379
    .line 380
    .line 381
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 382
    .line 383
    .line 384
    move-result-object p1

    .line 385
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 386
    .line 387
    .line 388
    throw p0
.end method

.method public final d(Landroid/content/Context;La3/g;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p3, Lh7/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lh7/g;

    .line 7
    .line 8
    iget v1, v0, Lh7/g;->j:I

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
    iput v1, v0, Lh7/g;->j:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lh7/g;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lh7/g;-><init>(La7/n;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lh7/g;->h:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lh7/g;->j:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_4

    .line 34
    .line 35
    if-eq v2, v4, :cond_3

    .line 36
    .line 37
    if-ne v2, v3, :cond_2

    .line 38
    .line 39
    iget-object p0, v0, Lh7/g;->g:Lxy0/c;

    .line 40
    .line 41
    iget-object p1, v0, Lh7/g;->f:Lay0/k;

    .line 42
    .line 43
    iget-object p2, v0, Lh7/g;->e:Landroid/content/Context;

    .line 44
    .line 45
    iget-object v2, v0, Lh7/g;->d:La7/n;

    .line 46
    .line 47
    :try_start_0
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Lxy0/s; {:try_start_0 .. :try_end_0} :catch_0

    .line 48
    .line 49
    .line 50
    :cond_1
    move-object v5, v2

    .line 51
    move-object v2, p0

    .line 52
    move-object p0, v5

    .line 53
    move-object v5, p2

    .line 54
    move-object p2, p1

    .line 55
    move-object p1, v5

    .line 56
    goto :goto_1

    .line 57
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 60
    .line 61
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p0

    .line 65
    :cond_3
    iget-object p0, v0, Lh7/g;->g:Lxy0/c;

    .line 66
    .line 67
    iget-object p1, v0, Lh7/g;->f:Lay0/k;

    .line 68
    .line 69
    iget-object p2, v0, Lh7/g;->e:Landroid/content/Context;

    .line 70
    .line 71
    iget-object v2, v0, Lh7/g;->d:La7/n;

    .line 72
    .line 73
    :try_start_1
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catch Lxy0/s; {:try_start_1 .. :try_end_1} :catch_0

    .line 74
    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_4
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    :try_start_2
    iget-object p3, p0, La7/n;->c:Lxy0/j;

    .line 81
    .line 82
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 83
    .line 84
    .line 85
    new-instance v2, Lxy0/c;

    .line 86
    .line 87
    invoke-direct {v2, p3}, Lxy0/c;-><init>(Lxy0/j;)V

    .line 88
    .line 89
    .line 90
    :goto_1
    iput-object p0, v0, Lh7/g;->d:La7/n;

    .line 91
    .line 92
    iput-object p1, v0, Lh7/g;->e:Landroid/content/Context;

    .line 93
    .line 94
    iput-object p2, v0, Lh7/g;->f:Lay0/k;

    .line 95
    .line 96
    iput-object v2, v0, Lh7/g;->g:Lxy0/c;

    .line 97
    .line 98
    iput v4, v0, Lh7/g;->j:I

    .line 99
    .line 100
    invoke-virtual {v2, v0}, Lxy0/c;->a(Lrx0/c;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p3

    .line 104
    if-ne p3, v1, :cond_5

    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_5
    move-object v5, v2

    .line 108
    move-object v2, p0

    .line 109
    move-object p0, v5

    .line 110
    move-object v5, p2

    .line 111
    move-object p2, p1

    .line 112
    move-object p1, v5

    .line 113
    :goto_2
    check-cast p3, Ljava/lang/Boolean;

    .line 114
    .line 115
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 116
    .line 117
    .line 118
    move-result p3

    .line 119
    if-eqz p3, :cond_6

    .line 120
    .line 121
    invoke-virtual {p0}, Lxy0/c;->c()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p3

    .line 125
    invoke-interface {p1, p3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    iput-object v2, v0, Lh7/g;->d:La7/n;

    .line 129
    .line 130
    iput-object p2, v0, Lh7/g;->e:Landroid/content/Context;

    .line 131
    .line 132
    iput-object p1, v0, Lh7/g;->f:Lay0/k;

    .line 133
    .line 134
    iput-object p0, v0, Lh7/g;->g:Lxy0/c;

    .line 135
    .line 136
    iput v3, v0, Lh7/g;->j:I

    .line 137
    .line 138
    invoke-virtual {v2, p2, p3, v0}, La7/n;->c(Landroid/content/Context;Ljava/lang/Object;Lrx0/c;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object p3
    :try_end_2
    .catch Lxy0/s; {:try_start_2 .. :try_end_2} :catch_0

    .line 142
    if-ne p3, v1, :cond_1

    .line 143
    .line 144
    :goto_3
    return-object v1

    .line 145
    :catch_0
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 146
    .line 147
    return-object p0
.end method

.method public final e(Ljava/lang/Object;Lrx0/c;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, La7/n;->c:Lxy0/j;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lxy0/a0;->u(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    if-ne p0, p1, :cond_0

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    return-object p0
.end method

.method public final f(Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p1, La7/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, La7/m;

    .line 7
    .line 8
    iget v1, v0, La7/m;->g:I

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
    iput v1, v0, La7/m;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, La7/m;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, La7/m;-><init>(La7/n;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, La7/m;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, La7/m;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, La7/m;->d:La7/g;

    .line 37
    .line 38
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    new-instance p1, La7/g;

    .line 54
    .line 55
    new-instance v2, Lvy0/k1;

    .line 56
    .line 57
    iget-object v4, p0, La7/n;->l:Lvy0/k1;

    .line 58
    .line 59
    invoke-direct {v2, v4}, Lvy0/k1;-><init>(Lvy0/i1;)V

    .line 60
    .line 61
    .line 62
    invoke-direct {p1, v2}, La7/g;-><init>(Lvy0/k1;)V

    .line 63
    .line 64
    .line 65
    iput-object p1, v0, La7/m;->d:La7/g;

    .line 66
    .line 67
    iput v3, v0, La7/m;->g:I

    .line 68
    .line 69
    invoke-virtual {p0, p1, v0}, La7/n;->e(Ljava/lang/Object;Lrx0/c;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    if-ne p0, v1, :cond_3

    .line 74
    .line 75
    return-object v1

    .line 76
    :cond_3
    move-object p0, p1

    .line 77
    :goto_1
    iget-object p0, p0, La7/g;->a:Lvy0/k1;

    .line 78
    .line 79
    return-object p0
.end method
