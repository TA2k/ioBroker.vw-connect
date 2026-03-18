.class public final synthetic La0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ly4/i;
.implements Lh0/b1;
.implements Lw7/k;
.implements Lw7/j;
.implements Lgs/e;
.implements Laq/e;
.implements Laq/b;
.implements Laq/i;
.implements Lgt/a;
.implements Lw7/f;
.implements Laq/f;
.implements Lb0/w1;
.implements Lk0/a;
.implements Lzn/b;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, La0/h;->d:I

    iput-object p2, p0, La0/h;->e:Ljava/lang/Object;

    iput-object p3, p0, La0/h;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lp0/c;Lb0/y;)V
    .locals 1

    .line 2
    const/16 v0, 0x15

    iput v0, p0, La0/h;->d:I

    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La0/h;->e:Ljava/lang/Object;

    iput-object p2, p0, La0/h;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lq0/e;Lb0/y;)V
    .locals 1

    .line 3
    const/16 v0, 0x17

    iput v0, p0, La0/h;->d:I

    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La0/h;->e:Ljava/lang/Object;

    iput-object p2, p0, La0/h;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lw0/c;Lh0/z;Ljava/util/ArrayList;)V
    .locals 0

    .line 4
    const/16 p1, 0x1b

    iput p1, p0, La0/h;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, La0/h;->e:Ljava/lang/Object;

    iput-object p3, p0, La0/h;->f:Ljava/lang/Object;

    return-void
.end method

.method private final d(Laq/j;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ldu/i;

    .line 4
    .line 5
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Ljava/util/Date;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    invoke-virtual {p1}, Laq/j;->i()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    iget-object v0, v0, Ldu/i;->g:Ldu/n;

    .line 19
    .line 20
    iget-object v1, v0, Ldu/n;->b:Ljava/lang/Object;

    .line 21
    .line 22
    monitor-enter v1

    .line 23
    :try_start_0
    iget-object v0, v0, Ldu/n;->a:Landroid/content/SharedPreferences;

    .line 24
    .line 25
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    const-string v2, "last_fetch_status"

    .line 30
    .line 31
    const/4 v3, -0x1

    .line 32
    invoke-interface {v0, v2, v3}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    const-string v2, "last_fetch_time_in_millis"

    .line 37
    .line 38
    invoke-virtual {p0}, Ljava/util/Date;->getTime()J

    .line 39
    .line 40
    .line 41
    move-result-wide v3

    .line 42
    invoke-interface {v0, v2, v3, v4}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 47
    .line 48
    .line 49
    monitor-exit v1

    .line 50
    return-object p1

    .line 51
    :catchall_0
    move-exception p0

    .line 52
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 53
    throw p0

    .line 54
    :cond_0
    invoke-virtual {p1}, Laq/j;->f()Ljava/lang/Exception;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    if-nez p0, :cond_1

    .line 59
    .line 60
    return-object p1

    .line 61
    :cond_1
    instance-of p0, p0, Lcu/e;

    .line 62
    .line 63
    if-eqz p0, :cond_2

    .line 64
    .line 65
    iget-object p0, v0, Ldu/i;->g:Ldu/n;

    .line 66
    .line 67
    iget-object v1, p0, Ldu/n;->b:Ljava/lang/Object;

    .line 68
    .line 69
    monitor-enter v1

    .line 70
    :try_start_1
    iget-object p0, p0, Ldu/n;->a:Landroid/content/SharedPreferences;

    .line 71
    .line 72
    invoke-interface {p0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    const-string v0, "last_fetch_status"

    .line 77
    .line 78
    const/4 v2, 0x2

    .line 79
    invoke-interface {p0, v0, v2}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 84
    .line 85
    .line 86
    monitor-exit v1

    .line 87
    return-object p1

    .line 88
    :catchall_1
    move-exception p0

    .line 89
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 90
    throw p0

    .line 91
    :cond_2
    iget-object p0, v0, Ldu/i;->g:Ldu/n;

    .line 92
    .line 93
    iget-object v0, p0, Ldu/n;->b:Ljava/lang/Object;

    .line 94
    .line 95
    monitor-enter v0

    .line 96
    :try_start_2
    iget-object p0, p0, Ldu/n;->a:Landroid/content/SharedPreferences;

    .line 97
    .line 98
    invoke-interface {p0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    const-string v1, "last_fetch_status"

    .line 103
    .line 104
    const/4 v2, 0x1

    .line 105
    invoke-interface {p0, v1, v2}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 110
    .line 111
    .line 112
    monitor-exit v0

    .line 113
    return-object p1

    .line 114
    :catchall_2
    move-exception p0

    .line 115
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 116
    throw p0
.end method


# virtual methods
.method public a(Ljava/lang/Object;Lt7/m;)V
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget-object v2, v0, La0/h;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Lb8/e;

    .line 8
    .line 9
    iget-object v0, v0, La0/h;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v0, Lt7/l0;

    .line 12
    .line 13
    move-object/from16 v3, p1

    .line 14
    .line 15
    check-cast v3, Lb8/j;

    .line 16
    .line 17
    iget-object v2, v2, Lb8/e;->h:Landroid/util/SparseArray;

    .line 18
    .line 19
    new-instance v4, Landroid/util/SparseArray;

    .line 20
    .line 21
    iget-object v5, v1, Lt7/m;->a:Landroid/util/SparseBooleanArray;

    .line 22
    .line 23
    invoke-virtual {v5}, Landroid/util/SparseBooleanArray;->size()I

    .line 24
    .line 25
    .line 26
    move-result v5

    .line 27
    invoke-direct {v4, v5}, Landroid/util/SparseArray;-><init>(I)V

    .line 28
    .line 29
    .line 30
    const/4 v5, 0x0

    .line 31
    move v6, v5

    .line 32
    :goto_0
    iget-object v7, v1, Lt7/m;->a:Landroid/util/SparseBooleanArray;

    .line 33
    .line 34
    invoke-virtual {v7}, Landroid/util/SparseBooleanArray;->size()I

    .line 35
    .line 36
    .line 37
    move-result v7

    .line 38
    if-ge v6, v7, :cond_0

    .line 39
    .line 40
    invoke-virtual {v1, v6}, Lt7/m;->a(I)I

    .line 41
    .line 42
    .line 43
    move-result v7

    .line 44
    invoke-virtual {v2, v7}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v8

    .line 48
    check-cast v8, Lb8/a;

    .line 49
    .line 50
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 51
    .line 52
    .line 53
    invoke-virtual {v4, v7, v8}, Landroid/util/SparseArray;->append(ILjava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    add-int/lit8 v6, v6, 0x1

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 60
    .line 61
    .line 62
    iget-object v2, v1, Lt7/m;->a:Landroid/util/SparseBooleanArray;

    .line 63
    .line 64
    invoke-virtual {v2}, Landroid/util/SparseBooleanArray;->size()I

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-nez v2, :cond_1

    .line 69
    .line 70
    goto/16 :goto_31

    .line 71
    .line 72
    :cond_1
    move v2, v5

    .line 73
    :goto_1
    iget-object v6, v1, Lt7/m;->a:Landroid/util/SparseBooleanArray;

    .line 74
    .line 75
    invoke-virtual {v6}, Landroid/util/SparseBooleanArray;->size()I

    .line 76
    .line 77
    .line 78
    move-result v6

    .line 79
    const/4 v7, 0x1

    .line 80
    const/16 v8, 0xb

    .line 81
    .line 82
    if-ge v2, v6, :cond_d

    .line 83
    .line 84
    invoke-virtual {v1, v2}, Lt7/m;->a(I)I

    .line 85
    .line 86
    .line 87
    move-result v6

    .line 88
    invoke-virtual {v4, v6}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v9

    .line 92
    check-cast v9, Lb8/a;

    .line 93
    .line 94
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 95
    .line 96
    .line 97
    if-nez v6, :cond_6

    .line 98
    .line 99
    iget-object v10, v3, Lb8/j;->c:Lb8/g;

    .line 100
    .line 101
    monitor-enter v10

    .line 102
    :try_start_0
    iget-object v6, v10, Lb8/g;->d:Lb8/j;

    .line 103
    .line 104
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 105
    .line 106
    .line 107
    iget-object v6, v10, Lb8/g;->e:Lt7/p0;

    .line 108
    .line 109
    iget-object v7, v9, Lb8/a;->b:Lt7/p0;

    .line 110
    .line 111
    iput-object v7, v10, Lb8/g;->e:Lt7/p0;

    .line 112
    .line 113
    iget-object v7, v10, Lb8/g;->c:Ljava/util/HashMap;

    .line 114
    .line 115
    invoke-virtual {v7}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 116
    .line 117
    .line 118
    move-result-object v7

    .line 119
    invoke-interface {v7}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 120
    .line 121
    .line 122
    move-result-object v7

    .line 123
    :cond_2
    :goto_2
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 124
    .line 125
    .line 126
    move-result v8

    .line 127
    if-eqz v8, :cond_5

    .line 128
    .line 129
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v8

    .line 133
    check-cast v8, Lb8/f;

    .line 134
    .line 135
    iget-object v11, v10, Lb8/g;->e:Lt7/p0;

    .line 136
    .line 137
    invoke-virtual {v8, v6, v11}, Lb8/f;->b(Lt7/p0;Lt7/p0;)Z

    .line 138
    .line 139
    .line 140
    move-result v11

    .line 141
    if-eqz v11, :cond_3

    .line 142
    .line 143
    invoke-virtual {v8, v9}, Lb8/f;->a(Lb8/a;)Z

    .line 144
    .line 145
    .line 146
    move-result v11

    .line 147
    if-eqz v11, :cond_2

    .line 148
    .line 149
    goto :goto_3

    .line 150
    :catchall_0
    move-exception v0

    .line 151
    goto :goto_4

    .line 152
    :cond_3
    :goto_3
    invoke-interface {v7}, Ljava/util/Iterator;->remove()V

    .line 153
    .line 154
    .line 155
    iget-boolean v11, v8, Lb8/f;->e:Z

    .line 156
    .line 157
    if-eqz v11, :cond_2

    .line 158
    .line 159
    iget-object v11, v8, Lb8/f;->a:Ljava/lang/String;

    .line 160
    .line 161
    iget-object v12, v10, Lb8/g;->f:Ljava/lang/String;

    .line 162
    .line 163
    invoke-virtual {v11, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 164
    .line 165
    .line 166
    move-result v11

    .line 167
    if-eqz v11, :cond_4

    .line 168
    .line 169
    invoke-virtual {v10, v8}, Lb8/g;->a(Lb8/f;)V

    .line 170
    .line 171
    .line 172
    :cond_4
    iget-object v11, v10, Lb8/g;->d:Lb8/j;

    .line 173
    .line 174
    iget-object v8, v8, Lb8/f;->a:Ljava/lang/String;

    .line 175
    .line 176
    invoke-virtual {v11, v9, v8}, Lb8/j;->d(Lb8/a;Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    goto :goto_2

    .line 180
    :cond_5
    invoke-virtual {v10, v9}, Lb8/g;->d(Lb8/a;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 181
    .line 182
    .line 183
    monitor-exit v10

    .line 184
    goto :goto_9

    .line 185
    :goto_4
    :try_start_1
    monitor-exit v10
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 186
    throw v0

    .line 187
    :cond_6
    if-ne v6, v8, :cond_c

    .line 188
    .line 189
    iget-object v6, v3, Lb8/j;->c:Lb8/g;

    .line 190
    .line 191
    iget v8, v3, Lb8/j;->l:I

    .line 192
    .line 193
    monitor-enter v6

    .line 194
    :try_start_2
    iget-object v10, v6, Lb8/g;->d:Lb8/j;

    .line 195
    .line 196
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 197
    .line 198
    .line 199
    if-nez v8, :cond_7

    .line 200
    .line 201
    goto :goto_5

    .line 202
    :cond_7
    move v7, v5

    .line 203
    :goto_5
    iget-object v8, v6, Lb8/g;->c:Ljava/util/HashMap;

    .line 204
    .line 205
    invoke-virtual {v8}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 206
    .line 207
    .line 208
    move-result-object v8

    .line 209
    invoke-interface {v8}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 210
    .line 211
    .line 212
    move-result-object v8

    .line 213
    :cond_8
    :goto_6
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 214
    .line 215
    .line 216
    move-result v10

    .line 217
    if-eqz v10, :cond_b

    .line 218
    .line 219
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v10

    .line 223
    check-cast v10, Lb8/f;

    .line 224
    .line 225
    invoke-virtual {v10, v9}, Lb8/f;->a(Lb8/a;)Z

    .line 226
    .line 227
    .line 228
    move-result v11

    .line 229
    if-eqz v11, :cond_8

    .line 230
    .line 231
    invoke-interface {v8}, Ljava/util/Iterator;->remove()V

    .line 232
    .line 233
    .line 234
    iget-boolean v11, v10, Lb8/f;->e:Z

    .line 235
    .line 236
    if-eqz v11, :cond_8

    .line 237
    .line 238
    iget-object v11, v10, Lb8/f;->a:Ljava/lang/String;

    .line 239
    .line 240
    iget-object v12, v6, Lb8/g;->f:Ljava/lang/String;

    .line 241
    .line 242
    invoke-virtual {v11, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 243
    .line 244
    .line 245
    move-result v11

    .line 246
    if-eqz v7, :cond_9

    .line 247
    .line 248
    if-eqz v11, :cond_9

    .line 249
    .line 250
    iget-boolean v12, v10, Lb8/f;->f:Z

    .line 251
    .line 252
    goto :goto_7

    .line 253
    :catchall_1
    move-exception v0

    .line 254
    goto :goto_8

    .line 255
    :cond_9
    :goto_7
    if-eqz v11, :cond_a

    .line 256
    .line 257
    invoke-virtual {v6, v10}, Lb8/g;->a(Lb8/f;)V

    .line 258
    .line 259
    .line 260
    :cond_a
    iget-object v11, v6, Lb8/g;->d:Lb8/j;

    .line 261
    .line 262
    iget-object v10, v10, Lb8/f;->a:Ljava/lang/String;

    .line 263
    .line 264
    invoke-virtual {v11, v9, v10}, Lb8/j;->d(Lb8/a;Ljava/lang/String;)V

    .line 265
    .line 266
    .line 267
    goto :goto_6

    .line 268
    :cond_b
    invoke-virtual {v6, v9}, Lb8/g;->d(Lb8/a;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 269
    .line 270
    .line 271
    monitor-exit v6

    .line 272
    goto :goto_9

    .line 273
    :goto_8
    :try_start_3
    monitor-exit v6
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 274
    throw v0

    .line 275
    :cond_c
    iget-object v6, v3, Lb8/j;->c:Lb8/g;

    .line 276
    .line 277
    invoke-virtual {v6, v9}, Lb8/g;->e(Lb8/a;)V

    .line 278
    .line 279
    .line 280
    :goto_9
    add-int/lit8 v2, v2, 0x1

    .line 281
    .line 282
    goto/16 :goto_1

    .line 283
    .line 284
    :cond_d
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 285
    .line 286
    .line 287
    move-result-wide v9

    .line 288
    iget-object v2, v1, Lt7/m;->a:Landroid/util/SparseBooleanArray;

    .line 289
    .line 290
    invoke-virtual {v2, v5}, Landroid/util/SparseBooleanArray;->get(I)Z

    .line 291
    .line 292
    .line 293
    move-result v2

    .line 294
    if-eqz v2, :cond_e

    .line 295
    .line 296
    invoke-virtual {v4, v5}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object v2

    .line 300
    check-cast v2, Lb8/a;

    .line 301
    .line 302
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 303
    .line 304
    .line 305
    iget-object v6, v3, Lb8/j;->k:Landroid/media/metrics/PlaybackMetrics$Builder;

    .line 306
    .line 307
    if-eqz v6, :cond_e

    .line 308
    .line 309
    iget-object v6, v2, Lb8/a;->b:Lt7/p0;

    .line 310
    .line 311
    iget-object v2, v2, Lb8/a;->d:Lh8/b0;

    .line 312
    .line 313
    invoke-virtual {v3, v6, v2}, Lb8/j;->c(Lt7/p0;Lh8/b0;)V

    .line 314
    .line 315
    .line 316
    :cond_e
    iget-object v2, v1, Lt7/m;->a:Landroid/util/SparseBooleanArray;

    .line 317
    .line 318
    const/4 v6, 0x2

    .line 319
    invoke-virtual {v2, v6}, Landroid/util/SparseBooleanArray;->get(I)Z

    .line 320
    .line 321
    .line 322
    move-result v2

    .line 323
    if-eqz v2, :cond_16

    .line 324
    .line 325
    iget-object v2, v3, Lb8/j;->k:Landroid/media/metrics/PlaybackMetrics$Builder;

    .line 326
    .line 327
    if-eqz v2, :cond_16

    .line 328
    .line 329
    move-object v2, v0

    .line 330
    check-cast v2, La8/i0;

    .line 331
    .line 332
    invoke-virtual {v2}, La8/i0;->l0()Lt7/w0;

    .line 333
    .line 334
    .line 335
    move-result-object v2

    .line 336
    iget-object v2, v2, Lt7/w0;->a:Lhr/h0;

    .line 337
    .line 338
    invoke-virtual {v2, v5}, Lhr/h0;->s(I)Lhr/f0;

    .line 339
    .line 340
    .line 341
    move-result-object v2

    .line 342
    :goto_a
    invoke-virtual {v2}, Lhr/f0;->hasNext()Z

    .line 343
    .line 344
    .line 345
    move-result v14

    .line 346
    if-eqz v14, :cond_11

    .line 347
    .line 348
    invoke-virtual {v2}, Lhr/f0;->next()Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object v14

    .line 352
    check-cast v14, Lt7/v0;

    .line 353
    .line 354
    move v15, v5

    .line 355
    :goto_b
    iget v8, v14, Lt7/v0;->a:I

    .line 356
    .line 357
    if-ge v15, v8, :cond_10

    .line 358
    .line 359
    iget-object v8, v14, Lt7/v0;->e:[Z

    .line 360
    .line 361
    aget-boolean v8, v8, v15

    .line 362
    .line 363
    if-eqz v8, :cond_f

    .line 364
    .line 365
    iget-object v8, v14, Lt7/v0;->b:Lt7/q0;

    .line 366
    .line 367
    iget-object v8, v8, Lt7/q0;->d:[Lt7/o;

    .line 368
    .line 369
    aget-object v8, v8, v15

    .line 370
    .line 371
    iget-object v8, v8, Lt7/o;->r:Lt7/k;

    .line 372
    .line 373
    if-eqz v8, :cond_f

    .line 374
    .line 375
    goto :goto_c

    .line 376
    :cond_f
    add-int/lit8 v15, v15, 0x1

    .line 377
    .line 378
    goto :goto_b

    .line 379
    :cond_10
    const/16 v8, 0xb

    .line 380
    .line 381
    goto :goto_a

    .line 382
    :cond_11
    const/4 v8, 0x0

    .line 383
    :goto_c
    if-eqz v8, :cond_16

    .line 384
    .line 385
    iget-object v2, v3, Lb8/j;->k:Landroid/media/metrics/PlaybackMetrics$Builder;

    .line 386
    .line 387
    invoke-static {v2}, La6/c;->j(Ljava/lang/Object;)Landroid/media/metrics/PlaybackMetrics$Builder;

    .line 388
    .line 389
    .line 390
    move-result-object v2

    .line 391
    move v14, v5

    .line 392
    :goto_d
    iget v15, v8, Lt7/k;->g:I

    .line 393
    .line 394
    if-ge v14, v15, :cond_15

    .line 395
    .line 396
    iget-object v15, v8, Lt7/k;->d:[Lt7/j;

    .line 397
    .line 398
    aget-object v15, v15, v14

    .line 399
    .line 400
    iget-object v15, v15, Lt7/j;->e:Ljava/util/UUID;

    .line 401
    .line 402
    sget-object v11, Lt7/e;->d:Ljava/util/UUID;

    .line 403
    .line 404
    invoke-virtual {v15, v11}, Ljava/util/UUID;->equals(Ljava/lang/Object;)Z

    .line 405
    .line 406
    .line 407
    move-result v11

    .line 408
    if-eqz v11, :cond_12

    .line 409
    .line 410
    const/4 v8, 0x3

    .line 411
    goto :goto_e

    .line 412
    :cond_12
    sget-object v11, Lt7/e;->e:Ljava/util/UUID;

    .line 413
    .line 414
    invoke-virtual {v15, v11}, Ljava/util/UUID;->equals(Ljava/lang/Object;)Z

    .line 415
    .line 416
    .line 417
    move-result v11

    .line 418
    if-eqz v11, :cond_13

    .line 419
    .line 420
    move v8, v6

    .line 421
    goto :goto_e

    .line 422
    :cond_13
    sget-object v11, Lt7/e;->c:Ljava/util/UUID;

    .line 423
    .line 424
    invoke-virtual {v15, v11}, Ljava/util/UUID;->equals(Ljava/lang/Object;)Z

    .line 425
    .line 426
    .line 427
    move-result v11

    .line 428
    if-eqz v11, :cond_14

    .line 429
    .line 430
    const/4 v8, 0x6

    .line 431
    goto :goto_e

    .line 432
    :cond_14
    add-int/lit8 v14, v14, 0x1

    .line 433
    .line 434
    goto :goto_d

    .line 435
    :cond_15
    move v8, v7

    .line 436
    :goto_e
    invoke-static {v2, v8}, La6/c;->o(Landroid/media/metrics/PlaybackMetrics$Builder;I)V

    .line 437
    .line 438
    .line 439
    :cond_16
    const/16 v2, 0x3f3

    .line 440
    .line 441
    iget-object v8, v1, Lt7/m;->a:Landroid/util/SparseBooleanArray;

    .line 442
    .line 443
    invoke-virtual {v8, v2}, Landroid/util/SparseBooleanArray;->get(I)Z

    .line 444
    .line 445
    .line 446
    move-result v2

    .line 447
    if-eqz v2, :cond_17

    .line 448
    .line 449
    iget v2, v3, Lb8/j;->A:I

    .line 450
    .line 451
    add-int/2addr v2, v7

    .line 452
    iput v2, v3, Lb8/j;->A:I

    .line 453
    .line 454
    :cond_17
    iget-object v2, v3, Lb8/j;->o:Lt7/f0;

    .line 455
    .line 456
    const/4 v8, 0x5

    .line 457
    const/4 v6, 0x4

    .line 458
    if-nez v2, :cond_18

    .line 459
    .line 460
    move v12, v7

    .line 461
    const/16 v8, 0xd

    .line 462
    .line 463
    const/4 v15, 0x6

    .line 464
    const/16 v16, 0x8

    .line 465
    .line 466
    const/16 v17, 0x7

    .line 467
    .line 468
    const/16 v18, 0x9

    .line 469
    .line 470
    goto/16 :goto_1e

    .line 471
    .line 472
    :cond_18
    iget v14, v2, Lt7/f0;->d:I

    .line 473
    .line 474
    iget-object v15, v3, Lb8/j;->a:Landroid/content/Context;

    .line 475
    .line 476
    iget v12, v3, Lb8/j;->w:I

    .line 477
    .line 478
    if-ne v12, v6, :cond_19

    .line 479
    .line 480
    move v12, v7

    .line 481
    goto :goto_f

    .line 482
    :cond_19
    move v12, v5

    .line 483
    :goto_f
    const/16 v6, 0x3e9

    .line 484
    .line 485
    if-ne v14, v6, :cond_1a

    .line 486
    .line 487
    new-instance v6, Lb8/i;

    .line 488
    .line 489
    const/16 v12, 0x14

    .line 490
    .line 491
    const/4 v14, 0x0

    .line 492
    invoke-direct {v6, v12, v5, v14}, Lb8/i;-><init>(III)V

    .line 493
    .line 494
    .line 495
    :goto_10
    const/16 v8, 0xd

    .line 496
    .line 497
    const/4 v15, 0x6

    .line 498
    const/16 v16, 0x8

    .line 499
    .line 500
    const/16 v17, 0x7

    .line 501
    .line 502
    const/16 v18, 0x9

    .line 503
    .line 504
    goto/16 :goto_1d

    .line 505
    .line 506
    :cond_1a
    instance-of v6, v2, La8/o;

    .line 507
    .line 508
    if-eqz v6, :cond_1c

    .line 509
    .line 510
    move-object v6, v2

    .line 511
    check-cast v6, La8/o;

    .line 512
    .line 513
    iget v13, v6, La8/o;->f:I

    .line 514
    .line 515
    if-ne v13, v7, :cond_1b

    .line 516
    .line 517
    move v13, v7

    .line 518
    goto :goto_11

    .line 519
    :cond_1b
    move v13, v5

    .line 520
    :goto_11
    iget v6, v6, La8/o;->j:I

    .line 521
    .line 522
    goto :goto_12

    .line 523
    :cond_1c
    move v6, v5

    .line 524
    move v13, v6

    .line 525
    :goto_12
    invoke-virtual {v2}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 526
    .line 527
    .line 528
    move-result-object v7

    .line 529
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 530
    .line 531
    .line 532
    instance-of v11, v7, Ljava/io/IOException;

    .line 533
    .line 534
    const/16 v19, 0x19

    .line 535
    .line 536
    const/16 v20, 0x1a

    .line 537
    .line 538
    const/16 v5, 0x17

    .line 539
    .line 540
    if-eqz v11, :cond_31

    .line 541
    .line 542
    instance-of v6, v7, Ly7/u;

    .line 543
    .line 544
    if-eqz v6, :cond_1d

    .line 545
    .line 546
    check-cast v7, Ly7/u;

    .line 547
    .line 548
    iget v5, v7, Ly7/u;->g:I

    .line 549
    .line 550
    new-instance v6, Lb8/i;

    .line 551
    .line 552
    const/4 v7, 0x0

    .line 553
    invoke-direct {v6, v8, v5, v7}, Lb8/i;-><init>(III)V

    .line 554
    .line 555
    .line 556
    goto :goto_10

    .line 557
    :cond_1d
    instance-of v6, v7, Ly7/t;

    .line 558
    .line 559
    if-nez v6, :cond_1e

    .line 560
    .line 561
    instance-of v6, v7, Lt7/e0;

    .line 562
    .line 563
    if-eqz v6, :cond_1f

    .line 564
    .line 565
    :cond_1e
    const/16 v7, 0x8

    .line 566
    .line 567
    const/4 v11, 0x0

    .line 568
    const/16 v13, 0x9

    .line 569
    .line 570
    const/4 v14, 0x7

    .line 571
    const/4 v15, 0x6

    .line 572
    goto/16 :goto_1a

    .line 573
    .line 574
    :cond_1f
    instance-of v6, v7, Ly7/s;

    .line 575
    .line 576
    if-nez v6, :cond_20

    .line 577
    .line 578
    instance-of v11, v7, Ly7/a0;

    .line 579
    .line 580
    if-eqz v11, :cond_21

    .line 581
    .line 582
    :cond_20
    const/4 v11, 0x0

    .line 583
    const/16 v13, 0x9

    .line 584
    .line 585
    goto/16 :goto_16

    .line 586
    .line 587
    :cond_21
    const/16 v6, 0x3ea

    .line 588
    .line 589
    if-ne v14, v6, :cond_22

    .line 590
    .line 591
    new-instance v6, Lb8/i;

    .line 592
    .line 593
    const/16 v5, 0x15

    .line 594
    .line 595
    const/4 v7, 0x0

    .line 596
    const/4 v11, 0x0

    .line 597
    invoke-direct {v6, v5, v11, v7}, Lb8/i;-><init>(III)V

    .line 598
    .line 599
    .line 600
    goto :goto_10

    .line 601
    :cond_22
    instance-of v6, v7, Ld8/d;

    .line 602
    .line 603
    if-eqz v6, :cond_29

    .line 604
    .line 605
    invoke-virtual {v7}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 606
    .line 607
    .line 608
    move-result-object v6

    .line 609
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 610
    .line 611
    .line 612
    instance-of v7, v6, Landroid/media/MediaDrm$MediaDrmStateException;

    .line 613
    .line 614
    if-eqz v7, :cond_23

    .line 615
    .line 616
    check-cast v6, Landroid/media/MediaDrm$MediaDrmStateException;

    .line 617
    .line 618
    invoke-virtual {v6}, Landroid/media/MediaDrm$MediaDrmStateException;->getDiagnosticInfo()Ljava/lang/String;

    .line 619
    .line 620
    .line 621
    move-result-object v5

    .line 622
    invoke-static {v5}, Lw7/w;->q(Ljava/lang/String;)I

    .line 623
    .line 624
    .line 625
    move-result v5

    .line 626
    invoke-static {v5}, Lw7/w;->p(I)I

    .line 627
    .line 628
    .line 629
    move-result v6

    .line 630
    packed-switch v6, :pswitch_data_0

    .line 631
    .line 632
    .line 633
    const/16 v6, 0x1b

    .line 634
    .line 635
    goto :goto_13

    .line 636
    :pswitch_0
    move/from16 v6, v20

    .line 637
    .line 638
    goto :goto_13

    .line 639
    :pswitch_1
    move/from16 v6, v19

    .line 640
    .line 641
    goto :goto_13

    .line 642
    :pswitch_2
    const/16 v6, 0x1c

    .line 643
    .line 644
    goto :goto_13

    .line 645
    :pswitch_3
    const/16 v6, 0x18

    .line 646
    .line 647
    :goto_13
    new-instance v7, Lb8/i;

    .line 648
    .line 649
    const/4 v11, 0x0

    .line 650
    invoke-direct {v7, v6, v5, v11}, Lb8/i;-><init>(III)V

    .line 651
    .line 652
    .line 653
    move-object v6, v7

    .line 654
    goto/16 :goto_10

    .line 655
    .line 656
    :cond_23
    instance-of v7, v6, Landroid/media/MediaDrmResetException;

    .line 657
    .line 658
    if-eqz v7, :cond_24

    .line 659
    .line 660
    new-instance v6, Lb8/i;

    .line 661
    .line 662
    const/4 v5, 0x0

    .line 663
    const/4 v7, 0x0

    .line 664
    const/16 v11, 0x1b

    .line 665
    .line 666
    invoke-direct {v6, v11, v7, v5}, Lb8/i;-><init>(III)V

    .line 667
    .line 668
    .line 669
    goto/16 :goto_10

    .line 670
    .line 671
    :cond_24
    const/4 v7, 0x0

    .line 672
    instance-of v11, v6, Landroid/media/NotProvisionedException;

    .line 673
    .line 674
    if-eqz v11, :cond_25

    .line 675
    .line 676
    new-instance v6, Lb8/i;

    .line 677
    .line 678
    const/4 v5, 0x0

    .line 679
    const/16 v12, 0x18

    .line 680
    .line 681
    invoke-direct {v6, v12, v7, v5}, Lb8/i;-><init>(III)V

    .line 682
    .line 683
    .line 684
    goto/16 :goto_10

    .line 685
    .line 686
    :cond_25
    instance-of v11, v6, Landroid/media/DeniedByServerException;

    .line 687
    .line 688
    if-eqz v11, :cond_26

    .line 689
    .line 690
    new-instance v6, Lb8/i;

    .line 691
    .line 692
    const/16 v5, 0x1d

    .line 693
    .line 694
    const/4 v11, 0x0

    .line 695
    invoke-direct {v6, v5, v7, v11}, Lb8/i;-><init>(III)V

    .line 696
    .line 697
    .line 698
    goto/16 :goto_10

    .line 699
    .line 700
    :cond_26
    instance-of v11, v6, Ld8/l;

    .line 701
    .line 702
    if-eqz v11, :cond_27

    .line 703
    .line 704
    new-instance v6, Lb8/i;

    .line 705
    .line 706
    const/4 v11, 0x0

    .line 707
    invoke-direct {v6, v5, v7, v11}, Lb8/i;-><init>(III)V

    .line 708
    .line 709
    .line 710
    goto/16 :goto_10

    .line 711
    .line 712
    :cond_27
    instance-of v5, v6, Ld8/a;

    .line 713
    .line 714
    if-eqz v5, :cond_28

    .line 715
    .line 716
    new-instance v6, Lb8/i;

    .line 717
    .line 718
    const/4 v5, 0x0

    .line 719
    const/16 v14, 0x1c

    .line 720
    .line 721
    invoke-direct {v6, v14, v7, v5}, Lb8/i;-><init>(III)V

    .line 722
    .line 723
    .line 724
    goto/16 :goto_10

    .line 725
    .line 726
    :cond_28
    new-instance v6, Lb8/i;

    .line 727
    .line 728
    const/16 v5, 0x1e

    .line 729
    .line 730
    const/4 v11, 0x0

    .line 731
    invoke-direct {v6, v5, v7, v11}, Lb8/i;-><init>(III)V

    .line 732
    .line 733
    .line 734
    goto/16 :goto_10

    .line 735
    .line 736
    :cond_29
    instance-of v5, v7, Ly7/p;

    .line 737
    .line 738
    if-eqz v5, :cond_2b

    .line 739
    .line 740
    invoke-virtual {v7}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 741
    .line 742
    .line 743
    move-result-object v5

    .line 744
    instance-of v5, v5, Ljava/io/FileNotFoundException;

    .line 745
    .line 746
    if-eqz v5, :cond_2b

    .line 747
    .line 748
    invoke-virtual {v7}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 749
    .line 750
    .line 751
    move-result-object v5

    .line 752
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 753
    .line 754
    .line 755
    invoke-virtual {v5}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 756
    .line 757
    .line 758
    move-result-object v5

    .line 759
    instance-of v6, v5, Landroid/system/ErrnoException;

    .line 760
    .line 761
    if-eqz v6, :cond_2a

    .line 762
    .line 763
    check-cast v5, Landroid/system/ErrnoException;

    .line 764
    .line 765
    iget v5, v5, Landroid/system/ErrnoException;->errno:I

    .line 766
    .line 767
    sget v6, Landroid/system/OsConstants;->EACCES:I

    .line 768
    .line 769
    if-ne v5, v6, :cond_2a

    .line 770
    .line 771
    new-instance v6, Lb8/i;

    .line 772
    .line 773
    const/16 v5, 0x20

    .line 774
    .line 775
    const/4 v7, 0x0

    .line 776
    const/4 v11, 0x0

    .line 777
    invoke-direct {v6, v5, v11, v7}, Lb8/i;-><init>(III)V

    .line 778
    .line 779
    .line 780
    goto/16 :goto_10

    .line 781
    .line 782
    :cond_2a
    const/4 v11, 0x0

    .line 783
    new-instance v6, Lb8/i;

    .line 784
    .line 785
    const/16 v5, 0x1f

    .line 786
    .line 787
    const/4 v7, 0x0

    .line 788
    invoke-direct {v6, v5, v11, v7}, Lb8/i;-><init>(III)V

    .line 789
    .line 790
    .line 791
    goto/16 :goto_10

    .line 792
    .line 793
    :cond_2b
    const/4 v11, 0x0

    .line 794
    new-instance v6, Lb8/i;

    .line 795
    .line 796
    const/4 v5, 0x0

    .line 797
    const/16 v13, 0x9

    .line 798
    .line 799
    invoke-direct {v6, v13, v11, v5}, Lb8/i;-><init>(III)V

    .line 800
    .line 801
    .line 802
    :goto_14
    move/from16 v18, v13

    .line 803
    .line 804
    const/16 v8, 0xd

    .line 805
    .line 806
    const/4 v15, 0x6

    .line 807
    :goto_15
    const/16 v16, 0x8

    .line 808
    .line 809
    const/16 v17, 0x7

    .line 810
    .line 811
    goto/16 :goto_1d

    .line 812
    .line 813
    :goto_16
    invoke-static {v15}, Lw7/o;->a(Landroid/content/Context;)Lw7/o;

    .line 814
    .line 815
    .line 816
    move-result-object v5

    .line 817
    invoke-virtual {v5}, Lw7/o;->b()I

    .line 818
    .line 819
    .line 820
    move-result v5

    .line 821
    const/4 v12, 0x1

    .line 822
    if-ne v5, v12, :cond_2c

    .line 823
    .line 824
    new-instance v6, Lb8/i;

    .line 825
    .line 826
    const/4 v5, 0x0

    .line 827
    const/4 v7, 0x3

    .line 828
    invoke-direct {v6, v7, v11, v5}, Lb8/i;-><init>(III)V

    .line 829
    .line 830
    .line 831
    goto :goto_14

    .line 832
    :cond_2c
    invoke-virtual {v7}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 833
    .line 834
    .line 835
    move-result-object v5

    .line 836
    instance-of v12, v5, Ljava/net/UnknownHostException;

    .line 837
    .line 838
    if-eqz v12, :cond_2d

    .line 839
    .line 840
    new-instance v6, Lb8/i;

    .line 841
    .line 842
    const/4 v5, 0x0

    .line 843
    const/4 v15, 0x6

    .line 844
    invoke-direct {v6, v15, v11, v5}, Lb8/i;-><init>(III)V

    .line 845
    .line 846
    .line 847
    move/from16 v18, v13

    .line 848
    .line 849
    const/16 v8, 0xd

    .line 850
    .line 851
    goto :goto_15

    .line 852
    :cond_2d
    const/4 v15, 0x6

    .line 853
    instance-of v5, v5, Ljava/net/SocketTimeoutException;

    .line 854
    .line 855
    if-eqz v5, :cond_2e

    .line 856
    .line 857
    new-instance v6, Lb8/i;

    .line 858
    .line 859
    const/4 v5, 0x0

    .line 860
    const/4 v14, 0x7

    .line 861
    invoke-direct {v6, v14, v11, v5}, Lb8/i;-><init>(III)V

    .line 862
    .line 863
    .line 864
    :goto_17
    move/from16 v18, v13

    .line 865
    .line 866
    move/from16 v17, v14

    .line 867
    .line 868
    const/16 v8, 0xd

    .line 869
    .line 870
    const/16 v16, 0x8

    .line 871
    .line 872
    goto/16 :goto_1d

    .line 873
    .line 874
    :cond_2e
    const/4 v14, 0x7

    .line 875
    if-eqz v6, :cond_2f

    .line 876
    .line 877
    check-cast v7, Ly7/s;

    .line 878
    .line 879
    iget v5, v7, Ly7/s;->f:I

    .line 880
    .line 881
    const/4 v12, 0x1

    .line 882
    if-ne v5, v12, :cond_2f

    .line 883
    .line 884
    new-instance v6, Lb8/i;

    .line 885
    .line 886
    const/4 v5, 0x0

    .line 887
    const/4 v7, 0x4

    .line 888
    invoke-direct {v6, v7, v11, v5}, Lb8/i;-><init>(III)V

    .line 889
    .line 890
    .line 891
    goto :goto_17

    .line 892
    :cond_2f
    new-instance v6, Lb8/i;

    .line 893
    .line 894
    const/4 v5, 0x0

    .line 895
    const/16 v7, 0x8

    .line 896
    .line 897
    invoke-direct {v6, v7, v11, v5}, Lb8/i;-><init>(III)V

    .line 898
    .line 899
    .line 900
    :goto_18
    move/from16 v16, v7

    .line 901
    .line 902
    move/from16 v18, v13

    .line 903
    .line 904
    move/from16 v17, v14

    .line 905
    .line 906
    :goto_19
    const/16 v8, 0xd

    .line 907
    .line 908
    goto/16 :goto_1d

    .line 909
    .line 910
    :goto_1a
    new-instance v6, Lb8/i;

    .line 911
    .line 912
    if-eqz v12, :cond_30

    .line 913
    .line 914
    const/16 v5, 0xa

    .line 915
    .line 916
    goto :goto_1b

    .line 917
    :cond_30
    const/16 v5, 0xb

    .line 918
    .line 919
    :goto_1b
    const/4 v12, 0x0

    .line 920
    invoke-direct {v6, v5, v11, v12}, Lb8/i;-><init>(III)V

    .line 921
    .line 922
    .line 923
    goto :goto_18

    .line 924
    :cond_31
    const/4 v8, 0x0

    .line 925
    const/16 v11, 0x1b

    .line 926
    .line 927
    const/16 v12, 0x18

    .line 928
    .line 929
    const/16 v14, 0x1c

    .line 930
    .line 931
    const/4 v15, 0x6

    .line 932
    const/16 v16, 0x8

    .line 933
    .line 934
    const/16 v17, 0x7

    .line 935
    .line 936
    const/16 v18, 0x9

    .line 937
    .line 938
    if-eqz v13, :cond_33

    .line 939
    .line 940
    if-eqz v6, :cond_32

    .line 941
    .line 942
    const/4 v11, 0x1

    .line 943
    if-ne v6, v11, :cond_33

    .line 944
    .line 945
    :cond_32
    new-instance v6, Lb8/i;

    .line 946
    .line 947
    const/16 v5, 0x23

    .line 948
    .line 949
    const/4 v7, 0x0

    .line 950
    invoke-direct {v6, v5, v8, v7}, Lb8/i;-><init>(III)V

    .line 951
    .line 952
    .line 953
    goto :goto_19

    .line 954
    :cond_33
    if-eqz v13, :cond_34

    .line 955
    .line 956
    const/4 v11, 0x3

    .line 957
    if-ne v6, v11, :cond_34

    .line 958
    .line 959
    new-instance v6, Lb8/i;

    .line 960
    .line 961
    const/16 v5, 0xf

    .line 962
    .line 963
    const/4 v7, 0x0

    .line 964
    invoke-direct {v6, v5, v8, v7}, Lb8/i;-><init>(III)V

    .line 965
    .line 966
    .line 967
    goto :goto_19

    .line 968
    :cond_34
    if-eqz v13, :cond_35

    .line 969
    .line 970
    const/4 v11, 0x2

    .line 971
    if-ne v6, v11, :cond_35

    .line 972
    .line 973
    new-instance v6, Lb8/i;

    .line 974
    .line 975
    const/4 v7, 0x0

    .line 976
    invoke-direct {v6, v5, v8, v7}, Lb8/i;-><init>(III)V

    .line 977
    .line 978
    .line 979
    goto :goto_19

    .line 980
    :cond_35
    instance-of v5, v7, Lf8/q;

    .line 981
    .line 982
    if-eqz v5, :cond_36

    .line 983
    .line 984
    check-cast v7, Lf8/q;

    .line 985
    .line 986
    iget-object v5, v7, Lf8/q;->g:Ljava/lang/String;

    .line 987
    .line 988
    invoke-static {v5}, Lw7/w;->q(Ljava/lang/String;)I

    .line 989
    .line 990
    .line 991
    move-result v5

    .line 992
    new-instance v6, Lb8/i;

    .line 993
    .line 994
    const/4 v7, 0x0

    .line 995
    const/16 v8, 0xd

    .line 996
    .line 997
    invoke-direct {v6, v8, v5, v7}, Lb8/i;-><init>(III)V

    .line 998
    .line 999
    .line 1000
    goto/16 :goto_1d

    .line 1001
    .line 1002
    :cond_36
    const/16 v8, 0xd

    .line 1003
    .line 1004
    instance-of v5, v7, Lf8/o;

    .line 1005
    .line 1006
    const/16 v6, 0xe

    .line 1007
    .line 1008
    if-eqz v5, :cond_37

    .line 1009
    .line 1010
    check-cast v7, Lf8/o;

    .line 1011
    .line 1012
    iget v5, v7, Lf8/o;->d:I

    .line 1013
    .line 1014
    new-instance v7, Lb8/i;

    .line 1015
    .line 1016
    const/4 v11, 0x0

    .line 1017
    invoke-direct {v7, v6, v5, v11}, Lb8/i;-><init>(III)V

    .line 1018
    .line 1019
    .line 1020
    move-object v6, v7

    .line 1021
    goto :goto_1d

    .line 1022
    :cond_37
    instance-of v5, v7, Ljava/lang/OutOfMemoryError;

    .line 1023
    .line 1024
    if-eqz v5, :cond_38

    .line 1025
    .line 1026
    new-instance v5, Lb8/i;

    .line 1027
    .line 1028
    const/4 v7, 0x0

    .line 1029
    const/4 v11, 0x0

    .line 1030
    invoke-direct {v5, v6, v11, v7}, Lb8/i;-><init>(III)V

    .line 1031
    .line 1032
    .line 1033
    move-object v6, v5

    .line 1034
    goto :goto_1d

    .line 1035
    :cond_38
    instance-of v5, v7, Lc8/l;

    .line 1036
    .line 1037
    if-eqz v5, :cond_39

    .line 1038
    .line 1039
    check-cast v7, Lc8/l;

    .line 1040
    .line 1041
    iget v5, v7, Lc8/l;->d:I

    .line 1042
    .line 1043
    new-instance v6, Lb8/i;

    .line 1044
    .line 1045
    const/16 v7, 0x11

    .line 1046
    .line 1047
    const/4 v11, 0x0

    .line 1048
    invoke-direct {v6, v7, v5, v11}, Lb8/i;-><init>(III)V

    .line 1049
    .line 1050
    .line 1051
    goto :goto_1d

    .line 1052
    :cond_39
    instance-of v5, v7, Lc8/m;

    .line 1053
    .line 1054
    if-eqz v5, :cond_3a

    .line 1055
    .line 1056
    check-cast v7, Lc8/m;

    .line 1057
    .line 1058
    iget v5, v7, Lc8/m;->d:I

    .line 1059
    .line 1060
    new-instance v6, Lb8/i;

    .line 1061
    .line 1062
    const/16 v7, 0x12

    .line 1063
    .line 1064
    const/4 v11, 0x0

    .line 1065
    invoke-direct {v6, v7, v5, v11}, Lb8/i;-><init>(III)V

    .line 1066
    .line 1067
    .line 1068
    goto :goto_1d

    .line 1069
    :cond_3a
    instance-of v5, v7, Landroid/media/MediaCodec$CryptoException;

    .line 1070
    .line 1071
    if-eqz v5, :cond_3b

    .line 1072
    .line 1073
    check-cast v7, Landroid/media/MediaCodec$CryptoException;

    .line 1074
    .line 1075
    invoke-virtual {v7}, Landroid/media/MediaCodec$CryptoException;->getErrorCode()I

    .line 1076
    .line 1077
    .line 1078
    move-result v5

    .line 1079
    invoke-static {v5}, Lw7/w;->p(I)I

    .line 1080
    .line 1081
    .line 1082
    move-result v6

    .line 1083
    packed-switch v6, :pswitch_data_1

    .line 1084
    .line 1085
    .line 1086
    const/16 v14, 0x1b

    .line 1087
    .line 1088
    goto :goto_1c

    .line 1089
    :pswitch_4
    move/from16 v14, v20

    .line 1090
    .line 1091
    goto :goto_1c

    .line 1092
    :pswitch_5
    move/from16 v14, v19

    .line 1093
    .line 1094
    goto :goto_1c

    .line 1095
    :pswitch_6
    move v14, v12

    .line 1096
    :goto_1c
    :pswitch_7
    new-instance v6, Lb8/i;

    .line 1097
    .line 1098
    const/4 v7, 0x0

    .line 1099
    invoke-direct {v6, v14, v5, v7}, Lb8/i;-><init>(III)V

    .line 1100
    .line 1101
    .line 1102
    goto :goto_1d

    .line 1103
    :cond_3b
    new-instance v6, Lb8/i;

    .line 1104
    .line 1105
    const/16 v5, 0x16

    .line 1106
    .line 1107
    const/4 v7, 0x0

    .line 1108
    const/4 v11, 0x0

    .line 1109
    invoke-direct {v6, v5, v11, v7}, Lb8/i;-><init>(III)V

    .line 1110
    .line 1111
    .line 1112
    :goto_1d
    invoke-static {}, Lb8/h;->d()Landroid/media/metrics/PlaybackErrorEvent$Builder;

    .line 1113
    .line 1114
    .line 1115
    move-result-object v5

    .line 1116
    iget-wide v11, v3, Lb8/j;->e:J

    .line 1117
    .line 1118
    sub-long v11, v9, v11

    .line 1119
    .line 1120
    invoke-static {v5, v11, v12}, La6/c;->f(Landroid/media/metrics/PlaybackErrorEvent$Builder;J)Landroid/media/metrics/PlaybackErrorEvent$Builder;

    .line 1121
    .line 1122
    .line 1123
    move-result-object v5

    .line 1124
    iget v7, v6, Lb8/i;->b:I

    .line 1125
    .line 1126
    invoke-static {v5, v7}, La6/c;->e(Landroid/media/metrics/PlaybackErrorEvent$Builder;I)Landroid/media/metrics/PlaybackErrorEvent$Builder;

    .line 1127
    .line 1128
    .line 1129
    move-result-object v5

    .line 1130
    iget v6, v6, Lb8/i;->c:I

    .line 1131
    .line 1132
    invoke-static {v5, v6}, La6/c;->t(Landroid/media/metrics/PlaybackErrorEvent$Builder;I)Landroid/media/metrics/PlaybackErrorEvent$Builder;

    .line 1133
    .line 1134
    .line 1135
    move-result-object v5

    .line 1136
    invoke-static {v5, v2}, La6/c;->g(Landroid/media/metrics/PlaybackErrorEvent$Builder;Lt7/f0;)Landroid/media/metrics/PlaybackErrorEvent$Builder;

    .line 1137
    .line 1138
    .line 1139
    move-result-object v2

    .line 1140
    invoke-static {v2}, La6/c;->h(Landroid/media/metrics/PlaybackErrorEvent$Builder;)Landroid/media/metrics/PlaybackErrorEvent;

    .line 1141
    .line 1142
    .line 1143
    move-result-object v2

    .line 1144
    iget-object v5, v3, Lb8/j;->b:Ljava/util/concurrent/Executor;

    .line 1145
    .line 1146
    new-instance v6, La8/z;

    .line 1147
    .line 1148
    const/16 v7, 0xb

    .line 1149
    .line 1150
    invoke-direct {v6, v7, v3, v2}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1151
    .line 1152
    .line 1153
    invoke-interface {v5, v6}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 1154
    .line 1155
    .line 1156
    const/4 v12, 0x1

    .line 1157
    iput-boolean v12, v3, Lb8/j;->B:Z

    .line 1158
    .line 1159
    const/4 v2, 0x0

    .line 1160
    iput-object v2, v3, Lb8/j;->o:Lt7/f0;

    .line 1161
    .line 1162
    :goto_1e
    iget-object v2, v1, Lt7/m;->a:Landroid/util/SparseBooleanArray;

    .line 1163
    .line 1164
    const/4 v11, 0x2

    .line 1165
    invoke-virtual {v2, v11}, Landroid/util/SparseBooleanArray;->get(I)Z

    .line 1166
    .line 1167
    .line 1168
    move-result v2

    .line 1169
    if-eqz v2, :cond_42

    .line 1170
    .line 1171
    move-object v2, v0

    .line 1172
    check-cast v2, La8/i0;

    .line 1173
    .line 1174
    invoke-virtual {v2}, La8/i0;->l0()Lt7/w0;

    .line 1175
    .line 1176
    .line 1177
    move-result-object v2

    .line 1178
    invoke-virtual {v2, v11}, Lt7/w0;->a(I)Z

    .line 1179
    .line 1180
    .line 1181
    move-result v5

    .line 1182
    invoke-virtual {v2, v12}, Lt7/w0;->a(I)Z

    .line 1183
    .line 1184
    .line 1185
    move-result v6

    .line 1186
    const/4 v7, 0x3

    .line 1187
    invoke-virtual {v2, v7}, Lt7/w0;->a(I)Z

    .line 1188
    .line 1189
    .line 1190
    move-result v2

    .line 1191
    if-nez v5, :cond_3c

    .line 1192
    .line 1193
    if-nez v6, :cond_3c

    .line 1194
    .line 1195
    if-eqz v2, :cond_42

    .line 1196
    .line 1197
    :cond_3c
    if-nez v5, :cond_3e

    .line 1198
    .line 1199
    iget-object v5, v3, Lb8/j;->s:Lt7/o;

    .line 1200
    .line 1201
    const/4 v7, 0x0

    .line 1202
    invoke-static {v5, v7}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1203
    .line 1204
    .line 1205
    move-result v5

    .line 1206
    if-eqz v5, :cond_3d

    .line 1207
    .line 1208
    goto :goto_1f

    .line 1209
    :cond_3d
    iput-object v7, v3, Lb8/j;->s:Lt7/o;

    .line 1210
    .line 1211
    const/4 v12, 0x1

    .line 1212
    invoke-virtual {v3, v12, v9, v10, v7}, Lb8/j;->e(IJLt7/o;)V

    .line 1213
    .line 1214
    .line 1215
    goto :goto_1f

    .line 1216
    :cond_3e
    const/4 v7, 0x0

    .line 1217
    :goto_1f
    if-nez v6, :cond_40

    .line 1218
    .line 1219
    iget-object v5, v3, Lb8/j;->t:Lt7/o;

    .line 1220
    .line 1221
    invoke-static {v5, v7}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1222
    .line 1223
    .line 1224
    move-result v5

    .line 1225
    if-eqz v5, :cond_3f

    .line 1226
    .line 1227
    goto :goto_20

    .line 1228
    :cond_3f
    iput-object v7, v3, Lb8/j;->t:Lt7/o;

    .line 1229
    .line 1230
    const/4 v11, 0x0

    .line 1231
    invoke-virtual {v3, v11, v9, v10, v7}, Lb8/j;->e(IJLt7/o;)V

    .line 1232
    .line 1233
    .line 1234
    :cond_40
    :goto_20
    if-nez v2, :cond_42

    .line 1235
    .line 1236
    iget-object v2, v3, Lb8/j;->u:Lt7/o;

    .line 1237
    .line 1238
    invoke-static {v2, v7}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1239
    .line 1240
    .line 1241
    move-result v2

    .line 1242
    if-eqz v2, :cond_41

    .line 1243
    .line 1244
    goto :goto_21

    .line 1245
    :cond_41
    iput-object v7, v3, Lb8/j;->u:Lt7/o;

    .line 1246
    .line 1247
    const/4 v11, 0x2

    .line 1248
    invoke-virtual {v3, v11, v9, v10, v7}, Lb8/j;->e(IJLt7/o;)V

    .line 1249
    .line 1250
    .line 1251
    :cond_42
    :goto_21
    iget-object v2, v3, Lb8/j;->p:Lb81/a;

    .line 1252
    .line 1253
    invoke-virtual {v3, v2}, Lb8/j;->a(Lb81/a;)Z

    .line 1254
    .line 1255
    .line 1256
    move-result v2

    .line 1257
    if-eqz v2, :cond_44

    .line 1258
    .line 1259
    iget-object v2, v3, Lb8/j;->p:Lb81/a;

    .line 1260
    .line 1261
    iget-object v2, v2, Lb81/a;->e:Ljava/lang/Object;

    .line 1262
    .line 1263
    check-cast v2, Lt7/o;

    .line 1264
    .line 1265
    iget v5, v2, Lt7/o;->v:I

    .line 1266
    .line 1267
    const/4 v6, -0x1

    .line 1268
    if-eq v5, v6, :cond_44

    .line 1269
    .line 1270
    iget-object v5, v3, Lb8/j;->s:Lt7/o;

    .line 1271
    .line 1272
    invoke-static {v5, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1273
    .line 1274
    .line 1275
    move-result v5

    .line 1276
    if-eqz v5, :cond_43

    .line 1277
    .line 1278
    :goto_22
    const/4 v2, 0x0

    .line 1279
    goto :goto_23

    .line 1280
    :cond_43
    iput-object v2, v3, Lb8/j;->s:Lt7/o;

    .line 1281
    .line 1282
    const/4 v12, 0x1

    .line 1283
    invoke-virtual {v3, v12, v9, v10, v2}, Lb8/j;->e(IJLt7/o;)V

    .line 1284
    .line 1285
    .line 1286
    goto :goto_22

    .line 1287
    :goto_23
    iput-object v2, v3, Lb8/j;->p:Lb81/a;

    .line 1288
    .line 1289
    :cond_44
    iget-object v2, v3, Lb8/j;->q:Lb81/a;

    .line 1290
    .line 1291
    invoke-virtual {v3, v2}, Lb8/j;->a(Lb81/a;)Z

    .line 1292
    .line 1293
    .line 1294
    move-result v2

    .line 1295
    if-eqz v2, :cond_46

    .line 1296
    .line 1297
    iget-object v2, v3, Lb8/j;->q:Lb81/a;

    .line 1298
    .line 1299
    iget-object v2, v2, Lb81/a;->e:Ljava/lang/Object;

    .line 1300
    .line 1301
    check-cast v2, Lt7/o;

    .line 1302
    .line 1303
    iget-object v5, v3, Lb8/j;->t:Lt7/o;

    .line 1304
    .line 1305
    invoke-static {v5, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1306
    .line 1307
    .line 1308
    move-result v5

    .line 1309
    if-eqz v5, :cond_45

    .line 1310
    .line 1311
    :goto_24
    const/4 v2, 0x0

    .line 1312
    goto :goto_25

    .line 1313
    :cond_45
    iput-object v2, v3, Lb8/j;->t:Lt7/o;

    .line 1314
    .line 1315
    const/4 v11, 0x0

    .line 1316
    invoke-virtual {v3, v11, v9, v10, v2}, Lb8/j;->e(IJLt7/o;)V

    .line 1317
    .line 1318
    .line 1319
    goto :goto_24

    .line 1320
    :goto_25
    iput-object v2, v3, Lb8/j;->q:Lb81/a;

    .line 1321
    .line 1322
    :cond_46
    iget-object v2, v3, Lb8/j;->r:Lb81/a;

    .line 1323
    .line 1324
    invoke-virtual {v3, v2}, Lb8/j;->a(Lb81/a;)Z

    .line 1325
    .line 1326
    .line 1327
    move-result v2

    .line 1328
    if-eqz v2, :cond_48

    .line 1329
    .line 1330
    iget-object v2, v3, Lb8/j;->r:Lb81/a;

    .line 1331
    .line 1332
    iget-object v2, v2, Lb81/a;->e:Ljava/lang/Object;

    .line 1333
    .line 1334
    check-cast v2, Lt7/o;

    .line 1335
    .line 1336
    iget-object v5, v3, Lb8/j;->u:Lt7/o;

    .line 1337
    .line 1338
    invoke-static {v5, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1339
    .line 1340
    .line 1341
    move-result v5

    .line 1342
    if-eqz v5, :cond_47

    .line 1343
    .line 1344
    :goto_26
    const/4 v2, 0x0

    .line 1345
    goto :goto_27

    .line 1346
    :cond_47
    iput-object v2, v3, Lb8/j;->u:Lt7/o;

    .line 1347
    .line 1348
    const/4 v11, 0x2

    .line 1349
    invoke-virtual {v3, v11, v9, v10, v2}, Lb8/j;->e(IJLt7/o;)V

    .line 1350
    .line 1351
    .line 1352
    goto :goto_26

    .line 1353
    :goto_27
    iput-object v2, v3, Lb8/j;->r:Lb81/a;

    .line 1354
    .line 1355
    :cond_48
    iget-object v2, v3, Lb8/j;->a:Landroid/content/Context;

    .line 1356
    .line 1357
    invoke-static {v2}, Lw7/o;->a(Landroid/content/Context;)Lw7/o;

    .line 1358
    .line 1359
    .line 1360
    move-result-object v2

    .line 1361
    invoke-virtual {v2}, Lw7/o;->b()I

    .line 1362
    .line 1363
    .line 1364
    move-result v2

    .line 1365
    packed-switch v2, :pswitch_data_2

    .line 1366
    .line 1367
    .line 1368
    :pswitch_8
    const/4 v14, 0x1

    .line 1369
    goto :goto_28

    .line 1370
    :pswitch_9
    move/from16 v14, v17

    .line 1371
    .line 1372
    goto :goto_28

    .line 1373
    :pswitch_a
    move/from16 v14, v16

    .line 1374
    .line 1375
    goto :goto_28

    .line 1376
    :pswitch_b
    const/4 v14, 0x3

    .line 1377
    goto :goto_28

    .line 1378
    :pswitch_c
    move v14, v15

    .line 1379
    goto :goto_28

    .line 1380
    :pswitch_d
    const/4 v14, 0x5

    .line 1381
    goto :goto_28

    .line 1382
    :pswitch_e
    const/4 v14, 0x4

    .line 1383
    goto :goto_28

    .line 1384
    :pswitch_f
    const/4 v14, 0x2

    .line 1385
    goto :goto_28

    .line 1386
    :pswitch_10
    move/from16 v14, v18

    .line 1387
    .line 1388
    goto :goto_28

    .line 1389
    :pswitch_11
    const/4 v14, 0x0

    .line 1390
    :goto_28
    iget v2, v3, Lb8/j;->n:I

    .line 1391
    .line 1392
    if-eq v14, v2, :cond_49

    .line 1393
    .line 1394
    iput v14, v3, Lb8/j;->n:I

    .line 1395
    .line 1396
    invoke-static {}, Lb8/h;->c()Landroid/media/metrics/NetworkEvent$Builder;

    .line 1397
    .line 1398
    .line 1399
    move-result-object v2

    .line 1400
    invoke-static {v2, v14}, La6/c;->b(Landroid/media/metrics/NetworkEvent$Builder;I)Landroid/media/metrics/NetworkEvent$Builder;

    .line 1401
    .line 1402
    .line 1403
    move-result-object v2

    .line 1404
    iget-wide v5, v3, Lb8/j;->e:J

    .line 1405
    .line 1406
    sub-long v5, v9, v5

    .line 1407
    .line 1408
    invoke-static {v2, v5, v6}, La6/c;->c(Landroid/media/metrics/NetworkEvent$Builder;J)Landroid/media/metrics/NetworkEvent$Builder;

    .line 1409
    .line 1410
    .line 1411
    move-result-object v2

    .line 1412
    invoke-static {v2}, La6/c;->d(Landroid/media/metrics/NetworkEvent$Builder;)Landroid/media/metrics/NetworkEvent;

    .line 1413
    .line 1414
    .line 1415
    move-result-object v2

    .line 1416
    iget-object v5, v3, Lb8/j;->b:Ljava/util/concurrent/Executor;

    .line 1417
    .line 1418
    new-instance v6, La8/z;

    .line 1419
    .line 1420
    const/16 v7, 0xa

    .line 1421
    .line 1422
    invoke-direct {v6, v7, v3, v2}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1423
    .line 1424
    .line 1425
    invoke-interface {v5, v6}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 1426
    .line 1427
    .line 1428
    :cond_49
    check-cast v0, La8/i0;

    .line 1429
    .line 1430
    invoke-virtual {v0}, La8/i0;->o0()I

    .line 1431
    .line 1432
    .line 1433
    move-result v2

    .line 1434
    const/4 v11, 0x2

    .line 1435
    if-eq v2, v11, :cond_4a

    .line 1436
    .line 1437
    const/4 v11, 0x0

    .line 1438
    iput-boolean v11, v3, Lb8/j;->v:Z

    .line 1439
    .line 1440
    goto :goto_29

    .line 1441
    :cond_4a
    const/4 v11, 0x0

    .line 1442
    :goto_29
    invoke-virtual {v0}, La8/i0;->L0()V

    .line 1443
    .line 1444
    .line 1445
    iget-object v2, v0, La8/i0;->y1:La8/i1;

    .line 1446
    .line 1447
    iget-object v2, v2, La8/i1;->f:La8/o;

    .line 1448
    .line 1449
    if-nez v2, :cond_4b

    .line 1450
    .line 1451
    iput-boolean v11, v3, Lb8/j;->x:Z

    .line 1452
    .line 1453
    const/16 v5, 0xa

    .line 1454
    .line 1455
    goto :goto_2a

    .line 1456
    :cond_4b
    iget-object v2, v1, Lt7/m;->a:Landroid/util/SparseBooleanArray;

    .line 1457
    .line 1458
    const/16 v5, 0xa

    .line 1459
    .line 1460
    invoke-virtual {v2, v5}, Landroid/util/SparseBooleanArray;->get(I)Z

    .line 1461
    .line 1462
    .line 1463
    move-result v2

    .line 1464
    if-eqz v2, :cond_4c

    .line 1465
    .line 1466
    const/4 v12, 0x1

    .line 1467
    iput-boolean v12, v3, Lb8/j;->x:Z

    .line 1468
    .line 1469
    :cond_4c
    :goto_2a
    invoke-virtual {v0}, La8/i0;->o0()I

    .line 1470
    .line 1471
    .line 1472
    move-result v2

    .line 1473
    iget-boolean v6, v3, Lb8/j;->v:Z

    .line 1474
    .line 1475
    if-eqz v6, :cond_4d

    .line 1476
    .line 1477
    const/4 v8, 0x5

    .line 1478
    :goto_2b
    const/4 v12, 0x1

    .line 1479
    goto/16 :goto_2d

    .line 1480
    .line 1481
    :cond_4d
    iget-boolean v6, v3, Lb8/j;->x:Z

    .line 1482
    .line 1483
    if-eqz v6, :cond_4e

    .line 1484
    .line 1485
    goto :goto_2b

    .line 1486
    :cond_4e
    const/4 v7, 0x4

    .line 1487
    if-ne v2, v7, :cond_4f

    .line 1488
    .line 1489
    const/16 v8, 0xb

    .line 1490
    .line 1491
    goto :goto_2b

    .line 1492
    :cond_4f
    const/16 v8, 0xc

    .line 1493
    .line 1494
    const/4 v11, 0x2

    .line 1495
    if-ne v2, v11, :cond_54

    .line 1496
    .line 1497
    iget v2, v3, Lb8/j;->m:I

    .line 1498
    .line 1499
    if-eqz v2, :cond_53

    .line 1500
    .line 1501
    if-eq v2, v11, :cond_53

    .line 1502
    .line 1503
    if-ne v2, v8, :cond_50

    .line 1504
    .line 1505
    goto :goto_2c

    .line 1506
    :cond_50
    invoke-virtual {v0}, La8/i0;->n0()Z

    .line 1507
    .line 1508
    .line 1509
    move-result v2

    .line 1510
    if-nez v2, :cond_51

    .line 1511
    .line 1512
    move/from16 v8, v17

    .line 1513
    .line 1514
    goto :goto_2b

    .line 1515
    :cond_51
    invoke-virtual {v0}, La8/i0;->L0()V

    .line 1516
    .line 1517
    .line 1518
    iget-object v0, v0, La8/i0;->y1:La8/i1;

    .line 1519
    .line 1520
    iget v0, v0, La8/i1;->n:I

    .line 1521
    .line 1522
    if-eqz v0, :cond_52

    .line 1523
    .line 1524
    move v8, v5

    .line 1525
    goto :goto_2b

    .line 1526
    :cond_52
    move v8, v15

    .line 1527
    goto :goto_2b

    .line 1528
    :cond_53
    :goto_2c
    move v8, v11

    .line 1529
    goto :goto_2b

    .line 1530
    :cond_54
    const/4 v11, 0x3

    .line 1531
    if-ne v2, v11, :cond_56

    .line 1532
    .line 1533
    invoke-virtual {v0}, La8/i0;->n0()Z

    .line 1534
    .line 1535
    .line 1536
    move-result v2

    .line 1537
    if-nez v2, :cond_55

    .line 1538
    .line 1539
    move v8, v7

    .line 1540
    goto :goto_2b

    .line 1541
    :cond_55
    invoke-virtual {v0}, La8/i0;->L0()V

    .line 1542
    .line 1543
    .line 1544
    iget-object v0, v0, La8/i0;->y1:La8/i1;

    .line 1545
    .line 1546
    iget v0, v0, La8/i1;->n:I

    .line 1547
    .line 1548
    if-eqz v0, :cond_53

    .line 1549
    .line 1550
    move/from16 v8, v18

    .line 1551
    .line 1552
    goto :goto_2b

    .line 1553
    :cond_56
    const/4 v12, 0x1

    .line 1554
    if-ne v2, v12, :cond_57

    .line 1555
    .line 1556
    iget v0, v3, Lb8/j;->m:I

    .line 1557
    .line 1558
    if-eqz v0, :cond_57

    .line 1559
    .line 1560
    goto :goto_2d

    .line 1561
    :cond_57
    iget v8, v3, Lb8/j;->m:I

    .line 1562
    .line 1563
    :goto_2d
    iget v0, v3, Lb8/j;->m:I

    .line 1564
    .line 1565
    if-eq v0, v8, :cond_58

    .line 1566
    .line 1567
    iput v8, v3, Lb8/j;->m:I

    .line 1568
    .line 1569
    iput-boolean v12, v3, Lb8/j;->B:Z

    .line 1570
    .line 1571
    invoke-static {}, Lb8/h;->g()Landroid/media/metrics/PlaybackStateEvent$Builder;

    .line 1572
    .line 1573
    .line 1574
    move-result-object v0

    .line 1575
    iget v2, v3, Lb8/j;->m:I

    .line 1576
    .line 1577
    invoke-static {v0, v2}, Lb8/h;->h(Landroid/media/metrics/PlaybackStateEvent$Builder;I)Landroid/media/metrics/PlaybackStateEvent$Builder;

    .line 1578
    .line 1579
    .line 1580
    move-result-object v0

    .line 1581
    iget-wide v5, v3, Lb8/j;->e:J

    .line 1582
    .line 1583
    sub-long/2addr v9, v5

    .line 1584
    invoke-static {v0, v9, v10}, Lb8/h;->i(Landroid/media/metrics/PlaybackStateEvent$Builder;J)Landroid/media/metrics/PlaybackStateEvent$Builder;

    .line 1585
    .line 1586
    .line 1587
    move-result-object v0

    .line 1588
    invoke-static {v0}, Lb8/h;->j(Landroid/media/metrics/PlaybackStateEvent$Builder;)Landroid/media/metrics/PlaybackStateEvent;

    .line 1589
    .line 1590
    .line 1591
    move-result-object v0

    .line 1592
    iget-object v2, v3, Lb8/j;->b:Ljava/util/concurrent/Executor;

    .line 1593
    .line 1594
    new-instance v5, La8/z;

    .line 1595
    .line 1596
    const/16 v6, 0xd

    .line 1597
    .line 1598
    invoke-direct {v5, v6, v3, v0}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1599
    .line 1600
    .line 1601
    invoke-interface {v2, v5}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 1602
    .line 1603
    .line 1604
    :cond_58
    iget-object v0, v1, Lt7/m;->a:Landroid/util/SparseBooleanArray;

    .line 1605
    .line 1606
    const/16 v1, 0x404

    .line 1607
    .line 1608
    invoke-virtual {v0, v1}, Landroid/util/SparseBooleanArray;->get(I)Z

    .line 1609
    .line 1610
    .line 1611
    move-result v0

    .line 1612
    if-eqz v0, :cond_5c

    .line 1613
    .line 1614
    iget-object v2, v3, Lb8/j;->c:Lb8/g;

    .line 1615
    .line 1616
    invoke-virtual {v4, v1}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 1617
    .line 1618
    .line 1619
    move-result-object v0

    .line 1620
    check-cast v0, Lb8/a;

    .line 1621
    .line 1622
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1623
    .line 1624
    .line 1625
    monitor-enter v2

    .line 1626
    :try_start_4
    iget-object v1, v2, Lb8/g;->f:Ljava/lang/String;

    .line 1627
    .line 1628
    if-eqz v1, :cond_59

    .line 1629
    .line 1630
    iget-object v3, v2, Lb8/g;->c:Ljava/util/HashMap;

    .line 1631
    .line 1632
    invoke-virtual {v3, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1633
    .line 1634
    .line 1635
    move-result-object v1

    .line 1636
    check-cast v1, Lb8/f;

    .line 1637
    .line 1638
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1639
    .line 1640
    .line 1641
    invoke-virtual {v2, v1}, Lb8/g;->a(Lb8/f;)V

    .line 1642
    .line 1643
    .line 1644
    goto :goto_2e

    .line 1645
    :catchall_2
    move-exception v0

    .line 1646
    goto :goto_30

    .line 1647
    :cond_59
    :goto_2e
    iget-object v1, v2, Lb8/g;->c:Ljava/util/HashMap;

    .line 1648
    .line 1649
    invoke-virtual {v1}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 1650
    .line 1651
    .line 1652
    move-result-object v1

    .line 1653
    invoke-interface {v1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 1654
    .line 1655
    .line 1656
    move-result-object v1

    .line 1657
    :cond_5a
    :goto_2f
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1658
    .line 1659
    .line 1660
    move-result v3

    .line 1661
    if-eqz v3, :cond_5b

    .line 1662
    .line 1663
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1664
    .line 1665
    .line 1666
    move-result-object v3

    .line 1667
    check-cast v3, Lb8/f;

    .line 1668
    .line 1669
    invoke-interface {v1}, Ljava/util/Iterator;->remove()V

    .line 1670
    .line 1671
    .line 1672
    iget-boolean v4, v3, Lb8/f;->e:Z

    .line 1673
    .line 1674
    if-eqz v4, :cond_5a

    .line 1675
    .line 1676
    iget-object v4, v2, Lb8/g;->d:Lb8/j;

    .line 1677
    .line 1678
    if-eqz v4, :cond_5a

    .line 1679
    .line 1680
    iget-object v3, v3, Lb8/f;->a:Ljava/lang/String;

    .line 1681
    .line 1682
    invoke-virtual {v4, v0, v3}, Lb8/j;->d(Lb8/a;Ljava/lang/String;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 1683
    .line 1684
    .line 1685
    goto :goto_2f

    .line 1686
    :cond_5b
    monitor-exit v2

    .line 1687
    return-void

    .line 1688
    :goto_30
    :try_start_5
    monitor-exit v2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 1689
    throw v0

    .line 1690
    :cond_5c
    :goto_31
    return-void

    .line 1691
    :pswitch_data_0
    .packed-switch 0x1772
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 1692
    .line 1693
    .line 1694
    .line 1695
    .line 1696
    .line 1697
    .line 1698
    .line 1699
    .line 1700
    .line 1701
    .line 1702
    .line 1703
    :pswitch_data_1
    .packed-switch 0x1772
        :pswitch_6
        :pswitch_7
        :pswitch_5
        :pswitch_4
    .end packed-switch

    .line 1704
    .line 1705
    .line 1706
    .line 1707
    .line 1708
    .line 1709
    .line 1710
    .line 1711
    .line 1712
    .line 1713
    .line 1714
    .line 1715
    :pswitch_data_2
    .packed-switch 0x0
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_8
        :pswitch_b
        :pswitch_8
        :pswitch_a
        :pswitch_9
    .end packed-switch
.end method

.method public accept(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ld8/f;

    .line 4
    .line 5
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lh8/x;

    .line 8
    .line 9
    check-cast p1, Lh8/h0;

    .line 10
    .line 11
    iget v1, v0, Ld8/f;->a:I

    .line 12
    .line 13
    iget-object v0, v0, Ld8/f;->b:Lh8/b0;

    .line 14
    .line 15
    invoke-interface {p1, v1, v0, p0}, Lh8/h0;->d(ILh8/b0;Lh8/x;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public apply(Ljava/lang/Object;)Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 3

    .line 1
    iget v0, p0, La0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lu/g1;

    .line 9
    .line 10
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Ljava/util/ArrayList;

    .line 13
    .line 14
    check-cast p1, Ljava/util/List;

    .line 15
    .line 16
    new-instance v1, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v2, "["

    .line 19
    .line 20
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    const-string v0, "] getSurface done with results: "

    .line 27
    .line 28
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    const-string v1, "SyncCaptureSessionBase"

    .line 39
    .line 40
    invoke-static {v1, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-eqz v0, :cond_0

    .line 48
    .line 49
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 50
    .line 51
    const-string p1, "Unable to open capture session without surfaces"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    new-instance p1, Lk0/j;

    .line 57
    .line 58
    const/4 v0, 0x1

    .line 59
    invoke-direct {p1, p0, v0}, Lk0/j;-><init>(Ljava/lang/Object;I)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_0
    const/4 v0, 0x0

    .line 64
    invoke-interface {p1, v0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    if-eqz v1, :cond_1

    .line 69
    .line 70
    new-instance v1, Lh0/s0;

    .line 71
    .line 72
    invoke-interface {p1, v0}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 73
    .line 74
    .line 75
    move-result p1

    .line 76
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    check-cast p0, Lh0/t0;

    .line 81
    .line 82
    const-string p1, "Surface closed"

    .line 83
    .line 84
    invoke-direct {v1, p1, p0}, Lh0/s0;-><init>(Ljava/lang/String;Lh0/t0;)V

    .line 85
    .line 86
    .line 87
    new-instance p1, Lk0/j;

    .line 88
    .line 89
    const/4 p0, 0x1

    .line 90
    invoke-direct {p1, v1, p0}, Lk0/j;-><init>(Ljava/lang/Object;I)V

    .line 91
    .line 92
    .line 93
    goto :goto_0

    .line 94
    :cond_1
    invoke-static {p1}, Lk0/h;->c(Ljava/lang/Object;)Lk0/j;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    :goto_0
    return-object p1

    .line 99
    :pswitch_0
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast v0, Lu/p0;

    .line 102
    .line 103
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast p0, Lb0/u1;

    .line 106
    .line 107
    check-cast p1, Ljava/lang/Void;

    .line 108
    .line 109
    invoke-virtual {v0}, Lu/p0;->b()V

    .line 110
    .line 111
    .line 112
    invoke-virtual {p0}, Lh0/t0;->a()V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v0}, Lu/p0;->n()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    return-object p0

    .line 120
    nop

    .line 121
    :pswitch_data_0
    .packed-switch 0x19
        :pswitch_0
    .end packed-switch
.end method

.method public b(Lgt/b;)V
    .locals 1

    .line 1
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lgt/a;

    .line 4
    .line 5
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lgt/a;

    .line 8
    .line 9
    invoke-interface {v0, p1}, Lgt/a;->b(Lgt/b;)V

    .line 10
    .line 11
    .line 12
    invoke-interface {p0, p1}, Lgt/a;->b(Lgt/b;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public c(Lh0/c1;)V
    .locals 0

    .line 1
    iget p1, p0, La0/h;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, La0/h;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Lbu/c;

    .line 9
    .line 10
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lh0/b1;

    .line 13
    .line 14
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    invoke-interface {p0, p1}, Lh0/b1;->c(Lh0/c1;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :pswitch_0
    iget-object p1, p0, La0/h;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p1, Lb0/n1;

    .line 24
    .line 25
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p0, Lh0/b1;

    .line 28
    .line 29
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    invoke-interface {p0, p1}, Lh0/b1;->c(Lh0/c1;)V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method

.method public e(Lin/z1;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, La0/h;->d:I

    .line 2
    .line 3
    sparse-switch v0, :sswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ljava/lang/String;

    .line 9
    .line 10
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lgs/b;

    .line 13
    .line 14
    :try_start_0
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lgs/b;->f:Lgs/e;

    .line 18
    .line 19
    invoke-interface {p0, p1}, Lgs/e;->e(Lin/z1;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 24
    .line 25
    .line 26
    return-object p0

    .line 27
    :catchall_0
    move-exception p0

    .line 28
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :sswitch_0
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v0, Lgs/s;

    .line 35
    .line 36
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p0, Lgs/s;

    .line 39
    .line 40
    new-instance v1, Les/d;

    .line 41
    .line 42
    const-class v2, Lsr/f;

    .line 43
    .line 44
    invoke-virtual {p1, v2}, Lin/z1;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    check-cast v2, Lsr/f;

    .line 49
    .line 50
    invoke-virtual {p1, v0}, Lin/z1;->b(Lgs/s;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    check-cast v0, Ljava/util/concurrent/Executor;

    .line 55
    .line 56
    invoke-virtual {p1, p0}, Lin/z1;->b(Lgs/s;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    check-cast p0, Ljava/util/concurrent/Executor;

    .line 61
    .line 62
    invoke-direct {v1, v2, v0, p0}, Les/d;-><init>(Lsr/f;Ljava/util/concurrent/Executor;Ljava/util/concurrent/Executor;)V

    .line 63
    .line 64
    .line 65
    return-object v1

    .line 66
    :sswitch_1
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v0, Ljava/lang/String;

    .line 69
    .line 70
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast p0, Lj9/d;

    .line 73
    .line 74
    const-class v1, Landroid/content/Context;

    .line 75
    .line 76
    invoke-virtual {p1, v1}, Lin/z1;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    check-cast p1, Landroid/content/Context;

    .line 81
    .line 82
    iget p0, p0, Lj9/d;->d:I

    .line 83
    .line 84
    packed-switch p0, :pswitch_data_0

    .line 85
    .line 86
    .line 87
    invoke-virtual {p1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    invoke-virtual {p1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    invoke-virtual {p0, p1}, Landroid/content/pm/PackageManager;->getInstallerPackageName(Ljava/lang/String;)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    if-eqz p0, :cond_0

    .line 100
    .line 101
    invoke-static {p0}, Lcom/google/firebase/FirebaseCommonRegistrar;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    goto :goto_0

    .line 106
    :cond_0
    const-string p0, ""

    .line 107
    .line 108
    goto :goto_0

    .line 109
    :pswitch_0
    invoke-virtual {p1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    const-string v1, "android.hardware.type.television"

    .line 114
    .line 115
    invoke-virtual {p0, v1}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    .line 116
    .line 117
    .line 118
    move-result p0

    .line 119
    if-eqz p0, :cond_1

    .line 120
    .line 121
    const-string p0, "tv"

    .line 122
    .line 123
    goto :goto_0

    .line 124
    :cond_1
    invoke-virtual {p1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    const-string v1, "android.hardware.type.watch"

    .line 129
    .line 130
    invoke-virtual {p0, v1}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    .line 131
    .line 132
    .line 133
    move-result p0

    .line 134
    if-eqz p0, :cond_2

    .line 135
    .line 136
    const-string p0, "watch"

    .line 137
    .line 138
    goto :goto_0

    .line 139
    :cond_2
    invoke-virtual {p1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    const-string v1, "android.hardware.type.automotive"

    .line 144
    .line 145
    invoke-virtual {p0, v1}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    .line 146
    .line 147
    .line 148
    move-result p0

    .line 149
    if-eqz p0, :cond_3

    .line 150
    .line 151
    const-string p0, "auto"

    .line 152
    .line 153
    goto :goto_0

    .line 154
    :cond_3
    invoke-virtual {p1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    const-string p1, "android.hardware.type.embedded"

    .line 159
    .line 160
    invoke-virtual {p0, p1}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    .line 161
    .line 162
    .line 163
    move-result p0

    .line 164
    if-eqz p0, :cond_0

    .line 165
    .line 166
    const-string p0, "embedded"

    .line 167
    .line 168
    goto :goto_0

    .line 169
    :pswitch_1
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    if-eqz p0, :cond_0

    .line 174
    .line 175
    iget p0, p0, Landroid/content/pm/ApplicationInfo;->minSdkVersion:I

    .line 176
    .line 177
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object p0

    .line 181
    goto :goto_0

    .line 182
    :pswitch_2
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    .line 183
    .line 184
    .line 185
    move-result-object p0

    .line 186
    if-eqz p0, :cond_0

    .line 187
    .line 188
    iget p0, p0, Landroid/content/pm/ApplicationInfo;->targetSdkVersion:I

    .line 189
    .line 190
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    :goto_0
    new-instance p1, Lbu/a;

    .line 195
    .line 196
    invoke-direct {p1, v0, p0}, Lbu/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    return-object p1

    .line 200
    nop

    .line 201
    :sswitch_data_0
    .sparse-switch
        0x6 -> :sswitch_1
        0x9 -> :sswitch_0
    .end sparse-switch

    .line 202
    .line 203
    .line 204
    .line 205
    .line 206
    .line 207
    .line 208
    .line 209
    .line 210
    .line 211
    :pswitch_data_0
    .packed-switch 0x1a
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public execute()Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lqn/s;

    .line 4
    .line 5
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Ljava/lang/Iterable;

    .line 8
    .line 9
    iget-object v0, v0, Lqn/s;->c:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v0, Lyn/d;

    .line 12
    .line 13
    check-cast v0, Lyn/h;

    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-nez v1, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 30
    .line 31
    const-string v2, "DELETE FROM events WHERE _id in "

    .line 32
    .line 33
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-static {p0}, Lyn/h;->j(Ljava/lang/Iterable;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    invoke-virtual {v0}, Lyn/h;->a()Landroid/database/sqlite/SQLiteDatabase;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    invoke-virtual {v0, p0}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteStatement;->execute()V

    .line 56
    .line 57
    .line 58
    :goto_0
    const/4 p0, 0x0

    .line 59
    return-object p0
.end method

.method public f(Lb0/j;)V
    .locals 2

    .line 1
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lp0/c;

    .line 4
    .line 5
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lb0/x1;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lb0/x1;->c:Lb0/y;

    .line 13
    .line 14
    invoke-virtual {p0}, Lb0/y;->a()Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    iget-boolean p0, p1, Lb0/j;->d:Z

    .line 21
    .line 22
    if-eqz p0, :cond_0

    .line 23
    .line 24
    sget-object p0, Lr0/f;->f:Lr0/f;

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    sget-object p0, Lr0/f;->e:Lr0/f;

    .line 28
    .line 29
    :goto_0
    iget-object p1, v0, Lp0/c;->d:Lc1/k2;

    .line 30
    .line 31
    iget-object v0, p1, Lc1/k2;->f:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 34
    .line 35
    const/4 v1, 0x1

    .line 36
    invoke-static {v0, v1}, Lr0/i;->d(Ljava/util/concurrent/atomic/AtomicBoolean;Z)V

    .line 37
    .line 38
    .line 39
    iget-object v0, p1, Lc1/k2;->h:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Ljava/lang/Thread;

    .line 42
    .line 43
    invoke-static {v0}, Lr0/i;->c(Ljava/lang/Thread;)V

    .line 44
    .line 45
    .line 46
    iget-object v0, p1, Lc1/k2;->p:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast v0, Lr0/f;

    .line 49
    .line 50
    if-eq v0, p0, :cond_1

    .line 51
    .line 52
    iput-object p0, p1, Lc1/k2;->p:Ljava/lang/Object;

    .line 53
    .line 54
    iget p0, p1, Lc1/k2;->e:I

    .line 55
    .line 56
    invoke-virtual {p1, p0}, Lc1/k2;->p(I)V

    .line 57
    .line 58
    .line 59
    :cond_1
    return-void
.end method

.method public g(Ljava/lang/Object;)Laq/t;
    .locals 1

    .line 1
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ldu/c;

    .line 4
    .line 5
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Ldu/e;

    .line 8
    .line 9
    check-cast p1, Ljava/lang/Void;

    .line 10
    .line 11
    monitor-enter v0

    .line 12
    :try_start_0
    invoke-static {p0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iput-object p1, v0, Ldu/c;->c:Laq/t;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    .line 18
    monitor-exit v0

    .line 19
    invoke-static {p0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    :catchall_0
    move-exception p0

    .line 25
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 26
    throw p0
.end method

.method public h(Ly4/h;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, La0/h;->d:I

    .line 2
    .line 3
    sparse-switch v0, :sswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lw0/r;

    .line 9
    .line 10
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Landroid/view/Surface;

    .line 13
    .line 14
    const-string v1, "TextureViewImpl"

    .line 15
    .line 16
    const-string v2, "Surface set on Preview."

    .line 17
    .line 18
    invoke-static {v1, v2}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object v1, v0, Lw0/r;->h:Lb0/x1;

    .line 22
    .line 23
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    new-instance v3, Lg0/c;

    .line 28
    .line 29
    const/4 v4, 0x3

    .line 30
    invoke-direct {v3, p1, v4}, Lg0/c;-><init>(Ljava/lang/Object;I)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1, p0, v2, v3}, Lb0/x1;->a(Landroid/view/Surface;Ljava/util/concurrent/Executor;Lc6/a;)V

    .line 34
    .line 35
    .line 36
    new-instance p1, Ljava/lang/StringBuilder;

    .line 37
    .line 38
    const-string v1, "provideSurface[request="

    .line 39
    .line 40
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    iget-object v0, v0, Lw0/r;->h:Lb0/x1;

    .line 44
    .line 45
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const-string v0, " surface="

    .line 49
    .line 50
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    const-string p0, "]"

    .line 57
    .line 58
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    return-object p0

    .line 66
    :sswitch_0
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v0, Lh0/z;

    .line 69
    .line 70
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast p0, Ljava/util/ArrayList;

    .line 73
    .line 74
    new-instance v1, Lu/j;

    .line 75
    .line 76
    invoke-direct {v1, p1, v0}, Lu/j;-><init>(Ly4/h;Lh0/z;)V

    .line 77
    .line 78
    .line 79
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    check-cast v0, Lh0/z;

    .line 83
    .line 84
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    invoke-interface {v0, p0, v1}, Lh0/z;->l(Ljava/util/concurrent/Executor;Lu/j;)V

    .line 89
    .line 90
    .line 91
    const-string p0, "waitForCaptureResult"

    .line 92
    .line 93
    return-object p0

    .line 94
    :sswitch_1
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v0, Lq0/e;

    .line 97
    .line 98
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast p0, Lb0/y;

    .line 101
    .line 102
    sget-object v1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 103
    .line 104
    new-instance v1, La8/y0;

    .line 105
    .line 106
    invoke-direct {v1, v0, p0, p1}, La8/y0;-><init>(Lq0/e;Lb0/y;Ly4/h;)V

    .line 107
    .line 108
    .line 109
    new-instance p0, Lu/g;

    .line 110
    .line 111
    const/4 p1, 0x0

    .line 112
    invoke-direct {p0, p1}, Lu/g;-><init>(I)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v0, v1, p0}, Lq0/e;->e(Ljava/lang/Runnable;Ljava/lang/Runnable;)V

    .line 116
    .line 117
    .line 118
    const-string p0, "Init GlRenderer"

    .line 119
    .line 120
    return-object p0

    .line 121
    :sswitch_2
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast v0, Lp0/c;

    .line 124
    .line 125
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast p0, Lb0/y;

    .line 128
    .line 129
    sget-object v1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 130
    .line 131
    new-instance v1, La8/y0;

    .line 132
    .line 133
    invoke-direct {v1, v0, p0, p1}, La8/y0;-><init>(Lp0/c;Lb0/y;Ly4/h;)V

    .line 134
    .line 135
    .line 136
    new-instance p0, Lu/g;

    .line 137
    .line 138
    const/4 p1, 0x0

    .line 139
    invoke-direct {p0, p1}, Lu/g;-><init>(I)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v0, v1, p0}, Lp0/c;->e(Ljava/lang/Runnable;Ljava/lang/Runnable;)V

    .line 143
    .line 144
    .line 145
    const-string p0, "Init GlRenderer"

    .line 146
    .line 147
    return-object p0

    .line 148
    :sswitch_3
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 149
    .line 150
    check-cast v0, Ljava/util/concurrent/Executor;

    .line 151
    .line 152
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast p0, Lay0/a;

    .line 155
    .line 156
    new-instance v1, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 157
    .line 158
    const/4 v2, 0x0

    .line 159
    invoke-direct {v1, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    .line 160
    .line 161
    .line 162
    new-instance v2, Leb/p;

    .line 163
    .line 164
    const/4 v3, 0x1

    .line 165
    invoke-direct {v2, v1, v3}, Leb/p;-><init>(Ljava/util/concurrent/atomic/AtomicBoolean;I)V

    .line 166
    .line 167
    .line 168
    sget-object v3, Leb/k;->d:Leb/k;

    .line 169
    .line 170
    invoke-virtual {p1, v3, v2}, Ly4/h;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 171
    .line 172
    .line 173
    new-instance v2, Leb/q;

    .line 174
    .line 175
    const/4 v3, 0x1

    .line 176
    invoke-direct {v2, v1, p1, p0, v3}, Leb/q;-><init>(Ljava/util/concurrent/atomic/AtomicBoolean;Ly4/h;Lay0/a;I)V

    .line 177
    .line 178
    .line 179
    invoke-interface {v0, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 180
    .line 181
    .line 182
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 183
    .line 184
    return-object p0

    .line 185
    :sswitch_4
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 186
    .line 187
    check-cast v0, Lb0/x1;

    .line 188
    .line 189
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 190
    .line 191
    check-cast p0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 192
    .line 193
    invoke-virtual {p0, p1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 194
    .line 195
    .line 196
    new-instance p0, Ljava/lang/StringBuilder;

    .line 197
    .line 198
    const-string p1, "SurfaceRequest-surface-recreation("

    .line 199
    .line 200
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 204
    .line 205
    .line 206
    move-result p1

    .line 207
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 208
    .line 209
    .line 210
    const-string p1, ")"

    .line 211
    .line 212
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 213
    .line 214
    .line 215
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 216
    .line 217
    .line 218
    move-result-object p0

    .line 219
    return-object p0

    .line 220
    :sswitch_5
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 221
    .line 222
    move-object v2, v0

    .line 223
    check-cast v2, Lb0/u;

    .line 224
    .line 225
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 226
    .line 227
    move-object v3, p0

    .line 228
    check-cast v3, Landroid/content/Context;

    .line 229
    .line 230
    iget-object v4, v2, Lb0/u;->d:Ljava/util/concurrent/Executor;

    .line 231
    .line 232
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 233
    .line 234
    .line 235
    move-result-wide v7

    .line 236
    new-instance v1, Lb0/t;

    .line 237
    .line 238
    const/4 v5, 0x1

    .line 239
    move-object v6, p1

    .line 240
    invoke-direct/range {v1 .. v8}, Lb0/t;-><init>(Lb0/u;Landroid/content/Context;Ljava/util/concurrent/Executor;ILy4/h;J)V

    .line 241
    .line 242
    .line 243
    invoke-interface {v4, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 244
    .line 245
    .line 246
    const-string p0, "CameraX initInternal"

    .line 247
    .line 248
    return-object p0

    .line 249
    :sswitch_data_0
    .sparse-switch
        0x1 -> :sswitch_5
        0x3 -> :sswitch_4
        0xe -> :sswitch_3
        0x15 -> :sswitch_2
        0x17 -> :sswitch_1
        0x1b -> :sswitch_0
    .end sparse-switch
.end method

.method public invoke(Ljava/lang/Object;)V
    .locals 5

    .line 1
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lb8/a;

    .line 4
    .line 5
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lh8/x;

    .line 8
    .line 9
    check-cast p1, Lb8/j;

    .line 10
    .line 11
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    iget-object v1, v0, Lb8/a;->d:Lh8/b0;

    .line 15
    .line 16
    if-nez v1, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    new-instance v2, Lb81/a;

    .line 20
    .line 21
    iget-object v3, p0, Lh8/x;->b:Lt7/o;

    .line 22
    .line 23
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    iget-object v4, p1, Lb8/j;->c:Lb8/g;

    .line 27
    .line 28
    iget-object v0, v0, Lb8/a;->b:Lt7/p0;

    .line 29
    .line 30
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v4, v0, v1}, Lb8/g;->c(Lt7/p0;Lh8/b0;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    const/4 v1, 0x2

    .line 38
    invoke-direct {v2, v1, v3, v0}, Lb81/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    iget p0, p0, Lh8/x;->a:I

    .line 42
    .line 43
    if-eqz p0, :cond_3

    .line 44
    .line 45
    const/4 v0, 0x1

    .line 46
    if-eq p0, v0, :cond_2

    .line 47
    .line 48
    const/4 v0, 0x2

    .line 49
    if-eq p0, v0, :cond_3

    .line 50
    .line 51
    const/4 v0, 0x3

    .line 52
    if-eq p0, v0, :cond_1

    .line 53
    .line 54
    :goto_0
    return-void

    .line 55
    :cond_1
    iput-object v2, p1, Lb8/j;->r:Lb81/a;

    .line 56
    .line 57
    return-void

    .line 58
    :cond_2
    iput-object v2, p1, Lb8/j;->q:Lb81/a;

    .line 59
    .line 60
    return-void

    .line 61
    :cond_3
    iput-object v2, p1, Lb8/j;->p:Lb81/a;

    .line 62
    .line 63
    return-void
.end method

.method public onComplete(Laq/j;)V
    .locals 2

    .line 1
    iget v0, p0, La0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lbb/g0;

    .line 9
    .line 10
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lb0/p1;

    .line 13
    .line 14
    const-string v1, "it"

    .line 15
    .line 16
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iget p1, v0, Lbb/g0;->e:I

    .line 20
    .line 21
    add-int/lit8 p1, p1, -0x1

    .line 22
    .line 23
    iput p1, v0, Lbb/g0;->e:I

    .line 24
    .line 25
    if-nez p1, :cond_0

    .line 26
    .line 27
    invoke-virtual {p0}, Lb0/b0;->close()V

    .line 28
    .line 29
    .line 30
    :cond_0
    return-void

    .line 31
    :pswitch_0
    iget-object p1, p0, La0/h;->e:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p1, Lcom/google/firebase/messaging/g;

    .line 34
    .line 35
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Landroid/content/Intent;

    .line 38
    .line 39
    invoke-virtual {p1, p0}, Lcom/google/firebase/messaging/g;->a(Landroid/content/Intent;)V

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :pswitch_data_0
    .packed-switch 0x7
        :pswitch_0
    .end packed-switch
.end method

.method public onFailure(Ljava/lang/Exception;)V
    .locals 2

    .line 1
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lhg0/g;

    .line 4
    .line 5
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 8
    .line 9
    instance-of v1, p1, Lko/o;

    .line 10
    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    check-cast p1, Lko/o;

    .line 14
    .line 15
    :try_start_0
    iget-object p1, p1, Lko/e;->d:Lcom/google/android/gms/common/api/Status;

    .line 16
    .line 17
    const/4 v1, 0x1

    .line 18
    invoke-virtual {p1, p0, v1}, Lcom/google/android/gms/common/api/Status;->y0(Landroid/app/Activity;I)V
    :try_end_0
    .catch Landroid/content/IntentSender$SendIntentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :catch_0
    move-exception p0

    .line 23
    new-instance p1, Lh50/q0;

    .line 24
    .line 25
    const/4 v1, 0x2

    .line 26
    invoke-direct {p1, p0, v1}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 27
    .line 28
    .line 29
    const/4 p0, 0x0

    .line 30
    invoke-static {p0, v0, p1}, Llp/nd;->m(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 31
    .line 32
    .line 33
    :cond_0
    return-void
.end method

.method public w(Laq/j;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, La0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    iget-object p1, p0, La0/h;->e:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v0, p1

    .line 9
    check-cast v0, Ldu/l;

    .line 10
    .line 11
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Laq/t;

    .line 14
    .line 15
    const-string p1, "Unable to connect to the server. Try again in a few minutes. HTTP status code: %d"

    .line 16
    .line 17
    iget-object v1, v0, Ldu/l;->p:Lto/a;

    .line 18
    .line 19
    const/16 v2, 0x8

    .line 20
    .line 21
    const/16 v3, 0x193

    .line 22
    .line 23
    const/4 v4, 0x1

    .line 24
    const/16 v5, 0xc8

    .line 25
    .line 26
    const/4 v6, 0x0

    .line 27
    const/4 v7, 0x0

    .line 28
    :try_start_0
    invoke-virtual {p0}, Laq/t;->i()Z

    .line 29
    .line 30
    .line 31
    move-result v8

    .line 32
    if-eqz v8, :cond_6

    .line 33
    .line 34
    invoke-virtual {p0}, Laq/t;->g()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Ljava/net/HttpURLConnection;

    .line 39
    .line 40
    iput-object p0, v0, Ldu/l;->f:Ljava/net/HttpURLConnection;

    .line 41
    .line 42
    invoke-virtual {p0}, Ljava/net/URLConnection;->getInputStream()Ljava/io/InputStream;

    .line 43
    .line 44
    .line 45
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_3
    .catchall {:try_start_0 .. :try_end_0} :catchall_5

    .line 46
    :try_start_1
    iget-object v8, v0, Ldu/l;->f:Ljava/net/HttpURLConnection;

    .line 47
    .line 48
    invoke-virtual {v8}, Ljava/net/HttpURLConnection;->getErrorStream()Ljava/io/InputStream;

    .line 49
    .line 50
    .line 51
    move-result-object v8
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_2
    .catchall {:try_start_1 .. :try_end_1} :catchall_4

    .line 52
    :try_start_2
    iget-object v9, v0, Ldu/l;->f:Ljava/net/HttpURLConnection;

    .line 53
    .line 54
    invoke-virtual {v9}, Ljava/net/HttpURLConnection;->getResponseCode()I

    .line 55
    .line 56
    .line 57
    move-result v9

    .line 58
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 59
    .line 60
    .line 61
    move-result-object v10
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_1
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    .line 62
    if-ne v9, v5, :cond_0

    .line 63
    .line 64
    :try_start_3
    monitor-enter v0
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 65
    :try_start_4
    iput v2, v0, Ldu/l;->c:I
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 66
    .line 67
    :try_start_5
    monitor-exit v0

    .line 68
    iget-object v11, v0, Ldu/l;->q:Ldu/n;

    .line 69
    .line 70
    sget-object v12, Ldu/n;->f:Ljava/util/Date;

    .line 71
    .line 72
    invoke-virtual {v11, v6, v12}, Ldu/n;->e(ILjava/util/Date;)V

    .line 73
    .line 74
    .line 75
    iget-object v11, v0, Ldu/l;->f:Ljava/net/HttpURLConnection;

    .line 76
    .line 77
    invoke-virtual {v0, v11}, Ldu/l;->j(Ljava/net/HttpURLConnection;)Lc8/f;

    .line 78
    .line 79
    .line 80
    move-result-object v11

    .line 81
    iput-object v11, v0, Ldu/l;->g:Lc8/f;

    .line 82
    .line 83
    invoke-virtual {v11}, Lc8/f;->c()V
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_0
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 84
    .line 85
    .line 86
    goto :goto_1

    .line 87
    :catchall_0
    move-exception v2

    .line 88
    :goto_0
    move-object v7, p0

    .line 89
    goto/16 :goto_a

    .line 90
    .line 91
    :catch_0
    move-exception v9

    .line 92
    goto/16 :goto_6

    .line 93
    .line 94
    :catchall_1
    move-exception v9

    .line 95
    :try_start_6
    monitor-exit v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 96
    :try_start_7
    throw v9
    :try_end_7
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_7} :catch_0
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 97
    :cond_0
    :goto_1
    invoke-virtual {v0, p0, v8}, Ldu/l;->b(Ljava/io/InputStream;Ljava/io/InputStream;)V

    .line 98
    .line 99
    .line 100
    monitor-enter v0

    .line 101
    :try_start_8
    iput-boolean v6, v0, Ldu/l;->b:Z
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_2

    .line 102
    .line 103
    monitor-exit v0

    .line 104
    iget-boolean p0, v0, Ldu/l;->e:Z

    .line 105
    .line 106
    if-nez p0, :cond_1

    .line 107
    .line 108
    invoke-static {v9}, Ldu/l;->d(I)Z

    .line 109
    .line 110
    .line 111
    move-result p0

    .line 112
    if-eqz p0, :cond_1

    .line 113
    .line 114
    goto :goto_2

    .line 115
    :cond_1
    move v4, v6

    .line 116
    :goto_2
    if-eqz v4, :cond_2

    .line 117
    .line 118
    new-instance p0, Ljava/util/Date;

    .line 119
    .line 120
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 121
    .line 122
    .line 123
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 124
    .line 125
    .line 126
    move-result-wide v1

    .line 127
    invoke-direct {p0, v1, v2}, Ljava/util/Date;-><init>(J)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v0, p0}, Ldu/l;->k(Ljava/util/Date;)V

    .line 131
    .line 132
    .line 133
    :cond_2
    if-nez v4, :cond_5

    .line 134
    .line 135
    if-ne v9, v5, :cond_3

    .line 136
    .line 137
    goto :goto_4

    .line 138
    :cond_3
    filled-new-array {v10}, [Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    invoke-static {p1, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    if-ne v9, v3, :cond_4

    .line 147
    .line 148
    iget-object p0, v0, Ldu/l;->f:Ljava/net/HttpURLConnection;

    .line 149
    .line 150
    invoke-virtual {p0}, Ljava/net/HttpURLConnection;->getErrorStream()Ljava/io/InputStream;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    invoke-static {p0}, Ldu/l;->f(Ljava/io/InputStream;)Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    :cond_4
    new-instance p1, Lcu/f;

    .line 159
    .line 160
    invoke-direct {p1, v9, v6, p0}, Lcu/f;-><init>(IILjava/lang/String;)V

    .line 161
    .line 162
    .line 163
    :goto_3
    invoke-virtual {v0}, Ldu/l;->g()V

    .line 164
    .line 165
    .line 166
    goto/16 :goto_9

    .line 167
    .line 168
    :cond_5
    :goto_4
    invoke-virtual {v0}, Ldu/l;->h()V

    .line 169
    .line 170
    .line 171
    goto/16 :goto_9

    .line 172
    .line 173
    :catchall_2
    move-exception p0

    .line 174
    :try_start_9
    monitor-exit v0
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 175
    throw p0

    .line 176
    :catchall_3
    move-exception v2

    .line 177
    move-object v10, v7

    .line 178
    goto :goto_0

    .line 179
    :catch_1
    move-exception v9

    .line 180
    move-object v10, v7

    .line 181
    goto :goto_6

    .line 182
    :catchall_4
    move-exception v2

    .line 183
    move-object v8, v7

    .line 184
    move-object v10, v8

    .line 185
    goto :goto_0

    .line 186
    :catch_2
    move-exception v9

    .line 187
    move-object v8, v7

    .line 188
    :goto_5
    move-object v10, v8

    .line 189
    goto :goto_6

    .line 190
    :catchall_5
    move-exception v2

    .line 191
    move-object v8, v7

    .line 192
    move-object v10, v8

    .line 193
    goto/16 :goto_a

    .line 194
    .line 195
    :catch_3
    move-exception v9

    .line 196
    move-object p0, v7

    .line 197
    move-object v8, p0

    .line 198
    goto :goto_5

    .line 199
    :cond_6
    :try_start_a
    new-instance v8, Ljava/io/IOException;

    .line 200
    .line 201
    invoke-virtual {p0}, Laq/t;->f()Ljava/lang/Exception;

    .line 202
    .line 203
    .line 204
    move-result-object p0

    .line 205
    invoke-direct {v8, p0}, Ljava/io/IOException;-><init>(Ljava/lang/Throwable;)V

    .line 206
    .line 207
    .line 208
    throw v8
    :try_end_a
    .catch Ljava/io/IOException; {:try_start_a .. :try_end_a} :catch_3
    .catchall {:try_start_a .. :try_end_a} :catchall_5

    .line 209
    :goto_6
    :try_start_b
    iget-boolean v11, v0, Ldu/l;->e:Z

    .line 210
    .line 211
    if-eqz v11, :cond_7

    .line 212
    .line 213
    monitor-enter v0
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_0

    .line 214
    :try_start_c
    iput v2, v0, Ldu/l;->c:I
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_6

    .line 215
    .line 216
    :try_start_d
    monitor-exit v0
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_0

    .line 217
    goto :goto_7

    .line 218
    :catchall_6
    move-exception v2

    .line 219
    :try_start_e
    monitor-exit v0
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_6

    .line 220
    :try_start_f
    throw v2

    .line 221
    :cond_7
    const-string v2, "FirebaseRemoteConfig"

    .line 222
    .line 223
    const-string v11, "Exception connecting to real-time RC backend. Retrying the connection..."

    .line 224
    .line 225
    invoke-static {v2, v11, v9}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_f
    .catchall {:try_start_f .. :try_end_f} :catchall_0

    .line 226
    .line 227
    .line 228
    :goto_7
    invoke-virtual {v0, p0, v8}, Ldu/l;->b(Ljava/io/InputStream;Ljava/io/InputStream;)V

    .line 229
    .line 230
    .line 231
    monitor-enter v0

    .line 232
    :try_start_10
    iput-boolean v6, v0, Ldu/l;->b:Z
    :try_end_10
    .catchall {:try_start_10 .. :try_end_10} :catchall_7

    .line 233
    .line 234
    monitor-exit v0

    .line 235
    iget-boolean p0, v0, Ldu/l;->e:Z

    .line 236
    .line 237
    if-nez p0, :cond_8

    .line 238
    .line 239
    if-eqz v10, :cond_9

    .line 240
    .line 241
    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    .line 242
    .line 243
    .line 244
    move-result p0

    .line 245
    invoke-static {p0}, Ldu/l;->d(I)Z

    .line 246
    .line 247
    .line 248
    move-result p0

    .line 249
    if-eqz p0, :cond_8

    .line 250
    .line 251
    goto :goto_8

    .line 252
    :cond_8
    move v4, v6

    .line 253
    :cond_9
    :goto_8
    if-eqz v4, :cond_a

    .line 254
    .line 255
    new-instance p0, Ljava/util/Date;

    .line 256
    .line 257
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 258
    .line 259
    .line 260
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 261
    .line 262
    .line 263
    move-result-wide v1

    .line 264
    invoke-direct {p0, v1, v2}, Ljava/util/Date;-><init>(J)V

    .line 265
    .line 266
    .line 267
    invoke-virtual {v0, p0}, Ldu/l;->k(Ljava/util/Date;)V

    .line 268
    .line 269
    .line 270
    :cond_a
    if-nez v4, :cond_5

    .line 271
    .line 272
    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    .line 273
    .line 274
    .line 275
    move-result p0

    .line 276
    if-ne p0, v5, :cond_b

    .line 277
    .line 278
    goto :goto_4

    .line 279
    :cond_b
    filled-new-array {v10}, [Ljava/lang/Object;

    .line 280
    .line 281
    .line 282
    move-result-object p0

    .line 283
    invoke-static {p1, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 284
    .line 285
    .line 286
    move-result-object p0

    .line 287
    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    .line 288
    .line 289
    .line 290
    move-result p1

    .line 291
    if-ne p1, v3, :cond_c

    .line 292
    .line 293
    iget-object p0, v0, Ldu/l;->f:Ljava/net/HttpURLConnection;

    .line 294
    .line 295
    invoke-virtual {p0}, Ljava/net/HttpURLConnection;->getErrorStream()Ljava/io/InputStream;

    .line 296
    .line 297
    .line 298
    move-result-object p0

    .line 299
    invoke-static {p0}, Ldu/l;->f(Ljava/io/InputStream;)Ljava/lang/String;

    .line 300
    .line 301
    .line 302
    move-result-object p0

    .line 303
    :cond_c
    new-instance p1, Lcu/f;

    .line 304
    .line 305
    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    .line 306
    .line 307
    .line 308
    move-result v1

    .line 309
    invoke-direct {p1, v1, v6, p0}, Lcu/f;-><init>(IILjava/lang/String;)V

    .line 310
    .line 311
    .line 312
    goto/16 :goto_3

    .line 313
    .line 314
    :goto_9
    iput-object v7, v0, Ldu/l;->f:Ljava/net/HttpURLConnection;

    .line 315
    .line 316
    iput-object v7, v0, Ldu/l;->g:Lc8/f;

    .line 317
    .line 318
    invoke-static {v7}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 319
    .line 320
    .line 321
    move-result-object p0

    .line 322
    return-object p0

    .line 323
    :catchall_7
    move-exception p0

    .line 324
    :try_start_11
    monitor-exit v0
    :try_end_11
    .catchall {:try_start_11 .. :try_end_11} :catchall_7

    .line 325
    throw p0

    .line 326
    :goto_a
    invoke-virtual {v0, v7, v8}, Ldu/l;->b(Ljava/io/InputStream;Ljava/io/InputStream;)V

    .line 327
    .line 328
    .line 329
    monitor-enter v0

    .line 330
    :try_start_12
    iput-boolean v6, v0, Ldu/l;->b:Z
    :try_end_12
    .catchall {:try_start_12 .. :try_end_12} :catchall_8

    .line 331
    .line 332
    monitor-exit v0

    .line 333
    iget-boolean p0, v0, Ldu/l;->e:Z

    .line 334
    .line 335
    if-nez p0, :cond_d

    .line 336
    .line 337
    if-eqz v10, :cond_e

    .line 338
    .line 339
    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    .line 340
    .line 341
    .line 342
    move-result p0

    .line 343
    invoke-static {p0}, Ldu/l;->d(I)Z

    .line 344
    .line 345
    .line 346
    move-result p0

    .line 347
    if-eqz p0, :cond_d

    .line 348
    .line 349
    goto :goto_b

    .line 350
    :cond_d
    move v4, v6

    .line 351
    :cond_e
    :goto_b
    if-eqz v4, :cond_f

    .line 352
    .line 353
    new-instance p0, Ljava/util/Date;

    .line 354
    .line 355
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 356
    .line 357
    .line 358
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 359
    .line 360
    .line 361
    move-result-wide v7

    .line 362
    invoke-direct {p0, v7, v8}, Ljava/util/Date;-><init>(J)V

    .line 363
    .line 364
    .line 365
    invoke-virtual {v0, p0}, Ldu/l;->k(Ljava/util/Date;)V

    .line 366
    .line 367
    .line 368
    :cond_f
    if-nez v4, :cond_11

    .line 369
    .line 370
    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    .line 371
    .line 372
    .line 373
    move-result p0

    .line 374
    if-eq p0, v5, :cond_11

    .line 375
    .line 376
    filled-new-array {v10}, [Ljava/lang/Object;

    .line 377
    .line 378
    .line 379
    move-result-object p0

    .line 380
    invoke-static {p1, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 381
    .line 382
    .line 383
    move-result-object p0

    .line 384
    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    .line 385
    .line 386
    .line 387
    move-result p1

    .line 388
    if-ne p1, v3, :cond_10

    .line 389
    .line 390
    iget-object p0, v0, Ldu/l;->f:Ljava/net/HttpURLConnection;

    .line 391
    .line 392
    invoke-virtual {p0}, Ljava/net/HttpURLConnection;->getErrorStream()Ljava/io/InputStream;

    .line 393
    .line 394
    .line 395
    move-result-object p0

    .line 396
    invoke-static {p0}, Ldu/l;->f(Ljava/io/InputStream;)Ljava/lang/String;

    .line 397
    .line 398
    .line 399
    move-result-object p0

    .line 400
    :cond_10
    new-instance p1, Lcu/f;

    .line 401
    .line 402
    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    .line 403
    .line 404
    .line 405
    move-result v1

    .line 406
    invoke-direct {p1, v1, v6, p0}, Lcu/f;-><init>(IILjava/lang/String;)V

    .line 407
    .line 408
    .line 409
    invoke-virtual {v0}, Ldu/l;->g()V

    .line 410
    .line 411
    .line 412
    goto :goto_c

    .line 413
    :cond_11
    invoke-virtual {v0}, Ldu/l;->h()V

    .line 414
    .line 415
    .line 416
    :goto_c
    throw v2

    .line 417
    :catchall_8
    move-exception p0

    .line 418
    :try_start_13
    monitor-exit v0
    :try_end_13
    .catchall {:try_start_13 .. :try_end_13} :catchall_8

    .line 419
    throw p0

    .line 420
    :pswitch_1
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 421
    .line 422
    check-cast v0, Ldu/i;

    .line 423
    .line 424
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 425
    .line 426
    check-cast p0, Ljava/util/HashMap;

    .line 427
    .line 428
    const-wide/16 v1, 0x0

    .line 429
    .line 430
    invoke-virtual {v0, p1, v1, v2, p0}, Ldu/i;->c(Laq/j;JLjava/util/HashMap;)Laq/t;

    .line 431
    .line 432
    .line 433
    move-result-object p0

    .line 434
    return-object p0

    .line 435
    :pswitch_2
    invoke-direct {p0, p1}, La0/h;->d(Laq/j;)Ljava/lang/Object;

    .line 436
    .line 437
    .line 438
    return-object p1

    .line 439
    :pswitch_3
    iget-object v0, p0, La0/h;->e:Ljava/lang/Object;

    .line 440
    .line 441
    check-cast v0, Lcom/google/firebase/messaging/j;

    .line 442
    .line 443
    iget-object p0, p0, La0/h;->f:Ljava/lang/Object;

    .line 444
    .line 445
    check-cast p0, Ljava/lang/String;

    .line 446
    .line 447
    monitor-enter v0

    .line 448
    :try_start_14
    iget-object v1, v0, Lcom/google/firebase/messaging/j;->b:Ljava/lang/Object;

    .line 449
    .line 450
    check-cast v1, Landroidx/collection/f;

    .line 451
    .line 452
    invoke-interface {v1, p0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 453
    .line 454
    .line 455
    monitor-exit v0

    .line 456
    return-object p1

    .line 457
    :catchall_9
    move-exception p0

    .line 458
    monitor-exit v0
    :try_end_14
    .catchall {:try_start_14 .. :try_end_14} :catchall_9

    .line 459
    throw p0

    .line 460
    nop

    .line 461
    :pswitch_data_0
    .packed-switch 0x8
        :pswitch_3
        :pswitch_0
        :pswitch_0
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method
