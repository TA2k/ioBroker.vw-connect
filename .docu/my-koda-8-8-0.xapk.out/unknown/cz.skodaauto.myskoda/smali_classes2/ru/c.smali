.class public Lru/c;
.super Lap0/o;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:I

.field public final g:Ljava/util/LinkedHashSet;

.field public final h:Lzu/a;


# direct methods
.method public constructor <init>()V
    .locals 10

    .line 1
    const/4 v0, 0x6

    .line 2
    invoke-direct {p0, v0}, Lap0/o;-><init>(I)V

    .line 3
    .line 4
    .line 5
    const/16 v0, 0x64

    .line 6
    .line 7
    iput v0, p0, Lru/c;->f:I

    .line 8
    .line 9
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 10
    .line 11
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Lru/c;->g:Ljava/util/LinkedHashSet;

    .line 15
    .line 16
    new-instance v0, Lzu/a;

    .line 17
    .line 18
    new-instance v1, Lxu/a;

    .line 19
    .line 20
    const-wide/16 v2, 0x0

    .line 21
    .line 22
    const-wide/high16 v4, 0x3ff0000000000000L    # 1.0

    .line 23
    .line 24
    const-wide/16 v6, 0x0

    .line 25
    .line 26
    const-wide/high16 v8, 0x3ff0000000000000L    # 1.0

    .line 27
    .line 28
    invoke-direct/range {v1 .. v9}, Lxu/a;-><init>(DDDD)V

    .line 29
    .line 30
    .line 31
    const/4 v2, 0x0

    .line 32
    invoke-direct {v0, v1, v2}, Lzu/a;-><init>(Lxu/a;I)V

    .line 33
    .line 34
    .line 35
    iput-object v0, p0, Lru/c;->h:Lzu/a;

    .line 36
    .line 37
    return-void
.end method


# virtual methods
.method public final b()Ljava/util/Collection;
    .locals 3

    .line 1
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lru/c;->h:Lzu/a;

    .line 7
    .line 8
    monitor-enter v1

    .line 9
    :try_start_0
    iget-object p0, p0, Lru/c;->g:Ljava/util/LinkedHashSet;

    .line 10
    .line 11
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    if-eqz v2, :cond_0

    .line 20
    .line 21
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    check-cast v2, Lru/b;

    .line 26
    .line 27
    iget-object v2, v2, Lru/b;->a:Lzj0/c;

    .line 28
    .line 29
    invoke-interface {v0, v2}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catchall_0
    move-exception p0

    .line 34
    goto :goto_1

    .line 35
    :cond_0
    monitor-exit v1

    .line 36
    return-object v0

    .line 37
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    throw p0
.end method

.method public b0(Lzu/a;F)Ljava/util/Collection;
    .locals 0

    .line 1
    iget-object p0, p0, Lru/c;->g:Ljava/util/LinkedHashSet;

    .line 2
    .line 3
    return-object p0
.end method

.method public final e(Ljava/util/Collection;)Z
    .locals 11

    .line 1
    invoke-interface {p1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    const/4 v0, 0x0

    .line 6
    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-eqz v1, :cond_2

    .line 11
    .line 12
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    check-cast v1, Lzj0/c;

    .line 17
    .line 18
    new-instance v7, Lru/b;

    .line 19
    .line 20
    invoke-direct {v7, v1}, Lru/b;-><init>(Lzj0/c;)V

    .line 21
    .line 22
    .line 23
    iget-object v1, p0, Lru/c;->h:Lzu/a;

    .line 24
    .line 25
    monitor-enter v1

    .line 26
    :try_start_0
    iget-object v2, p0, Lru/c;->g:Ljava/util/LinkedHashSet;

    .line 27
    .line 28
    invoke-interface {v2, v7}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v8

    .line 32
    if-eqz v8, :cond_1

    .line 33
    .line 34
    iget-object v2, p0, Lru/c;->h:Lzu/a;

    .line 35
    .line 36
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    iget-object v3, v7, Lru/b;->b:Lyu/a;

    .line 40
    .line 41
    iget-object v4, v2, Lzu/a;->a:Lxu/a;

    .line 42
    .line 43
    iget-wide v5, v3, Lyu/a;->a:D

    .line 44
    .line 45
    iget-wide v9, v3, Lyu/a;->b:D

    .line 46
    .line 47
    invoke-virtual {v4, v5, v6, v9, v10}, Lxu/a;->a(DD)Z

    .line 48
    .line 49
    .line 50
    move-result v4

    .line 51
    if-eqz v4, :cond_1

    .line 52
    .line 53
    move-object v5, v3

    .line 54
    iget-wide v3, v5, Lyu/a;->a:D

    .line 55
    .line 56
    iget-wide v5, v5, Lyu/a;->b:D

    .line 57
    .line 58
    invoke-virtual/range {v2 .. v7}, Lzu/a;->a(DDLru/b;)V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :catchall_0
    move-exception v0

    .line 63
    move-object p0, v0

    .line 64
    goto :goto_2

    .line 65
    :cond_1
    :goto_1
    monitor-exit v1

    .line 66
    if-eqz v8, :cond_0

    .line 67
    .line 68
    const/4 v0, 0x1

    .line 69
    goto :goto_0

    .line 70
    :goto_2
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 71
    throw p0

    .line 72
    :cond_2
    return v0
.end method

.method public final g()V
    .locals 2

    .line 1
    iget-object v0, p0, Lru/c;->h:Lzu/a;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lru/c;->g:Ljava/util/LinkedHashSet;

    .line 5
    .line 6
    invoke-interface {v1}, Ljava/util/Collection;->clear()V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lru/c;->h:Lzu/a;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    iput-object v1, p0, Lzu/a;->d:Ljava/util/ArrayList;

    .line 13
    .line 14
    iget-object p0, p0, Lzu/a;->c:Ljava/util/LinkedHashSet;

    .line 15
    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    invoke-interface {p0}, Ljava/util/Set;->clear()V

    .line 19
    .line 20
    .line 21
    :cond_0
    monitor-exit v0

    .line 22
    return-void

    .line 23
    :catchall_0
    move-exception p0

    .line 24
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    throw p0
.end method

.method public final m(F)Ljava/util/Set;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    float-to-int v2, v1

    .line 6
    iget v3, v0, Lru/c;->f:I

    .line 7
    .line 8
    int-to-double v3, v3

    .line 9
    int-to-double v5, v2

    .line 10
    const-wide/high16 v7, 0x4000000000000000L    # 2.0

    .line 11
    .line 12
    invoke-static {v7, v8, v5, v6}, Ljava/lang/Math;->pow(DD)D

    .line 13
    .line 14
    .line 15
    move-result-wide v5

    .line 16
    div-double/2addr v3, v5

    .line 17
    const-wide/high16 v5, 0x4070000000000000L    # 256.0

    .line 18
    .line 19
    div-double/2addr v3, v5

    .line 20
    new-instance v2, Ljava/util/HashSet;

    .line 21
    .line 22
    invoke-direct {v2}, Ljava/util/HashSet;-><init>()V

    .line 23
    .line 24
    .line 25
    new-instance v5, Ljava/util/HashSet;

    .line 26
    .line 27
    invoke-direct {v5}, Ljava/util/HashSet;-><init>()V

    .line 28
    .line 29
    .line 30
    new-instance v6, Ljava/util/HashMap;

    .line 31
    .line 32
    invoke-direct {v6}, Ljava/util/HashMap;-><init>()V

    .line 33
    .line 34
    .line 35
    new-instance v9, Ljava/util/HashMap;

    .line 36
    .line 37
    invoke-direct {v9}, Ljava/util/HashMap;-><init>()V

    .line 38
    .line 39
    .line 40
    iget-object v10, v0, Lru/c;->h:Lzu/a;

    .line 41
    .line 42
    monitor-enter v10

    .line 43
    :try_start_0
    iget-object v11, v0, Lru/c;->h:Lzu/a;

    .line 44
    .line 45
    invoke-virtual {v0, v11, v1}, Lru/c;->b0(Lzu/a;F)Ljava/util/Collection;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    invoke-interface {v1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 54
    .line 55
    .line 56
    move-result v11

    .line 57
    if-eqz v11, :cond_5

    .line 58
    .line 59
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v11

    .line 63
    check-cast v11, Lru/b;

    .line 64
    .line 65
    invoke-virtual {v2, v11}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v12

    .line 69
    if-eqz v12, :cond_0

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_0
    iget-object v12, v11, Lru/b;->b:Lyu/a;

    .line 73
    .line 74
    div-double v13, v3, v7

    .line 75
    .line 76
    new-instance v15, Lxu/a;

    .line 77
    .line 78
    iget-wide v7, v12, Lyu/a;->a:D

    .line 79
    .line 80
    sub-double v16, v7, v13

    .line 81
    .line 82
    add-double v18, v7, v13

    .line 83
    .line 84
    iget-wide v7, v12, Lyu/a;->b:D

    .line 85
    .line 86
    sub-double v20, v7, v13

    .line 87
    .line 88
    add-double v22, v7, v13

    .line 89
    .line 90
    invoke-direct/range {v15 .. v23}, Lxu/a;-><init>(DDDD)V

    .line 91
    .line 92
    .line 93
    iget-object v7, v0, Lru/c;->h:Lzu/a;

    .line 94
    .line 95
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 96
    .line 97
    .line 98
    new-instance v8, Ljava/util/ArrayList;

    .line 99
    .line 100
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 101
    .line 102
    .line 103
    invoke-virtual {v7, v15, v8}, Lzu/a;->b(Lxu/a;Ljava/util/ArrayList;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 107
    .line 108
    .line 109
    move-result v7

    .line 110
    const/4 v12, 0x1

    .line 111
    if-ne v7, v12, :cond_1

    .line 112
    .line 113
    invoke-virtual {v5, v11}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    invoke-virtual {v2, v11}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    const-wide/16 v7, 0x0

    .line 120
    .line 121
    invoke-static {v7, v8}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 122
    .line 123
    .line 124
    move-result-object v7

    .line 125
    invoke-virtual {v6, v11, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    const-wide/high16 v7, 0x4000000000000000L    # 2.0

    .line 129
    .line 130
    goto :goto_0

    .line 131
    :catchall_0
    move-exception v0

    .line 132
    goto/16 :goto_3

    .line 133
    .line 134
    :cond_1
    new-instance v7, Lru/h;

    .line 135
    .line 136
    iget-object v12, v11, Lru/b;->a:Lzj0/c;

    .line 137
    .line 138
    invoke-virtual {v12}, Lzj0/c;->a()Lcom/google/android/gms/maps/model/LatLng;

    .line 139
    .line 140
    .line 141
    move-result-object v12

    .line 142
    invoke-direct {v7, v12}, Lru/h;-><init>(Lcom/google/android/gms/maps/model/LatLng;)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {v5, v7}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    invoke-virtual {v8}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 149
    .line 150
    .line 151
    move-result-object v12

    .line 152
    :goto_1
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 153
    .line 154
    .line 155
    move-result v13

    .line 156
    if-eqz v13, :cond_4

    .line 157
    .line 158
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v13

    .line 162
    check-cast v13, Lru/b;

    .line 163
    .line 164
    invoke-virtual {v6, v13}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v14

    .line 168
    check-cast v14, Ljava/lang/Double;

    .line 169
    .line 170
    iget-object v15, v13, Lru/b;->b:Lyu/a;

    .line 171
    .line 172
    iget-object v0, v11, Lru/b;->b:Lyu/a;

    .line 173
    .line 174
    move-wide/from16 v16, v3

    .line 175
    .line 176
    iget-wide v3, v15, Lyu/a;->a:D

    .line 177
    .line 178
    move-wide/from16 v18, v3

    .line 179
    .line 180
    iget-wide v3, v0, Lyu/a;->a:D

    .line 181
    .line 182
    sub-double v3, v18, v3

    .line 183
    .line 184
    mul-double/2addr v3, v3

    .line 185
    move-wide/from16 v18, v3

    .line 186
    .line 187
    iget-wide v3, v15, Lyu/a;->b:D

    .line 188
    .line 189
    move-object/from16 p1, v1

    .line 190
    .line 191
    iget-wide v0, v0, Lyu/a;->b:D

    .line 192
    .line 193
    sub-double/2addr v3, v0

    .line 194
    mul-double/2addr v3, v3

    .line 195
    add-double v3, v3, v18

    .line 196
    .line 197
    if-eqz v14, :cond_3

    .line 198
    .line 199
    invoke-virtual {v14}, Ljava/lang/Double;->doubleValue()D

    .line 200
    .line 201
    .line 202
    move-result-wide v0

    .line 203
    cmpg-double v0, v0, v3

    .line 204
    .line 205
    if-gez v0, :cond_2

    .line 206
    .line 207
    :goto_2
    move-object/from16 v0, p0

    .line 208
    .line 209
    move-object/from16 v1, p1

    .line 210
    .line 211
    move-wide/from16 v3, v16

    .line 212
    .line 213
    goto :goto_1

    .line 214
    :cond_2
    invoke-virtual {v9, v13}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v0

    .line 218
    check-cast v0, Lru/h;

    .line 219
    .line 220
    iget-object v1, v13, Lru/b;->a:Lzj0/c;

    .line 221
    .line 222
    iget-object v0, v0, Lru/h;->b:Ljava/util/LinkedHashSet;

    .line 223
    .line 224
    invoke-interface {v0, v1}, Ljava/util/Collection;->remove(Ljava/lang/Object;)Z

    .line 225
    .line 226
    .line 227
    :cond_3
    invoke-static {v3, v4}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 228
    .line 229
    .line 230
    move-result-object v0

    .line 231
    invoke-virtual {v6, v13, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    iget-object v0, v13, Lru/b;->a:Lzj0/c;

    .line 235
    .line 236
    iget-object v1, v7, Lru/h;->b:Ljava/util/LinkedHashSet;

    .line 237
    .line 238
    invoke-interface {v1, v0}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 239
    .line 240
    .line 241
    invoke-virtual {v9, v13, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    goto :goto_2

    .line 245
    :cond_4
    move-object/from16 p1, v1

    .line 246
    .line 247
    move-wide/from16 v16, v3

    .line 248
    .line 249
    invoke-interface {v2, v8}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 250
    .line 251
    .line 252
    const-wide/high16 v7, 0x4000000000000000L    # 2.0

    .line 253
    .line 254
    move-object/from16 v0, p0

    .line 255
    .line 256
    move-object/from16 v1, p1

    .line 257
    .line 258
    move-wide/from16 v3, v16

    .line 259
    .line 260
    goto/16 :goto_0

    .line 261
    .line 262
    :cond_5
    monitor-exit v10

    .line 263
    return-object v5

    .line 264
    :goto_3
    monitor-exit v10
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 265
    throw v0
.end method

.method public final o()I
    .locals 0

    .line 1
    iget p0, p0, Lru/c;->f:I

    .line 2
    .line 3
    return p0
.end method
