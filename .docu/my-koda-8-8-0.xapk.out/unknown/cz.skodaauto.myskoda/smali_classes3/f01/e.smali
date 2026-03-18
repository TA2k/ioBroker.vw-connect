.class public final Lf01/e;
.super Lg01/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lay0/a;Ljava/lang/String;Z)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lf01/e;->e:I

    iput-object p1, p0, Lf01/e;->f:Ljava/lang/Object;

    .line 2
    invoke-direct {p0, p2, p3}, Lg01/a;-><init>(Ljava/lang/String;Z)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;ILjava/lang/Object;)V
    .locals 0

    .line 1
    iput p2, p0, Lf01/e;->e:I

    iput-object p3, p0, Lf01/e;->f:Ljava/lang/Object;

    const/4 p2, 0x1

    invoke-direct {p0, p1, p2}, Lg01/a;-><init>(Ljava/lang/String;Z)V

    return-void
.end method


# virtual methods
.method public final a()J
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lf01/e;->e:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, v0, Lf01/e;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lh01/q;

    .line 11
    .line 12
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 13
    .line 14
    .line 15
    move-result-wide v1

    .line 16
    iget-wide v3, v0, Lh01/q;->e:J

    .line 17
    .line 18
    sub-long v3, v1, v3

    .line 19
    .line 20
    const-wide/16 v5, 0x1

    .line 21
    .line 22
    add-long/2addr v3, v5

    .line 23
    iget-object v5, v0, Lh01/q;->h:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v5, Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 26
    .line 27
    invoke-virtual {v5}, Ljava/util/concurrent/ConcurrentLinkedQueue;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object v5

    .line 31
    const-string v6, "iterator(...)"

    .line 32
    .line 33
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const/4 v6, 0x0

    .line 37
    const-wide v7, 0x7fffffffffffffffL

    .line 38
    .line 39
    .line 40
    .line 41
    .line 42
    const/4 v9, 0x0

    .line 43
    move-object v11, v6

    .line 44
    move-object v12, v11

    .line 45
    move v10, v9

    .line 46
    :goto_0
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 47
    .line 48
    .line 49
    move-result v13

    .line 50
    if-eqz v13, :cond_3

    .line 51
    .line 52
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v13

    .line 56
    check-cast v13, Lh01/p;

    .line 57
    .line 58
    invoke-static {v13}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    monitor-enter v13

    .line 62
    :try_start_0
    invoke-virtual {v0, v13, v1, v2}, Lh01/q;->a(Lh01/p;J)I

    .line 63
    .line 64
    .line 65
    move-result v14

    .line 66
    if-lez v14, :cond_0

    .line 67
    .line 68
    add-int/lit8 v10, v10, 0x1

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_0
    iget-wide v14, v13, Lh01/p;->q:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 72
    .line 73
    cmp-long v16, v14, v3

    .line 74
    .line 75
    if-gez v16, :cond_1

    .line 76
    .line 77
    move-object v11, v13

    .line 78
    move-wide v3, v14

    .line 79
    :cond_1
    add-int/lit8 v9, v9, 0x1

    .line 80
    .line 81
    cmp-long v16, v14, v7

    .line 82
    .line 83
    if-gez v16, :cond_2

    .line 84
    .line 85
    move-object v12, v13

    .line 86
    move-wide v7, v14

    .line 87
    :cond_2
    :goto_1
    monitor-exit v13

    .line 88
    goto :goto_0

    .line 89
    :catchall_0
    move-exception v0

    .line 90
    monitor-exit v13

    .line 91
    throw v0

    .line 92
    :cond_3
    const-wide/16 v13, -0x1

    .line 93
    .line 94
    if-eqz v11, :cond_4

    .line 95
    .line 96
    move-object v6, v11

    .line 97
    goto :goto_2

    .line 98
    :cond_4
    const/4 v3, 0x5

    .line 99
    if-le v9, v3, :cond_5

    .line 100
    .line 101
    move-wide v3, v7

    .line 102
    move-object v6, v12

    .line 103
    goto :goto_2

    .line 104
    :cond_5
    move-wide v3, v13

    .line 105
    :goto_2
    if-eqz v6, :cond_8

    .line 106
    .line 107
    monitor-enter v6

    .line 108
    :try_start_1
    iget-object v1, v6, Lh01/p;->p:Ljava/util/ArrayList;

    .line 109
    .line 110
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 111
    .line 112
    .line 113
    move-result v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 114
    const-wide/16 v13, 0x0

    .line 115
    .line 116
    if-nez v1, :cond_6

    .line 117
    .line 118
    :goto_3
    monitor-exit v6

    .line 119
    goto :goto_4

    .line 120
    :cond_6
    :try_start_2
    iget-wide v1, v6, Lh01/p;->q:J

    .line 121
    .line 122
    cmp-long v1, v1, v3

    .line 123
    .line 124
    if-eqz v1, :cond_7

    .line 125
    .line 126
    goto :goto_3

    .line 127
    :cond_7
    const/4 v1, 0x1

    .line 128
    iput-boolean v1, v6, Lh01/p;->j:Z

    .line 129
    .line 130
    iget-object v1, v0, Lh01/q;->h:Ljava/lang/Object;

    .line 131
    .line 132
    check-cast v1, Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 133
    .line 134
    invoke-virtual {v1, v6}, Ljava/util/concurrent/ConcurrentLinkedQueue;->remove(Ljava/lang/Object;)Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 135
    .line 136
    .line 137
    monitor-exit v6

    .line 138
    iget-object v1, v6, Lh01/p;->e:Ljava/net/Socket;

    .line 139
    .line 140
    invoke-static {v1}, Le01/g;->c(Ljava/net/Socket;)V

    .line 141
    .line 142
    .line 143
    iget-object v1, v0, Lh01/q;->h:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast v1, Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 146
    .line 147
    invoke-virtual {v1}, Ljava/util/concurrent/ConcurrentLinkedQueue;->isEmpty()Z

    .line 148
    .line 149
    .line 150
    move-result v1

    .line 151
    if-eqz v1, :cond_a

    .line 152
    .line 153
    iget-object v0, v0, Lh01/q;->f:Ljava/lang/Object;

    .line 154
    .line 155
    check-cast v0, Lg01/b;

    .line 156
    .line 157
    invoke-virtual {v0}, Lg01/b;->a()V

    .line 158
    .line 159
    .line 160
    goto :goto_4

    .line 161
    :catchall_1
    move-exception v0

    .line 162
    monitor-exit v6

    .line 163
    throw v0

    .line 164
    :cond_8
    if-eqz v12, :cond_9

    .line 165
    .line 166
    iget-wide v3, v0, Lh01/q;->e:J

    .line 167
    .line 168
    add-long/2addr v7, v3

    .line 169
    sub-long v13, v7, v1

    .line 170
    .line 171
    goto :goto_4

    .line 172
    :cond_9
    if-lez v10, :cond_a

    .line 173
    .line 174
    iget-wide v13, v0, Lh01/q;->e:J

    .line 175
    .line 176
    :cond_a
    :goto_4
    return-wide v13

    .line 177
    :pswitch_0
    iget-object v0, v0, Lf01/e;->f:Ljava/lang/Object;

    .line 178
    .line 179
    check-cast v0, Lay0/a;

    .line 180
    .line 181
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    const-wide/16 v0, -0x1

    .line 185
    .line 186
    return-wide v0

    .line 187
    :pswitch_1
    iget-object v0, v0, Lf01/e;->f:Ljava/lang/Object;

    .line 188
    .line 189
    move-object v1, v0

    .line 190
    check-cast v1, Lf01/g;

    .line 191
    .line 192
    monitor-enter v1

    .line 193
    :try_start_3
    iget-boolean v0, v1, Lf01/g;->p:Z

    .line 194
    .line 195
    if-eqz v0, :cond_d

    .line 196
    .line 197
    iget-boolean v0, v1, Lf01/g;->q:Z
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 198
    .line 199
    if-eqz v0, :cond_b

    .line 200
    .line 201
    goto :goto_6

    .line 202
    :cond_b
    const/4 v0, 0x1

    .line 203
    :try_start_4
    invoke-virtual {v1}, Lf01/g;->E()V
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 204
    .line 205
    .line 206
    goto :goto_5

    .line 207
    :catchall_2
    move-exception v0

    .line 208
    goto :goto_7

    .line 209
    :catch_0
    :try_start_5
    iput-boolean v0, v1, Lf01/g;->r:Z
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 210
    .line 211
    :goto_5
    :try_start_6
    invoke-virtual {v1}, Lf01/g;->h()Z

    .line 212
    .line 213
    .line 214
    move-result v2

    .line 215
    if-eqz v2, :cond_d

    .line 216
    .line 217
    invoke-virtual {v1}, Lf01/g;->q()V

    .line 218
    .line 219
    .line 220
    const/4 v2, 0x0

    .line 221
    iput v2, v1, Lf01/g;->m:I
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_1
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 222
    .line 223
    goto :goto_6

    .line 224
    :catch_1
    :try_start_7
    iput-boolean v0, v1, Lf01/g;->s:Z

    .line 225
    .line 226
    iget-object v0, v1, Lf01/g;->k:Lu01/a0;

    .line 227
    .line 228
    if-eqz v0, :cond_c

    .line 229
    .line 230
    invoke-static {v0}, Le01/e;->b(Ljava/io/Closeable;)V

    .line 231
    .line 232
    .line 233
    :cond_c
    new-instance v0, Lu01/e;

    .line 234
    .line 235
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 236
    .line 237
    .line 238
    invoke-static {v0}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    .line 239
    .line 240
    .line 241
    move-result-object v0

    .line 242
    iput-object v0, v1, Lf01/g;->k:Lu01/a0;
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 243
    .line 244
    :cond_d
    :goto_6
    monitor-exit v1

    .line 245
    const-wide/16 v0, -0x1

    .line 246
    .line 247
    return-wide v0

    .line 248
    :goto_7
    monitor-exit v1

    .line 249
    throw v0

    .line 250
    nop

    .line 251
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
