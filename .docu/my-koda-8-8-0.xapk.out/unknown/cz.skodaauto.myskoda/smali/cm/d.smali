.class public final Lcm/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/AutoCloseable;


# static fields
.field public static final u:Lly0/n;


# instance fields
.field public final d:Lu01/y;

.field public final e:J

.field public final f:Lu01/y;

.field public final g:Lu01/y;

.field public final h:Lu01/y;

.field public final i:Ljava/util/LinkedHashMap;

.field public final j:Lpw0/a;

.field public final k:Ljava/lang/Object;

.field public l:J

.field public m:I

.field public n:Lu01/a0;

.field public o:Z

.field public p:Z

.field public q:Z

.field public r:Z

.field public s:Z

.field public final t:Lcm/c;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lly0/n;

    .line 2
    .line 3
    const-string v1, "[a-z0-9_-]{1,120}"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lly0/n;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lcm/d;->u:Lly0/n;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(JLu01/k;Lu01/y;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p4, p0, Lcm/d;->d:Lu01/y;

    .line 5
    .line 6
    iput-wide p1, p0, Lcm/d;->e:J

    .line 7
    .line 8
    const-wide/16 v0, 0x0

    .line 9
    .line 10
    cmp-long p1, p1, v0

    .line 11
    .line 12
    if-lez p1, :cond_0

    .line 13
    .line 14
    const-string p1, "journal"

    .line 15
    .line 16
    invoke-virtual {p4, p1}, Lu01/y;->e(Ljava/lang/String;)Lu01/y;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    iput-object p1, p0, Lcm/d;->f:Lu01/y;

    .line 21
    .line 22
    const-string p1, "journal.tmp"

    .line 23
    .line 24
    invoke-virtual {p4, p1}, Lu01/y;->e(Ljava/lang/String;)Lu01/y;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    iput-object p1, p0, Lcm/d;->g:Lu01/y;

    .line 29
    .line 30
    const-string p1, "journal.bkp"

    .line 31
    .line 32
    invoke-virtual {p4, p1}, Lu01/y;->e(Ljava/lang/String;)Lu01/y;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    iput-object p1, p0, Lcm/d;->h:Lu01/y;

    .line 37
    .line 38
    new-instance p1, Ljava/util/LinkedHashMap;

    .line 39
    .line 40
    const/4 p2, 0x0

    .line 41
    const/high16 p4, 0x3f400000    # 0.75f

    .line 42
    .line 43
    const/4 v0, 0x1

    .line 44
    invoke-direct {p1, p2, p4, v0}, Ljava/util/LinkedHashMap;-><init>(IFZ)V

    .line 45
    .line 46
    .line 47
    iput-object p1, p0, Lcm/d;->i:Ljava/util/LinkedHashMap;

    .line 48
    .line 49
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    sget-object p2, Lvy0/x;->d:Lvy0/w;

    .line 54
    .line 55
    const-string p4, "key"

    .line 56
    .line 57
    invoke-static {p2, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    sget-object p2, Lvy0/p0;->a:Lcz0/e;

    .line 61
    .line 62
    sget-object p2, Lcz0/d;->e:Lcz0/d;

    .line 63
    .line 64
    invoke-virtual {p2, v0}, Lvy0/x;->W(I)Lvy0/x;

    .line 65
    .line 66
    .line 67
    move-result-object p2

    .line 68
    invoke-static {p1, p2}, Ljp/de;->d(Lpx0/e;Lpx0/g;)Lpx0/g;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    invoke-static {p1}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    iput-object p1, p0, Lcm/d;->j:Lpw0/a;

    .line 77
    .line 78
    new-instance p1, Ljava/lang/Object;

    .line 79
    .line 80
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 81
    .line 82
    .line 83
    iput-object p1, p0, Lcm/d;->k:Ljava/lang/Object;

    .line 84
    .line 85
    new-instance p1, Lcm/c;

    .line 86
    .line 87
    invoke-direct {p1, p3}, Lu01/l;-><init>(Lu01/k;)V

    .line 88
    .line 89
    .line 90
    iput-object p1, p0, Lcm/d;->t:Lcm/c;

    .line 91
    .line 92
    return-void

    .line 93
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 94
    .line 95
    const-string p1, "maxSize <= 0"

    .line 96
    .line 97
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    throw p0
.end method

.method public static B(Ljava/lang/String;)V
    .locals 2

    .line 1
    sget-object v0, Lcm/d;->u:Lly0/n;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lly0/n;->d(Ljava/lang/CharSequence;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    const-string v0, "keys must match regex [a-z0-9_-]{1,120}: \""

    .line 11
    .line 12
    const/16 v1, 0x22

    .line 13
    .line 14
    invoke-static {v1, v0, p0}, Lvj/b;->f(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw v0
.end method

.method public static final a(Lcm/d;La8/b;Z)V
    .locals 10

    .line 1
    iget-object v0, p0, Lcm/d;->k:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p1, La8/b;->f:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v1, Lcm/a;

    .line 7
    .line 8
    iget-object v2, v1, Lcm/a;->g:La8/b;

    .line 9
    .line 10
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    if-eqz v2, :cond_d

    .line 15
    .line 16
    const/4 v2, 0x2

    .line 17
    const/4 v3, 0x0

    .line 18
    if-eqz p2, :cond_4

    .line 19
    .line 20
    iget-boolean v4, v1, Lcm/a;->f:Z

    .line 21
    .line 22
    if-nez v4, :cond_4

    .line 23
    .line 24
    move v4, v3

    .line 25
    :goto_0
    if-ge v4, v2, :cond_1

    .line 26
    .line 27
    iget-object v5, p1, La8/b;->g:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v5, [Z

    .line 30
    .line 31
    aget-boolean v5, v5, v4

    .line 32
    .line 33
    if-eqz v5, :cond_0

    .line 34
    .line 35
    iget-object v5, p0, Lcm/d;->t:Lcm/c;

    .line 36
    .line 37
    iget-object v6, v1, Lcm/a;->d:Ljava/util/ArrayList;

    .line 38
    .line 39
    invoke-virtual {v6, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v6

    .line 43
    check-cast v6, Lu01/y;

    .line 44
    .line 45
    invoke-virtual {v5, v6}, Lu01/k;->j(Lu01/y;)Z

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    if-nez v5, :cond_0

    .line 50
    .line 51
    invoke-virtual {p1, v3}, La8/b;->e(Z)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 52
    .line 53
    .line 54
    monitor-exit v0

    .line 55
    return-void

    .line 56
    :catchall_0
    move-exception p0

    .line 57
    goto/16 :goto_8

    .line 58
    .line 59
    :cond_0
    add-int/lit8 v4, v4, 0x1

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_1
    move p1, v3

    .line 63
    :goto_1
    if-ge p1, v2, :cond_5

    .line 64
    .line 65
    :try_start_1
    iget-object v4, v1, Lcm/a;->d:Ljava/util/ArrayList;

    .line 66
    .line 67
    invoke-virtual {v4, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    check-cast v4, Lu01/y;

    .line 72
    .line 73
    iget-object v5, v1, Lcm/a;->c:Ljava/util/ArrayList;

    .line 74
    .line 75
    invoke-virtual {v5, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v5

    .line 79
    check-cast v5, Lu01/y;

    .line 80
    .line 81
    iget-object v6, p0, Lcm/d;->t:Lcm/c;

    .line 82
    .line 83
    invoke-virtual {v6, v4}, Lu01/k;->j(Lu01/y;)Z

    .line 84
    .line 85
    .line 86
    move-result v6

    .line 87
    if-eqz v6, :cond_2

    .line 88
    .line 89
    iget-object v6, p0, Lcm/d;->t:Lcm/c;

    .line 90
    .line 91
    invoke-virtual {v6, v4, v5}, Lu01/l;->b(Lu01/y;Lu01/y;)V

    .line 92
    .line 93
    .line 94
    goto :goto_2

    .line 95
    :cond_2
    iget-object v4, p0, Lcm/d;->t:Lcm/c;

    .line 96
    .line 97
    iget-object v6, v1, Lcm/a;->c:Ljava/util/ArrayList;

    .line 98
    .line 99
    invoke-virtual {v6, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v6

    .line 103
    check-cast v6, Lu01/y;

    .line 104
    .line 105
    invoke-static {v4, v6}, Lkp/h8;->a(Lu01/k;Lu01/y;)V

    .line 106
    .line 107
    .line 108
    :goto_2
    iget-object v4, v1, Lcm/a;->b:[J

    .line 109
    .line 110
    aget-wide v6, v4, p1

    .line 111
    .line 112
    iget-object v4, p0, Lcm/d;->t:Lcm/c;

    .line 113
    .line 114
    invoke-virtual {v4, v5}, Lu01/k;->l(Lu01/y;)Li5/f;

    .line 115
    .line 116
    .line 117
    move-result-object v4

    .line 118
    iget-object v4, v4, Li5/f;->e:Ljava/lang/Object;

    .line 119
    .line 120
    check-cast v4, Ljava/lang/Long;

    .line 121
    .line 122
    if-eqz v4, :cond_3

    .line 123
    .line 124
    invoke-virtual {v4}, Ljava/lang/Long;->longValue()J

    .line 125
    .line 126
    .line 127
    move-result-wide v4

    .line 128
    goto :goto_3

    .line 129
    :cond_3
    const-wide/16 v4, 0x0

    .line 130
    .line 131
    :goto_3
    iget-object v8, v1, Lcm/a;->b:[J

    .line 132
    .line 133
    aput-wide v4, v8, p1

    .line 134
    .line 135
    iget-wide v8, p0, Lcm/d;->l:J

    .line 136
    .line 137
    sub-long/2addr v8, v6

    .line 138
    add-long/2addr v8, v4

    .line 139
    iput-wide v8, p0, Lcm/d;->l:J

    .line 140
    .line 141
    add-int/lit8 p1, p1, 0x1

    .line 142
    .line 143
    goto :goto_1

    .line 144
    :cond_4
    move p1, v3

    .line 145
    :goto_4
    if-ge p1, v2, :cond_5

    .line 146
    .line 147
    iget-object v4, p0, Lcm/d;->t:Lcm/c;

    .line 148
    .line 149
    iget-object v5, v1, Lcm/a;->d:Ljava/util/ArrayList;

    .line 150
    .line 151
    invoke-virtual {v5, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v5

    .line 155
    check-cast v5, Lu01/y;

    .line 156
    .line 157
    invoke-virtual {v4, v5}, Lu01/k;->h(Lu01/y;)V

    .line 158
    .line 159
    .line 160
    add-int/lit8 p1, p1, 0x1

    .line 161
    .line 162
    goto :goto_4

    .line 163
    :cond_5
    const/4 p1, 0x0

    .line 164
    iput-object p1, v1, Lcm/a;->g:La8/b;

    .line 165
    .line 166
    iget-boolean p1, v1, Lcm/a;->f:Z

    .line 167
    .line 168
    if-eqz p1, :cond_6

    .line 169
    .line 170
    invoke-virtual {p0, v1}, Lcm/d;->l(Lcm/a;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 171
    .line 172
    .line 173
    monitor-exit v0

    .line 174
    return-void

    .line 175
    :cond_6
    :try_start_2
    iget p1, p0, Lcm/d;->m:I

    .line 176
    .line 177
    const/4 v2, 0x1

    .line 178
    add-int/2addr p1, v2

    .line 179
    iput p1, p0, Lcm/d;->m:I

    .line 180
    .line 181
    iget-object p1, p0, Lcm/d;->n:Lu01/a0;

    .line 182
    .line 183
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    const/16 v4, 0xa

    .line 187
    .line 188
    const/16 v5, 0x20

    .line 189
    .line 190
    if-nez p2, :cond_8

    .line 191
    .line 192
    iget-boolean p2, v1, Lcm/a;->e:Z

    .line 193
    .line 194
    if-eqz p2, :cond_7

    .line 195
    .line 196
    goto :goto_5

    .line 197
    :cond_7
    iget-object p2, p0, Lcm/d;->i:Ljava/util/LinkedHashMap;

    .line 198
    .line 199
    iget-object v6, v1, Lcm/a;->a:Ljava/lang/String;

    .line 200
    .line 201
    invoke-interface {p2, v6}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    const-string p2, "REMOVE"

    .line 205
    .line 206
    invoke-virtual {p1, p2}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 207
    .line 208
    .line 209
    invoke-virtual {p1, v5}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 210
    .line 211
    .line 212
    iget-object p2, v1, Lcm/a;->a:Ljava/lang/String;

    .line 213
    .line 214
    invoke-virtual {p1, p2}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 215
    .line 216
    .line 217
    invoke-virtual {p1, v4}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 218
    .line 219
    .line 220
    goto :goto_7

    .line 221
    :cond_8
    :goto_5
    iput-boolean v2, v1, Lcm/a;->e:Z

    .line 222
    .line 223
    const-string p2, "CLEAN"

    .line 224
    .line 225
    invoke-virtual {p1, p2}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 226
    .line 227
    .line 228
    invoke-virtual {p1, v5}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 229
    .line 230
    .line 231
    iget-object p2, v1, Lcm/a;->a:Ljava/lang/String;

    .line 232
    .line 233
    invoke-virtual {p1, p2}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 234
    .line 235
    .line 236
    iget-object p2, v1, Lcm/a;->b:[J

    .line 237
    .line 238
    array-length v1, p2

    .line 239
    move v6, v3

    .line 240
    :goto_6
    if-ge v6, v1, :cond_9

    .line 241
    .line 242
    aget-wide v7, p2, v6

    .line 243
    .line 244
    invoke-virtual {p1, v5}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 245
    .line 246
    .line 247
    invoke-virtual {p1, v7, v8}, Lu01/a0;->N(J)Lu01/g;

    .line 248
    .line 249
    .line 250
    add-int/lit8 v6, v6, 0x1

    .line 251
    .line 252
    goto :goto_6

    .line 253
    :cond_9
    invoke-virtual {p1, v4}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 254
    .line 255
    .line 256
    :goto_7
    invoke-virtual {p1}, Lu01/a0;->flush()V

    .line 257
    .line 258
    .line 259
    iget-wide p1, p0, Lcm/d;->l:J

    .line 260
    .line 261
    iget-wide v4, p0, Lcm/d;->e:J

    .line 262
    .line 263
    cmp-long p1, p1, v4

    .line 264
    .line 265
    if-gtz p1, :cond_b

    .line 266
    .line 267
    iget p1, p0, Lcm/d;->m:I

    .line 268
    .line 269
    const/16 p2, 0x7d0

    .line 270
    .line 271
    if-lt p1, p2, :cond_a

    .line 272
    .line 273
    move v3, v2

    .line 274
    :cond_a
    if-eqz v3, :cond_c

    .line 275
    .line 276
    :cond_b
    invoke-virtual {p0}, Lcm/d;->g()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 277
    .line 278
    .line 279
    :cond_c
    monitor-exit v0

    .line 280
    return-void

    .line 281
    :cond_d
    :try_start_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 282
    .line 283
    const-string p1, "Check failed."

    .line 284
    .line 285
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 286
    .line 287
    .line 288
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 289
    :goto_8
    monitor-exit v0

    .line 290
    throw p0
.end method


# virtual methods
.method public final E()V
    .locals 11

    .line 1
    iget-object v0, p0, Lcm/d;->k:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcm/d;->n:Lu01/a0;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {v1}, Lu01/a0;->close()V

    .line 9
    .line 10
    .line 11
    goto :goto_0

    .line 12
    :catchall_0
    move-exception p0

    .line 13
    goto/16 :goto_7

    .line 14
    .line 15
    :cond_0
    :goto_0
    iget-object v1, p0, Lcm/d;->t:Lcm/c;

    .line 16
    .line 17
    iget-object v2, p0, Lcm/d;->g:Lu01/y;

    .line 18
    .line 19
    const/4 v3, 0x0

    .line 20
    invoke-virtual {v1, v2, v3}, Lcm/c;->E(Lu01/y;Z)Lu01/f0;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-static {v1}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    .line 25
    .line 26
    .line 27
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 28
    :try_start_1
    const-string v2, "libcore.io.DiskLruCache"

    .line 29
    .line 30
    invoke-virtual {v1, v2}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 31
    .line 32
    .line 33
    const/16 v2, 0xa

    .line 34
    .line 35
    invoke-virtual {v1, v2}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 36
    .line 37
    .line 38
    const-string v4, "1"

    .line 39
    .line 40
    invoke-virtual {v1, v4}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v1, v2}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 44
    .line 45
    .line 46
    const/4 v4, 0x3

    .line 47
    int-to-long v4, v4

    .line 48
    invoke-virtual {v1, v4, v5}, Lu01/a0;->N(J)Lu01/g;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v1, v2}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 52
    .line 53
    .line 54
    const/4 v4, 0x2

    .line 55
    int-to-long v4, v4

    .line 56
    invoke-virtual {v1, v4, v5}, Lu01/a0;->N(J)Lu01/g;

    .line 57
    .line 58
    .line 59
    invoke-virtual {v1, v2}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 60
    .line 61
    .line 62
    invoke-virtual {v1, v2}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 63
    .line 64
    .line 65
    iget-object v4, p0, Lcm/d;->i:Ljava/util/LinkedHashMap;

    .line 66
    .line 67
    invoke-virtual {v4}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    invoke-interface {v4}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 72
    .line 73
    .line 74
    move-result-object v4

    .line 75
    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 76
    .line 77
    .line 78
    move-result v5

    .line 79
    if-eqz v5, :cond_3

    .line 80
    .line 81
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v5

    .line 85
    check-cast v5, Lcm/a;

    .line 86
    .line 87
    iget-object v6, v5, Lcm/a;->g:La8/b;

    .line 88
    .line 89
    const/16 v7, 0x20

    .line 90
    .line 91
    if-eqz v6, :cond_1

    .line 92
    .line 93
    const-string v6, "DIRTY"

    .line 94
    .line 95
    invoke-virtual {v1, v6}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 96
    .line 97
    .line 98
    invoke-virtual {v1, v7}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 99
    .line 100
    .line 101
    iget-object v5, v5, Lcm/a;->a:Ljava/lang/String;

    .line 102
    .line 103
    invoke-virtual {v1, v5}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 104
    .line 105
    .line 106
    invoke-virtual {v1, v2}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 107
    .line 108
    .line 109
    goto :goto_1

    .line 110
    :catchall_1
    move-exception v2

    .line 111
    goto :goto_3

    .line 112
    :cond_1
    const-string v6, "CLEAN"

    .line 113
    .line 114
    invoke-virtual {v1, v6}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 115
    .line 116
    .line 117
    invoke-virtual {v1, v7}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 118
    .line 119
    .line 120
    iget-object v6, v5, Lcm/a;->a:Ljava/lang/String;

    .line 121
    .line 122
    invoke-virtual {v1, v6}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 123
    .line 124
    .line 125
    iget-object v5, v5, Lcm/a;->b:[J

    .line 126
    .line 127
    array-length v6, v5

    .line 128
    move v8, v3

    .line 129
    :goto_2
    if-ge v8, v6, :cond_2

    .line 130
    .line 131
    aget-wide v9, v5, v8

    .line 132
    .line 133
    invoke-virtual {v1, v7}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 134
    .line 135
    .line 136
    invoke-virtual {v1, v9, v10}, Lu01/a0;->N(J)Lu01/g;

    .line 137
    .line 138
    .line 139
    add-int/lit8 v8, v8, 0x1

    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_2
    invoke-virtual {v1, v2}, Lu01/a0;->writeByte(I)Lu01/g;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 143
    .line 144
    .line 145
    goto :goto_1

    .line 146
    :cond_3
    :try_start_2
    invoke-virtual {v1}, Lu01/a0;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 147
    .line 148
    .line 149
    const/4 v1, 0x0

    .line 150
    goto :goto_5

    .line 151
    :catchall_2
    move-exception v1

    .line 152
    goto :goto_5

    .line 153
    :goto_3
    :try_start_3
    invoke-virtual {v1}, Lu01/a0;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 154
    .line 155
    .line 156
    goto :goto_4

    .line 157
    :catchall_3
    move-exception v1

    .line 158
    :try_start_4
    invoke-static {v2, v1}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 159
    .line 160
    .line 161
    :goto_4
    move-object v1, v2

    .line 162
    :goto_5
    if-nez v1, :cond_5

    .line 163
    .line 164
    iget-object v1, p0, Lcm/d;->t:Lcm/c;

    .line 165
    .line 166
    iget-object v2, p0, Lcm/d;->f:Lu01/y;

    .line 167
    .line 168
    invoke-virtual {v1, v2}, Lu01/k;->j(Lu01/y;)Z

    .line 169
    .line 170
    .line 171
    move-result v1

    .line 172
    if-eqz v1, :cond_4

    .line 173
    .line 174
    iget-object v1, p0, Lcm/d;->t:Lcm/c;

    .line 175
    .line 176
    iget-object v2, p0, Lcm/d;->f:Lu01/y;

    .line 177
    .line 178
    iget-object v4, p0, Lcm/d;->h:Lu01/y;

    .line 179
    .line 180
    invoke-virtual {v1, v2, v4}, Lu01/l;->b(Lu01/y;Lu01/y;)V

    .line 181
    .line 182
    .line 183
    iget-object v1, p0, Lcm/d;->t:Lcm/c;

    .line 184
    .line 185
    iget-object v2, p0, Lcm/d;->g:Lu01/y;

    .line 186
    .line 187
    iget-object v4, p0, Lcm/d;->f:Lu01/y;

    .line 188
    .line 189
    invoke-virtual {v1, v2, v4}, Lu01/l;->b(Lu01/y;Lu01/y;)V

    .line 190
    .line 191
    .line 192
    iget-object v1, p0, Lcm/d;->t:Lcm/c;

    .line 193
    .line 194
    iget-object v2, p0, Lcm/d;->h:Lu01/y;

    .line 195
    .line 196
    invoke-virtual {v1, v2}, Lu01/k;->h(Lu01/y;)V

    .line 197
    .line 198
    .line 199
    goto :goto_6

    .line 200
    :cond_4
    iget-object v1, p0, Lcm/d;->t:Lcm/c;

    .line 201
    .line 202
    iget-object v2, p0, Lcm/d;->g:Lu01/y;

    .line 203
    .line 204
    iget-object v4, p0, Lcm/d;->f:Lu01/y;

    .line 205
    .line 206
    invoke-virtual {v1, v2, v4}, Lu01/l;->b(Lu01/y;Lu01/y;)V

    .line 207
    .line 208
    .line 209
    :goto_6
    iget-object v1, p0, Lcm/d;->t:Lcm/c;

    .line 210
    .line 211
    iget-object v2, p0, Lcm/d;->f:Lu01/y;

    .line 212
    .line 213
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 214
    .line 215
    .line 216
    const-string v4, "file"

    .line 217
    .line 218
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    invoke-virtual {v1, v2}, Lu01/l;->a(Lu01/y;)Lu01/f0;

    .line 222
    .line 223
    .line 224
    move-result-object v1

    .line 225
    new-instance v2, Lcm/e;

    .line 226
    .line 227
    new-instance v4, La2/e;

    .line 228
    .line 229
    const/16 v5, 0xe

    .line 230
    .line 231
    invoke-direct {v4, p0, v5}, La2/e;-><init>(Ljava/lang/Object;I)V

    .line 232
    .line 233
    .line 234
    invoke-direct {v2, v1, v4}, Lcm/e;-><init>(Lu01/f0;La2/e;)V

    .line 235
    .line 236
    .line 237
    invoke-static {v2}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    .line 238
    .line 239
    .line 240
    move-result-object v1

    .line 241
    iput-object v1, p0, Lcm/d;->n:Lu01/a0;

    .line 242
    .line 243
    iput v3, p0, Lcm/d;->m:I

    .line 244
    .line 245
    iput-boolean v3, p0, Lcm/d;->o:Z

    .line 246
    .line 247
    iput-boolean v3, p0, Lcm/d;->s:Z
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 248
    .line 249
    monitor-exit v0

    .line 250
    return-void

    .line 251
    :cond_5
    :try_start_5
    throw v1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 252
    :goto_7
    monitor-exit v0

    .line 253
    throw p0
.end method

.method public final b(Ljava/lang/String;)La8/b;
    .locals 5

    .line 1
    iget-object v0, p0, Lcm/d;->k:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean v1, p0, Lcm/d;->q:Z

    .line 5
    .line 6
    if-nez v1, :cond_7

    .line 7
    .line 8
    invoke-static {p1}, Lcm/d;->B(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lcm/d;->f()V

    .line 12
    .line 13
    .line 14
    iget-object v1, p0, Lcm/d;->i:Ljava/util/LinkedHashMap;

    .line 15
    .line 16
    invoke-virtual {v1, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lcm/a;

    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    if-eqz v1, :cond_0

    .line 24
    .line 25
    iget-object v3, v1, Lcm/a;->g:La8/b;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :catchall_0
    move-exception p0

    .line 29
    goto :goto_2

    .line 30
    :cond_0
    move-object v3, v2

    .line 31
    :goto_0
    if-eqz v3, :cond_1

    .line 32
    .line 33
    monitor-exit v0

    .line 34
    return-object v2

    .line 35
    :cond_1
    if-eqz v1, :cond_2

    .line 36
    .line 37
    :try_start_1
    iget v3, v1, Lcm/a;->h:I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 38
    .line 39
    if-eqz v3, :cond_2

    .line 40
    .line 41
    monitor-exit v0

    .line 42
    return-object v2

    .line 43
    :cond_2
    :try_start_2
    iget-boolean v3, p0, Lcm/d;->r:Z

    .line 44
    .line 45
    if-nez v3, :cond_6

    .line 46
    .line 47
    iget-boolean v3, p0, Lcm/d;->s:Z

    .line 48
    .line 49
    if-eqz v3, :cond_3

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_3
    iget-object v3, p0, Lcm/d;->n:Lu01/a0;

    .line 53
    .line 54
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    const-string v4, "DIRTY"

    .line 58
    .line 59
    invoke-virtual {v3, v4}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 60
    .line 61
    .line 62
    const/16 v4, 0x20

    .line 63
    .line 64
    invoke-virtual {v3, v4}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 65
    .line 66
    .line 67
    invoke-virtual {v3, p1}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 68
    .line 69
    .line 70
    const/16 v4, 0xa

    .line 71
    .line 72
    invoke-virtual {v3, v4}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 73
    .line 74
    .line 75
    invoke-virtual {v3}, Lu01/a0;->flush()V

    .line 76
    .line 77
    .line 78
    iget-boolean v3, p0, Lcm/d;->o:Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 79
    .line 80
    if-eqz v3, :cond_4

    .line 81
    .line 82
    monitor-exit v0

    .line 83
    return-object v2

    .line 84
    :cond_4
    if-nez v1, :cond_5

    .line 85
    .line 86
    :try_start_3
    new-instance v1, Lcm/a;

    .line 87
    .line 88
    invoke-direct {v1, p0, p1}, Lcm/a;-><init>(Lcm/d;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    iget-object v2, p0, Lcm/d;->i:Ljava/util/LinkedHashMap;

    .line 92
    .line 93
    invoke-interface {v2, p1, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    :cond_5
    new-instance p1, La8/b;

    .line 97
    .line 98
    invoke-direct {p1, p0, v1}, La8/b;-><init>(Lcm/d;Lcm/a;)V

    .line 99
    .line 100
    .line 101
    iput-object p1, v1, Lcm/a;->g:La8/b;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 102
    .line 103
    monitor-exit v0

    .line 104
    return-object p1

    .line 105
    :cond_6
    :goto_1
    :try_start_4
    invoke-virtual {p0}, Lcm/d;->g()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 106
    .line 107
    .line 108
    monitor-exit v0

    .line 109
    return-object v2

    .line 110
    :cond_7
    :try_start_5
    const-string p0, "cache is closed"

    .line 111
    .line 112
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 113
    .line 114
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    throw p1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 118
    :goto_2
    monitor-exit v0

    .line 119
    throw p0
.end method

.method public final close()V
    .locals 8

    .line 1
    iget-object v0, p0, Lcm/d;->k:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean v1, p0, Lcm/d;->p:Z

    .line 5
    .line 6
    const/4 v2, 0x1

    .line 7
    if-eqz v1, :cond_3

    .line 8
    .line 9
    iget-boolean v1, p0, Lcm/d;->q:Z

    .line 10
    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    goto :goto_1

    .line 14
    :cond_0
    iget-object v1, p0, Lcm/d;->i:Ljava/util/LinkedHashMap;

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    const/4 v3, 0x0

    .line 21
    new-array v4, v3, [Lcm/a;

    .line 22
    .line 23
    invoke-interface {v1, v4}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    check-cast v1, [Lcm/a;

    .line 28
    .line 29
    array-length v4, v1

    .line 30
    :goto_0
    if-ge v3, v4, :cond_2

    .line 31
    .line 32
    aget-object v5, v1, v3

    .line 33
    .line 34
    iget-object v5, v5, Lcm/a;->g:La8/b;

    .line 35
    .line 36
    if-eqz v5, :cond_1

    .line 37
    .line 38
    iget-object v6, v5, La8/b;->f:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v6, Lcm/a;

    .line 41
    .line 42
    iget-object v7, v6, Lcm/a;->g:La8/b;

    .line 43
    .line 44
    invoke-static {v7, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v5

    .line 48
    if-eqz v5, :cond_1

    .line 49
    .line 50
    iput-boolean v2, v6, Lcm/a;->f:Z

    .line 51
    .line 52
    :cond_1
    add-int/lit8 v3, v3, 0x1

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :catchall_0
    move-exception p0

    .line 56
    goto :goto_2

    .line 57
    :cond_2
    invoke-virtual {p0}, Lcm/d;->q()V

    .line 58
    .line 59
    .line 60
    iget-object v1, p0, Lcm/d;->j:Lpw0/a;

    .line 61
    .line 62
    const/4 v3, 0x0

    .line 63
    invoke-static {v1, v3}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 64
    .line 65
    .line 66
    iget-object v1, p0, Lcm/d;->n:Lu01/a0;

    .line 67
    .line 68
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v1}, Lu01/a0;->close()V

    .line 72
    .line 73
    .line 74
    iput-object v3, p0, Lcm/d;->n:Lu01/a0;

    .line 75
    .line 76
    iput-boolean v2, p0, Lcm/d;->q:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 77
    .line 78
    monitor-exit v0

    .line 79
    return-void

    .line 80
    :cond_3
    :goto_1
    :try_start_1
    iput-boolean v2, p0, Lcm/d;->q:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 81
    .line 82
    monitor-exit v0

    .line 83
    return-void

    .line 84
    :goto_2
    monitor-exit v0

    .line 85
    throw p0
.end method

.method public final d(Ljava/lang/String;)Lcm/b;
    .locals 5

    .line 1
    iget-object v0, p0, Lcm/d;->k:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean v1, p0, Lcm/d;->q:Z

    .line 5
    .line 6
    if-nez v1, :cond_4

    .line 7
    .line 8
    invoke-static {p1}, Lcm/d;->B(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lcm/d;->f()V

    .line 12
    .line 13
    .line 14
    iget-object v1, p0, Lcm/d;->i:Ljava/util/LinkedHashMap;

    .line 15
    .line 16
    invoke-virtual {v1, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Lcm/a;

    .line 21
    .line 22
    if-eqz v1, :cond_3

    .line 23
    .line 24
    invoke-virtual {v1}, Lcm/a;->a()Lcm/b;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    if-nez v1, :cond_0

    .line 29
    .line 30
    goto :goto_2

    .line 31
    :cond_0
    iget v2, p0, Lcm/d;->m:I

    .line 32
    .line 33
    const/4 v3, 0x1

    .line 34
    add-int/2addr v2, v3

    .line 35
    iput v2, p0, Lcm/d;->m:I

    .line 36
    .line 37
    iget-object v2, p0, Lcm/d;->n:Lu01/a0;

    .line 38
    .line 39
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    const-string v4, "READ"

    .line 43
    .line 44
    invoke-virtual {v2, v4}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 45
    .line 46
    .line 47
    const/16 v4, 0x20

    .line 48
    .line 49
    invoke-virtual {v2, v4}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v2, p1}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 53
    .line 54
    .line 55
    const/16 p1, 0xa

    .line 56
    .line 57
    invoke-virtual {v2, p1}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v2}, Lu01/a0;->flush()V

    .line 61
    .line 62
    .line 63
    iget p1, p0, Lcm/d;->m:I

    .line 64
    .line 65
    const/16 v2, 0x7d0

    .line 66
    .line 67
    if-lt p1, v2, :cond_1

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_1
    const/4 v3, 0x0

    .line 71
    :goto_0
    if-eqz v3, :cond_2

    .line 72
    .line 73
    invoke-virtual {p0}, Lcm/d;->g()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 74
    .line 75
    .line 76
    goto :goto_1

    .line 77
    :catchall_0
    move-exception p0

    .line 78
    goto :goto_3

    .line 79
    :cond_2
    :goto_1
    monitor-exit v0

    .line 80
    return-object v1

    .line 81
    :cond_3
    :goto_2
    monitor-exit v0

    .line 82
    const/4 p0, 0x0

    .line 83
    return-object p0

    .line 84
    :cond_4
    :try_start_1
    const-string p0, "cache is closed"

    .line 85
    .line 86
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 87
    .line 88
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 92
    :goto_3
    monitor-exit v0

    .line 93
    throw p0
.end method

.method public final f()V
    .locals 5

    .line 1
    iget-object v0, p0, Lcm/d;->k:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean v1, p0, Lcm/d;->p:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    monitor-exit v0

    .line 9
    return-void

    .line 10
    :cond_0
    :try_start_1
    iget-object v1, p0, Lcm/d;->t:Lcm/c;

    .line 11
    .line 12
    iget-object v2, p0, Lcm/d;->g:Lu01/y;

    .line 13
    .line 14
    invoke-virtual {v1, v2}, Lu01/k;->h(Lu01/y;)V

    .line 15
    .line 16
    .line 17
    iget-object v1, p0, Lcm/d;->t:Lcm/c;

    .line 18
    .line 19
    iget-object v2, p0, Lcm/d;->h:Lu01/y;

    .line 20
    .line 21
    invoke-virtual {v1, v2}, Lu01/k;->j(Lu01/y;)Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_2

    .line 26
    .line 27
    iget-object v1, p0, Lcm/d;->t:Lcm/c;

    .line 28
    .line 29
    iget-object v2, p0, Lcm/d;->f:Lu01/y;

    .line 30
    .line 31
    invoke-virtual {v1, v2}, Lu01/k;->j(Lu01/y;)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_1

    .line 36
    .line 37
    iget-object v1, p0, Lcm/d;->t:Lcm/c;

    .line 38
    .line 39
    iget-object v2, p0, Lcm/d;->h:Lu01/y;

    .line 40
    .line 41
    invoke-virtual {v1, v2}, Lu01/k;->h(Lu01/y;)V

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :catchall_0
    move-exception p0

    .line 46
    goto :goto_2

    .line 47
    :cond_1
    iget-object v1, p0, Lcm/d;->t:Lcm/c;

    .line 48
    .line 49
    iget-object v2, p0, Lcm/d;->h:Lu01/y;

    .line 50
    .line 51
    iget-object v3, p0, Lcm/d;->f:Lu01/y;

    .line 52
    .line 53
    invoke-virtual {v1, v2, v3}, Lu01/l;->b(Lu01/y;Lu01/y;)V

    .line 54
    .line 55
    .line 56
    :cond_2
    :goto_0
    iget-object v1, p0, Lcm/d;->t:Lcm/c;

    .line 57
    .line 58
    iget-object v2, p0, Lcm/d;->f:Lu01/y;

    .line 59
    .line 60
    invoke-virtual {v1, v2}, Lu01/k;->j(Lu01/y;)Z

    .line 61
    .line 62
    .line 63
    move-result v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 64
    const/4 v2, 0x1

    .line 65
    if-eqz v1, :cond_3

    .line 66
    .line 67
    :try_start_2
    invoke-virtual {p0}, Lcm/d;->j()V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p0}, Lcm/d;->h()V

    .line 71
    .line 72
    .line 73
    iput-boolean v2, p0, Lcm/d;->p:Z
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 74
    .line 75
    monitor-exit v0

    .line 76
    return-void

    .line 77
    :catch_0
    const/4 v1, 0x0

    .line 78
    :try_start_3
    invoke-virtual {p0}, Lcm/d;->close()V

    .line 79
    .line 80
    .line 81
    iget-object v3, p0, Lcm/d;->t:Lcm/c;

    .line 82
    .line 83
    iget-object v4, p0, Lcm/d;->d:Lu01/y;

    .line 84
    .line 85
    invoke-static {v3, v4}, Lkp/h8;->b(Lu01/k;Lu01/y;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 86
    .line 87
    .line 88
    :try_start_4
    iput-boolean v1, p0, Lcm/d;->q:Z

    .line 89
    .line 90
    goto :goto_1

    .line 91
    :catchall_1
    move-exception v2

    .line 92
    iput-boolean v1, p0, Lcm/d;->q:Z

    .line 93
    .line 94
    throw v2

    .line 95
    :cond_3
    :goto_1
    invoke-virtual {p0}, Lcm/d;->E()V

    .line 96
    .line 97
    .line 98
    iput-boolean v2, p0, Lcm/d;->p:Z
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 99
    .line 100
    monitor-exit v0

    .line 101
    return-void

    .line 102
    :goto_2
    monitor-exit v0

    .line 103
    throw p0
.end method

.method public final g()V
    .locals 3

    .line 1
    new-instance v0, La10/a;

    .line 2
    .line 3
    const/16 v1, 0x9

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, p0, v2, v1}, La10/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 7
    .line 8
    .line 9
    const/4 v1, 0x3

    .line 10
    iget-object p0, p0, Lcm/d;->j:Lpw0/a;

    .line 11
    .line 12
    invoke-static {p0, v2, v2, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final h()V
    .locals 9

    .line 1
    iget-object v0, p0, Lcm/d;->i:Ljava/util/LinkedHashMap;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    const-wide/16 v1, 0x0

    .line 12
    .line 13
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    if-eqz v3, :cond_3

    .line 18
    .line 19
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    check-cast v3, Lcm/a;

    .line 24
    .line 25
    iget-object v4, v3, Lcm/a;->g:La8/b;

    .line 26
    .line 27
    const/4 v5, 0x2

    .line 28
    const/4 v6, 0x0

    .line 29
    if-nez v4, :cond_1

    .line 30
    .line 31
    :goto_1
    if-ge v6, v5, :cond_0

    .line 32
    .line 33
    iget-object v4, v3, Lcm/a;->b:[J

    .line 34
    .line 35
    aget-wide v7, v4, v6

    .line 36
    .line 37
    add-long/2addr v1, v7

    .line 38
    add-int/lit8 v6, v6, 0x1

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    const/4 v4, 0x0

    .line 42
    iput-object v4, v3, Lcm/a;->g:La8/b;

    .line 43
    .line 44
    :goto_2
    if-ge v6, v5, :cond_2

    .line 45
    .line 46
    iget-object v4, v3, Lcm/a;->c:Ljava/util/ArrayList;

    .line 47
    .line 48
    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v4

    .line 52
    check-cast v4, Lu01/y;

    .line 53
    .line 54
    iget-object v7, p0, Lcm/d;->t:Lcm/c;

    .line 55
    .line 56
    invoke-virtual {v7, v4}, Lu01/k;->h(Lu01/y;)V

    .line 57
    .line 58
    .line 59
    iget-object v4, v3, Lcm/a;->d:Ljava/util/ArrayList;

    .line 60
    .line 61
    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v4

    .line 65
    check-cast v4, Lu01/y;

    .line 66
    .line 67
    invoke-virtual {v7, v4}, Lu01/k;->h(Lu01/y;)V

    .line 68
    .line 69
    .line 70
    add-int/lit8 v6, v6, 0x1

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_2
    invoke-interface {v0}, Ljava/util/Iterator;->remove()V

    .line 74
    .line 75
    .line 76
    goto :goto_0

    .line 77
    :cond_3
    iput-wide v1, p0, Lcm/d;->l:J

    .line 78
    .line 79
    return-void
.end method

.method public final j()V
    .locals 13

    .line 1
    const-string v0, ", "

    .line 2
    .line 3
    const-string v1, "unexpected journal header: ["

    .line 4
    .line 5
    iget-object v2, p0, Lcm/d;->t:Lcm/c;

    .line 6
    .line 7
    iget-object v3, p0, Lcm/d;->f:Lu01/y;

    .line 8
    .line 9
    invoke-virtual {v2, v3}, Lu01/l;->H(Lu01/y;)Lu01/h0;

    .line 10
    .line 11
    .line 12
    move-result-object v4

    .line 13
    invoke-static {v4}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 14
    .line 15
    .line 16
    move-result-object v4

    .line 17
    const-wide v5, 0x7fffffffffffffffL

    .line 18
    .line 19
    .line 20
    .line 21
    .line 22
    :try_start_0
    invoke-virtual {v4, v5, v6}, Lu01/b0;->x(J)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v7

    .line 26
    invoke-virtual {v4, v5, v6}, Lu01/b0;->x(J)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v8

    .line 30
    invoke-virtual {v4, v5, v6}, Lu01/b0;->x(J)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v9

    .line 34
    invoke-virtual {v4, v5, v6}, Lu01/b0;->x(J)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v10

    .line 38
    invoke-virtual {v4, v5, v6}, Lu01/b0;->x(J)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v11

    .line 42
    const-string v12, "libcore.io.DiskLruCache"

    .line 43
    .line 44
    invoke-virtual {v12, v7}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v12

    .line 48
    if-eqz v12, :cond_1

    .line 49
    .line 50
    const-string v12, "1"

    .line 51
    .line 52
    invoke-virtual {v12, v8}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v12

    .line 56
    if-eqz v12, :cond_1

    .line 57
    .line 58
    const/4 v12, 0x3

    .line 59
    invoke-static {v12}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v12

    .line 63
    invoke-static {v12, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v12

    .line 67
    if-eqz v12, :cond_1

    .line 68
    .line 69
    const/4 v12, 0x2

    .line 70
    invoke-static {v12}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v12

    .line 74
    invoke-static {v12, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v12

    .line 78
    if-eqz v12, :cond_1

    .line 79
    .line 80
    invoke-virtual {v11}, Ljava/lang/String;->length()I

    .line 81
    .line 82
    .line 83
    move-result v12
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 84
    if-gtz v12, :cond_1

    .line 85
    .line 86
    const/4 v0, 0x0

    .line 87
    :goto_0
    :try_start_1
    invoke-virtual {v4, v5, v6}, Lu01/b0;->x(J)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    invoke-virtual {p0, v1}, Lcm/d;->k(Ljava/lang/String;)V
    :try_end_1
    .catch Ljava/io/EOFException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 92
    .line 93
    .line 94
    add-int/lit8 v0, v0, 0x1

    .line 95
    .line 96
    goto :goto_0

    .line 97
    :catchall_0
    move-exception p0

    .line 98
    goto :goto_2

    .line 99
    :catch_0
    :try_start_2
    iget-object v1, p0, Lcm/d;->i:Ljava/util/LinkedHashMap;

    .line 100
    .line 101
    invoke-interface {v1}, Ljava/util/Map;->size()I

    .line 102
    .line 103
    .line 104
    move-result v1

    .line 105
    sub-int/2addr v0, v1

    .line 106
    iput v0, p0, Lcm/d;->m:I

    .line 107
    .line 108
    invoke-virtual {v4}, Lu01/b0;->Z()Z

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    if-nez v0, :cond_0

    .line 113
    .line 114
    invoke-virtual {p0}, Lcm/d;->E()V

    .line 115
    .line 116
    .line 117
    goto :goto_1

    .line 118
    :cond_0
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 119
    .line 120
    .line 121
    const-string v0, "file"

    .line 122
    .line 123
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v2, v3}, Lu01/l;->a(Lu01/y;)Lu01/f0;

    .line 127
    .line 128
    .line 129
    move-result-object v0

    .line 130
    new-instance v1, Lcm/e;

    .line 131
    .line 132
    new-instance v2, La2/e;

    .line 133
    .line 134
    const/16 v3, 0xe

    .line 135
    .line 136
    invoke-direct {v2, p0, v3}, La2/e;-><init>(Ljava/lang/Object;I)V

    .line 137
    .line 138
    .line 139
    invoke-direct {v1, v0, v2}, Lcm/e;-><init>(Lu01/f0;La2/e;)V

    .line 140
    .line 141
    .line 142
    invoke-static {v1}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    iput-object v0, p0, Lcm/d;->n:Lu01/a0;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 147
    .line 148
    :goto_1
    :try_start_3
    invoke-virtual {v4}, Lu01/b0;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 149
    .line 150
    .line 151
    const/4 p0, 0x0

    .line 152
    goto :goto_3

    .line 153
    :catchall_1
    move-exception p0

    .line 154
    goto :goto_3

    .line 155
    :cond_1
    :try_start_4
    new-instance p0, Ljava/io/IOException;

    .line 156
    .line 157
    new-instance v2, Ljava/lang/StringBuilder;

    .line 158
    .line 159
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v2, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 163
    .line 164
    .line 165
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 166
    .line 167
    .line 168
    invoke-virtual {v2, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 169
    .line 170
    .line 171
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 172
    .line 173
    .line 174
    invoke-virtual {v2, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 175
    .line 176
    .line 177
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 178
    .line 179
    .line 180
    invoke-virtual {v2, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 181
    .line 182
    .line 183
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 184
    .line 185
    .line 186
    invoke-virtual {v2, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 187
    .line 188
    .line 189
    const/16 v0, 0x5d

    .line 190
    .line 191
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 192
    .line 193
    .line 194
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object v0

    .line 198
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    throw p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 202
    :goto_2
    :try_start_5
    invoke-virtual {v4}, Lu01/b0;->close()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 203
    .line 204
    .line 205
    goto :goto_3

    .line 206
    :catchall_2
    move-exception v0

    .line 207
    invoke-static {p0, v0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 208
    .line 209
    .line 210
    :goto_3
    if-nez p0, :cond_2

    .line 211
    .line 212
    return-void

    .line 213
    :cond_2
    throw p0
.end method

.method public final k(Ljava/lang/String;)V
    .locals 11

    .line 1
    const/16 v0, 0x20

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x6

    .line 5
    invoke-static {p1, v0, v1, v2}, Lly0/p;->J(Ljava/lang/CharSequence;CII)I

    .line 6
    .line 7
    .line 8
    move-result v3

    .line 9
    const-string v4, "unexpected journal line: "

    .line 10
    .line 11
    const/4 v5, -0x1

    .line 12
    if-eq v3, v5, :cond_8

    .line 13
    .line 14
    add-int/lit8 v6, v3, 0x1

    .line 15
    .line 16
    const/4 v7, 0x4

    .line 17
    invoke-static {p1, v0, v6, v7}, Lly0/p;->J(Ljava/lang/CharSequence;CII)I

    .line 18
    .line 19
    .line 20
    move-result v8

    .line 21
    iget-object v9, p0, Lcm/d;->i:Ljava/util/LinkedHashMap;

    .line 22
    .line 23
    const-string v10, "substring(...)"

    .line 24
    .line 25
    if-ne v8, v5, :cond_0

    .line 26
    .line 27
    invoke-virtual {p1, v6}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v6

    .line 31
    invoke-static {v6, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    if-ne v3, v2, :cond_1

    .line 35
    .line 36
    const-string v2, "REMOVE"

    .line 37
    .line 38
    invoke-static {p1, v2, v1}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    if-eqz v2, :cond_1

    .line 43
    .line 44
    invoke-interface {v9, v6}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :cond_0
    invoke-virtual {p1, v6, v8}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v6

    .line 52
    invoke-static {v6, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    :cond_1
    invoke-virtual {v9, v6}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    if-nez v2, :cond_2

    .line 60
    .line 61
    new-instance v2, Lcm/a;

    .line 62
    .line 63
    invoke-direct {v2, p0, v6}, Lcm/a;-><init>(Lcm/d;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    invoke-interface {v9, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    :cond_2
    check-cast v2, Lcm/a;

    .line 70
    .line 71
    const/4 v6, 0x5

    .line 72
    if-eq v8, v5, :cond_4

    .line 73
    .line 74
    if-ne v3, v6, :cond_4

    .line 75
    .line 76
    const-string v9, "CLEAN"

    .line 77
    .line 78
    invoke-static {p1, v9, v1}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 79
    .line 80
    .line 81
    move-result v9

    .line 82
    if-eqz v9, :cond_4

    .line 83
    .line 84
    const/4 p0, 0x1

    .line 85
    add-int/2addr v8, p0

    .line 86
    invoke-virtual {p1, v8}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    invoke-static {p1, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    new-array v3, p0, [C

    .line 94
    .line 95
    aput-char v0, v3, v1

    .line 96
    .line 97
    invoke-static {p1, v3}, Lly0/p;->X(Ljava/lang/CharSequence;[C)Ljava/util/List;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    iput-boolean p0, v2, Lcm/a;->e:Z

    .line 102
    .line 103
    const/4 p0, 0x0

    .line 104
    iput-object p0, v2, Lcm/a;->g:La8/b;

    .line 105
    .line 106
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 107
    .line 108
    .line 109
    move-result p0

    .line 110
    const/4 v0, 0x2

    .line 111
    if-ne p0, v0, :cond_3

    .line 112
    .line 113
    :try_start_0
    move-object p0, p1

    .line 114
    check-cast p0, Ljava/util/Collection;

    .line 115
    .line 116
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 117
    .line 118
    .line 119
    move-result p0

    .line 120
    :goto_0
    if-ge v1, p0, :cond_6

    .line 121
    .line 122
    iget-object v0, v2, Lcm/a;->b:[J

    .line 123
    .line 124
    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v3

    .line 128
    check-cast v3, Ljava/lang/String;

    .line 129
    .line 130
    invoke-static {v3}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 131
    .line 132
    .line 133
    move-result-wide v5

    .line 134
    aput-wide v5, v0, v1
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 135
    .line 136
    add-int/lit8 v1, v1, 0x1

    .line 137
    .line 138
    goto :goto_0

    .line 139
    :catch_0
    new-instance p0, Ljava/io/IOException;

    .line 140
    .line 141
    new-instance v0, Ljava/lang/StringBuilder;

    .line 142
    .line 143
    invoke-direct {v0, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 147
    .line 148
    .line 149
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    throw p0

    .line 157
    :cond_3
    new-instance p0, Ljava/io/IOException;

    .line 158
    .line 159
    new-instance v0, Ljava/lang/StringBuilder;

    .line 160
    .line 161
    invoke-direct {v0, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 165
    .line 166
    .line 167
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object p1

    .line 171
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    throw p0

    .line 175
    :cond_4
    if-ne v8, v5, :cond_5

    .line 176
    .line 177
    if-ne v3, v6, :cond_5

    .line 178
    .line 179
    const-string v0, "DIRTY"

    .line 180
    .line 181
    invoke-static {p1, v0, v1}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 182
    .line 183
    .line 184
    move-result v0

    .line 185
    if-eqz v0, :cond_5

    .line 186
    .line 187
    new-instance p1, La8/b;

    .line 188
    .line 189
    invoke-direct {p1, p0, v2}, La8/b;-><init>(Lcm/d;Lcm/a;)V

    .line 190
    .line 191
    .line 192
    iput-object p1, v2, Lcm/a;->g:La8/b;

    .line 193
    .line 194
    return-void

    .line 195
    :cond_5
    if-ne v8, v5, :cond_7

    .line 196
    .line 197
    if-ne v3, v7, :cond_7

    .line 198
    .line 199
    const-string p0, "READ"

    .line 200
    .line 201
    invoke-static {p1, p0, v1}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 202
    .line 203
    .line 204
    move-result p0

    .line 205
    if-eqz p0, :cond_7

    .line 206
    .line 207
    :cond_6
    return-void

    .line 208
    :cond_7
    new-instance p0, Ljava/io/IOException;

    .line 209
    .line 210
    invoke-virtual {v4, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object p1

    .line 214
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    throw p0

    .line 218
    :cond_8
    new-instance p0, Ljava/io/IOException;

    .line 219
    .line 220
    invoke-virtual {v4, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object p1

    .line 224
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    throw p0
.end method

.method public final l(Lcm/a;)V
    .locals 10

    .line 1
    iget v0, p1, Lcm/a;->h:I

    .line 2
    .line 3
    iget-object v1, p1, Lcm/a;->a:Ljava/lang/String;

    .line 4
    .line 5
    const/16 v2, 0xa

    .line 6
    .line 7
    const/16 v3, 0x20

    .line 8
    .line 9
    if-lez v0, :cond_0

    .line 10
    .line 11
    iget-object v0, p0, Lcm/d;->n:Lu01/a0;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const-string v4, "DIRTY"

    .line 16
    .line 17
    invoke-virtual {v0, v4}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0, v3}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, v1}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, v2}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Lu01/a0;->flush()V

    .line 30
    .line 31
    .line 32
    :cond_0
    iget v0, p1, Lcm/a;->h:I

    .line 33
    .line 34
    const/4 v4, 0x1

    .line 35
    if-gtz v0, :cond_5

    .line 36
    .line 37
    iget-object v0, p1, Lcm/a;->g:La8/b;

    .line 38
    .line 39
    if-eqz v0, :cond_1

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    const/4 v0, 0x0

    .line 43
    :goto_0
    const/4 v5, 0x2

    .line 44
    if-ge v0, v5, :cond_2

    .line 45
    .line 46
    iget-object v5, p1, Lcm/a;->c:Ljava/util/ArrayList;

    .line 47
    .line 48
    invoke-virtual {v5, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v5

    .line 52
    check-cast v5, Lu01/y;

    .line 53
    .line 54
    iget-object v6, p0, Lcm/d;->t:Lcm/c;

    .line 55
    .line 56
    invoke-virtual {v6, v5}, Lu01/k;->h(Lu01/y;)V

    .line 57
    .line 58
    .line 59
    iget-wide v5, p0, Lcm/d;->l:J

    .line 60
    .line 61
    iget-object v7, p1, Lcm/a;->b:[J

    .line 62
    .line 63
    aget-wide v8, v7, v0

    .line 64
    .line 65
    sub-long/2addr v5, v8

    .line 66
    iput-wide v5, p0, Lcm/d;->l:J

    .line 67
    .line 68
    const-wide/16 v5, 0x0

    .line 69
    .line 70
    aput-wide v5, v7, v0

    .line 71
    .line 72
    add-int/lit8 v0, v0, 0x1

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_2
    iget p1, p0, Lcm/d;->m:I

    .line 76
    .line 77
    add-int/2addr p1, v4

    .line 78
    iput p1, p0, Lcm/d;->m:I

    .line 79
    .line 80
    iget-object p1, p0, Lcm/d;->n:Lu01/a0;

    .line 81
    .line 82
    if-eqz p1, :cond_3

    .line 83
    .line 84
    const-string v0, "REMOVE"

    .line 85
    .line 86
    invoke-virtual {p1, v0}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 87
    .line 88
    .line 89
    invoke-virtual {p1, v3}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 90
    .line 91
    .line 92
    invoke-virtual {p1, v1}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 93
    .line 94
    .line 95
    invoke-virtual {p1, v2}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 96
    .line 97
    .line 98
    invoke-virtual {p1}, Lu01/a0;->flush()V

    .line 99
    .line 100
    .line 101
    :cond_3
    iget-object p1, p0, Lcm/d;->i:Ljava/util/LinkedHashMap;

    .line 102
    .line 103
    invoke-interface {p1, v1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    iget p1, p0, Lcm/d;->m:I

    .line 107
    .line 108
    const/16 v0, 0x7d0

    .line 109
    .line 110
    if-lt p1, v0, :cond_4

    .line 111
    .line 112
    invoke-virtual {p0}, Lcm/d;->g()V

    .line 113
    .line 114
    .line 115
    :cond_4
    return-void

    .line 116
    :cond_5
    :goto_1
    iput-boolean v4, p1, Lcm/a;->f:Z

    .line 117
    .line 118
    return-void
.end method

.method public final q()V
    .locals 4

    .line 1
    :goto_0
    iget-wide v0, p0, Lcm/d;->l:J

    .line 2
    .line 3
    iget-wide v2, p0, Lcm/d;->e:J

    .line 4
    .line 5
    cmp-long v0, v0, v2

    .line 6
    .line 7
    if-lez v0, :cond_2

    .line 8
    .line 9
    iget-object v0, p0, Lcm/d;->i:Ljava/util/LinkedHashMap;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    check-cast v1, Lcm/a;

    .line 30
    .line 31
    iget-boolean v2, v1, Lcm/a;->f:Z

    .line 32
    .line 33
    if-nez v2, :cond_0

    .line 34
    .line 35
    invoke-virtual {p0, v1}, Lcm/d;->l(Lcm/a;)V

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    return-void

    .line 40
    :cond_2
    const/4 v0, 0x0

    .line 41
    iput-boolean v0, p0, Lcm/d;->r:Z

    .line 42
    .line 43
    return-void
.end method
