.class public final Lk01/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Li01/d;


# static fields
.field public static final g:Ljava/util/List;

.field public static final h:Ljava/util/List;


# instance fields
.field public final a:Lh01/p;

.field public final b:Li01/f;

.field public final c:Lk01/p;

.field public volatile d:Lk01/x;

.field public final e:Ld01/i0;

.field public volatile f:Z


# direct methods
.method static constructor <clinit>()V
    .locals 12

    .line 1
    const-string v10, ":scheme"

    .line 2
    .line 3
    const-string v11, ":authority"

    .line 4
    .line 5
    const-string v0, "connection"

    .line 6
    .line 7
    const-string v1, "host"

    .line 8
    .line 9
    const-string v2, "keep-alive"

    .line 10
    .line 11
    const-string v3, "proxy-connection"

    .line 12
    .line 13
    const-string v4, "te"

    .line 14
    .line 15
    const-string v5, "transfer-encoding"

    .line 16
    .line 17
    const-string v6, "encoding"

    .line 18
    .line 19
    const-string v7, "upgrade"

    .line 20
    .line 21
    const-string v8, ":method"

    .line 22
    .line 23
    const-string v9, ":path"

    .line 24
    .line 25
    filled-new-array/range {v0 .. v11}, [Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-static {v0}, Le01/g;->k([Ljava/lang/Object;)Ljava/util/List;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    sput-object v0, Lk01/q;->g:Ljava/util/List;

    .line 34
    .line 35
    const-string v7, "encoding"

    .line 36
    .line 37
    const-string v8, "upgrade"

    .line 38
    .line 39
    const-string v1, "connection"

    .line 40
    .line 41
    const-string v2, "host"

    .line 42
    .line 43
    const-string v3, "keep-alive"

    .line 44
    .line 45
    const-string v4, "proxy-connection"

    .line 46
    .line 47
    const-string v5, "te"

    .line 48
    .line 49
    const-string v6, "transfer-encoding"

    .line 50
    .line 51
    filled-new-array/range {v1 .. v8}, [Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    invoke-static {v0}, Le01/g;->k([Ljava/lang/Object;)Ljava/util/List;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    sput-object v0, Lk01/q;->h:Ljava/util/List;

    .line 60
    .line 61
    return-void
.end method

.method public constructor <init>(Ld01/h0;Lh01/p;Li01/f;Lk01/p;)V
    .locals 1

    .line 1
    const-string v0, "http2Connection"

    .line 2
    .line 3
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p2, p0, Lk01/q;->a:Lh01/p;

    .line 10
    .line 11
    iput-object p3, p0, Lk01/q;->b:Li01/f;

    .line 12
    .line 13
    iput-object p4, p0, Lk01/q;->c:Lk01/p;

    .line 14
    .line 15
    iget-object p1, p1, Ld01/h0;->s:Ljava/util/List;

    .line 16
    .line 17
    sget-object p2, Ld01/i0;->j:Ld01/i0;

    .line 18
    .line 19
    invoke-interface {p1, p2}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    if-eqz p1, :cond_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    sget-object p2, Ld01/i0;->i:Ld01/i0;

    .line 27
    .line 28
    :goto_0
    iput-object p2, p0, Lk01/q;->e:Ld01/i0;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 0

    .line 1
    iget-object p0, p0, Lk01/q;->d:Lk01/x;

    .line 2
    .line 3
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lk01/x;->l:Lk01/u;

    .line 7
    .line 8
    invoke-virtual {p0}, Lk01/u;->close()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final b(Ld01/t0;)J
    .locals 0

    .line 1
    invoke-static {p1}, Li01/e;->a(Ld01/t0;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const-wide/16 p0, 0x0

    .line 8
    .line 9
    return-wide p0

    .line 10
    :cond_0
    invoke-static {p1}, Le01/g;->e(Ld01/t0;)J

    .line 11
    .line 12
    .line 13
    move-result-wide p0

    .line 14
    return-wide p0
.end method

.method public final c(Ld01/t0;)Lu01/h0;
    .locals 0

    .line 1
    iget-object p0, p0, Lk01/q;->d:Lk01/x;

    .line 2
    .line 3
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lk01/x;->k:Lk01/v;

    .line 7
    .line 8
    return-object p0
.end method

.method public final cancel()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lk01/q;->f:Z

    .line 3
    .line 4
    iget-object p0, p0, Lk01/q;->d:Lk01/x;

    .line 5
    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    sget-object v0, Lk01/b;->k:Lk01/b;

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Lk01/x;->f(Lk01/b;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    return-void
.end method

.method public final d()Z
    .locals 4

    .line 1
    iget-object p0, p0, Lk01/q;->d:Lk01/x;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p0, :cond_2

    .line 5
    .line 6
    monitor-enter p0

    .line 7
    :try_start_0
    iget-object v1, p0, Lk01/x;->k:Lk01/v;

    .line 8
    .line 9
    iget-boolean v2, v1, Lk01/v;->e:Z

    .line 10
    .line 11
    const/4 v3, 0x1

    .line 12
    if-eqz v2, :cond_0

    .line 13
    .line 14
    iget-object v1, v1, Lk01/v;->g:Lu01/f;

    .line 15
    .line 16
    invoke-virtual {v1}, Lu01/f;->Z()Z

    .line 17
    .line 18
    .line 19
    move-result v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    move v1, v3

    .line 23
    goto :goto_0

    .line 24
    :catchall_0
    move-exception v0

    .line 25
    goto :goto_1

    .line 26
    :cond_0
    move v1, v0

    .line 27
    :goto_0
    monitor-exit p0

    .line 28
    if-ne v1, v3, :cond_1

    .line 29
    .line 30
    return v3

    .line 31
    :cond_1
    return v0

    .line 32
    :goto_1
    monitor-exit p0

    .line 33
    throw v0

    .line 34
    :cond_2
    return v0
.end method

.method public final e(Z)Ld01/s0;
    .locals 9

    .line 1
    iget-object v0, p0, Lk01/q;->d:Lk01/x;

    .line 2
    .line 3
    if-eqz v0, :cond_f

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :cond_0
    :goto_0
    :try_start_0
    iget-object v1, v0, Lk01/x;->i:Ljava/util/ArrayDeque;

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    const/4 v2, 0x0

    .line 13
    if-eqz v1, :cond_7

    .line 14
    .line 15
    invoke-virtual {v0}, Lk01/x;->g()Lk01/b;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    if-nez v1, :cond_7

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    if-nez p1, :cond_3

    .line 23
    .line 24
    iget-object v3, v0, Lk01/x;->e:Lk01/p;

    .line 25
    .line 26
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    iget-object v3, v0, Lk01/x;->l:Lk01/u;

    .line 30
    .line 31
    iget-boolean v4, v3, Lk01/u;->f:Z

    .line 32
    .line 33
    if-nez v4, :cond_2

    .line 34
    .line 35
    iget-boolean v3, v3, Lk01/u;->d:Z

    .line 36
    .line 37
    if-eqz v3, :cond_1

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    move v3, v2

    .line 41
    goto :goto_2

    .line 42
    :cond_2
    :goto_1
    move v3, v1

    .line 43
    :goto_2
    if-eqz v3, :cond_4

    .line 44
    .line 45
    :cond_3
    move v2, v1

    .line 46
    :cond_4
    if-eqz v2, :cond_5

    .line 47
    .line 48
    iget-object v1, v0, Lk01/x;->m:Lk01/w;

    .line 49
    .line 50
    invoke-virtual {v1}, Lu01/d;->h()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 51
    .line 52
    .line 53
    goto :goto_3

    .line 54
    :catchall_0
    move-exception p0

    .line 55
    goto/16 :goto_8

    .line 56
    .line 57
    :cond_5
    :goto_3
    :try_start_1
    invoke-virtual {v0}, Ljava/lang/Object;->wait()V
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 58
    .line 59
    .line 60
    if-eqz v2, :cond_0

    .line 61
    .line 62
    :try_start_2
    iget-object v1, v0, Lk01/x;->m:Lk01/w;

    .line 63
    .line 64
    invoke-virtual {v1}, Lk01/w;->l()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :catchall_1
    move-exception p0

    .line 69
    goto :goto_4

    .line 70
    :catch_0
    :try_start_3
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    invoke-virtual {p0}, Ljava/lang/Thread;->interrupt()V

    .line 75
    .line 76
    .line 77
    new-instance p0, Ljava/io/InterruptedIOException;

    .line 78
    .line 79
    invoke-direct {p0}, Ljava/io/InterruptedIOException;-><init>()V

    .line 80
    .line 81
    .line 82
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 83
    :goto_4
    if-eqz v2, :cond_6

    .line 84
    .line 85
    :try_start_4
    iget-object p1, v0, Lk01/x;->m:Lk01/w;

    .line 86
    .line 87
    invoke-virtual {p1}, Lk01/w;->l()V

    .line 88
    .line 89
    .line 90
    :cond_6
    throw p0

    .line 91
    :cond_7
    iget-object v1, v0, Lk01/x;->i:Ljava/util/ArrayDeque;

    .line 92
    .line 93
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    if-nez v1, :cond_d

    .line 98
    .line 99
    iget-object v1, v0, Lk01/x;->i:Ljava/util/ArrayDeque;

    .line 100
    .line 101
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->removeFirst()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    const-string v3, "removeFirst(...)"

    .line 106
    .line 107
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    check-cast v1, Ld01/y;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 111
    .line 112
    monitor-exit v0

    .line 113
    iget-object p0, p0, Lk01/q;->e:Ld01/i0;

    .line 114
    .line 115
    const-string v0, "protocol"

    .line 116
    .line 117
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    new-instance v0, Ld01/x;

    .line 121
    .line 122
    const/4 v3, 0x0

    .line 123
    const/4 v4, 0x0

    .line 124
    invoke-direct {v0, v4, v3}, Ld01/x;-><init>(BI)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v1}, Ld01/y;->size()I

    .line 128
    .line 129
    .line 130
    move-result v3

    .line 131
    const/4 v4, 0x0

    .line 132
    move-object v5, v4

    .line 133
    :goto_5
    if-ge v2, v3, :cond_a

    .line 134
    .line 135
    invoke-virtual {v1, v2}, Ld01/y;->e(I)Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object v6

    .line 139
    invoke-virtual {v1, v2}, Ld01/y;->k(I)Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object v7

    .line 143
    const-string v8, ":status"

    .line 144
    .line 145
    invoke-virtual {v6, v8}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    move-result v8

    .line 149
    if-eqz v8, :cond_8

    .line 150
    .line 151
    const-string v5, "HTTP/1.1 "

    .line 152
    .line 153
    invoke-virtual {v5, v7}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object v5

    .line 157
    invoke-static {v5}, Llp/m1;->b(Ljava/lang/String;)Lbb/g0;

    .line 158
    .line 159
    .line 160
    move-result-object v5

    .line 161
    goto :goto_6

    .line 162
    :cond_8
    sget-object v8, Lk01/q;->h:Ljava/util/List;

    .line 163
    .line 164
    invoke-interface {v8, v6}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 165
    .line 166
    .line 167
    move-result v8

    .line 168
    if-nez v8, :cond_9

    .line 169
    .line 170
    invoke-virtual {v0, v6, v7}, Ld01/x;->f(Ljava/lang/String;Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    :cond_9
    :goto_6
    add-int/lit8 v2, v2, 0x1

    .line 174
    .line 175
    goto :goto_5

    .line 176
    :cond_a
    if-eqz v5, :cond_c

    .line 177
    .line 178
    new-instance v1, Ld01/s0;

    .line 179
    .line 180
    invoke-direct {v1}, Ld01/s0;-><init>()V

    .line 181
    .line 182
    .line 183
    iput-object p0, v1, Ld01/s0;->b:Ld01/i0;

    .line 184
    .line 185
    iget p0, v5, Lbb/g0;->e:I

    .line 186
    .line 187
    iput p0, v1, Ld01/s0;->c:I

    .line 188
    .line 189
    iget-object p0, v5, Lbb/g0;->g:Ljava/lang/Object;

    .line 190
    .line 191
    check-cast p0, Ljava/lang/String;

    .line 192
    .line 193
    iput-object p0, v1, Ld01/s0;->d:Ljava/lang/String;

    .line 194
    .line 195
    invoke-virtual {v0}, Ld01/x;->j()Ld01/y;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    invoke-virtual {v1, p0}, Ld01/s0;->c(Ld01/y;)V

    .line 200
    .line 201
    .line 202
    if-eqz p1, :cond_b

    .line 203
    .line 204
    iget p0, v1, Ld01/s0;->c:I

    .line 205
    .line 206
    const/16 p1, 0x64

    .line 207
    .line 208
    if-ne p0, p1, :cond_b

    .line 209
    .line 210
    return-object v4

    .line 211
    :cond_b
    return-object v1

    .line 212
    :cond_c
    new-instance p0, Ljava/net/ProtocolException;

    .line 213
    .line 214
    const-string p1, "Expected \':status\' header not present"

    .line 215
    .line 216
    invoke-direct {p0, p1}, Ljava/net/ProtocolException;-><init>(Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    throw p0

    .line 220
    :cond_d
    :try_start_5
    iget-object p0, v0, Lk01/x;->p:Ljava/io/IOException;

    .line 221
    .line 222
    if-eqz p0, :cond_e

    .line 223
    .line 224
    goto :goto_7

    .line 225
    :cond_e
    new-instance p0, Lk01/c0;

    .line 226
    .line 227
    invoke-virtual {v0}, Lk01/x;->g()Lk01/b;

    .line 228
    .line 229
    .line 230
    move-result-object p1

    .line 231
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    invoke-direct {p0, p1}, Lk01/c0;-><init>(Lk01/b;)V

    .line 235
    .line 236
    .line 237
    :goto_7
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 238
    :goto_8
    monitor-exit v0

    .line 239
    throw p0

    .line 240
    :cond_f
    new-instance p0, Ljava/io/IOException;

    .line 241
    .line 242
    const-string p1, "stream wasn\'t created"

    .line 243
    .line 244
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    throw p0
.end method

.method public final f()Ld01/y;
    .locals 2

    .line 1
    iget-object p0, p0, Lk01/q;->d:Lk01/x;

    .line 2
    .line 3
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    monitor-enter p0

    .line 7
    :try_start_0
    iget-object v0, p0, Lk01/x;->k:Lk01/v;

    .line 8
    .line 9
    iget-boolean v1, v0, Lk01/v;->e:Z

    .line 10
    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    iget-object v0, v0, Lk01/v;->f:Lu01/f;

    .line 14
    .line 15
    invoke-virtual {v0}, Lu01/f;->Z()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    iget-object v0, p0, Lk01/x;->k:Lk01/v;

    .line 22
    .line 23
    iget-object v0, v0, Lk01/v;->g:Lu01/f;

    .line 24
    .line 25
    invoke-virtual {v0}, Lu01/f;->Z()Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    iget-object v0, p0, Lk01/x;->k:Lk01/v;

    .line 32
    .line 33
    iget-object v0, v0, Lk01/v;->h:Ld01/y;

    .line 34
    .line 35
    if-nez v0, :cond_0

    .line 36
    .line 37
    sget-object v0, Ld01/y;->e:Ld01/y;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :catchall_0
    move-exception v0

    .line 41
    goto :goto_2

    .line 42
    :cond_0
    :goto_0
    monitor-exit p0

    .line 43
    return-object v0

    .line 44
    :cond_1
    :try_start_1
    invoke-virtual {p0}, Lk01/x;->g()Lk01/b;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    if-eqz v0, :cond_3

    .line 49
    .line 50
    iget-object v0, p0, Lk01/x;->p:Ljava/io/IOException;

    .line 51
    .line 52
    if-eqz v0, :cond_2

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_2
    new-instance v0, Lk01/c0;

    .line 56
    .line 57
    invoke-virtual {p0}, Lk01/x;->g()Lk01/b;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    invoke-direct {v0, v1}, Lk01/c0;-><init>(Lk01/b;)V

    .line 65
    .line 66
    .line 67
    :goto_1
    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 68
    :cond_3
    monitor-exit p0

    .line 69
    const/4 p0, 0x0

    .line 70
    return-object p0

    .line 71
    :goto_2
    monitor-exit p0

    .line 72
    throw v0
.end method

.method public final g()V
    .locals 0

    .line 1
    iget-object p0, p0, Lk01/q;->c:Lk01/p;

    .line 2
    .line 3
    invoke-virtual {p0}, Lk01/p;->flush()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final h()Lu01/g0;
    .locals 0

    .line 1
    iget-object p0, p0, Lk01/q;->d:Lk01/x;

    .line 2
    .line 3
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public final i()Li01/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lk01/q;->a:Lh01/p;

    .line 2
    .line 3
    return-object p0
.end method

.method public final j(Ld01/k0;J)Lu01/f0;
    .locals 0

    .line 1
    const-string p2, "request"

    .line 2
    .line 3
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lk01/q;->d:Lk01/x;

    .line 7
    .line 8
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lk01/x;->l:Lk01/u;

    .line 12
    .line 13
    return-object p0
.end method

.method public final k(Ld01/k0;)V
    .locals 14

    .line 1
    const-string v0, "request"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lk01/q;->d:Lk01/x;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    iget-object v0, p1, Ld01/k0;->d:Ld01/r0;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    const/4 v2, 0x1

    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    move v0, v2

    .line 18
    goto :goto_0

    .line 19
    :cond_1
    move v0, v1

    .line 20
    :goto_0
    iget-object v3, p1, Ld01/k0;->c:Ld01/y;

    .line 21
    .line 22
    new-instance v4, Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-virtual {v3}, Ld01/y;->size()I

    .line 25
    .line 26
    .line 27
    move-result v5

    .line 28
    add-int/lit8 v5, v5, 0x4

    .line 29
    .line 30
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 31
    .line 32
    .line 33
    new-instance v5, Lk01/d;

    .line 34
    .line 35
    sget-object v6, Lk01/d;->f:Lu01/i;

    .line 36
    .line 37
    iget-object v7, p1, Ld01/k0;->b:Ljava/lang/String;

    .line 38
    .line 39
    invoke-direct {v5, v6, v7}, Lk01/d;-><init>(Lu01/i;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    new-instance v5, Lk01/d;

    .line 46
    .line 47
    sget-object v6, Lk01/d;->g:Lu01/i;

    .line 48
    .line 49
    iget-object v7, p1, Ld01/k0;->a:Ld01/a0;

    .line 50
    .line 51
    const-string v8, "url"

    .line 52
    .line 53
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v7}, Ld01/a0;->b()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v8

    .line 60
    invoke-virtual {v7}, Ld01/a0;->d()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v9

    .line 64
    if-eqz v9, :cond_2

    .line 65
    .line 66
    new-instance v10, Ljava/lang/StringBuilder;

    .line 67
    .line 68
    invoke-direct {v10}, Ljava/lang/StringBuilder;-><init>()V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v10, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const/16 v8, 0x3f

    .line 75
    .line 76
    invoke-virtual {v10, v8}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v10, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v8

    .line 86
    :cond_2
    invoke-direct {v5, v6, v8}, Lk01/d;-><init>(Lu01/i;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    const-string v5, "Host"

    .line 93
    .line 94
    iget-object p1, p1, Ld01/k0;->c:Ld01/y;

    .line 95
    .line 96
    invoke-virtual {p1, v5}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    if-eqz p1, :cond_3

    .line 101
    .line 102
    new-instance v5, Lk01/d;

    .line 103
    .line 104
    sget-object v6, Lk01/d;->i:Lu01/i;

    .line 105
    .line 106
    invoke-direct {v5, v6, p1}, Lk01/d;-><init>(Lu01/i;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    :cond_3
    new-instance p1, Lk01/d;

    .line 113
    .line 114
    sget-object v5, Lk01/d;->h:Lu01/i;

    .line 115
    .line 116
    iget-object v6, v7, Ld01/a0;->a:Ljava/lang/String;

    .line 117
    .line 118
    invoke-direct {p1, v5, v6}, Lk01/d;-><init>(Lu01/i;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v4, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    invoke-virtual {v3}, Ld01/y;->size()I

    .line 125
    .line 126
    .line 127
    move-result p1

    .line 128
    move v5, v1

    .line 129
    :goto_1
    if-ge v5, p1, :cond_6

    .line 130
    .line 131
    invoke-virtual {v3, v5}, Ld01/y;->e(I)Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object v6

    .line 135
    sget-object v7, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 136
    .line 137
    const-string v8, "US"

    .line 138
    .line 139
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v6, v7}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object v6

    .line 146
    const-string v7, "toLowerCase(...)"

    .line 147
    .line 148
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    sget-object v7, Lk01/q;->g:Ljava/util/List;

    .line 152
    .line 153
    invoke-interface {v7, v6}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 154
    .line 155
    .line 156
    move-result v7

    .line 157
    if-eqz v7, :cond_4

    .line 158
    .line 159
    const-string v7, "te"

    .line 160
    .line 161
    invoke-virtual {v6, v7}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    move-result v7

    .line 165
    if-eqz v7, :cond_5

    .line 166
    .line 167
    invoke-virtual {v3, v5}, Ld01/y;->k(I)Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object v7

    .line 171
    const-string v8, "trailers"

    .line 172
    .line 173
    invoke-virtual {v7, v8}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 174
    .line 175
    .line 176
    move-result v7

    .line 177
    if-eqz v7, :cond_5

    .line 178
    .line 179
    :cond_4
    new-instance v7, Lk01/d;

    .line 180
    .line 181
    invoke-virtual {v3, v5}, Ld01/y;->k(I)Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v8

    .line 185
    invoke-direct {v7, v6, v8}, Lk01/d;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v4, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    :cond_5
    add-int/lit8 v5, v5, 0x1

    .line 192
    .line 193
    goto :goto_1

    .line 194
    :cond_6
    iget-object v8, p0, Lk01/q;->c:Lk01/p;

    .line 195
    .line 196
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 197
    .line 198
    .line 199
    xor-int/lit8 v9, v0, 0x1

    .line 200
    .line 201
    iget-object p1, v8, Lk01/p;->z:Lk01/y;

    .line 202
    .line 203
    monitor-enter p1

    .line 204
    :try_start_0
    monitor-enter v8
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 205
    :try_start_1
    iget v3, v8, Lk01/p;->h:I

    .line 206
    .line 207
    const v5, 0x3fffffff    # 1.9999999f

    .line 208
    .line 209
    .line 210
    if-le v3, v5, :cond_7

    .line 211
    .line 212
    sget-object v3, Lk01/b;->j:Lk01/b;

    .line 213
    .line 214
    invoke-virtual {v8, v3}, Lk01/p;->f(Lk01/b;)V

    .line 215
    .line 216
    .line 217
    goto :goto_2

    .line 218
    :catchall_0
    move-exception v0

    .line 219
    move-object p0, v0

    .line 220
    goto/16 :goto_3

    .line 221
    .line 222
    :cond_7
    :goto_2
    iget-boolean v3, v8, Lk01/p;->i:Z

    .line 223
    .line 224
    if-nez v3, :cond_d

    .line 225
    .line 226
    iget v7, v8, Lk01/p;->h:I

    .line 227
    .line 228
    add-int/lit8 v3, v7, 0x2

    .line 229
    .line 230
    iput v3, v8, Lk01/p;->h:I

    .line 231
    .line 232
    new-instance v6, Lk01/x;

    .line 233
    .line 234
    const/4 v11, 0x0

    .line 235
    const/4 v10, 0x0

    .line 236
    invoke-direct/range {v6 .. v11}, Lk01/x;-><init>(ILk01/p;ZZLd01/y;)V

    .line 237
    .line 238
    .line 239
    if-eqz v0, :cond_8

    .line 240
    .line 241
    iget-wide v10, v8, Lk01/p;->w:J

    .line 242
    .line 243
    iget-wide v12, v8, Lk01/p;->x:J

    .line 244
    .line 245
    cmp-long v0, v10, v12

    .line 246
    .line 247
    if-gez v0, :cond_8

    .line 248
    .line 249
    iget-wide v10, v6, Lk01/x;->g:J

    .line 250
    .line 251
    iget-wide v12, v6, Lk01/x;->h:J

    .line 252
    .line 253
    cmp-long v0, v10, v12

    .line 254
    .line 255
    if-ltz v0, :cond_9

    .line 256
    .line 257
    :cond_8
    move v1, v2

    .line 258
    :cond_9
    invoke-virtual {v6}, Lk01/x;->i()Z

    .line 259
    .line 260
    .line 261
    move-result v0

    .line 262
    if-eqz v0, :cond_a

    .line 263
    .line 264
    iget-object v0, v8, Lk01/p;->e:Ljava/util/LinkedHashMap;

    .line 265
    .line 266
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 267
    .line 268
    .line 269
    move-result-object v2

    .line 270
    invoke-interface {v0, v2, v6}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 271
    .line 272
    .line 273
    :cond_a
    :try_start_2
    monitor-exit v8

    .line 274
    iget-object v0, v8, Lk01/p;->z:Lk01/y;

    .line 275
    .line 276
    invoke-virtual {v0, v7, v4, v9}, Lk01/y;->g(ILjava/util/ArrayList;Z)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 277
    .line 278
    .line 279
    monitor-exit p1

    .line 280
    if-eqz v1, :cond_b

    .line 281
    .line 282
    iget-object p1, v8, Lk01/p;->z:Lk01/y;

    .line 283
    .line 284
    invoke-virtual {p1}, Lk01/y;->flush()V

    .line 285
    .line 286
    .line 287
    :cond_b
    iput-object v6, p0, Lk01/q;->d:Lk01/x;

    .line 288
    .line 289
    iget-boolean p1, p0, Lk01/q;->f:Z

    .line 290
    .line 291
    if-nez p1, :cond_c

    .line 292
    .line 293
    iget-object p1, p0, Lk01/q;->d:Lk01/x;

    .line 294
    .line 295
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 296
    .line 297
    .line 298
    iget-object p1, p1, Lk01/x;->m:Lk01/w;

    .line 299
    .line 300
    iget-object v0, p0, Lk01/q;->b:Li01/f;

    .line 301
    .line 302
    iget v0, v0, Li01/f;->g:I

    .line 303
    .line 304
    int-to-long v0, v0

    .line 305
    sget-object v2, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 306
    .line 307
    invoke-virtual {p1, v0, v1, v2}, Lu01/j0;->g(JLjava/util/concurrent/TimeUnit;)Lu01/j0;

    .line 308
    .line 309
    .line 310
    iget-object p1, p0, Lk01/q;->d:Lk01/x;

    .line 311
    .line 312
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 313
    .line 314
    .line 315
    iget-object p1, p1, Lk01/x;->n:Lk01/w;

    .line 316
    .line 317
    iget-object p0, p0, Lk01/q;->b:Li01/f;

    .line 318
    .line 319
    iget p0, p0, Li01/f;->h:I

    .line 320
    .line 321
    int-to-long v0, p0

    .line 322
    invoke-virtual {p1, v0, v1, v2}, Lu01/j0;->g(JLjava/util/concurrent/TimeUnit;)Lu01/j0;

    .line 323
    .line 324
    .line 325
    return-void

    .line 326
    :cond_c
    iget-object p0, p0, Lk01/q;->d:Lk01/x;

    .line 327
    .line 328
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 329
    .line 330
    .line 331
    sget-object p1, Lk01/b;->k:Lk01/b;

    .line 332
    .line 333
    invoke-virtual {p0, p1}, Lk01/x;->f(Lk01/b;)V

    .line 334
    .line 335
    .line 336
    new-instance p0, Ljava/io/IOException;

    .line 337
    .line 338
    const-string p1, "Canceled"

    .line 339
    .line 340
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 341
    .line 342
    .line 343
    throw p0

    .line 344
    :catchall_1
    move-exception v0

    .line 345
    move-object p0, v0

    .line 346
    goto :goto_4

    .line 347
    :cond_d
    :try_start_3
    new-instance p0, Lk01/a;

    .line 348
    .line 349
    invoke-direct {p0}, Ljava/io/IOException;-><init>()V

    .line 350
    .line 351
    .line 352
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 353
    :goto_3
    :try_start_4
    monitor-exit v8

    .line 354
    throw p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 355
    :goto_4
    monitor-exit p1

    .line 356
    throw p0
.end method
