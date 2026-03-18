.class public final Lh01/p;
.super Lk01/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Li01/c;


# instance fields
.field public final b:Lg01/c;

.field public final c:Ld01/w0;

.field public final d:Ljava/net/Socket;

.field public final e:Ljava/net/Socket;

.field public final f:Ld01/w;

.field public final g:Ld01/i0;

.field public final h:Lgw0/c;

.field public i:Lk01/p;

.field public j:Z

.field public k:Z

.field public l:I

.field public m:I

.field public n:I

.field public o:I

.field public final p:Ljava/util/ArrayList;

.field public q:J


# direct methods
.method public constructor <init>(Lg01/c;Lh01/q;Ld01/w0;Ljava/net/Socket;Ljava/net/Socket;Ld01/w;Ld01/i0;Lgw0/c;)V
    .locals 1

    .line 1
    const-string v0, "taskRunner"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "connectionPool"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p2, "route"

    .line 12
    .line 13
    invoke-static {p3, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string p2, "rawSocket"

    .line 17
    .line 18
    invoke-static {p4, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string p2, "javaNetSocket"

    .line 22
    .line 23
    invoke-static {p5, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string p2, "protocol"

    .line 27
    .line 28
    invoke-static {p7, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const-string p2, "socket"

    .line 32
    .line 33
    invoke-static {p8, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 37
    .line 38
    .line 39
    iput-object p1, p0, Lh01/p;->b:Lg01/c;

    .line 40
    .line 41
    iput-object p3, p0, Lh01/p;->c:Ld01/w0;

    .line 42
    .line 43
    iput-object p4, p0, Lh01/p;->d:Ljava/net/Socket;

    .line 44
    .line 45
    iput-object p5, p0, Lh01/p;->e:Ljava/net/Socket;

    .line 46
    .line 47
    iput-object p6, p0, Lh01/p;->f:Ld01/w;

    .line 48
    .line 49
    iput-object p7, p0, Lh01/p;->g:Ld01/i0;

    .line 50
    .line 51
    iput-object p8, p0, Lh01/p;->h:Lgw0/c;

    .line 52
    .line 53
    const/4 p1, 0x1

    .line 54
    iput p1, p0, Lh01/p;->o:I

    .line 55
    .line 56
    new-instance p1, Ljava/util/ArrayList;

    .line 57
    .line 58
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 59
    .line 60
    .line 61
    iput-object p1, p0, Lh01/p;->p:Ljava/util/ArrayList;

    .line 62
    .line 63
    const-wide p1, 0x7fffffffffffffffL

    .line 64
    .line 65
    .line 66
    .line 67
    .line 68
    iput-wide p1, p0, Lh01/p;->q:J

    .line 69
    .line 70
    return-void
.end method

.method public static d(Ld01/h0;Ld01/w0;Ljava/io/IOException;)V
    .locals 3

    .line 1
    const-string v0, "failedRoute"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "failure"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p1, Ld01/w0;->b:Ljava/net/Proxy;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/net/Proxy;->type()Ljava/net/Proxy$Type;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sget-object v1, Ljava/net/Proxy$Type;->DIRECT:Ljava/net/Proxy$Type;

    .line 18
    .line 19
    if-eq v0, v1, :cond_0

    .line 20
    .line 21
    iget-object v0, p1, Ld01/w0;->a:Ld01/a;

    .line 22
    .line 23
    iget-object v1, v0, Ld01/a;->g:Ljava/net/ProxySelector;

    .line 24
    .line 25
    iget-object v0, v0, Ld01/a;->h:Ld01/a0;

    .line 26
    .line 27
    invoke-virtual {v0}, Ld01/a0;->j()Ljava/net/URI;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    iget-object v2, p1, Ld01/w0;->b:Ljava/net/Proxy;

    .line 32
    .line 33
    invoke-virtual {v2}, Ljava/net/Proxy;->address()Ljava/net/SocketAddress;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    invoke-virtual {v1, v0, v2, p2}, Ljava/net/ProxySelector;->connectFailed(Ljava/net/URI;Ljava/net/SocketAddress;Ljava/io/IOException;)V

    .line 38
    .line 39
    .line 40
    :cond_0
    iget-object p0, p0, Ld01/h0;->C:Lbu/c;

    .line 41
    .line 42
    monitor-enter p0

    .line 43
    :try_start_0
    iget-object p2, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p2, Ljava/util/LinkedHashSet;

    .line 46
    .line 47
    invoke-interface {p2, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 48
    .line 49
    .line 50
    monitor-exit p0

    .line 51
    return-void

    .line 52
    :catchall_0
    move-exception p1

    .line 53
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 54
    throw p1
.end method


# virtual methods
.method public final a(Lk01/p;Lk01/b0;)V
    .locals 0

    .line 1
    const-string p1, "settings"

    .line 2
    .line 3
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    monitor-enter p0

    .line 7
    :try_start_0
    iget p1, p2, Lk01/b0;->a:I

    .line 8
    .line 9
    and-int/lit8 p1, p1, 0x8

    .line 10
    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    iget-object p1, p2, Lk01/b0;->b:[I

    .line 14
    .line 15
    const/4 p2, 0x3

    .line 16
    aget p1, p1, p2

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const p1, 0x7fffffff

    .line 20
    .line 21
    .line 22
    :goto_0
    iput p1, p0, Lh01/p;->o:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    .line 24
    monitor-exit p0

    .line 25
    return-void

    .line 26
    :catchall_0
    move-exception p1

    .line 27
    monitor-exit p0

    .line 28
    throw p1
.end method

.method public final b(Lk01/x;)V
    .locals 1

    .line 1
    sget-object p0, Lk01/b;->j:Lk01/b;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-virtual {p1, p0, v0}, Lk01/x;->d(Lk01/b;Ljava/io/IOException;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final c()V
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    const/4 v0, 0x1

    .line 3
    :try_start_0
    iput-boolean v0, p0, Lh01/p;->j:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 4
    .line 5
    monitor-exit p0

    .line 6
    return-void

    .line 7
    :catchall_0
    move-exception v0

    .line 8
    monitor-exit p0

    .line 9
    throw v0
.end method

.method public final cancel()V
    .locals 0

    .line 1
    iget-object p0, p0, Lh01/p;->d:Ljava/net/Socket;

    .line 2
    .line 3
    invoke-static {p0}, Le01/g;->c(Ljava/net/Socket;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final e()Ld01/w0;
    .locals 0

    .line 1
    iget-object p0, p0, Lh01/p;->c:Ld01/w0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final f(Ld01/a;Ljava/util/List;)Z
    .locals 10

    .line 1
    const-string v0, "hostname"

    .line 2
    .line 3
    iget-object v1, p1, Ld01/a;->h:Ld01/a0;

    .line 4
    .line 5
    sget-object v2, Le01/g;->a:Ljava/util/TimeZone;

    .line 6
    .line 7
    iget-object v2, p0, Lh01/p;->p:Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    iget v3, p0, Lh01/p;->o:I

    .line 14
    .line 15
    const/4 v4, 0x0

    .line 16
    if-ge v2, v3, :cond_a

    .line 17
    .line 18
    iget-boolean v2, p0, Lh01/p;->j:Z

    .line 19
    .line 20
    if-eqz v2, :cond_0

    .line 21
    .line 22
    goto/16 :goto_1

    .line 23
    .line 24
    :cond_0
    iget-object v2, p0, Lh01/p;->c:Ld01/w0;

    .line 25
    .line 26
    iget-object v3, v2, Ld01/w0;->a:Ld01/a;

    .line 27
    .line 28
    iget-object v5, v2, Ld01/w0;->a:Ld01/a;

    .line 29
    .line 30
    invoke-virtual {v3, p1}, Ld01/a;->a(Ld01/a;)Z

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    if-nez v3, :cond_1

    .line 35
    .line 36
    goto/16 :goto_1

    .line 37
    .line 38
    :cond_1
    iget-object v3, v1, Ld01/a0;->d:Ljava/lang/String;

    .line 39
    .line 40
    iget-object v6, v1, Ld01/a0;->d:Ljava/lang/String;

    .line 41
    .line 42
    iget-object v7, v5, Ld01/a;->h:Ld01/a0;

    .line 43
    .line 44
    iget-object v7, v7, Ld01/a0;->d:Ljava/lang/String;

    .line 45
    .line 46
    invoke-static {v3, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    const/4 v7, 0x1

    .line 51
    if-eqz v3, :cond_2

    .line 52
    .line 53
    return v7

    .line 54
    :cond_2
    iget-object v3, p0, Lh01/p;->i:Lk01/p;

    .line 55
    .line 56
    if-nez v3, :cond_3

    .line 57
    .line 58
    goto/16 :goto_1

    .line 59
    .line 60
    :cond_3
    if-eqz p2, :cond_a

    .line 61
    .line 62
    check-cast p2, Ljava/lang/Iterable;

    .line 63
    .line 64
    instance-of v3, p2, Ljava/util/Collection;

    .line 65
    .line 66
    if-eqz v3, :cond_4

    .line 67
    .line 68
    move-object v3, p2

    .line 69
    check-cast v3, Ljava/util/Collection;

    .line 70
    .line 71
    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    if-eqz v3, :cond_4

    .line 76
    .line 77
    goto/16 :goto_1

    .line 78
    .line 79
    :cond_4
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 80
    .line 81
    .line 82
    move-result-object p2

    .line 83
    :cond_5
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 84
    .line 85
    .line 86
    move-result v3

    .line 87
    if-eqz v3, :cond_a

    .line 88
    .line 89
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v3

    .line 93
    check-cast v3, Ld01/w0;

    .line 94
    .line 95
    iget-object v8, v3, Ld01/w0;->b:Ljava/net/Proxy;

    .line 96
    .line 97
    invoke-virtual {v8}, Ljava/net/Proxy;->type()Ljava/net/Proxy$Type;

    .line 98
    .line 99
    .line 100
    move-result-object v8

    .line 101
    sget-object v9, Ljava/net/Proxy$Type;->DIRECT:Ljava/net/Proxy$Type;

    .line 102
    .line 103
    if-ne v8, v9, :cond_5

    .line 104
    .line 105
    iget-object v8, v2, Ld01/w0;->b:Ljava/net/Proxy;

    .line 106
    .line 107
    invoke-virtual {v8}, Ljava/net/Proxy;->type()Ljava/net/Proxy$Type;

    .line 108
    .line 109
    .line 110
    move-result-object v8

    .line 111
    if-ne v8, v9, :cond_5

    .line 112
    .line 113
    iget-object v8, v2, Ld01/w0;->c:Ljava/net/InetSocketAddress;

    .line 114
    .line 115
    iget-object v3, v3, Ld01/w0;->c:Ljava/net/InetSocketAddress;

    .line 116
    .line 117
    invoke-static {v8, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result v3

    .line 121
    if-eqz v3, :cond_5

    .line 122
    .line 123
    iget-object p2, p1, Ld01/a;->d:Ljavax/net/ssl/HostnameVerifier;

    .line 124
    .line 125
    sget-object v2, Lr01/c;->a:Lr01/c;

    .line 126
    .line 127
    if-eq p2, v2, :cond_6

    .line 128
    .line 129
    goto :goto_1

    .line 130
    :cond_6
    sget-object p2, Le01/g;->a:Ljava/util/TimeZone;

    .line 131
    .line 132
    iget-object p2, v5, Ld01/a;->h:Ld01/a0;

    .line 133
    .line 134
    iget v1, v1, Ld01/a0;->e:I

    .line 135
    .line 136
    iget v2, p2, Ld01/a0;->e:I

    .line 137
    .line 138
    if-eq v1, v2, :cond_7

    .line 139
    .line 140
    goto :goto_1

    .line 141
    :cond_7
    iget-object p2, p2, Ld01/a0;->d:Ljava/lang/String;

    .line 142
    .line 143
    invoke-static {v6, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result p2

    .line 147
    iget-object v1, p0, Lh01/p;->f:Ld01/w;

    .line 148
    .line 149
    if-eqz p2, :cond_8

    .line 150
    .line 151
    goto :goto_0

    .line 152
    :cond_8
    iget-boolean p0, p0, Lh01/p;->k:Z

    .line 153
    .line 154
    if-nez p0, :cond_a

    .line 155
    .line 156
    if-eqz v1, :cond_a

    .line 157
    .line 158
    invoke-virtual {v1}, Ld01/w;->a()Ljava/util/List;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    move-object p2, p0

    .line 163
    check-cast p2, Ljava/util/Collection;

    .line 164
    .line 165
    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    .line 166
    .line 167
    .line 168
    move-result p2

    .line 169
    if-nez p2, :cond_a

    .line 170
    .line 171
    invoke-interface {p0, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    const-string p2, "null cannot be cast to non-null type java.security.cert.X509Certificate"

    .line 176
    .line 177
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    check-cast p0, Ljava/security/cert/X509Certificate;

    .line 181
    .line 182
    invoke-static {v6, p0}, Lr01/c;->c(Ljava/lang/String;Ljava/security/cert/X509Certificate;)Z

    .line 183
    .line 184
    .line 185
    move-result p0

    .line 186
    if-eqz p0, :cond_a

    .line 187
    .line 188
    :goto_0
    :try_start_0
    iget-object p0, p1, Ld01/a;->e:Ld01/l;

    .line 189
    .line 190
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 194
    .line 195
    .line 196
    invoke-virtual {v1}, Ld01/w;->a()Ljava/util/List;

    .line 197
    .line 198
    .line 199
    move-result-object p1

    .line 200
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    const-string p2, "peerCertificates"

    .line 204
    .line 205
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    iget-object p0, p0, Ld01/l;->a:Ljava/util/Set;

    .line 209
    .line 210
    check-cast p0, Ljava/lang/Iterable;

    .line 211
    .line 212
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 213
    .line 214
    .line 215
    move-result-object p0

    .line 216
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 217
    .line 218
    .line 219
    move-result p1

    .line 220
    if-nez p1, :cond_9

    .line 221
    .line 222
    return v7

    .line 223
    :cond_9
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object p0

    .line 227
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 228
    .line 229
    .line 230
    new-instance p0, Ljava/lang/ClassCastException;

    .line 231
    .line 232
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 233
    .line 234
    .line 235
    throw p0
    :try_end_0
    .catch Ljavax/net/ssl/SSLPeerUnverifiedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 236
    :catch_0
    :cond_a
    :goto_1
    return v4
.end method

.method public final g(Z)Z
    .locals 7

    .line 1
    sget-object v0, Le01/g;->a:Ljava/util/TimeZone;

    .line 2
    .line 3
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget-object v2, p0, Lh01/p;->d:Ljava/net/Socket;

    .line 8
    .line 9
    invoke-virtual {v2}, Ljava/net/Socket;->isClosed()Z

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    const/4 v3, 0x0

    .line 14
    if-nez v2, :cond_5

    .line 15
    .line 16
    iget-object v2, p0, Lh01/p;->e:Ljava/net/Socket;

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/net/Socket;->isClosed()Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-nez v2, :cond_5

    .line 23
    .line 24
    iget-object v2, p0, Lh01/p;->e:Ljava/net/Socket;

    .line 25
    .line 26
    invoke-virtual {v2}, Ljava/net/Socket;->isInputShutdown()Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-nez v2, :cond_5

    .line 31
    .line 32
    iget-object v2, p0, Lh01/p;->e:Ljava/net/Socket;

    .line 33
    .line 34
    invoke-virtual {v2}, Ljava/net/Socket;->isOutputShutdown()Z

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    if-eqz v2, :cond_0

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_0
    iget-object v2, p0, Lh01/p;->i:Lk01/p;

    .line 42
    .line 43
    const/4 v4, 0x1

    .line 44
    if-eqz v2, :cond_3

    .line 45
    .line 46
    monitor-enter v2

    .line 47
    :try_start_0
    iget-boolean p0, v2, Lk01/p;->i:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 48
    .line 49
    if-eqz p0, :cond_1

    .line 50
    .line 51
    monitor-exit v2

    .line 52
    return v3

    .line 53
    :cond_1
    :try_start_1
    iget-wide p0, v2, Lk01/p;->q:J

    .line 54
    .line 55
    iget-wide v5, v2, Lk01/p;->p:J

    .line 56
    .line 57
    cmp-long p0, p0, v5

    .line 58
    .line 59
    if-gez p0, :cond_2

    .line 60
    .line 61
    iget-wide p0, v2, Lk01/p;->r:J
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 62
    .line 63
    cmp-long p0, v0, p0

    .line 64
    .line 65
    if-ltz p0, :cond_2

    .line 66
    .line 67
    monitor-exit v2

    .line 68
    return v3

    .line 69
    :catchall_0
    move-exception p0

    .line 70
    goto :goto_0

    .line 71
    :cond_2
    monitor-exit v2

    .line 72
    return v4

    .line 73
    :goto_0
    monitor-exit v2

    .line 74
    throw p0

    .line 75
    :cond_3
    monitor-enter p0

    .line 76
    :try_start_2
    iget-wide v5, p0, Lh01/p;->q:J
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 77
    .line 78
    sub-long/2addr v0, v5

    .line 79
    monitor-exit p0

    .line 80
    const-wide v5, 0x2540be400L

    .line 81
    .line 82
    .line 83
    .line 84
    .line 85
    cmp-long v0, v0, v5

    .line 86
    .line 87
    if-ltz v0, :cond_4

    .line 88
    .line 89
    if-eqz p1, :cond_4

    .line 90
    .line 91
    iget-object p1, p0, Lh01/p;->e:Ljava/net/Socket;

    .line 92
    .line 93
    iget-object p0, p0, Lh01/p;->h:Lgw0/c;

    .line 94
    .line 95
    iget-object p0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 96
    .line 97
    check-cast p0, Lu01/b0;

    .line 98
    .line 99
    const-string v0, "<this>"

    .line 100
    .line 101
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    const-string v0, "source"

    .line 105
    .line 106
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    :try_start_3
    invoke-virtual {p1}, Ljava/net/Socket;->getSoTimeout()I

    .line 110
    .line 111
    .line 112
    move-result v0
    :try_end_3
    .catch Ljava/net/SocketTimeoutException; {:try_start_3 .. :try_end_3} :catch_0
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_1

    .line 113
    :try_start_4
    invoke-virtual {p1, v4}, Ljava/net/Socket;->setSoTimeout(I)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {p0}, Lu01/b0;->Z()Z

    .line 117
    .line 118
    .line 119
    move-result p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 120
    xor-int/2addr p0, v4

    .line 121
    :try_start_5
    invoke-virtual {p1, v0}, Ljava/net/Socket;->setSoTimeout(I)V

    .line 122
    .line 123
    .line 124
    return p0

    .line 125
    :catchall_1
    move-exception p0

    .line 126
    invoke-virtual {p1, v0}, Ljava/net/Socket;->setSoTimeout(I)V

    .line 127
    .line 128
    .line 129
    throw p0
    :try_end_5
    .catch Ljava/net/SocketTimeoutException; {:try_start_5 .. :try_end_5} :catch_0
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_1

    .line 130
    :catch_0
    move v3, v4

    .line 131
    :catch_1
    return v3

    .line 132
    :cond_4
    return v4

    .line 133
    :catchall_2
    move-exception p1

    .line 134
    monitor-exit p0

    .line 135
    throw p1

    .line 136
    :cond_5
    :goto_1
    return v3
.end method

.method public final h(Lh01/o;Ljava/io/IOException;)V
    .locals 3

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    instance-of v0, p2, Lk01/c0;

    .line 3
    .line 4
    const/4 v1, 0x1

    .line 5
    if-eqz v0, :cond_2

    .line 6
    .line 7
    move-object v0, p2

    .line 8
    check-cast v0, Lk01/c0;

    .line 9
    .line 10
    iget-object v0, v0, Lk01/c0;->d:Lk01/b;

    .line 11
    .line 12
    sget-object v2, Lk01/b;->j:Lk01/b;

    .line 13
    .line 14
    if-ne v0, v2, :cond_0

    .line 15
    .line 16
    iget p1, p0, Lh01/p;->n:I

    .line 17
    .line 18
    add-int/2addr p1, v1

    .line 19
    iput p1, p0, Lh01/p;->n:I

    .line 20
    .line 21
    if-le p1, v1, :cond_6

    .line 22
    .line 23
    iput-boolean v1, p0, Lh01/p;->j:Z

    .line 24
    .line 25
    iget p1, p0, Lh01/p;->l:I

    .line 26
    .line 27
    add-int/2addr p1, v1

    .line 28
    iput p1, p0, Lh01/p;->l:I

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :catchall_0
    move-exception p1

    .line 32
    goto :goto_2

    .line 33
    :cond_0
    check-cast p2, Lk01/c0;

    .line 34
    .line 35
    iget-object p2, p2, Lk01/c0;->d:Lk01/b;

    .line 36
    .line 37
    sget-object v0, Lk01/b;->k:Lk01/b;

    .line 38
    .line 39
    if-ne p2, v0, :cond_1

    .line 40
    .line 41
    iget-boolean p1, p1, Lh01/o;->t:Z

    .line 42
    .line 43
    if-nez p1, :cond_6

    .line 44
    .line 45
    :cond_1
    iput-boolean v1, p0, Lh01/p;->j:Z

    .line 46
    .line 47
    iget p1, p0, Lh01/p;->l:I

    .line 48
    .line 49
    add-int/2addr p1, v1

    .line 50
    iput p1, p0, Lh01/p;->l:I

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_2
    iget-object v0, p0, Lh01/p;->i:Lk01/p;

    .line 54
    .line 55
    if-eqz v0, :cond_3

    .line 56
    .line 57
    move v0, v1

    .line 58
    goto :goto_0

    .line 59
    :cond_3
    const/4 v0, 0x0

    .line 60
    :goto_0
    if-eqz v0, :cond_4

    .line 61
    .line 62
    instance-of v0, p2, Lk01/a;

    .line 63
    .line 64
    if-eqz v0, :cond_6

    .line 65
    .line 66
    :cond_4
    iput-boolean v1, p0, Lh01/p;->j:Z

    .line 67
    .line 68
    iget v0, p0, Lh01/p;->m:I

    .line 69
    .line 70
    if-nez v0, :cond_6

    .line 71
    .line 72
    if-eqz p2, :cond_5

    .line 73
    .line 74
    iget-object p1, p1, Lh01/o;->d:Ld01/h0;

    .line 75
    .line 76
    iget-object v0, p0, Lh01/p;->c:Ld01/w0;

    .line 77
    .line 78
    invoke-static {p1, v0, p2}, Lh01/p;->d(Ld01/h0;Ld01/w0;Ljava/io/IOException;)V

    .line 79
    .line 80
    .line 81
    :cond_5
    iget p1, p0, Lh01/p;->l:I

    .line 82
    .line 83
    add-int/2addr p1, v1

    .line 84
    iput p1, p0, Lh01/p;->l:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 85
    .line 86
    :cond_6
    :goto_1
    monitor-exit p0

    .line 87
    return-void

    .line 88
    :goto_2
    monitor-exit p0

    .line 89
    throw p1
.end method

.method public final i()V
    .locals 7

    .line 1
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iput-wide v0, p0, Lh01/p;->q:J

    .line 6
    .line 7
    iget-object v0, p0, Lh01/p;->g:Ld01/i0;

    .line 8
    .line 9
    sget-object v1, Ld01/i0;->i:Ld01/i0;

    .line 10
    .line 11
    if-eq v0, v1, :cond_1

    .line 12
    .line 13
    sget-object v1, Ld01/i0;->j:Ld01/i0;

    .line 14
    .line 15
    if-ne v0, v1, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    return-void

    .line 19
    :cond_1
    :goto_0
    iget-object v0, p0, Lh01/p;->e:Ljava/net/Socket;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-virtual {v0, v1}, Ljava/net/Socket;->setSoTimeout(I)V

    .line 23
    .line 24
    .line 25
    sget-object v0, Lk01/c;->a:Lk01/c;

    .line 26
    .line 27
    new-instance v2, Landroidx/lifecycle/c1;

    .line 28
    .line 29
    iget-object v3, p0, Lh01/p;->b:Lg01/c;

    .line 30
    .line 31
    invoke-direct {v2, v3}, Landroidx/lifecycle/c1;-><init>(Lg01/c;)V

    .line 32
    .line 33
    .line 34
    iget-object v3, p0, Lh01/p;->h:Lgw0/c;

    .line 35
    .line 36
    iget-object v4, p0, Lh01/p;->c:Ld01/w0;

    .line 37
    .line 38
    iget-object v4, v4, Ld01/w0;->a:Ld01/a;

    .line 39
    .line 40
    iget-object v4, v4, Ld01/a;->h:Ld01/a0;

    .line 41
    .line 42
    iget-object v4, v4, Ld01/a0;->d:Ljava/lang/String;

    .line 43
    .line 44
    const-string v5, "socket"

    .line 45
    .line 46
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    const-string v5, "peerName"

    .line 50
    .line 51
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    iput-object v3, v2, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 55
    .line 56
    new-instance v3, Ljava/lang/StringBuilder;

    .line 57
    .line 58
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 59
    .line 60
    .line 61
    sget-object v5, Le01/g;->b:Ljava/lang/String;

    .line 62
    .line 63
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const/16 v5, 0x20

    .line 67
    .line 68
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v3

    .line 78
    const-string v4, "<set-?>"

    .line 79
    .line 80
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    iput-object v3, v2, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 84
    .line 85
    iput-object p0, v2, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 86
    .line 87
    iput-object v0, v2, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 88
    .line 89
    new-instance v0, Lk01/p;

    .line 90
    .line 91
    invoke-direct {v0, v2}, Lk01/p;-><init>(Landroidx/lifecycle/c1;)V

    .line 92
    .line 93
    .line 94
    iput-object v0, p0, Lh01/p;->i:Lk01/p;

    .line 95
    .line 96
    sget-object v2, Lk01/p;->C:Lk01/b0;

    .line 97
    .line 98
    iget v3, v2, Lk01/b0;->a:I

    .line 99
    .line 100
    and-int/lit8 v3, v3, 0x8

    .line 101
    .line 102
    if-eqz v3, :cond_2

    .line 103
    .line 104
    iget-object v2, v2, Lk01/b0;->b:[I

    .line 105
    .line 106
    const/4 v3, 0x3

    .line 107
    aget v2, v2, v3

    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_2
    const v2, 0x7fffffff

    .line 111
    .line 112
    .line 113
    :goto_1
    iput v2, p0, Lh01/p;->o:I

    .line 114
    .line 115
    iget-object p0, v0, Lk01/p;->z:Lk01/y;

    .line 116
    .line 117
    const-string v2, ">> CONNECTION "

    .line 118
    .line 119
    monitor-enter p0

    .line 120
    :try_start_0
    iget-boolean v3, p0, Lk01/y;->g:Z

    .line 121
    .line 122
    if-nez v3, :cond_9

    .line 123
    .line 124
    sget-object v3, Lk01/y;->i:Ljava/util/logging/Logger;

    .line 125
    .line 126
    sget-object v4, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 127
    .line 128
    invoke-virtual {v3, v4}, Ljava/util/logging/Logger;->isLoggable(Ljava/util/logging/Level;)Z

    .line 129
    .line 130
    .line 131
    move-result v4

    .line 132
    if-eqz v4, :cond_3

    .line 133
    .line 134
    new-instance v4, Ljava/lang/StringBuilder;

    .line 135
    .line 136
    invoke-direct {v4, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    sget-object v2, Lk01/h;->a:Lu01/i;

    .line 140
    .line 141
    invoke-virtual {v2}, Lu01/i;->e()Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object v2

    .line 145
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v2

    .line 152
    new-array v4, v1, [Ljava/lang/Object;

    .line 153
    .line 154
    invoke-static {v2, v4}, Le01/g;->d(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v2

    .line 158
    invoke-virtual {v3, v2}, Ljava/util/logging/Logger;->fine(Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    goto :goto_2

    .line 162
    :catchall_0
    move-exception v0

    .line 163
    goto/16 :goto_7

    .line 164
    .line 165
    :cond_3
    :goto_2
    iget-object v2, p0, Lk01/y;->d:Lu01/g;

    .line 166
    .line 167
    sget-object v3, Lk01/h;->a:Lu01/i;

    .line 168
    .line 169
    invoke-interface {v2, v3}, Lu01/g;->t(Lu01/i;)Lu01/g;

    .line 170
    .line 171
    .line 172
    iget-object v2, p0, Lk01/y;->d:Lu01/g;

    .line 173
    .line 174
    invoke-interface {v2}, Lu01/g;->flush()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 175
    .line 176
    .line 177
    monitor-exit p0

    .line 178
    iget-object p0, v0, Lk01/p;->z:Lk01/y;

    .line 179
    .line 180
    iget-object v2, v0, Lk01/p;->t:Lk01/b0;

    .line 181
    .line 182
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 183
    .line 184
    .line 185
    const-string v3, "settings"

    .line 186
    .line 187
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    monitor-enter p0

    .line 191
    :try_start_1
    iget-boolean v3, p0, Lk01/y;->g:Z

    .line 192
    .line 193
    if-nez v3, :cond_8

    .line 194
    .line 195
    iget v3, v2, Lk01/b0;->a:I

    .line 196
    .line 197
    invoke-static {v3}, Ljava/lang/Integer;->bitCount(I)I

    .line 198
    .line 199
    .line 200
    move-result v3

    .line 201
    mul-int/lit8 v3, v3, 0x6

    .line 202
    .line 203
    const/4 v4, 0x4

    .line 204
    invoke-virtual {p0, v1, v3, v4, v1}, Lk01/y;->d(IIII)V

    .line 205
    .line 206
    .line 207
    move v3, v1

    .line 208
    :goto_3
    const/16 v4, 0xa

    .line 209
    .line 210
    if-ge v3, v4, :cond_6

    .line 211
    .line 212
    const/4 v4, 0x1

    .line 213
    shl-int v5, v4, v3

    .line 214
    .line 215
    iget v6, v2, Lk01/b0;->a:I

    .line 216
    .line 217
    and-int/2addr v5, v6

    .line 218
    if-eqz v5, :cond_4

    .line 219
    .line 220
    goto :goto_4

    .line 221
    :cond_4
    move v4, v1

    .line 222
    :goto_4
    if-eqz v4, :cond_5

    .line 223
    .line 224
    iget-object v4, p0, Lk01/y;->d:Lu01/g;

    .line 225
    .line 226
    invoke-interface {v4, v3}, Lu01/g;->writeShort(I)Lu01/g;

    .line 227
    .line 228
    .line 229
    iget-object v4, p0, Lk01/y;->d:Lu01/g;

    .line 230
    .line 231
    iget-object v5, v2, Lk01/b0;->b:[I

    .line 232
    .line 233
    aget v5, v5, v3

    .line 234
    .line 235
    invoke-interface {v4, v5}, Lu01/g;->writeInt(I)Lu01/g;

    .line 236
    .line 237
    .line 238
    goto :goto_5

    .line 239
    :catchall_1
    move-exception v0

    .line 240
    goto :goto_6

    .line 241
    :cond_5
    :goto_5
    add-int/lit8 v3, v3, 0x1

    .line 242
    .line 243
    goto :goto_3

    .line 244
    :cond_6
    iget-object v2, p0, Lk01/y;->d:Lu01/g;

    .line 245
    .line 246
    invoke-interface {v2}, Lu01/g;->flush()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 247
    .line 248
    .line 249
    monitor-exit p0

    .line 250
    iget-object p0, v0, Lk01/p;->t:Lk01/b0;

    .line 251
    .line 252
    invoke-virtual {p0}, Lk01/b0;->a()I

    .line 253
    .line 254
    .line 255
    move-result p0

    .line 256
    const v2, 0xffff

    .line 257
    .line 258
    .line 259
    if-eq p0, v2, :cond_7

    .line 260
    .line 261
    iget-object v3, v0, Lk01/p;->z:Lk01/y;

    .line 262
    .line 263
    sub-int/2addr p0, v2

    .line 264
    int-to-long v4, p0

    .line 265
    invoke-virtual {v3, v1, v4, v5}, Lk01/y;->k(IJ)V

    .line 266
    .line 267
    .line 268
    :cond_7
    iget-object p0, v0, Lk01/p;->j:Lg01/c;

    .line 269
    .line 270
    invoke-virtual {p0}, Lg01/c;->d()Lg01/b;

    .line 271
    .line 272
    .line 273
    move-result-object v1

    .line 274
    iget-object v2, v0, Lk01/p;->f:Ljava/lang/String;

    .line 275
    .line 276
    iget-object v5, v0, Lk01/p;->A:Lc41/f;

    .line 277
    .line 278
    const/4 v6, 0x6

    .line 279
    const-wide/16 v3, 0x0

    .line 280
    .line 281
    invoke-static/range {v1 .. v6}, Lg01/b;->c(Lg01/b;Ljava/lang/String;JLay0/a;I)V

    .line 282
    .line 283
    .line 284
    return-void

    .line 285
    :cond_8
    :try_start_2
    new-instance v0, Ljava/io/IOException;

    .line 286
    .line 287
    const-string v1, "closed"

    .line 288
    .line 289
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    throw v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 293
    :goto_6
    monitor-exit p0

    .line 294
    throw v0

    .line 295
    :cond_9
    :try_start_3
    new-instance v0, Ljava/io/IOException;

    .line 296
    .line 297
    const-string v1, "closed"

    .line 298
    .line 299
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 300
    .line 301
    .line 302
    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 303
    :goto_7
    monitor-exit p0

    .line 304
    throw v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Connection{"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lh01/p;->c:Ld01/w0;

    .line 9
    .line 10
    iget-object v2, v1, Ld01/w0;->a:Ld01/a;

    .line 11
    .line 12
    iget-object v2, v2, Ld01/a;->h:Ld01/a0;

    .line 13
    .line 14
    iget-object v2, v2, Ld01/a0;->d:Ljava/lang/String;

    .line 15
    .line 16
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const/16 v2, 0x3a

    .line 20
    .line 21
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    iget-object v2, v1, Ld01/w0;->a:Ld01/a;

    .line 25
    .line 26
    iget-object v2, v2, Ld01/a;->h:Ld01/a0;

    .line 27
    .line 28
    iget v2, v2, Ld01/a0;->e:I

    .line 29
    .line 30
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v2, ", proxy="

    .line 34
    .line 35
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v2, v1, Ld01/w0;->b:Ljava/net/Proxy;

    .line 39
    .line 40
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v2, " hostAddress="

    .line 44
    .line 45
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, v1, Ld01/w0;->c:Ljava/net/InetSocketAddress;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, " cipherSuite="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lh01/p;->f:Ld01/w;

    .line 59
    .line 60
    if-eqz v1, :cond_0

    .line 61
    .line 62
    iget-object v1, v1, Ld01/w;->b:Ld01/n;

    .line 63
    .line 64
    if-nez v1, :cond_1

    .line 65
    .line 66
    :cond_0
    const-string v1, "none"

    .line 67
    .line 68
    :cond_1
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    const-string v1, " protocol="

    .line 72
    .line 73
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    iget-object p0, p0, Lh01/p;->g:Ld01/i0;

    .line 77
    .line 78
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    const/16 p0, 0x7d

    .line 82
    .line 83
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    return-object p0
.end method
