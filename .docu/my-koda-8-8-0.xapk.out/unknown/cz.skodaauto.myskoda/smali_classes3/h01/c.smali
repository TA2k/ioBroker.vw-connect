.class public final Lh01/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh01/u;
.implements Li01/c;


# instance fields
.field public final a:Lg01/c;

.field public final b:Lh01/q;

.field public final c:I

.field public final d:I

.field public final e:I

.field public final f:I

.field public final g:Z

.field public final h:Lh01/o;

.field public final i:Lh01/r;

.field public final j:Ld01/w0;

.field public final k:Ljava/util/List;

.field public final l:I

.field public final m:Ld01/k0;

.field public final n:I

.field public final o:Z

.field public volatile p:Z

.field public q:Ljava/net/Socket;

.field public r:Ljava/net/Socket;

.field public s:Ld01/w;

.field public t:Ld01/i0;

.field public u:Lgw0/c;

.field public v:Lh01/p;


# direct methods
.method public constructor <init>(Lg01/c;Lh01/q;IIIIZLh01/o;Lh01/r;Ld01/w0;Ljava/util/List;ILd01/k0;IZ)V
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
    const-string v0, "route"

    .line 12
    .line 13
    invoke-static {p10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lh01/c;->a:Lg01/c;

    .line 20
    .line 21
    iput-object p2, p0, Lh01/c;->b:Lh01/q;

    .line 22
    .line 23
    iput p3, p0, Lh01/c;->c:I

    .line 24
    .line 25
    iput p4, p0, Lh01/c;->d:I

    .line 26
    .line 27
    iput p5, p0, Lh01/c;->e:I

    .line 28
    .line 29
    iput p6, p0, Lh01/c;->f:I

    .line 30
    .line 31
    iput-boolean p7, p0, Lh01/c;->g:Z

    .line 32
    .line 33
    iput-object p8, p0, Lh01/c;->h:Lh01/o;

    .line 34
    .line 35
    iput-object p9, p0, Lh01/c;->i:Lh01/r;

    .line 36
    .line 37
    iput-object p10, p0, Lh01/c;->j:Ld01/w0;

    .line 38
    .line 39
    iput-object p11, p0, Lh01/c;->k:Ljava/util/List;

    .line 40
    .line 41
    iput p12, p0, Lh01/c;->l:I

    .line 42
    .line 43
    iput-object p13, p0, Lh01/c;->m:Ld01/k0;

    .line 44
    .line 45
    iput p14, p0, Lh01/c;->n:I

    .line 46
    .line 47
    move/from16 p1, p15

    .line 48
    .line 49
    iput-boolean p1, p0, Lh01/c;->o:Z

    .line 50
    .line 51
    return-void
.end method

.method public static l(Lh01/c;ILd01/k0;IZI)Lh01/c;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    and-int/lit8 v1, p5, 0x1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget v1, v0, Lh01/c;->l:I

    .line 8
    .line 9
    move v14, v1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move/from16 v14, p1

    .line 12
    .line 13
    :goto_0
    and-int/lit8 v1, p5, 0x2

    .line 14
    .line 15
    if-eqz v1, :cond_1

    .line 16
    .line 17
    iget-object v1, v0, Lh01/c;->m:Ld01/k0;

    .line 18
    .line 19
    move-object v15, v1

    .line 20
    goto :goto_1

    .line 21
    :cond_1
    move-object/from16 v15, p2

    .line 22
    .line 23
    :goto_1
    and-int/lit8 v1, p5, 0x4

    .line 24
    .line 25
    if-eqz v1, :cond_2

    .line 26
    .line 27
    iget v1, v0, Lh01/c;->n:I

    .line 28
    .line 29
    move/from16 v16, v1

    .line 30
    .line 31
    goto :goto_2

    .line 32
    :cond_2
    move/from16 v16, p3

    .line 33
    .line 34
    :goto_2
    and-int/lit8 v1, p5, 0x8

    .line 35
    .line 36
    if-eqz v1, :cond_3

    .line 37
    .line 38
    iget-boolean v1, v0, Lh01/c;->o:Z

    .line 39
    .line 40
    move/from16 v17, v1

    .line 41
    .line 42
    goto :goto_3

    .line 43
    :cond_3
    move/from16 v17, p4

    .line 44
    .line 45
    :goto_3
    new-instance v2, Lh01/c;

    .line 46
    .line 47
    iget-object v3, v0, Lh01/c;->a:Lg01/c;

    .line 48
    .line 49
    iget-object v4, v0, Lh01/c;->b:Lh01/q;

    .line 50
    .line 51
    iget v5, v0, Lh01/c;->c:I

    .line 52
    .line 53
    iget v6, v0, Lh01/c;->d:I

    .line 54
    .line 55
    iget v7, v0, Lh01/c;->e:I

    .line 56
    .line 57
    iget v8, v0, Lh01/c;->f:I

    .line 58
    .line 59
    iget-boolean v9, v0, Lh01/c;->g:Z

    .line 60
    .line 61
    iget-object v10, v0, Lh01/c;->h:Lh01/o;

    .line 62
    .line 63
    iget-object v11, v0, Lh01/c;->i:Lh01/r;

    .line 64
    .line 65
    iget-object v12, v0, Lh01/c;->j:Ld01/w0;

    .line 66
    .line 67
    iget-object v13, v0, Lh01/c;->k:Ljava/util/List;

    .line 68
    .line 69
    invoke-direct/range {v2 .. v17}, Lh01/c;-><init>(Lg01/c;Lh01/q;IIIIZLh01/o;Lh01/r;Ld01/w0;Ljava/util/List;ILd01/k0;IZ)V

    .line 70
    .line 71
    .line 72
    return-object v2
.end method


# virtual methods
.method public final a()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lh01/c;->t:Ld01/i0;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public final b()Lh01/p;
    .locals 3

    .line 1
    iget-object v0, p0, Lh01/c;->h:Lh01/o;

    .line 2
    .line 3
    iget-object v0, v0, Lh01/o;->d:Ld01/h0;

    .line 4
    .line 5
    iget-object v0, v0, Ld01/h0;->C:Lbu/c;

    .line 6
    .line 7
    iget-object v1, p0, Lh01/c;->j:Ld01/w0;

    .line 8
    .line 9
    monitor-enter v0

    .line 10
    :try_start_0
    const-string v2, "route"

    .line 11
    .line 12
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iget-object v2, v0, Lbu/c;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v2, Ljava/util/LinkedHashSet;

    .line 18
    .line 19
    invoke-interface {v2, v1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 20
    .line 21
    .line 22
    monitor-exit v0

    .line 23
    iget-object v0, p0, Lh01/c;->v:Lh01/p;

    .line 24
    .line 25
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lh01/c;->j:Ld01/w0;

    .line 29
    .line 30
    const-string v2, "route"

    .line 31
    .line 32
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    iget-object v1, p0, Lh01/c;->i:Lh01/r;

    .line 36
    .line 37
    iget-object v2, p0, Lh01/c;->k:Ljava/util/List;

    .line 38
    .line 39
    invoke-virtual {v1, p0, v2}, Lh01/r;->d(Lh01/c;Ljava/util/List;)Lh01/s;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    if-eqz v1, :cond_0

    .line 44
    .line 45
    iget-object p0, v1, Lh01/s;->a:Lh01/p;

    .line 46
    .line 47
    return-object p0

    .line 48
    :cond_0
    monitor-enter v0

    .line 49
    :try_start_1
    iget-object v1, p0, Lh01/c;->b:Lh01/q;

    .line 50
    .line 51
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    sget-object v2, Le01/g;->a:Ljava/util/TimeZone;

    .line 55
    .line 56
    iget-object v2, v1, Lh01/q;->h:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v2, Ljava/util/concurrent/ConcurrentLinkedQueue;

    .line 59
    .line 60
    invoke-virtual {v2, v0}, Ljava/util/concurrent/ConcurrentLinkedQueue;->add(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    iget-object v2, v1, Lh01/q;->f:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v2, Lg01/b;

    .line 66
    .line 67
    iget-object v1, v1, Lh01/q;->g:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v1, Lf01/e;

    .line 70
    .line 71
    invoke-static {v2, v1}, Lg01/b;->e(Lg01/b;Lg01/a;)V

    .line 72
    .line 73
    .line 74
    iget-object p0, p0, Lh01/c;->h:Lh01/o;

    .line 75
    .line 76
    invoke-virtual {p0, v0}, Lh01/o;->b(Lh01/p;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 77
    .line 78
    .line 79
    monitor-exit v0

    .line 80
    return-object v0

    .line 81
    :catchall_0
    move-exception p0

    .line 82
    monitor-exit v0

    .line 83
    throw p0

    .line 84
    :catchall_1
    move-exception p0

    .line 85
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 86
    throw p0
.end method

.method public final c()V
    .locals 0

    .line 1
    return-void
.end method

.method public final cancel()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lh01/c;->p:Z

    .line 3
    .line 4
    iget-object p0, p0, Lh01/c;->q:Ljava/net/Socket;

    .line 5
    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    invoke-static {p0}, Le01/g;->c(Ljava/net/Socket;)V

    .line 9
    .line 10
    .line 11
    :cond_0
    return-void
.end method

.method public final d()Lh01/t;
    .locals 20

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    const-string v2, "inetSocketAddress"

    .line 4
    .line 5
    iget-object v3, v1, Lh01/c;->b:Lh01/q;

    .line 6
    .line 7
    iget-object v0, v1, Lh01/c;->h:Lh01/o;

    .line 8
    .line 9
    iget-object v4, v0, Lh01/o;->v:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 10
    .line 11
    iget-object v9, v1, Lh01/c;->q:Ljava/net/Socket;

    .line 12
    .line 13
    if-eqz v9, :cond_13

    .line 14
    .line 15
    invoke-virtual {v1}, Lh01/c;->a()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-nez v0, :cond_12

    .line 20
    .line 21
    iget-object v0, v1, Lh01/c;->j:Ld01/w0;

    .line 22
    .line 23
    iget-object v5, v0, Ld01/w0;->a:Ld01/a;

    .line 24
    .line 25
    iget-object v14, v0, Ld01/w0;->c:Ljava/net/InetSocketAddress;

    .line 26
    .line 27
    iget-object v0, v0, Ld01/w0;->a:Ld01/a;

    .line 28
    .line 29
    iget-object v5, v5, Ld01/a;->j:Ljava/util/List;

    .line 30
    .line 31
    invoke-virtual {v4, v1}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    const/4 v6, 0x0

    .line 35
    :try_start_0
    iget-object v7, v1, Lh01/c;->m:Ld01/k0;

    .line 36
    .line 37
    if-eqz v7, :cond_2

    .line 38
    .line 39
    invoke-virtual {v1}, Lh01/c;->k()Lh01/t;

    .line 40
    .line 41
    .line 42
    move-result-object v7

    .line 43
    iget-object v8, v7, Lh01/t;->b:Lh01/u;

    .line 44
    .line 45
    if-nez v8, :cond_0

    .line 46
    .line 47
    iget-object v8, v7, Lh01/t;->c:Ljava/lang/Throwable;
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 48
    .line 49
    if-eqz v8, :cond_2

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :catchall_0
    move-exception v0

    .line 53
    const/4 v15, 0x0

    .line 54
    goto/16 :goto_9

    .line 55
    .line 56
    :catch_0
    move-exception v0

    .line 57
    move-object v15, v6

    .line 58
    :goto_0
    const/16 v19, 0x0

    .line 59
    .line 60
    goto/16 :goto_5

    .line 61
    .line 62
    :cond_0
    :goto_1
    invoke-virtual {v4, v1}, Ljava/util/concurrent/CopyOnWriteArrayList;->remove(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    iget-object v0, v1, Lh01/c;->r:Ljava/net/Socket;

    .line 66
    .line 67
    if-eqz v0, :cond_1

    .line 68
    .line 69
    invoke-static {v0}, Le01/g;->c(Ljava/net/Socket;)V

    .line 70
    .line 71
    .line 72
    :cond_1
    invoke-static {v9}, Le01/g;->c(Ljava/net/Socket;)V

    .line 73
    .line 74
    .line 75
    return-object v7

    .line 76
    :cond_2
    :try_start_1
    iget-object v7, v0, Ld01/a;->c:Ljavax/net/ssl/SSLSocketFactory;
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 77
    .line 78
    const/4 v8, 0x1

    .line 79
    const-string v10, "socket"

    .line 80
    .line 81
    if-eqz v7, :cond_6

    .line 82
    .line 83
    :try_start_2
    iget-object v7, v1, Lh01/c;->u:Lgw0/c;

    .line 84
    .line 85
    if-eqz v7, :cond_5

    .line 86
    .line 87
    iget-object v7, v7, Lgw0/c;->f:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast v7, Lu01/b0;

    .line 90
    .line 91
    iget-object v7, v7, Lu01/b0;->e:Lu01/f;

    .line 92
    .line 93
    invoke-virtual {v7}, Lu01/f;->Z()Z

    .line 94
    .line 95
    .line 96
    move-result v7

    .line 97
    if-eqz v7, :cond_4

    .line 98
    .line 99
    iget-object v7, v1, Lh01/c;->u:Lgw0/c;

    .line 100
    .line 101
    if-eqz v7, :cond_3

    .line 102
    .line 103
    iget-object v7, v7, Lgw0/c;->g:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast v7, Lu01/a0;

    .line 106
    .line 107
    iget-object v7, v7, Lu01/a0;->e:Lu01/f;

    .line 108
    .line 109
    invoke-virtual {v7}, Lu01/f;->Z()Z

    .line 110
    .line 111
    .line 112
    move-result v7

    .line 113
    if-eqz v7, :cond_4

    .line 114
    .line 115
    iget-object v7, v0, Ld01/a;->c:Ljavax/net/ssl/SSLSocketFactory;

    .line 116
    .line 117
    iget-object v0, v0, Ld01/a;->h:Ld01/a0;

    .line 118
    .line 119
    iget-object v11, v0, Ld01/a0;->d:Ljava/lang/String;

    .line 120
    .line 121
    iget v0, v0, Ld01/a0;->e:I

    .line 122
    .line 123
    invoke-virtual {v7, v9, v11, v0, v8}, Ljavax/net/ssl/SSLSocketFactory;->createSocket(Ljava/net/Socket;Ljava/lang/String;IZ)Ljava/net/Socket;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    const-string v7, "null cannot be cast to non-null type javax.net.ssl.SSLSocket"

    .line 128
    .line 129
    invoke-static {v0, v7}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    check-cast v0, Ljavax/net/ssl/SSLSocket;

    .line 133
    .line 134
    invoke-virtual {v1, v5, v0}, Lh01/c;->n(Ljava/util/List;Ljavax/net/ssl/SSLSocket;)Lh01/c;

    .line 135
    .line 136
    .line 137
    move-result-object v7

    .line 138
    iget v11, v7, Lh01/c;->n:I

    .line 139
    .line 140
    invoke-interface {v5, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v11

    .line 144
    check-cast v11, Ld01/p;

    .line 145
    .line 146
    invoke-virtual {v7, v5, v0}, Lh01/c;->m(Ljava/util/List;Ljavax/net/ssl/SSLSocket;)Lh01/c;

    .line 147
    .line 148
    .line 149
    move-result-object v5
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 150
    :try_start_3
    iget-boolean v7, v7, Lh01/c;->o:Z

    .line 151
    .line 152
    invoke-virtual {v11, v0, v7}, Ld01/p;->a(Ljavax/net/ssl/SSLSocket;Z)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v1, v0, v11}, Lh01/c;->j(Ljavax/net/ssl/SSLSocket;Ld01/p;)V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_1
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 156
    .line 157
    .line 158
    move-object/from16 v16, v5

    .line 159
    .line 160
    goto :goto_3

    .line 161
    :catch_1
    move-exception v0

    .line 162
    move-object v15, v6

    .line 163
    const/16 v19, 0x0

    .line 164
    .line 165
    move-object v6, v5

    .line 166
    goto/16 :goto_5

    .line 167
    .line 168
    :cond_3
    :try_start_4
    invoke-static {v10}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    throw v6

    .line 172
    :cond_4
    new-instance v0, Ljava/io/IOException;

    .line 173
    .line 174
    const-string v5, "TLS tunnel buffered too many bytes!"

    .line 175
    .line 176
    invoke-direct {v0, v5}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    throw v0

    .line 180
    :cond_5
    invoke-static {v10}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    throw v6

    .line 184
    :cond_6
    iput-object v9, v1, Lh01/c;->r:Ljava/net/Socket;

    .line 185
    .line 186
    iget-object v0, v0, Ld01/a;->i:Ljava/util/List;

    .line 187
    .line 188
    sget-object v5, Ld01/i0;->j:Ld01/i0;

    .line 189
    .line 190
    invoke-interface {v0, v5}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 191
    .line 192
    .line 193
    move-result v0

    .line 194
    if-eqz v0, :cond_7

    .line 195
    .line 196
    goto :goto_2

    .line 197
    :cond_7
    sget-object v5, Ld01/i0;->g:Ld01/i0;

    .line 198
    .line 199
    :goto_2
    iput-object v5, v1, Lh01/c;->t:Ld01/i0;
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 200
    .line 201
    move-object/from16 v16, v6

    .line 202
    .line 203
    :goto_3
    :try_start_5
    new-instance v5, Lh01/p;
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_8
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 204
    .line 205
    move-object v7, v6

    .line 206
    :try_start_6
    iget-object v6, v1, Lh01/c;->a:Lg01/c;
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_7
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 207
    .line 208
    move-object v11, v7

    .line 209
    :try_start_7
    iget-object v7, v1, Lh01/c;->b:Lh01/q;

    .line 210
    .line 211
    move v12, v8

    .line 212
    iget-object v8, v1, Lh01/c;->j:Ld01/w0;

    .line 213
    .line 214
    move-object v0, v10

    .line 215
    iget-object v10, v1, Lh01/c;->r:Ljava/net/Socket;

    .line 216
    .line 217
    invoke-static {v10}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V
    :try_end_7
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_7} :catch_6
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 218
    .line 219
    .line 220
    move-object v13, v11

    .line 221
    :try_start_8
    iget-object v11, v1, Lh01/c;->s:Ld01/w;

    .line 222
    .line 223
    move/from16 v17, v12

    .line 224
    .line 225
    iget-object v12, v1, Lh01/c;->t:Ld01/i0;

    .line 226
    .line 227
    invoke-static {v12}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V
    :try_end_8
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_5
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 228
    .line 229
    .line 230
    move-object/from16 v18, v13

    .line 231
    .line 232
    :try_start_9
    iget-object v13, v1, Lh01/c;->u:Lgw0/c;

    .line 233
    .line 234
    if-eqz v13, :cond_8

    .line 235
    .line 236
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_9
    .catch Ljava/io/IOException; {:try_start_9 .. :try_end_9} :catch_4
    .catchall {:try_start_9 .. :try_end_9} :catchall_0

    .line 237
    .line 238
    .line 239
    move-object/from16 v15, v18

    .line 240
    .line 241
    :try_start_a
    invoke-direct/range {v5 .. v13}, Lh01/p;-><init>(Lg01/c;Lh01/q;Ld01/w0;Ljava/net/Socket;Ljava/net/Socket;Ld01/w;Ld01/i0;Lgw0/c;)V

    .line 242
    .line 243
    .line 244
    iput-object v5, v1, Lh01/c;->v:Lh01/p;

    .line 245
    .line 246
    invoke-virtual {v5}, Lh01/p;->i()V

    .line 247
    .line 248
    .line 249
    invoke-static {v14, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_a
    .catch Ljava/io/IOException; {:try_start_a .. :try_end_a} :catch_3
    .catchall {:try_start_a .. :try_end_a} :catchall_0

    .line 250
    .line 251
    .line 252
    :try_start_b
    new-instance v0, Lh01/t;

    .line 253
    .line 254
    const/4 v5, 0x6

    .line 255
    invoke-direct {v0, v1, v15, v15, v5}, Lh01/t;-><init>(Lh01/u;Lh01/c;Ljava/lang/Throwable;I)V
    :try_end_b
    .catch Ljava/io/IOException; {:try_start_b .. :try_end_b} :catch_2
    .catchall {:try_start_b .. :try_end_b} :catchall_1

    .line 256
    .line 257
    .line 258
    invoke-virtual {v4, v1}, Ljava/util/concurrent/CopyOnWriteArrayList;->remove(Ljava/lang/Object;)Z

    .line 259
    .line 260
    .line 261
    return-object v0

    .line 262
    :catchall_1
    move-exception v0

    .line 263
    move/from16 v15, v17

    .line 264
    .line 265
    goto/16 :goto_9

    .line 266
    .line 267
    :catch_2
    move-exception v0

    .line 268
    move-object/from16 v6, v16

    .line 269
    .line 270
    move/from16 v19, v17

    .line 271
    .line 272
    goto :goto_5

    .line 273
    :catch_3
    move-exception v0

    .line 274
    :goto_4
    move-object/from16 v6, v16

    .line 275
    .line 276
    goto/16 :goto_0

    .line 277
    .line 278
    :catch_4
    move-exception v0

    .line 279
    move-object/from16 v15, v18

    .line 280
    .line 281
    goto :goto_4

    .line 282
    :cond_8
    move-object/from16 v15, v18

    .line 283
    .line 284
    :try_start_c
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 285
    .line 286
    .line 287
    throw v15
    :try_end_c
    .catch Ljava/io/IOException; {:try_start_c .. :try_end_c} :catch_3
    .catchall {:try_start_c .. :try_end_c} :catchall_0

    .line 288
    :catch_5
    move-exception v0

    .line 289
    move-object v15, v13

    .line 290
    goto :goto_4

    .line 291
    :catch_6
    move-exception v0

    .line 292
    move-object v15, v11

    .line 293
    goto :goto_4

    .line 294
    :catch_7
    move-exception v0

    .line 295
    move-object v15, v7

    .line 296
    goto :goto_4

    .line 297
    :catch_8
    move-exception v0

    .line 298
    move-object v15, v6

    .line 299
    goto :goto_4

    .line 300
    :goto_5
    :try_start_d
    invoke-static {v14, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 301
    .line 302
    .line 303
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 304
    .line 305
    .line 306
    iget-boolean v2, v1, Lh01/c;->g:Z

    .line 307
    .line 308
    if-eqz v2, :cond_d

    .line 309
    .line 310
    instance-of v2, v0, Ljava/net/ProtocolException;

    .line 311
    .line 312
    if-eqz v2, :cond_9

    .line 313
    .line 314
    goto :goto_7

    .line 315
    :cond_9
    instance-of v2, v0, Ljava/io/InterruptedIOException;

    .line 316
    .line 317
    if-eqz v2, :cond_a

    .line 318
    .line 319
    goto :goto_7

    .line 320
    :cond_a
    instance-of v2, v0, Ljavax/net/ssl/SSLHandshakeException;

    .line 321
    .line 322
    if-eqz v2, :cond_b

    .line 323
    .line 324
    invoke-virtual {v0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 325
    .line 326
    .line 327
    move-result-object v2

    .line 328
    instance-of v2, v2, Ljava/security/cert/CertificateException;

    .line 329
    .line 330
    if-eqz v2, :cond_b

    .line 331
    .line 332
    goto :goto_7

    .line 333
    :cond_b
    instance-of v2, v0, Ljavax/net/ssl/SSLPeerUnverifiedException;

    .line 334
    .line 335
    if-eqz v2, :cond_c

    .line 336
    .line 337
    goto :goto_7

    .line 338
    :cond_c
    instance-of v2, v0, Ljavax/net/ssl/SSLException;

    .line 339
    .line 340
    if-eqz v2, :cond_d

    .line 341
    .line 342
    goto :goto_8

    .line 343
    :goto_6
    move/from16 v15, v19

    .line 344
    .line 345
    goto :goto_9

    .line 346
    :cond_d
    :goto_7
    move-object v6, v15

    .line 347
    :goto_8
    new-instance v2, Lh01/t;

    .line 348
    .line 349
    invoke-direct {v2, v1, v6, v0}, Lh01/t;-><init>(Lh01/u;Lh01/u;Ljava/lang/Throwable;)V
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_2

    .line 350
    .line 351
    .line 352
    invoke-virtual {v4, v1}, Ljava/util/concurrent/CopyOnWriteArrayList;->remove(Ljava/lang/Object;)Z

    .line 353
    .line 354
    .line 355
    if-nez v19, :cond_f

    .line 356
    .line 357
    iget-object v0, v1, Lh01/c;->r:Ljava/net/Socket;

    .line 358
    .line 359
    if-eqz v0, :cond_e

    .line 360
    .line 361
    invoke-static {v0}, Le01/g;->c(Ljava/net/Socket;)V

    .line 362
    .line 363
    .line 364
    :cond_e
    invoke-static {v9}, Le01/g;->c(Ljava/net/Socket;)V

    .line 365
    .line 366
    .line 367
    :cond_f
    return-object v2

    .line 368
    :catchall_2
    move-exception v0

    .line 369
    goto :goto_6

    .line 370
    :goto_9
    invoke-virtual {v4, v1}, Ljava/util/concurrent/CopyOnWriteArrayList;->remove(Ljava/lang/Object;)Z

    .line 371
    .line 372
    .line 373
    if-nez v15, :cond_11

    .line 374
    .line 375
    iget-object v1, v1, Lh01/c;->r:Ljava/net/Socket;

    .line 376
    .line 377
    if-eqz v1, :cond_10

    .line 378
    .line 379
    invoke-static {v1}, Le01/g;->c(Ljava/net/Socket;)V

    .line 380
    .line 381
    .line 382
    :cond_10
    invoke-static {v9}, Le01/g;->c(Ljava/net/Socket;)V

    .line 383
    .line 384
    .line 385
    :cond_11
    throw v0

    .line 386
    :cond_12
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 387
    .line 388
    const-string v1, "already connected"

    .line 389
    .line 390
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 391
    .line 392
    .line 393
    throw v0

    .line 394
    :cond_13
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 395
    .line 396
    const-string v1, "TCP not connected"

    .line 397
    .line 398
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 399
    .line 400
    .line 401
    throw v0
.end method

.method public final e()Ld01/w0;
    .locals 0

    .line 1
    iget-object p0, p0, Lh01/c;->j:Ld01/w0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final f()Lh01/u;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Lh01/c;

    .line 4
    .line 5
    iget v14, v0, Lh01/c;->n:I

    .line 6
    .line 7
    iget-boolean v15, v0, Lh01/c;->o:Z

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    iget-object v1, v0, Lh01/c;->a:Lg01/c;

    .line 11
    .line 12
    move-object v3, v2

    .line 13
    iget-object v2, v0, Lh01/c;->b:Lh01/q;

    .line 14
    .line 15
    move-object v4, v3

    .line 16
    iget v3, v0, Lh01/c;->c:I

    .line 17
    .line 18
    move-object v5, v4

    .line 19
    iget v4, v0, Lh01/c;->d:I

    .line 20
    .line 21
    move-object v6, v5

    .line 22
    iget v5, v0, Lh01/c;->e:I

    .line 23
    .line 24
    move-object v7, v6

    .line 25
    iget v6, v0, Lh01/c;->f:I

    .line 26
    .line 27
    move-object v8, v7

    .line 28
    iget-boolean v7, v0, Lh01/c;->g:Z

    .line 29
    .line 30
    move-object v9, v8

    .line 31
    iget-object v8, v0, Lh01/c;->h:Lh01/o;

    .line 32
    .line 33
    move-object v10, v9

    .line 34
    iget-object v9, v0, Lh01/c;->i:Lh01/r;

    .line 35
    .line 36
    move-object v11, v10

    .line 37
    iget-object v10, v0, Lh01/c;->j:Ld01/w0;

    .line 38
    .line 39
    move-object v12, v11

    .line 40
    iget-object v11, v0, Lh01/c;->k:Ljava/util/List;

    .line 41
    .line 42
    move-object v13, v12

    .line 43
    iget v12, v0, Lh01/c;->l:I

    .line 44
    .line 45
    iget-object v0, v0, Lh01/c;->m:Ld01/k0;

    .line 46
    .line 47
    move-object/from16 v16, v13

    .line 48
    .line 49
    move-object v13, v0

    .line 50
    move-object/from16 v0, v16

    .line 51
    .line 52
    invoke-direct/range {v0 .. v15}, Lh01/c;-><init>(Lg01/c;Lh01/q;IIIIZLh01/o;Lh01/r;Ld01/w0;Ljava/util/List;ILd01/k0;IZ)V

    .line 53
    .line 54
    .line 55
    return-object v0
.end method

.method public final g()Lh01/t;
    .locals 10

    .line 1
    const-string v0, "inetSocketAddress"

    .line 2
    .line 3
    iget-object v1, p0, Lh01/c;->b:Lh01/q;

    .line 4
    .line 5
    iget-object v2, p0, Lh01/c;->j:Ld01/w0;

    .line 6
    .line 7
    iget-object v3, p0, Lh01/c;->h:Lh01/o;

    .line 8
    .line 9
    iget-object v3, v3, Lh01/o;->v:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 10
    .line 11
    iget-object v4, p0, Lh01/c;->q:Ljava/net/Socket;

    .line 12
    .line 13
    if-nez v4, :cond_3

    .line 14
    .line 15
    invoke-virtual {v3, p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    const/4 v4, 0x0

    .line 19
    const/4 v5, 0x0

    .line 20
    :try_start_0
    iget-object v6, v2, Ld01/w0;->c:Ljava/net/InetSocketAddress;

    .line 21
    .line 22
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0}, Lh01/c;->i()V

    .line 29
    .line 30
    .line 31
    const/4 v5, 0x1

    .line 32
    new-instance v6, Lh01/t;

    .line 33
    .line 34
    const/4 v7, 0x6

    .line 35
    invoke-direct {v6, p0, v4, v4, v7}, Lh01/t;-><init>(Lh01/u;Lh01/c;Ljava/lang/Throwable;I)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 36
    .line 37
    .line 38
    invoke-virtual {v3, p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->remove(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    return-object v6

    .line 42
    :catchall_0
    move-exception v0

    .line 43
    goto :goto_0

    .line 44
    :catch_0
    move-exception v6

    .line 45
    :try_start_1
    iget-object v7, v2, Ld01/w0;->a:Ld01/a;

    .line 46
    .line 47
    iget-object v7, v2, Ld01/w0;->b:Ljava/net/Proxy;

    .line 48
    .line 49
    invoke-virtual {v7}, Ljava/net/Proxy;->type()Ljava/net/Proxy$Type;

    .line 50
    .line 51
    .line 52
    move-result-object v7

    .line 53
    sget-object v8, Ljava/net/Proxy$Type;->DIRECT:Ljava/net/Proxy$Type;

    .line 54
    .line 55
    if-eq v7, v8, :cond_0

    .line 56
    .line 57
    iget-object v7, v2, Ld01/w0;->a:Ld01/a;

    .line 58
    .line 59
    iget-object v8, v7, Ld01/a;->g:Ljava/net/ProxySelector;

    .line 60
    .line 61
    iget-object v7, v7, Ld01/a;->h:Ld01/a0;

    .line 62
    .line 63
    invoke-virtual {v7}, Ld01/a0;->j()Ljava/net/URI;

    .line 64
    .line 65
    .line 66
    move-result-object v7

    .line 67
    iget-object v9, v2, Ld01/w0;->b:Ljava/net/Proxy;

    .line 68
    .line 69
    invoke-virtual {v9}, Ljava/net/Proxy;->address()Ljava/net/SocketAddress;

    .line 70
    .line 71
    .line 72
    move-result-object v9

    .line 73
    invoke-virtual {v8, v7, v9, v6}, Ljava/net/ProxySelector;->connectFailed(Ljava/net/URI;Ljava/net/SocketAddress;Ljava/io/IOException;)V

    .line 74
    .line 75
    .line 76
    :cond_0
    iget-object v2, v2, Ld01/w0;->c:Ljava/net/InetSocketAddress;

    .line 77
    .line 78
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    new-instance v0, Lh01/t;

    .line 85
    .line 86
    const/4 v1, 0x2

    .line 87
    invoke-direct {v0, p0, v4, v6, v1}, Lh01/t;-><init>(Lh01/u;Lh01/c;Ljava/lang/Throwable;I)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 88
    .line 89
    .line 90
    invoke-virtual {v3, p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->remove(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    if-nez v5, :cond_1

    .line 94
    .line 95
    iget-object p0, p0, Lh01/c;->q:Ljava/net/Socket;

    .line 96
    .line 97
    if-eqz p0, :cond_1

    .line 98
    .line 99
    invoke-static {p0}, Le01/g;->c(Ljava/net/Socket;)V

    .line 100
    .line 101
    .line 102
    :cond_1
    return-object v0

    .line 103
    :goto_0
    invoke-virtual {v3, p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->remove(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    if-nez v5, :cond_2

    .line 107
    .line 108
    iget-object p0, p0, Lh01/c;->q:Ljava/net/Socket;

    .line 109
    .line 110
    if-eqz p0, :cond_2

    .line 111
    .line 112
    invoke-static {p0}, Le01/g;->c(Ljava/net/Socket;)V

    .line 113
    .line 114
    .line 115
    :cond_2
    throw v0

    .line 116
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 117
    .line 118
    const-string v0, "TCP already connected"

    .line 119
    .line 120
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    throw p0
.end method

.method public final h(Lh01/o;Ljava/io/IOException;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final i()V
    .locals 4

    .line 1
    iget-object v0, p0, Lh01/c;->j:Ld01/w0;

    .line 2
    .line 3
    iget-object v0, v0, Ld01/w0;->b:Ljava/net/Proxy;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/net/Proxy;->type()Ljava/net/Proxy$Type;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    const/4 v0, -0x1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    sget-object v1, Lh01/b;->a:[I

    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    aget v0, v1, v0

    .line 20
    .line 21
    :goto_0
    const/4 v1, 0x1

    .line 22
    if-eq v0, v1, :cond_1

    .line 23
    .line 24
    const/4 v1, 0x2

    .line 25
    if-eq v0, v1, :cond_1

    .line 26
    .line 27
    new-instance v0, Ljava/net/Socket;

    .line 28
    .line 29
    iget-object v1, p0, Lh01/c;->j:Ld01/w0;

    .line 30
    .line 31
    iget-object v1, v1, Ld01/w0;->b:Ljava/net/Proxy;

    .line 32
    .line 33
    invoke-direct {v0, v1}, Ljava/net/Socket;-><init>(Ljava/net/Proxy;)V

    .line 34
    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    iget-object v0, p0, Lh01/c;->j:Ld01/w0;

    .line 38
    .line 39
    iget-object v0, v0, Ld01/w0;->a:Ld01/a;

    .line 40
    .line 41
    iget-object v0, v0, Ld01/a;->b:Ljavax/net/SocketFactory;

    .line 42
    .line 43
    invoke-virtual {v0}, Ljavax/net/SocketFactory;->createSocket()Ljava/net/Socket;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    :goto_1
    iput-object v0, p0, Lh01/c;->q:Ljava/net/Socket;

    .line 51
    .line 52
    iget-boolean v1, p0, Lh01/c;->p:Z

    .line 53
    .line 54
    if-nez v1, :cond_3

    .line 55
    .line 56
    iget v1, p0, Lh01/c;->f:I

    .line 57
    .line 58
    invoke-virtual {v0, v1}, Ljava/net/Socket;->setSoTimeout(I)V

    .line 59
    .line 60
    .line 61
    :try_start_0
    sget-object v1, Ln01/d;->a:Ln01/b;

    .line 62
    .line 63
    sget-object v1, Ln01/d;->a:Ln01/b;

    .line 64
    .line 65
    iget-object v2, p0, Lh01/c;->j:Ld01/w0;

    .line 66
    .line 67
    iget-object v2, v2, Ld01/w0;->c:Ljava/net/InetSocketAddress;

    .line 68
    .line 69
    iget v3, p0, Lh01/c;->e:I

    .line 70
    .line 71
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 72
    .line 73
    .line 74
    const-string v1, "address"

    .line 75
    .line 76
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    invoke-virtual {v0, v2, v3}, Ljava/net/Socket;->connect(Ljava/net/SocketAddress;I)V
    :try_end_0
    .catch Ljava/net/ConnectException; {:try_start_0 .. :try_end_0} :catch_1

    .line 80
    .line 81
    .line 82
    :try_start_1
    new-instance v1, Lun/a;

    .line 83
    .line 84
    invoke-direct {v1, v0}, Lun/a;-><init>(Ljava/net/Socket;)V

    .line 85
    .line 86
    .line 87
    new-instance v0, Lgw0/c;

    .line 88
    .line 89
    invoke-direct {v0, v1}, Lgw0/c;-><init>(Lu01/g0;)V

    .line 90
    .line 91
    .line 92
    iput-object v0, p0, Lh01/c;->u:Lgw0/c;
    :try_end_1
    .catch Ljava/lang/NullPointerException; {:try_start_1 .. :try_end_1} :catch_0

    .line 93
    .line 94
    return-void

    .line 95
    :catch_0
    move-exception p0

    .line 96
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    const-string v1, "throw with null exception"

    .line 101
    .line 102
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v0

    .line 106
    if-nez v0, :cond_2

    .line 107
    .line 108
    return-void

    .line 109
    :cond_2
    new-instance v0, Ljava/io/IOException;

    .line 110
    .line 111
    invoke-direct {v0, p0}, Ljava/io/IOException;-><init>(Ljava/lang/Throwable;)V

    .line 112
    .line 113
    .line 114
    throw v0

    .line 115
    :catch_1
    move-exception v0

    .line 116
    new-instance v1, Ljava/net/ConnectException;

    .line 117
    .line 118
    new-instance v2, Ljava/lang/StringBuilder;

    .line 119
    .line 120
    const-string v3, "Failed to connect to "

    .line 121
    .line 122
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    iget-object p0, p0, Lh01/c;->j:Ld01/w0;

    .line 126
    .line 127
    iget-object p0, p0, Ld01/w0;->c:Ljava/net/InetSocketAddress;

    .line 128
    .line 129
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    invoke-direct {v1, p0}, Ljava/net/ConnectException;-><init>(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    invoke-virtual {v1, v0}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    .line 140
    .line 141
    .line 142
    throw v1

    .line 143
    :cond_3
    new-instance p0, Ljava/io/IOException;

    .line 144
    .line 145
    const-string v0, "canceled"

    .line 146
    .line 147
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    throw p0
.end method

.method public final j(Ljavax/net/ssl/SSLSocket;Ld01/p;)V
    .locals 10

    .line 1
    iget-object v0, p0, Lh01/c;->j:Ld01/w0;

    .line 2
    .line 3
    iget-object v0, v0, Ld01/w0;->a:Ld01/a;

    .line 4
    .line 5
    :try_start_0
    iget-boolean v1, p2, Ld01/p;->b:Z

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_2

    .line 9
    .line 10
    sget-object v1, Ln01/d;->a:Ln01/b;

    .line 11
    .line 12
    sget-object v1, Ln01/d;->a:Ln01/b;

    .line 13
    .line 14
    iget-object v3, v0, Ld01/a;->h:Ld01/a0;

    .line 15
    .line 16
    iget-object v3, v3, Ld01/a0;->d:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v4, v0, Ld01/a;->i:Ljava/util/List;

    .line 19
    .line 20
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    const-string v5, "protocols"

    .line 24
    .line 25
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    iget-object v1, v1, Ln01/b;->d:Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    :cond_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    if-eqz v5, :cond_1

    .line 39
    .line 40
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v5

    .line 44
    move-object v6, v5

    .line 45
    check-cast v6, Lo01/n;

    .line 46
    .line 47
    invoke-interface {v6, p1}, Lo01/n;->a(Ljavax/net/ssl/SSLSocket;)Z

    .line 48
    .line 49
    .line 50
    move-result v6

    .line 51
    if-eqz v6, :cond_0

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_1
    move-object v5, v2

    .line 55
    :goto_0
    check-cast v5, Lo01/n;

    .line 56
    .line 57
    if-eqz v5, :cond_2

    .line 58
    .line 59
    invoke-interface {v5, p1, v3, v4}, Lo01/n;->d(Ljavax/net/ssl/SSLSocket;Ljava/lang/String;Ljava/util/List;)V

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :catchall_0
    move-exception p0

    .line 64
    goto/16 :goto_4

    .line 65
    .line 66
    :cond_2
    :goto_1
    invoke-virtual {p1}, Ljavax/net/ssl/SSLSocket;->startHandshake()V

    .line 67
    .line 68
    .line 69
    invoke-virtual {p1}, Ljavax/net/ssl/SSLSocket;->getSession()Ljavax/net/ssl/SSLSession;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    invoke-static {v1}, Ljp/se;->a(Ljavax/net/ssl/SSLSession;)Ld01/w;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    iget-object v4, v0, Ld01/a;->d:Ljavax/net/ssl/HostnameVerifier;

    .line 81
    .line 82
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    iget-object v5, v0, Ld01/a;->h:Ld01/a0;

    .line 86
    .line 87
    iget-object v5, v5, Ld01/a0;->d:Ljava/lang/String;

    .line 88
    .line 89
    invoke-interface {v4, v5, v1}, Ljavax/net/ssl/HostnameVerifier;->verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    if-nez v1, :cond_4

    .line 94
    .line 95
    invoke-virtual {v3}, Ld01/w;->a()Ljava/util/List;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    move-object p2, p0

    .line 100
    check-cast p2, Ljava/util/Collection;

    .line 101
    .line 102
    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    .line 103
    .line 104
    .line 105
    move-result p2

    .line 106
    if-nez p2, :cond_3

    .line 107
    .line 108
    const/4 p2, 0x0

    .line 109
    invoke-interface {p0, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    const-string p2, "null cannot be cast to non-null type java.security.cert.X509Certificate"

    .line 114
    .line 115
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    check-cast p0, Ljava/security/cert/X509Certificate;

    .line 119
    .line 120
    new-instance p2, Ljavax/net/ssl/SSLPeerUnverifiedException;

    .line 121
    .line 122
    new-instance v1, Ljava/lang/StringBuilder;

    .line 123
    .line 124
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 125
    .line 126
    .line 127
    const-string v2, "\n            |Hostname "

    .line 128
    .line 129
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    iget-object v0, v0, Ld01/a;->h:Ld01/a0;

    .line 133
    .line 134
    iget-object v0, v0, Ld01/a0;->d:Ljava/lang/String;

    .line 135
    .line 136
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 137
    .line 138
    .line 139
    const-string v0, " not verified:\n            |    certificate: "

    .line 140
    .line 141
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    sget-object v0, Ld01/l;->c:Ld01/l;

    .line 145
    .line 146
    new-instance v0, Ljava/lang/StringBuilder;

    .line 147
    .line 148
    const-string v2, "sha256/"

    .line 149
    .line 150
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    sget-object v2, Lu01/i;->g:Lu01/i;

    .line 154
    .line 155
    invoke-virtual {p0}, Ljava/security/cert/Certificate;->getPublicKey()Ljava/security/PublicKey;

    .line 156
    .line 157
    .line 158
    move-result-object v2

    .line 159
    invoke-interface {v2}, Ljava/security/Key;->getEncoded()[B

    .line 160
    .line 161
    .line 162
    move-result-object v2

    .line 163
    const-string v3, "getEncoded(...)"

    .line 164
    .line 165
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    const v3, -0x499602d2

    .line 169
    .line 170
    .line 171
    invoke-static {v3, v2}, Lpy/a;->s(I[B)Lu01/i;

    .line 172
    .line 173
    .line 174
    move-result-object v2

    .line 175
    const-string v3, "SHA-256"

    .line 176
    .line 177
    invoke-virtual {v2, v3}, Lu01/i;->c(Ljava/lang/String;)Lu01/i;

    .line 178
    .line 179
    .line 180
    move-result-object v2

    .line 181
    invoke-virtual {v2}, Lu01/i;->a()Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v2

    .line 185
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 186
    .line 187
    .line 188
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 189
    .line 190
    .line 191
    move-result-object v0

    .line 192
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 193
    .line 194
    .line 195
    const-string v0, "\n            |    DN: "

    .line 196
    .line 197
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 198
    .line 199
    .line 200
    invoke-virtual {p0}, Ljava/security/cert/X509Certificate;->getSubjectDN()Ljava/security/Principal;

    .line 201
    .line 202
    .line 203
    move-result-object v0

    .line 204
    invoke-interface {v0}, Ljava/security/Principal;->getName()Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object v0

    .line 208
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 209
    .line 210
    .line 211
    const-string v0, "\n            |    subjectAltNames: "

    .line 212
    .line 213
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 214
    .line 215
    .line 216
    const/4 v0, 0x7

    .line 217
    invoke-static {p0, v0}, Lr01/c;->a(Ljava/security/cert/X509Certificate;I)Ljava/util/List;

    .line 218
    .line 219
    .line 220
    move-result-object v0

    .line 221
    const/4 v2, 0x2

    .line 222
    invoke-static {p0, v2}, Lr01/c;->a(Ljava/security/cert/X509Certificate;I)Ljava/util/List;

    .line 223
    .line 224
    .line 225
    move-result-object p0

    .line 226
    check-cast v0, Ljava/util/Collection;

    .line 227
    .line 228
    check-cast p0, Ljava/lang/Iterable;

    .line 229
    .line 230
    invoke-static {p0, v0}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 231
    .line 232
    .line 233
    move-result-object p0

    .line 234
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 235
    .line 236
    .line 237
    const-string p0, "\n            "

    .line 238
    .line 239
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 240
    .line 241
    .line 242
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 243
    .line 244
    .line 245
    move-result-object p0

    .line 246
    invoke-static {p0}, Lly0/q;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 247
    .line 248
    .line 249
    move-result-object p0

    .line 250
    invoke-direct {p2, p0}, Ljavax/net/ssl/SSLPeerUnverifiedException;-><init>(Ljava/lang/String;)V

    .line 251
    .line 252
    .line 253
    throw p2

    .line 254
    :cond_3
    new-instance p0, Ljavax/net/ssl/SSLPeerUnverifiedException;

    .line 255
    .line 256
    new-instance p2, Ljava/lang/StringBuilder;

    .line 257
    .line 258
    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    .line 259
    .line 260
    .line 261
    const-string v1, "Hostname "

    .line 262
    .line 263
    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 264
    .line 265
    .line 266
    iget-object v0, v0, Ld01/a;->h:Ld01/a0;

    .line 267
    .line 268
    iget-object v0, v0, Ld01/a0;->d:Ljava/lang/String;

    .line 269
    .line 270
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 271
    .line 272
    .line 273
    const-string v0, " not verified (no certificates)"

    .line 274
    .line 275
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 276
    .line 277
    .line 278
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 279
    .line 280
    .line 281
    move-result-object p2

    .line 282
    invoke-direct {p0, p2}, Ljavax/net/ssl/SSLPeerUnverifiedException;-><init>(Ljava/lang/String;)V

    .line 283
    .line 284
    .line 285
    throw p0

    .line 286
    :cond_4
    iget-object v1, v0, Ld01/a;->e:Ld01/l;

    .line 287
    .line 288
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 289
    .line 290
    .line 291
    new-instance v4, Ld01/w;

    .line 292
    .line 293
    iget-object v5, v3, Ld01/w;->a:Ld01/x0;

    .line 294
    .line 295
    iget-object v6, v3, Ld01/w;->b:Ld01/n;

    .line 296
    .line 297
    iget-object v7, v3, Ld01/w;->c:Ljava/util/List;

    .line 298
    .line 299
    new-instance v8, Lc41/b;

    .line 300
    .line 301
    const/4 v9, 0x5

    .line 302
    invoke-direct {v8, v1, v3, v0, v9}, Lc41/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 303
    .line 304
    .line 305
    invoke-direct {v4, v5, v6, v7, v8}, Ld01/w;-><init>(Ld01/x0;Ld01/n;Ljava/util/List;Lay0/a;)V

    .line 306
    .line 307
    .line 308
    iput-object v4, p0, Lh01/c;->s:Ld01/w;

    .line 309
    .line 310
    iget-object v0, v0, Ld01/a;->h:Ld01/a0;

    .line 311
    .line 312
    iget-object v0, v0, Ld01/a0;->d:Ljava/lang/String;

    .line 313
    .line 314
    const-string v3, "hostname"

    .line 315
    .line 316
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 317
    .line 318
    .line 319
    iget-object v0, v1, Ld01/l;->a:Ljava/util/Set;

    .line 320
    .line 321
    check-cast v0, Ljava/lang/Iterable;

    .line 322
    .line 323
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 324
    .line 325
    .line 326
    move-result-object v0

    .line 327
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 328
    .line 329
    .line 330
    move-result v1

    .line 331
    if-nez v1, :cond_9

    .line 332
    .line 333
    iget-boolean p2, p2, Ld01/p;->b:Z

    .line 334
    .line 335
    if-eqz p2, :cond_7

    .line 336
    .line 337
    sget-object p2, Ln01/d;->a:Ln01/b;

    .line 338
    .line 339
    sget-object p2, Ln01/d;->a:Ln01/b;

    .line 340
    .line 341
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 342
    .line 343
    .line 344
    iget-object p2, p2, Ln01/b;->d:Ljava/util/ArrayList;

    .line 345
    .line 346
    invoke-virtual {p2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 347
    .line 348
    .line 349
    move-result-object p2

    .line 350
    :cond_5
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 351
    .line 352
    .line 353
    move-result v0

    .line 354
    if-eqz v0, :cond_6

    .line 355
    .line 356
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 357
    .line 358
    .line 359
    move-result-object v0

    .line 360
    move-object v1, v0

    .line 361
    check-cast v1, Lo01/n;

    .line 362
    .line 363
    invoke-interface {v1, p1}, Lo01/n;->a(Ljavax/net/ssl/SSLSocket;)Z

    .line 364
    .line 365
    .line 366
    move-result v1

    .line 367
    if-eqz v1, :cond_5

    .line 368
    .line 369
    goto :goto_2

    .line 370
    :cond_6
    move-object v0, v2

    .line 371
    :goto_2
    check-cast v0, Lo01/n;

    .line 372
    .line 373
    if-eqz v0, :cond_7

    .line 374
    .line 375
    invoke-interface {v0, p1}, Lo01/n;->c(Ljavax/net/ssl/SSLSocket;)Ljava/lang/String;

    .line 376
    .line 377
    .line 378
    move-result-object v2

    .line 379
    :cond_7
    iput-object p1, p0, Lh01/c;->r:Ljava/net/Socket;

    .line 380
    .line 381
    new-instance p2, Lun/a;

    .line 382
    .line 383
    invoke-direct {p2, p1}, Lun/a;-><init>(Ljava/net/Socket;)V

    .line 384
    .line 385
    .line 386
    new-instance v0, Lgw0/c;

    .line 387
    .line 388
    invoke-direct {v0, p2}, Lgw0/c;-><init>(Lu01/g0;)V

    .line 389
    .line 390
    .line 391
    iput-object v0, p0, Lh01/c;->u:Lgw0/c;

    .line 392
    .line 393
    if-eqz v2, :cond_8

    .line 394
    .line 395
    sget-object p2, Ld01/i0;->e:Ld01/r;

    .line 396
    .line 397
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 398
    .line 399
    .line 400
    invoke-static {v2}, Ld01/r;->e(Ljava/lang/String;)Ld01/i0;

    .line 401
    .line 402
    .line 403
    move-result-object p2

    .line 404
    goto :goto_3

    .line 405
    :cond_8
    sget-object p2, Ld01/i0;->g:Ld01/i0;

    .line 406
    .line 407
    :goto_3
    iput-object p2, p0, Lh01/c;->t:Ld01/i0;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 408
    .line 409
    sget-object p0, Ln01/d;->a:Ln01/b;

    .line 410
    .line 411
    sget-object p0, Ln01/d;->a:Ln01/b;

    .line 412
    .line 413
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 414
    .line 415
    .line 416
    return-void

    .line 417
    :cond_9
    :try_start_1
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 418
    .line 419
    .line 420
    move-result-object p0

    .line 421
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 422
    .line 423
    .line 424
    new-instance p0, Ljava/lang/ClassCastException;

    .line 425
    .line 426
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 427
    .line 428
    .line 429
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 430
    :goto_4
    sget-object p2, Ln01/d;->a:Ln01/b;

    .line 431
    .line 432
    sget-object p2, Ln01/d;->a:Ln01/b;

    .line 433
    .line 434
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 435
    .line 436
    .line 437
    invoke-static {p1}, Le01/g;->c(Ljava/net/Socket;)V

    .line 438
    .line 439
    .line 440
    throw p0
.end method

.method public final k()Lh01/t;
    .locals 13

    .line 1
    iget-object v0, p0, Lh01/c;->m:Ld01/k0;

    .line 2
    .line 3
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lh01/c;->j:Ld01/w0;

    .line 7
    .line 8
    iget-object v2, v1, Ld01/w0;->a:Ld01/a;

    .line 9
    .line 10
    iget-object v3, v1, Ld01/w0;->c:Ljava/net/InetSocketAddress;

    .line 11
    .line 12
    iget-object v2, v2, Ld01/a;->h:Ld01/a0;

    .line 13
    .line 14
    new-instance v4, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    const-string v5, "CONNECT "

    .line 17
    .line 18
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const/4 v5, 0x1

    .line 22
    invoke-static {v2, v5}, Le01/g;->i(Ld01/a0;Z)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v2, " HTTP/1.1"

    .line 30
    .line 31
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    :goto_0
    new-instance v4, Lj01/f;

    .line 39
    .line 40
    iget-object v6, p0, Lh01/c;->u:Lgw0/c;

    .line 41
    .line 42
    const-string v7, "socket"

    .line 43
    .line 44
    const/4 v8, 0x0

    .line 45
    if-eqz v6, :cond_a

    .line 46
    .line 47
    invoke-direct {v4, v8, p0, v6}, Lj01/f;-><init>(Ld01/h0;Li01/c;Lgw0/c;)V

    .line 48
    .line 49
    .line 50
    iget-object v6, p0, Lh01/c;->u:Lgw0/c;

    .line 51
    .line 52
    if-eqz v6, :cond_9

    .line 53
    .line 54
    iget-object v6, v6, Lgw0/c;->f:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v6, Lu01/b0;

    .line 57
    .line 58
    iget-object v6, v6, Lu01/b0;->d:Lu01/h0;

    .line 59
    .line 60
    invoke-interface {v6}, Lu01/h0;->timeout()Lu01/j0;

    .line 61
    .line 62
    .line 63
    move-result-object v6

    .line 64
    iget v9, p0, Lh01/c;->c:I

    .line 65
    .line 66
    int-to-long v9, v9

    .line 67
    sget-object v11, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 68
    .line 69
    invoke-virtual {v6, v9, v10, v11}, Lu01/j0;->g(JLjava/util/concurrent/TimeUnit;)Lu01/j0;

    .line 70
    .line 71
    .line 72
    iget-object v6, p0, Lh01/c;->u:Lgw0/c;

    .line 73
    .line 74
    if-eqz v6, :cond_8

    .line 75
    .line 76
    iget-object v6, v6, Lgw0/c;->g:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v6, Lu01/a0;

    .line 79
    .line 80
    iget-object v6, v6, Lu01/a0;->d:Lu01/f0;

    .line 81
    .line 82
    invoke-interface {v6}, Lu01/f0;->timeout()Lu01/j0;

    .line 83
    .line 84
    .line 85
    move-result-object v6

    .line 86
    iget v7, p0, Lh01/c;->d:I

    .line 87
    .line 88
    int-to-long v9, v7

    .line 89
    invoke-virtual {v6, v9, v10, v11}, Lu01/j0;->g(JLjava/util/concurrent/TimeUnit;)Lu01/j0;

    .line 90
    .line 91
    .line 92
    iget-object v6, v0, Ld01/k0;->c:Ld01/y;

    .line 93
    .line 94
    invoke-virtual {v4, v6, v2}, Lj01/f;->m(Ld01/y;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v4}, Lj01/f;->a()V

    .line 98
    .line 99
    .line 100
    const/4 v6, 0x0

    .line 101
    invoke-virtual {v4, v6}, Lj01/f;->e(Z)Ld01/s0;

    .line 102
    .line 103
    .line 104
    move-result-object v6

    .line 105
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    iput-object v0, v6, Ld01/s0;->a:Ld01/k0;

    .line 109
    .line 110
    invoke-virtual {v6}, Ld01/s0;->a()Ld01/t0;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    iget v6, v0, Ld01/t0;->g:I

    .line 115
    .line 116
    invoke-static {v0}, Le01/g;->e(Ld01/t0;)J

    .line 117
    .line 118
    .line 119
    move-result-wide v9

    .line 120
    const-wide/16 v11, -0x1

    .line 121
    .line 122
    cmp-long v7, v9, v11

    .line 123
    .line 124
    if-nez v7, :cond_0

    .line 125
    .line 126
    goto :goto_1

    .line 127
    :cond_0
    iget-object v7, v0, Ld01/t0;->d:Ld01/k0;

    .line 128
    .line 129
    iget-object v7, v7, Ld01/k0;->a:Ld01/a0;

    .line 130
    .line 131
    invoke-virtual {v4, v7, v9, v10}, Lj01/f;->l(Ld01/a0;J)Lj01/d;

    .line 132
    .line 133
    .line 134
    move-result-object v4

    .line 135
    const v7, 0x7fffffff

    .line 136
    .line 137
    .line 138
    invoke-static {v4, v7}, Le01/g;->g(Lu01/h0;I)Z

    .line 139
    .line 140
    .line 141
    invoke-virtual {v4}, Lj01/d;->close()V

    .line 142
    .line 143
    .line 144
    :goto_1
    const/16 v4, 0xc8

    .line 145
    .line 146
    if-eq v6, v4, :cond_4

    .line 147
    .line 148
    const/16 v4, 0x197

    .line 149
    .line 150
    if-ne v6, v4, :cond_3

    .line 151
    .line 152
    iget-object v4, v1, Ld01/w0;->a:Ld01/a;

    .line 153
    .line 154
    iget-object v4, v4, Ld01/a;->f:Ld01/c;

    .line 155
    .line 156
    invoke-interface {v4, v1, v0}, Ld01/c;->a(Ld01/w0;Ld01/t0;)Ld01/k0;

    .line 157
    .line 158
    .line 159
    move-result-object v4

    .line 160
    if-eqz v4, :cond_2

    .line 161
    .line 162
    const-string v6, "Connection"

    .line 163
    .line 164
    invoke-static {v0, v6}, Ld01/t0;->b(Ld01/t0;Ljava/lang/String;)Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object v0

    .line 168
    const-string v6, "close"

    .line 169
    .line 170
    invoke-virtual {v6, v0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 171
    .line 172
    .line 173
    move-result v0

    .line 174
    if-eqz v0, :cond_1

    .line 175
    .line 176
    goto :goto_2

    .line 177
    :cond_1
    move-object v0, v4

    .line 178
    goto/16 :goto_0

    .line 179
    .line 180
    :cond_2
    new-instance p0, Ljava/io/IOException;

    .line 181
    .line 182
    const-string v0, "Failed to authenticate with proxy"

    .line 183
    .line 184
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 185
    .line 186
    .line 187
    throw p0

    .line 188
    :cond_3
    new-instance p0, Ljava/io/IOException;

    .line 189
    .line 190
    const-string v0, "Unexpected response code for CONNECT: "

    .line 191
    .line 192
    invoke-static {v6, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 193
    .line 194
    .line 195
    move-result-object v0

    .line 196
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    throw p0

    .line 200
    :cond_4
    move-object v4, v8

    .line 201
    :goto_2
    if-nez v4, :cond_5

    .line 202
    .line 203
    new-instance v0, Lh01/t;

    .line 204
    .line 205
    const/4 v1, 0x6

    .line 206
    invoke-direct {v0, p0, v8, v8, v1}, Lh01/t;-><init>(Lh01/u;Lh01/c;Ljava/lang/Throwable;I)V

    .line 207
    .line 208
    .line 209
    return-object v0

    .line 210
    :cond_5
    iget-object v0, p0, Lh01/c;->q:Ljava/net/Socket;

    .line 211
    .line 212
    if-eqz v0, :cond_6

    .line 213
    .line 214
    invoke-static {v0}, Le01/g;->c(Ljava/net/Socket;)V

    .line 215
    .line 216
    .line 217
    :cond_6
    iget v0, p0, Lh01/c;->l:I

    .line 218
    .line 219
    add-int/lit8 v2, v0, 0x1

    .line 220
    .line 221
    const/16 v0, 0x15

    .line 222
    .line 223
    const-string v1, "inetSocketAddress"

    .line 224
    .line 225
    if-ge v2, v0, :cond_7

    .line 226
    .line 227
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    new-instance v0, Lh01/t;

    .line 231
    .line 232
    const/4 v5, 0x0

    .line 233
    const/16 v6, 0xc

    .line 234
    .line 235
    move-object v3, v4

    .line 236
    const/4 v4, 0x0

    .line 237
    move-object v1, p0

    .line 238
    invoke-static/range {v1 .. v6}, Lh01/c;->l(Lh01/c;ILd01/k0;IZI)Lh01/c;

    .line 239
    .line 240
    .line 241
    move-result-object p0

    .line 242
    move-object v2, v1

    .line 243
    const/4 v1, 0x4

    .line 244
    invoke-direct {v0, v2, p0, v8, v1}, Lh01/t;-><init>(Lh01/u;Lh01/c;Ljava/lang/Throwable;I)V

    .line 245
    .line 246
    .line 247
    return-object v0

    .line 248
    :cond_7
    move-object v2, p0

    .line 249
    new-instance p0, Ljava/net/ProtocolException;

    .line 250
    .line 251
    const-string v0, "Too many tunnel connections attempted: 21"

    .line 252
    .line 253
    invoke-direct {p0, v0}, Ljava/net/ProtocolException;-><init>(Ljava/lang/String;)V

    .line 254
    .line 255
    .line 256
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 257
    .line 258
    .line 259
    iget-object v0, v2, Lh01/c;->b:Lh01/q;

    .line 260
    .line 261
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 262
    .line 263
    .line 264
    new-instance v0, Lh01/t;

    .line 265
    .line 266
    const/4 v1, 0x2

    .line 267
    invoke-direct {v0, v2, v8, p0, v1}, Lh01/t;-><init>(Lh01/u;Lh01/c;Ljava/lang/Throwable;I)V

    .line 268
    .line 269
    .line 270
    return-object v0

    .line 271
    :cond_8
    invoke-static {v7}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    throw v8

    .line 275
    :cond_9
    invoke-static {v7}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 276
    .line 277
    .line 278
    throw v8

    .line 279
    :cond_a
    invoke-static {v7}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 280
    .line 281
    .line 282
    throw v8
.end method

.method public final m(Ljava/util/List;Ljavax/net/ssl/SSLSocket;)Lh01/c;
    .locals 9

    .line 1
    const-string v0, "connectionSpecs"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lh01/c;->n:I

    .line 7
    .line 8
    add-int/lit8 v1, v0, 0x1

    .line 9
    .line 10
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    move v6, v1

    .line 15
    :goto_0
    if-ge v6, v2, :cond_4

    .line 16
    .line 17
    invoke-interface {p1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    check-cast v1, Ld01/p;

    .line 22
    .line 23
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    iget-boolean v3, v1, Ld01/p;->a:Z

    .line 27
    .line 28
    if-nez v3, :cond_0

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_0
    iget-object v3, v1, Ld01/p;->d:[Ljava/lang/String;

    .line 32
    .line 33
    if-eqz v3, :cond_1

    .line 34
    .line 35
    invoke-virtual {p2}, Ljavax/net/ssl/SSLSocket;->getEnabledProtocols()[Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    sget-object v5, Lox0/a;->e:Lox0/a;

    .line 40
    .line 41
    invoke-static {v3, v4, v5}, Le01/e;->h([Ljava/lang/String;[Ljava/lang/String;Ljava/util/Comparator;)Z

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    if-nez v3, :cond_1

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    iget-object v1, v1, Ld01/p;->c:[Ljava/lang/String;

    .line 49
    .line 50
    if-eqz v1, :cond_2

    .line 51
    .line 52
    invoke-virtual {p2}, Ljavax/net/ssl/SSLSocket;->getEnabledCipherSuites()[Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    sget-object v4, Ld01/n;->c:Ld01/m;

    .line 57
    .line 58
    invoke-static {v1, v3, v4}, Le01/e;->h([Ljava/lang/String;[Ljava/lang/String;Ljava/util/Comparator;)Z

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    if-nez v1, :cond_2

    .line 63
    .line 64
    :goto_1
    add-int/lit8 v6, v6, 0x1

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_2
    const/4 p1, -0x1

    .line 68
    if-eq v0, p1, :cond_3

    .line 69
    .line 70
    const/4 p1, 0x1

    .line 71
    :goto_2
    move v7, p1

    .line 72
    goto :goto_3

    .line 73
    :cond_3
    const/4 p1, 0x0

    .line 74
    goto :goto_2

    .line 75
    :goto_3
    const/4 v8, 0x3

    .line 76
    const/4 v4, 0x0

    .line 77
    const/4 v5, 0x0

    .line 78
    move-object v3, p0

    .line 79
    invoke-static/range {v3 .. v8}, Lh01/c;->l(Lh01/c;ILd01/k0;IZI)Lh01/c;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0

    .line 84
    :cond_4
    const/4 p0, 0x0

    .line 85
    return-object p0
.end method

.method public final n(Ljava/util/List;Ljavax/net/ssl/SSLSocket;)Lh01/c;
    .locals 3

    .line 1
    const-string v0, "connectionSpecs"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lh01/c;->n:I

    .line 7
    .line 8
    const/4 v1, -0x1

    .line 9
    if-eq v0, v1, :cond_0

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    invoke-virtual {p0, p1, p2}, Lh01/c;->m(Ljava/util/List;Ljavax/net/ssl/SSLSocket;)Lh01/c;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    return-object v0

    .line 19
    :cond_1
    new-instance v0, Ljava/net/UnknownServiceException;

    .line 20
    .line 21
    new-instance v1, Ljava/lang/StringBuilder;

    .line 22
    .line 23
    const-string v2, "Unable to find acceptable protocols. isFallback="

    .line 24
    .line 25
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    iget-boolean p0, p0, Lh01/c;->o:Z

    .line 29
    .line 30
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string p0, ", modes="

    .line 34
    .line 35
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string p0, ", supported protocols="

    .line 42
    .line 43
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {p2}, Ljavax/net/ssl/SSLSocket;->getEnabledProtocols()[Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    invoke-static {p0}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    const-string p1, "toString(...)"

    .line 58
    .line 59
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-direct {v0, p0}, Ljava/net/UnknownServiceException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw v0
.end method
