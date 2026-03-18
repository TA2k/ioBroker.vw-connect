.class public final Lh01/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lh01/o;

.field public final b:Lh01/h;

.field public final c:Li01/d;

.field public d:Z

.field public e:Z


# direct methods
.method public constructor <init>(Lh01/o;Lh01/h;Li01/d;)V
    .locals 1

    .line 1
    const-string v0, "finder"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lh01/g;->a:Lh01/o;

    .line 10
    .line 11
    iput-object p2, p0, Lh01/g;->b:Lh01/h;

    .line 12
    .line 13
    iput-object p3, p0, Lh01/g;->c:Li01/d;

    .line 14
    .line 15
    return-void
.end method

.method public static a(Lh01/g;ZLjava/io/IOException;I)Ljava/io/IOException;
    .locals 10

    .line 1
    and-int/lit8 v0, p3, 0x4

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    move v0, v2

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v0, v1

    .line 10
    :goto_0
    and-int/lit8 p3, p3, 0x8

    .line 11
    .line 12
    if-eqz p3, :cond_1

    .line 13
    .line 14
    move p3, v2

    .line 15
    goto :goto_1

    .line 16
    :cond_1
    move p3, v1

    .line 17
    :goto_1
    if-eqz p2, :cond_2

    .line 18
    .line 19
    invoke-virtual {p0, p2}, Lh01/g;->e(Ljava/io/IOException;)V

    .line 20
    .line 21
    .line 22
    :cond_2
    iget-object v3, p0, Lh01/g;->a:Lh01/o;

    .line 23
    .line 24
    if-eqz p3, :cond_3

    .line 25
    .line 26
    if-nez p1, :cond_3

    .line 27
    .line 28
    move v5, v1

    .line 29
    goto :goto_2

    .line 30
    :cond_3
    move v5, v2

    .line 31
    :goto_2
    if-eqz v0, :cond_4

    .line 32
    .line 33
    if-nez p1, :cond_4

    .line 34
    .line 35
    move v6, v1

    .line 36
    goto :goto_3

    .line 37
    :cond_4
    move v6, v2

    .line 38
    :goto_3
    if-eqz p3, :cond_5

    .line 39
    .line 40
    if-eqz p1, :cond_5

    .line 41
    .line 42
    move v8, v1

    .line 43
    goto :goto_4

    .line 44
    :cond_5
    move v8, v2

    .line 45
    :goto_4
    if-eqz v0, :cond_6

    .line 46
    .line 47
    if-eqz p1, :cond_6

    .line 48
    .line 49
    move v7, v1

    .line 50
    :goto_5
    move-object v4, p0

    .line 51
    move-object v9, p2

    .line 52
    goto :goto_6

    .line 53
    :cond_6
    move v7, v2

    .line 54
    goto :goto_5

    .line 55
    :goto_6
    invoke-virtual/range {v3 .. v9}, Lh01/o;->f(Lh01/g;ZZZZLjava/io/IOException;)Ljava/io/IOException;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0
.end method


# virtual methods
.method public final b(Ld01/k0;Z)Lh01/e;
    .locals 6

    .line 1
    const-string v0, "request"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-boolean p2, p0, Lh01/g;->d:Z

    .line 7
    .line 8
    iget-object p2, p1, Ld01/k0;->d:Ld01/r0;

    .line 9
    .line 10
    invoke-static {p2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p2}, Ld01/r0;->contentLength()J

    .line 14
    .line 15
    .line 16
    move-result-wide v3

    .line 17
    iget-object p2, p0, Lh01/g;->c:Li01/d;

    .line 18
    .line 19
    invoke-interface {p2, p1, v3, v4}, Li01/d;->j(Ld01/k0;J)Lu01/f0;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    new-instance v0, Lh01/e;

    .line 24
    .line 25
    const/4 v5, 0x0

    .line 26
    move-object v1, p0

    .line 27
    invoke-direct/range {v0 .. v5}, Lh01/e;-><init>(Lh01/g;Lu01/f0;JZ)V

    .line 28
    .line 29
    .line 30
    return-object v0
.end method

.method public final c()Lh01/p;
    .locals 1

    .line 1
    iget-object p0, p0, Lh01/g;->c:Li01/d;

    .line 2
    .line 3
    invoke-interface {p0}, Li01/d;->i()Li01/c;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    instance-of v0, p0, Lh01/p;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    check-cast p0, Lh01/p;

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    :goto_0
    if-eqz p0, :cond_1

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 19
    .line 20
    const-string v0, "no connection for CONNECT tunnels"

    .line 21
    .line 22
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p0
.end method

.method public final d(Z)Ld01/s0;
    .locals 1

    .line 1
    :try_start_0
    iget-object v0, p0, Lh01/g;->c:Li01/d;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Li01/d;->e(Z)Ld01/s0;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    iput-object p0, p1, Ld01/s0;->n:Lh01/g;
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 10
    .line 11
    return-object p1

    .line 12
    :catch_0
    move-exception p1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    return-object p1

    .line 15
    :goto_0
    invoke-virtual {p0, p1}, Lh01/g;->e(Ljava/io/IOException;)V

    .line 16
    .line 17
    .line 18
    throw p1
.end method

.method public final e(Ljava/io/IOException;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lh01/g;->e:Z

    .line 3
    .line 4
    iget-object v0, p0, Lh01/g;->c:Li01/d;

    .line 5
    .line 6
    invoke-interface {v0}, Li01/d;->i()Li01/c;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iget-object p0, p0, Lh01/g;->a:Lh01/o;

    .line 11
    .line 12
    invoke-interface {v0, p0, p1}, Li01/c;->h(Lh01/o;Ljava/io/IOException;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final f()Lgw0/c;
    .locals 3

    .line 1
    iget-object v0, p0, Lh01/g;->a:Lh01/o;

    .line 2
    .line 3
    iget-boolean v1, v0, Lh01/o;->m:Z

    .line 4
    .line 5
    if-nez v1, :cond_4

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    iput-boolean v1, v0, Lh01/o;->m:Z

    .line 9
    .line 10
    iget-object v2, v0, Lh01/o;->h:Lh01/n;

    .line 11
    .line 12
    invoke-virtual {v2}, Lu01/d;->i()Z

    .line 13
    .line 14
    .line 15
    monitor-enter v0

    .line 16
    :try_start_0
    iget-object v2, v0, Lh01/o;->u:Lh01/g;

    .line 17
    .line 18
    if-eqz v2, :cond_3

    .line 19
    .line 20
    iget-boolean v2, v0, Lh01/o;->q:Z

    .line 21
    .line 22
    if-nez v2, :cond_2

    .line 23
    .line 24
    iget-boolean v2, v0, Lh01/o;->r:Z

    .line 25
    .line 26
    if-nez v2, :cond_2

    .line 27
    .line 28
    iget-boolean v2, v0, Lh01/o;->o:Z

    .line 29
    .line 30
    if-nez v2, :cond_1

    .line 31
    .line 32
    iget-boolean v2, v0, Lh01/o;->p:Z

    .line 33
    .line 34
    if-eqz v2, :cond_0

    .line 35
    .line 36
    const/4 v2, 0x0

    .line 37
    iput-boolean v2, v0, Lh01/o;->p:Z

    .line 38
    .line 39
    iput-boolean v1, v0, Lh01/o;->q:Z

    .line 40
    .line 41
    iput-boolean v1, v0, Lh01/o;->r:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 42
    .line 43
    monitor-exit v0

    .line 44
    iget-object v0, p0, Lh01/g;->c:Li01/d;

    .line 45
    .line 46
    invoke-interface {v0}, Li01/d;->i()Li01/c;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    const-string v1, "null cannot be cast to non-null type okhttp3.internal.connection.RealConnection"

    .line 51
    .line 52
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    check-cast v0, Lh01/p;

    .line 56
    .line 57
    iget-object v1, v0, Lh01/p;->e:Ljava/net/Socket;

    .line 58
    .line 59
    invoke-virtual {v1, v2}, Ljava/net/Socket;->setSoTimeout(I)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v0}, Lh01/p;->c()V

    .line 63
    .line 64
    .line 65
    new-instance v0, Lgw0/c;

    .line 66
    .line 67
    invoke-direct {v0, p0}, Lgw0/c;-><init>(Lh01/g;)V

    .line 68
    .line 69
    .line 70
    return-object v0

    .line 71
    :catchall_0
    move-exception p0

    .line 72
    goto :goto_0

    .line 73
    :cond_0
    :try_start_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 74
    .line 75
    const-string v1, "Check failed."

    .line 76
    .line 77
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw p0

    .line 81
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 82
    .line 83
    const-string v1, "Check failed."

    .line 84
    .line 85
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw p0

    .line 89
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 90
    .line 91
    const-string v1, "Check failed."

    .line 92
    .line 93
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p0

    .line 97
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 98
    .line 99
    const-string v1, "Check failed."

    .line 100
    .line 101
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 105
    :goto_0
    monitor-exit v0

    .line 106
    throw p0

    .line 107
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 108
    .line 109
    const-string v0, "Check failed."

    .line 110
    .line 111
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    throw p0
.end method
