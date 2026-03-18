.class public final Lk01/w;
.super Lu01/d;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic n:Lk01/x;


# direct methods
.method public constructor <init>(Lk01/x;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lk01/w;->n:Lk01/x;

    .line 2
    .line 3
    invoke-direct {p0}, Lu01/d;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final j(Ljava/io/IOException;)Ljava/io/IOException;
    .locals 0

    .line 1
    new-instance p0, Ljava/net/SocketTimeoutException;

    .line 2
    .line 3
    const-string p1, "timeout"

    .line 4
    .line 5
    invoke-direct {p0, p1}, Ljava/net/SocketTimeoutException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    return-object p0
.end method

.method public final k()V
    .locals 8

    .line 1
    iget-object v0, p0, Lk01/w;->n:Lk01/x;

    .line 2
    .line 3
    sget-object v1, Lk01/b;->k:Lk01/b;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Lk01/x;->f(Lk01/b;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lk01/w;->n:Lk01/x;

    .line 9
    .line 10
    iget-object p0, p0, Lk01/x;->e:Lk01/p;

    .line 11
    .line 12
    monitor-enter p0

    .line 13
    :try_start_0
    iget-wide v0, p0, Lk01/p;->q:J

    .line 14
    .line 15
    iget-wide v2, p0, Lk01/p;->p:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    .line 17
    cmp-long v0, v0, v2

    .line 18
    .line 19
    if-gez v0, :cond_0

    .line 20
    .line 21
    monitor-exit p0

    .line 22
    return-void

    .line 23
    :cond_0
    const-wide/16 v0, 0x1

    .line 24
    .line 25
    add-long/2addr v2, v0

    .line 26
    :try_start_1
    iput-wide v2, p0, Lk01/p;->p:J

    .line 27
    .line 28
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 29
    .line 30
    .line 31
    move-result-wide v0

    .line 32
    const v2, 0x3b9aca00

    .line 33
    .line 34
    .line 35
    int-to-long v2, v2

    .line 36
    add-long/2addr v0, v2

    .line 37
    iput-wide v0, p0, Lk01/p;->r:J
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 38
    .line 39
    monitor-exit p0

    .line 40
    iget-object v2, p0, Lk01/p;->k:Lg01/b;

    .line 41
    .line 42
    new-instance v0, Ljava/lang/StringBuilder;

    .line 43
    .line 44
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 45
    .line 46
    .line 47
    iget-object v1, p0, Lk01/p;->f:Ljava/lang/String;

    .line 48
    .line 49
    const-string v3, " ping"

    .line 50
    .line 51
    invoke-static {v0, v1, v3}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v3

    .line 55
    new-instance v6, Lh50/q0;

    .line 56
    .line 57
    const/16 v0, 0x12

    .line 58
    .line 59
    invoke-direct {v6, p0, v0}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 60
    .line 61
    .line 62
    const/4 v7, 0x6

    .line 63
    const-wide/16 v4, 0x0

    .line 64
    .line 65
    invoke-static/range {v2 .. v7}, Lg01/b;->c(Lg01/b;Ljava/lang/String;JLay0/a;I)V

    .line 66
    .line 67
    .line 68
    return-void

    .line 69
    :catchall_0
    move-exception v0

    .line 70
    monitor-exit p0

    .line 71
    throw v0
.end method

.method public final l()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lu01/d;->i()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    const/4 v0, 0x0

    .line 9
    invoke-virtual {p0, v0}, Lk01/w;->j(Ljava/io/IOException;)Ljava/io/IOException;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    throw p0
.end method
