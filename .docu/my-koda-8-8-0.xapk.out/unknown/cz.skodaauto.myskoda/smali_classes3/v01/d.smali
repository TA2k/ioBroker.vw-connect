.class public final Lv01/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu01/f0;


# instance fields
.field public final d:Ljava/io/OutputStream;

.field public final e:Lv01/h;

.field public final synthetic f:Lun/a;


# direct methods
.method public constructor <init>(Lun/a;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv01/d;->f:Lun/a;

    .line 5
    .line 6
    iget-object p1, p1, Lun/a;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Ljava/net/Socket;

    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/net/Socket;->getOutputStream()Ljava/io/OutputStream;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iput-object v0, p0, Lv01/d;->d:Ljava/io/OutputStream;

    .line 15
    .line 16
    new-instance v0, Lv01/h;

    .line 17
    .line 18
    invoke-direct {v0, p1}, Lv01/h;-><init>(Ljava/net/Socket;)V

    .line 19
    .line 20
    .line 21
    iput-object v0, p0, Lv01/d;->e:Lv01/h;

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final F(Lu01/f;J)V
    .locals 7

    .line 1
    const-string v0, "source"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-wide v1, p1, Lu01/f;->e:J

    .line 7
    .line 8
    const-wide/16 v3, 0x0

    .line 9
    .line 10
    move-wide v5, p2

    .line 11
    invoke-static/range {v1 .. v6}, Lu01/b;->e(JJJ)V

    .line 12
    .line 13
    .line 14
    :cond_0
    :goto_0
    const-wide/16 v0, 0x0

    .line 15
    .line 16
    cmp-long v0, p2, v0

    .line 17
    .line 18
    if-lez v0, :cond_3

    .line 19
    .line 20
    iget-object v1, p0, Lv01/d;->e:Lv01/h;

    .line 21
    .line 22
    invoke-virtual {v1}, Lu01/j0;->f()V

    .line 23
    .line 24
    .line 25
    iget-object v0, p1, Lu01/f;->d:Lu01/c0;

    .line 26
    .line 27
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget v2, v0, Lu01/c0;->c:I

    .line 31
    .line 32
    iget v3, v0, Lu01/c0;->b:I

    .line 33
    .line 34
    sub-int/2addr v2, v3

    .line 35
    int-to-long v2, v2

    .line 36
    invoke-static {p2, p3, v2, v3}, Ljava/lang/Math;->min(JJ)J

    .line 37
    .line 38
    .line 39
    move-result-wide v2

    .line 40
    long-to-int v2, v2

    .line 41
    invoke-virtual {v1}, Lu01/d;->h()V

    .line 42
    .line 43
    .line 44
    :try_start_0
    iget-object v3, p0, Lv01/d;->d:Ljava/io/OutputStream;

    .line 45
    .line 46
    iget-object v4, v0, Lu01/c0;->a:[B

    .line 47
    .line 48
    iget v5, v0, Lu01/c0;->b:I

    .line 49
    .line 50
    invoke-virtual {v3, v4, v5, v2}, Ljava/io/OutputStream;->write([BII)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 51
    .line 52
    .line 53
    invoke-virtual {v1}, Lu01/d;->i()Z

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    if-nez v3, :cond_1

    .line 58
    .line 59
    iget v1, v0, Lu01/c0;->b:I

    .line 60
    .line 61
    add-int/2addr v1, v2

    .line 62
    iput v1, v0, Lu01/c0;->b:I

    .line 63
    .line 64
    int-to-long v2, v2

    .line 65
    sub-long/2addr p2, v2

    .line 66
    iget-wide v4, p1, Lu01/f;->e:J

    .line 67
    .line 68
    sub-long/2addr v4, v2

    .line 69
    iput-wide v4, p1, Lu01/f;->e:J

    .line 70
    .line 71
    iget v2, v0, Lu01/c0;->c:I

    .line 72
    .line 73
    if-ne v1, v2, :cond_0

    .line 74
    .line 75
    invoke-virtual {v0}, Lu01/c0;->a()Lu01/c0;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    iput-object v1, p1, Lu01/f;->d:Lu01/c0;

    .line 80
    .line 81
    invoke-static {v0}, Lu01/d0;->a(Lu01/c0;)V

    .line 82
    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_1
    const/4 p0, 0x0

    .line 86
    invoke-virtual {v1, p0}, Lu01/d;->j(Ljava/io/IOException;)Ljava/io/IOException;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    throw p0

    .line 91
    :catchall_0
    move-exception v0

    .line 92
    move-object p0, v0

    .line 93
    goto :goto_2

    .line 94
    :catch_0
    move-exception v0

    .line 95
    move-object p0, v0

    .line 96
    :try_start_1
    invoke-virtual {v1}, Lu01/d;->i()Z

    .line 97
    .line 98
    .line 99
    move-result p1

    .line 100
    if-nez p1, :cond_2

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_2
    invoke-virtual {v1, p0}, Lu01/d;->j(Ljava/io/IOException;)Ljava/io/IOException;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    :goto_1
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 108
    :goto_2
    invoke-virtual {v1}, Lu01/d;->i()Z

    .line 109
    .line 110
    .line 111
    throw p0

    .line 112
    :cond_3
    return-void
.end method

.method public final close()V
    .locals 5

    .line 1
    iget-object v0, p0, Lv01/d;->d:Ljava/io/OutputStream;

    .line 2
    .line 3
    iget-object v1, p0, Lv01/d;->f:Lun/a;

    .line 4
    .line 5
    iget-object p0, p0, Lv01/d;->e:Lv01/h;

    .line 6
    .line 7
    invoke-virtual {p0}, Lu01/d;->h()V

    .line 8
    .line 9
    .line 10
    :try_start_0
    iget-object v2, v1, Lun/a;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v2, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 13
    .line 14
    iget-object v1, v1, Lun/a;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Ljava/net/Socket;

    .line 17
    .line 18
    const-string v3, "<this>"

    .line 19
    .line 20
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    :cond_0
    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    and-int/lit8 v4, v3, 0x1

    .line 28
    .line 29
    if-eqz v4, :cond_1

    .line 30
    .line 31
    const/4 v2, 0x0

    .line 32
    goto :goto_0

    .line 33
    :cond_1
    or-int/lit8 v4, v3, 0x1

    .line 34
    .line 35
    invoke-virtual {v2, v3, v4}, Ljava/util/concurrent/atomic/AtomicInteger;->compareAndSet(II)Z

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    if-eqz v3, :cond_0

    .line 40
    .line 41
    move v2, v4

    .line 42
    :goto_0
    if-eqz v2, :cond_6

    .line 43
    .line 44
    const/4 v3, 0x3

    .line 45
    if-eq v2, v3, :cond_4

    .line 46
    .line 47
    invoke-virtual {v1}, Ljava/net/Socket;->isClosed()Z

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    if-nez v2, :cond_3

    .line 52
    .line 53
    invoke-virtual {v1}, Ljava/net/Socket;->isOutputShutdown()Z

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    if-eqz v2, :cond_2

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_2
    invoke-virtual {v0}, Ljava/io/OutputStream;->flush()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 61
    .line 62
    .line 63
    :try_start_1
    invoke-virtual {v1}, Ljava/net/Socket;->shutdownOutput()V
    :try_end_1
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 64
    .line 65
    .line 66
    goto :goto_2

    .line 67
    :catchall_0
    move-exception v0

    .line 68
    goto :goto_5

    .line 69
    :catch_0
    move-exception v0

    .line 70
    goto :goto_3

    .line 71
    :catch_1
    :try_start_2
    invoke-virtual {v0}, Ljava/io/OutputStream;->close()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 72
    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_3
    :goto_1
    invoke-virtual {p0}, Lu01/d;->i()Z

    .line 76
    .line 77
    .line 78
    return-void

    .line 79
    :cond_4
    :try_start_3
    invoke-virtual {v1}, Ljava/net/Socket;->close()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 80
    .line 81
    .line 82
    :goto_2
    invoke-virtual {p0}, Lu01/d;->i()Z

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    if-nez v0, :cond_5

    .line 87
    .line 88
    return-void

    .line 89
    :cond_5
    const/4 v0, 0x0

    .line 90
    invoke-virtual {p0, v0}, Lv01/h;->j(Ljava/io/IOException;)Ljava/io/IOException;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    throw p0

    .line 95
    :cond_6
    invoke-virtual {p0}, Lu01/d;->i()Z

    .line 96
    .line 97
    .line 98
    return-void

    .line 99
    :goto_3
    :try_start_4
    invoke-virtual {p0}, Lu01/d;->i()Z

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    if-nez v1, :cond_7

    .line 104
    .line 105
    goto :goto_4

    .line 106
    :cond_7
    invoke-virtual {p0, v0}, Lv01/h;->j(Ljava/io/IOException;)Ljava/io/IOException;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    :goto_4
    throw v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 111
    :goto_5
    invoke-virtual {p0}, Lu01/d;->i()Z

    .line 112
    .line 113
    .line 114
    throw v0
.end method

.method public final flush()V
    .locals 2

    .line 1
    iget-object v0, p0, Lv01/d;->e:Lv01/h;

    .line 2
    .line 3
    invoke-virtual {v0}, Lu01/d;->h()V

    .line 4
    .line 5
    .line 6
    :try_start_0
    iget-object p0, p0, Lv01/d;->d:Ljava/io/OutputStream;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/io/OutputStream;->flush()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Lu01/d;->i()Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-nez p0, :cond_0

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    invoke-virtual {v0, p0}, Lu01/d;->j(Ljava/io/IOException;)Ljava/io/IOException;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    throw p0

    .line 24
    :catchall_0
    move-exception p0

    .line 25
    goto :goto_1

    .line 26
    :catch_0
    move-exception p0

    .line 27
    :try_start_1
    invoke-virtual {v0}, Lu01/d;->i()Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-nez v1, :cond_1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    invoke-virtual {v0, p0}, Lu01/d;->j(Ljava/io/IOException;)Ljava/io/IOException;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    :goto_0
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 39
    :goto_1
    invoke-virtual {v0}, Lu01/d;->i()Z

    .line 40
    .line 41
    .line 42
    throw p0
.end method

.method public final timeout()Lu01/j0;
    .locals 0

    .line 1
    iget-object p0, p0, Lv01/d;->e:Lv01/h;

    .line 2
    .line 3
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "sink("

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lv01/d;->f:Lun/a;

    .line 9
    .line 10
    iget-object p0, p0, Lun/a;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Ljava/net/Socket;

    .line 13
    .line 14
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const/16 p0, 0x29

    .line 18
    .line 19
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method
