.class public final Lv01/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu01/h0;


# instance fields
.field public final d:Ljava/io/InputStream;

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
    iput-object p1, p0, Lv01/e;->f:Lun/a;

    .line 5
    .line 6
    iget-object p1, p1, Lun/a;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Ljava/net/Socket;

    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/net/Socket;->getInputStream()Ljava/io/InputStream;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iput-object v0, p0, Lv01/e;->d:Ljava/io/InputStream;

    .line 15
    .line 16
    new-instance v0, Lv01/h;

    .line 17
    .line 18
    invoke-direct {v0, p1}, Lv01/h;-><init>(Ljava/net/Socket;)V

    .line 19
    .line 20
    .line 21
    iput-object v0, p0, Lv01/e;->e:Lv01/h;

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final A(Lu01/f;J)J
    .locals 4

    .line 1
    const-string v0, "sink"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-wide/16 v0, 0x0

    .line 7
    .line 8
    cmp-long v2, p2, v0

    .line 9
    .line 10
    if-nez v2, :cond_0

    .line 11
    .line 12
    return-wide v0

    .line 13
    :cond_0
    if-ltz v2, :cond_6

    .line 14
    .line 15
    iget-object v0, p0, Lv01/e;->e:Lv01/h;

    .line 16
    .line 17
    invoke-virtual {v0}, Lu01/j0;->f()V

    .line 18
    .line 19
    .line 20
    const/4 v1, 0x1

    .line 21
    invoke-virtual {p1, v1}, Lu01/f;->W(I)Lu01/c0;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    iget v2, v1, Lu01/c0;->c:I

    .line 26
    .line 27
    rsub-int v2, v2, 0x2000

    .line 28
    .line 29
    int-to-long v2, v2

    .line 30
    invoke-static {p2, p3, v2, v3}, Ljava/lang/Math;->min(JJ)J

    .line 31
    .line 32
    .line 33
    move-result-wide p2

    .line 34
    long-to-int p2, p2

    .line 35
    :try_start_0
    invoke-virtual {v0}, Lu01/d;->h()V
    :try_end_0
    .catch Ljava/lang/AssertionError; {:try_start_0 .. :try_end_0} :catch_1

    .line 36
    .line 37
    .line 38
    :try_start_1
    iget-object p0, p0, Lv01/e;->d:Ljava/io/InputStream;

    .line 39
    .line 40
    iget-object p3, v1, Lu01/c0;->a:[B

    .line 41
    .line 42
    iget v2, v1, Lu01/c0;->c:I

    .line 43
    .line 44
    invoke-virtual {p0, p3, v2, p2}, Ljava/io/InputStream;->read([BII)I

    .line 45
    .line 46
    .line 47
    move-result p0
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 48
    :try_start_2
    invoke-virtual {v0}, Lu01/d;->i()Z

    .line 49
    .line 50
    .line 51
    move-result p2
    :try_end_2
    .catch Ljava/lang/AssertionError; {:try_start_2 .. :try_end_2} :catch_1

    .line 52
    if-nez p2, :cond_3

    .line 53
    .line 54
    const/4 p2, -0x1

    .line 55
    if-ne p0, p2, :cond_2

    .line 56
    .line 57
    iget p0, v1, Lu01/c0;->b:I

    .line 58
    .line 59
    iget p2, v1, Lu01/c0;->c:I

    .line 60
    .line 61
    if-ne p0, p2, :cond_1

    .line 62
    .line 63
    invoke-virtual {v1}, Lu01/c0;->a()Lu01/c0;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    iput-object p0, p1, Lu01/f;->d:Lu01/c0;

    .line 68
    .line 69
    invoke-static {v1}, Lu01/d0;->a(Lu01/c0;)V

    .line 70
    .line 71
    .line 72
    :cond_1
    const-wide/16 p0, -0x1

    .line 73
    .line 74
    return-wide p0

    .line 75
    :cond_2
    iget p2, v1, Lu01/c0;->c:I

    .line 76
    .line 77
    add-int/2addr p2, p0

    .line 78
    iput p2, v1, Lu01/c0;->c:I

    .line 79
    .line 80
    iget-wide p2, p1, Lu01/f;->e:J

    .line 81
    .line 82
    int-to-long v0, p0

    .line 83
    add-long/2addr p2, v0

    .line 84
    iput-wide p2, p1, Lu01/f;->e:J

    .line 85
    .line 86
    return-wide v0

    .line 87
    :cond_3
    const/4 p0, 0x0

    .line 88
    :try_start_3
    invoke-virtual {v0, p0}, Lu01/d;->j(Ljava/io/IOException;)Ljava/io/IOException;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    throw p0
    :try_end_3
    .catch Ljava/lang/AssertionError; {:try_start_3 .. :try_end_3} :catch_1

    .line 93
    :catchall_0
    move-exception p0

    .line 94
    goto :goto_1

    .line 95
    :catch_0
    move-exception p0

    .line 96
    :try_start_4
    invoke-virtual {v0}, Lu01/d;->i()Z

    .line 97
    .line 98
    .line 99
    move-result p1

    .line 100
    if-nez p1, :cond_4

    .line 101
    .line 102
    goto :goto_0

    .line 103
    :cond_4
    invoke-virtual {v0, p0}, Lu01/d;->j(Ljava/io/IOException;)Ljava/io/IOException;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    :goto_0
    throw p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 108
    :goto_1
    :try_start_5
    invoke-virtual {v0}, Lu01/d;->i()Z

    .line 109
    .line 110
    .line 111
    throw p0
    :try_end_5
    .catch Ljava/lang/AssertionError; {:try_start_5 .. :try_end_5} :catch_1

    .line 112
    :catch_1
    move-exception p0

    .line 113
    invoke-static {p0}, Lv01/k;->a(Ljava/lang/AssertionError;)Z

    .line 114
    .line 115
    .line 116
    move-result p1

    .line 117
    if-eqz p1, :cond_5

    .line 118
    .line 119
    new-instance p1, Ljava/io/IOException;

    .line 120
    .line 121
    invoke-direct {p1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/Throwable;)V

    .line 122
    .line 123
    .line 124
    throw p1

    .line 125
    :cond_5
    throw p0

    .line 126
    :cond_6
    const-string p0, "byteCount < 0: "

    .line 127
    .line 128
    invoke-static {p2, p3, p0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 133
    .line 134
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    throw p1
.end method

.method public final close()V
    .locals 5

    .line 1
    iget-object v0, p0, Lv01/e;->f:Lun/a;

    .line 2
    .line 3
    iget-object v1, p0, Lv01/e;->e:Lv01/h;

    .line 4
    .line 5
    invoke-virtual {v1}, Lu01/d;->h()V

    .line 6
    .line 7
    .line 8
    :try_start_0
    iget-object v2, v0, Lun/a;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v2, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 11
    .line 12
    iget-object v0, v0, Lun/a;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v0, Ljava/net/Socket;

    .line 15
    .line 16
    const-string v3, "<this>"

    .line 17
    .line 18
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    and-int/lit8 v4, v3, 0x2

    .line 26
    .line 27
    if-eqz v4, :cond_1

    .line 28
    .line 29
    const/4 v2, 0x0

    .line 30
    goto :goto_0

    .line 31
    :cond_1
    or-int/lit8 v4, v3, 0x2

    .line 32
    .line 33
    invoke-virtual {v2, v3, v4}, Ljava/util/concurrent/atomic/AtomicInteger;->compareAndSet(II)Z

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    if-eqz v3, :cond_0

    .line 38
    .line 39
    move v2, v4

    .line 40
    :goto_0
    if-eqz v2, :cond_6

    .line 41
    .line 42
    const/4 v3, 0x3

    .line 43
    if-eq v2, v3, :cond_4

    .line 44
    .line 45
    invoke-virtual {v0}, Ljava/net/Socket;->isClosed()Z

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    if-nez v2, :cond_3

    .line 50
    .line 51
    invoke-virtual {v0}, Ljava/net/Socket;->isInputShutdown()Z

    .line 52
    .line 53
    .line 54
    move-result v2
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 55
    if-eqz v2, :cond_2

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_2
    :try_start_1
    invoke-virtual {v0}, Ljava/net/Socket;->shutdownInput()V
    :try_end_1
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 59
    .line 60
    .line 61
    goto :goto_2

    .line 62
    :catchall_0
    move-exception p0

    .line 63
    goto :goto_5

    .line 64
    :catch_0
    move-exception p0

    .line 65
    goto :goto_3

    .line 66
    :catch_1
    :try_start_2
    iget-object p0, p0, Lv01/e;->d:Ljava/io/InputStream;

    .line 67
    .line 68
    invoke-virtual {p0}, Ljava/io/InputStream;->close()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 69
    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_3
    :goto_1
    invoke-virtual {v1}, Lu01/d;->i()Z

    .line 73
    .line 74
    .line 75
    return-void

    .line 76
    :cond_4
    :try_start_3
    invoke-virtual {v0}, Ljava/net/Socket;->close()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 77
    .line 78
    .line 79
    :goto_2
    invoke-virtual {v1}, Lu01/d;->i()Z

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    if-nez p0, :cond_5

    .line 84
    .line 85
    return-void

    .line 86
    :cond_5
    const/4 p0, 0x0

    .line 87
    invoke-virtual {v1, p0}, Lv01/h;->j(Ljava/io/IOException;)Ljava/io/IOException;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    throw p0

    .line 92
    :cond_6
    invoke-virtual {v1}, Lu01/d;->i()Z

    .line 93
    .line 94
    .line 95
    return-void

    .line 96
    :goto_3
    :try_start_4
    invoke-virtual {v1}, Lu01/d;->i()Z

    .line 97
    .line 98
    .line 99
    move-result v0

    .line 100
    if-nez v0, :cond_7

    .line 101
    .line 102
    goto :goto_4

    .line 103
    :cond_7
    invoke-virtual {v1, p0}, Lv01/h;->j(Ljava/io/IOException;)Ljava/io/IOException;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    :goto_4
    throw p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 108
    :goto_5
    invoke-virtual {v1}, Lu01/d;->i()Z

    .line 109
    .line 110
    .line 111
    throw p0
.end method

.method public final timeout()Lu01/j0;
    .locals 0

    .line 1
    iget-object p0, p0, Lv01/e;->e:Lv01/h;

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
    const-string v1, "source("

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lv01/e;->f:Lun/a;

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
