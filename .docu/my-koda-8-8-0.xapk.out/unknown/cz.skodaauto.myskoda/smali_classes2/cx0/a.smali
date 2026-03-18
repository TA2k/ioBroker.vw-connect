.class public final Lcx0/a;
.super Ljava/io/InputStream;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcx0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lcx0/a;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/io/InputStream;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method private final a()V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public available()I
    .locals 4

    .line 1
    iget v0, p0, Lcx0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/io/InputStream;->available()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lcx0/a;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lu01/b0;

    .line 14
    .line 15
    iget-boolean v0, p0, Lu01/b0;->f:Z

    .line 16
    .line 17
    if-nez v0, :cond_0

    .line 18
    .line 19
    iget-object p0, p0, Lu01/b0;->e:Lu01/f;

    .line 20
    .line 21
    iget-wide v0, p0, Lu01/f;->e:J

    .line 22
    .line 23
    const p0, 0x7fffffff

    .line 24
    .line 25
    .line 26
    int-to-long v2, p0

    .line 27
    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->min(JJ)J

    .line 28
    .line 29
    .line 30
    move-result-wide v0

    .line 31
    long-to-int p0, v0

    .line 32
    return p0

    .line 33
    :cond_0
    new-instance p0, Ljava/io/IOException;

    .line 34
    .line 35
    const-string v0, "closed"

    .line 36
    .line 37
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw p0

    .line 41
    :pswitch_1
    iget-object p0, p0, Lcx0/a;->e:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast p0, Lu01/f;

    .line 44
    .line 45
    iget-wide v0, p0, Lu01/f;->e:J

    .line 46
    .line 47
    const p0, 0x7fffffff

    .line 48
    .line 49
    .line 50
    int-to-long v2, p0

    .line 51
    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->min(JJ)J

    .line 52
    .line 53
    .line 54
    move-result-wide v0

    .line 55
    long-to-int p0, v0

    .line 56
    return p0

    .line 57
    :pswitch_2
    iget-object p0, p0, Lcx0/a;->e:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast p0, Lcx0/a;

    .line 60
    .line 61
    invoke-virtual {p0}, Ljava/io/InputStream;->available()I

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    return p0

    .line 66
    nop

    .line 67
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final close()V
    .locals 1

    .line 1
    iget v0, p0, Lcx0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcx0/a;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lu01/b0;

    .line 9
    .line 10
    invoke-virtual {p0}, Lu01/b0;->close()V

    .line 11
    .line 12
    .line 13
    :pswitch_0
    return-void

    .line 14
    :pswitch_1
    invoke-super {p0}, Ljava/io/InputStream;->close()V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lcx0/a;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Lcx0/a;

    .line 20
    .line 21
    invoke-virtual {p0}, Lcx0/a;->close()V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :pswitch_2
    iget-object p0, p0, Lcx0/a;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p0, Lio/ktor/utils/io/t;

    .line 28
    .line 29
    invoke-static {p0}, Lio/ktor/utils/io/h0;->a(Lio/ktor/utils/io/t;)V

    .line 30
    .line 31
    .line 32
    return-void

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final read()I
    .locals 5

    iget v0, p0, Lcx0/a;->d:I

    packed-switch v0, :pswitch_data_0

    .line 1
    iget-object p0, p0, Lcx0/a;->e:Ljava/lang/Object;

    check-cast p0, Lu01/b0;

    iget-object v0, p0, Lu01/b0;->e:Lu01/f;

    iget-boolean v1, p0, Lu01/b0;->f:Z

    if-nez v1, :cond_1

    .line 2
    iget-wide v1, v0, Lu01/f;->e:J

    const-wide/16 v3, 0x0

    cmp-long v1, v1, v3

    if-nez v1, :cond_0

    .line 3
    iget-object p0, p0, Lu01/b0;->d:Lu01/h0;

    const-wide/16 v1, 0x2000

    invoke-interface {p0, v0, v1, v2}, Lu01/h0;->A(Lu01/f;J)J

    move-result-wide v1

    const-wide/16 v3, -0x1

    cmp-long p0, v1, v3

    if-nez p0, :cond_0

    const/4 p0, -0x1

    goto :goto_0

    .line 4
    :cond_0
    invoke-virtual {v0}, Lu01/f;->readByte()B

    move-result p0

    and-int/lit16 p0, p0, 0xff

    :goto_0
    return p0

    .line 5
    :cond_1
    new-instance p0, Ljava/io/IOException;

    const-string v0, "closed"

    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 6
    :pswitch_0
    iget-object p0, p0, Lcx0/a;->e:Ljava/lang/Object;

    check-cast p0, Lu01/f;

    .line 7
    iget-wide v0, p0, Lu01/f;->e:J

    const-wide/16 v2, 0x0

    cmp-long v0, v0, v2

    if-lez v0, :cond_2

    .line 8
    invoke-virtual {p0}, Lu01/f;->readByte()B

    move-result p0

    and-int/lit16 p0, p0, 0xff

    goto :goto_1

    :cond_2
    const/4 p0, -0x1

    :goto_1
    return p0

    .line 9
    :pswitch_1
    iget-object p0, p0, Lcx0/a;->e:Ljava/lang/Object;

    check-cast p0, Lcx0/a;

    invoke-virtual {p0}, Lcx0/a;->read()I

    move-result p0

    return p0

    .line 10
    :pswitch_2
    iget-object p0, p0, Lcx0/a;->e:Ljava/lang/Object;

    check-cast p0, Lio/ktor/utils/io/t;

    invoke-interface {p0}, Lio/ktor/utils/io/t;->g()Z

    move-result v0

    if-eqz v0, :cond_3

    goto :goto_2

    .line 11
    :cond_3
    invoke-interface {p0}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    move-result-object v0

    invoke-virtual {v0}, Lnz0/a;->Z()Z

    move-result v0

    if-eqz v0, :cond_4

    .line 12
    new-instance v0, La50/a;

    const/16 v1, 0x19

    const/4 v2, 0x0

    invoke-direct {v0, p0, v2, v1}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    invoke-static {v0}, Lvy0/e0;->L(Lay0/n;)Ljava/lang/Object;

    .line 13
    :cond_4
    invoke-interface {p0}, Lio/ktor/utils/io/t;->g()Z

    move-result v0

    if-eqz v0, :cond_5

    :goto_2
    const/4 p0, -0x1

    goto :goto_3

    .line 14
    :cond_5
    invoke-interface {p0}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    move-result-object p0

    invoke-virtual {p0}, Lnz0/a;->readByte()B

    move-result p0

    and-int/lit16 p0, p0, 0xff

    :goto_3
    return p0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final read([BII)I
    .locals 8

    iget v0, p0, Lcx0/a;->d:I

    packed-switch v0, :pswitch_data_0

    const-string v0, "data"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    iget-object p0, p0, Lcx0/a;->e:Ljava/lang/Object;

    check-cast p0, Lu01/b0;

    iget-object v0, p0, Lu01/b0;->e:Lu01/f;

    iget-boolean v1, p0, Lu01/b0;->f:Z

    if-nez v1, :cond_1

    .line 16
    array-length v1, p1

    int-to-long v2, v1

    int-to-long v4, p2

    int-to-long v6, p3

    invoke-static/range {v2 .. v7}, Lu01/b;->e(JJJ)V

    .line 17
    iget-wide v1, v0, Lu01/f;->e:J

    const-wide/16 v3, 0x0

    cmp-long v1, v1, v3

    if-nez v1, :cond_0

    .line 18
    iget-object p0, p0, Lu01/b0;->d:Lu01/h0;

    const-wide/16 v1, 0x2000

    invoke-interface {p0, v0, v1, v2}, Lu01/h0;->A(Lu01/f;J)J

    move-result-wide v1

    const-wide/16 v3, -0x1

    cmp-long p0, v1, v3

    if-nez p0, :cond_0

    const/4 p0, -0x1

    goto :goto_0

    .line 19
    :cond_0
    invoke-virtual {v0, p1, p2, p3}, Lu01/f;->read([BII)I

    move-result p0

    :goto_0
    return p0

    .line 20
    :cond_1
    new-instance p0, Ljava/io/IOException;

    const-string p1, "closed"

    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 21
    :pswitch_0
    const-string v0, "sink"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    iget-object p0, p0, Lcx0/a;->e:Ljava/lang/Object;

    check-cast p0, Lu01/f;

    invoke-virtual {p0, p1, p2, p3}, Lu01/f;->read([BII)I

    move-result p0

    return p0

    .line 23
    :pswitch_1
    const-string v0, "b"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    iget-object p0, p0, Lcx0/a;->e:Ljava/lang/Object;

    check-cast p0, Lcx0/a;

    invoke-virtual {p0, p1, p2, p3}, Lcx0/a;->read([BII)I

    move-result p0

    return p0

    .line 25
    :pswitch_2
    const-string v0, "b"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    iget-object p0, p0, Lcx0/a;->e:Ljava/lang/Object;

    check-cast p0, Lio/ktor/utils/io/t;

    invoke-interface {p0}, Lio/ktor/utils/io/t;->g()Z

    move-result v0

    if-eqz v0, :cond_2

    goto :goto_1

    .line 27
    :cond_2
    invoke-interface {p0}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    move-result-object v0

    invoke-virtual {v0}, Lnz0/a;->Z()Z

    move-result v0

    if-eqz v0, :cond_3

    .line 28
    new-instance v0, La50/a;

    const/16 v1, 0x19

    const/4 v2, 0x0

    invoke-direct {v0, p0, v2, v1}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    invoke-static {v0}, Lvy0/e0;->L(Lay0/n;)Ljava/lang/Object;

    .line 29
    :cond_3
    invoke-interface {p0}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    iget-wide v0, v0, Lnz0/a;->f:J

    long-to-int v0, v0

    .line 31
    invoke-static {v0, p3}, Ljava/lang/Math;->min(II)I

    move-result p3

    .line 32
    invoke-interface {p0}, Lio/ktor/utils/io/t;->e()Lnz0/a;

    move-result-object v0

    add-int/2addr p3, p2

    invoke-virtual {v0, p1, p2, p3}, Lnz0/a;->a([BII)I

    move-result p1

    if-ltz p1, :cond_4

    goto :goto_2

    .line 33
    :cond_4
    invoke-interface {p0}, Lio/ktor/utils/io/t;->g()Z

    move-result p0

    if-eqz p0, :cond_5

    :goto_1
    const/4 p1, -0x1

    goto :goto_2

    :cond_5
    const/4 p1, 0x0

    :goto_2
    return p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    iget v0, p0, Lcx0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lcx0/a;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lu01/b0;

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, ".inputStream()"

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :pswitch_1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 34
    .line 35
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lcx0/a;->e:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p0, Lu01/f;

    .line 41
    .line 42
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string p0, ".inputStream()"

    .line 46
    .line 47
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0

    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public transferTo(Ljava/io/OutputStream;)J
    .locals 14

    .line 1
    iget v0, p0, Lcx0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Ljava/io/InputStream;->transferTo(Ljava/io/OutputStream;)J

    .line 7
    .line 8
    .line 9
    move-result-wide p0

    .line 10
    return-wide p0

    .line 11
    :pswitch_0
    const-string v0, "out"

    .line 12
    .line 13
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lcx0/a;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lu01/b0;

    .line 19
    .line 20
    iget-object v0, p0, Lu01/b0;->e:Lu01/f;

    .line 21
    .line 22
    iget-boolean v1, p0, Lu01/b0;->f:Z

    .line 23
    .line 24
    if-nez v1, :cond_4

    .line 25
    .line 26
    const-wide/16 v1, 0x0

    .line 27
    .line 28
    move-wide v3, v1

    .line 29
    :cond_0
    iget-wide v5, v0, Lu01/f;->e:J

    .line 30
    .line 31
    cmp-long v5, v5, v1

    .line 32
    .line 33
    if-nez v5, :cond_2

    .line 34
    .line 35
    iget-object v5, p0, Lu01/b0;->d:Lu01/h0;

    .line 36
    .line 37
    const-wide/16 v6, 0x2000

    .line 38
    .line 39
    invoke-interface {v5, v0, v6, v7}, Lu01/h0;->A(Lu01/f;J)J

    .line 40
    .line 41
    .line 42
    move-result-wide v5

    .line 43
    const-wide/16 v7, -0x1

    .line 44
    .line 45
    cmp-long v5, v5, v7

    .line 46
    .line 47
    if-eqz v5, :cond_1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_1
    return-wide v3

    .line 51
    :cond_2
    :goto_0
    iget-wide v6, v0, Lu01/f;->e:J

    .line 52
    .line 53
    add-long/2addr v3, v6

    .line 54
    const-wide/16 v8, 0x0

    .line 55
    .line 56
    move-wide v10, v6

    .line 57
    invoke-static/range {v6 .. v11}, Lu01/b;->e(JJJ)V

    .line 58
    .line 59
    .line 60
    iget-object v5, v0, Lu01/f;->d:Lu01/c0;

    .line 61
    .line 62
    :cond_3
    :goto_1
    cmp-long v8, v6, v1

    .line 63
    .line 64
    if-lez v8, :cond_0

    .line 65
    .line 66
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    iget v8, v5, Lu01/c0;->c:I

    .line 70
    .line 71
    iget v9, v5, Lu01/c0;->b:I

    .line 72
    .line 73
    sub-int/2addr v8, v9

    .line 74
    int-to-long v8, v8

    .line 75
    invoke-static {v6, v7, v8, v9}, Ljava/lang/Math;->min(JJ)J

    .line 76
    .line 77
    .line 78
    move-result-wide v8

    .line 79
    long-to-int v8, v8

    .line 80
    iget-object v9, v5, Lu01/c0;->a:[B

    .line 81
    .line 82
    iget v10, v5, Lu01/c0;->b:I

    .line 83
    .line 84
    invoke-virtual {p1, v9, v10, v8}, Ljava/io/OutputStream;->write([BII)V

    .line 85
    .line 86
    .line 87
    iget v9, v5, Lu01/c0;->b:I

    .line 88
    .line 89
    add-int/2addr v9, v8

    .line 90
    iput v9, v5, Lu01/c0;->b:I

    .line 91
    .line 92
    iget-wide v10, v0, Lu01/f;->e:J

    .line 93
    .line 94
    int-to-long v12, v8

    .line 95
    sub-long/2addr v10, v12

    .line 96
    iput-wide v10, v0, Lu01/f;->e:J

    .line 97
    .line 98
    sub-long/2addr v6, v12

    .line 99
    iget v8, v5, Lu01/c0;->c:I

    .line 100
    .line 101
    if-ne v9, v8, :cond_3

    .line 102
    .line 103
    invoke-virtual {v5}, Lu01/c0;->a()Lu01/c0;

    .line 104
    .line 105
    .line 106
    move-result-object v8

    .line 107
    iput-object v8, v0, Lu01/f;->d:Lu01/c0;

    .line 108
    .line 109
    invoke-static {v5}, Lu01/d0;->a(Lu01/c0;)V

    .line 110
    .line 111
    .line 112
    move-object v5, v8

    .line 113
    goto :goto_1

    .line 114
    :cond_4
    new-instance p0, Ljava/io/IOException;

    .line 115
    .line 116
    const-string p1, "closed"

    .line 117
    .line 118
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    throw p0

    .line 122
    nop

    .line 123
    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
    .end packed-switch
.end method
