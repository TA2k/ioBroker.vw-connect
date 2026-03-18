.class public final Lu01/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu01/h;


# instance fields
.field public final d:Lu01/h0;

.field public final e:Lu01/f;

.field public f:Z


# direct methods
.method public constructor <init>(Lu01/h0;)V
    .locals 1

    .line 1
    const-string v0, "source"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lu01/b0;->d:Lu01/h0;

    .line 10
    .line 11
    new-instance p1, Lu01/f;

    .line 12
    .line 13
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lu01/b0;->e:Lu01/f;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final A(Lu01/f;J)J
    .locals 6

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
    if-ltz v2, :cond_3

    .line 11
    .line 12
    iget-boolean v3, p0, Lu01/b0;->f:Z

    .line 13
    .line 14
    if-nez v3, :cond_2

    .line 15
    .line 16
    iget-object v3, p0, Lu01/b0;->e:Lu01/f;

    .line 17
    .line 18
    iget-wide v4, v3, Lu01/f;->e:J

    .line 19
    .line 20
    cmp-long v4, v4, v0

    .line 21
    .line 22
    if-nez v4, :cond_1

    .line 23
    .line 24
    if-nez v2, :cond_0

    .line 25
    .line 26
    return-wide v0

    .line 27
    :cond_0
    iget-object p0, p0, Lu01/b0;->d:Lu01/h0;

    .line 28
    .line 29
    const-wide/16 v0, 0x2000

    .line 30
    .line 31
    invoke-interface {p0, v3, v0, v1}, Lu01/h0;->A(Lu01/f;J)J

    .line 32
    .line 33
    .line 34
    move-result-wide v0

    .line 35
    const-wide/16 v4, -0x1

    .line 36
    .line 37
    cmp-long p0, v0, v4

    .line 38
    .line 39
    if-nez p0, :cond_1

    .line 40
    .line 41
    return-wide v4

    .line 42
    :cond_1
    iget-wide v0, v3, Lu01/f;->e:J

    .line 43
    .line 44
    invoke-static {p2, p3, v0, v1}, Ljava/lang/Math;->min(JJ)J

    .line 45
    .line 46
    .line 47
    move-result-wide p2

    .line 48
    invoke-virtual {v3, p1, p2, p3}, Lu01/f;->A(Lu01/f;J)J

    .line 49
    .line 50
    .line 51
    move-result-wide p0

    .line 52
    return-wide p0

    .line 53
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string p1, "closed"

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_3
    const-string p0, "byteCount < 0: "

    .line 62
    .line 63
    invoke-static {p2, p3, p0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 68
    .line 69
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw p1
.end method

.method public final D(JLu01/i;)J
    .locals 1

    .line 1
    const-string v0, "bytes"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3}, Lu01/i;->d()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    invoke-static {p0, p3, v0, p1, p2}, Lv01/b;->c(Lu01/b0;Lu01/i;IJ)J

    .line 11
    .line 12
    .line 13
    move-result-wide p0

    .line 14
    return-wide p0
.end method

.method public final L(Lu01/g;)J
    .locals 10

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    move-wide v2, v0

    .line 4
    :cond_0
    :goto_0
    iget-object v4, p0, Lu01/b0;->d:Lu01/h0;

    .line 5
    .line 6
    const-wide/16 v5, 0x2000

    .line 7
    .line 8
    iget-object v7, p0, Lu01/b0;->e:Lu01/f;

    .line 9
    .line 10
    invoke-interface {v4, v7, v5, v6}, Lu01/h0;->A(Lu01/f;J)J

    .line 11
    .line 12
    .line 13
    move-result-wide v4

    .line 14
    const-wide/16 v8, -0x1

    .line 15
    .line 16
    cmp-long v4, v4, v8

    .line 17
    .line 18
    if-eqz v4, :cond_1

    .line 19
    .line 20
    invoke-virtual {v7}, Lu01/f;->d()J

    .line 21
    .line 22
    .line 23
    move-result-wide v4

    .line 24
    cmp-long v6, v4, v0

    .line 25
    .line 26
    if-lez v6, :cond_0

    .line 27
    .line 28
    add-long/2addr v2, v4

    .line 29
    invoke-interface {p1, v7, v4, v5}, Lu01/f0;->F(Lu01/f;J)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    iget-wide v4, v7, Lu01/f;->e:J

    .line 34
    .line 35
    cmp-long p0, v4, v0

    .line 36
    .line 37
    if-lez p0, :cond_2

    .line 38
    .line 39
    add-long/2addr v2, v4

    .line 40
    invoke-interface {p1, v7, v4, v5}, Lu01/f0;->F(Lu01/f;J)V

    .line 41
    .line 42
    .line 43
    :cond_2
    return-wide v2
.end method

.method public final Q(Lu01/w;)I
    .locals 6

    .line 1
    const-string v0, "options"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p0, Lu01/b0;->f:Z

    .line 7
    .line 8
    if-nez v0, :cond_3

    .line 9
    .line 10
    :cond_0
    const/4 v0, 0x1

    .line 11
    iget-object v1, p0, Lu01/b0;->e:Lu01/f;

    .line 12
    .line 13
    invoke-static {v1, p1, v0}, Lv01/a;->d(Lu01/f;Lu01/w;Z)I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v2, -0x2

    .line 18
    const/4 v3, -0x1

    .line 19
    if-eq v0, v2, :cond_1

    .line 20
    .line 21
    if-eq v0, v3, :cond_2

    .line 22
    .line 23
    iget-object p0, p1, Lu01/w;->d:[Lu01/i;

    .line 24
    .line 25
    aget-object p0, p0, v0

    .line 26
    .line 27
    invoke-virtual {p0}, Lu01/i;->d()I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    int-to-long p0, p0

    .line 32
    invoke-virtual {v1, p0, p1}, Lu01/f;->skip(J)V

    .line 33
    .line 34
    .line 35
    return v0

    .line 36
    :cond_1
    iget-object v0, p0, Lu01/b0;->d:Lu01/h0;

    .line 37
    .line 38
    const-wide/16 v4, 0x2000

    .line 39
    .line 40
    invoke-interface {v0, v1, v4, v5}, Lu01/h0;->A(Lu01/f;J)J

    .line 41
    .line 42
    .line 43
    move-result-wide v0

    .line 44
    const-wide/16 v4, -0x1

    .line 45
    .line 46
    cmp-long v0, v0, v4

    .line 47
    .line 48
    if-nez v0, :cond_0

    .line 49
    .line 50
    :cond_2
    return v3

    .line 51
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string p1, "closed"

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0
.end method

.method public final S(J)Lu01/i;
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lu01/b0;->e(J)V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lu01/b0;->e:Lu01/f;

    .line 5
    .line 6
    invoke-virtual {p0, p1, p2}, Lu01/f;->S(J)Lu01/i;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public final Y()[B
    .locals 2

    .line 1
    iget-object v0, p0, Lu01/b0;->d:Lu01/h0;

    .line 2
    .line 3
    iget-object p0, p0, Lu01/b0;->e:Lu01/f;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lu01/f;->P(Lu01/h0;)J

    .line 6
    .line 7
    .line 8
    iget-wide v0, p0, Lu01/f;->e:J

    .line 9
    .line 10
    invoke-virtual {p0, v0, v1}, Lu01/f;->q(J)[B

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public final Z()Z
    .locals 4

    .line 1
    iget-boolean v0, p0, Lu01/b0;->f:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lu01/b0;->e:Lu01/f;

    .line 6
    .line 7
    invoke-virtual {v0}, Lu01/f;->Z()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    iget-object p0, p0, Lu01/b0;->d:Lu01/h0;

    .line 14
    .line 15
    const-wide/16 v1, 0x2000

    .line 16
    .line 17
    invoke-interface {p0, v0, v1, v2}, Lu01/h0;->A(Lu01/f;J)J

    .line 18
    .line 19
    .line 20
    move-result-wide v0

    .line 21
    const-wide/16 v2, -0x1

    .line 22
    .line 23
    cmp-long p0, v0, v2

    .line 24
    .line 25
    if-nez p0, :cond_0

    .line 26
    .line 27
    const/4 p0, 0x1

    .line 28
    return p0

    .line 29
    :cond_0
    const/4 p0, 0x0

    .line 30
    return p0

    .line 31
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 32
    .line 33
    const-string v0, "closed"

    .line 34
    .line 35
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0
.end method

.method public final a(BJJ)J
    .locals 9

    .line 1
    iget-boolean p2, p0, Lu01/b0;->f:Z

    .line 2
    .line 3
    if-nez p2, :cond_4

    .line 4
    .line 5
    const-wide/16 p2, 0x0

    .line 6
    .line 7
    cmp-long v0, p2, p4

    .line 8
    .line 9
    if-gtz v0, :cond_3

    .line 10
    .line 11
    move-wide v3, p2

    .line 12
    :goto_0
    cmp-long p2, v3, p4

    .line 13
    .line 14
    const-wide/16 v7, -0x1

    .line 15
    .line 16
    if-gez p2, :cond_2

    .line 17
    .line 18
    iget-object v1, p0, Lu01/b0;->e:Lu01/f;

    .line 19
    .line 20
    move v2, p1

    .line 21
    move-wide v5, p4

    .line 22
    invoke-virtual/range {v1 .. v6}, Lu01/f;->j(BJJ)J

    .line 23
    .line 24
    .line 25
    move-result-wide p1

    .line 26
    cmp-long p3, p1, v7

    .line 27
    .line 28
    if-eqz p3, :cond_0

    .line 29
    .line 30
    return-wide p1

    .line 31
    :cond_0
    iget-wide p1, v1, Lu01/f;->e:J

    .line 32
    .line 33
    cmp-long p3, p1, v5

    .line 34
    .line 35
    if-gez p3, :cond_2

    .line 36
    .line 37
    iget-object p3, p0, Lu01/b0;->d:Lu01/h0;

    .line 38
    .line 39
    const-wide/16 p4, 0x2000

    .line 40
    .line 41
    invoke-interface {p3, v1, p4, p5}, Lu01/h0;->A(Lu01/f;J)J

    .line 42
    .line 43
    .line 44
    move-result-wide p3

    .line 45
    cmp-long p3, p3, v7

    .line 46
    .line 47
    if-nez p3, :cond_1

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    invoke-static {v3, v4, p1, p2}, Ljava/lang/Math;->max(JJ)J

    .line 51
    .line 52
    .line 53
    move-result-wide v3

    .line 54
    move p1, v2

    .line 55
    move-wide p4, v5

    .line 56
    goto :goto_0

    .line 57
    :cond_2
    :goto_1
    return-wide v7

    .line 58
    :cond_3
    move-wide v5, p4

    .line 59
    const-string p0, "fromIndex=0 toIndex="

    .line 60
    .line 61
    invoke-static {v5, v6, p0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 66
    .line 67
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    throw p1

    .line 75
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 76
    .line 77
    const-string p1, "closed"

    .line 78
    .line 79
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    throw p0
.end method

.method public final b()Lu01/b0;
    .locals 1

    .line 1
    new-instance v0, Lu01/z;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lu01/z;-><init>(Lu01/h;)V

    .line 4
    .line 5
    .line 6
    invoke-static {v0}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public final c(J)Z
    .locals 4

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p1, v0

    .line 4
    .line 5
    if-ltz v0, :cond_3

    .line 6
    .line 7
    iget-boolean v0, p0, Lu01/b0;->f:Z

    .line 8
    .line 9
    if-nez v0, :cond_2

    .line 10
    .line 11
    :cond_0
    iget-object v0, p0, Lu01/b0;->e:Lu01/f;

    .line 12
    .line 13
    iget-wide v1, v0, Lu01/f;->e:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-gez v1, :cond_1

    .line 18
    .line 19
    iget-object v1, p0, Lu01/b0;->d:Lu01/h0;

    .line 20
    .line 21
    const-wide/16 v2, 0x2000

    .line 22
    .line 23
    invoke-interface {v1, v0, v2, v3}, Lu01/h0;->A(Lu01/f;J)J

    .line 24
    .line 25
    .line 26
    move-result-wide v0

    .line 27
    const-wide/16 v2, -0x1

    .line 28
    .line 29
    cmp-long v0, v0, v2

    .line 30
    .line 31
    if-nez v0, :cond_0

    .line 32
    .line 33
    const/4 p0, 0x0

    .line 34
    return p0

    .line 35
    :cond_1
    const/4 p0, 0x1

    .line 36
    return p0

    .line 37
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 38
    .line 39
    const-string p1, "closed"

    .line 40
    .line 41
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0

    .line 45
    :cond_3
    const-string p0, "byteCount < 0: "

    .line 46
    .line 47
    invoke-static {p1, p2, p0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 52
    .line 53
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p1
.end method

.method public final close()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lu01/b0;->f:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    iput-boolean v0, p0, Lu01/b0;->f:Z

    .line 7
    .line 8
    iget-object v0, p0, Lu01/b0;->d:Lu01/h0;

    .line 9
    .line 10
    invoke-interface {v0}, Ljava/io/Closeable;->close()V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lu01/b0;->e:Lu01/f;

    .line 14
    .line 15
    invoke-virtual {p0}, Lu01/f;->a()V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public final d()I
    .locals 2

    .line 1
    const-wide/16 v0, 0x4

    .line 2
    .line 3
    invoke-virtual {p0, v0, v1}, Lu01/b0;->e(J)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu01/b0;->e:Lu01/f;

    .line 7
    .line 8
    invoke-virtual {p0}, Lu01/f;->readInt()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    const/high16 v0, -0x1000000

    .line 13
    .line 14
    and-int/2addr v0, p0

    .line 15
    ushr-int/lit8 v0, v0, 0x18

    .line 16
    .line 17
    const/high16 v1, 0xff0000

    .line 18
    .line 19
    and-int/2addr v1, p0

    .line 20
    ushr-int/lit8 v1, v1, 0x8

    .line 21
    .line 22
    or-int/2addr v0, v1

    .line 23
    const v1, 0xff00

    .line 24
    .line 25
    .line 26
    and-int/2addr v1, p0

    .line 27
    shl-int/lit8 v1, v1, 0x8

    .line 28
    .line 29
    or-int/2addr v0, v1

    .line 30
    and-int/lit16 p0, p0, 0xff

    .line 31
    .line 32
    shl-int/lit8 p0, p0, 0x18

    .line 33
    .line 34
    or-int/2addr p0, v0

    .line 35
    return p0
.end method

.method public final e(J)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lu01/b0;->c(J)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    new-instance p0, Ljava/io/EOFException;

    .line 9
    .line 10
    invoke-direct {p0}, Ljava/io/EOFException;-><init>()V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public final f()J
    .locals 15

    .line 1
    const-wide/16 v0, 0x8

    .line 2
    .line 3
    invoke-virtual {p0, v0, v1}, Lu01/b0;->e(J)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu01/b0;->e:Lu01/f;

    .line 7
    .line 8
    iget-wide v0, p0, Lu01/f;->e:J

    .line 9
    .line 10
    const-wide/16 v2, 0x8

    .line 11
    .line 12
    cmp-long v0, v0, v2

    .line 13
    .line 14
    if-ltz v0, :cond_2

    .line 15
    .line 16
    iget-object v0, p0, Lu01/f;->d:Lu01/c0;

    .line 17
    .line 18
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    iget v1, v0, Lu01/c0;->b:I

    .line 22
    .line 23
    iget v4, v0, Lu01/c0;->c:I

    .line 24
    .line 25
    sub-int v5, v4, v1

    .line 26
    .line 27
    int-to-long v5, v5

    .line 28
    cmp-long v5, v5, v2

    .line 29
    .line 30
    const/16 v6, 0x20

    .line 31
    .line 32
    if-gez v5, :cond_0

    .line 33
    .line 34
    invoke-virtual {p0}, Lu01/f;->readInt()I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    int-to-long v0, v0

    .line 39
    const-wide v2, 0xffffffffL

    .line 40
    .line 41
    .line 42
    .line 43
    .line 44
    and-long/2addr v0, v2

    .line 45
    shl-long/2addr v0, v6

    .line 46
    invoke-virtual {p0}, Lu01/f;->readInt()I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    int-to-long v4, p0

    .line 51
    and-long/2addr v2, v4

    .line 52
    or-long/2addr v0, v2

    .line 53
    goto :goto_1

    .line 54
    :cond_0
    iget-object v5, v0, Lu01/c0;->a:[B

    .line 55
    .line 56
    add-int/lit8 v7, v1, 0x1

    .line 57
    .line 58
    aget-byte v8, v5, v1

    .line 59
    .line 60
    int-to-long v8, v8

    .line 61
    const-wide/16 v10, 0xff

    .line 62
    .line 63
    and-long/2addr v8, v10

    .line 64
    const/16 v12, 0x38

    .line 65
    .line 66
    shl-long/2addr v8, v12

    .line 67
    add-int/lit8 v12, v1, 0x2

    .line 68
    .line 69
    aget-byte v7, v5, v7

    .line 70
    .line 71
    int-to-long v13, v7

    .line 72
    and-long/2addr v13, v10

    .line 73
    const/16 v7, 0x30

    .line 74
    .line 75
    shl-long/2addr v13, v7

    .line 76
    or-long v7, v8, v13

    .line 77
    .line 78
    add-int/lit8 v9, v1, 0x3

    .line 79
    .line 80
    aget-byte v12, v5, v12

    .line 81
    .line 82
    int-to-long v12, v12

    .line 83
    and-long/2addr v12, v10

    .line 84
    const/16 v14, 0x28

    .line 85
    .line 86
    shl-long/2addr v12, v14

    .line 87
    or-long/2addr v7, v12

    .line 88
    add-int/lit8 v12, v1, 0x4

    .line 89
    .line 90
    aget-byte v9, v5, v9

    .line 91
    .line 92
    int-to-long v13, v9

    .line 93
    and-long/2addr v13, v10

    .line 94
    shl-long/2addr v13, v6

    .line 95
    or-long v6, v7, v13

    .line 96
    .line 97
    add-int/lit8 v8, v1, 0x5

    .line 98
    .line 99
    aget-byte v9, v5, v12

    .line 100
    .line 101
    int-to-long v12, v9

    .line 102
    and-long/2addr v12, v10

    .line 103
    const/16 v9, 0x18

    .line 104
    .line 105
    shl-long/2addr v12, v9

    .line 106
    or-long/2addr v6, v12

    .line 107
    add-int/lit8 v9, v1, 0x6

    .line 108
    .line 109
    aget-byte v8, v5, v8

    .line 110
    .line 111
    int-to-long v12, v8

    .line 112
    and-long/2addr v12, v10

    .line 113
    const/16 v8, 0x10

    .line 114
    .line 115
    shl-long/2addr v12, v8

    .line 116
    or-long/2addr v6, v12

    .line 117
    add-int/lit8 v8, v1, 0x7

    .line 118
    .line 119
    aget-byte v9, v5, v9

    .line 120
    .line 121
    int-to-long v12, v9

    .line 122
    and-long/2addr v12, v10

    .line 123
    const/16 v9, 0x8

    .line 124
    .line 125
    shl-long/2addr v12, v9

    .line 126
    or-long/2addr v6, v12

    .line 127
    add-int/2addr v1, v9

    .line 128
    aget-byte v5, v5, v8

    .line 129
    .line 130
    int-to-long v8, v5

    .line 131
    and-long/2addr v8, v10

    .line 132
    or-long v5, v6, v8

    .line 133
    .line 134
    iget-wide v7, p0, Lu01/f;->e:J

    .line 135
    .line 136
    sub-long/2addr v7, v2

    .line 137
    iput-wide v7, p0, Lu01/f;->e:J

    .line 138
    .line 139
    if-ne v1, v4, :cond_1

    .line 140
    .line 141
    invoke-virtual {v0}, Lu01/c0;->a()Lu01/c0;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    iput-object v1, p0, Lu01/f;->d:Lu01/c0;

    .line 146
    .line 147
    invoke-static {v0}, Lu01/d0;->a(Lu01/c0;)V

    .line 148
    .line 149
    .line 150
    :goto_0
    move-wide v0, v5

    .line 151
    goto :goto_1

    .line 152
    :cond_1
    iput v1, v0, Lu01/c0;->b:I

    .line 153
    .line 154
    goto :goto_0

    .line 155
    :goto_1
    const-wide/high16 v2, -0x100000000000000L

    .line 156
    .line 157
    and-long/2addr v2, v0

    .line 158
    const/16 p0, 0x38

    .line 159
    .line 160
    ushr-long/2addr v2, p0

    .line 161
    const-wide/high16 v4, 0xff000000000000L

    .line 162
    .line 163
    and-long/2addr v4, v0

    .line 164
    const/16 v6, 0x28

    .line 165
    .line 166
    ushr-long/2addr v4, v6

    .line 167
    or-long/2addr v2, v4

    .line 168
    const-wide v4, 0xff0000000000L

    .line 169
    .line 170
    .line 171
    .line 172
    .line 173
    and-long/2addr v4, v0

    .line 174
    const/16 v7, 0x18

    .line 175
    .line 176
    ushr-long/2addr v4, v7

    .line 177
    or-long/2addr v2, v4

    .line 178
    const-wide v4, 0xff00000000L

    .line 179
    .line 180
    .line 181
    .line 182
    .line 183
    and-long/2addr v4, v0

    .line 184
    const/16 v8, 0x8

    .line 185
    .line 186
    ushr-long/2addr v4, v8

    .line 187
    or-long/2addr v2, v4

    .line 188
    const-wide v4, 0xff000000L

    .line 189
    .line 190
    .line 191
    .line 192
    .line 193
    and-long/2addr v4, v0

    .line 194
    shl-long/2addr v4, v8

    .line 195
    or-long/2addr v2, v4

    .line 196
    const-wide/32 v4, 0xff0000

    .line 197
    .line 198
    .line 199
    and-long/2addr v4, v0

    .line 200
    shl-long/2addr v4, v7

    .line 201
    or-long/2addr v2, v4

    .line 202
    const-wide/32 v4, 0xff00

    .line 203
    .line 204
    .line 205
    and-long/2addr v4, v0

    .line 206
    shl-long/2addr v4, v6

    .line 207
    or-long/2addr v2, v4

    .line 208
    const-wide/16 v4, 0xff

    .line 209
    .line 210
    and-long/2addr v0, v4

    .line 211
    shl-long/2addr v0, p0

    .line 212
    or-long/2addr v0, v2

    .line 213
    return-wide v0

    .line 214
    :cond_2
    new-instance p0, Ljava/io/EOFException;

    .line 215
    .line 216
    invoke-direct {p0}, Ljava/io/EOFException;-><init>()V

    .line 217
    .line 218
    .line 219
    throw p0
.end method

.method public final f0(Ljava/nio/charset/Charset;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "charset"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lu01/b0;->d:Lu01/h0;

    .line 7
    .line 8
    iget-object p0, p0, Lu01/b0;->e:Lu01/f;

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Lu01/f;->P(Lu01/h0;)J

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lu01/f;->f0(Ljava/nio/charset/Charset;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final g()S
    .locals 2

    .line 1
    const-wide/16 v0, 0x2

    .line 2
    .line 3
    invoke-virtual {p0, v0, v1}, Lu01/b0;->e(J)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu01/b0;->e:Lu01/f;

    .line 7
    .line 8
    invoke-virtual {p0}, Lu01/f;->H()S

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final h(J)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0, p1, p2}, Lu01/b0;->e(J)V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lu01/b0;->e:Lu01/f;

    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    sget-object v0, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 10
    .line 11
    invoke-virtual {p0, p1, p2, v0}, Lu01/f;->M(JLjava/nio/charset/Charset;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final i(Lu01/i;)J
    .locals 2

    .line 1
    const-string v0, "bytes"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-wide v0, 0x7fffffffffffffffL

    .line 7
    .line 8
    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, v0, v1, p1}, Lu01/b0;->D(JLu01/i;)J

    .line 12
    .line 13
    .line 14
    move-result-wide p0

    .line 15
    return-wide p0
.end method

.method public final isOpen()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lu01/b0;->f:Z

    .line 2
    .line 3
    xor-int/lit8 p0, p0, 0x1

    .line 4
    .line 5
    return p0
.end method

.method public final n()Lu01/f;
    .locals 0

    .line 1
    iget-object p0, p0, Lu01/b0;->e:Lu01/f;

    .line 2
    .line 3
    return-object p0
.end method

.method public final read(Ljava/nio/ByteBuffer;)I
    .locals 5

    .line 1
    const-string v0, "sink"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lu01/b0;->e:Lu01/f;

    .line 7
    .line 8
    iget-wide v1, v0, Lu01/f;->e:J

    .line 9
    .line 10
    const-wide/16 v3, 0x0

    .line 11
    .line 12
    cmp-long v1, v1, v3

    .line 13
    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    iget-object p0, p0, Lu01/b0;->d:Lu01/h0;

    .line 17
    .line 18
    const-wide/16 v1, 0x2000

    .line 19
    .line 20
    invoke-interface {p0, v0, v1, v2}, Lu01/h0;->A(Lu01/f;J)J

    .line 21
    .line 22
    .line 23
    move-result-wide v1

    .line 24
    const-wide/16 v3, -0x1

    .line 25
    .line 26
    cmp-long p0, v1, v3

    .line 27
    .line 28
    if-nez p0, :cond_0

    .line 29
    .line 30
    const/4 p0, -0x1

    .line 31
    return p0

    .line 32
    :cond_0
    invoke-virtual {v0, p1}, Lu01/f;->read(Ljava/nio/ByteBuffer;)I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    return p0
.end method

.method public final readByte()B
    .locals 2

    .line 1
    const-wide/16 v0, 0x1

    .line 2
    .line 3
    invoke-virtual {p0, v0, v1}, Lu01/b0;->e(J)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu01/b0;->e:Lu01/f;

    .line 7
    .line 8
    invoke-virtual {p0}, Lu01/f;->readByte()B

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final readInt()I
    .locals 2

    .line 1
    const-wide/16 v0, 0x4

    .line 2
    .line 3
    invoke-virtual {p0, v0, v1}, Lu01/b0;->e(J)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu01/b0;->e:Lu01/f;

    .line 7
    .line 8
    invoke-virtual {p0}, Lu01/f;->readInt()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final readShort()S
    .locals 2

    .line 1
    const-wide/16 v0, 0x2

    .line 2
    .line 3
    invoke-virtual {p0, v0, v1}, Lu01/b0;->e(J)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lu01/b0;->e:Lu01/f;

    .line 7
    .line 8
    invoke-virtual {p0}, Lu01/f;->readShort()S

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final skip(J)V
    .locals 5

    .line 1
    iget-boolean v0, p0, Lu01/b0;->f:Z

    .line 2
    .line 3
    if-nez v0, :cond_3

    .line 4
    .line 5
    :goto_0
    const-wide/16 v0, 0x0

    .line 6
    .line 7
    cmp-long v2, p1, v0

    .line 8
    .line 9
    if-lez v2, :cond_2

    .line 10
    .line 11
    iget-object v2, p0, Lu01/b0;->e:Lu01/f;

    .line 12
    .line 13
    iget-wide v3, v2, Lu01/f;->e:J

    .line 14
    .line 15
    cmp-long v0, v3, v0

    .line 16
    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    iget-object v0, p0, Lu01/b0;->d:Lu01/h0;

    .line 20
    .line 21
    const-wide/16 v3, 0x2000

    .line 22
    .line 23
    invoke-interface {v0, v2, v3, v4}, Lu01/h0;->A(Lu01/f;J)J

    .line 24
    .line 25
    .line 26
    move-result-wide v0

    .line 27
    const-wide/16 v3, -0x1

    .line 28
    .line 29
    cmp-long v0, v0, v3

    .line 30
    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_0
    new-instance p0, Ljava/io/EOFException;

    .line 35
    .line 36
    invoke-direct {p0}, Ljava/io/EOFException;-><init>()V

    .line 37
    .line 38
    .line 39
    throw p0

    .line 40
    :cond_1
    :goto_1
    iget-wide v0, v2, Lu01/f;->e:J

    .line 41
    .line 42
    invoke-static {p1, p2, v0, v1}, Ljava/lang/Math;->min(JJ)J

    .line 43
    .line 44
    .line 45
    move-result-wide v0

    .line 46
    invoke-virtual {v2, v0, v1}, Lu01/f;->skip(J)V

    .line 47
    .line 48
    .line 49
    sub-long/2addr p1, v0

    .line 50
    goto :goto_0

    .line 51
    :cond_2
    return-void

    .line 52
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "closed"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0
.end method

.method public final timeout()Lu01/j0;
    .locals 0

    .line 1
    iget-object p0, p0, Lu01/b0;->d:Lu01/h0;

    .line 2
    .line 3
    invoke-interface {p0}, Lu01/h0;->timeout()Lu01/j0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "buffer("

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lu01/b0;->d:Lu01/h0;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const/16 p0, 0x29

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public final v(JLu01/i;)Z
    .locals 2

    .line 1
    const-string p1, "bytes"

    .line 2
    .line 3
    invoke-static {p3, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3}, Lu01/i;->d()I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    iget-boolean p2, p0, Lu01/b0;->f:Z

    .line 11
    .line 12
    if-nez p2, :cond_4

    .line 13
    .line 14
    if-gez p1, :cond_0

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_0
    invoke-virtual {p3}, Lu01/i;->d()I

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    if-le p1, p2, :cond_1

    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_1
    if-nez p1, :cond_2

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_2
    const-wide/16 v0, 0x1

    .line 28
    .line 29
    invoke-static {p0, p3, p1, v0, v1}, Lv01/b;->c(Lu01/b0;Lu01/i;IJ)J

    .line 30
    .line 31
    .line 32
    move-result-wide p0

    .line 33
    const-wide/16 p2, -0x1

    .line 34
    .line 35
    cmp-long p0, p0, p2

    .line 36
    .line 37
    if-eqz p0, :cond_3

    .line 38
    .line 39
    :goto_0
    const/4 p0, 0x1

    .line 40
    return p0

    .line 41
    :cond_3
    :goto_1
    const/4 p0, 0x0

    .line 42
    return p0

    .line 43
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "closed"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0
.end method

.method public final w0()Ljava/io/InputStream;
    .locals 2

    .line 1
    new-instance v0, Lcx0/a;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, p0, v1}, Lcx0/a;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public final x(J)Ljava/lang/String;
    .locals 18

    .line 1
    move-wide/from16 v6, p1

    .line 2
    .line 3
    const-wide/16 v0, 0x0

    .line 4
    .line 5
    cmp-long v0, v6, v0

    .line 6
    .line 7
    if-ltz v0, :cond_3

    .line 8
    .line 9
    const-wide v8, 0x7fffffffffffffffL

    .line 10
    .line 11
    .line 12
    .line 13
    .line 14
    cmp-long v0, v6, v8

    .line 15
    .line 16
    const-wide/16 v10, 0x1

    .line 17
    .line 18
    if-nez v0, :cond_0

    .line 19
    .line 20
    move-wide v4, v8

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    add-long v0, v6, v10

    .line 23
    .line 24
    move-wide v4, v0

    .line 25
    :goto_0
    const/16 v1, 0xa

    .line 26
    .line 27
    const-wide/16 v2, 0x0

    .line 28
    .line 29
    move-object/from16 v0, p0

    .line 30
    .line 31
    invoke-virtual/range {v0 .. v5}, Lu01/b0;->a(BJJ)J

    .line 32
    .line 33
    .line 34
    move-result-wide v1

    .line 35
    const-wide/16 v12, -0x1

    .line 36
    .line 37
    cmp-long v3, v1, v12

    .line 38
    .line 39
    iget-object v12, v0, Lu01/b0;->e:Lu01/f;

    .line 40
    .line 41
    if-eqz v3, :cond_1

    .line 42
    .line 43
    invoke-static {v12, v1, v2}, Lv01/a;->c(Lu01/f;J)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    return-object v0

    .line 48
    :cond_1
    cmp-long v1, v4, v8

    .line 49
    .line 50
    if-gez v1, :cond_2

    .line 51
    .line 52
    invoke-virtual {v0, v4, v5}, Lu01/b0;->c(J)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_2

    .line 57
    .line 58
    sub-long v1, v4, v10

    .line 59
    .line 60
    invoke-virtual {v12, v1, v2}, Lu01/f;->h(J)B

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    const/16 v2, 0xd

    .line 65
    .line 66
    if-ne v1, v2, :cond_2

    .line 67
    .line 68
    add-long v1, v4, v10

    .line 69
    .line 70
    invoke-virtual {v0, v1, v2}, Lu01/b0;->c(J)Z

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    if-eqz v0, :cond_2

    .line 75
    .line 76
    invoke-virtual {v12, v4, v5}, Lu01/f;->h(J)B

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    const/16 v1, 0xa

    .line 81
    .line 82
    if-ne v0, v1, :cond_2

    .line 83
    .line 84
    invoke-static {v12, v4, v5}, Lv01/a;->c(Lu01/f;J)Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    return-object v0

    .line 89
    :cond_2
    new-instance v13, Lu01/f;

    .line 90
    .line 91
    invoke-direct {v13}, Ljava/lang/Object;-><init>()V

    .line 92
    .line 93
    .line 94
    iget-wide v0, v12, Lu01/f;->e:J

    .line 95
    .line 96
    const/16 v2, 0x20

    .line 97
    .line 98
    int-to-long v2, v2

    .line 99
    invoke-static {v2, v3, v0, v1}, Ljava/lang/Math;->min(JJ)J

    .line 100
    .line 101
    .line 102
    move-result-wide v16

    .line 103
    const-wide/16 v14, 0x0

    .line 104
    .line 105
    invoke-virtual/range {v12 .. v17}, Lu01/f;->f(Lu01/f;JJ)V

    .line 106
    .line 107
    .line 108
    new-instance v0, Ljava/io/EOFException;

    .line 109
    .line 110
    new-instance v1, Ljava/lang/StringBuilder;

    .line 111
    .line 112
    const-string v2, "\\n not found: limit="

    .line 113
    .line 114
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    iget-wide v2, v12, Lu01/f;->e:J

    .line 118
    .line 119
    invoke-static {v2, v3, v6, v7}, Ljava/lang/Math;->min(JJ)J

    .line 120
    .line 121
    .line 122
    move-result-wide v2

    .line 123
    invoke-virtual {v1, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    const-string v2, " content="

    .line 127
    .line 128
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 129
    .line 130
    .line 131
    iget-wide v2, v13, Lu01/f;->e:J

    .line 132
    .line 133
    invoke-virtual {v13, v2, v3}, Lu01/f;->S(J)Lu01/i;

    .line 134
    .line 135
    .line 136
    move-result-object v2

    .line 137
    invoke-virtual {v2}, Lu01/i;->e()Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object v2

    .line 141
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    const/16 v2, 0x2026

    .line 145
    .line 146
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 147
    .line 148
    .line 149
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v1

    .line 153
    invoke-direct {v0, v1}, Ljava/io/EOFException;-><init>(Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    throw v0

    .line 157
    :cond_3
    const-string v0, "limit < 0: "

    .line 158
    .line 159
    invoke-static {v6, v7, v0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object v0

    .line 163
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 164
    .line 165
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    throw v1
.end method

.method public final y(Lu01/i;)J
    .locals 10

    .line 1
    const-string v0, "targetBytes"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p0, Lu01/b0;->f:Z

    .line 7
    .line 8
    if-nez v0, :cond_2

    .line 9
    .line 10
    const-wide/16 v0, 0x0

    .line 11
    .line 12
    :goto_0
    iget-object v2, p0, Lu01/b0;->e:Lu01/f;

    .line 13
    .line 14
    invoke-virtual {v2, v0, v1, p1}, Lu01/f;->k(JLu01/i;)J

    .line 15
    .line 16
    .line 17
    move-result-wide v3

    .line 18
    const-wide/16 v5, -0x1

    .line 19
    .line 20
    cmp-long v7, v3, v5

    .line 21
    .line 22
    if-eqz v7, :cond_0

    .line 23
    .line 24
    return-wide v3

    .line 25
    :cond_0
    iget-wide v3, v2, Lu01/f;->e:J

    .line 26
    .line 27
    iget-object v7, p0, Lu01/b0;->d:Lu01/h0;

    .line 28
    .line 29
    const-wide/16 v8, 0x2000

    .line 30
    .line 31
    invoke-interface {v7, v2, v8, v9}, Lu01/h0;->A(Lu01/f;J)J

    .line 32
    .line 33
    .line 34
    move-result-wide v7

    .line 35
    cmp-long v2, v7, v5

    .line 36
    .line 37
    if-nez v2, :cond_1

    .line 38
    .line 39
    return-wide v5

    .line 40
    :cond_1
    invoke-static {v0, v1, v3, v4}, Ljava/lang/Math;->max(JJ)J

    .line 41
    .line 42
    .line 43
    move-result-wide v0

    .line 44
    goto :goto_0

    .line 45
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "closed"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0
.end method
