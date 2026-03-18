.class public final Lnz0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lnz0/i;
.implements Ljava/lang/AutoCloseable;
.implements Ljava/io/Flushable;


# instance fields
.field public d:Lnz0/g;

.field public e:Lnz0/g;

.field public f:J


# virtual methods
.method public final I(Lnz0/a;J)J
    .locals 4

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v2, p2, v0

    .line 4
    .line 5
    if-ltz v2, :cond_2

    .line 6
    .line 7
    iget-wide v2, p0, Lnz0/a;->f:J

    .line 8
    .line 9
    cmp-long v0, v2, v0

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    const-wide/16 p0, -0x1

    .line 14
    .line 15
    return-wide p0

    .line 16
    :cond_0
    cmp-long v0, p2, v2

    .line 17
    .line 18
    if-lez v0, :cond_1

    .line 19
    .line 20
    move-wide p2, v2

    .line 21
    :cond_1
    invoke-virtual {p1, p0, p2, p3}, Lnz0/a;->l(Lnz0/a;J)V

    .line 22
    .line 23
    .line 24
    return-wide p2

    .line 25
    :cond_2
    const-string p0, "byteCount ("

    .line 26
    .line 27
    const-string p1, ") < 0"

    .line 28
    .line 29
    invoke-static {p2, p3, p0, p1}, Lp3/m;->g(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 34
    .line 35
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p1
.end method

.method public final Z()Z
    .locals 4

    .line 1
    iget-wide v0, p0, Lnz0/a;->f:J

    .line 2
    .line 3
    const-wide/16 v2, 0x0

    .line 4
    .line 5
    cmp-long p0, v0, v2

    .line 6
    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method

.method public final a([BII)I
    .locals 7

    .line 1
    array-length v0, p1

    .line 2
    int-to-long v1, v0

    .line 3
    int-to-long v3, p2

    .line 4
    int-to-long v5, p3

    .line 5
    invoke-static/range {v1 .. v6}, Lnz0/j;->a(JJJ)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lnz0/a;->d:Lnz0/g;

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    const/4 p0, -0x1

    .line 13
    return p0

    .line 14
    :cond_0
    sub-int/2addr p3, p2

    .line 15
    invoke-virtual {v0}, Lnz0/g;->b()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-static {p3, v1}, Ljava/lang/Math;->min(II)I

    .line 20
    .line 21
    .line 22
    move-result p3

    .line 23
    add-int v1, p2, p3

    .line 24
    .line 25
    sub-int/2addr v1, p2

    .line 26
    iget-object v2, v0, Lnz0/g;->a:[B

    .line 27
    .line 28
    iget v3, v0, Lnz0/g;->b:I

    .line 29
    .line 30
    add-int v4, v3, v1

    .line 31
    .line 32
    invoke-static {p2, v3, v4, v2, p1}, Lmx0/n;->g(III[B[B)V

    .line 33
    .line 34
    .line 35
    iget p1, v0, Lnz0/g;->b:I

    .line 36
    .line 37
    add-int/2addr p1, v1

    .line 38
    iput p1, v0, Lnz0/g;->b:I

    .line 39
    .line 40
    iget-wide p1, p0, Lnz0/a;->f:J

    .line 41
    .line 42
    int-to-long v1, p3

    .line 43
    sub-long/2addr p1, v1

    .line 44
    iput-wide p1, p0, Lnz0/a;->f:J

    .line 45
    .line 46
    invoke-static {v0}, Lnz0/j;->d(Lnz0/g;)Z

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    if-eqz p1, :cond_1

    .line 51
    .line 52
    invoke-virtual {p0}, Lnz0/a;->d()V

    .line 53
    .line 54
    .line 55
    :cond_1
    return p3
.end method

.method public final b(Lnz0/a;J)V
    .locals 3

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
    cmp-long v0, p2, v0

    .line 9
    .line 10
    if-ltz v0, :cond_1

    .line 11
    .line 12
    iget-wide v0, p0, Lnz0/a;->f:J

    .line 13
    .line 14
    cmp-long v2, v0, p2

    .line 15
    .line 16
    if-ltz v2, :cond_0

    .line 17
    .line 18
    invoke-virtual {p1, p0, p2, p3}, Lnz0/a;->l(Lnz0/a;J)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    invoke-virtual {p1, p0, v0, v1}, Lnz0/a;->l(Lnz0/a;J)V

    .line 23
    .line 24
    .line 25
    new-instance p1, Ljava/io/EOFException;

    .line 26
    .line 27
    const-string v0, "Buffer exhausted before writing "

    .line 28
    .line 29
    const-string v1, " bytes. Only "

    .line 30
    .line 31
    invoke-static {p2, p3, v0, v1}, Lp3/m;->o(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    move-result-object p2

    .line 35
    iget-wide v0, p0, Lnz0/a;->f:J

    .line 36
    .line 37
    const-string p0, " bytes were written."

    .line 38
    .line 39
    invoke-static {v0, v1, p0, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->k(JLjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    invoke-direct {p1, p0}, Ljava/io/EOFException;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw p1

    .line 47
    :cond_1
    const-string p0, "byteCount ("

    .line 48
    .line 49
    const-string p1, ") < 0"

    .line 50
    .line 51
    invoke-static {p2, p3, p0, p1}, Lp3/m;->g(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 56
    .line 57
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p1
.end method

.method public final c(J)Z
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p1, v0

    .line 4
    .line 5
    if-ltz v0, :cond_1

    .line 6
    .line 7
    iget-wide v0, p0, Lnz0/a;->f:J

    .line 8
    .line 9
    cmp-long p0, v0, p1

    .line 10
    .line 11
    if-ltz p0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0

    .line 17
    :cond_1
    const-string p0, "byteCount: "

    .line 18
    .line 19
    const-string v0, " < 0"

    .line 20
    .line 21
    invoke-static {p1, p2, p0, v0}, Lp3/m;->g(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 26
    .line 27
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p1
.end method

.method public final close()V
    .locals 0

    .line 1
    return-void
.end method

.method public final d()V
    .locals 3

    .line 1
    iget-object v0, p0, Lnz0/a;->d:Lnz0/g;

    .line 2
    .line 3
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    iget-object v1, v0, Lnz0/g;->f:Lnz0/g;

    .line 7
    .line 8
    iput-object v1, p0, Lnz0/a;->d:Lnz0/g;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    iput-object v2, p0, Lnz0/a;->e:Lnz0/g;

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    iput-object v2, v1, Lnz0/g;->g:Lnz0/g;

    .line 17
    .line 18
    :goto_0
    iput-object v2, v0, Lnz0/g;->f:Lnz0/g;

    .line 19
    .line 20
    invoke-static {v0}, Lnz0/h;->a(Lnz0/g;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final e(J)V
    .locals 4

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p1, v0

    .line 4
    .line 5
    if-ltz v0, :cond_1

    .line 6
    .line 7
    iget-wide v0, p0, Lnz0/a;->f:J

    .line 8
    .line 9
    cmp-long v0, v0, p1

    .line 10
    .line 11
    if-ltz v0, :cond_0

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    new-instance v0, Ljava/io/EOFException;

    .line 15
    .line 16
    new-instance v1, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v2, "Buffer doesn\'t contain required number of bytes (size: "

    .line 19
    .line 20
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-wide v2, p0, Lnz0/a;->f:J

    .line 24
    .line 25
    invoke-virtual {v1, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string p0, ", required: "

    .line 29
    .line 30
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1, p1, p2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    const/16 p0, 0x29

    .line 37
    .line 38
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-direct {v0, p0}, Ljava/io/EOFException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw v0

    .line 49
    :cond_1
    const-string p0, "byteCount: "

    .line 50
    .line 51
    invoke-static {p1, p2, p0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 56
    .line 57
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p1
.end method

.method public final synthetic f()V
    .locals 3

    .line 1
    iget-object v0, p0, Lnz0/a;->e:Lnz0/g;

    .line 2
    .line 3
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    iget-object v1, v0, Lnz0/g;->g:Lnz0/g;

    .line 7
    .line 8
    iput-object v1, p0, Lnz0/a;->e:Lnz0/g;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    iput-object v2, p0, Lnz0/a;->d:Lnz0/g;

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    iput-object v2, v1, Lnz0/g;->f:Lnz0/g;

    .line 17
    .line 18
    :goto_0
    iput-object v2, v0, Lnz0/g;->g:Lnz0/g;

    .line 19
    .line 20
    invoke-static {v0}, Lnz0/h;->a(Lnz0/g;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final flush()V
    .locals 0

    .line 1
    return-void
.end method

.method public final g(Lnz0/d;)J
    .locals 6

    .line 1
    const-string v0, "source"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-wide/16 v0, 0x0

    .line 7
    .line 8
    :goto_0
    const-wide/16 v2, 0x2000

    .line 9
    .line 10
    invoke-interface {p1, p0, v2, v3}, Lnz0/d;->I(Lnz0/a;J)J

    .line 11
    .line 12
    .line 13
    move-result-wide v2

    .line 14
    const-wide/16 v4, -0x1

    .line 15
    .line 16
    cmp-long v4, v2, v4

    .line 17
    .line 18
    if-eqz v4, :cond_0

    .line 19
    .line 20
    add-long/2addr v0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    return-wide v0
.end method

.method public final h(Lnz0/a;)J
    .locals 4

    .line 1
    const-string v0, "sink"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-wide v0, p0, Lnz0/a;->f:J

    .line 7
    .line 8
    const-wide/16 v2, 0x0

    .line 9
    .line 10
    cmp-long v2, v0, v2

    .line 11
    .line 12
    if-lez v2, :cond_0

    .line 13
    .line 14
    invoke-virtual {p1, p0, v0, v1}, Lnz0/a;->l(Lnz0/a;J)V

    .line 15
    .line 16
    .line 17
    :cond_0
    return-wide v0
.end method

.method public final synthetic j(I)Lnz0/g;
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-lt p1, v0, :cond_3

    .line 3
    .line 4
    const/16 v0, 0x2000

    .line 5
    .line 6
    if-gt p1, v0, :cond_3

    .line 7
    .line 8
    iget-object v1, p0, Lnz0/a;->e:Lnz0/g;

    .line 9
    .line 10
    if-nez v1, :cond_0

    .line 11
    .line 12
    invoke-static {}, Lnz0/h;->b()Lnz0/g;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iput-object p1, p0, Lnz0/a;->d:Lnz0/g;

    .line 17
    .line 18
    iput-object p1, p0, Lnz0/a;->e:Lnz0/g;

    .line 19
    .line 20
    return-object p1

    .line 21
    :cond_0
    iget v2, v1, Lnz0/g;->c:I

    .line 22
    .line 23
    add-int/2addr v2, p1

    .line 24
    if-gt v2, v0, :cond_2

    .line 25
    .line 26
    iget-boolean p1, v1, Lnz0/g;->e:Z

    .line 27
    .line 28
    if-nez p1, :cond_1

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    return-object v1

    .line 32
    :cond_2
    :goto_0
    invoke-static {}, Lnz0/h;->b()Lnz0/g;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    invoke-virtual {v1, p1}, Lnz0/g;->e(Lnz0/g;)V

    .line 37
    .line 38
    .line 39
    iput-object p1, p0, Lnz0/a;->e:Lnz0/g;

    .line 40
    .line 41
    return-object p1

    .line 42
    :cond_3
    const-string p0, "unexpected capacity ("

    .line 43
    .line 44
    const-string v0, "), should be in range [1, 8192]"

    .line 45
    .line 46
    invoke-static {p0, p1, v0}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 51
    .line 52
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p1
.end method

.method public final k(I[B)V
    .locals 7

    .line 1
    const-string v0, "source"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p2

    .line 7
    int-to-long v1, v0

    .line 8
    const/4 v0, 0x0

    .line 9
    int-to-long v3, v0

    .line 10
    int-to-long v5, p1

    .line 11
    invoke-static/range {v1 .. v6}, Lnz0/j;->a(JJJ)V

    .line 12
    .line 13
    .line 14
    :goto_0
    if-ge v0, p1, :cond_0

    .line 15
    .line 16
    const/4 v1, 0x1

    .line 17
    invoke-virtual {p0, v1}, Lnz0/a;->j(I)Lnz0/g;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    sub-int v2, p1, v0

    .line 22
    .line 23
    invoke-virtual {v1}, Lnz0/g;->a()I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    invoke-static {v2, v3}, Ljava/lang/Math;->min(II)I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    add-int/2addr v2, v0

    .line 32
    iget-object v3, v1, Lnz0/g;->a:[B

    .line 33
    .line 34
    iget v4, v1, Lnz0/g;->c:I

    .line 35
    .line 36
    invoke-static {v4, v0, v2, p2, v3}, Lmx0/n;->g(III[B[B)V

    .line 37
    .line 38
    .line 39
    iget v3, v1, Lnz0/g;->c:I

    .line 40
    .line 41
    sub-int v0, v2, v0

    .line 42
    .line 43
    add-int/2addr v0, v3

    .line 44
    iput v0, v1, Lnz0/g;->c:I

    .line 45
    .line 46
    move v0, v2

    .line 47
    goto :goto_0

    .line 48
    :cond_0
    iget-wide v0, p0, Lnz0/a;->f:J

    .line 49
    .line 50
    int-to-long p1, p1

    .line 51
    add-long/2addr v0, p1

    .line 52
    iput-wide v0, p0, Lnz0/a;->f:J

    .line 53
    .line 54
    return-void
.end method

.method public final l(Lnz0/a;J)V
    .locals 8

    .line 1
    if-eq p1, p0, :cond_10

    .line 2
    .line 3
    iget-wide v0, p1, Lnz0/a;->f:J

    .line 4
    .line 5
    const-wide/16 v2, 0x0

    .line 6
    .line 7
    cmp-long v4, v2, v0

    .line 8
    .line 9
    if-gtz v4, :cond_f

    .line 10
    .line 11
    cmp-long v4, v0, p2

    .line 12
    .line 13
    if-ltz v4, :cond_f

    .line 14
    .line 15
    cmp-long v2, p2, v2

    .line 16
    .line 17
    if-ltz v2, :cond_f

    .line 18
    .line 19
    :goto_0
    const-wide/16 v0, 0x0

    .line 20
    .line 21
    cmp-long v0, p2, v0

    .line 22
    .line 23
    if-lez v0, :cond_e

    .line 24
    .line 25
    iget-object v0, p1, Lnz0/a;->d:Lnz0/g;

    .line 26
    .line 27
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0}, Lnz0/g;->b()I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    int-to-long v0, v0

    .line 35
    cmp-long v0, p2, v0

    .line 36
    .line 37
    const/4 v1, 0x0

    .line 38
    if-gez v0, :cond_5

    .line 39
    .line 40
    iget-object v0, p0, Lnz0/a;->e:Lnz0/g;

    .line 41
    .line 42
    if-eqz v0, :cond_1

    .line 43
    .line 44
    iget-boolean v2, v0, Lnz0/g;->e:Z

    .line 45
    .line 46
    if-eqz v2, :cond_1

    .line 47
    .line 48
    iget v2, v0, Lnz0/g;->c:I

    .line 49
    .line 50
    int-to-long v2, v2

    .line 51
    add-long/2addr v2, p2

    .line 52
    iget-object v4, v0, Lnz0/g;->d:Lnz0/j;

    .line 53
    .line 54
    if-eqz v4, :cond_0

    .line 55
    .line 56
    check-cast v4, Lnz0/f;

    .line 57
    .line 58
    iget v4, v4, Lnz0/f;->b:I

    .line 59
    .line 60
    if-lez v4, :cond_0

    .line 61
    .line 62
    move v4, v1

    .line 63
    goto :goto_1

    .line 64
    :cond_0
    iget v4, v0, Lnz0/g;->b:I

    .line 65
    .line 66
    :goto_1
    int-to-long v4, v4

    .line 67
    sub-long/2addr v2, v4

    .line 68
    const-wide/16 v4, 0x2000

    .line 69
    .line 70
    cmp-long v2, v2, v4

    .line 71
    .line 72
    if-gtz v2, :cond_1

    .line 73
    .line 74
    iget-object v1, p1, Lnz0/a;->d:Lnz0/g;

    .line 75
    .line 76
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    long-to-int v2, p2

    .line 80
    invoke-virtual {v1, v0, v2}, Lnz0/g;->g(Lnz0/g;I)V

    .line 81
    .line 82
    .line 83
    iget-wide v0, p1, Lnz0/a;->f:J

    .line 84
    .line 85
    sub-long/2addr v0, p2

    .line 86
    iput-wide v0, p1, Lnz0/a;->f:J

    .line 87
    .line 88
    iget-wide v0, p0, Lnz0/a;->f:J

    .line 89
    .line 90
    add-long/2addr v0, p2

    .line 91
    iput-wide v0, p0, Lnz0/a;->f:J

    .line 92
    .line 93
    return-void

    .line 94
    :cond_1
    iget-object v0, p1, Lnz0/a;->d:Lnz0/g;

    .line 95
    .line 96
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    long-to-int v2, p2

    .line 100
    if-lez v2, :cond_4

    .line 101
    .line 102
    iget v3, v0, Lnz0/g;->c:I

    .line 103
    .line 104
    iget v4, v0, Lnz0/g;->b:I

    .line 105
    .line 106
    sub-int/2addr v3, v4

    .line 107
    if-gt v2, v3, :cond_4

    .line 108
    .line 109
    const/16 v3, 0x400

    .line 110
    .line 111
    if-lt v2, v3, :cond_2

    .line 112
    .line 113
    invoke-virtual {v0}, Lnz0/g;->f()Lnz0/g;

    .line 114
    .line 115
    .line 116
    move-result-object v3

    .line 117
    goto :goto_2

    .line 118
    :cond_2
    invoke-static {}, Lnz0/h;->b()Lnz0/g;

    .line 119
    .line 120
    .line 121
    move-result-object v3

    .line 122
    iget-object v4, v0, Lnz0/g;->a:[B

    .line 123
    .line 124
    iget-object v5, v3, Lnz0/g;->a:[B

    .line 125
    .line 126
    iget v6, v0, Lnz0/g;->b:I

    .line 127
    .line 128
    add-int v7, v6, v2

    .line 129
    .line 130
    invoke-static {v1, v6, v7, v4, v5}, Lmx0/n;->g(III[B[B)V

    .line 131
    .line 132
    .line 133
    :goto_2
    iget v4, v3, Lnz0/g;->b:I

    .line 134
    .line 135
    add-int/2addr v4, v2

    .line 136
    iput v4, v3, Lnz0/g;->c:I

    .line 137
    .line 138
    iget v4, v0, Lnz0/g;->b:I

    .line 139
    .line 140
    add-int/2addr v4, v2

    .line 141
    iput v4, v0, Lnz0/g;->b:I

    .line 142
    .line 143
    iget-object v2, v0, Lnz0/g;->g:Lnz0/g;

    .line 144
    .line 145
    if-eqz v2, :cond_3

    .line 146
    .line 147
    invoke-virtual {v2, v3}, Lnz0/g;->e(Lnz0/g;)V

    .line 148
    .line 149
    .line 150
    goto :goto_3

    .line 151
    :cond_3
    iput-object v0, v3, Lnz0/g;->f:Lnz0/g;

    .line 152
    .line 153
    iput-object v3, v0, Lnz0/g;->g:Lnz0/g;

    .line 154
    .line 155
    :goto_3
    iput-object v3, p1, Lnz0/a;->d:Lnz0/g;

    .line 156
    .line 157
    goto :goto_4

    .line 158
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 159
    .line 160
    const-string p1, "byteCount out of range"

    .line 161
    .line 162
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    throw p0

    .line 166
    :cond_5
    :goto_4
    iget-object v0, p1, Lnz0/a;->d:Lnz0/g;

    .line 167
    .line 168
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 169
    .line 170
    .line 171
    invoke-virtual {v0}, Lnz0/g;->b()I

    .line 172
    .line 173
    .line 174
    move-result v2

    .line 175
    int-to-long v2, v2

    .line 176
    invoke-virtual {v0}, Lnz0/g;->d()Lnz0/g;

    .line 177
    .line 178
    .line 179
    move-result-object v4

    .line 180
    iput-object v4, p1, Lnz0/a;->d:Lnz0/g;

    .line 181
    .line 182
    if-nez v4, :cond_6

    .line 183
    .line 184
    const/4 v4, 0x0

    .line 185
    iput-object v4, p1, Lnz0/a;->e:Lnz0/g;

    .line 186
    .line 187
    :cond_6
    iget-object v4, p0, Lnz0/a;->d:Lnz0/g;

    .line 188
    .line 189
    if-nez v4, :cond_7

    .line 190
    .line 191
    iput-object v0, p0, Lnz0/a;->d:Lnz0/g;

    .line 192
    .line 193
    iput-object v0, p0, Lnz0/a;->e:Lnz0/g;

    .line 194
    .line 195
    goto :goto_7

    .line 196
    :cond_7
    iget-object v4, p0, Lnz0/a;->e:Lnz0/g;

    .line 197
    .line 198
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    invoke-virtual {v4, v0}, Lnz0/g;->e(Lnz0/g;)V

    .line 202
    .line 203
    .line 204
    iget-object v4, v0, Lnz0/g;->g:Lnz0/g;

    .line 205
    .line 206
    if-eqz v4, :cond_d

    .line 207
    .line 208
    iget-boolean v5, v4, Lnz0/g;->e:Z

    .line 209
    .line 210
    if-nez v5, :cond_8

    .line 211
    .line 212
    goto :goto_6

    .line 213
    :cond_8
    iget v5, v0, Lnz0/g;->c:I

    .line 214
    .line 215
    iget v6, v0, Lnz0/g;->b:I

    .line 216
    .line 217
    sub-int/2addr v5, v6

    .line 218
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 219
    .line 220
    .line 221
    iget v4, v4, Lnz0/g;->c:I

    .line 222
    .line 223
    rsub-int v4, v4, 0x2000

    .line 224
    .line 225
    iget-object v6, v0, Lnz0/g;->g:Lnz0/g;

    .line 226
    .line 227
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 228
    .line 229
    .line 230
    iget-object v6, v6, Lnz0/g;->d:Lnz0/j;

    .line 231
    .line 232
    if-eqz v6, :cond_9

    .line 233
    .line 234
    check-cast v6, Lnz0/f;

    .line 235
    .line 236
    iget v6, v6, Lnz0/f;->b:I

    .line 237
    .line 238
    if-lez v6, :cond_9

    .line 239
    .line 240
    goto :goto_5

    .line 241
    :cond_9
    iget-object v1, v0, Lnz0/g;->g:Lnz0/g;

    .line 242
    .line 243
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 244
    .line 245
    .line 246
    iget v1, v1, Lnz0/g;->b:I

    .line 247
    .line 248
    :goto_5
    add-int/2addr v4, v1

    .line 249
    if-le v5, v4, :cond_a

    .line 250
    .line 251
    goto :goto_6

    .line 252
    :cond_a
    iget-object v1, v0, Lnz0/g;->g:Lnz0/g;

    .line 253
    .line 254
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 255
    .line 256
    .line 257
    invoke-virtual {v0, v1, v5}, Lnz0/g;->g(Lnz0/g;I)V

    .line 258
    .line 259
    .line 260
    invoke-virtual {v0}, Lnz0/g;->d()Lnz0/g;

    .line 261
    .line 262
    .line 263
    move-result-object v4

    .line 264
    if-nez v4, :cond_c

    .line 265
    .line 266
    invoke-static {v0}, Lnz0/h;->a(Lnz0/g;)V

    .line 267
    .line 268
    .line 269
    move-object v0, v1

    .line 270
    :goto_6
    iput-object v0, p0, Lnz0/a;->e:Lnz0/g;

    .line 271
    .line 272
    iget-object v1, v0, Lnz0/g;->g:Lnz0/g;

    .line 273
    .line 274
    if-nez v1, :cond_b

    .line 275
    .line 276
    iput-object v0, p0, Lnz0/a;->d:Lnz0/g;

    .line 277
    .line 278
    :cond_b
    :goto_7
    iget-wide v0, p1, Lnz0/a;->f:J

    .line 279
    .line 280
    sub-long/2addr v0, v2

    .line 281
    iput-wide v0, p1, Lnz0/a;->f:J

    .line 282
    .line 283
    iget-wide v0, p0, Lnz0/a;->f:J

    .line 284
    .line 285
    add-long/2addr v0, v2

    .line 286
    iput-wide v0, p0, Lnz0/a;->f:J

    .line 287
    .line 288
    sub-long/2addr p2, v2

    .line 289
    goto/16 :goto_0

    .line 290
    .line 291
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 292
    .line 293
    const-string p1, "Check failed."

    .line 294
    .line 295
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 296
    .line 297
    .line 298
    throw p0

    .line 299
    :cond_d
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 300
    .line 301
    const-string p1, "cannot compact"

    .line 302
    .line 303
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 304
    .line 305
    .line 306
    throw p0

    .line 307
    :cond_e
    return-void

    .line 308
    :cond_f
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 309
    .line 310
    const-string p1, "offset (0) and byteCount ("

    .line 311
    .line 312
    const-string v2, ") are not within the range [0..size("

    .line 313
    .line 314
    invoke-static {p2, p3, p1, v2}, Lp3/m;->o(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 315
    .line 316
    .line 317
    move-result-object p1

    .line 318
    const-string p2, "))"

    .line 319
    .line 320
    invoke-static {v0, v1, p2, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->k(JLjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 321
    .line 322
    .line 323
    move-result-object p1

    .line 324
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 325
    .line 326
    .line 327
    throw p0

    .line 328
    :cond_10
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 329
    .line 330
    const-string p1, "source == this"

    .line 331
    .line 332
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 333
    .line 334
    .line 335
    throw p0
.end method

.method public final n()Lnz0/a;
    .locals 0

    .line 1
    return-object p0
.end method

.method public final q(B)V
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, v0}, Lnz0/a;->j(I)Lnz0/g;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    iget-object v1, v0, Lnz0/g;->a:[B

    .line 7
    .line 8
    iget v2, v0, Lnz0/g;->c:I

    .line 9
    .line 10
    add-int/lit8 v3, v2, 0x1

    .line 11
    .line 12
    iput v3, v0, Lnz0/g;->c:I

    .line 13
    .line 14
    aput-byte p1, v1, v2

    .line 15
    .line 16
    iget-wide v0, p0, Lnz0/a;->f:J

    .line 17
    .line 18
    const-wide/16 v2, 0x1

    .line 19
    .line 20
    add-long/2addr v0, v2

    .line 21
    iput-wide v0, p0, Lnz0/a;->f:J

    .line 22
    .line 23
    return-void
.end method

.method public final readByte()B
    .locals 7

    .line 1
    iget-object v0, p0, Lnz0/a;->d:Lnz0/g;

    .line 2
    .line 3
    const-wide/16 v1, 0x1

    .line 4
    .line 5
    if-eqz v0, :cond_2

    .line 6
    .line 7
    invoke-virtual {v0}, Lnz0/g;->b()I

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    if-nez v3, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Lnz0/a;->d()V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0}, Lnz0/a;->readByte()B

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    return p0

    .line 21
    :cond_0
    iget-object v4, v0, Lnz0/g;->a:[B

    .line 22
    .line 23
    iget v5, v0, Lnz0/g;->b:I

    .line 24
    .line 25
    add-int/lit8 v6, v5, 0x1

    .line 26
    .line 27
    iput v6, v0, Lnz0/g;->b:I

    .line 28
    .line 29
    aget-byte v0, v4, v5

    .line 30
    .line 31
    iget-wide v4, p0, Lnz0/a;->f:J

    .line 32
    .line 33
    sub-long/2addr v4, v1

    .line 34
    iput-wide v4, p0, Lnz0/a;->f:J

    .line 35
    .line 36
    const/4 v1, 0x1

    .line 37
    if-ne v3, v1, :cond_1

    .line 38
    .line 39
    invoke-virtual {p0}, Lnz0/a;->d()V

    .line 40
    .line 41
    .line 42
    :cond_1
    return v0

    .line 43
    :cond_2
    new-instance v0, Ljava/io/EOFException;

    .line 44
    .line 45
    new-instance v3, Ljava/lang/StringBuilder;

    .line 46
    .line 47
    const-string v4, "Buffer doesn\'t contain required number of bytes (size: "

    .line 48
    .line 49
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    iget-wide v4, p0, Lnz0/a;->f:J

    .line 53
    .line 54
    invoke-virtual {v3, v4, v5}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    const-string p0, ", required: "

    .line 58
    .line 59
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    invoke-virtual {v3, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    const/16 p0, 0x29

    .line 66
    .line 67
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    invoke-direct {v0, p0}, Ljava/io/EOFException;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    throw v0
.end method

.method public final skip(J)V
    .locals 10

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v2, p1, v0

    .line 4
    .line 5
    if-ltz v2, :cond_3

    .line 6
    .line 7
    move-wide v2, p1

    .line 8
    :cond_0
    :goto_0
    cmp-long v4, v2, v0

    .line 9
    .line 10
    if-lez v4, :cond_2

    .line 11
    .line 12
    iget-object v4, p0, Lnz0/a;->d:Lnz0/g;

    .line 13
    .line 14
    if-eqz v4, :cond_1

    .line 15
    .line 16
    iget v5, v4, Lnz0/g;->c:I

    .line 17
    .line 18
    iget v6, v4, Lnz0/g;->b:I

    .line 19
    .line 20
    sub-int/2addr v5, v6

    .line 21
    int-to-long v5, v5

    .line 22
    invoke-static {v2, v3, v5, v6}, Ljava/lang/Math;->min(JJ)J

    .line 23
    .line 24
    .line 25
    move-result-wide v5

    .line 26
    long-to-int v5, v5

    .line 27
    iget-wide v6, p0, Lnz0/a;->f:J

    .line 28
    .line 29
    int-to-long v8, v5

    .line 30
    sub-long/2addr v6, v8

    .line 31
    iput-wide v6, p0, Lnz0/a;->f:J

    .line 32
    .line 33
    sub-long/2addr v2, v8

    .line 34
    iget v6, v4, Lnz0/g;->b:I

    .line 35
    .line 36
    add-int/2addr v6, v5

    .line 37
    iput v6, v4, Lnz0/g;->b:I

    .line 38
    .line 39
    iget v4, v4, Lnz0/g;->c:I

    .line 40
    .line 41
    if-ne v6, v4, :cond_0

    .line 42
    .line 43
    invoke-virtual {p0}, Lnz0/a;->d()V

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    new-instance p0, Ljava/io/EOFException;

    .line 48
    .line 49
    const-string v0, "Buffer exhausted before skipping "

    .line 50
    .line 51
    const-string v1, " bytes."

    .line 52
    .line 53
    invoke-static {p1, p2, v0, v1}, Lp3/m;->g(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    invoke-direct {p0, p1}, Ljava/io/EOFException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_2
    return-void

    .line 62
    :cond_3
    const-string p0, "byteCount ("

    .line 63
    .line 64
    const-string v0, ") < 0"

    .line 65
    .line 66
    invoke-static {p1, p2, p0, v0}, Lp3/m;->g(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 71
    .line 72
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    throw p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 11

    .line 1
    iget-wide v0, p0, Lnz0/a;->f:J

    .line 2
    .line 3
    const-wide/16 v2, 0x0

    .line 4
    .line 5
    cmp-long v2, v0, v2

    .line 6
    .line 7
    if-nez v2, :cond_0

    .line 8
    .line 9
    const-string p0, "Buffer(size=0)"

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    const/16 v2, 0x40

    .line 13
    .line 14
    int-to-long v2, v2

    .line 15
    invoke-static {v2, v3, v0, v1}, Ljava/lang/Math;->min(JJ)J

    .line 16
    .line 17
    .line 18
    move-result-wide v0

    .line 19
    long-to-int v0, v0

    .line 20
    new-instance v1, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    mul-int/lit8 v4, v0, 0x2

    .line 23
    .line 24
    iget-wide v5, p0, Lnz0/a;->f:J

    .line 25
    .line 26
    cmp-long v5, v5, v2

    .line 27
    .line 28
    const/4 v6, 0x0

    .line 29
    if-lez v5, :cond_1

    .line 30
    .line 31
    const/4 v5, 0x1

    .line 32
    goto :goto_0

    .line 33
    :cond_1
    move v5, v6

    .line 34
    :goto_0
    add-int/2addr v4, v5

    .line 35
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 36
    .line 37
    .line 38
    iget-object v4, p0, Lnz0/a;->d:Lnz0/g;

    .line 39
    .line 40
    move v5, v6

    .line 41
    :goto_1
    if-eqz v4, :cond_3

    .line 42
    .line 43
    move v7, v6

    .line 44
    :goto_2
    if-ge v5, v0, :cond_2

    .line 45
    .line 46
    invoke-virtual {v4}, Lnz0/g;->b()I

    .line 47
    .line 48
    .line 49
    move-result v8

    .line 50
    if-ge v7, v8, :cond_2

    .line 51
    .line 52
    add-int/lit8 v8, v7, 0x1

    .line 53
    .line 54
    invoke-virtual {v4, v7}, Lnz0/g;->c(I)B

    .line 55
    .line 56
    .line 57
    move-result v7

    .line 58
    add-int/lit8 v5, v5, 0x1

    .line 59
    .line 60
    shr-int/lit8 v9, v7, 0x4

    .line 61
    .line 62
    and-int/lit8 v9, v9, 0xf

    .line 63
    .line 64
    sget-object v10, Lnz0/j;->a:[C

    .line 65
    .line 66
    aget-char v9, v10, v9

    .line 67
    .line 68
    invoke-virtual {v1, v9}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    and-int/lit8 v7, v7, 0xf

    .line 72
    .line 73
    aget-char v7, v10, v7

    .line 74
    .line 75
    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    move v7, v8

    .line 79
    goto :goto_2

    .line 80
    :cond_2
    iget-object v4, v4, Lnz0/g;->f:Lnz0/g;

    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_3
    iget-wide v4, p0, Lnz0/a;->f:J

    .line 84
    .line 85
    cmp-long v0, v4, v2

    .line 86
    .line 87
    if-lez v0, :cond_4

    .line 88
    .line 89
    const/16 v0, 0x2026

    .line 90
    .line 91
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    :cond_4
    new-instance v0, Ljava/lang/StringBuilder;

    .line 95
    .line 96
    const-string v2, "Buffer(size="

    .line 97
    .line 98
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    iget-wide v2, p0, Lnz0/a;->f:J

    .line 102
    .line 103
    invoke-virtual {v0, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    const-string p0, " hex="

    .line 107
    .line 108
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    const/16 p0, 0x29

    .line 115
    .line 116
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 117
    .line 118
    .line 119
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    return-object p0
.end method
