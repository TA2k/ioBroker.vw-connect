.class public final Lp11/p;
.super Lq11/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final e:Ln11/a;

.field public final f:Ln11/f;

.field public final g:Ln11/g;

.field public final h:Z

.field public final i:Ln11/g;

.field public final j:Ln11/g;


# direct methods
.method public constructor <init>(Ln11/a;Ln11/f;Ln11/g;Ln11/g;Ln11/g;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Ln11/a;->q()Ln11/b;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-direct {p0, v0}, Lq11/a;-><init>(Ln11/b;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1}, Ln11/a;->s()Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    iput-object p1, p0, Lp11/p;->e:Ln11/a;

    .line 15
    .line 16
    iput-object p2, p0, Lp11/p;->f:Ln11/f;

    .line 17
    .line 18
    iput-object p3, p0, Lp11/p;->g:Ln11/g;

    .line 19
    .line 20
    if-eqz p3, :cond_0

    .line 21
    .line 22
    invoke-virtual {p3}, Ln11/g;->d()J

    .line 23
    .line 24
    .line 25
    move-result-wide p1

    .line 26
    const-wide/32 v0, 0x2932e00

    .line 27
    .line 28
    .line 29
    cmp-long p1, p1, v0

    .line 30
    .line 31
    if-gez p1, :cond_0

    .line 32
    .line 33
    const/4 p1, 0x1

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const/4 p1, 0x0

    .line 36
    :goto_0
    iput-boolean p1, p0, Lp11/p;->h:Z

    .line 37
    .line 38
    iput-object p4, p0, Lp11/p;->i:Ln11/g;

    .line 39
    .line 40
    iput-object p5, p0, Lp11/p;->j:Ln11/g;

    .line 41
    .line 42
    return-void

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 44
    .line 45
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 46
    .line 47
    .line 48
    throw p0
.end method


# virtual methods
.method public final a(IJ)J
    .locals 4

    .line 1
    iget-boolean v0, p0, Lp11/p;->h:Z

    .line 2
    .line 3
    iget-object v1, p0, Lp11/p;->e:Ln11/a;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0, p2, p3}, Lp11/p;->z(J)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    int-to-long v2, p0

    .line 12
    add-long/2addr p2, v2

    .line 13
    invoke-virtual {v1, p1, p2, p3}, Ln11/a;->a(IJ)J

    .line 14
    .line 15
    .line 16
    move-result-wide p0

    .line 17
    sub-long/2addr p0, v2

    .line 18
    return-wide p0

    .line 19
    :cond_0
    iget-object p0, p0, Lp11/p;->f:Ln11/f;

    .line 20
    .line 21
    invoke-virtual {p0, p2, p3}, Ln11/f;->b(J)J

    .line 22
    .line 23
    .line 24
    move-result-wide v2

    .line 25
    invoke-virtual {v1, p1, v2, v3}, Ln11/a;->a(IJ)J

    .line 26
    .line 27
    .line 28
    move-result-wide v0

    .line 29
    invoke-virtual {p0, v0, v1, p2, p3}, Ln11/f;->a(JJ)J

    .line 30
    .line 31
    .line 32
    move-result-wide p0

    .line 33
    return-wide p0
.end method

.method public final b(J)I
    .locals 1

    .line 1
    iget-object v0, p0, Lp11/p;->f:Ln11/f;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Ln11/f;->b(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide p1

    .line 7
    iget-object p0, p0, Lp11/p;->e:Ln11/a;

    .line 8
    .line 9
    invoke-virtual {p0, p1, p2}, Ln11/a;->b(J)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final c(ILjava/util/Locale;)Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lp11/p;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ln11/a;->c(ILjava/util/Locale;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final d(JLjava/util/Locale;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object v0, p0, Lp11/p;->f:Ln11/f;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Ln11/f;->b(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide p1

    .line 7
    iget-object p0, p0, Lp11/p;->e:Ln11/a;

    .line 8
    .line 9
    invoke-virtual {p0, p1, p2, p3}, Ln11/a;->d(JLjava/util/Locale;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lp11/p;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lp11/p;

    .line 11
    .line 12
    iget-object v1, p0, Lp11/p;->e:Ln11/a;

    .line 13
    .line 14
    iget-object v3, p1, Lp11/p;->e:Ln11/a;

    .line 15
    .line 16
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    iget-object v1, p0, Lp11/p;->f:Ln11/f;

    .line 23
    .line 24
    iget-object v3, p1, Lp11/p;->f:Ln11/f;

    .line 25
    .line 26
    invoke-virtual {v1, v3}, Ln11/f;->equals(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    iget-object v1, p0, Lp11/p;->g:Ln11/g;

    .line 33
    .line 34
    iget-object v3, p1, Lp11/p;->g:Ln11/g;

    .line 35
    .line 36
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-eqz v1, :cond_1

    .line 41
    .line 42
    iget-object p0, p0, Lp11/p;->i:Ln11/g;

    .line 43
    .line 44
    iget-object p1, p1, Lp11/p;->i:Ln11/g;

    .line 45
    .line 46
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    if-eqz p0, :cond_1

    .line 51
    .line 52
    return v0

    .line 53
    :cond_1
    return v2
.end method

.method public final f(ILjava/util/Locale;)Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lp11/p;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ln11/a;->f(ILjava/util/Locale;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final g(JLjava/util/Locale;)Ljava/lang/String;
    .locals 1

    .line 1
    iget-object v0, p0, Lp11/p;->f:Ln11/f;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Ln11/f;->b(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide p1

    .line 7
    iget-object p0, p0, Lp11/p;->e:Ln11/a;

    .line 8
    .line 9
    invoke-virtual {p0, p1, p2, p3}, Ln11/a;->g(JLjava/util/Locale;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Lp11/p;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object p0, p0, Lp11/p;->f:Ln11/f;

    .line 8
    .line 9
    invoke-virtual {p0}, Ln11/f;->hashCode()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    xor-int/2addr p0, v0

    .line 14
    return p0
.end method

.method public final i()Ln11/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lp11/p;->g:Ln11/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final j()Ln11/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lp11/p;->j:Ln11/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final k(Ljava/util/Locale;)I
    .locals 0

    .line 1
    iget-object p0, p0, Lp11/p;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ln11/a;->k(Ljava/util/Locale;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final l()I
    .locals 0

    .line 1
    iget-object p0, p0, Lp11/p;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Ln11/a;->l()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final o()I
    .locals 0

    .line 1
    iget-object p0, p0, Lp11/p;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Ln11/a;->o()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final p()Ln11/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lp11/p;->i:Ln11/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final r(J)Z
    .locals 1

    .line 1
    iget-object v0, p0, Lp11/p;->f:Ln11/f;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Ln11/f;->b(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide p1

    .line 7
    iget-object p0, p0, Lp11/p;->e:Ln11/a;

    .line 8
    .line 9
    invoke-virtual {p0, p1, p2}, Ln11/a;->r(J)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final t(J)J
    .locals 1

    .line 1
    iget-object v0, p0, Lp11/p;->f:Ln11/f;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Ln11/f;->b(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide p1

    .line 7
    iget-object p0, p0, Lp11/p;->e:Ln11/a;

    .line 8
    .line 9
    invoke-virtual {p0, p1, p2}, Ln11/a;->t(J)J

    .line 10
    .line 11
    .line 12
    move-result-wide p0

    .line 13
    return-wide p0
.end method

.method public final u(J)J
    .locals 4

    .line 1
    iget-boolean v0, p0, Lp11/p;->h:Z

    .line 2
    .line 3
    iget-object v1, p0, Lp11/p;->e:Ln11/a;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0, p1, p2}, Lp11/p;->z(J)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    int-to-long v2, p0

    .line 12
    add-long/2addr p1, v2

    .line 13
    invoke-virtual {v1, p1, p2}, Ln11/a;->u(J)J

    .line 14
    .line 15
    .line 16
    move-result-wide p0

    .line 17
    sub-long/2addr p0, v2

    .line 18
    return-wide p0

    .line 19
    :cond_0
    iget-object p0, p0, Lp11/p;->f:Ln11/f;

    .line 20
    .line 21
    invoke-virtual {p0, p1, p2}, Ln11/f;->b(J)J

    .line 22
    .line 23
    .line 24
    move-result-wide v2

    .line 25
    invoke-virtual {v1, v2, v3}, Ln11/a;->u(J)J

    .line 26
    .line 27
    .line 28
    move-result-wide v0

    .line 29
    invoke-virtual {p0, v0, v1, p1, p2}, Ln11/f;->a(JJ)J

    .line 30
    .line 31
    .line 32
    move-result-wide p0

    .line 33
    return-wide p0
.end method

.method public final v(IJ)J
    .locals 4

    .line 1
    iget-object v0, p0, Lp11/p;->f:Ln11/f;

    .line 2
    .line 3
    invoke-virtual {v0, p2, p3}, Ln11/f;->b(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    iget-object v3, p0, Lp11/p;->e:Ln11/a;

    .line 8
    .line 9
    invoke-virtual {v3, p1, v1, v2}, Ln11/a;->v(IJ)J

    .line 10
    .line 11
    .line 12
    move-result-wide v1

    .line 13
    invoke-virtual {v0, v1, v2, p2, p3}, Ln11/f;->a(JJ)J

    .line 14
    .line 15
    .line 16
    move-result-wide p2

    .line 17
    invoke-virtual {p0, p2, p3}, Lp11/p;->b(J)I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-ne p0, p1, :cond_0

    .line 22
    .line 23
    return-wide p2

    .line 24
    :cond_0
    new-instance p0, Lgz0/a;

    .line 25
    .line 26
    iget-object p2, v0, Ln11/f;->d:Ljava/lang/String;

    .line 27
    .line 28
    invoke-direct {p0, v1, v2, p2}, Lgz0/a;-><init>(JLjava/lang/String;)V

    .line 29
    .line 30
    .line 31
    new-instance p2, Ln11/i;

    .line 32
    .line 33
    invoke-virtual {v3}, Ln11/a;->q()Ln11/b;

    .line 34
    .line 35
    .line 36
    move-result-object p3

    .line 37
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    invoke-direct {p2, p3, p1, v0}, Ln11/i;-><init>(Ln11/b;Ljava/lang/Integer;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p2, p0}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    .line 49
    .line 50
    .line 51
    throw p2
.end method

.method public final w(JLjava/lang/String;Ljava/util/Locale;)J
    .locals 3

    .line 1
    iget-object v0, p0, Lp11/p;->f:Ln11/f;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Ln11/f;->b(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    iget-object p0, p0, Lp11/p;->e:Ln11/a;

    .line 8
    .line 9
    invoke-virtual {p0, v1, v2, p3, p4}, Ln11/a;->w(JLjava/lang/String;Ljava/util/Locale;)J

    .line 10
    .line 11
    .line 12
    move-result-wide p3

    .line 13
    invoke-virtual {v0, p3, p4, p1, p2}, Ln11/f;->a(JJ)J

    .line 14
    .line 15
    .line 16
    move-result-wide p0

    .line 17
    return-wide p0
.end method

.method public final z(J)I
    .locals 6

    .line 1
    iget-object p0, p0, Lp11/p;->f:Ln11/f;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ln11/f;->i(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    int-to-long v0, p0

    .line 8
    add-long v2, p1, v0

    .line 9
    .line 10
    xor-long/2addr v2, p1

    .line 11
    const-wide/16 v4, 0x0

    .line 12
    .line 13
    cmp-long v2, v2, v4

    .line 14
    .line 15
    if-gez v2, :cond_1

    .line 16
    .line 17
    xor-long/2addr p1, v0

    .line 18
    cmp-long p1, p1, v4

    .line 19
    .line 20
    if-gez p1, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/ArithmeticException;

    .line 24
    .line 25
    const-string p1, "Adding time zone offset caused overflow"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    :goto_0
    return p0
.end method
