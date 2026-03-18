.class public final Ln11/l;
.super Lo11/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Serializable;


# instance fields
.field public final d:J

.field public final e:Ljp/u1;


# direct methods
.method public constructor <init>(JLjp/u1;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Ln11/c;->a:Ljava/util/concurrent/atomic/AtomicReference;

    .line 5
    .line 6
    if-nez p3, :cond_0

    .line 7
    .line 8
    invoke-static {}, Lp11/n;->P()Lp11/n;

    .line 9
    .line 10
    .line 11
    move-result-object p3

    .line 12
    :cond_0
    invoke-virtual {p3}, Ljp/u1;->m()Ln11/f;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    sget-object v1, Ln11/f;->e:Ln11/n;

    .line 17
    .line 18
    invoke-virtual {v0, v1, p1, p2}, Ln11/f;->f(Ln11/f;J)J

    .line 19
    .line 20
    .line 21
    move-result-wide p1

    .line 22
    iput-wide p1, p0, Ln11/l;->d:J

    .line 23
    .line 24
    invoke-virtual {p3}, Ljp/u1;->I()Ljp/u1;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    iput-object p1, p0, Ln11/l;->e:Ljp/u1;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final b(Ln11/b;)I
    .locals 2

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Ln11/l;->e:Ljp/u1;

    .line 4
    .line 5
    invoke-virtual {p1, v0}, Ln11/b;->a(Ljp/u1;)Ln11/a;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iget-wide v0, p0, Ln11/l;->d:J

    .line 10
    .line 11
    invoke-virtual {p1, v0, v1}, Ln11/a;->b(J)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 17
    .line 18
    const-string p1, "The DateTimeFieldType must not be null"

    .line 19
    .line 20
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p0
.end method

.method public final c()Ljp/u1;
    .locals 0

    .line 1
    iget-object p0, p0, Ln11/l;->e:Ljp/u1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final compareTo(Ljava/lang/Object;)I
    .locals 3

    .line 1
    check-cast p1, Lo11/b;

    .line 2
    .line 3
    if-ne p0, p1, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    instance-of v0, p1, Ln11/l;

    .line 7
    .line 8
    if-eqz v0, :cond_3

    .line 9
    .line 10
    move-object v0, p1

    .line 11
    check-cast v0, Ln11/l;

    .line 12
    .line 13
    iget-object v1, p0, Ln11/l;->e:Ljp/u1;

    .line 14
    .line 15
    iget-object v2, v0, Ln11/l;->e:Ljp/u1;

    .line 16
    .line 17
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_3

    .line 22
    .line 23
    iget-wide p0, p0, Ln11/l;->d:J

    .line 24
    .line 25
    iget-wide v0, v0, Ln11/l;->d:J

    .line 26
    .line 27
    cmp-long p0, p0, v0

    .line 28
    .line 29
    if-gez p0, :cond_1

    .line 30
    .line 31
    const/4 p0, -0x1

    .line 32
    return p0

    .line 33
    :cond_1
    if-nez p0, :cond_2

    .line 34
    .line 35
    :goto_0
    const/4 p0, 0x0

    .line 36
    return p0

    .line 37
    :cond_2
    const/4 p0, 0x1

    .line 38
    return p0

    .line 39
    :cond_3
    invoke-super {p0, p1}, Lo11/b;->a(Lo11/b;)I

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    return p0
.end method

.method public final d(ILjp/u1;)Ln11/a;
    .locals 0

    .line 1
    if-eqz p1, :cond_3

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    if-eq p1, p0, :cond_2

    .line 5
    .line 6
    const/4 p0, 0x2

    .line 7
    if-eq p1, p0, :cond_1

    .line 8
    .line 9
    const/4 p0, 0x3

    .line 10
    if-ne p1, p0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p2}, Ljp/u1;->t()Ln11/a;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :cond_0
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 18
    .line 19
    const-string p2, "Invalid index: "

    .line 20
    .line 21
    invoke-static {p1, p2}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-virtual {p2}, Ljp/u1;->f()Ln11/a;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :cond_2
    invoke-virtual {p2}, Ljp/u1;->y()Ln11/a;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :cond_3
    invoke-virtual {p2}, Ljp/u1;->K()Ln11/a;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
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
    instance-of v1, p1, Ln11/l;

    .line 6
    .line 7
    if-eqz v1, :cond_2

    .line 8
    .line 9
    move-object v1, p1

    .line 10
    check-cast v1, Ln11/l;

    .line 11
    .line 12
    iget-object v2, p0, Ln11/l;->e:Ljp/u1;

    .line 13
    .line 14
    iget-object v3, v1, Ln11/l;->e:Ljp/u1;

    .line 15
    .line 16
    invoke-virtual {v2, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    if-eqz v2, :cond_2

    .line 21
    .line 22
    iget-wide p0, p0, Ln11/l;->d:J

    .line 23
    .line 24
    iget-wide v1, v1, Ln11/l;->d:J

    .line 25
    .line 26
    cmp-long p0, p0, v1

    .line 27
    .line 28
    if-nez p0, :cond_1

    .line 29
    .line 30
    return v0

    .line 31
    :cond_1
    const/4 p0, 0x0

    .line 32
    return p0

    .line 33
    :cond_2
    invoke-super {p0, p1}, Lo11/b;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    return p0
.end method

.method public final f(I)I
    .locals 3

    .line 1
    iget-wide v0, p0, Ln11/l;->d:J

    .line 2
    .line 3
    iget-object p0, p0, Ln11/l;->e:Ljp/u1;

    .line 4
    .line 5
    if-eqz p1, :cond_3

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    if-eq p1, v2, :cond_2

    .line 9
    .line 10
    const/4 v2, 0x2

    .line 11
    if-eq p1, v2, :cond_1

    .line 12
    .line 13
    const/4 v2, 0x3

    .line 14
    if-ne p1, v2, :cond_0

    .line 15
    .line 16
    invoke-virtual {p0}, Ljp/u1;->t()Ln11/a;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-virtual {p0, v0, v1}, Ln11/a;->b(J)I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    return p0

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 26
    .line 27
    const-string v0, "Invalid index: "

    .line 28
    .line 29
    invoke-static {p1, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-direct {p0, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0

    .line 37
    :cond_1
    invoke-virtual {p0}, Ljp/u1;->f()Ln11/a;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-virtual {p0, v0, v1}, Ln11/a;->b(J)I

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    return p0

    .line 46
    :cond_2
    invoke-virtual {p0}, Ljp/u1;->y()Ln11/a;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    invoke-virtual {p0, v0, v1}, Ln11/a;->b(J)I

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    return p0

    .line 55
    :cond_3
    invoke-virtual {p0}, Ljp/u1;->K()Ln11/a;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    invoke-virtual {p0, v0, v1}, Ln11/a;->b(J)I

    .line 60
    .line 61
    .line 62
    move-result p0

    .line 63
    return p0
.end method

.method public final g(Ln11/b;)Z
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    iget-object p0, p0, Ln11/l;->e:Ljp/u1;

    .line 6
    .line 7
    invoke-virtual {p1, p0}, Ln11/b;->a(Ljp/u1;)Ln11/a;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-virtual {p0}, Ln11/a;->s()Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0
.end method

.method public final h()I
    .locals 0

    .line 1
    const/4 p0, 0x4

    .line 2
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lr11/v;->E:Lr11/b;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lr11/b;->c(Lo11/b;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
