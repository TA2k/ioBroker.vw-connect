.class public final Lnz0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lnz0/i;


# instance fields
.field public final d:Lnz0/c;

.field public e:Z

.field public final f:Lnz0/a;


# direct methods
.method public constructor <init>(Lnz0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lnz0/e;->d:Lnz0/c;

    .line 5
    .line 6
    new-instance p1, Lnz0/a;

    .line 7
    .line 8
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lnz0/e;->f:Lnz0/a;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final I(Lnz0/a;J)J
    .locals 5

    .line 1
    iget-boolean v0, p0, Lnz0/e;->e:Z

    .line 2
    .line 3
    if-nez v0, :cond_2

    .line 4
    .line 5
    const-wide/16 v0, 0x0

    .line 6
    .line 7
    cmp-long v2, p2, v0

    .line 8
    .line 9
    if-ltz v2, :cond_1

    .line 10
    .line 11
    iget-object v2, p0, Lnz0/e;->f:Lnz0/a;

    .line 12
    .line 13
    iget-wide v3, v2, Lnz0/a;->f:J

    .line 14
    .line 15
    cmp-long v0, v3, v0

    .line 16
    .line 17
    if-nez v0, :cond_0

    .line 18
    .line 19
    iget-object p0, p0, Lnz0/e;->d:Lnz0/c;

    .line 20
    .line 21
    const-wide/16 v0, 0x2000

    .line 22
    .line 23
    invoke-virtual {p0, v2, v0, v1}, Lnz0/c;->I(Lnz0/a;J)J

    .line 24
    .line 25
    .line 26
    move-result-wide v0

    .line 27
    const-wide/16 v3, -0x1

    .line 28
    .line 29
    cmp-long p0, v0, v3

    .line 30
    .line 31
    if-nez p0, :cond_0

    .line 32
    .line 33
    return-wide v3

    .line 34
    :cond_0
    iget-wide v0, v2, Lnz0/a;->f:J

    .line 35
    .line 36
    invoke-static {p2, p3, v0, v1}, Ljava/lang/Math;->min(JJ)J

    .line 37
    .line 38
    .line 39
    move-result-wide p2

    .line 40
    invoke-virtual {v2, p1, p2, p3}, Lnz0/a;->I(Lnz0/a;J)J

    .line 41
    .line 42
    .line 43
    move-result-wide p0

    .line 44
    return-wide p0

    .line 45
    :cond_1
    const-string p0, "byteCount: "

    .line 46
    .line 47
    invoke-static {p2, p3, p0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

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

    .line 61
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 62
    .line 63
    const-string p1, "Source is closed."

    .line 64
    .line 65
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p0
.end method

.method public final Z()Z
    .locals 4

    .line 1
    iget-boolean v0, p0, Lnz0/e;->e:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lnz0/e;->f:Lnz0/a;

    .line 6
    .line 7
    invoke-virtual {v0}, Lnz0/a;->Z()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    iget-object p0, p0, Lnz0/e;->d:Lnz0/c;

    .line 14
    .line 15
    const-wide/16 v1, 0x2000

    .line 16
    .line 17
    invoke-virtual {p0, v0, v1, v2}, Lnz0/c;->I(Lnz0/a;J)J

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
    const-string v0, "Source is closed."

    .line 34
    .line 35
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0
.end method

.method public final c(J)Z
    .locals 4

    .line 1
    iget-boolean v0, p0, Lnz0/e;->e:Z

    .line 2
    .line 3
    if-nez v0, :cond_3

    .line 4
    .line 5
    const-wide/16 v0, 0x0

    .line 6
    .line 7
    cmp-long v0, p1, v0

    .line 8
    .line 9
    if-ltz v0, :cond_2

    .line 10
    .line 11
    :cond_0
    iget-object v0, p0, Lnz0/e;->f:Lnz0/a;

    .line 12
    .line 13
    iget-wide v1, v0, Lnz0/a;->f:J

    .line 14
    .line 15
    cmp-long v1, v1, p1

    .line 16
    .line 17
    if-gez v1, :cond_1

    .line 18
    .line 19
    iget-object v1, p0, Lnz0/e;->d:Lnz0/c;

    .line 20
    .line 21
    const-wide/16 v2, 0x2000

    .line 22
    .line 23
    invoke-virtual {v1, v0, v2, v3}, Lnz0/c;->I(Lnz0/a;J)J

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
    const-string p0, "byteCount: "

    .line 38
    .line 39
    invoke-static {p1, p2, p0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 44
    .line 45
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p1

    .line 53
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string p1, "Source is closed."

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0
.end method

.method public final close()V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lnz0/e;->e:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    const/4 v0, 0x1

    .line 7
    iput-boolean v0, p0, Lnz0/e;->e:Z

    .line 8
    .line 9
    iget-object v1, p0, Lnz0/e;->d:Lnz0/c;

    .line 10
    .line 11
    iput-boolean v0, v1, Lnz0/c;->h:Z

    .line 12
    .line 13
    iget-object p0, p0, Lnz0/e;->f:Lnz0/a;

    .line 14
    .line 15
    iget-wide v0, p0, Lnz0/a;->f:J

    .line 16
    .line 17
    invoke-virtual {p0, v0, v1}, Lnz0/a;->skip(J)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public final e(J)V
    .locals 2

    .line 1
    invoke-virtual {p0, p1, p2}, Lnz0/e;->c(J)Z

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
    const-string v0, "Source doesn\'t contain required number of bytes ("

    .line 11
    .line 12
    const-string v1, ")."

    .line 13
    .line 14
    invoke-static {p1, p2, v0, v1}, Lp3/m;->g(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-direct {p0, p1}, Ljava/io/EOFException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0
.end method

.method public final n()Lnz0/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lnz0/e;->f:Lnz0/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final readByte()B
    .locals 2

    .line 1
    const-wide/16 v0, 0x1

    .line 2
    .line 3
    invoke-virtual {p0, v0, v1}, Lnz0/e;->e(J)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lnz0/e;->f:Lnz0/a;

    .line 7
    .line 8
    invoke-virtual {p0}, Lnz0/a;->readByte()B

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "buffered("

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lnz0/e;->d:Lnz0/c;

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
