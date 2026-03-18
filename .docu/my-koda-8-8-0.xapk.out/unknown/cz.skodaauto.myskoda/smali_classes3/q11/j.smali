.class public final Lq11/j;
.super Lq11/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final e:J


# direct methods
.method public constructor <init>(Ln11/h;J)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lq11/b;-><init>(Ln11/h;)V

    .line 2
    .line 3
    .line 4
    iput-wide p2, p0, Lq11/j;->e:J

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(IJ)J
    .locals 2

    .line 1
    int-to-long v0, p1

    .line 2
    iget-wide p0, p0, Lq11/j;->e:J

    .line 3
    .line 4
    mul-long/2addr v0, p0

    .line 5
    invoke-static {p2, p3, v0, v1}, Ljp/je;->d(JJ)J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    return-wide p0
.end method

.method public final b(JJ)J
    .locals 8

    .line 1
    iget-wide v0, p0, Lq11/j;->e:J

    .line 2
    .line 3
    const-wide/16 v2, 0x1

    .line 4
    .line 5
    cmp-long p0, v0, v2

    .line 6
    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    goto :goto_1

    .line 10
    :cond_0
    cmp-long p0, p3, v2

    .line 11
    .line 12
    if-nez p0, :cond_1

    .line 13
    .line 14
    move-wide p3, v0

    .line 15
    goto :goto_1

    .line 16
    :cond_1
    const-wide/16 v2, 0x0

    .line 17
    .line 18
    cmp-long p0, p3, v2

    .line 19
    .line 20
    if-eqz p0, :cond_4

    .line 21
    .line 22
    cmp-long p0, v0, v2

    .line 23
    .line 24
    if-nez p0, :cond_2

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_2
    mul-long v2, p3, v0

    .line 28
    .line 29
    div-long v4, v2, v0

    .line 30
    .line 31
    cmp-long p0, v4, p3

    .line 32
    .line 33
    if-nez p0, :cond_5

    .line 34
    .line 35
    const-wide/high16 v4, -0x8000000000000000L

    .line 36
    .line 37
    cmp-long p0, p3, v4

    .line 38
    .line 39
    const-wide/16 v6, -0x1

    .line 40
    .line 41
    if-nez p0, :cond_3

    .line 42
    .line 43
    cmp-long p0, v0, v6

    .line 44
    .line 45
    if-eqz p0, :cond_5

    .line 46
    .line 47
    :cond_3
    cmp-long p0, v0, v4

    .line 48
    .line 49
    if-nez p0, :cond_4

    .line 50
    .line 51
    cmp-long p0, p3, v6

    .line 52
    .line 53
    if-eqz p0, :cond_5

    .line 54
    .line 55
    :cond_4
    :goto_0
    move-wide p3, v2

    .line 56
    goto :goto_1

    .line 57
    :cond_5
    new-instance p0, Ljava/lang/ArithmeticException;

    .line 58
    .line 59
    const-string p1, "Multiplication overflows a long: "

    .line 60
    .line 61
    const-string p2, " * "

    .line 62
    .line 63
    invoke-static {p3, p4, p1, p2}, Lp3/m;->o(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    invoke-virtual {p1, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    invoke-direct {p0, p1}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    throw p0

    .line 78
    :goto_1
    invoke-static {p1, p2, p3, p4}, Ljp/je;->d(JJ)J

    .line 79
    .line 80
    .line 81
    move-result-wide p0

    .line 82
    return-wide p0
.end method

.method public final d()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lq11/j;->e:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final e()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lq11/j;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lq11/j;

    .line 11
    .line 12
    iget-object v1, p0, Lq11/b;->d:Ln11/h;

    .line 13
    .line 14
    iget-object v3, p1, Lq11/b;->d:Ln11/h;

    .line 15
    .line 16
    if-ne v1, v3, :cond_1

    .line 17
    .line 18
    iget-wide v3, p0, Lq11/j;->e:J

    .line 19
    .line 20
    iget-wide p0, p1, Lq11/j;->e:J

    .line 21
    .line 22
    cmp-long p0, v3, p0

    .line 23
    .line 24
    if-nez p0, :cond_1

    .line 25
    .line 26
    return v0

    .line 27
    :cond_1
    return v2
.end method

.method public final hashCode()I
    .locals 5

    .line 1
    const/16 v0, 0x20

    .line 2
    .line 3
    iget-wide v1, p0, Lq11/j;->e:J

    .line 4
    .line 5
    ushr-long v3, v1, v0

    .line 6
    .line 7
    xor-long v0, v1, v3

    .line 8
    .line 9
    long-to-int v0, v0

    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lq11/b;->d:Ln11/h;

    .line 12
    .line 13
    iget-byte p0, p0, Ln11/h;->e:B

    .line 14
    .line 15
    shl-int p0, v1, p0

    .line 16
    .line 17
    add-int/2addr v0, p0

    .line 18
    return v0
.end method
