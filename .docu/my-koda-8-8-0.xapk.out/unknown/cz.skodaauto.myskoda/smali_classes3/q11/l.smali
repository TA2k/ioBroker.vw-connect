.class public final Lq11/l;
.super Lq11/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final e:Ln11/g;

.field public final f:I


# direct methods
.method public constructor <init>(Ln11/g;Ln11/h;)V
    .locals 0

    .line 1
    invoke-direct {p0, p2}, Lq11/b;-><init>(Ln11/h;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Ln11/g;->f()Z

    .line 5
    .line 6
    .line 7
    move-result p2

    .line 8
    if-eqz p2, :cond_0

    .line 9
    .line 10
    iput-object p1, p0, Lq11/l;->e:Ln11/g;

    .line 11
    .line 12
    const/16 p1, 0x64

    .line 13
    .line 14
    iput p1, p0, Lq11/l;->f:I

    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 18
    .line 19
    const-string p1, "The field must be supported"

    .line 20
    .line 21
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    throw p0
.end method


# virtual methods
.method public final a(IJ)J
    .locals 4

    .line 1
    int-to-long v0, p1

    .line 2
    iget p1, p0, Lq11/l;->f:I

    .line 3
    .line 4
    int-to-long v2, p1

    .line 5
    mul-long/2addr v0, v2

    .line 6
    iget-object p0, p0, Lq11/l;->e:Ln11/g;

    .line 7
    .line 8
    invoke-virtual {p0, p2, p3, v0, v1}, Ln11/g;->b(JJ)J

    .line 9
    .line 10
    .line 11
    move-result-wide p0

    .line 12
    return-wide p0
.end method

.method public final b(JJ)J
    .locals 8

    .line 1
    const/4 v0, -0x1

    .line 2
    iget v1, p0, Lq11/l;->f:I

    .line 3
    .line 4
    const-string v2, " * "

    .line 5
    .line 6
    const-string v3, "Multiplication overflows a long: "

    .line 7
    .line 8
    if-eq v1, v0, :cond_2

    .line 9
    .line 10
    if-eqz v1, :cond_1

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    if-eq v1, v0, :cond_3

    .line 14
    .line 15
    int-to-long v4, v1

    .line 16
    mul-long v6, p3, v4

    .line 17
    .line 18
    div-long v4, v6, v4

    .line 19
    .line 20
    cmp-long v0, v4, p3

    .line 21
    .line 22
    if-nez v0, :cond_0

    .line 23
    .line 24
    move-wide p3, v6

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance p0, Ljava/lang/ArithmeticException;

    .line 27
    .line 28
    new-instance p1, Ljava/lang/StringBuilder;

    .line 29
    .line 30
    invoke-direct {p1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p1, p3, p4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    invoke-direct {p0, p1}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_1
    const-wide/16 p3, 0x0

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_2
    const-wide/high16 v4, -0x8000000000000000L

    .line 54
    .line 55
    cmp-long v0, p3, v4

    .line 56
    .line 57
    if-eqz v0, :cond_4

    .line 58
    .line 59
    neg-long p3, p3

    .line 60
    :cond_3
    :goto_0
    iget-object p0, p0, Lq11/l;->e:Ln11/g;

    .line 61
    .line 62
    invoke-virtual {p0, p1, p2, p3, p4}, Ln11/g;->b(JJ)J

    .line 63
    .line 64
    .line 65
    move-result-wide p0

    .line 66
    return-wide p0

    .line 67
    :cond_4
    new-instance p0, Ljava/lang/ArithmeticException;

    .line 68
    .line 69
    new-instance p1, Ljava/lang/StringBuilder;

    .line 70
    .line 71
    invoke-direct {p1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p1, p3, p4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    invoke-direct {p0, p1}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    throw p0
.end method

.method public final d()J
    .locals 4

    .line 1
    iget-object v0, p0, Lq11/l;->e:Ln11/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Ln11/g;->d()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget p0, p0, Lq11/l;->f:I

    .line 8
    .line 9
    int-to-long v2, p0

    .line 10
    mul-long/2addr v0, v2

    .line 11
    return-wide v0
.end method

.method public final e()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/l;->e:Ln11/g;

    .line 2
    .line 3
    invoke-virtual {p0}, Ln11/g;->e()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    instance-of v0, p1, Lq11/l;

    .line 5
    .line 6
    if-eqz v0, :cond_1

    .line 7
    .line 8
    check-cast p1, Lq11/l;

    .line 9
    .line 10
    iget-object v0, p0, Lq11/l;->e:Ln11/g;

    .line 11
    .line 12
    iget-object v1, p1, Lq11/l;->e:Ln11/g;

    .line 13
    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    iget-object v0, p0, Lq11/b;->d:Ln11/h;

    .line 21
    .line 22
    iget-object v1, p1, Lq11/b;->d:Ln11/h;

    .line 23
    .line 24
    if-ne v0, v1, :cond_1

    .line 25
    .line 26
    iget p0, p0, Lq11/l;->f:I

    .line 27
    .line 28
    iget p1, p1, Lq11/l;->f:I

    .line 29
    .line 30
    if-ne p0, p1, :cond_1

    .line 31
    .line 32
    :goto_0
    const/4 p0, 0x1

    .line 33
    return p0

    .line 34
    :cond_1
    const/4 p0, 0x0

    .line 35
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget v0, p0, Lq11/l;->f:I

    .line 2
    .line 3
    int-to-long v0, v0

    .line 4
    const/16 v2, 0x20

    .line 5
    .line 6
    ushr-long v2, v0, v2

    .line 7
    .line 8
    xor-long/2addr v0, v2

    .line 9
    long-to-int v0, v0

    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object v2, p0, Lq11/b;->d:Ln11/h;

    .line 12
    .line 13
    iget-byte v2, v2, Ln11/h;->e:B

    .line 14
    .line 15
    shl-int/2addr v1, v2

    .line 16
    add-int/2addr v0, v1

    .line 17
    iget-object p0, p0, Lq11/l;->e:Ln11/g;

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    add-int/2addr p0, v0

    .line 24
    return p0
.end method
