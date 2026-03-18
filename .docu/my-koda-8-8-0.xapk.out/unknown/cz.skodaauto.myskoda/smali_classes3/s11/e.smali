.class public final Ls11/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ls11/c;

.field public final b:Ljava/lang/String;

.field public final c:I


# direct methods
.method public constructor <init>(Ls11/c;Ljava/lang/String;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ls11/e;->a:Ls11/c;

    .line 5
    .line 6
    iput-object p2, p0, Ls11/e;->b:Ljava/lang/String;

    .line 7
    .line 8
    iput p3, p0, Ls11/e;->c:I

    .line 9
    .line 10
    return-void
.end method

.method public static c(Ljava/io/DataInput;)Ls11/e;
    .locals 9

    .line 1
    new-instance v0, Ls11/e;

    .line 2
    .line 3
    new-instance v1, Ls11/c;

    .line 4
    .line 5
    invoke-interface {p0}, Ljava/io/DataInput;->readUnsignedByte()I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    int-to-char v2, v2

    .line 10
    invoke-interface {p0}, Ljava/io/DataInput;->readUnsignedByte()I

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    invoke-interface {p0}, Ljava/io/DataInput;->readByte()B

    .line 15
    .line 16
    .line 17
    move-result v4

    .line 18
    invoke-interface {p0}, Ljava/io/DataInput;->readUnsignedByte()I

    .line 19
    .line 20
    .line 21
    move-result v5

    .line 22
    invoke-interface {p0}, Ljava/io/DataInput;->readBoolean()Z

    .line 23
    .line 24
    .line 25
    move-result v6

    .line 26
    invoke-static {p0}, Lkp/v6;->c(Ljava/io/DataInput;)J

    .line 27
    .line 28
    .line 29
    move-result-wide v7

    .line 30
    long-to-int v7, v7

    .line 31
    invoke-direct/range {v1 .. v7}, Ls11/c;-><init>(CIIIZI)V

    .line 32
    .line 33
    .line 34
    invoke-interface {p0}, Ljava/io/DataInput;->readUTF()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    invoke-static {p0}, Lkp/v6;->c(Ljava/io/DataInput;)J

    .line 39
    .line 40
    .line 41
    move-result-wide v3

    .line 42
    long-to-int p0, v3

    .line 43
    invoke-direct {v0, v1, v2, p0}, Ls11/e;-><init>(Ls11/c;Ljava/lang/String;I)V

    .line 44
    .line 45
    .line 46
    return-object v0
.end method


# virtual methods
.method public final a(JII)J
    .locals 6

    .line 1
    iget-object p0, p0, Ls11/e;->a:Ls11/c;

    .line 2
    .line 3
    iget v0, p0, Ls11/c;->b:I

    .line 4
    .line 5
    iget-char v1, p0, Ls11/c;->a:C

    .line 6
    .line 7
    const/16 v2, 0x77

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    if-ne v1, v2, :cond_0

    .line 11
    .line 12
    add-int/2addr p3, p4

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/16 p4, 0x73

    .line 15
    .line 16
    if-ne v1, p4, :cond_1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    move p3, v3

    .line 20
    :goto_0
    int-to-long p3, p3

    .line 21
    add-long/2addr p1, p3

    .line 22
    sget-object v1, Lp11/n;->P:Lp11/n;

    .line 23
    .line 24
    iget-object v2, v1, Lp11/b;->I:Ln11/a;

    .line 25
    .line 26
    invoke-virtual {v2, v0, p1, p2}, Ln11/a;->v(IJ)J

    .line 27
    .line 28
    .line 29
    move-result-wide v4

    .line 30
    iget-object v2, v1, Lp11/b;->s:Ln11/a;

    .line 31
    .line 32
    invoke-virtual {v2, v3, v4, v5}, Ln11/a;->v(IJ)J

    .line 33
    .line 34
    .line 35
    move-result-wide v2

    .line 36
    iget-object v4, v1, Lp11/b;->s:Ln11/a;

    .line 37
    .line 38
    iget v5, p0, Ls11/c;->f:I

    .line 39
    .line 40
    invoke-virtual {v4, v5, v2, v3}, Ln11/a;->a(IJ)J

    .line 41
    .line 42
    .line 43
    move-result-wide v2

    .line 44
    invoke-virtual {p0, v2, v3, v1}, Ls11/c;->b(JLjp/u1;)J

    .line 45
    .line 46
    .line 47
    move-result-wide v2

    .line 48
    iget v4, p0, Ls11/c;->d:I

    .line 49
    .line 50
    const/4 v5, 0x1

    .line 51
    if-nez v4, :cond_2

    .line 52
    .line 53
    cmp-long p1, v2, p1

    .line 54
    .line 55
    if-gtz p1, :cond_3

    .line 56
    .line 57
    iget-object p1, v1, Lp11/b;->J:Ln11/a;

    .line 58
    .line 59
    invoke-virtual {p1, v5, v2, v3}, Ln11/a;->a(IJ)J

    .line 60
    .line 61
    .line 62
    move-result-wide p1

    .line 63
    invoke-virtual {p0, p1, p2, v1}, Ls11/c;->b(JLjp/u1;)J

    .line 64
    .line 65
    .line 66
    move-result-wide v2

    .line 67
    goto :goto_1

    .line 68
    :cond_2
    invoke-virtual {p0, v2, v3, v1}, Ls11/c;->d(JLjp/u1;)J

    .line 69
    .line 70
    .line 71
    move-result-wide v2

    .line 72
    cmp-long p1, v2, p1

    .line 73
    .line 74
    if-gtz p1, :cond_3

    .line 75
    .line 76
    iget-object p1, v1, Lp11/b;->J:Ln11/a;

    .line 77
    .line 78
    invoke-virtual {p1, v5, v2, v3}, Ln11/a;->a(IJ)J

    .line 79
    .line 80
    .line 81
    move-result-wide p1

    .line 82
    iget-object v2, v1, Lp11/b;->I:Ln11/a;

    .line 83
    .line 84
    invoke-virtual {v2, v0, p1, p2}, Ln11/a;->v(IJ)J

    .line 85
    .line 86
    .line 87
    move-result-wide p1

    .line 88
    invoke-virtual {p0, p1, p2, v1}, Ls11/c;->b(JLjp/u1;)J

    .line 89
    .line 90
    .line 91
    move-result-wide p1

    .line 92
    invoke-virtual {p0, p1, p2, v1}, Ls11/c;->d(JLjp/u1;)J

    .line 93
    .line 94
    .line 95
    move-result-wide v2

    .line 96
    :cond_3
    :goto_1
    sub-long/2addr v2, p3

    .line 97
    return-wide v2
.end method

.method public final b(JII)J
    .locals 6

    .line 1
    iget-object p0, p0, Ls11/e;->a:Ls11/c;

    .line 2
    .line 3
    iget v0, p0, Ls11/c;->b:I

    .line 4
    .line 5
    iget-char v1, p0, Ls11/c;->a:C

    .line 6
    .line 7
    const/16 v2, 0x77

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    if-ne v1, v2, :cond_0

    .line 11
    .line 12
    add-int/2addr p3, p4

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/16 p4, 0x73

    .line 15
    .line 16
    if-ne v1, p4, :cond_1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    move p3, v3

    .line 20
    :goto_0
    int-to-long p3, p3

    .line 21
    add-long/2addr p1, p3

    .line 22
    sget-object v1, Lp11/n;->P:Lp11/n;

    .line 23
    .line 24
    iget-object v2, v1, Lp11/b;->I:Ln11/a;

    .line 25
    .line 26
    invoke-virtual {v2, v0, p1, p2}, Ln11/a;->v(IJ)J

    .line 27
    .line 28
    .line 29
    move-result-wide v4

    .line 30
    iget-object v2, v1, Lp11/b;->s:Ln11/a;

    .line 31
    .line 32
    invoke-virtual {v2, v3, v4, v5}, Ln11/a;->v(IJ)J

    .line 33
    .line 34
    .line 35
    move-result-wide v2

    .line 36
    iget-object v4, v1, Lp11/b;->s:Ln11/a;

    .line 37
    .line 38
    iget v5, p0, Ls11/c;->f:I

    .line 39
    .line 40
    invoke-virtual {v4, v5, v2, v3}, Ln11/a;->a(IJ)J

    .line 41
    .line 42
    .line 43
    move-result-wide v2

    .line 44
    invoke-virtual {p0, v2, v3, v1}, Ls11/c;->c(JLjp/u1;)J

    .line 45
    .line 46
    .line 47
    move-result-wide v2

    .line 48
    iget v4, p0, Ls11/c;->d:I

    .line 49
    .line 50
    const/4 v5, -0x1

    .line 51
    if-nez v4, :cond_2

    .line 52
    .line 53
    cmp-long p1, v2, p1

    .line 54
    .line 55
    if-ltz p1, :cond_3

    .line 56
    .line 57
    iget-object p1, v1, Lp11/b;->J:Ln11/a;

    .line 58
    .line 59
    invoke-virtual {p1, v5, v2, v3}, Ln11/a;->a(IJ)J

    .line 60
    .line 61
    .line 62
    move-result-wide p1

    .line 63
    invoke-virtual {p0, p1, p2, v1}, Ls11/c;->c(JLjp/u1;)J

    .line 64
    .line 65
    .line 66
    move-result-wide v2

    .line 67
    goto :goto_1

    .line 68
    :cond_2
    invoke-virtual {p0, v2, v3, v1}, Ls11/c;->d(JLjp/u1;)J

    .line 69
    .line 70
    .line 71
    move-result-wide v2

    .line 72
    cmp-long p1, v2, p1

    .line 73
    .line 74
    if-ltz p1, :cond_3

    .line 75
    .line 76
    iget-object p1, v1, Lp11/b;->J:Ln11/a;

    .line 77
    .line 78
    invoke-virtual {p1, v5, v2, v3}, Ln11/a;->a(IJ)J

    .line 79
    .line 80
    .line 81
    move-result-wide p1

    .line 82
    iget-object v2, v1, Lp11/b;->I:Ln11/a;

    .line 83
    .line 84
    invoke-virtual {v2, v0, p1, p2}, Ln11/a;->v(IJ)J

    .line 85
    .line 86
    .line 87
    move-result-wide p1

    .line 88
    invoke-virtual {p0, p1, p2, v1}, Ls11/c;->c(JLjp/u1;)J

    .line 89
    .line 90
    .line 91
    move-result-wide p1

    .line 92
    invoke-virtual {p0, p1, p2, v1}, Ls11/c;->d(JLjp/u1;)J

    .line 93
    .line 94
    .line 95
    move-result-wide v2

    .line 96
    :cond_3
    :goto_1
    sub-long/2addr v2, p3

    .line 97
    return-wide v2
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
    instance-of v1, p1, Ls11/e;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Ls11/e;

    .line 11
    .line 12
    iget v1, p0, Ls11/e;->c:I

    .line 13
    .line 14
    iget v3, p1, Ls11/e;->c:I

    .line 15
    .line 16
    if-ne v1, v3, :cond_1

    .line 17
    .line 18
    iget-object v1, p0, Ls11/e;->b:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v3, p1, Ls11/e;->b:Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-eqz v1, :cond_1

    .line 27
    .line 28
    iget-object p0, p0, Ls11/e;->a:Ls11/c;

    .line 29
    .line 30
    iget-object p1, p1, Ls11/e;->a:Ls11/c;

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Ls11/c;->equals(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    if-eqz p0, :cond_1

    .line 37
    .line 38
    return v0

    .line 39
    :cond_1
    return v2
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Ls11/e;->a:Ls11/c;

    .line 7
    .line 8
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string v1, " named "

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    iget-object v1, p0, Ls11/e;->b:Ljava/lang/String;

    .line 17
    .line 18
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string v1, " at "

    .line 22
    .line 23
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    iget p0, p0, Ls11/e;->c:I

    .line 27
    .line 28
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0
.end method
