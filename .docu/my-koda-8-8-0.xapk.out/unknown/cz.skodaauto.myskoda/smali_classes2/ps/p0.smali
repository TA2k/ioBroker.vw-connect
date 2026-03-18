.class public final Lps/p0;
.super Lps/j2;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:J

.field public final b:Ljava/lang/String;

.field public final c:Lps/d2;

.field public final d:Lps/e2;

.field public final e:Lps/f2;

.field public final f:Lps/i2;


# direct methods
.method public constructor <init>(JLjava/lang/String;Lps/d2;Lps/e2;Lps/f2;Lps/i2;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lps/p0;->a:J

    .line 5
    .line 6
    iput-object p3, p0, Lps/p0;->b:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p4, p0, Lps/p0;->c:Lps/d2;

    .line 9
    .line 10
    iput-object p5, p0, Lps/p0;->d:Lps/e2;

    .line 11
    .line 12
    iput-object p6, p0, Lps/p0;->e:Lps/f2;

    .line 13
    .line 14
    iput-object p7, p0, Lps/p0;->f:Lps/i2;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final a()Lps/o0;
    .locals 3

    .line 1
    new-instance v0, Lps/o0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-wide v1, p0, Lps/p0;->a:J

    .line 7
    .line 8
    iput-wide v1, v0, Lps/o0;->a:J

    .line 9
    .line 10
    iget-object v1, p0, Lps/p0;->b:Ljava/lang/String;

    .line 11
    .line 12
    iput-object v1, v0, Lps/o0;->b:Ljava/lang/String;

    .line 13
    .line 14
    iget-object v1, p0, Lps/p0;->c:Lps/d2;

    .line 15
    .line 16
    iput-object v1, v0, Lps/o0;->c:Lps/d2;

    .line 17
    .line 18
    iget-object v1, p0, Lps/p0;->d:Lps/e2;

    .line 19
    .line 20
    iput-object v1, v0, Lps/o0;->d:Lps/e2;

    .line 21
    .line 22
    iget-object v1, p0, Lps/p0;->e:Lps/f2;

    .line 23
    .line 24
    iput-object v1, v0, Lps/o0;->e:Lps/f2;

    .line 25
    .line 26
    iget-object p0, p0, Lps/p0;->f:Lps/i2;

    .line 27
    .line 28
    iput-object p0, v0, Lps/o0;->f:Lps/i2;

    .line 29
    .line 30
    const/4 p0, 0x1

    .line 31
    iput-byte p0, v0, Lps/o0;->g:B

    .line 32
    .line 33
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 8

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lps/j2;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_3

    .line 9
    .line 10
    check-cast p1, Lps/j2;

    .line 11
    .line 12
    check-cast p1, Lps/p0;

    .line 13
    .line 14
    iget-object v1, p1, Lps/p0;->f:Lps/i2;

    .line 15
    .line 16
    iget-object v3, p1, Lps/p0;->e:Lps/f2;

    .line 17
    .line 18
    iget-wide v4, p1, Lps/p0;->a:J

    .line 19
    .line 20
    iget-wide v6, p0, Lps/p0;->a:J

    .line 21
    .line 22
    cmp-long v4, v6, v4

    .line 23
    .line 24
    if-nez v4, :cond_3

    .line 25
    .line 26
    iget-object v4, p0, Lps/p0;->b:Ljava/lang/String;

    .line 27
    .line 28
    iget-object v5, p1, Lps/p0;->b:Ljava/lang/String;

    .line 29
    .line 30
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v4

    .line 34
    if-eqz v4, :cond_3

    .line 35
    .line 36
    iget-object v4, p0, Lps/p0;->c:Lps/d2;

    .line 37
    .line 38
    iget-object v5, p1, Lps/p0;->c:Lps/d2;

    .line 39
    .line 40
    invoke-virtual {v4, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v4

    .line 44
    if-eqz v4, :cond_3

    .line 45
    .line 46
    iget-object v4, p0, Lps/p0;->d:Lps/e2;

    .line 47
    .line 48
    iget-object p1, p1, Lps/p0;->d:Lps/e2;

    .line 49
    .line 50
    invoke-virtual {v4, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p1

    .line 54
    if-eqz p1, :cond_3

    .line 55
    .line 56
    iget-object p1, p0, Lps/p0;->e:Lps/f2;

    .line 57
    .line 58
    if-nez p1, :cond_1

    .line 59
    .line 60
    if-nez v3, :cond_3

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_1
    invoke-virtual {p1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    if-eqz p1, :cond_3

    .line 68
    .line 69
    :goto_0
    iget-object p0, p0, Lps/p0;->f:Lps/i2;

    .line 70
    .line 71
    if-nez p0, :cond_2

    .line 72
    .line 73
    if-nez v1, :cond_3

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_2
    invoke-virtual {p0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result p0

    .line 80
    if-eqz p0, :cond_3

    .line 81
    .line 82
    :goto_1
    return v0

    .line 83
    :cond_3
    return v2
.end method

.method public final hashCode()I
    .locals 5

    .line 1
    const/16 v0, 0x20

    .line 2
    .line 3
    iget-wide v1, p0, Lps/p0;->a:J

    .line 4
    .line 5
    ushr-long v3, v1, v0

    .line 6
    .line 7
    xor-long v0, v3, v1

    .line 8
    .line 9
    long-to-int v0, v0

    .line 10
    const v1, 0xf4243

    .line 11
    .line 12
    .line 13
    xor-int/2addr v0, v1

    .line 14
    mul-int/2addr v0, v1

    .line 15
    iget-object v2, p0, Lps/p0;->b:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    xor-int/2addr v0, v2

    .line 22
    mul-int/2addr v0, v1

    .line 23
    iget-object v2, p0, Lps/p0;->c:Lps/d2;

    .line 24
    .line 25
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    xor-int/2addr v0, v2

    .line 30
    mul-int/2addr v0, v1

    .line 31
    iget-object v2, p0, Lps/p0;->d:Lps/e2;

    .line 32
    .line 33
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    xor-int/2addr v0, v2

    .line 38
    mul-int/2addr v0, v1

    .line 39
    const/4 v2, 0x0

    .line 40
    iget-object v3, p0, Lps/p0;->e:Lps/f2;

    .line 41
    .line 42
    if-nez v3, :cond_0

    .line 43
    .line 44
    move v3, v2

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    :goto_0
    xor-int/2addr v0, v3

    .line 51
    mul-int/2addr v0, v1

    .line 52
    iget-object p0, p0, Lps/p0;->f:Lps/i2;

    .line 53
    .line 54
    if-nez p0, :cond_1

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 58
    .line 59
    .line 60
    move-result v2

    .line 61
    :goto_1
    xor-int p0, v0, v2

    .line 62
    .line 63
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Event{timestamp="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-wide v1, p0, Lps/p0;->a:J

    .line 9
    .line 10
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", type="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lps/p0;->b:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", app="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lps/p0;->c:Lps/d2;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", device="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lps/p0;->d:Lps/e2;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", log="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lps/p0;->e:Lps/f2;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", rollouts="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object p0, p0, Lps/p0;->f:Lps/i2;

    .line 59
    .line 60
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string p0, "}"

    .line 64
    .line 65
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0
.end method
