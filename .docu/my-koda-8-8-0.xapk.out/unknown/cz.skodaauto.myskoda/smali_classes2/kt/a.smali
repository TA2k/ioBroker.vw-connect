.class public final Lkt/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/String;

.field public final d:Lkt/b;

.field public final e:I


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkt/b;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkt/a;->a:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lkt/a;->b:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Lkt/a;->c:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Lkt/a;->d:Lkt/b;

    .line 11
    .line 12
    iput p5, p0, Lkt/a;->e:I

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    if-ne p1, p0, :cond_0

    .line 2
    .line 3
    goto :goto_4

    .line 4
    :cond_0
    instance-of v0, p1, Lkt/a;

    .line 5
    .line 6
    if-eqz v0, :cond_6

    .line 7
    .line 8
    check-cast p1, Lkt/a;

    .line 9
    .line 10
    iget v0, p1, Lkt/a;->e:I

    .line 11
    .line 12
    iget-object v1, p1, Lkt/a;->d:Lkt/b;

    .line 13
    .line 14
    iget-object v2, p1, Lkt/a;->c:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v3, p1, Lkt/a;->b:Ljava/lang/String;

    .line 17
    .line 18
    iget-object p1, p1, Lkt/a;->a:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v4, p0, Lkt/a;->a:Ljava/lang/String;

    .line 21
    .line 22
    if-nez v4, :cond_1

    .line 23
    .line 24
    if-nez p1, :cond_6

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    invoke-virtual {v4, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    if-eqz p1, :cond_6

    .line 32
    .line 33
    :goto_0
    iget-object p1, p0, Lkt/a;->b:Ljava/lang/String;

    .line 34
    .line 35
    if-nez p1, :cond_2

    .line 36
    .line 37
    if-nez v3, :cond_6

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_2
    invoke-virtual {p1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result p1

    .line 44
    if-eqz p1, :cond_6

    .line 45
    .line 46
    :goto_1
    iget-object p1, p0, Lkt/a;->c:Ljava/lang/String;

    .line 47
    .line 48
    if-nez p1, :cond_3

    .line 49
    .line 50
    if-nez v2, :cond_6

    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_3
    invoke-virtual {p1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result p1

    .line 57
    if-eqz p1, :cond_6

    .line 58
    .line 59
    :goto_2
    iget-object p1, p0, Lkt/a;->d:Lkt/b;

    .line 60
    .line 61
    if-nez p1, :cond_4

    .line 62
    .line 63
    if-nez v1, :cond_6

    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_4
    invoke-virtual {p1, v1}, Lkt/b;->equals(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    if-eqz p1, :cond_6

    .line 71
    .line 72
    :goto_3
    iget p0, p0, Lkt/a;->e:I

    .line 73
    .line 74
    if-nez p0, :cond_5

    .line 75
    .line 76
    if-nez v0, :cond_6

    .line 77
    .line 78
    goto :goto_4

    .line 79
    :cond_5
    invoke-static {p0, v0}, Lu/w;->a(II)Z

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    if-eqz p0, :cond_6

    .line 84
    .line 85
    :goto_4
    const/4 p0, 0x1

    .line 86
    return p0

    .line 87
    :cond_6
    const/4 p0, 0x0

    .line 88
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lkt/a;->a:Ljava/lang/String;

    .line 3
    .line 4
    if-nez v1, :cond_0

    .line 5
    .line 6
    move v1, v0

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    :goto_0
    const v2, 0xf4243

    .line 13
    .line 14
    .line 15
    xor-int/2addr v1, v2

    .line 16
    mul-int/2addr v1, v2

    .line 17
    iget-object v3, p0, Lkt/a;->b:Ljava/lang/String;

    .line 18
    .line 19
    if-nez v3, :cond_1

    .line 20
    .line 21
    move v3, v0

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    :goto_1
    xor-int/2addr v1, v3

    .line 28
    mul-int/2addr v1, v2

    .line 29
    iget-object v3, p0, Lkt/a;->c:Ljava/lang/String;

    .line 30
    .line 31
    if-nez v3, :cond_2

    .line 32
    .line 33
    move v3, v0

    .line 34
    goto :goto_2

    .line 35
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    :goto_2
    xor-int/2addr v1, v3

    .line 40
    mul-int/2addr v1, v2

    .line 41
    iget-object v3, p0, Lkt/a;->d:Lkt/b;

    .line 42
    .line 43
    if-nez v3, :cond_3

    .line 44
    .line 45
    move v3, v0

    .line 46
    goto :goto_3

    .line 47
    :cond_3
    invoke-virtual {v3}, Lkt/b;->hashCode()I

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    :goto_3
    xor-int/2addr v1, v3

    .line 52
    mul-int/2addr v1, v2

    .line 53
    iget p0, p0, Lkt/a;->e:I

    .line 54
    .line 55
    if-nez p0, :cond_4

    .line 56
    .line 57
    goto :goto_4

    .line 58
    :cond_4
    invoke-static {p0}, Lu/w;->o(I)I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    :goto_4
    xor-int p0, v1, v0

    .line 63
    .line 64
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "InstallationResponse{uri="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lkt/a;->a:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", fid="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lkt/a;->b:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", refreshToken="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lkt/a;->c:Ljava/lang/String;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", authToken="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lkt/a;->d:Lkt/b;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", responseCode="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const/4 v1, 0x1

    .line 49
    iget p0, p0, Lkt/a;->e:I

    .line 50
    .line 51
    if-eq p0, v1, :cond_1

    .line 52
    .line 53
    const/4 v1, 0x2

    .line 54
    if-eq p0, v1, :cond_0

    .line 55
    .line 56
    const-string p0, "null"

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_0
    const-string p0, "BAD_CONFIG"

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_1
    const-string p0, "OK"

    .line 63
    .line 64
    :goto_0
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    const-string p0, "}"

    .line 68
    .line 69
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0
.end method
