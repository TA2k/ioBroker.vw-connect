.class public final Lps/r0;
.super Lps/b2;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/util/List;

.field public final b:Lps/x1;

.field public final c:Lps/p1;

.field public final d:Lps/u0;

.field public final e:Ljava/util/List;


# direct methods
.method public constructor <init>(Ljava/util/List;Lps/t0;Lps/p1;Lps/u0;Ljava/util/List;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lps/r0;->a:Ljava/util/List;

    .line 5
    .line 6
    iput-object p2, p0, Lps/r0;->b:Lps/x1;

    .line 7
    .line 8
    iput-object p3, p0, Lps/r0;->c:Lps/p1;

    .line 9
    .line 10
    iput-object p4, p0, Lps/r0;->d:Lps/u0;

    .line 11
    .line 12
    iput-object p5, p0, Lps/r0;->e:Ljava/util/List;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p1, p0, :cond_0

    .line 2
    .line 3
    goto :goto_3

    .line 4
    :cond_0
    instance-of v0, p1, Lps/b2;

    .line 5
    .line 6
    if-eqz v0, :cond_4

    .line 7
    .line 8
    check-cast p1, Lps/b2;

    .line 9
    .line 10
    iget-object v0, p0, Lps/r0;->a:Ljava/util/List;

    .line 11
    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    move-object v0, p1

    .line 15
    check-cast v0, Lps/r0;

    .line 16
    .line 17
    iget-object v0, v0, Lps/r0;->a:Ljava/util/List;

    .line 18
    .line 19
    if-nez v0, :cond_4

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_1
    move-object v1, p1

    .line 23
    check-cast v1, Lps/r0;

    .line 24
    .line 25
    iget-object v1, v1, Lps/r0;->a:Ljava/util/List;

    .line 26
    .line 27
    invoke-interface {v0, v1}, Ljava/util/List;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_4

    .line 32
    .line 33
    :goto_0
    iget-object v0, p0, Lps/r0;->b:Lps/x1;

    .line 34
    .line 35
    if-nez v0, :cond_2

    .line 36
    .line 37
    move-object v0, p1

    .line 38
    check-cast v0, Lps/r0;

    .line 39
    .line 40
    iget-object v0, v0, Lps/r0;->b:Lps/x1;

    .line 41
    .line 42
    if-nez v0, :cond_4

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_2
    move-object v1, p1

    .line 46
    check-cast v1, Lps/r0;

    .line 47
    .line 48
    iget-object v1, v1, Lps/r0;->b:Lps/x1;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-eqz v0, :cond_4

    .line 55
    .line 56
    :goto_1
    iget-object v0, p0, Lps/r0;->c:Lps/p1;

    .line 57
    .line 58
    if-nez v0, :cond_3

    .line 59
    .line 60
    move-object v0, p1

    .line 61
    check-cast v0, Lps/r0;

    .line 62
    .line 63
    iget-object v0, v0, Lps/r0;->c:Lps/p1;

    .line 64
    .line 65
    if-nez v0, :cond_4

    .line 66
    .line 67
    goto :goto_2

    .line 68
    :cond_3
    move-object v1, p1

    .line 69
    check-cast v1, Lps/r0;

    .line 70
    .line 71
    iget-object v1, v1, Lps/r0;->c:Lps/p1;

    .line 72
    .line 73
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    if-eqz v0, :cond_4

    .line 78
    .line 79
    :goto_2
    check-cast p1, Lps/r0;

    .line 80
    .line 81
    iget-object v0, p1, Lps/r0;->d:Lps/u0;

    .line 82
    .line 83
    iget-object v1, p0, Lps/r0;->d:Lps/u0;

    .line 84
    .line 85
    invoke-virtual {v1, v0}, Lps/u0;->equals(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    if-eqz v0, :cond_4

    .line 90
    .line 91
    iget-object p0, p0, Lps/r0;->e:Ljava/util/List;

    .line 92
    .line 93
    iget-object p1, p1, Lps/r0;->e:Ljava/util/List;

    .line 94
    .line 95
    invoke-interface {p0, p1}, Ljava/util/List;->equals(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    if-eqz p0, :cond_4

    .line 100
    .line 101
    :goto_3
    const/4 p0, 0x1

    .line 102
    return p0

    .line 103
    :cond_4
    const/4 p0, 0x0

    .line 104
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lps/r0;->a:Ljava/util/List;

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
    invoke-interface {v1}, Ljava/util/List;->hashCode()I

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
    iget-object v3, p0, Lps/r0;->b:Lps/x1;

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
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

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
    iget-object v3, p0, Lps/r0;->c:Lps/p1;

    .line 30
    .line 31
    if-nez v3, :cond_2

    .line 32
    .line 33
    goto :goto_2

    .line 34
    :cond_2
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    :goto_2
    xor-int/2addr v0, v1

    .line 39
    mul-int/2addr v0, v2

    .line 40
    iget-object v1, p0, Lps/r0;->d:Lps/u0;

    .line 41
    .line 42
    invoke-virtual {v1}, Lps/u0;->hashCode()I

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    xor-int/2addr v0, v1

    .line 47
    mul-int/2addr v0, v2

    .line 48
    iget-object p0, p0, Lps/r0;->e:Ljava/util/List;

    .line 49
    .line 50
    invoke-interface {p0}, Ljava/util/List;->hashCode()I

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    xor-int/2addr p0, v0

    .line 55
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Execution{threads="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lps/r0;->a:Ljava/util/List;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", exception="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lps/r0;->b:Lps/x1;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", appExitInfo="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lps/r0;->c:Lps/p1;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", signal="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lps/r0;->d:Lps/u0;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", binaries="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Lps/r0;->e:Ljava/util/List;

    .line 49
    .line 50
    const-string v1, "}"

    .line 51
    .line 52
    invoke-static {v0, p0, v1}, Lu/w;->i(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method
