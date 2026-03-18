.class public final Llc0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Llc0/l;

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;


# direct methods
.method public constructor <init>(Llc0/l;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "tokenType"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Llc0/k;->a:Llc0/l;

    .line 10
    .line 11
    iput-object p2, p0, Llc0/k;->b:Ljava/lang/String;

    .line 12
    .line 13
    iput-object p3, p0, Llc0/k;->c:Ljava/lang/String;

    .line 14
    .line 15
    iput-object p4, p0, Llc0/k;->d:Ljava/lang/String;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
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
    instance-of v1, p1, Llc0/k;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Llc0/k;

    .line 12
    .line 13
    iget-object v1, p0, Llc0/k;->a:Llc0/l;

    .line 14
    .line 15
    iget-object v3, p1, Llc0/k;->a:Llc0/l;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p1, Llc0/k;->b:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v3, p0, Llc0/k;->b:Ljava/lang/String;

    .line 23
    .line 24
    if-nez v3, :cond_4

    .line 25
    .line 26
    if-nez v1, :cond_3

    .line 27
    .line 28
    move v1, v0

    .line 29
    goto :goto_1

    .line 30
    :cond_3
    :goto_0
    move v1, v2

    .line 31
    goto :goto_1

    .line 32
    :cond_4
    if-nez v1, :cond_5

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_5
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    :goto_1
    if-nez v1, :cond_6

    .line 40
    .line 41
    return v2

    .line 42
    :cond_6
    iget-object v1, p1, Llc0/k;->c:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v3, p0, Llc0/k;->c:Ljava/lang/String;

    .line 45
    .line 46
    if-nez v3, :cond_8

    .line 47
    .line 48
    if-nez v1, :cond_7

    .line 49
    .line 50
    move v1, v0

    .line 51
    goto :goto_3

    .line 52
    :cond_7
    :goto_2
    move v1, v2

    .line 53
    goto :goto_3

    .line 54
    :cond_8
    if-nez v1, :cond_9

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_9
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    :goto_3
    if-nez v1, :cond_a

    .line 62
    .line 63
    return v2

    .line 64
    :cond_a
    iget-object p1, p1, Llc0/k;->d:Ljava/lang/String;

    .line 65
    .line 66
    iget-object p0, p0, Llc0/k;->d:Ljava/lang/String;

    .line 67
    .line 68
    if-nez p0, :cond_c

    .line 69
    .line 70
    if-nez p1, :cond_b

    .line 71
    .line 72
    move p0, v0

    .line 73
    goto :goto_5

    .line 74
    :cond_b
    :goto_4
    move p0, v2

    .line 75
    goto :goto_5

    .line 76
    :cond_c
    if-nez p1, :cond_d

    .line 77
    .line 78
    goto :goto_4

    .line 79
    :cond_d
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    :goto_5
    if-nez p0, :cond_e

    .line 84
    .line 85
    return v2

    .line 86
    :cond_e
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Llc0/k;->a:Llc0/l;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    iget-object v2, p0, Llc0/k;->b:Ljava/lang/String;

    .line 11
    .line 12
    if-nez v2, :cond_0

    .line 13
    .line 14
    move v2, v1

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    :goto_0
    add-int/2addr v0, v2

    .line 21
    mul-int/lit8 v0, v0, 0x1f

    .line 22
    .line 23
    iget-object v2, p0, Llc0/k;->c:Ljava/lang/String;

    .line 24
    .line 25
    if-nez v2, :cond_1

    .line 26
    .line 27
    move v2, v1

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    :goto_1
    add-int/2addr v0, v2

    .line 34
    mul-int/lit8 v0, v0, 0x1f

    .line 35
    .line 36
    iget-object p0, p0, Llc0/k;->d:Ljava/lang/String;

    .line 37
    .line 38
    if-nez p0, :cond_2

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_2
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    :goto_2
    add-int/2addr v0, v1

    .line 46
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    .line 1
    const-string v0, ")"

    .line 2
    .line 3
    const-string v1, "null"

    .line 4
    .line 5
    iget-object v2, p0, Llc0/k;->b:Ljava/lang/String;

    .line 6
    .line 7
    if-nez v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const-string v3, "AccessToken(value="

    .line 12
    .line 13
    invoke-static {v3, v2, v0}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    :goto_0
    iget-object v3, p0, Llc0/k;->c:Ljava/lang/String;

    .line 18
    .line 19
    if-nez v3, :cond_1

    .line 20
    .line 21
    move-object v3, v1

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    const-string v4, "RefreshToken(value="

    .line 24
    .line 25
    invoke-static {v4, v3, v0}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    :goto_1
    iget-object v4, p0, Llc0/k;->d:Ljava/lang/String;

    .line 30
    .line 31
    if-nez v4, :cond_2

    .line 32
    .line 33
    goto :goto_2

    .line 34
    :cond_2
    const-string v1, "IdToken(value="

    .line 35
    .line 36
    invoke-static {v1, v4, v0}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    :goto_2
    new-instance v4, Ljava/lang/StringBuilder;

    .line 41
    .line 42
    const-string v5, "TokenBundle(tokenType="

    .line 43
    .line 44
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    iget-object p0, p0, Llc0/k;->a:Llc0/l;

    .line 48
    .line 49
    invoke-virtual {v4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    const-string p0, ", accessToken="

    .line 53
    .line 54
    invoke-virtual {v4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string p0, ", refreshToken="

    .line 61
    .line 62
    invoke-virtual {v4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    const-string p0, ", idToken="

    .line 66
    .line 67
    invoke-static {v4, v3, p0, v1, v0}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0
.end method
