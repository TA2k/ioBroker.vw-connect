.class public final Lrn/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/Integer;

.field public final c:Lrn/m;

.field public final d:J

.field public final e:J

.field public final f:Ljava/util/Map;

.field public final g:Ljava/lang/Integer;

.field public final h:Ljava/lang/String;

.field public final i:[B

.field public final j:[B


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/Integer;Lrn/m;JJLjava/util/HashMap;Ljava/lang/Integer;Ljava/lang/String;[B[B)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrn/h;->a:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lrn/h;->b:Ljava/lang/Integer;

    .line 7
    .line 8
    iput-object p3, p0, Lrn/h;->c:Lrn/m;

    .line 9
    .line 10
    iput-wide p4, p0, Lrn/h;->d:J

    .line 11
    .line 12
    iput-wide p6, p0, Lrn/h;->e:J

    .line 13
    .line 14
    iput-object p8, p0, Lrn/h;->f:Ljava/util/Map;

    .line 15
    .line 16
    iput-object p9, p0, Lrn/h;->g:Ljava/lang/Integer;

    .line 17
    .line 18
    iput-object p10, p0, Lrn/h;->h:Ljava/lang/String;

    .line 19
    .line 20
    iput-object p11, p0, Lrn/h;->i:[B

    .line 21
    .line 22
    iput-object p12, p0, Lrn/h;->j:[B

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lrn/h;->f:Ljava/util/Map;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/String;

    .line 8
    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    const-string p0, ""

    .line 12
    .line 13
    :cond_0
    return-object p0
.end method

.method public final b(Ljava/lang/String;)I
    .locals 0

    .line 1
    iget-object p0, p0, Lrn/h;->f:Ljava/util/Map;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/String;

    .line 8
    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    return p0

    .line 13
    :cond_0
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(Ljava/lang/String;)Ljava/lang/Integer;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method

.method public final c()Lg1/q;
    .locals 3

    .line 1
    new-instance v0, Lg1/q;

    .line 2
    .line 3
    invoke-direct {v0}, Lg1/q;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lrn/h;->a:Ljava/lang/String;

    .line 7
    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    iput-object v1, v0, Lg1/q;->b:Ljava/lang/Object;

    .line 11
    .line 12
    iget-object v1, p0, Lrn/h;->b:Ljava/lang/Integer;

    .line 13
    .line 14
    iput-object v1, v0, Lg1/q;->c:Ljava/lang/Object;

    .line 15
    .line 16
    iget-object v1, p0, Lrn/h;->g:Ljava/lang/Integer;

    .line 17
    .line 18
    iput-object v1, v0, Lg1/q;->h:Ljava/lang/Object;

    .line 19
    .line 20
    iget-object v1, p0, Lrn/h;->h:Ljava/lang/String;

    .line 21
    .line 22
    iput-object v1, v0, Lg1/q;->i:Ljava/lang/Object;

    .line 23
    .line 24
    iget-object v1, p0, Lrn/h;->i:[B

    .line 25
    .line 26
    iput-object v1, v0, Lg1/q;->j:Ljava/lang/Object;

    .line 27
    .line 28
    iget-object v1, p0, Lrn/h;->j:[B

    .line 29
    .line 30
    iput-object v1, v0, Lg1/q;->k:Ljava/lang/Object;

    .line 31
    .line 32
    iget-object v1, p0, Lrn/h;->c:Lrn/m;

    .line 33
    .line 34
    if-eqz v1, :cond_0

    .line 35
    .line 36
    iput-object v1, v0, Lg1/q;->d:Ljava/lang/Object;

    .line 37
    .line 38
    iget-wide v1, p0, Lrn/h;->d:J

    .line 39
    .line 40
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    iput-object v1, v0, Lg1/q;->e:Ljava/lang/Object;

    .line 45
    .line 46
    iget-wide v1, p0, Lrn/h;->e:J

    .line 47
    .line 48
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    iput-object v1, v0, Lg1/q;->f:Ljava/lang/Object;

    .line 53
    .line 54
    new-instance v1, Ljava/util/HashMap;

    .line 55
    .line 56
    iget-object p0, p0, Lrn/h;->f:Ljava/util/Map;

    .line 57
    .line 58
    invoke-direct {v1, p0}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 59
    .line 60
    .line 61
    iput-object v1, v0, Lg1/q;->g:Ljava/lang/Object;

    .line 62
    .line 63
    return-object v0

    .line 64
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 65
    .line 66
    const-string v0, "Null encodedPayload"

    .line 67
    .line 68
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    throw p0

    .line 72
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    .line 73
    .line 74
    const-string v0, "Null transportName"

    .line 75
    .line 76
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    throw p0
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
    instance-of v1, p1, Lrn/h;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_4

    .line 9
    .line 10
    check-cast p1, Lrn/h;

    .line 11
    .line 12
    iget-object v1, p1, Lrn/h;->h:Ljava/lang/String;

    .line 13
    .line 14
    iget-object v3, p1, Lrn/h;->g:Ljava/lang/Integer;

    .line 15
    .line 16
    iget-object v4, p1, Lrn/h;->b:Ljava/lang/Integer;

    .line 17
    .line 18
    iget-object v5, p0, Lrn/h;->a:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v6, p1, Lrn/h;->a:Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v5

    .line 26
    if-eqz v5, :cond_4

    .line 27
    .line 28
    iget-object v5, p0, Lrn/h;->b:Ljava/lang/Integer;

    .line 29
    .line 30
    if-nez v5, :cond_1

    .line 31
    .line 32
    if-nez v4, :cond_4

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    invoke-virtual {v5, v4}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    if-eqz v4, :cond_4

    .line 40
    .line 41
    :goto_0
    iget-object v4, p0, Lrn/h;->c:Lrn/m;

    .line 42
    .line 43
    iget-object v5, p1, Lrn/h;->c:Lrn/m;

    .line 44
    .line 45
    invoke-virtual {v4, v5}, Lrn/m;->equals(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    if-eqz v4, :cond_4

    .line 50
    .line 51
    iget-wide v4, p0, Lrn/h;->d:J

    .line 52
    .line 53
    iget-wide v6, p1, Lrn/h;->d:J

    .line 54
    .line 55
    cmp-long v4, v4, v6

    .line 56
    .line 57
    if-nez v4, :cond_4

    .line 58
    .line 59
    iget-wide v4, p0, Lrn/h;->e:J

    .line 60
    .line 61
    iget-wide v6, p1, Lrn/h;->e:J

    .line 62
    .line 63
    cmp-long v4, v4, v6

    .line 64
    .line 65
    if-nez v4, :cond_4

    .line 66
    .line 67
    iget-object v4, p0, Lrn/h;->f:Ljava/util/Map;

    .line 68
    .line 69
    iget-object v5, p1, Lrn/h;->f:Ljava/util/Map;

    .line 70
    .line 71
    invoke-interface {v4, v5}, Ljava/util/Map;->equals(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v4

    .line 75
    if-eqz v4, :cond_4

    .line 76
    .line 77
    iget-object v4, p0, Lrn/h;->g:Ljava/lang/Integer;

    .line 78
    .line 79
    if-nez v4, :cond_2

    .line 80
    .line 81
    if-nez v3, :cond_4

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_2
    invoke-virtual {v4, v3}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result v3

    .line 88
    if-eqz v3, :cond_4

    .line 89
    .line 90
    :goto_1
    iget-object v3, p0, Lrn/h;->h:Ljava/lang/String;

    .line 91
    .line 92
    if-nez v3, :cond_3

    .line 93
    .line 94
    if-nez v1, :cond_4

    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_3
    invoke-virtual {v3, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    if-eqz v1, :cond_4

    .line 102
    .line 103
    :goto_2
    iget-object v1, p0, Lrn/h;->i:[B

    .line 104
    .line 105
    iget-object v3, p1, Lrn/h;->i:[B

    .line 106
    .line 107
    invoke-static {v1, v3}, Ljava/util/Arrays;->equals([B[B)Z

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    if-eqz v1, :cond_4

    .line 112
    .line 113
    iget-object p0, p0, Lrn/h;->j:[B

    .line 114
    .line 115
    iget-object p1, p1, Lrn/h;->j:[B

    .line 116
    .line 117
    invoke-static {p0, p1}, Ljava/util/Arrays;->equals([B[B)Z

    .line 118
    .line 119
    .line 120
    move-result p0

    .line 121
    if-eqz p0, :cond_4

    .line 122
    .line 123
    return v0

    .line 124
    :cond_4
    return v2
.end method

.method public final hashCode()I
    .locals 8

    .line 1
    iget-object v0, p0, Lrn/h;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const v1, 0xf4243

    .line 8
    .line 9
    .line 10
    xor-int/2addr v0, v1

    .line 11
    mul-int/2addr v0, v1

    .line 12
    const/4 v2, 0x0

    .line 13
    iget-object v3, p0, Lrn/h;->b:Ljava/lang/Integer;

    .line 14
    .line 15
    if-nez v3, :cond_0

    .line 16
    .line 17
    move v3, v2

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Integer;->hashCode()I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    :goto_0
    xor-int/2addr v0, v3

    .line 24
    mul-int/2addr v0, v1

    .line 25
    iget-object v3, p0, Lrn/h;->c:Lrn/m;

    .line 26
    .line 27
    invoke-virtual {v3}, Lrn/m;->hashCode()I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    xor-int/2addr v0, v3

    .line 32
    mul-int/2addr v0, v1

    .line 33
    iget-wide v3, p0, Lrn/h;->d:J

    .line 34
    .line 35
    const/16 v5, 0x20

    .line 36
    .line 37
    ushr-long v6, v3, v5

    .line 38
    .line 39
    xor-long/2addr v3, v6

    .line 40
    long-to-int v3, v3

    .line 41
    xor-int/2addr v0, v3

    .line 42
    mul-int/2addr v0, v1

    .line 43
    iget-wide v3, p0, Lrn/h;->e:J

    .line 44
    .line 45
    ushr-long v5, v3, v5

    .line 46
    .line 47
    xor-long/2addr v3, v5

    .line 48
    long-to-int v3, v3

    .line 49
    xor-int/2addr v0, v3

    .line 50
    mul-int/2addr v0, v1

    .line 51
    iget-object v3, p0, Lrn/h;->f:Ljava/util/Map;

    .line 52
    .line 53
    invoke-interface {v3}, Ljava/util/Map;->hashCode()I

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    xor-int/2addr v0, v3

    .line 58
    mul-int/2addr v0, v1

    .line 59
    iget-object v3, p0, Lrn/h;->g:Ljava/lang/Integer;

    .line 60
    .line 61
    if-nez v3, :cond_1

    .line 62
    .line 63
    move v3, v2

    .line 64
    goto :goto_1

    .line 65
    :cond_1
    invoke-virtual {v3}, Ljava/lang/Integer;->hashCode()I

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    :goto_1
    xor-int/2addr v0, v3

    .line 70
    mul-int/2addr v0, v1

    .line 71
    iget-object v3, p0, Lrn/h;->h:Ljava/lang/String;

    .line 72
    .line 73
    if-nez v3, :cond_2

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    :goto_2
    xor-int/2addr v0, v2

    .line 81
    mul-int/2addr v0, v1

    .line 82
    iget-object v2, p0, Lrn/h;->i:[B

    .line 83
    .line 84
    invoke-static {v2}, Ljava/util/Arrays;->hashCode([B)I

    .line 85
    .line 86
    .line 87
    move-result v2

    .line 88
    xor-int/2addr v0, v2

    .line 89
    mul-int/2addr v0, v1

    .line 90
    iget-object p0, p0, Lrn/h;->j:[B

    .line 91
    .line 92
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([B)I

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    xor-int/2addr p0, v0

    .line 97
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "EventInternal{transportName="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lrn/h;->a:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", code="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lrn/h;->b:Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", encodedPayload="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lrn/h;->c:Lrn/m;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", eventMillis="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-wide v1, p0, Lrn/h;->d:J

    .line 39
    .line 40
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", uptimeMillis="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-wide v1, p0, Lrn/h;->e:J

    .line 49
    .line 50
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", autoMetadata="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lrn/h;->f:Ljava/util/Map;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", productId="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-object v1, p0, Lrn/h;->g:Ljava/lang/Integer;

    .line 69
    .line 70
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", pseudonymousId="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-object v1, p0, Lrn/h;->h:Ljava/lang/String;

    .line 79
    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", experimentIdsClear="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    iget-object v1, p0, Lrn/h;->i:[B

    .line 89
    .line 90
    invoke-static {v1}, Ljava/util/Arrays;->toString([B)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    const-string v1, ", experimentIdsEncrypted="

    .line 98
    .line 99
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    iget-object p0, p0, Lrn/h;->j:[B

    .line 103
    .line 104
    invoke-static {p0}, Ljava/util/Arrays;->toString([B)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    const-string p0, "}"

    .line 112
    .line 113
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    return-object p0
.end method
