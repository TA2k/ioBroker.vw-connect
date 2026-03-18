.class public final Lqn/t;
.super Lqn/f0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:J

.field public final b:Ljava/lang/Integer;

.field public final c:Lqn/b0;

.field public final d:J

.field public final e:[B

.field public final f:Ljava/lang/String;

.field public final g:J

.field public final h:Lqn/j0;

.field public final i:Lqn/c0;


# direct methods
.method public constructor <init>(JLjava/lang/Integer;Lqn/b0;J[BLjava/lang/String;JLqn/j0;Lqn/c0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lqn/t;->a:J

    .line 5
    .line 6
    iput-object p3, p0, Lqn/t;->b:Ljava/lang/Integer;

    .line 7
    .line 8
    iput-object p4, p0, Lqn/t;->c:Lqn/b0;

    .line 9
    .line 10
    iput-wide p5, p0, Lqn/t;->d:J

    .line 11
    .line 12
    iput-object p7, p0, Lqn/t;->e:[B

    .line 13
    .line 14
    iput-object p8, p0, Lqn/t;->f:Ljava/lang/String;

    .line 15
    .line 16
    iput-wide p9, p0, Lqn/t;->g:J

    .line 17
    .line 18
    iput-object p11, p0, Lqn/t;->h:Lqn/j0;

    .line 19
    .line 20
    iput-object p12, p0, Lqn/t;->i:Lqn/c0;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 12

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lqn/f0;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_7

    .line 9
    .line 10
    check-cast p1, Lqn/f0;

    .line 11
    .line 12
    move-object v1, p1

    .line 13
    check-cast v1, Lqn/t;

    .line 14
    .line 15
    iget-object v3, v1, Lqn/t;->i:Lqn/c0;

    .line 16
    .line 17
    iget-object v4, v1, Lqn/t;->h:Lqn/j0;

    .line 18
    .line 19
    iget-object v5, v1, Lqn/t;->f:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v6, v1, Lqn/t;->c:Lqn/b0;

    .line 22
    .line 23
    iget-object v7, v1, Lqn/t;->b:Ljava/lang/Integer;

    .line 24
    .line 25
    iget-wide v8, v1, Lqn/t;->a:J

    .line 26
    .line 27
    iget-wide v10, p0, Lqn/t;->a:J

    .line 28
    .line 29
    cmp-long v8, v10, v8

    .line 30
    .line 31
    if-nez v8, :cond_7

    .line 32
    .line 33
    iget-object v8, p0, Lqn/t;->b:Ljava/lang/Integer;

    .line 34
    .line 35
    if-nez v8, :cond_1

    .line 36
    .line 37
    if-nez v7, :cond_7

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    invoke-virtual {v8, v7}, Ljava/lang/Integer;->equals(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v7

    .line 44
    if-eqz v7, :cond_7

    .line 45
    .line 46
    :goto_0
    iget-object v7, p0, Lqn/t;->c:Lqn/b0;

    .line 47
    .line 48
    if-nez v7, :cond_2

    .line 49
    .line 50
    if-nez v6, :cond_7

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_2
    invoke-virtual {v7, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v6

    .line 57
    if-eqz v6, :cond_7

    .line 58
    .line 59
    :goto_1
    iget-wide v6, p0, Lqn/t;->d:J

    .line 60
    .line 61
    iget-wide v8, v1, Lqn/t;->d:J

    .line 62
    .line 63
    cmp-long v6, v6, v8

    .line 64
    .line 65
    if-nez v6, :cond_7

    .line 66
    .line 67
    instance-of v6, p1, Lqn/t;

    .line 68
    .line 69
    if-eqz v6, :cond_3

    .line 70
    .line 71
    check-cast p1, Lqn/t;

    .line 72
    .line 73
    iget-object p1, p1, Lqn/t;->e:[B

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_3
    iget-object p1, v1, Lqn/t;->e:[B

    .line 77
    .line 78
    :goto_2
    iget-object v6, p0, Lqn/t;->e:[B

    .line 79
    .line 80
    invoke-static {v6, p1}, Ljava/util/Arrays;->equals([B[B)Z

    .line 81
    .line 82
    .line 83
    move-result p1

    .line 84
    if-eqz p1, :cond_7

    .line 85
    .line 86
    iget-object p1, p0, Lqn/t;->f:Ljava/lang/String;

    .line 87
    .line 88
    if-nez p1, :cond_4

    .line 89
    .line 90
    if-nez v5, :cond_7

    .line 91
    .line 92
    goto :goto_3

    .line 93
    :cond_4
    invoke-virtual {p1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result p1

    .line 97
    if-eqz p1, :cond_7

    .line 98
    .line 99
    :goto_3
    iget-wide v5, p0, Lqn/t;->g:J

    .line 100
    .line 101
    iget-wide v7, v1, Lqn/t;->g:J

    .line 102
    .line 103
    cmp-long p1, v5, v7

    .line 104
    .line 105
    if-nez p1, :cond_7

    .line 106
    .line 107
    iget-object p1, p0, Lqn/t;->h:Lqn/j0;

    .line 108
    .line 109
    if-nez p1, :cond_5

    .line 110
    .line 111
    if-nez v4, :cond_7

    .line 112
    .line 113
    goto :goto_4

    .line 114
    :cond_5
    invoke-virtual {p1, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 115
    .line 116
    .line 117
    move-result p1

    .line 118
    if-eqz p1, :cond_7

    .line 119
    .line 120
    :goto_4
    iget-object p0, p0, Lqn/t;->i:Lqn/c0;

    .line 121
    .line 122
    if-nez p0, :cond_6

    .line 123
    .line 124
    if-nez v3, :cond_7

    .line 125
    .line 126
    goto :goto_5

    .line 127
    :cond_6
    invoke-virtual {p0, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result p0

    .line 131
    if-eqz p0, :cond_7

    .line 132
    .line 133
    :goto_5
    return v0

    .line 134
    :cond_7
    return v2
.end method

.method public final hashCode()I
    .locals 8

    .line 1
    iget-wide v0, p0, Lqn/t;->a:J

    .line 2
    .line 3
    const/16 v2, 0x20

    .line 4
    .line 5
    ushr-long v3, v0, v2

    .line 6
    .line 7
    xor-long/2addr v0, v3

    .line 8
    long-to-int v0, v0

    .line 9
    const v1, 0xf4243

    .line 10
    .line 11
    .line 12
    xor-int/2addr v0, v1

    .line 13
    mul-int/2addr v0, v1

    .line 14
    const/4 v3, 0x0

    .line 15
    iget-object v4, p0, Lqn/t;->b:Ljava/lang/Integer;

    .line 16
    .line 17
    if-nez v4, :cond_0

    .line 18
    .line 19
    move v4, v3

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    invoke-virtual {v4}, Ljava/lang/Integer;->hashCode()I

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    :goto_0
    xor-int/2addr v0, v4

    .line 26
    mul-int/2addr v0, v1

    .line 27
    iget-object v4, p0, Lqn/t;->c:Lqn/b0;

    .line 28
    .line 29
    if-nez v4, :cond_1

    .line 30
    .line 31
    move v4, v3

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 34
    .line 35
    .line 36
    move-result v4

    .line 37
    :goto_1
    xor-int/2addr v0, v4

    .line 38
    mul-int/2addr v0, v1

    .line 39
    iget-wide v4, p0, Lqn/t;->d:J

    .line 40
    .line 41
    ushr-long v6, v4, v2

    .line 42
    .line 43
    xor-long/2addr v4, v6

    .line 44
    long-to-int v4, v4

    .line 45
    xor-int/2addr v0, v4

    .line 46
    mul-int/2addr v0, v1

    .line 47
    iget-object v4, p0, Lqn/t;->e:[B

    .line 48
    .line 49
    invoke-static {v4}, Ljava/util/Arrays;->hashCode([B)I

    .line 50
    .line 51
    .line 52
    move-result v4

    .line 53
    xor-int/2addr v0, v4

    .line 54
    mul-int/2addr v0, v1

    .line 55
    iget-object v4, p0, Lqn/t;->f:Ljava/lang/String;

    .line 56
    .line 57
    if-nez v4, :cond_2

    .line 58
    .line 59
    move v4, v3

    .line 60
    goto :goto_2

    .line 61
    :cond_2
    invoke-virtual {v4}, Ljava/lang/String;->hashCode()I

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    :goto_2
    xor-int/2addr v0, v4

    .line 66
    mul-int/2addr v0, v1

    .line 67
    iget-wide v4, p0, Lqn/t;->g:J

    .line 68
    .line 69
    ushr-long v6, v4, v2

    .line 70
    .line 71
    xor-long/2addr v4, v6

    .line 72
    long-to-int v2, v4

    .line 73
    xor-int/2addr v0, v2

    .line 74
    mul-int/2addr v0, v1

    .line 75
    iget-object v2, p0, Lqn/t;->h:Lqn/j0;

    .line 76
    .line 77
    if-nez v2, :cond_3

    .line 78
    .line 79
    move v2, v3

    .line 80
    goto :goto_3

    .line 81
    :cond_3
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 82
    .line 83
    .line 84
    move-result v2

    .line 85
    :goto_3
    xor-int/2addr v0, v2

    .line 86
    mul-int/2addr v0, v1

    .line 87
    iget-object p0, p0, Lqn/t;->i:Lqn/c0;

    .line 88
    .line 89
    if-nez p0, :cond_4

    .line 90
    .line 91
    goto :goto_4

    .line 92
    :cond_4
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 93
    .line 94
    .line 95
    move-result v3

    .line 96
    :goto_4
    xor-int p0, v0, v3

    .line 97
    .line 98
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "LogEvent{eventTimeMs="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-wide v1, p0, Lqn/t;->a:J

    .line 9
    .line 10
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", eventCode="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lqn/t;->b:Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", complianceData="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lqn/t;->c:Lqn/b0;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", eventUptimeMs="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-wide v1, p0, Lqn/t;->d:J

    .line 39
    .line 40
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", sourceExtension="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lqn/t;->e:[B

    .line 49
    .line 50
    invoke-static {v1}, Ljava/util/Arrays;->toString([B)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    const-string v1, ", sourceExtensionJsonProto3="

    .line 58
    .line 59
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    iget-object v1, p0, Lqn/t;->f:Ljava/lang/String;

    .line 63
    .line 64
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    const-string v1, ", timezoneOffsetSeconds="

    .line 68
    .line 69
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    iget-wide v1, p0, Lqn/t;->g:J

    .line 73
    .line 74
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    const-string v1, ", networkConnectionInfo="

    .line 78
    .line 79
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    iget-object v1, p0, Lqn/t;->h:Lqn/j0;

    .line 83
    .line 84
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    const-string v1, ", experimentIds="

    .line 88
    .line 89
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    iget-object p0, p0, Lqn/t;->i:Lqn/c0;

    .line 93
    .line 94
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    const-string p0, "}"

    .line 98
    .line 99
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    return-object p0
.end method
