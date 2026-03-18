.class public final Ljt/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic h:I


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:I

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;

.field public final e:J

.field public final f:J

.field public final g:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    or-int/lit8 v0, v0, 0x2

    .line 3
    .line 4
    int-to-byte v0, v0

    .line 5
    or-int/lit8 v0, v0, 0x1

    .line 6
    .line 7
    int-to-byte v0, v0

    .line 8
    const/4 v1, 0x3

    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 15
    .line 16
    .line 17
    and-int/lit8 v2, v0, 0x1

    .line 18
    .line 19
    if-nez v2, :cond_1

    .line 20
    .line 21
    const-string v2, " expiresInSecs"

    .line 22
    .line 23
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    :cond_1
    and-int/lit8 v0, v0, 0x2

    .line 27
    .line 28
    if-nez v0, :cond_2

    .line 29
    .line 30
    const-string v0, " tokenCreationEpochInSecs"

    .line 31
    .line 32
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    :cond_2
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 36
    .line 37
    const-string v2, "Missing required properties:"

    .line 38
    .line 39
    invoke-static {v2, v1}, Lkx/a;->j(Ljava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw v0
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;JJLjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ljt/b;->a:Ljava/lang/String;

    .line 5
    .line 6
    iput p2, p0, Ljt/b;->b:I

    .line 7
    .line 8
    iput-object p3, p0, Ljt/b;->c:Ljava/lang/String;

    .line 9
    .line 10
    iput-object p4, p0, Ljt/b;->d:Ljava/lang/String;

    .line 11
    .line 12
    iput-wide p5, p0, Ljt/b;->e:J

    .line 13
    .line 14
    iput-wide p7, p0, Ljt/b;->f:J

    .line 15
    .line 16
    iput-object p9, p0, Ljt/b;->g:Ljava/lang/String;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final a()Ljt/a;
    .locals 3

    .line 1
    new-instance v0, Ljt/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Ljt/b;->a:Ljava/lang/String;

    .line 7
    .line 8
    iput-object v1, v0, Ljt/a;->a:Ljava/lang/String;

    .line 9
    .line 10
    iget v1, p0, Ljt/b;->b:I

    .line 11
    .line 12
    iput v1, v0, Ljt/a;->b:I

    .line 13
    .line 14
    iget-object v1, p0, Ljt/b;->c:Ljava/lang/String;

    .line 15
    .line 16
    iput-object v1, v0, Ljt/a;->c:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v1, p0, Ljt/b;->d:Ljava/lang/String;

    .line 19
    .line 20
    iput-object v1, v0, Ljt/a;->d:Ljava/lang/String;

    .line 21
    .line 22
    iget-wide v1, p0, Ljt/b;->e:J

    .line 23
    .line 24
    iput-wide v1, v0, Ljt/a;->e:J

    .line 25
    .line 26
    iget-wide v1, p0, Ljt/b;->f:J

    .line 27
    .line 28
    iput-wide v1, v0, Ljt/a;->f:J

    .line 29
    .line 30
    iget-object p0, p0, Ljt/b;->g:Ljava/lang/String;

    .line 31
    .line 32
    iput-object p0, v0, Ljt/a;->g:Ljava/lang/String;

    .line 33
    .line 34
    const/4 p0, 0x3

    .line 35
    iput-byte p0, v0, Ljt/a;->h:B

    .line 36
    .line 37
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    if-ne p1, p0, :cond_0

    .line 2
    .line 3
    goto :goto_3

    .line 4
    :cond_0
    instance-of v0, p1, Ljt/b;

    .line 5
    .line 6
    if-eqz v0, :cond_5

    .line 7
    .line 8
    check-cast p1, Ljt/b;

    .line 9
    .line 10
    iget-object v0, p1, Ljt/b;->g:Ljava/lang/String;

    .line 11
    .line 12
    iget-object v1, p1, Ljt/b;->d:Ljava/lang/String;

    .line 13
    .line 14
    iget-object v2, p1, Ljt/b;->c:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v3, p1, Ljt/b;->a:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v4, p0, Ljt/b;->a:Ljava/lang/String;

    .line 19
    .line 20
    if-nez v4, :cond_1

    .line 21
    .line 22
    if-nez v3, :cond_5

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    invoke-virtual {v4, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    if-eqz v3, :cond_5

    .line 30
    .line 31
    :goto_0
    iget v3, p0, Ljt/b;->b:I

    .line 32
    .line 33
    iget v4, p1, Ljt/b;->b:I

    .line 34
    .line 35
    invoke-static {v3, v4}, Lu/w;->a(II)Z

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    if-eqz v3, :cond_5

    .line 40
    .line 41
    iget-object v3, p0, Ljt/b;->c:Ljava/lang/String;

    .line 42
    .line 43
    if-nez v3, :cond_2

    .line 44
    .line 45
    if-nez v2, :cond_5

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_2
    invoke-virtual {v3, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    if-eqz v2, :cond_5

    .line 53
    .line 54
    :goto_1
    iget-object v2, p0, Ljt/b;->d:Ljava/lang/String;

    .line 55
    .line 56
    if-nez v2, :cond_3

    .line 57
    .line 58
    if-nez v1, :cond_5

    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_3
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-eqz v1, :cond_5

    .line 66
    .line 67
    :goto_2
    iget-wide v1, p0, Ljt/b;->e:J

    .line 68
    .line 69
    iget-wide v3, p1, Ljt/b;->e:J

    .line 70
    .line 71
    cmp-long v1, v1, v3

    .line 72
    .line 73
    if-nez v1, :cond_5

    .line 74
    .line 75
    iget-wide v1, p0, Ljt/b;->f:J

    .line 76
    .line 77
    iget-wide v3, p1, Ljt/b;->f:J

    .line 78
    .line 79
    cmp-long p1, v1, v3

    .line 80
    .line 81
    if-nez p1, :cond_5

    .line 82
    .line 83
    iget-object p0, p0, Ljt/b;->g:Ljava/lang/String;

    .line 84
    .line 85
    if-nez p0, :cond_4

    .line 86
    .line 87
    if-nez v0, :cond_5

    .line 88
    .line 89
    goto :goto_3

    .line 90
    :cond_4
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result p0

    .line 94
    if-eqz p0, :cond_5

    .line 95
    .line 96
    :goto_3
    const/4 p0, 0x1

    .line 97
    return p0

    .line 98
    :cond_5
    const/4 p0, 0x0

    .line 99
    return p0
.end method

.method public final hashCode()I
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Ljt/b;->a:Ljava/lang/String;

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
    iget v3, p0, Ljt/b;->b:I

    .line 18
    .line 19
    invoke-static {v3}, Lu/w;->o(I)I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    xor-int/2addr v1, v3

    .line 24
    mul-int/2addr v1, v2

    .line 25
    iget-object v3, p0, Ljt/b;->c:Ljava/lang/String;

    .line 26
    .line 27
    if-nez v3, :cond_1

    .line 28
    .line 29
    move v3, v0

    .line 30
    goto :goto_1

    .line 31
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    :goto_1
    xor-int/2addr v1, v3

    .line 36
    mul-int/2addr v1, v2

    .line 37
    iget-object v3, p0, Ljt/b;->d:Ljava/lang/String;

    .line 38
    .line 39
    if-nez v3, :cond_2

    .line 40
    .line 41
    move v3, v0

    .line 42
    goto :goto_2

    .line 43
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    :goto_2
    xor-int/2addr v1, v3

    .line 48
    mul-int/2addr v1, v2

    .line 49
    iget-wide v3, p0, Ljt/b;->e:J

    .line 50
    .line 51
    const/16 v5, 0x20

    .line 52
    .line 53
    ushr-long v6, v3, v5

    .line 54
    .line 55
    xor-long/2addr v3, v6

    .line 56
    long-to-int v3, v3

    .line 57
    xor-int/2addr v1, v3

    .line 58
    mul-int/2addr v1, v2

    .line 59
    iget-wide v3, p0, Ljt/b;->f:J

    .line 60
    .line 61
    ushr-long v5, v3, v5

    .line 62
    .line 63
    xor-long/2addr v3, v5

    .line 64
    long-to-int v3, v3

    .line 65
    xor-int/2addr v1, v3

    .line 66
    mul-int/2addr v1, v2

    .line 67
    iget-object p0, p0, Ljt/b;->g:Ljava/lang/String;

    .line 68
    .line 69
    if-nez p0, :cond_3

    .line 70
    .line 71
    goto :goto_3

    .line 72
    :cond_3
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    :goto_3
    xor-int p0, v1, v0

    .line 77
    .line 78
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "PersistedInstallationEntry{firebaseInstallationId="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Ljt/b;->a:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", registrationStatus="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    const/4 v1, 0x1

    .line 19
    iget v2, p0, Ljt/b;->b:I

    .line 20
    .line 21
    if-eq v2, v1, :cond_4

    .line 22
    .line 23
    const/4 v1, 0x2

    .line 24
    if-eq v2, v1, :cond_3

    .line 25
    .line 26
    const/4 v1, 0x3

    .line 27
    if-eq v2, v1, :cond_2

    .line 28
    .line 29
    const/4 v1, 0x4

    .line 30
    if-eq v2, v1, :cond_1

    .line 31
    .line 32
    const/4 v1, 0x5

    .line 33
    if-eq v2, v1, :cond_0

    .line 34
    .line 35
    const-string v1, "null"

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const-string v1, "REGISTER_ERROR"

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    const-string v1, "REGISTERED"

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    const-string v1, "UNREGISTERED"

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_3
    const-string v1, "NOT_GENERATED"

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_4
    const-string v1, "ATTEMPT_MIGRATION"

    .line 51
    .line 52
    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const-string v1, ", authToken="

    .line 56
    .line 57
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    iget-object v1, p0, Ljt/b;->c:Ljava/lang/String;

    .line 61
    .line 62
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    const-string v1, ", refreshToken="

    .line 66
    .line 67
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    iget-object v1, p0, Ljt/b;->d:Ljava/lang/String;

    .line 71
    .line 72
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    const-string v1, ", expiresInSecs="

    .line 76
    .line 77
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    iget-wide v1, p0, Ljt/b;->e:J

    .line 81
    .line 82
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    const-string v1, ", tokenCreationEpochInSecs="

    .line 86
    .line 87
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    iget-wide v1, p0, Ljt/b;->f:J

    .line 91
    .line 92
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const-string v1, ", fisError="

    .line 96
    .line 97
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    iget-object p0, p0, Ljt/b;->g:Ljava/lang/String;

    .line 101
    .line 102
    const-string v1, "}"

    .line 103
    .line 104
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    return-object p0
.end method
