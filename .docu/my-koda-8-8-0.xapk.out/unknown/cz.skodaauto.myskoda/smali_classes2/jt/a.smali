.class public final Ljt/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Ljava/lang/String;

.field public b:I

.field public c:Ljava/lang/String;

.field public d:Ljava/lang/String;

.field public e:J

.field public f:J

.field public g:Ljava/lang/String;

.field public h:B


# virtual methods
.method public final a()Ljt/b;
    .locals 11

    .line 1
    iget-byte v0, p0, Ljt/a;->h:B

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    if-ne v0, v1, :cond_1

    .line 5
    .line 6
    iget v0, p0, Ljt/a;->b:I

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    new-instance v1, Ljt/b;

    .line 12
    .line 13
    iget-object v2, p0, Ljt/a;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget v3, p0, Ljt/a;->b:I

    .line 16
    .line 17
    iget-object v4, p0, Ljt/a;->c:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v5, p0, Ljt/a;->d:Ljava/lang/String;

    .line 20
    .line 21
    iget-wide v6, p0, Ljt/a;->e:J

    .line 22
    .line 23
    iget-wide v8, p0, Ljt/a;->f:J

    .line 24
    .line 25
    iget-object v10, p0, Ljt/a;->g:Ljava/lang/String;

    .line 26
    .line 27
    invoke-direct/range {v1 .. v10}, Ljt/b;-><init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;JJLjava/lang/String;)V

    .line 28
    .line 29
    .line 30
    return-object v1

    .line 31
    :cond_1
    :goto_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 32
    .line 33
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 34
    .line 35
    .line 36
    iget v1, p0, Ljt/a;->b:I

    .line 37
    .line 38
    if-nez v1, :cond_2

    .line 39
    .line 40
    const-string v1, " registrationStatus"

    .line 41
    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    :cond_2
    iget-byte v1, p0, Ljt/a;->h:B

    .line 46
    .line 47
    and-int/lit8 v1, v1, 0x1

    .line 48
    .line 49
    if-nez v1, :cond_3

    .line 50
    .line 51
    const-string v1, " expiresInSecs"

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    :cond_3
    iget-byte p0, p0, Ljt/a;->h:B

    .line 57
    .line 58
    and-int/lit8 p0, p0, 0x2

    .line 59
    .line 60
    if-nez p0, :cond_4

    .line 61
    .line 62
    const-string p0, " tokenCreationEpochInSecs"

    .line 63
    .line 64
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 68
    .line 69
    const-string v1, "Missing required properties:"

    .line 70
    .line 71
    invoke-static {v1, v0}, Lkx/a;->j(Ljava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    throw p0
.end method
