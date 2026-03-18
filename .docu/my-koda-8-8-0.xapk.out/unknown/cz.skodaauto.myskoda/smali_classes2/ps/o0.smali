.class public final Lps/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:J

.field public b:Ljava/lang/String;

.field public c:Lps/d2;

.field public d:Lps/e2;

.field public e:Lps/f2;

.field public f:Lps/i2;

.field public g:B


# virtual methods
.method public final a()Lps/p0;
    .locals 10

    .line 1
    iget-byte v0, p0, Lps/o0;->g:B

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-ne v0, v1, :cond_1

    .line 5
    .line 6
    iget-object v5, p0, Lps/o0;->b:Ljava/lang/String;

    .line 7
    .line 8
    if-eqz v5, :cond_1

    .line 9
    .line 10
    iget-object v6, p0, Lps/o0;->c:Lps/d2;

    .line 11
    .line 12
    if-eqz v6, :cond_1

    .line 13
    .line 14
    iget-object v7, p0, Lps/o0;->d:Lps/e2;

    .line 15
    .line 16
    if-nez v7, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    new-instance v2, Lps/p0;

    .line 20
    .line 21
    iget-wide v3, p0, Lps/o0;->a:J

    .line 22
    .line 23
    iget-object v8, p0, Lps/o0;->e:Lps/f2;

    .line 24
    .line 25
    iget-object v9, p0, Lps/o0;->f:Lps/i2;

    .line 26
    .line 27
    invoke-direct/range {v2 .. v9}, Lps/p0;-><init>(JLjava/lang/String;Lps/d2;Lps/e2;Lps/f2;Lps/i2;)V

    .line 28
    .line 29
    .line 30
    return-object v2

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
    iget-byte v2, p0, Lps/o0;->g:B

    .line 37
    .line 38
    and-int/2addr v1, v2

    .line 39
    if-nez v1, :cond_2

    .line 40
    .line 41
    const-string v1, " timestamp"

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    :cond_2
    iget-object v1, p0, Lps/o0;->b:Ljava/lang/String;

    .line 47
    .line 48
    if-nez v1, :cond_3

    .line 49
    .line 50
    const-string v1, " type"

    .line 51
    .line 52
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    :cond_3
    iget-object v1, p0, Lps/o0;->c:Lps/d2;

    .line 56
    .line 57
    if-nez v1, :cond_4

    .line 58
    .line 59
    const-string v1, " app"

    .line 60
    .line 61
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    :cond_4
    iget-object p0, p0, Lps/o0;->d:Lps/e2;

    .line 65
    .line 66
    if-nez p0, :cond_5

    .line 67
    .line 68
    const-string p0, " device"

    .line 69
    .line 70
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 74
    .line 75
    const-string v1, "Missing required properties:"

    .line 76
    .line 77
    invoke-static {v1, v0}, Lkx/a;->j(Ljava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    throw p0
.end method
