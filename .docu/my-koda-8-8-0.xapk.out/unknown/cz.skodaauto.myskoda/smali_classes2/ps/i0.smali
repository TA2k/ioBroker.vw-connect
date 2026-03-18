.class public final Lps/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Ljava/lang/String;

.field public b:Ljava/lang/String;

.field public c:Ljava/lang/String;

.field public d:J

.field public e:Ljava/lang/Long;

.field public f:Z

.field public g:Lps/u1;

.field public h:Lps/l2;

.field public i:Lps/k2;

.field public j:Lps/v1;

.field public k:Ljava/util/List;

.field public l:I

.field public m:B


# virtual methods
.method public final a()Lps/j0;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-byte v1, v0, Lps/i0;->m:B

    .line 4
    .line 5
    const/4 v2, 0x7

    .line 6
    if-ne v1, v2, :cond_1

    .line 7
    .line 8
    iget-object v4, v0, Lps/i0;->a:Ljava/lang/String;

    .line 9
    .line 10
    if-eqz v4, :cond_1

    .line 11
    .line 12
    iget-object v5, v0, Lps/i0;->b:Ljava/lang/String;

    .line 13
    .line 14
    if-eqz v5, :cond_1

    .line 15
    .line 16
    iget-object v11, v0, Lps/i0;->g:Lps/u1;

    .line 17
    .line 18
    if-nez v11, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance v3, Lps/j0;

    .line 22
    .line 23
    iget-object v6, v0, Lps/i0;->c:Ljava/lang/String;

    .line 24
    .line 25
    iget-wide v7, v0, Lps/i0;->d:J

    .line 26
    .line 27
    iget-object v9, v0, Lps/i0;->e:Ljava/lang/Long;

    .line 28
    .line 29
    iget-boolean v10, v0, Lps/i0;->f:Z

    .line 30
    .line 31
    iget-object v12, v0, Lps/i0;->h:Lps/l2;

    .line 32
    .line 33
    iget-object v13, v0, Lps/i0;->i:Lps/k2;

    .line 34
    .line 35
    iget-object v14, v0, Lps/i0;->j:Lps/v1;

    .line 36
    .line 37
    iget-object v15, v0, Lps/i0;->k:Ljava/util/List;

    .line 38
    .line 39
    iget v0, v0, Lps/i0;->l:I

    .line 40
    .line 41
    move/from16 v16, v0

    .line 42
    .line 43
    invoke-direct/range {v3 .. v16}, Lps/j0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JLjava/lang/Long;ZLps/u1;Lps/l2;Lps/k2;Lps/v1;Ljava/util/List;I)V

    .line 44
    .line 45
    .line 46
    return-object v3

    .line 47
    :cond_1
    :goto_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 48
    .line 49
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 50
    .line 51
    .line 52
    iget-object v2, v0, Lps/i0;->a:Ljava/lang/String;

    .line 53
    .line 54
    if-nez v2, :cond_2

    .line 55
    .line 56
    const-string v2, " generator"

    .line 57
    .line 58
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    :cond_2
    iget-object v2, v0, Lps/i0;->b:Ljava/lang/String;

    .line 62
    .line 63
    if-nez v2, :cond_3

    .line 64
    .line 65
    const-string v2, " identifier"

    .line 66
    .line 67
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    :cond_3
    iget-byte v2, v0, Lps/i0;->m:B

    .line 71
    .line 72
    and-int/lit8 v2, v2, 0x1

    .line 73
    .line 74
    if-nez v2, :cond_4

    .line 75
    .line 76
    const-string v2, " startedAt"

    .line 77
    .line 78
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    :cond_4
    iget-byte v2, v0, Lps/i0;->m:B

    .line 82
    .line 83
    and-int/lit8 v2, v2, 0x2

    .line 84
    .line 85
    if-nez v2, :cond_5

    .line 86
    .line 87
    const-string v2, " crashed"

    .line 88
    .line 89
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    :cond_5
    iget-object v2, v0, Lps/i0;->g:Lps/u1;

    .line 93
    .line 94
    if-nez v2, :cond_6

    .line 95
    .line 96
    const-string v2, " app"

    .line 97
    .line 98
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    :cond_6
    iget-byte v0, v0, Lps/i0;->m:B

    .line 102
    .line 103
    and-int/lit8 v0, v0, 0x4

    .line 104
    .line 105
    if-nez v0, :cond_7

    .line 106
    .line 107
    const-string v0, " generatorType"

    .line 108
    .line 109
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 113
    .line 114
    const-string v2, "Missing required properties:"

    .line 115
    .line 116
    invoke-static {v2, v1}, Lkx/a;->j(Ljava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v1

    .line 120
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    throw v0
.end method
