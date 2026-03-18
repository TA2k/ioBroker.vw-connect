.class public final Lh71/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:F

.field public final b:F

.field public final c:F

.field public final d:F

.field public final e:F

.field public final f:F

.field public final g:F

.field public final h:F

.field public final i:F

.field public final j:F


# direct methods
.method public constructor <init>(FFFFFFFFFF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lh71/t;->a:F

    .line 5
    .line 6
    iput p2, p0, Lh71/t;->b:F

    .line 7
    .line 8
    iput p3, p0, Lh71/t;->c:F

    .line 9
    .line 10
    iput p4, p0, Lh71/t;->d:F

    .line 11
    .line 12
    iput p5, p0, Lh71/t;->e:F

    .line 13
    .line 14
    iput p6, p0, Lh71/t;->f:F

    .line 15
    .line 16
    iput p7, p0, Lh71/t;->g:F

    .line 17
    .line 18
    iput p8, p0, Lh71/t;->h:F

    .line 19
    .line 20
    iput p9, p0, Lh71/t;->i:F

    .line 21
    .line 22
    iput p10, p0, Lh71/t;->j:F

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto/16 :goto_1

    .line 4
    .line 5
    :cond_0
    instance-of v0, p1, Lh71/t;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    goto/16 :goto_0

    .line 10
    .line 11
    :cond_1
    check-cast p1, Lh71/t;

    .line 12
    .line 13
    iget v0, p0, Lh71/t;->a:F

    .line 14
    .line 15
    iget v1, p1, Lh71/t;->a:F

    .line 16
    .line 17
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_2

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_2
    iget v0, p0, Lh71/t;->b:F

    .line 25
    .line 26
    iget v1, p1, Lh71/t;->b:F

    .line 27
    .line 28
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-nez v0, :cond_3

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_3
    iget v0, p0, Lh71/t;->c:F

    .line 36
    .line 37
    iget v1, p1, Lh71/t;->c:F

    .line 38
    .line 39
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-nez v0, :cond_4

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_4
    iget v0, p0, Lh71/t;->d:F

    .line 47
    .line 48
    iget v1, p1, Lh71/t;->d:F

    .line 49
    .line 50
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-nez v0, :cond_5

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_5
    iget v0, p0, Lh71/t;->e:F

    .line 58
    .line 59
    iget v1, p1, Lh71/t;->e:F

    .line 60
    .line 61
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    if-nez v0, :cond_6

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_6
    iget v0, p0, Lh71/t;->f:F

    .line 69
    .line 70
    iget v1, p1, Lh71/t;->f:F

    .line 71
    .line 72
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    if-nez v0, :cond_7

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_7
    iget v0, p0, Lh71/t;->g:F

    .line 80
    .line 81
    iget v1, p1, Lh71/t;->g:F

    .line 82
    .line 83
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 84
    .line 85
    .line 86
    move-result v0

    .line 87
    if-nez v0, :cond_8

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_8
    iget v0, p0, Lh71/t;->h:F

    .line 91
    .line 92
    iget v1, p1, Lh71/t;->h:F

    .line 93
    .line 94
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 95
    .line 96
    .line 97
    move-result v0

    .line 98
    if-nez v0, :cond_9

    .line 99
    .line 100
    goto :goto_0

    .line 101
    :cond_9
    iget v0, p0, Lh71/t;->i:F

    .line 102
    .line 103
    iget v1, p1, Lh71/t;->i:F

    .line 104
    .line 105
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 106
    .line 107
    .line 108
    move-result v0

    .line 109
    if-nez v0, :cond_a

    .line 110
    .line 111
    goto :goto_0

    .line 112
    :cond_a
    iget p0, p0, Lh71/t;->j:F

    .line 113
    .line 114
    iget p1, p1, Lh71/t;->j:F

    .line 115
    .line 116
    invoke-static {p0, p1}, Lt4/f;->a(FF)Z

    .line 117
    .line 118
    .line 119
    move-result p0

    .line 120
    if-nez p0, :cond_b

    .line 121
    .line 122
    :goto_0
    const/4 p0, 0x0

    .line 123
    return p0

    .line 124
    :cond_b
    :goto_1
    const/4 p0, 0x1

    .line 125
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lh71/t;->a:F

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Float;->hashCode(F)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget v2, p0, Lh71/t;->b:F

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget v2, p0, Lh71/t;->c:F

    .line 17
    .line 18
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget v2, p0, Lh71/t;->d:F

    .line 23
    .line 24
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget v2, p0, Lh71/t;->e:F

    .line 29
    .line 30
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget v2, p0, Lh71/t;->f:F

    .line 35
    .line 36
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget v2, p0, Lh71/t;->g:F

    .line 41
    .line 42
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget v2, p0, Lh71/t;->h:F

    .line 47
    .line 48
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget v2, p0, Lh71/t;->i:F

    .line 53
    .line 54
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    iget p0, p0, Lh71/t;->j:F

    .line 59
    .line 60
    invoke-static {p0}, Ljava/lang/Float;->hashCode(F)I

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    add-int/2addr p0, v0

    .line 65
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 12

    .line 1
    iget v0, p0, Lh71/t;->a:F

    .line 2
    .line 3
    invoke-static {v0}, Lt4/f;->b(F)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget v1, p0, Lh71/t;->b:F

    .line 8
    .line 9
    invoke-static {v1}, Lt4/f;->b(F)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iget v2, p0, Lh71/t;->c:F

    .line 14
    .line 15
    invoke-static {v2}, Lt4/f;->b(F)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    iget v3, p0, Lh71/t;->d:F

    .line 20
    .line 21
    invoke-static {v3}, Lt4/f;->b(F)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    iget v4, p0, Lh71/t;->e:F

    .line 26
    .line 27
    invoke-static {v4}, Lt4/f;->b(F)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    iget v5, p0, Lh71/t;->f:F

    .line 32
    .line 33
    invoke-static {v5}, Lt4/f;->b(F)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v5

    .line 37
    iget v6, p0, Lh71/t;->g:F

    .line 38
    .line 39
    invoke-static {v6}, Lt4/f;->b(F)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v6

    .line 43
    iget v7, p0, Lh71/t;->h:F

    .line 44
    .line 45
    invoke-static {v7}, Lt4/f;->b(F)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v7

    .line 49
    iget v8, p0, Lh71/t;->i:F

    .line 50
    .line 51
    invoke-static {v8}, Lt4/f;->b(F)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v8

    .line 55
    iget p0, p0, Lh71/t;->j:F

    .line 56
    .line 57
    invoke-static {p0}, Lt4/f;->b(F)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    const-string v9, ", xxs="

    .line 62
    .line 63
    const-string v10, ", xs="

    .line 64
    .line 65
    const-string v11, "RpaSpacings(xxxs="

    .line 66
    .line 67
    invoke-static {v11, v0, v9, v1, v10}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    const-string v1, ", s="

    .line 72
    .line 73
    const-string v9, ", m="

    .line 74
    .line 75
    invoke-static {v0, v2, v1, v3, v9}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    const-string v1, ", l="

    .line 79
    .line 80
    const-string v2, ", xl="

    .line 81
    .line 82
    invoke-static {v0, v4, v1, v5, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    const-string v1, ", xxl="

    .line 86
    .line 87
    const-string v2, ", xxxl="

    .line 88
    .line 89
    invoke-static {v0, v6, v1, v7, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    const-string v1, ", doublexxxl="

    .line 93
    .line 94
    const-string v2, ")"

    .line 95
    .line 96
    invoke-static {v0, v8, v1, p0, v2}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    return-object p0
.end method
