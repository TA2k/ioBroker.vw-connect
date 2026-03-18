.class public final Lqa/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Z

.field public final d:I

.field public final e:Ljava/lang/String;

.field public final f:I

.field public final g:I


# direct methods
.method public constructor <init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V
    .locals 1

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "type"

    .line 7
    .line 8
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p3, p0, Lqa/h;->a:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p4, p0, Lqa/h;->b:Ljava/lang/String;

    .line 17
    .line 18
    iput-boolean p6, p0, Lqa/h;->c:Z

    .line 19
    .line 20
    iput p1, p0, Lqa/h;->d:I

    .line 21
    .line 22
    iput-object p5, p0, Lqa/h;->e:Ljava/lang/String;

    .line 23
    .line 24
    iput p2, p0, Lqa/h;->f:I

    .line 25
    .line 26
    sget-object p1, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 27
    .line 28
    invoke-virtual {p4, p1}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    const-string p2, "toUpperCase(...)"

    .line 33
    .line 34
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string p2, "INT"

    .line 38
    .line 39
    const/4 p3, 0x0

    .line 40
    invoke-static {p1, p2, p3}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 41
    .line 42
    .line 43
    move-result p2

    .line 44
    if-eqz p2, :cond_0

    .line 45
    .line 46
    const/4 p1, 0x3

    .line 47
    goto :goto_2

    .line 48
    :cond_0
    const-string p2, "CHAR"

    .line 49
    .line 50
    invoke-static {p1, p2, p3}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 51
    .line 52
    .line 53
    move-result p2

    .line 54
    if-nez p2, :cond_5

    .line 55
    .line 56
    const-string p2, "CLOB"

    .line 57
    .line 58
    invoke-static {p1, p2, p3}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 59
    .line 60
    .line 61
    move-result p2

    .line 62
    if-nez p2, :cond_5

    .line 63
    .line 64
    const-string p2, "TEXT"

    .line 65
    .line 66
    invoke-static {p1, p2, p3}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 67
    .line 68
    .line 69
    move-result p2

    .line 70
    if-eqz p2, :cond_1

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_1
    const-string p2, "BLOB"

    .line 74
    .line 75
    invoke-static {p1, p2, p3}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 76
    .line 77
    .line 78
    move-result p2

    .line 79
    if-eqz p2, :cond_2

    .line 80
    .line 81
    const/4 p1, 0x5

    .line 82
    goto :goto_2

    .line 83
    :cond_2
    const-string p2, "REAL"

    .line 84
    .line 85
    invoke-static {p1, p2, p3}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 86
    .line 87
    .line 88
    move-result p2

    .line 89
    if-nez p2, :cond_4

    .line 90
    .line 91
    const-string p2, "FLOA"

    .line 92
    .line 93
    invoke-static {p1, p2, p3}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 94
    .line 95
    .line 96
    move-result p2

    .line 97
    if-nez p2, :cond_4

    .line 98
    .line 99
    const-string p2, "DOUB"

    .line 100
    .line 101
    invoke-static {p1, p2, p3}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 102
    .line 103
    .line 104
    move-result p1

    .line 105
    if-eqz p1, :cond_3

    .line 106
    .line 107
    goto :goto_0

    .line 108
    :cond_3
    const/4 p1, 0x1

    .line 109
    goto :goto_2

    .line 110
    :cond_4
    :goto_0
    const/4 p1, 0x4

    .line 111
    goto :goto_2

    .line 112
    :cond_5
    :goto_1
    const/4 p1, 0x2

    .line 113
    :goto_2
    iput p1, p0, Lqa/h;->g:I

    .line 114
    .line 115
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 8

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    goto/16 :goto_2

    .line 5
    .line 6
    :cond_0
    instance-of v1, p1, Lqa/h;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    if-nez v1, :cond_1

    .line 10
    .line 11
    goto/16 :goto_3

    .line 12
    .line 13
    :cond_1
    iget v1, p0, Lqa/h;->d:I

    .line 14
    .line 15
    if-lez v1, :cond_2

    .line 16
    .line 17
    move v1, v0

    .line 18
    goto :goto_0

    .line 19
    :cond_2
    move v1, v2

    .line 20
    :goto_0
    check-cast p1, Lqa/h;

    .line 21
    .line 22
    iget v3, p1, Lqa/h;->f:I

    .line 23
    .line 24
    iget v4, p1, Lqa/h;->d:I

    .line 25
    .line 26
    if-lez v4, :cond_3

    .line 27
    .line 28
    move v4, v0

    .line 29
    goto :goto_1

    .line 30
    :cond_3
    move v4, v2

    .line 31
    :goto_1
    if-eq v1, v4, :cond_4

    .line 32
    .line 33
    goto :goto_3

    .line 34
    :cond_4
    iget-object v1, p0, Lqa/h;->a:Ljava/lang/String;

    .line 35
    .line 36
    iget-object v4, p1, Lqa/h;->a:Ljava/lang/String;

    .line 37
    .line 38
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-nez v1, :cond_5

    .line 43
    .line 44
    goto :goto_3

    .line 45
    :cond_5
    iget-boolean v1, p0, Lqa/h;->c:Z

    .line 46
    .line 47
    iget-boolean v4, p1, Lqa/h;->c:Z

    .line 48
    .line 49
    if-eq v1, v4, :cond_6

    .line 50
    .line 51
    goto :goto_3

    .line 52
    :cond_6
    iget-object v1, p1, Lqa/h;->e:Ljava/lang/String;

    .line 53
    .line 54
    const/4 v4, 0x2

    .line 55
    iget v5, p0, Lqa/h;->f:I

    .line 56
    .line 57
    iget-object v6, p0, Lqa/h;->e:Ljava/lang/String;

    .line 58
    .line 59
    if-ne v5, v0, :cond_7

    .line 60
    .line 61
    if-ne v3, v4, :cond_7

    .line 62
    .line 63
    if-eqz v6, :cond_7

    .line 64
    .line 65
    invoke-static {v6, v1}, Ljp/ef;->b(Ljava/lang/String;Ljava/lang/String;)Z

    .line 66
    .line 67
    .line 68
    move-result v7

    .line 69
    if-nez v7, :cond_7

    .line 70
    .line 71
    goto :goto_3

    .line 72
    :cond_7
    if-ne v5, v4, :cond_8

    .line 73
    .line 74
    if-ne v3, v0, :cond_8

    .line 75
    .line 76
    if-eqz v1, :cond_8

    .line 77
    .line 78
    invoke-static {v1, v6}, Ljp/ef;->b(Ljava/lang/String;Ljava/lang/String;)Z

    .line 79
    .line 80
    .line 81
    move-result v4

    .line 82
    if-nez v4, :cond_8

    .line 83
    .line 84
    goto :goto_3

    .line 85
    :cond_8
    if-eqz v5, :cond_a

    .line 86
    .line 87
    if-ne v5, v3, :cond_a

    .line 88
    .line 89
    if-eqz v6, :cond_9

    .line 90
    .line 91
    invoke-static {v6, v1}, Ljp/ef;->b(Ljava/lang/String;Ljava/lang/String;)Z

    .line 92
    .line 93
    .line 94
    move-result v1

    .line 95
    if-nez v1, :cond_a

    .line 96
    .line 97
    goto :goto_3

    .line 98
    :cond_9
    if-eqz v1, :cond_a

    .line 99
    .line 100
    goto :goto_3

    .line 101
    :cond_a
    iget p0, p0, Lqa/h;->g:I

    .line 102
    .line 103
    iget p1, p1, Lqa/h;->g:I

    .line 104
    .line 105
    if-ne p0, p1, :cond_b

    .line 106
    .line 107
    :goto_2
    return v0

    .line 108
    :cond_b
    :goto_3
    return v2
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lqa/h;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget v1, p0, Lqa/h;->g:I

    .line 10
    .line 11
    add-int/2addr v0, v1

    .line 12
    mul-int/lit8 v0, v0, 0x1f

    .line 13
    .line 14
    iget-boolean v1, p0, Lqa/h;->c:Z

    .line 15
    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    const/16 v1, 0x4cf

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/16 v1, 0x4d5

    .line 22
    .line 23
    :goto_0
    add-int/2addr v0, v1

    .line 24
    mul-int/lit8 v0, v0, 0x1f

    .line 25
    .line 26
    iget p0, p0, Lqa/h;->d:I

    .line 27
    .line 28
    add-int/2addr v0, p0

    .line 29
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "\n            |Column {\n            |   name = \'"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lqa/h;->a:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, "\',\n            |   type = \'"

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lqa/h;->b:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, "\',\n            |   affinity = \'"

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget v1, p0, Lqa/h;->g:I

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, "\',\n            |   notNull = \'"

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-boolean v1, p0, Lqa/h;->c:Z

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, "\',\n            |   primaryKeyPosition = \'"

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget v1, p0, Lqa/h;->d:I

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, "\',\n            |   defaultValue = \'"

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object p0, p0, Lqa/h;->e:Ljava/lang/String;

    .line 59
    .line 60
    if-nez p0, :cond_0

    .line 61
    .line 62
    const-string p0, "undefined"

    .line 63
    .line 64
    :cond_0
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    const-string p0, "\'\n            |}\n        "

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
    invoke-static {p0}, Lly0/q;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    const-string v0, "    "

    .line 81
    .line 82
    invoke-static {p0, v0}, Lly0/q;->d(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    return-object p0
.end method
