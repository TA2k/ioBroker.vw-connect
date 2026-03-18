.class final Lcom/squareup/moshi/JsonValueWriter;
.super Lcom/squareup/moshi/JsonWriter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public m:[Ljava/lang/Object;

.field public n:Ljava/lang/String;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/squareup/moshi/JsonWriter;-><init>()V

    .line 2
    .line 3
    .line 4
    const/16 v0, 0x20

    .line 5
    .line 6
    new-array v0, v0, [Ljava/lang/Object;

    .line 7
    .line 8
    iput-object v0, p0, Lcom/squareup/moshi/JsonValueWriter;->m:[Ljava/lang/Object;

    .line 9
    .line 10
    const/4 v0, 0x6

    .line 11
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonWriter;->B(I)V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final H(D)Lcom/squareup/moshi/JsonWriter;
    .locals 2

    .line 1
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->i:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    invoke-static {p1, p2}, Ljava/lang/Double;->isNaN(D)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    const-wide/high16 v0, -0x10000000000000L    # Double.NEGATIVE_INFINITY

    .line 12
    .line 13
    cmpl-double v0, p1, v0

    .line 14
    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    const-wide/high16 v0, 0x7ff0000000000000L    # Double.POSITIVE_INFINITY

    .line 18
    .line 19
    cmpl-double v0, p1, v0

    .line 20
    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 25
    .line 26
    new-instance v0, Ljava/lang/StringBuilder;

    .line 27
    .line 28
    const-string v1, "Numeric values must be finite, but was "

    .line 29
    .line 30
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0, p1, p2}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_1
    :goto_0
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 45
    .line 46
    if-eqz v0, :cond_2

    .line 47
    .line 48
    const/4 v0, 0x0

    .line 49
    iput-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 50
    .line 51
    invoke-static {p1, p2}, Ljava/lang/Double;->toString(D)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonValueWriter;->j(Ljava/lang/String;)Lcom/squareup/moshi/JsonWriter;

    .line 56
    .line 57
    .line 58
    return-object p0

    .line 59
    :cond_2
    invoke-static {p1, p2}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonValueWriter;->W(Ljava/io/Serializable;)V

    .line 64
    .line 65
    .line 66
    iget-object p1, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 67
    .line 68
    iget p2, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 69
    .line 70
    add-int/lit8 p2, p2, -0x1

    .line 71
    .line 72
    aget v0, p1, p2

    .line 73
    .line 74
    add-int/lit8 v0, v0, 0x1

    .line 75
    .line 76
    aput v0, p1, p2

    .line 77
    .line 78
    return-object p0
.end method

.method public final M(J)Lcom/squareup/moshi/JsonWriter;
    .locals 1

    .line 1
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    iput-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 7
    .line 8
    invoke-static {p1, p2}, Ljava/lang/Long;->toString(J)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonValueWriter;->j(Ljava/lang/String;)Lcom/squareup/moshi/JsonWriter;

    .line 13
    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonValueWriter;->W(Ljava/io/Serializable;)V

    .line 21
    .line 22
    .line 23
    iget-object p1, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 24
    .line 25
    iget p2, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 26
    .line 27
    add-int/lit8 p2, p2, -0x1

    .line 28
    .line 29
    aget v0, p1, p2

    .line 30
    .line 31
    add-int/lit8 v0, v0, 0x1

    .line 32
    .line 33
    aput v0, p1, p2

    .line 34
    .line 35
    return-object p0
.end method

.method public final T(Ljava/lang/Float;)Lcom/squareup/moshi/JsonWriter;
    .locals 2

    .line 1
    if-nez p1, :cond_2

    .line 2
    .line 3
    if-nez p1, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonValueWriter;->k()Lcom/squareup/moshi/JsonWriter;

    .line 6
    .line 7
    .line 8
    return-object p0

    .line 9
    :cond_0
    new-instance v0, Ljava/math/BigDecimal;

    .line 10
    .line 11
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-direct {v0, p1}, Ljava/math/BigDecimal;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget-boolean p1, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 19
    .line 20
    if-eqz p1, :cond_1

    .line 21
    .line 22
    const/4 p1, 0x0

    .line 23
    iput-boolean p1, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/math/BigDecimal;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonValueWriter;->j(Ljava/lang/String;)Lcom/squareup/moshi/JsonWriter;

    .line 30
    .line 31
    .line 32
    return-object p0

    .line 33
    :cond_1
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonValueWriter;->W(Ljava/io/Serializable;)V

    .line 34
    .line 35
    .line 36
    iget-object p1, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 37
    .line 38
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 39
    .line 40
    add-int/lit8 v0, v0, -0x1

    .line 41
    .line 42
    aget v1, p1, v0

    .line 43
    .line 44
    add-int/lit8 v1, v1, 0x1

    .line 45
    .line 46
    aput v1, p1, v0

    .line 47
    .line 48
    return-object p0

    .line 49
    :cond_2
    invoke-virtual {p1}, Ljava/lang/Number;->doubleValue()D

    .line 50
    .line 51
    .line 52
    move-result-wide v0

    .line 53
    invoke-virtual {p0, v0, v1}, Lcom/squareup/moshi/JsonValueWriter;->H(D)Lcom/squareup/moshi/JsonWriter;

    .line 54
    .line 55
    .line 56
    return-object p0
.end method

.method public final U(Ljava/lang/String;)Lcom/squareup/moshi/JsonWriter;
    .locals 2

    .line 1
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    iput-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonValueWriter;->j(Ljava/lang/String;)Lcom/squareup/moshi/JsonWriter;

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonValueWriter;->W(Ljava/io/Serializable;)V

    .line 13
    .line 14
    .line 15
    iget-object p1, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 16
    .line 17
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 18
    .line 19
    add-int/lit8 v0, v0, -0x1

    .line 20
    .line 21
    aget v1, p1, v0

    .line 22
    .line 23
    add-int/lit8 v1, v1, 0x1

    .line 24
    .line 25
    aput v1, p1, v0

    .line 26
    .line 27
    return-object p0
.end method

.method public final V(Z)Lcom/squareup/moshi/JsonWriter;
    .locals 2

    .line 1
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonValueWriter;->W(Ljava/io/Serializable;)V

    .line 10
    .line 11
    .line 12
    iget-object p1, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 13
    .line 14
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 15
    .line 16
    add-int/lit8 v0, v0, -0x1

    .line 17
    .line 18
    aget v1, p1, v0

    .line 19
    .line 20
    add-int/lit8 v1, v1, 0x1

    .line 21
    .line 22
    aput v1, p1, v0

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    new-instance v0, Ljava/lang/StringBuilder;

    .line 28
    .line 29
    const-string v1, "Boolean cannot be used as a map key in JSON at path "

    .line 30
    .line 31
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->h()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p1
.end method

.method public final W(Ljava/io/Serializable;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->q()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget v1, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    if-ne v1, v2, :cond_1

    .line 9
    .line 10
    const/4 v3, 0x6

    .line 11
    if-ne v0, v3, :cond_0

    .line 12
    .line 13
    iget-object v0, p0, Lcom/squareup/moshi/JsonWriter;->e:[I

    .line 14
    .line 15
    sub-int/2addr v1, v2

    .line 16
    const/4 v2, 0x7

    .line 17
    aput v2, v0, v1

    .line 18
    .line 19
    iget-object p0, p0, Lcom/squareup/moshi/JsonValueWriter;->m:[Ljava/lang/Object;

    .line 20
    .line 21
    aput-object p1, p0, v1

    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string p1, "JSON must have only one top-level value."

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :cond_1
    const/4 v3, 0x3

    .line 33
    if-ne v0, v3, :cond_5

    .line 34
    .line 35
    iget-object v3, p0, Lcom/squareup/moshi/JsonValueWriter;->n:Ljava/lang/String;

    .line 36
    .line 37
    if-eqz v3, :cond_5

    .line 38
    .line 39
    if-nez p1, :cond_2

    .line 40
    .line 41
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->j:Z

    .line 42
    .line 43
    if-eqz v0, :cond_3

    .line 44
    .line 45
    :cond_2
    iget-object v0, p0, Lcom/squareup/moshi/JsonValueWriter;->m:[Ljava/lang/Object;

    .line 46
    .line 47
    sub-int/2addr v1, v2

    .line 48
    aget-object v0, v0, v1

    .line 49
    .line 50
    check-cast v0, Ljava/util/Map;

    .line 51
    .line 52
    invoke-interface {v0, v3, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    if-nez v0, :cond_4

    .line 57
    .line 58
    :cond_3
    const/4 p1, 0x0

    .line 59
    iput-object p1, p0, Lcom/squareup/moshi/JsonValueWriter;->n:Ljava/lang/String;

    .line 60
    .line 61
    return-void

    .line 62
    :cond_4
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 63
    .line 64
    new-instance v2, Ljava/lang/StringBuilder;

    .line 65
    .line 66
    const-string v3, "Map key \'"

    .line 67
    .line 68
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    iget-object v3, p0, Lcom/squareup/moshi/JsonValueWriter;->n:Ljava/lang/String;

    .line 72
    .line 73
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    const-string v3, "\' has multiple values at path "

    .line 77
    .line 78
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->h()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    const-string p0, ": "

    .line 89
    .line 90
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    const-string p0, " and "

    .line 97
    .line 98
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    invoke-direct {v1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    throw v1

    .line 112
    :cond_5
    if-ne v0, v2, :cond_6

    .line 113
    .line 114
    iget-object p0, p0, Lcom/squareup/moshi/JsonValueWriter;->m:[Ljava/lang/Object;

    .line 115
    .line 116
    sub-int/2addr v1, v2

    .line 117
    aget-object p0, p0, v1

    .line 118
    .line 119
    check-cast p0, Ljava/util/List;

    .line 120
    .line 121
    invoke-interface {p0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    return-void

    .line 125
    :cond_6
    const/16 p0, 0x9

    .line 126
    .line 127
    if-ne v0, p0, :cond_7

    .line 128
    .line 129
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 130
    .line 131
    const-string p1, "Sink from valueSink() was not closed"

    .line 132
    .line 133
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    throw p0

    .line 137
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 138
    .line 139
    const-string p1, "Nesting problem."

    .line 140
    .line 141
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    throw p0
.end method

.method public final a()Lcom/squareup/moshi/JsonWriter;
    .locals 4

    .line 1
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 6
    .line 7
    iget v1, p0, Lcom/squareup/moshi/JsonWriter;->l:I

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    if-ne v0, v1, :cond_0

    .line 11
    .line 12
    iget-object v3, p0, Lcom/squareup/moshi/JsonWriter;->e:[I

    .line 13
    .line 14
    sub-int/2addr v0, v2

    .line 15
    aget v0, v3, v0

    .line 16
    .line 17
    if-ne v0, v2, :cond_0

    .line 18
    .line 19
    not-int v0, v1

    .line 20
    iput v0, p0, Lcom/squareup/moshi/JsonWriter;->l:I

    .line 21
    .line 22
    return-object p0

    .line 23
    :cond_0
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->d()V

    .line 24
    .line 25
    .line 26
    new-instance v0, Ljava/util/ArrayList;

    .line 27
    .line 28
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonValueWriter;->W(Ljava/io/Serializable;)V

    .line 32
    .line 33
    .line 34
    iget-object v1, p0, Lcom/squareup/moshi/JsonValueWriter;->m:[Ljava/lang/Object;

    .line 35
    .line 36
    iget v3, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 37
    .line 38
    aput-object v0, v1, v3

    .line 39
    .line 40
    iget-object v0, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 41
    .line 42
    const/4 v1, 0x0

    .line 43
    aput v1, v0, v3

    .line 44
    .line 45
    invoke-virtual {p0, v2}, Lcom/squareup/moshi/JsonWriter;->B(I)V

    .line 46
    .line 47
    .line 48
    return-object p0

    .line 49
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    new-instance v1, Ljava/lang/StringBuilder;

    .line 52
    .line 53
    const-string v2, "Array cannot be used as a map key in JSON at path "

    .line 54
    .line 55
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->h()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw v0
.end method

.method public final b()Lcom/squareup/moshi/JsonWriter;
    .locals 4

    .line 1
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 6
    .line 7
    iget v1, p0, Lcom/squareup/moshi/JsonWriter;->l:I

    .line 8
    .line 9
    const/4 v2, 0x3

    .line 10
    if-ne v0, v1, :cond_0

    .line 11
    .line 12
    iget-object v3, p0, Lcom/squareup/moshi/JsonWriter;->e:[I

    .line 13
    .line 14
    add-int/lit8 v0, v0, -0x1

    .line 15
    .line 16
    aget v0, v3, v0

    .line 17
    .line 18
    if-ne v0, v2, :cond_0

    .line 19
    .line 20
    not-int v0, v1

    .line 21
    iput v0, p0, Lcom/squareup/moshi/JsonWriter;->l:I

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_0
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->d()V

    .line 25
    .line 26
    .line 27
    new-instance v0, Lcom/squareup/moshi/LinkedHashTreeMap;

    .line 28
    .line 29
    invoke-direct {v0}, Lcom/squareup/moshi/LinkedHashTreeMap;-><init>()V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonValueWriter;->W(Ljava/io/Serializable;)V

    .line 33
    .line 34
    .line 35
    iget-object v1, p0, Lcom/squareup/moshi/JsonValueWriter;->m:[Ljava/lang/Object;

    .line 36
    .line 37
    iget v3, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 38
    .line 39
    aput-object v0, v1, v3

    .line 40
    .line 41
    invoke-virtual {p0, v2}, Lcom/squareup/moshi/JsonWriter;->B(I)V

    .line 42
    .line 43
    .line 44
    return-object p0

    .line 45
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    new-instance v1, Ljava/lang/StringBuilder;

    .line 48
    .line 49
    const-string v2, "Object cannot be used as a map key in JSON at path "

    .line 50
    .line 51
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->h()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw v0
.end method

.method public final close()V
    .locals 3

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-gt v0, v1, :cond_1

    .line 5
    .line 6
    if-ne v0, v1, :cond_0

    .line 7
    .line 8
    iget-object v2, p0, Lcom/squareup/moshi/JsonWriter;->e:[I

    .line 9
    .line 10
    sub-int/2addr v0, v1

    .line 11
    aget v0, v2, v0

    .line 12
    .line 13
    const/4 v1, 0x7

    .line 14
    if-ne v0, v1, :cond_1

    .line 15
    .line 16
    :cond_0
    const/4 v0, 0x0

    .line 17
    iput v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 18
    .line 19
    return-void

    .line 20
    :cond_1
    new-instance p0, Ljava/io/IOException;

    .line 21
    .line 22
    const-string v0, "Incomplete document"

    .line 23
    .line 24
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw p0
.end method

.method public final f()Lcom/squareup/moshi/JsonWriter;
    .locals 5

    .line 1
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->q()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    if-ne v0, v1, :cond_1

    .line 7
    .line 8
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 9
    .line 10
    iget v2, p0, Lcom/squareup/moshi/JsonWriter;->l:I

    .line 11
    .line 12
    not-int v3, v2

    .line 13
    if-ne v0, v3, :cond_0

    .line 14
    .line 15
    not-int v0, v2

    .line 16
    iput v0, p0, Lcom/squareup/moshi/JsonWriter;->l:I

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_0
    add-int/lit8 v2, v0, -0x1

    .line 20
    .line 21
    iput v2, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 22
    .line 23
    iget-object v3, p0, Lcom/squareup/moshi/JsonValueWriter;->m:[Ljava/lang/Object;

    .line 24
    .line 25
    const/4 v4, 0x0

    .line 26
    aput-object v4, v3, v2

    .line 27
    .line 28
    iget-object v2, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 29
    .line 30
    add-int/lit8 v0, v0, -0x2

    .line 31
    .line 32
    aget v3, v2, v0

    .line 33
    .line 34
    add-int/2addr v3, v1

    .line 35
    aput v3, v2, v0

    .line 36
    .line 37
    return-object p0

    .line 38
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 39
    .line 40
    const-string v0, "Nesting problem."

    .line 41
    .line 42
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw p0
.end method

.method public final flush()V
    .locals 1

    .line 1
    iget p0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 7
    .line 8
    const-string v0, "JsonWriter is closed."

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public final g()Lcom/squareup/moshi/JsonWriter;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->q()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x3

    .line 6
    if-ne v0, v1, :cond_2

    .line 7
    .line 8
    iget-object v0, p0, Lcom/squareup/moshi/JsonValueWriter;->n:Ljava/lang/String;

    .line 9
    .line 10
    if-nez v0, :cond_1

    .line 11
    .line 12
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 13
    .line 14
    iget v1, p0, Lcom/squareup/moshi/JsonWriter;->l:I

    .line 15
    .line 16
    not-int v2, v1

    .line 17
    if-ne v0, v2, :cond_0

    .line 18
    .line 19
    not-int v0, v1

    .line 20
    iput v0, p0, Lcom/squareup/moshi/JsonWriter;->l:I

    .line 21
    .line 22
    return-object p0

    .line 23
    :cond_0
    const/4 v1, 0x0

    .line 24
    iput-boolean v1, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 25
    .line 26
    add-int/lit8 v1, v0, -0x1

    .line 27
    .line 28
    iput v1, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 29
    .line 30
    iget-object v2, p0, Lcom/squareup/moshi/JsonValueWriter;->m:[Ljava/lang/Object;

    .line 31
    .line 32
    const/4 v3, 0x0

    .line 33
    aput-object v3, v2, v1

    .line 34
    .line 35
    iget-object v2, p0, Lcom/squareup/moshi/JsonWriter;->f:[Ljava/lang/String;

    .line 36
    .line 37
    aput-object v3, v2, v1

    .line 38
    .line 39
    iget-object v1, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 40
    .line 41
    add-int/lit8 v0, v0, -0x2

    .line 42
    .line 43
    aget v2, v1, v0

    .line 44
    .line 45
    add-int/lit8 v2, v2, 0x1

    .line 46
    .line 47
    aput v2, v1, v0

    .line 48
    .line 49
    return-object p0

    .line 50
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    new-instance v1, Ljava/lang/StringBuilder;

    .line 53
    .line 54
    const-string v2, "Dangling name: "

    .line 55
    .line 56
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    iget-object p0, p0, Lcom/squareup/moshi/JsonValueWriter;->n:Ljava/lang/String;

    .line 60
    .line 61
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    throw v0

    .line 72
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 73
    .line 74
    const-string v0, "Nesting problem."

    .line 75
    .line 76
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    throw p0
.end method

.method public final j(Ljava/lang/String;)Lcom/squareup/moshi/JsonWriter;
    .locals 2

    .line 1
    if-eqz p1, :cond_2

    .line 2
    .line 3
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 4
    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->q()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const/4 v1, 0x3

    .line 12
    if-ne v0, v1, :cond_0

    .line 13
    .line 14
    iget-object v0, p0, Lcom/squareup/moshi/JsonValueWriter;->n:Ljava/lang/String;

    .line 15
    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 19
    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    iput-object p1, p0, Lcom/squareup/moshi/JsonValueWriter;->n:Ljava/lang/String;

    .line 23
    .line 24
    iget-object v0, p0, Lcom/squareup/moshi/JsonWriter;->f:[Ljava/lang/String;

    .line 25
    .line 26
    iget v1, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 27
    .line 28
    add-int/lit8 v1, v1, -0x1

    .line 29
    .line 30
    aput-object p1, v0, v1

    .line 31
    .line 32
    return-object p0

    .line 33
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 34
    .line 35
    const-string p1, "Nesting problem."

    .line 36
    .line 37
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw p0

    .line 41
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 42
    .line 43
    const-string p1, "JsonWriter is closed."

    .line 44
    .line 45
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_2
    new-instance p0, Ljava/lang/NullPointerException;

    .line 50
    .line 51
    const-string p1, "name == null"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0
.end method

.method public final k()Lcom/squareup/moshi/JsonWriter;
    .locals 3

    .line 1
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonValueWriter;->W(Ljava/io/Serializable;)V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 10
    .line 11
    iget v1, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 12
    .line 13
    add-int/lit8 v1, v1, -0x1

    .line 14
    .line 15
    aget v2, v0, v1

    .line 16
    .line 17
    add-int/lit8 v2, v2, 0x1

    .line 18
    .line 19
    aput v2, v0, v1

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    new-instance v1, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    const-string v2, "null cannot be used as a map key in JSON at path "

    .line 27
    .line 28
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->h()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw v0
.end method
