.class public final Lcom/squareup/moshi/internal/Util$ParameterizedTypeImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/reflect/ParameterizedType;


# instance fields
.field public final d:Ljava/lang/reflect/Type;

.field public final e:Ljava/lang/reflect/Type;

.field public final f:[Ljava/lang/reflect/Type;


# direct methods
.method public varargs constructor <init>(Ljava/lang/reflect/Type;Ljava/lang/reflect/Type;[Ljava/lang/reflect/Type;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    instance-of v0, p2, Ljava/lang/Class;

    .line 5
    .line 6
    if-eqz v0, :cond_3

    .line 7
    .line 8
    move-object v0, p2

    .line 9
    check-cast v0, Ljava/lang/Class;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Class;->getEnclosingClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, "unexpected owner type for "

    .line 16
    .line 17
    if-eqz p1, :cond_1

    .line 18
    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    invoke-static {p1}, Lcom/squareup/moshi/Types;->c(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    if-ne v2, v0, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 29
    .line 30
    new-instance p3, Ljava/lang/StringBuilder;

    .line 31
    .line 32
    invoke-direct {p3, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    const-string p2, ": "

    .line 39
    .line 40
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_1
    if-nez v0, :cond_2

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 58
    .line 59
    new-instance p1, Ljava/lang/StringBuilder;

    .line 60
    .line 61
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    const-string p2, ": null"

    .line 68
    .line 69
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    throw p0

    .line 80
    :cond_3
    :goto_0
    if-nez p1, :cond_4

    .line 81
    .line 82
    const/4 p1, 0x0

    .line 83
    goto :goto_1

    .line 84
    :cond_4
    invoke-static {p1}, Lax/b;->a(Ljava/lang/reflect/Type;)Ljava/lang/reflect/Type;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    :goto_1
    iput-object p1, p0, Lcom/squareup/moshi/internal/Util$ParameterizedTypeImpl;->d:Ljava/lang/reflect/Type;

    .line 89
    .line 90
    invoke-static {p2}, Lax/b;->a(Ljava/lang/reflect/Type;)Ljava/lang/reflect/Type;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    iput-object p1, p0, Lcom/squareup/moshi/internal/Util$ParameterizedTypeImpl;->e:Ljava/lang/reflect/Type;

    .line 95
    .line 96
    invoke-virtual {p3}, [Ljava/lang/reflect/Type;->clone()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    check-cast p1, [Ljava/lang/reflect/Type;

    .line 101
    .line 102
    iput-object p1, p0, Lcom/squareup/moshi/internal/Util$ParameterizedTypeImpl;->f:[Ljava/lang/reflect/Type;

    .line 103
    .line 104
    const/4 p1, 0x0

    .line 105
    :goto_2
    iget-object p2, p0, Lcom/squareup/moshi/internal/Util$ParameterizedTypeImpl;->f:[Ljava/lang/reflect/Type;

    .line 106
    .line 107
    array-length p3, p2

    .line 108
    if-ge p1, p3, :cond_5

    .line 109
    .line 110
    aget-object p2, p2, p1

    .line 111
    .line 112
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 113
    .line 114
    .line 115
    iget-object p2, p0, Lcom/squareup/moshi/internal/Util$ParameterizedTypeImpl;->f:[Ljava/lang/reflect/Type;

    .line 116
    .line 117
    aget-object p2, p2, p1

    .line 118
    .line 119
    invoke-static {p2}, Lax/b;->b(Ljava/lang/reflect/Type;)V

    .line 120
    .line 121
    .line 122
    iget-object p2, p0, Lcom/squareup/moshi/internal/Util$ParameterizedTypeImpl;->f:[Ljava/lang/reflect/Type;

    .line 123
    .line 124
    aget-object p3, p2, p1

    .line 125
    .line 126
    invoke-static {p3}, Lax/b;->a(Ljava/lang/reflect/Type;)Ljava/lang/reflect/Type;

    .line 127
    .line 128
    .line 129
    move-result-object p3

    .line 130
    aput-object p3, p2, p1

    .line 131
    .line 132
    add-int/lit8 p1, p1, 0x1

    .line 133
    .line 134
    goto :goto_2

    .line 135
    :cond_5
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Ljava/lang/reflect/ParameterizedType;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Ljava/lang/reflect/ParameterizedType;

    .line 6
    .line 7
    invoke-static {p0, p1}, Lcom/squareup/moshi/Types;->b(Ljava/lang/reflect/Type;Ljava/lang/reflect/Type;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public final getActualTypeArguments()[Ljava/lang/reflect/Type;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/squareup/moshi/internal/Util$ParameterizedTypeImpl;->f:[Ljava/lang/reflect/Type;

    .line 2
    .line 3
    invoke-virtual {p0}, [Ljava/lang/reflect/Type;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, [Ljava/lang/reflect/Type;

    .line 8
    .line 9
    return-object p0
.end method

.method public final getOwnerType()Ljava/lang/reflect/Type;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/squareup/moshi/internal/Util$ParameterizedTypeImpl;->d:Ljava/lang/reflect/Type;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getRawType()Ljava/lang/reflect/Type;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/squareup/moshi/internal/Util$ParameterizedTypeImpl;->e:Ljava/lang/reflect/Type;

    .line 2
    .line 3
    return-object p0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/squareup/moshi/internal/Util$ParameterizedTypeImpl;->f:[Ljava/lang/reflect/Type;

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lcom/squareup/moshi/internal/Util$ParameterizedTypeImpl;->e:Ljava/lang/reflect/Type;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    xor-int/2addr v0, v1

    .line 14
    sget-object v1, Lax/b;->a:Ljava/util/Set;

    .line 15
    .line 16
    iget-object p0, p0, Lcom/squareup/moshi/internal/Util$ParameterizedTypeImpl;->d:Ljava/lang/reflect/Type;

    .line 17
    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    :goto_0
    xor-int/2addr p0, v0

    .line 27
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/squareup/moshi/internal/Util$ParameterizedTypeImpl;->f:[Ljava/lang/reflect/Type;

    .line 4
    .line 5
    array-length v2, v1

    .line 6
    const/4 v3, 0x1

    .line 7
    add-int/2addr v2, v3

    .line 8
    mul-int/lit8 v2, v2, 0x1e

    .line 9
    .line 10
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lcom/squareup/moshi/internal/Util$ParameterizedTypeImpl;->e:Ljava/lang/reflect/Type;

    .line 14
    .line 15
    invoke-static {p0}, Lax/b;->k(Ljava/lang/reflect/Type;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    array-length p0, v1

    .line 23
    if-nez p0, :cond_0

    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :cond_0
    const-string p0, "<"

    .line 31
    .line 32
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const/4 p0, 0x0

    .line 36
    aget-object p0, v1, p0

    .line 37
    .line 38
    invoke-static {p0}, Lax/b;->k(Ljava/lang/reflect/Type;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    :goto_0
    array-length p0, v1

    .line 46
    if-ge v3, p0, :cond_1

    .line 47
    .line 48
    const-string p0, ", "

    .line 49
    .line 50
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    aget-object p0, v1, v3

    .line 54
    .line 55
    invoke-static {p0}, Lax/b;->k(Ljava/lang/reflect/Type;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    add-int/lit8 v3, v3, 0x1

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_1
    const-string p0, ">"

    .line 66
    .line 67
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0
.end method
