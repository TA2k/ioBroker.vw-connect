.class public final Lcom/google/gson/internal/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/reflect/ParameterizedType;
.implements Ljava/io/Serializable;


# instance fields
.field public final d:Ljava/lang/reflect/Type;

.field public final e:Ljava/lang/reflect/Type;

.field public final f:[Ljava/lang/reflect/Type;


# direct methods
.method public varargs constructor <init>(Ljava/lang/reflect/Type;Ljava/lang/Class;[Ljava/lang/reflect/Type;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    if-nez p1, :cond_1

    .line 8
    .line 9
    invoke-virtual {p2}, Ljava/lang/Class;->getModifiers()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-static {v0}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    invoke-virtual {p2}, Ljava/lang/Class;->getDeclaringClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    if-nez v0, :cond_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 27
    .line 28
    new-instance p1, Ljava/lang/StringBuilder;

    .line 29
    .line 30
    const-string p3, "Must specify owner type for "

    .line 31
    .line 32
    invoke-direct {p1, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw p0

    .line 46
    :cond_1
    :goto_0
    if-nez p1, :cond_2

    .line 47
    .line 48
    const/4 p1, 0x0

    .line 49
    goto :goto_1

    .line 50
    :cond_2
    invoke-static {p1}, Lcom/google/gson/internal/f;->a(Ljava/lang/reflect/Type;)Ljava/lang/reflect/Type;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    :goto_1
    iput-object p1, p0, Lcom/google/gson/internal/d;->d:Ljava/lang/reflect/Type;

    .line 55
    .line 56
    invoke-static {p2}, Lcom/google/gson/internal/f;->a(Ljava/lang/reflect/Type;)Ljava/lang/reflect/Type;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    iput-object p1, p0, Lcom/google/gson/internal/d;->e:Ljava/lang/reflect/Type;

    .line 61
    .line 62
    invoke-virtual {p3}, [Ljava/lang/reflect/Type;->clone()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    check-cast p1, [Ljava/lang/reflect/Type;

    .line 67
    .line 68
    iput-object p1, p0, Lcom/google/gson/internal/d;->f:[Ljava/lang/reflect/Type;

    .line 69
    .line 70
    array-length p1, p1

    .line 71
    const/4 p2, 0x0

    .line 72
    :goto_2
    if-ge p2, p1, :cond_3

    .line 73
    .line 74
    iget-object p3, p0, Lcom/google/gson/internal/d;->f:[Ljava/lang/reflect/Type;

    .line 75
    .line 76
    aget-object p3, p3, p2

    .line 77
    .line 78
    invoke-static {p3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    iget-object p3, p0, Lcom/google/gson/internal/d;->f:[Ljava/lang/reflect/Type;

    .line 82
    .line 83
    aget-object p3, p3, p2

    .line 84
    .line 85
    invoke-static {p3}, Lcom/google/gson/internal/f;->c(Ljava/lang/reflect/Type;)V

    .line 86
    .line 87
    .line 88
    iget-object p3, p0, Lcom/google/gson/internal/d;->f:[Ljava/lang/reflect/Type;

    .line 89
    .line 90
    aget-object v0, p3, p2

    .line 91
    .line 92
    invoke-static {v0}, Lcom/google/gson/internal/f;->a(Ljava/lang/reflect/Type;)Ljava/lang/reflect/Type;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    aput-object v0, p3, p2

    .line 97
    .line 98
    add-int/lit8 p2, p2, 0x1

    .line 99
    .line 100
    goto :goto_2

    .line 101
    :cond_3
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
    invoke-static {p0, p1}, Lcom/google/gson/internal/f;->e(Ljava/lang/reflect/Type;Ljava/lang/reflect/Type;)Z

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
    iget-object p0, p0, Lcom/google/gson/internal/d;->f:[Ljava/lang/reflect/Type;

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
    iget-object p0, p0, Lcom/google/gson/internal/d;->d:Ljava/lang/reflect/Type;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getRawType()Ljava/lang/reflect/Type;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/gson/internal/d;->e:Ljava/lang/reflect/Type;

    .line 2
    .line 3
    return-object p0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/gson/internal/d;->f:[Ljava/lang/reflect/Type;

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lcom/google/gson/internal/d;->e:Ljava/lang/reflect/Type;

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
    iget-object p0, p0, Lcom/google/gson/internal/d;->d:Ljava/lang/reflect/Type;

    .line 15
    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 p0, 0x0

    .line 24
    :goto_0
    xor-int/2addr p0, v0

    .line 25
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/gson/internal/d;->f:[Ljava/lang/reflect/Type;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    iget-object p0, p0, Lcom/google/gson/internal/d;->e:Ljava/lang/reflect/Type;

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    invoke-static {p0}, Lcom/google/gson/internal/f;->k(Ljava/lang/reflect/Type;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :cond_0
    new-instance v2, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    add-int/lit8 v3, v1, 0x1

    .line 16
    .line 17
    mul-int/lit8 v3, v3, 0x1e

    .line 18
    .line 19
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 20
    .line 21
    .line 22
    invoke-static {p0}, Lcom/google/gson/internal/f;->k(Ljava/lang/reflect/Type;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string p0, "<"

    .line 30
    .line 31
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const/4 p0, 0x0

    .line 35
    aget-object p0, v0, p0

    .line 36
    .line 37
    invoke-static {p0}, Lcom/google/gson/internal/f;->k(Ljava/lang/reflect/Type;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const/4 p0, 0x1

    .line 45
    :goto_0
    if-ge p0, v1, :cond_1

    .line 46
    .line 47
    const-string v3, ", "

    .line 48
    .line 49
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    aget-object v3, v0, p0

    .line 53
    .line 54
    invoke-static {v3}, Lcom/google/gson/internal/f;->k(Ljava/lang/reflect/Type;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v3

    .line 58
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    add-int/lit8 p0, p0, 0x1

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_1
    const-string p0, ">"

    .line 65
    .line 66
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0
.end method
