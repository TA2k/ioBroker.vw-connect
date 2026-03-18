.class final Lcom/squareup/moshi/JsonUtf8Writer;
.super Lcom/squareup/moshi/JsonWriter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final p:[Ljava/lang/String;


# instance fields
.field public final m:Lu01/g;

.field public n:Ljava/lang/String;

.field public o:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    const/16 v0, 0x80

    .line 2
    .line 3
    new-array v0, v0, [Ljava/lang/String;

    .line 4
    .line 5
    sput-object v0, Lcom/squareup/moshi/JsonUtf8Writer;->p:[Ljava/lang/String;

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    :goto_0
    const/16 v1, 0x1f

    .line 9
    .line 10
    if-gt v0, v1, :cond_0

    .line 11
    .line 12
    sget-object v1, Lcom/squareup/moshi/JsonUtf8Writer;->p:[Ljava/lang/String;

    .line 13
    .line 14
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    const-string v3, "\\u%04x"

    .line 23
    .line 24
    invoke-static {v3, v2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    aput-object v2, v1, v0

    .line 29
    .line 30
    add-int/lit8 v0, v0, 0x1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    sget-object v0, Lcom/squareup/moshi/JsonUtf8Writer;->p:[Ljava/lang/String;

    .line 34
    .line 35
    const/16 v1, 0x22

    .line 36
    .line 37
    const-string v2, "\\\""

    .line 38
    .line 39
    aput-object v2, v0, v1

    .line 40
    .line 41
    const/16 v1, 0x5c

    .line 42
    .line 43
    const-string v2, "\\\\"

    .line 44
    .line 45
    aput-object v2, v0, v1

    .line 46
    .line 47
    const/16 v1, 0x9

    .line 48
    .line 49
    const-string v2, "\\t"

    .line 50
    .line 51
    aput-object v2, v0, v1

    .line 52
    .line 53
    const/16 v1, 0x8

    .line 54
    .line 55
    const-string v2, "\\b"

    .line 56
    .line 57
    aput-object v2, v0, v1

    .line 58
    .line 59
    const/16 v1, 0xa

    .line 60
    .line 61
    const-string v2, "\\n"

    .line 62
    .line 63
    aput-object v2, v0, v1

    .line 64
    .line 65
    const/16 v1, 0xd

    .line 66
    .line 67
    const-string v2, "\\r"

    .line 68
    .line 69
    aput-object v2, v0, v1

    .line 70
    .line 71
    const/16 v1, 0xc

    .line 72
    .line 73
    const-string v2, "\\f"

    .line 74
    .line 75
    aput-object v2, v0, v1

    .line 76
    .line 77
    return-void
.end method

.method public constructor <init>(Lu01/g;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/squareup/moshi/JsonWriter;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, ":"

    .line 5
    .line 6
    iput-object v0, p0, Lcom/squareup/moshi/JsonUtf8Writer;->n:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p1, p0, Lcom/squareup/moshi/JsonUtf8Writer;->m:Lu01/g;

    .line 9
    .line 10
    const/4 p1, 0x6

    .line 11
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonWriter;->B(I)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public static l0(Lu01/g;Ljava/lang/String;)V
    .locals 6

    .line 1
    const/16 v0, 0x22

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lu01/g;->writeByte(I)Lu01/g;

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    const/4 v2, 0x0

    .line 11
    move v3, v2

    .line 12
    :goto_0
    if-ge v2, v1, :cond_5

    .line 13
    .line 14
    invoke-virtual {p1, v2}, Ljava/lang/String;->charAt(I)C

    .line 15
    .line 16
    .line 17
    move-result v4

    .line 18
    const/16 v5, 0x80

    .line 19
    .line 20
    if-ge v4, v5, :cond_0

    .line 21
    .line 22
    sget-object v5, Lcom/squareup/moshi/JsonUtf8Writer;->p:[Ljava/lang/String;

    .line 23
    .line 24
    aget-object v4, v5, v4

    .line 25
    .line 26
    if-nez v4, :cond_2

    .line 27
    .line 28
    goto :goto_2

    .line 29
    :cond_0
    const/16 v5, 0x2028

    .line 30
    .line 31
    if-ne v4, v5, :cond_1

    .line 32
    .line 33
    const-string v4, "\\u2028"

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    const/16 v5, 0x2029

    .line 37
    .line 38
    if-ne v4, v5, :cond_4

    .line 39
    .line 40
    const-string v4, "\\u2029"

    .line 41
    .line 42
    :cond_2
    :goto_1
    if-ge v3, v2, :cond_3

    .line 43
    .line 44
    invoke-interface {p0, v3, v2, p1}, Lu01/g;->j0(IILjava/lang/String;)Lu01/g;

    .line 45
    .line 46
    .line 47
    :cond_3
    invoke-interface {p0, v4}, Lu01/g;->z(Ljava/lang/String;)Lu01/g;

    .line 48
    .line 49
    .line 50
    add-int/lit8 v3, v2, 0x1

    .line 51
    .line 52
    :cond_4
    :goto_2
    add-int/lit8 v2, v2, 0x1

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_5
    if-ge v3, v1, :cond_6

    .line 56
    .line 57
    invoke-interface {p0, v3, v1, p1}, Lu01/g;->j0(IILjava/lang/String;)Lu01/g;

    .line 58
    .line 59
    .line 60
    :cond_6
    invoke-interface {p0, v0}, Lu01/g;->writeByte(I)Lu01/g;

    .line 61
    .line 62
    .line 63
    return-void
.end method


# virtual methods
.method public final E(Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lcom/squareup/moshi/JsonWriter;->E(Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    const-string p1, ": "

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const-string p1, ":"

    .line 14
    .line 15
    :goto_0
    iput-object p1, p0, Lcom/squareup/moshi/JsonUtf8Writer;->n:Ljava/lang/String;

    .line 16
    .line 17
    return-void
.end method

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
    invoke-static {p1, p2}, Ljava/lang/Double;->isInfinite(D)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 19
    .line 20
    new-instance v0, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    const-string v1, "Numeric values must be finite, but was "

    .line 23
    .line 24
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, p1, p2}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    :cond_1
    :goto_0
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 39
    .line 40
    if-eqz v0, :cond_2

    .line 41
    .line 42
    const/4 v0, 0x0

    .line 43
    iput-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 44
    .line 45
    invoke-static {p1, p2}, Ljava/lang/Double;->toString(D)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonUtf8Writer;->j(Ljava/lang/String;)Lcom/squareup/moshi/JsonWriter;

    .line 50
    .line 51
    .line 52
    return-object p0

    .line 53
    :cond_2
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->n0()V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->W()V

    .line 57
    .line 58
    .line 59
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Writer;->m:Lu01/g;

    .line 60
    .line 61
    invoke-static {p1, p2}, Ljava/lang/Double;->toString(D)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    invoke-interface {v0, p1}, Lu01/g;->z(Ljava/lang/String;)Lu01/g;

    .line 66
    .line 67
    .line 68
    iget-object p1, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 69
    .line 70
    iget p2, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 71
    .line 72
    add-int/lit8 p2, p2, -0x1

    .line 73
    .line 74
    aget v0, p1, p2

    .line 75
    .line 76
    add-int/lit8 v0, v0, 0x1

    .line 77
    .line 78
    aput v0, p1, p2

    .line 79
    .line 80
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
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonUtf8Writer;->j(Ljava/lang/String;)Lcom/squareup/moshi/JsonWriter;

    .line 13
    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->n0()V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->W()V

    .line 20
    .line 21
    .line 22
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Writer;->m:Lu01/g;

    .line 23
    .line 24
    invoke-static {p1, p2}, Ljava/lang/Long;->toString(J)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    invoke-interface {v0, p1}, Lu01/g;->z(Ljava/lang/String;)Lu01/g;

    .line 29
    .line 30
    .line 31
    iget-object p1, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 32
    .line 33
    iget p2, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 34
    .line 35
    add-int/lit8 p2, p2, -0x1

    .line 36
    .line 37
    aget v0, p1, p2

    .line 38
    .line 39
    add-int/lit8 v0, v0, 0x1

    .line 40
    .line 41
    aput v0, p1, p2

    .line 42
    .line 43
    return-object p0
.end method

.method public final T(Ljava/lang/Float;)Lcom/squareup/moshi/JsonWriter;
    .locals 2

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->k()Lcom/squareup/moshi/JsonWriter;

    .line 4
    .line 5
    .line 6
    return-object p0

    .line 7
    :cond_0
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-boolean v1, p0, Lcom/squareup/moshi/JsonWriter;->i:Z

    .line 12
    .line 13
    if-nez v1, :cond_2

    .line 14
    .line 15
    const-string v1, "-Infinity"

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_1

    .line 22
    .line 23
    const-string v1, "Infinity"

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-nez v1, :cond_1

    .line 30
    .line 31
    const-string v1, "NaN"

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-nez v1, :cond_1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 41
    .line 42
    new-instance v0, Ljava/lang/StringBuilder;

    .line 43
    .line 44
    const-string v1, "Numeric values must be finite, but was "

    .line 45
    .line 46
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_2
    :goto_0
    iget-boolean p1, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 61
    .line 62
    if-eqz p1, :cond_3

    .line 63
    .line 64
    const/4 p1, 0x0

    .line 65
    iput-boolean p1, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 66
    .line 67
    invoke-virtual {p0, v0}, Lcom/squareup/moshi/JsonUtf8Writer;->j(Ljava/lang/String;)Lcom/squareup/moshi/JsonWriter;

    .line 68
    .line 69
    .line 70
    return-object p0

    .line 71
    :cond_3
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->n0()V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->W()V

    .line 75
    .line 76
    .line 77
    iget-object p1, p0, Lcom/squareup/moshi/JsonUtf8Writer;->m:Lu01/g;

    .line 78
    .line 79
    invoke-interface {p1, v0}, Lu01/g;->z(Ljava/lang/String;)Lu01/g;

    .line 80
    .line 81
    .line 82
    iget-object p1, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 83
    .line 84
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 85
    .line 86
    add-int/lit8 v0, v0, -0x1

    .line 87
    .line 88
    aget v1, p1, v0

    .line 89
    .line 90
    add-int/lit8 v1, v1, 0x1

    .line 91
    .line 92
    aput v1, p1, v0

    .line 93
    .line 94
    return-object p0
.end method

.method public final U(Ljava/lang/String;)Lcom/squareup/moshi/JsonWriter;
    .locals 2

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->k()Lcom/squareup/moshi/JsonWriter;

    .line 4
    .line 5
    .line 6
    return-object p0

    .line 7
    :cond_0
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonUtf8Writer;->j(Ljava/lang/String;)Lcom/squareup/moshi/JsonWriter;

    .line 15
    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_1
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->n0()V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->W()V

    .line 22
    .line 23
    .line 24
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Writer;->m:Lu01/g;

    .line 25
    .line 26
    invoke-static {v0, p1}, Lcom/squareup/moshi/JsonUtf8Writer;->l0(Lu01/g;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    iget-object p1, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 30
    .line 31
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 32
    .line 33
    add-int/lit8 v0, v0, -0x1

    .line 34
    .line 35
    aget v1, p1, v0

    .line 36
    .line 37
    add-int/lit8 v1, v1, 0x1

    .line 38
    .line 39
    aput v1, p1, v0

    .line 40
    .line 41
    return-object p0
.end method

.method public final V(Z)Lcom/squareup/moshi/JsonWriter;
    .locals 2

    .line 1
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->n0()V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->W()V

    .line 9
    .line 10
    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    const-string p1, "true"

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const-string p1, "false"

    .line 17
    .line 18
    :goto_0
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Writer;->m:Lu01/g;

    .line 19
    .line 20
    invoke-interface {v0, p1}, Lu01/g;->z(Ljava/lang/String;)Lu01/g;

    .line 21
    .line 22
    .line 23
    iget-object p1, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 24
    .line 25
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 26
    .line 27
    add-int/lit8 v0, v0, -0x1

    .line 28
    .line 29
    aget v1, p1, v0

    .line 30
    .line 31
    add-int/lit8 v1, v1, 0x1

    .line 32
    .line 33
    aput v1, p1, v0

    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    new-instance v0, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    const-string v1, "Boolean cannot be used as a map key in JSON at path "

    .line 41
    .line 42
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->h()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p1
.end method

.method public final W()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->q()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x2

    .line 6
    const/4 v2, 0x1

    .line 7
    if-eq v0, v2, :cond_6

    .line 8
    .line 9
    iget-object v3, p0, Lcom/squareup/moshi/JsonUtf8Writer;->m:Lu01/g;

    .line 10
    .line 11
    if-eq v0, v1, :cond_5

    .line 12
    .line 13
    const/4 v1, 0x4

    .line 14
    if-eq v0, v1, :cond_4

    .line 15
    .line 16
    const/16 v1, 0x9

    .line 17
    .line 18
    if-eq v0, v1, :cond_3

    .line 19
    .line 20
    const/4 v1, 0x6

    .line 21
    const/4 v3, 0x7

    .line 22
    if-eq v0, v1, :cond_2

    .line 23
    .line 24
    if-ne v0, v3, :cond_1

    .line 25
    .line 26
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->i:Z

    .line 27
    .line 28
    if-eqz v0, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 32
    .line 33
    const-string v0, "JSON must have only one top-level value."

    .line 34
    .line 35
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0

    .line 39
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 40
    .line 41
    const-string v0, "Nesting problem."

    .line 42
    .line 43
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw p0

    .line 47
    :cond_2
    :goto_0
    move v1, v3

    .line 48
    goto :goto_1

    .line 49
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string v0, "Sink from valueSink() was not closed"

    .line 52
    .line 53
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_4
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Writer;->n:Ljava/lang/String;

    .line 58
    .line 59
    invoke-interface {v3, v0}, Lu01/g;->z(Ljava/lang/String;)Lu01/g;

    .line 60
    .line 61
    .line 62
    const/4 v1, 0x5

    .line 63
    goto :goto_1

    .line 64
    :cond_5
    const/16 v0, 0x2c

    .line 65
    .line 66
    invoke-interface {v3, v0}, Lu01/g;->writeByte(I)Lu01/g;

    .line 67
    .line 68
    .line 69
    :cond_6
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->h0()V

    .line 70
    .line 71
    .line 72
    :goto_1
    iget-object v0, p0, Lcom/squareup/moshi/JsonWriter;->e:[I

    .line 73
    .line 74
    iget p0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 75
    .line 76
    sub-int/2addr p0, v2

    .line 77
    aput v1, v0, p0

    .line 78
    .line 79
    return-void
.end method

.method public final a()Lcom/squareup/moshi/JsonWriter;
    .locals 3

    .line 1
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->n0()V

    .line 6
    .line 7
    .line 8
    const/4 v0, 0x2

    .line 9
    const/16 v1, 0x5b

    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    invoke-virtual {p0, v1, v2, v0}, Lcom/squareup/moshi/JsonUtf8Writer;->k0(CII)V

    .line 13
    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 17
    .line 18
    new-instance v1, Ljava/lang/StringBuilder;

    .line 19
    .line 20
    const-string v2, "Array cannot be used as a map key in JSON at path "

    .line 21
    .line 22
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->h()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw v0
.end method

.method public final b()Lcom/squareup/moshi/JsonWriter;
    .locals 3

    .line 1
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->n0()V

    .line 6
    .line 7
    .line 8
    const/4 v0, 0x5

    .line 9
    const/16 v1, 0x7b

    .line 10
    .line 11
    const/4 v2, 0x3

    .line 12
    invoke-virtual {p0, v1, v2, v0}, Lcom/squareup/moshi/JsonUtf8Writer;->k0(CII)V

    .line 13
    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 17
    .line 18
    new-instance v1, Ljava/lang/StringBuilder;

    .line 19
    .line 20
    const-string v2, "Object cannot be used as a map key in JSON at path "

    .line 21
    .line 22
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->h()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw v0
.end method

.method public final close()V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Writer;->m:Lu01/g;

    .line 2
    .line 3
    invoke-interface {v0}, Lu01/f0;->close()V

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    if-gt v0, v1, :cond_1

    .line 10
    .line 11
    if-ne v0, v1, :cond_0

    .line 12
    .line 13
    iget-object v2, p0, Lcom/squareup/moshi/JsonWriter;->e:[I

    .line 14
    .line 15
    sub-int/2addr v0, v1

    .line 16
    aget v0, v2, v0

    .line 17
    .line 18
    const/4 v1, 0x7

    .line 19
    if-ne v0, v1, :cond_1

    .line 20
    .line 21
    :cond_0
    const/4 v0, 0x0

    .line 22
    iput v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 23
    .line 24
    return-void

    .line 25
    :cond_1
    new-instance p0, Ljava/io/IOException;

    .line 26
    .line 27
    const-string v0, "Incomplete document"

    .line 28
    .line 29
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0
.end method

.method public final e0(CII)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->q()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eq v0, p3, :cond_1

    .line 6
    .line 7
    if-ne v0, p2, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 11
    .line 12
    const-string p1, "Nesting problem."

    .line 13
    .line 14
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0

    .line 18
    :cond_1
    :goto_0
    iget-object p2, p0, Lcom/squareup/moshi/JsonUtf8Writer;->o:Ljava/lang/String;

    .line 19
    .line 20
    if-nez p2, :cond_4

    .line 21
    .line 22
    iget p2, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 23
    .line 24
    iget v1, p0, Lcom/squareup/moshi/JsonWriter;->l:I

    .line 25
    .line 26
    not-int v1, v1

    .line 27
    if-ne p2, v1, :cond_2

    .line 28
    .line 29
    iput v1, p0, Lcom/squareup/moshi/JsonWriter;->l:I

    .line 30
    .line 31
    return-void

    .line 32
    :cond_2
    add-int/lit8 v1, p2, -0x1

    .line 33
    .line 34
    iput v1, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 35
    .line 36
    iget-object v2, p0, Lcom/squareup/moshi/JsonWriter;->f:[Ljava/lang/String;

    .line 37
    .line 38
    const/4 v3, 0x0

    .line 39
    aput-object v3, v2, v1

    .line 40
    .line 41
    iget-object v1, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 42
    .line 43
    add-int/lit8 p2, p2, -0x2

    .line 44
    .line 45
    aget v2, v1, p2

    .line 46
    .line 47
    add-int/lit8 v2, v2, 0x1

    .line 48
    .line 49
    aput v2, v1, p2

    .line 50
    .line 51
    if-ne v0, p3, :cond_3

    .line 52
    .line 53
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->h0()V

    .line 54
    .line 55
    .line 56
    :cond_3
    iget-object p0, p0, Lcom/squareup/moshi/JsonUtf8Writer;->m:Lu01/g;

    .line 57
    .line 58
    invoke-interface {p0, p1}, Lu01/g;->writeByte(I)Lu01/g;

    .line 59
    .line 60
    .line 61
    return-void

    .line 62
    :cond_4
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 63
    .line 64
    new-instance p2, Ljava/lang/StringBuilder;

    .line 65
    .line 66
    const-string p3, "Dangling name: "

    .line 67
    .line 68
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    iget-object p0, p0, Lcom/squareup/moshi/JsonUtf8Writer;->o:Ljava/lang/String;

    .line 72
    .line 73
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    throw p1
.end method

.method public final f()Lcom/squareup/moshi/JsonWriter;
    .locals 3

    .line 1
    const/4 v0, 0x2

    .line 2
    const/16 v1, 0x5d

    .line 3
    .line 4
    const/4 v2, 0x1

    .line 5
    invoke-virtual {p0, v1, v2, v0}, Lcom/squareup/moshi/JsonUtf8Writer;->e0(CII)V

    .line 6
    .line 7
    .line 8
    return-object p0
.end method

.method public final flush()V
    .locals 1

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lcom/squareup/moshi/JsonUtf8Writer;->m:Lu01/g;

    .line 6
    .line 7
    invoke-interface {p0}, Lu01/g;->flush()V

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 12
    .line 13
    const-string v0, "JsonWriter is closed."

    .line 14
    .line 15
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    throw p0
.end method

.method public final g()Lcom/squareup/moshi/JsonWriter;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 3
    .line 4
    const/4 v0, 0x5

    .line 5
    const/16 v1, 0x7d

    .line 6
    .line 7
    const/4 v2, 0x3

    .line 8
    invoke-virtual {p0, v1, v2, v0}, Lcom/squareup/moshi/JsonUtf8Writer;->e0(CII)V

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public final h0()V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/squareup/moshi/JsonWriter;->h:Ljava/lang/String;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_1

    .line 6
    :cond_0
    const/16 v0, 0xa

    .line 7
    .line 8
    iget-object v1, p0, Lcom/squareup/moshi/JsonUtf8Writer;->m:Lu01/g;

    .line 9
    .line 10
    invoke-interface {v1, v0}, Lu01/g;->writeByte(I)Lu01/g;

    .line 11
    .line 12
    .line 13
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    :goto_0
    if-ge v2, v0, :cond_1

    .line 17
    .line 18
    iget-object v3, p0, Lcom/squareup/moshi/JsonWriter;->h:Ljava/lang/String;

    .line 19
    .line 20
    invoke-interface {v1, v3}, Lu01/g;->z(Ljava/lang/String;)Lu01/g;

    .line 21
    .line 22
    .line 23
    add-int/lit8 v2, v2, 0x1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    :goto_1
    return-void
.end method

.method public final j(Ljava/lang/String;)Lcom/squareup/moshi/JsonWriter;
    .locals 2

    .line 1
    if-eqz p1, :cond_3

    .line 2
    .line 3
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 4
    .line 5
    if-eqz v0, :cond_2

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
    if-eq v0, v1, :cond_0

    .line 13
    .line 14
    const/4 v1, 0x5

    .line 15
    if-ne v0, v1, :cond_1

    .line 16
    .line 17
    :cond_0
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Writer;->o:Ljava/lang/String;

    .line 18
    .line 19
    if-nez v0, :cond_1

    .line 20
    .line 21
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    iput-object p1, p0, Lcom/squareup/moshi/JsonUtf8Writer;->o:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v0, p0, Lcom/squareup/moshi/JsonWriter;->f:[Ljava/lang/String;

    .line 28
    .line 29
    iget v1, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 30
    .line 31
    add-int/lit8 v1, v1, -0x1

    .line 32
    .line 33
    aput-object p1, v0, v1

    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    const-string p1, "Nesting problem."

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "JsonWriter is closed."

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_3
    new-instance p0, Ljava/lang/NullPointerException;

    .line 53
    .line 54
    const-string p1, "name == null"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0
.end method

.method public final k()Lcom/squareup/moshi/JsonWriter;
    .locals 3

    .line 1
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->k:Z

    .line 2
    .line 3
    if-nez v0, :cond_2

    .line 4
    .line 5
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Writer;->o:Ljava/lang/String;

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    iget-boolean v0, p0, Lcom/squareup/moshi/JsonWriter;->j:Z

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->n0()V

    .line 14
    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x0

    .line 18
    iput-object v0, p0, Lcom/squareup/moshi/JsonUtf8Writer;->o:Ljava/lang/String;

    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_1
    :goto_0
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->W()V

    .line 22
    .line 23
    .line 24
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Writer;->m:Lu01/g;

    .line 25
    .line 26
    const-string v1, "null"

    .line 27
    .line 28
    invoke-interface {v0, v1}, Lu01/g;->z(Ljava/lang/String;)Lu01/g;

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 32
    .line 33
    iget v1, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 34
    .line 35
    add-int/lit8 v1, v1, -0x1

    .line 36
    .line 37
    aget v2, v0, v1

    .line 38
    .line 39
    add-int/lit8 v2, v2, 0x1

    .line 40
    .line 41
    aput v2, v0, v1

    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_2
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    new-instance v1, Ljava/lang/StringBuilder;

    .line 47
    .line 48
    const-string v2, "null cannot be used as a map key in JSON at path "

    .line 49
    .line 50
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->h()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    throw v0
.end method

.method public final k0(CII)V
    .locals 3

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 2
    .line 3
    iget v1, p0, Lcom/squareup/moshi/JsonWriter;->l:I

    .line 4
    .line 5
    if-ne v0, v1, :cond_1

    .line 6
    .line 7
    iget-object v2, p0, Lcom/squareup/moshi/JsonWriter;->e:[I

    .line 8
    .line 9
    add-int/lit8 v0, v0, -0x1

    .line 10
    .line 11
    aget v0, v2, v0

    .line 12
    .line 13
    if-eq v0, p2, :cond_0

    .line 14
    .line 15
    if-ne v0, p3, :cond_1

    .line 16
    .line 17
    :cond_0
    not-int p1, v1

    .line 18
    iput p1, p0, Lcom/squareup/moshi/JsonWriter;->l:I

    .line 19
    .line 20
    return-void

    .line 21
    :cond_1
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->W()V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->d()V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, p2}, Lcom/squareup/moshi/JsonWriter;->B(I)V

    .line 28
    .line 29
    .line 30
    iget-object p2, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 31
    .line 32
    iget p3, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 33
    .line 34
    add-int/lit8 p3, p3, -0x1

    .line 35
    .line 36
    const/4 v0, 0x0

    .line 37
    aput v0, p2, p3

    .line 38
    .line 39
    iget-object p0, p0, Lcom/squareup/moshi/JsonUtf8Writer;->m:Lu01/g;

    .line 40
    .line 41
    invoke-interface {p0, p1}, Lu01/g;->writeByte(I)Lu01/g;

    .line 42
    .line 43
    .line 44
    return-void
.end method

.method public final n0()V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Writer;->o:Ljava/lang/String;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->q()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x5

    .line 10
    iget-object v2, p0, Lcom/squareup/moshi/JsonUtf8Writer;->m:Lu01/g;

    .line 11
    .line 12
    if-ne v0, v1, :cond_0

    .line 13
    .line 14
    const/16 v0, 0x2c

    .line 15
    .line 16
    invoke-interface {v2, v0}, Lu01/g;->writeByte(I)Lu01/g;

    .line 17
    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 v1, 0x3

    .line 21
    if-ne v0, v1, :cond_1

    .line 22
    .line 23
    :goto_0
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonUtf8Writer;->h0()V

    .line 24
    .line 25
    .line 26
    iget-object v0, p0, Lcom/squareup/moshi/JsonWriter;->e:[I

    .line 27
    .line 28
    iget v1, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 29
    .line 30
    add-int/lit8 v1, v1, -0x1

    .line 31
    .line 32
    const/4 v3, 0x4

    .line 33
    aput v3, v0, v1

    .line 34
    .line 35
    iget-object v0, p0, Lcom/squareup/moshi/JsonUtf8Writer;->o:Ljava/lang/String;

    .line 36
    .line 37
    invoke-static {v2, v0}, Lcom/squareup/moshi/JsonUtf8Writer;->l0(Lu01/g;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    const/4 v0, 0x0

    .line 41
    iput-object v0, p0, Lcom/squareup/moshi/JsonUtf8Writer;->o:Ljava/lang/String;

    .line 42
    .line 43
    return-void

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string v0, "Nesting problem."

    .line 47
    .line 48
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    return-void
.end method
