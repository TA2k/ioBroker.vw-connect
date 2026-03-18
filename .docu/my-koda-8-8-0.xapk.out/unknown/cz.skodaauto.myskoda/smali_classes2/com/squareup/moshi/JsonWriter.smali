.class public abstract Lcom/squareup/moshi/JsonWriter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;
.implements Ljava/io/Flushable;


# instance fields
.field public d:I

.field public e:[I

.field public f:[Ljava/lang/String;

.field public g:[I

.field public h:Ljava/lang/String;

.field public i:Z

.field public j:Z

.field public k:Z

.field public l:I


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 6
    .line 7
    const/16 v0, 0x20

    .line 8
    .line 9
    new-array v1, v0, [I

    .line 10
    .line 11
    iput-object v1, p0, Lcom/squareup/moshi/JsonWriter;->e:[I

    .line 12
    .line 13
    new-array v1, v0, [Ljava/lang/String;

    .line 14
    .line 15
    iput-object v1, p0, Lcom/squareup/moshi/JsonWriter;->f:[Ljava/lang/String;

    .line 16
    .line 17
    new-array v0, v0, [I

    .line 18
    .line 19
    iput-object v0, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 20
    .line 21
    const/4 v0, -0x1

    .line 22
    iput v0, p0, Lcom/squareup/moshi/JsonWriter;->l:I

    .line 23
    .line 24
    return-void
.end method

.method public static l(Lu01/f;)Lcom/squareup/moshi/JsonWriter;
    .locals 1

    .line 1
    new-instance v0, Lcom/squareup/moshi/JsonUtf8Writer;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lcom/squareup/moshi/JsonUtf8Writer;-><init>(Lu01/g;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public final B(I)V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/squareup/moshi/JsonWriter;->e:[I

    .line 2
    .line 3
    iget v1, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 8
    .line 9
    aput p1, v0, v1

    .line 10
    .line 11
    return-void
.end method

.method public E(Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const/4 p1, 0x0

    .line 9
    :goto_0
    iput-object p1, p0, Lcom/squareup/moshi/JsonWriter;->h:Ljava/lang/String;

    .line 10
    .line 11
    return-void
.end method

.method public abstract H(D)Lcom/squareup/moshi/JsonWriter;
.end method

.method public abstract M(J)Lcom/squareup/moshi/JsonWriter;
.end method

.method public abstract T(Ljava/lang/Float;)Lcom/squareup/moshi/JsonWriter;
.end method

.method public abstract U(Ljava/lang/String;)Lcom/squareup/moshi/JsonWriter;
.end method

.method public abstract V(Z)Lcom/squareup/moshi/JsonWriter;
.end method

.method public abstract a()Lcom/squareup/moshi/JsonWriter;
.end method

.method public abstract b()Lcom/squareup/moshi/JsonWriter;
.end method

.method public final d()V
    .locals 3

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 2
    .line 3
    iget-object v1, p0, Lcom/squareup/moshi/JsonWriter;->e:[I

    .line 4
    .line 5
    array-length v2, v1

    .line 6
    if-eq v0, v2, :cond_0

    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    const/16 v2, 0x100

    .line 10
    .line 11
    if-eq v0, v2, :cond_2

    .line 12
    .line 13
    array-length v0, v1

    .line 14
    mul-int/lit8 v0, v0, 0x2

    .line 15
    .line 16
    invoke-static {v1, v0}, Ljava/util/Arrays;->copyOf([II)[I

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    iput-object v0, p0, Lcom/squareup/moshi/JsonWriter;->e:[I

    .line 21
    .line 22
    iget-object v0, p0, Lcom/squareup/moshi/JsonWriter;->f:[Ljava/lang/String;

    .line 23
    .line 24
    array-length v1, v0

    .line 25
    mul-int/lit8 v1, v1, 0x2

    .line 26
    .line 27
    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    check-cast v0, [Ljava/lang/String;

    .line 32
    .line 33
    iput-object v0, p0, Lcom/squareup/moshi/JsonWriter;->f:[Ljava/lang/String;

    .line 34
    .line 35
    iget-object v0, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 36
    .line 37
    array-length v1, v0

    .line 38
    mul-int/lit8 v1, v1, 0x2

    .line 39
    .line 40
    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([II)[I

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    iput-object v0, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 45
    .line 46
    instance-of v0, p0, Lcom/squareup/moshi/JsonValueWriter;

    .line 47
    .line 48
    if-eqz v0, :cond_1

    .line 49
    .line 50
    check-cast p0, Lcom/squareup/moshi/JsonValueWriter;

    .line 51
    .line 52
    iget-object v0, p0, Lcom/squareup/moshi/JsonValueWriter;->m:[Ljava/lang/Object;

    .line 53
    .line 54
    array-length v1, v0

    .line 55
    mul-int/lit8 v1, v1, 0x2

    .line 56
    .line 57
    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    iput-object v0, p0, Lcom/squareup/moshi/JsonValueWriter;->m:[Ljava/lang/Object;

    .line 62
    .line 63
    :cond_1
    return-void

    .line 64
    :cond_2
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 65
    .line 66
    new-instance v1, Ljava/lang/StringBuilder;

    .line 67
    .line 68
    const-string v2, "Nesting too deep at "

    .line 69
    .line 70
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonWriter;->h()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    const-string p0, ": circular reference?"

    .line 81
    .line 82
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    throw v0
.end method

.method public abstract f()Lcom/squareup/moshi/JsonWriter;
.end method

.method public abstract g()Lcom/squareup/moshi/JsonWriter;
.end method

.method public final h()Ljava/lang/String;
    .locals 3

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 2
    .line 3
    iget-object v1, p0, Lcom/squareup/moshi/JsonWriter;->e:[I

    .line 4
    .line 5
    iget-object v2, p0, Lcom/squareup/moshi/JsonWriter;->f:[Ljava/lang/String;

    .line 6
    .line 7
    iget-object p0, p0, Lcom/squareup/moshi/JsonWriter;->g:[I

    .line 8
    .line 9
    invoke-static {v0, v1, v2, p0}, Lcom/squareup/moshi/JsonScope;->a(I[I[Ljava/lang/String;[I)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method

.method public abstract j(Ljava/lang/String;)Lcom/squareup/moshi/JsonWriter;
.end method

.method public abstract k()Lcom/squareup/moshi/JsonWriter;
.end method

.method public final q()I
    .locals 1

    .line 1
    iget v0, p0, Lcom/squareup/moshi/JsonWriter;->d:I

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lcom/squareup/moshi/JsonWriter;->e:[I

    .line 6
    .line 7
    add-int/lit8 v0, v0, -0x1

    .line 8
    .line 9
    aget p0, p0, v0

    .line 10
    .line 11
    return p0

    .line 12
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 13
    .line 14
    const-string v0, "JsonWriter is closed."

    .line 15
    .line 16
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw p0
.end method
