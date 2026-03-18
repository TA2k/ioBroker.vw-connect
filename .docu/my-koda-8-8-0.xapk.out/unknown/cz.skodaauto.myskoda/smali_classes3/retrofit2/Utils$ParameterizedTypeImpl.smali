.class final Lretrofit2/Utils$ParameterizedTypeImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/reflect/ParameterizedType;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lretrofit2/Utils;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "ParameterizedTypeImpl"
.end annotation


# instance fields
.field public final d:Ljava/lang/reflect/Type;

.field public final e:Ljava/lang/reflect/Type;

.field public final f:[Ljava/lang/reflect/Type;


# direct methods
.method public varargs constructor <init>(Ljava/lang/reflect/Type;Ljava/lang/reflect/Type;[Ljava/lang/reflect/Type;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    instance-of v0, p2, Ljava/lang/Class;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    if-eqz v0, :cond_3

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    if-nez p1, :cond_0

    .line 11
    .line 12
    move v2, v0

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move v2, v1

    .line 15
    :goto_0
    move-object v3, p2

    .line 16
    check-cast v3, Ljava/lang/Class;

    .line 17
    .line 18
    invoke-virtual {v3}, Ljava/lang/Class;->getEnclosingClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    if-nez v3, :cond_1

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_1
    move v0, v1

    .line 26
    :goto_1
    if-ne v2, v0, :cond_2

    .line 27
    .line 28
    goto :goto_2

    .line 29
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 30
    .line 31
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :cond_3
    :goto_2
    array-length v0, p3

    .line 36
    :goto_3
    if-ge v1, v0, :cond_4

    .line 37
    .line 38
    aget-object v2, p3, v1

    .line 39
    .line 40
    const-string v3, "typeArgument == null"

    .line 41
    .line 42
    invoke-static {v2, v3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    invoke-static {v2}, Lretrofit2/Utils;->a(Ljava/lang/reflect/Type;)V

    .line 46
    .line 47
    .line 48
    add-int/lit8 v1, v1, 0x1

    .line 49
    .line 50
    goto :goto_3

    .line 51
    :cond_4
    iput-object p1, p0, Lretrofit2/Utils$ParameterizedTypeImpl;->d:Ljava/lang/reflect/Type;

    .line 52
    .line 53
    iput-object p2, p0, Lretrofit2/Utils$ParameterizedTypeImpl;->e:Ljava/lang/reflect/Type;

    .line 54
    .line 55
    invoke-virtual {p3}, [Ljava/lang/reflect/Type;->clone()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    check-cast p1, [Ljava/lang/reflect/Type;

    .line 60
    .line 61
    iput-object p1, p0, Lretrofit2/Utils$ParameterizedTypeImpl;->f:[Ljava/lang/reflect/Type;

    .line 62
    .line 63
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
    invoke-static {p0, p1}, Lretrofit2/Utils;->b(Ljava/lang/reflect/Type;Ljava/lang/reflect/Type;)Z

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
    iget-object p0, p0, Lretrofit2/Utils$ParameterizedTypeImpl;->f:[Ljava/lang/reflect/Type;

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
    iget-object p0, p0, Lretrofit2/Utils$ParameterizedTypeImpl;->d:Ljava/lang/reflect/Type;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getRawType()Ljava/lang/reflect/Type;
    .locals 0

    .line 1
    iget-object p0, p0, Lretrofit2/Utils$ParameterizedTypeImpl;->e:Ljava/lang/reflect/Type;

    .line 2
    .line 3
    return-object p0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lretrofit2/Utils$ParameterizedTypeImpl;->f:[Ljava/lang/reflect/Type;

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lretrofit2/Utils$ParameterizedTypeImpl;->e:Ljava/lang/reflect/Type;

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
    iget-object p0, p0, Lretrofit2/Utils$ParameterizedTypeImpl;->d:Ljava/lang/reflect/Type;

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
    iget-object v0, p0, Lretrofit2/Utils$ParameterizedTypeImpl;->f:[Ljava/lang/reflect/Type;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    iget-object p0, p0, Lretrofit2/Utils$ParameterizedTypeImpl;->e:Ljava/lang/reflect/Type;

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    invoke-static {p0}, Lretrofit2/Utils;->n(Ljava/lang/reflect/Type;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    array-length v2, v0

    .line 16
    const/4 v3, 0x1

    .line 17
    add-int/2addr v2, v3

    .line 18
    mul-int/lit8 v2, v2, 0x1e

    .line 19
    .line 20
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 21
    .line 22
    .line 23
    invoke-static {p0}, Lretrofit2/Utils;->n(Ljava/lang/reflect/Type;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string p0, "<"

    .line 31
    .line 32
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const/4 p0, 0x0

    .line 36
    aget-object p0, v0, p0

    .line 37
    .line 38
    invoke-static {p0}, Lretrofit2/Utils;->n(Ljava/lang/reflect/Type;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    :goto_0
    array-length p0, v0

    .line 46
    if-ge v3, p0, :cond_1

    .line 47
    .line 48
    const-string p0, ", "

    .line 49
    .line 50
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    aget-object p0, v0, v3

    .line 54
    .line 55
    invoke-static {p0}, Lretrofit2/Utils;->n(Ljava/lang/reflect/Type;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

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
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0
.end method
