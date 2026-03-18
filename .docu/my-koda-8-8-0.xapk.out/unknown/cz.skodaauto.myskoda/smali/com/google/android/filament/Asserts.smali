.class final Lcom/google/android/filament/Asserts;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static assertDouble4([D)[D
    .locals 2

    .line 1
    const/4 v0, 0x4

    .line 2
    if-nez p0, :cond_0

    .line 3
    .line 4
    new-array p0, v0, [D

    .line 5
    .line 6
    return-object p0

    .line 7
    :cond_0
    array-length v1, p0

    .line 8
    if-lt v1, v0, :cond_1

    .line 9
    .line 10
    return-object p0

    .line 11
    :cond_1
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 12
    .line 13
    const-string v0, "Array length must be at least 4"

    .line 14
    .line 15
    invoke-direct {p0, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    throw p0
.end method

.method public static assertDouble4In([D)V
    .locals 1

    .line 1
    array-length p0, p0

    .line 2
    const/4 v0, 0x4

    .line 3
    if-lt p0, v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 7
    .line 8
    const-string v0, "Array length must be at least 4"

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public static assertFloat3([F)[F
    .locals 2

    .line 1
    const/4 v0, 0x3

    .line 2
    if-nez p0, :cond_0

    .line 3
    .line 4
    new-array p0, v0, [F

    .line 5
    .line 6
    return-object p0

    .line 7
    :cond_0
    array-length v1, p0

    .line 8
    if-lt v1, v0, :cond_1

    .line 9
    .line 10
    return-object p0

    .line 11
    :cond_1
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 12
    .line 13
    const-string v0, "Array length must be at least 3"

    .line 14
    .line 15
    invoke-direct {p0, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    throw p0
.end method

.method public static assertFloat3In([F)V
    .locals 1

    .line 1
    array-length p0, p0

    .line 2
    const/4 v0, 0x3

    .line 3
    if-lt p0, v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 7
    .line 8
    const-string v0, "Array length must be at least 3"

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public static assertFloat4([F)[F
    .locals 2

    .line 1
    const/4 v0, 0x4

    .line 2
    if-nez p0, :cond_0

    .line 3
    .line 4
    new-array p0, v0, [F

    .line 5
    .line 6
    return-object p0

    .line 7
    :cond_0
    array-length v1, p0

    .line 8
    if-lt v1, v0, :cond_1

    .line 9
    .line 10
    return-object p0

    .line 11
    :cond_1
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 12
    .line 13
    const-string v0, "Array length must be at least 4"

    .line 14
    .line 15
    invoke-direct {p0, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    throw p0
.end method

.method public static assertFloat4In([F)V
    .locals 1

    .line 1
    array-length p0, p0

    .line 2
    const/4 v0, 0x4

    .line 3
    if-lt p0, v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 7
    .line 8
    const-string v0, "Array length must be at least 4"

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public static assertMat3f([F)[F
    .locals 2

    .line 1
    const/16 v0, 0x9

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    new-array p0, v0, [F

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    array-length v1, p0

    .line 9
    if-lt v1, v0, :cond_1

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_1
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 13
    .line 14
    const-string v0, "Array length must be at least 9"

    .line 15
    .line 16
    invoke-direct {p0, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw p0
.end method

.method public static assertMat3fIn([F)V
    .locals 1

    .line 1
    array-length p0, p0

    .line 2
    const/16 v0, 0x9

    .line 3
    .line 4
    if-lt p0, v0, :cond_0

    .line 5
    .line 6
    return-void

    .line 7
    :cond_0
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 8
    .line 9
    const-string v0, "Array length must be at least 9"

    .line 10
    .line 11
    invoke-direct {p0, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    throw p0
.end method

.method public static assertMat4([D)[D
    .locals 2

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    new-array p0, v0, [D

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    array-length v1, p0

    .line 9
    if-lt v1, v0, :cond_1

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_1
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 13
    .line 14
    const-string v0, "Array length must be at least 16"

    .line 15
    .line 16
    invoke-direct {p0, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw p0
.end method

.method public static assertMat4In([D)V
    .locals 1

    .line 1
    array-length p0, p0

    .line 2
    const/16 v0, 0x10

    .line 3
    .line 4
    if-lt p0, v0, :cond_0

    .line 5
    .line 6
    return-void

    .line 7
    :cond_0
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 8
    .line 9
    const-string v0, "Array length must be at least 16"

    .line 10
    .line 11
    invoke-direct {p0, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    throw p0
.end method

.method public static assertMat4d([D)[D
    .locals 2

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    new-array p0, v0, [D

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    array-length v1, p0

    .line 9
    if-lt v1, v0, :cond_1

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_1
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 13
    .line 14
    const-string v0, "Array length must be at least 16"

    .line 15
    .line 16
    invoke-direct {p0, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw p0
.end method

.method public static assertMat4dIn([D)V
    .locals 1

    .line 1
    array-length p0, p0

    .line 2
    const/16 v0, 0x10

    .line 3
    .line 4
    if-lt p0, v0, :cond_0

    .line 5
    .line 6
    return-void

    .line 7
    :cond_0
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 8
    .line 9
    const-string v0, "Array length must be at least 16"

    .line 10
    .line 11
    invoke-direct {p0, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    throw p0
.end method

.method public static assertMat4f([F)[F
    .locals 2

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    new-array p0, v0, [F

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    array-length v1, p0

    .line 9
    if-lt v1, v0, :cond_1

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_1
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 13
    .line 14
    const-string v0, "Array length must be at least 16"

    .line 15
    .line 16
    invoke-direct {p0, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw p0
.end method

.method public static assertMat4fIn([F)V
    .locals 1

    .line 1
    array-length p0, p0

    .line 2
    const/16 v0, 0x10

    .line 3
    .line 4
    if-lt p0, v0, :cond_0

    .line 5
    .line 6
    return-void

    .line 7
    :cond_0
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 8
    .line 9
    const-string v0, "Array length must be at least 16"

    .line 10
    .line 11
    invoke-direct {p0, v0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    throw p0
.end method
