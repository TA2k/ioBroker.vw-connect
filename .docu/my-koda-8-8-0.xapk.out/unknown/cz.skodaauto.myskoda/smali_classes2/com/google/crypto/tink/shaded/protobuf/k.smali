.class public final Lcom/google/crypto/tink/shaded/protobuf/k;
.super Lcom/google/crypto/tink/shaded/protobuf/q0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Ljava/util/logging/Logger;

.field public static final f:Z


# instance fields
.field public a:Lcom/google/crypto/tink/shaded/protobuf/m;

.field public final b:[B

.field public final c:I

.field public d:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lcom/google/crypto/tink/shaded/protobuf/k;->e:Ljava/util/logging/Logger;

    .line 12
    .line 13
    sget-boolean v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->f:Z

    .line 14
    .line 15
    sput-boolean v0, Lcom/google/crypto/tink/shaded/protobuf/k;->f:Z

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(I[B)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    array-length v0, p2

    .line 5
    sub-int/2addr v0, p1

    .line 6
    or-int/2addr v0, p1

    .line 7
    const/4 v1, 0x0

    .line 8
    if-ltz v0, :cond_0

    .line 9
    .line 10
    iput-object p2, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->b:[B

    .line 11
    .line 12
    iput v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 13
    .line 14
    iput p1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->c:I

    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 18
    .line 19
    array-length p2, p2

    .line 20
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    filled-new-array {p2, v0, p1}, [Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    const-string p2, "Array range is invalid. Buffer.length=%d, offset=%d, length=%d"

    .line 37
    .line 38
    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

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
.end method

.method public static A(Lcom/google/crypto/tink/shaded/protobuf/i;)I
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/i;->size()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-static {p0}, Lcom/google/crypto/tink/shaded/protobuf/k;->H(I)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    add-int/2addr v0, p0

    .line 10
    return v0
.end method

.method public static B(I)I
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    add-int/lit8 p0, p0, 0x4

    .line 6
    .line 7
    return p0
.end method

.method public static C(I)I
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    add-int/lit8 p0, p0, 0x8

    .line 6
    .line 7
    return p0
.end method

.method public static D(ILcom/google/crypto/tink/shaded/protobuf/a;Lcom/google/crypto/tink/shaded/protobuf/a1;)I
    .locals 3

    .line 1
    invoke-static {p0}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    mul-int/lit8 p0, p0, 0x2

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    move-object v0, p1

    .line 11
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 12
    .line 13
    iget v1, v0, Lcom/google/crypto/tink/shaded/protobuf/x;->memoizedSerializedSize:I

    .line 14
    .line 15
    const/4 v2, -0x1

    .line 16
    if-ne v1, v2, :cond_0

    .line 17
    .line 18
    invoke-interface {p2, p1}, Lcom/google/crypto/tink/shaded/protobuf/a1;->i(Lcom/google/crypto/tink/shaded/protobuf/a;)I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    iput v1, v0, Lcom/google/crypto/tink/shaded/protobuf/x;->memoizedSerializedSize:I

    .line 23
    .line 24
    :cond_0
    add-int/2addr v1, p0

    .line 25
    return v1
.end method

.method public static E(I)I
    .locals 0

    .line 1
    if-ltz p0, :cond_0

    .line 2
    .line 3
    invoke-static {p0}, Lcom/google/crypto/tink/shaded/protobuf/k;->H(I)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0

    .line 8
    :cond_0
    const/16 p0, 0xa

    .line 9
    .line 10
    return p0
.end method

.method public static F(Ljava/lang/String;)I
    .locals 1

    .line 1
    :try_start_0
    invoke-static {p0}, Lcom/google/crypto/tink/shaded/protobuf/o1;->b(Ljava/lang/String;)I

    .line 2
    .line 3
    .line 4
    move-result p0
    :try_end_0
    .catch Lcom/google/crypto/tink/shaded/protobuf/n1; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    goto :goto_0

    .line 6
    :catch_0
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/b0;->a:Ljava/nio/charset/Charset;

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    array-length p0, p0

    .line 13
    :goto_0
    invoke-static {p0}, Lcom/google/crypto/tink/shaded/protobuf/k;->H(I)I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    add-int/2addr v0, p0

    .line 18
    return v0
.end method

.method public static G(I)I
    .locals 0

    .line 1
    shl-int/lit8 p0, p0, 0x3

    .line 2
    .line 3
    invoke-static {p0}, Lcom/google/crypto/tink/shaded/protobuf/k;->H(I)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public static H(I)I
    .locals 1

    .line 1
    and-int/lit8 v0, p0, -0x80

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    and-int/lit16 v0, p0, -0x4000

    .line 8
    .line 9
    if-nez v0, :cond_1

    .line 10
    .line 11
    const/4 p0, 0x2

    .line 12
    return p0

    .line 13
    :cond_1
    const/high16 v0, -0x200000

    .line 14
    .line 15
    and-int/2addr v0, p0

    .line 16
    if-nez v0, :cond_2

    .line 17
    .line 18
    const/4 p0, 0x3

    .line 19
    return p0

    .line 20
    :cond_2
    const/high16 v0, -0x10000000

    .line 21
    .line 22
    and-int/2addr p0, v0

    .line 23
    if-nez p0, :cond_3

    .line 24
    .line 25
    const/4 p0, 0x4

    .line 26
    return p0

    .line 27
    :cond_3
    const/4 p0, 0x5

    .line 28
    return p0
.end method

.method public static I(J)I
    .locals 6

    .line 1
    const-wide/16 v0, -0x80

    .line 2
    .line 3
    and-long/2addr v0, p0

    .line 4
    const-wide/16 v2, 0x0

    .line 5
    .line 6
    cmp-long v0, v0, v2

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    return v1

    .line 12
    :cond_0
    cmp-long v0, p0, v2

    .line 13
    .line 14
    if-gez v0, :cond_1

    .line 15
    .line 16
    const/16 p0, 0xa

    .line 17
    .line 18
    return p0

    .line 19
    :cond_1
    const-wide v4, -0x800000000L

    .line 20
    .line 21
    .line 22
    .line 23
    .line 24
    and-long/2addr v4, p0

    .line 25
    cmp-long v0, v4, v2

    .line 26
    .line 27
    if-eqz v0, :cond_2

    .line 28
    .line 29
    const/16 v0, 0x1c

    .line 30
    .line 31
    ushr-long/2addr p0, v0

    .line 32
    const/4 v0, 0x6

    .line 33
    goto :goto_0

    .line 34
    :cond_2
    const/4 v0, 0x2

    .line 35
    :goto_0
    const-wide/32 v4, -0x200000

    .line 36
    .line 37
    .line 38
    and-long/2addr v4, p0

    .line 39
    cmp-long v4, v4, v2

    .line 40
    .line 41
    if-eqz v4, :cond_3

    .line 42
    .line 43
    add-int/lit8 v0, v0, 0x2

    .line 44
    .line 45
    const/16 v4, 0xe

    .line 46
    .line 47
    ushr-long/2addr p0, v4

    .line 48
    :cond_3
    const-wide/16 v4, -0x4000

    .line 49
    .line 50
    and-long/2addr p0, v4

    .line 51
    cmp-long p0, p0, v2

    .line 52
    .line 53
    if-eqz p0, :cond_4

    .line 54
    .line 55
    add-int/2addr v0, v1

    .line 56
    :cond_4
    return v0
.end method

.method public static z(ILcom/google/crypto/tink/shaded/protobuf/i;)I
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-static {p1}, Lcom/google/crypto/tink/shaded/protobuf/k;->A(Lcom/google/crypto/tink/shaded/protobuf/i;)I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    add-int/2addr p1, p0

    .line 10
    return p1
.end method


# virtual methods
.method public final J(B)V
    .locals 3

    .line 1
    :try_start_0
    iget-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->b:[B

    .line 2
    .line 3
    iget v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 8
    .line 9
    aput-byte p1, v0, v1
    :try_end_0
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 10
    .line 11
    return-void

    .line 12
    :catch_0
    move-exception p1

    .line 13
    new-instance v0, Lcom/google/crypto/tink/shaded/protobuf/l;

    .line 14
    .line 15
    iget v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 16
    .line 17
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    iget p0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->c:I

    .line 22
    .line 23
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    const/4 v2, 0x1

    .line 28
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    filled-new-array {v1, p0, v2}, [Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    const-string v1, "Pos: %d, limit: %d, len: %d"

    .line 37
    .line 38
    invoke-static {v1, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-direct {v0, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/l;-><init>(Ljava/lang/String;Ljava/lang/IndexOutOfBoundsException;)V

    .line 43
    .line 44
    .line 45
    throw v0
.end method

.method public final K([BII)V
    .locals 2

    .line 1
    :try_start_0
    iget-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->b:[B

    .line 2
    .line 3
    iget v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 4
    .line 5
    invoke-static {p1, p2, v0, v1, p3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 6
    .line 7
    .line 8
    iget p1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 9
    .line 10
    add-int/2addr p1, p3

    .line 11
    iput p1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I
    :try_end_0
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 12
    .line 13
    return-void

    .line 14
    :catch_0
    move-exception p1

    .line 15
    new-instance p2, Lcom/google/crypto/tink/shaded/protobuf/l;

    .line 16
    .line 17
    iget v0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 18
    .line 19
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    iget p0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->c:I

    .line 24
    .line 25
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 30
    .line 31
    .line 32
    move-result-object p3

    .line 33
    filled-new-array {v0, p0, p3}, [Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    const-string p3, "Pos: %d, limit: %d, len: %d"

    .line 38
    .line 39
    invoke-static {p3, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    invoke-direct {p2, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/l;-><init>(Ljava/lang/String;Ljava/lang/IndexOutOfBoundsException;)V

    .line 44
    .line 45
    .line 46
    throw p2
.end method

.method public final L(II)V
    .locals 1

    .line 1
    const/4 v0, 0x5

    .line 2
    invoke-virtual {p0, p1, v0}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 3
    .line 4
    .line 5
    invoke-virtual {p0, p2}, Lcom/google/crypto/tink/shaded/protobuf/k;->M(I)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final M(I)V
    .locals 5

    .line 1
    :try_start_0
    iget-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->b:[B

    .line 2
    .line 3
    iget v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 8
    .line 9
    and-int/lit16 v3, p1, 0xff

    .line 10
    .line 11
    int-to-byte v3, v3

    .line 12
    aput-byte v3, v0, v1

    .line 13
    .line 14
    add-int/lit8 v3, v1, 0x2

    .line 15
    .line 16
    iput v3, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 17
    .line 18
    shr-int/lit8 v4, p1, 0x8

    .line 19
    .line 20
    and-int/lit16 v4, v4, 0xff

    .line 21
    .line 22
    int-to-byte v4, v4

    .line 23
    aput-byte v4, v0, v2

    .line 24
    .line 25
    add-int/lit8 v2, v1, 0x3

    .line 26
    .line 27
    iput v2, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 28
    .line 29
    shr-int/lit8 v4, p1, 0x10

    .line 30
    .line 31
    and-int/lit16 v4, v4, 0xff

    .line 32
    .line 33
    int-to-byte v4, v4

    .line 34
    aput-byte v4, v0, v3

    .line 35
    .line 36
    add-int/lit8 v1, v1, 0x4

    .line 37
    .line 38
    iput v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 39
    .line 40
    shr-int/lit8 p1, p1, 0x18

    .line 41
    .line 42
    and-int/lit16 p1, p1, 0xff

    .line 43
    .line 44
    int-to-byte p1, p1

    .line 45
    aput-byte p1, v0, v2
    :try_end_0
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 46
    .line 47
    return-void

    .line 48
    :catch_0
    move-exception p1

    .line 49
    new-instance v0, Lcom/google/crypto/tink/shaded/protobuf/l;

    .line 50
    .line 51
    iget v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 52
    .line 53
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    iget p0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->c:I

    .line 58
    .line 59
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    const/4 v2, 0x1

    .line 64
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    filled-new-array {v1, p0, v2}, [Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    const-string v1, "Pos: %d, limit: %d, len: %d"

    .line 73
    .line 74
    invoke-static {v1, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    invoke-direct {v0, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/l;-><init>(Ljava/lang/String;Ljava/lang/IndexOutOfBoundsException;)V

    .line 79
    .line 80
    .line 81
    throw v0
.end method

.method public final N(IJ)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, p1, v0}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 3
    .line 4
    .line 5
    invoke-virtual {p0, p2, p3}, Lcom/google/crypto/tink/shaded/protobuf/k;->O(J)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final O(J)V
    .locals 7

    .line 1
    :try_start_0
    iget-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->b:[B

    .line 2
    .line 3
    iget v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 8
    .line 9
    long-to-int v3, p1

    .line 10
    and-int/lit16 v3, v3, 0xff

    .line 11
    .line 12
    int-to-byte v3, v3

    .line 13
    aput-byte v3, v0, v1

    .line 14
    .line 15
    add-int/lit8 v3, v1, 0x2

    .line 16
    .line 17
    iput v3, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 18
    .line 19
    const/16 v4, 0x8

    .line 20
    .line 21
    shr-long v5, p1, v4

    .line 22
    .line 23
    long-to-int v5, v5

    .line 24
    and-int/lit16 v5, v5, 0xff

    .line 25
    .line 26
    int-to-byte v5, v5

    .line 27
    aput-byte v5, v0, v2

    .line 28
    .line 29
    add-int/lit8 v2, v1, 0x3

    .line 30
    .line 31
    iput v2, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 32
    .line 33
    const/16 v5, 0x10

    .line 34
    .line 35
    shr-long v5, p1, v5

    .line 36
    .line 37
    long-to-int v5, v5

    .line 38
    and-int/lit16 v5, v5, 0xff

    .line 39
    .line 40
    int-to-byte v5, v5

    .line 41
    aput-byte v5, v0, v3

    .line 42
    .line 43
    add-int/lit8 v3, v1, 0x4

    .line 44
    .line 45
    iput v3, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 46
    .line 47
    const/16 v5, 0x18

    .line 48
    .line 49
    shr-long v5, p1, v5

    .line 50
    .line 51
    long-to-int v5, v5

    .line 52
    and-int/lit16 v5, v5, 0xff

    .line 53
    .line 54
    int-to-byte v5, v5

    .line 55
    aput-byte v5, v0, v2

    .line 56
    .line 57
    add-int/lit8 v2, v1, 0x5

    .line 58
    .line 59
    iput v2, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 60
    .line 61
    const/16 v5, 0x20

    .line 62
    .line 63
    shr-long v5, p1, v5

    .line 64
    .line 65
    long-to-int v5, v5

    .line 66
    and-int/lit16 v5, v5, 0xff

    .line 67
    .line 68
    int-to-byte v5, v5

    .line 69
    aput-byte v5, v0, v3

    .line 70
    .line 71
    add-int/lit8 v3, v1, 0x6

    .line 72
    .line 73
    iput v3, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 74
    .line 75
    const/16 v5, 0x28

    .line 76
    .line 77
    shr-long v5, p1, v5

    .line 78
    .line 79
    long-to-int v5, v5

    .line 80
    and-int/lit16 v5, v5, 0xff

    .line 81
    .line 82
    int-to-byte v5, v5

    .line 83
    aput-byte v5, v0, v2

    .line 84
    .line 85
    add-int/lit8 v2, v1, 0x7

    .line 86
    .line 87
    iput v2, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 88
    .line 89
    const/16 v5, 0x30

    .line 90
    .line 91
    shr-long v5, p1, v5

    .line 92
    .line 93
    long-to-int v5, v5

    .line 94
    and-int/lit16 v5, v5, 0xff

    .line 95
    .line 96
    int-to-byte v5, v5

    .line 97
    aput-byte v5, v0, v3

    .line 98
    .line 99
    add-int/2addr v1, v4

    .line 100
    iput v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 101
    .line 102
    const/16 v1, 0x38

    .line 103
    .line 104
    shr-long/2addr p1, v1

    .line 105
    long-to-int p1, p1

    .line 106
    and-int/lit16 p1, p1, 0xff

    .line 107
    .line 108
    int-to-byte p1, p1

    .line 109
    aput-byte p1, v0, v2
    :try_end_0
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 110
    .line 111
    return-void

    .line 112
    :catch_0
    move-exception p1

    .line 113
    new-instance p2, Lcom/google/crypto/tink/shaded/protobuf/l;

    .line 114
    .line 115
    iget v0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 116
    .line 117
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 118
    .line 119
    .line 120
    move-result-object v0

    .line 121
    iget p0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->c:I

    .line 122
    .line 123
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    const/4 v1, 0x1

    .line 128
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    filled-new-array {v0, p0, v1}, [Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    const-string v0, "Pos: %d, limit: %d, len: %d"

    .line 137
    .line 138
    invoke-static {v0, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    invoke-direct {p2, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/l;-><init>(Ljava/lang/String;Ljava/lang/IndexOutOfBoundsException;)V

    .line 143
    .line 144
    .line 145
    throw p2
.end method

.method public final P(I)V
    .locals 2

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/k;->R(I)V

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :cond_0
    int-to-long v0, p1

    .line 8
    invoke-virtual {p0, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k;->T(J)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final Q(II)V
    .locals 0

    .line 1
    shl-int/lit8 p1, p1, 0x3

    .line 2
    .line 3
    or-int/2addr p1, p2

    .line 4
    invoke-virtual {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/k;->R(I)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final R(I)V
    .locals 5

    .line 1
    sget-boolean v0, Lcom/google/crypto/tink/shaded/protobuf/k;->f:Z

    .line 2
    .line 3
    iget v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->c:I

    .line 4
    .line 5
    iget-object v2, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->b:[B

    .line 6
    .line 7
    if-eqz v0, :cond_4

    .line 8
    .line 9
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/c;->a()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-nez v0, :cond_4

    .line 14
    .line 15
    iget v0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 16
    .line 17
    sub-int v3, v1, v0

    .line 18
    .line 19
    const/4 v4, 0x5

    .line 20
    if-lt v3, v4, :cond_4

    .line 21
    .line 22
    and-int/lit8 v1, p1, -0x80

    .line 23
    .line 24
    if-nez v1, :cond_0

    .line 25
    .line 26
    add-int/lit8 v1, v0, 0x1

    .line 27
    .line 28
    iput v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 29
    .line 30
    int-to-long v0, v0

    .line 31
    int-to-byte p0, p1

    .line 32
    invoke-static {v2, v0, v1, p0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :cond_0
    add-int/lit8 v1, v0, 0x1

    .line 37
    .line 38
    iput v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 39
    .line 40
    int-to-long v0, v0

    .line 41
    or-int/lit16 v3, p1, 0x80

    .line 42
    .line 43
    int-to-byte v3, v3

    .line 44
    invoke-static {v2, v0, v1, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 45
    .line 46
    .line 47
    ushr-int/lit8 v0, p1, 0x7

    .line 48
    .line 49
    and-int/lit8 v1, v0, -0x80

    .line 50
    .line 51
    if-nez v1, :cond_1

    .line 52
    .line 53
    iget p1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 54
    .line 55
    add-int/lit8 v1, p1, 0x1

    .line 56
    .line 57
    iput v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 58
    .line 59
    int-to-long p0, p1

    .line 60
    int-to-byte v0, v0

    .line 61
    invoke-static {v2, p0, p1, v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 62
    .line 63
    .line 64
    return-void

    .line 65
    :cond_1
    iget v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 66
    .line 67
    add-int/lit8 v3, v1, 0x1

    .line 68
    .line 69
    iput v3, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 70
    .line 71
    int-to-long v3, v1

    .line 72
    or-int/lit16 v0, v0, 0x80

    .line 73
    .line 74
    int-to-byte v0, v0

    .line 75
    invoke-static {v2, v3, v4, v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 76
    .line 77
    .line 78
    ushr-int/lit8 v0, p1, 0xe

    .line 79
    .line 80
    and-int/lit8 v1, v0, -0x80

    .line 81
    .line 82
    if-nez v1, :cond_2

    .line 83
    .line 84
    iget p1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 85
    .line 86
    add-int/lit8 v1, p1, 0x1

    .line 87
    .line 88
    iput v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 89
    .line 90
    int-to-long p0, p1

    .line 91
    int-to-byte v0, v0

    .line 92
    invoke-static {v2, p0, p1, v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 93
    .line 94
    .line 95
    return-void

    .line 96
    :cond_2
    iget v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 97
    .line 98
    add-int/lit8 v3, v1, 0x1

    .line 99
    .line 100
    iput v3, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 101
    .line 102
    int-to-long v3, v1

    .line 103
    or-int/lit16 v0, v0, 0x80

    .line 104
    .line 105
    int-to-byte v0, v0

    .line 106
    invoke-static {v2, v3, v4, v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 107
    .line 108
    .line 109
    ushr-int/lit8 v0, p1, 0x15

    .line 110
    .line 111
    and-int/lit8 v1, v0, -0x80

    .line 112
    .line 113
    if-nez v1, :cond_3

    .line 114
    .line 115
    iget p1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 116
    .line 117
    add-int/lit8 v1, p1, 0x1

    .line 118
    .line 119
    iput v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 120
    .line 121
    int-to-long p0, p1

    .line 122
    int-to-byte v0, v0

    .line 123
    invoke-static {v2, p0, p1, v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 124
    .line 125
    .line 126
    return-void

    .line 127
    :cond_3
    iget v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 128
    .line 129
    add-int/lit8 v3, v1, 0x1

    .line 130
    .line 131
    iput v3, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 132
    .line 133
    int-to-long v3, v1

    .line 134
    or-int/lit16 v0, v0, 0x80

    .line 135
    .line 136
    int-to-byte v0, v0

    .line 137
    invoke-static {v2, v3, v4, v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 138
    .line 139
    .line 140
    ushr-int/lit8 p1, p1, 0x1c

    .line 141
    .line 142
    iget v0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 143
    .line 144
    add-int/lit8 v1, v0, 0x1

    .line 145
    .line 146
    iput v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 147
    .line 148
    int-to-long v0, v0

    .line 149
    int-to-byte p0, p1

    .line 150
    invoke-static {v2, v0, v1, p0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 151
    .line 152
    .line 153
    return-void

    .line 154
    :cond_4
    :goto_0
    and-int/lit8 v0, p1, -0x80

    .line 155
    .line 156
    if-nez v0, :cond_5

    .line 157
    .line 158
    :try_start_0
    iget v0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 159
    .line 160
    add-int/lit8 v3, v0, 0x1

    .line 161
    .line 162
    iput v3, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 163
    .line 164
    int-to-byte p1, p1

    .line 165
    aput-byte p1, v2, v0

    .line 166
    .line 167
    return-void

    .line 168
    :catch_0
    move-exception p1

    .line 169
    goto :goto_1

    .line 170
    :cond_5
    iget v0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 171
    .line 172
    add-int/lit8 v3, v0, 0x1

    .line 173
    .line 174
    iput v3, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 175
    .line 176
    and-int/lit8 v3, p1, 0x7f

    .line 177
    .line 178
    or-int/lit16 v3, v3, 0x80

    .line 179
    .line 180
    int-to-byte v3, v3

    .line 181
    aput-byte v3, v2, v0
    :try_end_0
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 182
    .line 183
    ushr-int/lit8 p1, p1, 0x7

    .line 184
    .line 185
    goto :goto_0

    .line 186
    :goto_1
    new-instance v0, Lcom/google/crypto/tink/shaded/protobuf/l;

    .line 187
    .line 188
    iget p0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 189
    .line 190
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 195
    .line 196
    .line 197
    move-result-object v1

    .line 198
    const/4 v2, 0x1

    .line 199
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 200
    .line 201
    .line 202
    move-result-object v2

    .line 203
    filled-new-array {p0, v1, v2}, [Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object p0

    .line 207
    const-string v1, "Pos: %d, limit: %d, len: %d"

    .line 208
    .line 209
    invoke-static {v1, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object p0

    .line 213
    invoke-direct {v0, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/l;-><init>(Ljava/lang/String;Ljava/lang/IndexOutOfBoundsException;)V

    .line 214
    .line 215
    .line 216
    throw v0
.end method

.method public final S(IJ)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, p1, v0}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 3
    .line 4
    .line 5
    invoke-virtual {p0, p2, p3}, Lcom/google/crypto/tink/shaded/protobuf/k;->T(J)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final T(J)V
    .locals 10

    .line 1
    sget-boolean v0, Lcom/google/crypto/tink/shaded/protobuf/k;->f:Z

    .line 2
    .line 3
    iget v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->c:I

    .line 4
    .line 5
    const/4 v2, 0x7

    .line 6
    const-wide/16 v3, 0x0

    .line 7
    .line 8
    const-wide/16 v5, -0x80

    .line 9
    .line 10
    iget-object v7, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->b:[B

    .line 11
    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    iget v0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 15
    .line 16
    sub-int v0, v1, v0

    .line 17
    .line 18
    const/16 v8, 0xa

    .line 19
    .line 20
    if-lt v0, v8, :cond_1

    .line 21
    .line 22
    :goto_0
    and-long v0, p1, v5

    .line 23
    .line 24
    cmp-long v0, v0, v3

    .line 25
    .line 26
    if-nez v0, :cond_0

    .line 27
    .line 28
    iget v0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 29
    .line 30
    add-int/lit8 v1, v0, 0x1

    .line 31
    .line 32
    iput v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 33
    .line 34
    int-to-long v0, v0

    .line 35
    long-to-int p0, p1

    .line 36
    int-to-byte p0, p0

    .line 37
    invoke-static {v7, v0, v1, p0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :cond_0
    iget v0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 42
    .line 43
    add-int/lit8 v1, v0, 0x1

    .line 44
    .line 45
    iput v1, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 46
    .line 47
    int-to-long v0, v0

    .line 48
    long-to-int v8, p1

    .line 49
    and-int/lit8 v8, v8, 0x7f

    .line 50
    .line 51
    or-int/lit16 v8, v8, 0x80

    .line 52
    .line 53
    int-to-byte v8, v8

    .line 54
    invoke-static {v7, v0, v1, v8}, Lcom/google/crypto/tink/shaded/protobuf/l1;->j([BJB)V

    .line 55
    .line 56
    .line 57
    ushr-long/2addr p1, v2

    .line 58
    goto :goto_0

    .line 59
    :cond_1
    :goto_1
    and-long v8, p1, v5

    .line 60
    .line 61
    cmp-long v0, v8, v3

    .line 62
    .line 63
    if-nez v0, :cond_2

    .line 64
    .line 65
    :try_start_0
    iget v0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 66
    .line 67
    add-int/lit8 v2, v0, 0x1

    .line 68
    .line 69
    iput v2, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 70
    .line 71
    long-to-int p1, p1

    .line 72
    int-to-byte p1, p1

    .line 73
    aput-byte p1, v7, v0

    .line 74
    .line 75
    return-void

    .line 76
    :catch_0
    move-exception p1

    .line 77
    goto :goto_2

    .line 78
    :cond_2
    iget v0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 79
    .line 80
    add-int/lit8 v8, v0, 0x1

    .line 81
    .line 82
    iput v8, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 83
    .line 84
    long-to-int v8, p1

    .line 85
    and-int/lit8 v8, v8, 0x7f

    .line 86
    .line 87
    or-int/lit16 v8, v8, 0x80

    .line 88
    .line 89
    int-to-byte v8, v8

    .line 90
    aput-byte v8, v7, v0
    :try_end_0
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 91
    .line 92
    ushr-long/2addr p1, v2

    .line 93
    goto :goto_1

    .line 94
    :goto_2
    new-instance p2, Lcom/google/crypto/tink/shaded/protobuf/l;

    .line 95
    .line 96
    iget p0, p0, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 97
    .line 98
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    const/4 v1, 0x1

    .line 107
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 108
    .line 109
    .line 110
    move-result-object v1

    .line 111
    filled-new-array {p0, v0, v1}, [Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    const-string v0, "Pos: %d, limit: %d, len: %d"

    .line 116
    .line 117
    invoke-static {v0, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    invoke-direct {p2, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/l;-><init>(Ljava/lang/String;Ljava/lang/IndexOutOfBoundsException;)V

    .line 122
    .line 123
    .line 124
    throw p2
.end method
