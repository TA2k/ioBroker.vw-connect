.class public final Lmr/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Comparable;


# instance fields
.field public final d:[B


# direct methods
.method public constructor <init>([B)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    array-length v0, p1

    .line 5
    invoke-static {p1, v0}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iput-object p1, p0, Lmr/d;->d:[B

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final compareTo(Ljava/lang/Object;)I
    .locals 4

    .line 1
    check-cast p1, Lmr/d;

    .line 2
    .line 3
    iget-object p0, p0, Lmr/d;->d:[B

    .line 4
    .line 5
    array-length v0, p0

    .line 6
    iget-object v1, p1, Lmr/d;->d:[B

    .line 7
    .line 8
    array-length v2, v1

    .line 9
    if-eq v0, v2, :cond_0

    .line 10
    .line 11
    array-length p0, p0

    .line 12
    array-length p1, v1

    .line 13
    sub-int/2addr p0, p1

    .line 14
    return p0

    .line 15
    :cond_0
    const/4 v0, 0x0

    .line 16
    move v1, v0

    .line 17
    :goto_0
    array-length v2, p0

    .line 18
    if-ge v1, v2, :cond_2

    .line 19
    .line 20
    aget-byte v2, p0, v1

    .line 21
    .line 22
    iget-object v3, p1, Lmr/d;->d:[B

    .line 23
    .line 24
    aget-byte v3, v3, v1

    .line 25
    .line 26
    if-eq v2, v3, :cond_1

    .line 27
    .line 28
    sub-int/2addr v2, v3

    .line 29
    return v2

    .line 30
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_2
    return v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lmr/d;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    check-cast p1, Lmr/d;

    .line 8
    .line 9
    iget-object p0, p0, Lmr/d;->d:[B

    .line 10
    .line 11
    iget-object p1, p1, Lmr/d;->d:[B

    .line 12
    .line 13
    invoke-static {p0, p1}, Ljava/util/Arrays;->equals([B[B)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lmr/d;->d:[B

    .line 2
    .line 3
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([B)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lmr/d;->d:[B

    .line 2
    .line 3
    invoke-static {p0}, Lkp/d6;->b([B)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
