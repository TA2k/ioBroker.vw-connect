.class public final Lrr/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lmr/b;


# instance fields
.field public final a:Lpr/a;

.field public final b:I


# direct methods
.method public constructor <init>(Lpr/a;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrr/d;->a:Lpr/a;

    .line 5
    .line 6
    iput p2, p0, Lrr/d;->b:I

    .line 7
    .line 8
    const/16 p0, 0xa

    .line 9
    .line 10
    if-lt p2, p0, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    new-array p0, p0, [B

    .line 14
    .line 15
    invoke-interface {p1, p2, p0}, Lpr/a;->g(I[B)[B

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    new-instance p0, Ljava/security/InvalidAlgorithmParameterException;

    .line 20
    .line 21
    const-string p1, "tag size too small, need at least 10 bytes"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/security/InvalidAlgorithmParameterException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0
.end method


# virtual methods
.method public final a([B[B)V
    .locals 3

    .line 1
    invoke-virtual {p0, p2}, Lrr/d;->b([B)[B

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_1

    .line 6
    .line 7
    if-eqz p1, :cond_1

    .line 8
    .line 9
    array-length p2, p0

    .line 10
    array-length v0, p1

    .line 11
    if-ne p2, v0, :cond_1

    .line 12
    .line 13
    const/4 p2, 0x0

    .line 14
    move v0, p2

    .line 15
    :goto_0
    array-length v1, p0

    .line 16
    if-ge p2, v1, :cond_0

    .line 17
    .line 18
    aget-byte v1, p0, p2

    .line 19
    .line 20
    aget-byte v2, p1, p2

    .line 21
    .line 22
    xor-int/2addr v1, v2

    .line 23
    or-int/2addr v0, v1

    .line 24
    add-int/lit8 p2, p2, 0x1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    if-nez v0, :cond_1

    .line 28
    .line 29
    return-void

    .line 30
    :cond_1
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 31
    .line 32
    const-string p1, "invalid MAC"

    .line 33
    .line 34
    invoke-direct {p0, p1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0
.end method

.method public final b([B)[B
    .locals 1

    .line 1
    iget-object v0, p0, Lrr/d;->a:Lpr/a;

    .line 2
    .line 3
    iget p0, p0, Lrr/d;->b:I

    .line 4
    .line 5
    invoke-interface {v0, p0, p1}, Lpr/a;->g(I[B)[B

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
