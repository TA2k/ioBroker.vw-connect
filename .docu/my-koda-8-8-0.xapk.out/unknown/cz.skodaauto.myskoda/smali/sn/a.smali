.class public final Lsn/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:I

.field public final b:J


# direct methods
.method public constructor <init>(IJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    iput p1, p0, Lsn/a;->a:I

    .line 7
    .line 8
    iput-wide p2, p0, Lsn/a;->b:J

    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 12
    .line 13
    const-string p1, "Null status"

    .line 14
    .line 15
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    throw p0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p1, p0, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    instance-of v0, p1, Lsn/a;

    .line 5
    .line 6
    if-eqz v0, :cond_1

    .line 7
    .line 8
    check-cast p1, Lsn/a;

    .line 9
    .line 10
    iget v0, p0, Lsn/a;->a:I

    .line 11
    .line 12
    iget v1, p1, Lsn/a;->a:I

    .line 13
    .line 14
    invoke-static {v0, v1}, Lu/w;->a(II)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    iget-wide v0, p0, Lsn/a;->b:J

    .line 21
    .line 22
    iget-wide p0, p1, Lsn/a;->b:J

    .line 23
    .line 24
    cmp-long p0, v0, p0

    .line 25
    .line 26
    if-nez p0, :cond_1

    .line 27
    .line 28
    :goto_0
    const/4 p0, 0x1

    .line 29
    return p0

    .line 30
    :cond_1
    const/4 p0, 0x0

    .line 31
    return p0
.end method

.method public final hashCode()I
    .locals 6

    .line 1
    iget v0, p0, Lsn/a;->a:I

    .line 2
    .line 3
    invoke-static {v0}, Lu/w;->o(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const v1, 0xf4243

    .line 8
    .line 9
    .line 10
    xor-int/2addr v0, v1

    .line 11
    mul-int/2addr v0, v1

    .line 12
    const/16 v1, 0x20

    .line 13
    .line 14
    iget-wide v2, p0, Lsn/a;->b:J

    .line 15
    .line 16
    ushr-long v4, v2, v1

    .line 17
    .line 18
    xor-long v1, v4, v2

    .line 19
    .line 20
    long-to-int p0, v1

    .line 21
    xor-int/2addr p0, v0

    .line 22
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "BackendResponse{status="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    iget v2, p0, Lsn/a;->a:I

    .line 10
    .line 11
    if-eq v2, v1, :cond_3

    .line 12
    .line 13
    const/4 v1, 0x2

    .line 14
    if-eq v2, v1, :cond_2

    .line 15
    .line 16
    const/4 v1, 0x3

    .line 17
    if-eq v2, v1, :cond_1

    .line 18
    .line 19
    const/4 v1, 0x4

    .line 20
    if-eq v2, v1, :cond_0

    .line 21
    .line 22
    const-string v1, "null"

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const-string v1, "INVALID_PAYLOAD"

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    const-string v1, "FATAL_ERROR"

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_2
    const-string v1, "TRANSIENT_ERROR"

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_3
    const-string v1, "OK"

    .line 35
    .line 36
    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string v1, ", nextRequestWaitMillis="

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    iget-wide v1, p0, Lsn/a;->b:J

    .line 45
    .line 46
    const-string p0, "}"

    .line 47
    .line 48
    invoke-static {v1, v2, p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->k(JLjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method
