.class public final Lcom/wultra/android/sslpinning/model/CertificateInfo;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Serializable;
.implements Ljava/lang/Comparable;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Ljava/io/Serializable;",
        "Ljava/lang/Comparable<",
        "Lcom/wultra/android/sslpinning/model/CertificateInfo;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000>\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000f\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0012\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0008\n\u0002\u0010\u0008\n\u0002\u0008\u0006\n\u0002\u0010\u000b\n\u0002\u0010\u0000\n\u0002\u0008\u0006\u0008\u0086\u0008\u0018\u00002\u00020\u00012\u0008\u0012\u0004\u0012\u00020\u00000\u0002B\u000f\u0008\u0010\u0012\u0006\u0010\u0003\u001a\u00020\u0004\u00a2\u0006\u0002\u0010\u0005B\u001d\u0012\u0006\u0010\u0006\u001a\u00020\u0007\u0012\u0006\u0010\u0008\u001a\u00020\t\u0012\u0006\u0010\n\u001a\u00020\u000b\u00a2\u0006\u0002\u0010\u000cJ\u0011\u0010\u0013\u001a\u00020\u00142\u0006\u0010\u0015\u001a\u00020\u0000H\u0096\u0002J\t\u0010\u0016\u001a\u00020\u0007H\u00c6\u0003J\t\u0010\u0017\u001a\u00020\tH\u00c6\u0003J\t\u0010\u0018\u001a\u00020\u000bH\u00c6\u0003J\'\u0010\u0019\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u00072\u0008\u0008\u0002\u0010\u0008\u001a\u00020\t2\u0008\u0008\u0002\u0010\n\u001a\u00020\u000bH\u00c6\u0001J\u0013\u0010\u001a\u001a\u00020\u001b2\u0008\u0010\u0015\u001a\u0004\u0018\u00010\u001cH\u0096\u0002J\u0008\u0010\u001d\u001a\u00020\u0014H\u0016J\u0015\u0010\u001e\u001a\u00020\u001b2\u0006\u0010\u001f\u001a\u00020\u000bH\u0000\u00a2\u0006\u0002\u0008 J\t\u0010!\u001a\u00020\u0007H\u00d6\u0001R\u0011\u0010\u0006\u001a\u00020\u0007\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\r\u0010\u000eR\u0011\u0010\n\u001a\u00020\u000b\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000f\u0010\u0010R\u0011\u0010\u0008\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0011\u0010\u0012\u00a8\u0006\""
    }
    d2 = {
        "Lcom/wultra/android/sslpinning/model/CertificateInfo;",
        "Ljava/io/Serializable;",
        "",
        "responseEntry",
        "Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;",
        "(Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;)V",
        "commonName",
        "",
        "fingerprint",
        "",
        "expires",
        "Ljava/util/Date;",
        "(Ljava/lang/String;[BLjava/util/Date;)V",
        "getCommonName",
        "()Ljava/lang/String;",
        "getExpires",
        "()Ljava/util/Date;",
        "getFingerprint",
        "()[B",
        "compareTo",
        "",
        "other",
        "component1",
        "component2",
        "component3",
        "copy",
        "equals",
        "",
        "",
        "hashCode",
        "isExpired",
        "date",
        "isExpired$library_release",
        "toString",
        "library_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x8,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final commonName:Ljava/lang/String;

.field private final expires:Ljava/util/Date;

.field private final fingerprint:[B


# direct methods
.method public constructor <init>(Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;)V
    .locals 2

    const-string v0, "responseEntry"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    invoke-virtual {p1}, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1}, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;->getFingerprint()[B

    move-result-object v1

    .line 5
    invoke-virtual {p1}, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;->getExpires()Ljava/util/Date;

    move-result-object p1

    .line 6
    invoke-direct {p0, v0, v1, p1}, Lcom/wultra/android/sslpinning/model/CertificateInfo;-><init>(Ljava/lang/String;[BLjava/util/Date;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;[BLjava/util/Date;)V
    .locals 1

    const-string v0, "commonName"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "fingerprint"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "expires"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->commonName:Ljava/lang/String;

    .line 2
    iput-object p2, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->fingerprint:[B

    .line 3
    iput-object p3, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->expires:Ljava/util/Date;

    return-void
.end method

.method public static synthetic copy$default(Lcom/wultra/android/sslpinning/model/CertificateInfo;Ljava/lang/String;[BLjava/util/Date;ILjava/lang/Object;)Lcom/wultra/android/sslpinning/model/CertificateInfo;
    .locals 0

    .line 1
    and-int/lit8 p5, p4, 0x1

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->commonName:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p4, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->fingerprint:[B

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 14
    .line 15
    if-eqz p4, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->expires:Ljava/util/Date;

    .line 18
    .line 19
    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Lcom/wultra/android/sslpinning/model/CertificateInfo;->copy(Ljava/lang/String;[BLjava/util/Date;)Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method


# virtual methods
.method public compareTo(Lcom/wultra/android/sslpinning/model/CertificateInfo;)I
    .locals 2

    const-string v0, "other"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    iget-object v0, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->commonName:Ljava/lang/String;

    iget-object v1, p1, Lcom/wultra/android/sslpinning/model/CertificateInfo;->commonName:Ljava/lang/String;

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    .line 3
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->expires:Ljava/util/Date;

    iget-object p1, p1, Lcom/wultra/android/sslpinning/model/CertificateInfo;->expires:Ljava/util/Date;

    invoke-virtual {p0, p1}, Ljava/util/Date;->compareTo(Ljava/util/Date;)I

    move-result p0

    neg-int p0, p0

    return p0

    .line 4
    :cond_0
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->commonName:Ljava/lang/String;

    iget-object p1, p1, Lcom/wultra/android/sslpinning/model/CertificateInfo;->commonName:Ljava/lang/String;

    invoke-virtual {p0, p1}, Ljava/lang/String;->compareTo(Ljava/lang/String;)I

    move-result p0

    return p0
.end method

.method public bridge synthetic compareTo(Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Lcom/wultra/android/sslpinning/model/CertificateInfo;

    invoke-virtual {p0, p1}, Lcom/wultra/android/sslpinning/model/CertificateInfo;->compareTo(Lcom/wultra/android/sslpinning/model/CertificateInfo;)I

    move-result p0

    return p0
.end method

.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->commonName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->fingerprint:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->expires:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;[BLjava/util/Date;)Lcom/wultra/android/sslpinning/model/CertificateInfo;
    .locals 0

    .line 1
    const-string p0, "commonName"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "fingerprint"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "expires"

    .line 12
    .line 13
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 17
    .line 18
    invoke-direct {p0, p1, p2, p3}, Lcom/wultra/android/sslpinning/model/CertificateInfo;-><init>(Ljava/lang/String;[BLjava/util/Date;)V

    .line 19
    .line 20
    .line 21
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    if-eqz p1, :cond_1

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    goto :goto_0

    .line 12
    :cond_1
    const/4 v1, 0x0

    .line 13
    :goto_0
    const-class v2, Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 14
    .line 15
    invoke-virtual {v2, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    const/4 v2, 0x0

    .line 20
    if-nez v1, :cond_2

    .line 21
    .line 22
    return v2

    .line 23
    :cond_2
    const-string v1, "null cannot be cast to non-null type com.wultra.android.sslpinning.model.CertificateInfo"

    .line 24
    .line 25
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    check-cast p1, Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 29
    .line 30
    iget-object v1, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->commonName:Ljava/lang/String;

    .line 31
    .line 32
    iget-object v3, p1, Lcom/wultra/android/sslpinning/model/CertificateInfo;->commonName:Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-nez v1, :cond_3

    .line 39
    .line 40
    return v2

    .line 41
    :cond_3
    iget-object v1, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->fingerprint:[B

    .line 42
    .line 43
    iget-object v3, p1, Lcom/wultra/android/sslpinning/model/CertificateInfo;->fingerprint:[B

    .line 44
    .line 45
    invoke-static {v1, v3}, Ljava/util/Arrays;->equals([B[B)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-nez v1, :cond_4

    .line 50
    .line 51
    return v2

    .line 52
    :cond_4
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->expires:Ljava/util/Date;

    .line 53
    .line 54
    iget-object p1, p1, Lcom/wultra/android/sslpinning/model/CertificateInfo;->expires:Ljava/util/Date;

    .line 55
    .line 56
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    if-nez p0, :cond_5

    .line 61
    .line 62
    return v2

    .line 63
    :cond_5
    return v0
.end method

.method public final getCommonName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->commonName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getExpires()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->expires:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getFingerprint()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->fingerprint:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->commonName:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->fingerprint:[B

    .line 10
    .line 11
    invoke-static {v1}, Ljava/util/Arrays;->hashCode([B)I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    add-int/2addr v1, v0

    .line 16
    mul-int/lit8 v1, v1, 0x1f

    .line 17
    .line 18
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->expires:Ljava/util/Date;

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/util/Date;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    add-int/2addr p0, v1

    .line 25
    return p0
.end method

.method public final isExpired$library_release(Ljava/util/Date;)Z
    .locals 1

    .line 1
    const-string v0, "date"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->expires:Ljava/util/Date;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ljava/util/Date;->before(Ljava/util/Date;)Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "CertificateInfo(commonName="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->commonName:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", fingerprint="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->fingerprint:[B

    .line 19
    .line 20
    invoke-static {v1}, Ljava/util/Arrays;->toString([B)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v1, ", expires="

    .line 28
    .line 29
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CertificateInfo;->expires:Ljava/util/Date;

    .line 33
    .line 34
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const/16 p0, 0x29

    .line 38
    .line 39
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0
.end method
