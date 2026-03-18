.class public final Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0002\u0008\u0008\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001:\u0001\u0013B\u0013\u0012\u000c\u0010\u0002\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u0003\u00a2\u0006\u0002\u0010\u0005J\u0014\u0010\t\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u0003H\u00c6\u0003\u00a2\u0006\u0002\u0010\u0007J\u001e\u0010\n\u001a\u00020\u00002\u000e\u0008\u0002\u0010\u0002\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u0003H\u00c6\u0001\u00a2\u0006\u0002\u0010\u000bJ\u0013\u0010\u000c\u001a\u00020\r2\u0008\u0010\u000e\u001a\u0004\u0018\u00010\u0001H\u0096\u0002J\u0008\u0010\u000f\u001a\u00020\u0010H\u0016J\t\u0010\u0011\u001a\u00020\u0012H\u00d6\u0001R\u0019\u0010\u0002\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u0003\u00a2\u0006\n\n\u0002\u0010\u0008\u001a\u0004\u0008\u0006\u0010\u0007\u00a8\u0006\u0014"
    }
    d2 = {
        "Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;",
        "",
        "fingerprints",
        "",
        "Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;",
        "([Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;)V",
        "getFingerprints",
        "()[Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;",
        "[Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;",
        "component1",
        "copy",
        "([Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;)Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;",
        "equals",
        "",
        "other",
        "hashCode",
        "",
        "toString",
        "",
        "Entry",
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
.field private final fingerprints:[Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;


# direct methods
.method public constructor <init>([Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;)V
    .locals 1

    .line 1
    const-string v0, "fingerprints"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;->fingerprints:[Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;

    .line 10
    .line 11
    return-void
.end method

.method public static synthetic copy$default(Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;[Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;ILjava/lang/Object;)Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;
    .locals 0

    .line 1
    and-int/lit8 p2, p2, 0x1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;->fingerprints:[Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p0, p1}, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;->copy([Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;)Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method


# virtual methods
.method public final component1()[Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;->fingerprints:[Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy([Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;)Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;
    .locals 0

    .line 1
    const-string p0, "fingerprints"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;-><init>([Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;)V

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 3

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
    const-class v2, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;

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
    const-string v1, "null cannot be cast to non-null type com.wultra.android.sslpinning.model.GetFingerprintResponse"

    .line 24
    .line 25
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    check-cast p1, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;

    .line 29
    .line 30
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;->fingerprints:[Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;

    .line 31
    .line 32
    iget-object p1, p1, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;->fingerprints:[Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;

    .line 33
    .line 34
    invoke-static {p0, p1}, Ljava/util/Arrays;->equals([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    if-nez p0, :cond_3

    .line 39
    .line 40
    return v2

    .line 41
    :cond_3
    return v0
.end method

.method public final getFingerprints()[Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;->fingerprints:[Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;->fingerprints:[Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;

    .line 2
    .line 3
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "GetFingerprintResponse(fingerprints="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;->fingerprints:[Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;

    .line 9
    .line 10
    invoke-static {p0}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const/16 p0, 0x29

    .line 18
    .line 19
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method
