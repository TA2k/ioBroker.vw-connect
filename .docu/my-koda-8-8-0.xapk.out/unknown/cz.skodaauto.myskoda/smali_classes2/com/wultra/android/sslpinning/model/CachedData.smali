.class public final Lcom/wultra/android/sslpinning/model/CachedData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000:\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u000b\n\u0002\u0008\n\n\u0002\u0010\u000e\n\u0002\u0008\u000b\u0008\u0080\u0008\u0018\u00002\u00020\u0001B\u001d\u0012\u000c\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00030\u0002\u0012\u0006\u0010\u0006\u001a\u00020\u0005\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u0017\u0010\r\u001a\u00020\n2\u0006\u0010\t\u001a\u00020\u0005H\u0000\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\u000f\u0010\u0011\u001a\u00020\u000eH\u0000\u00a2\u0006\u0004\u0008\u000f\u0010\u0010J\u001a\u0010\u0014\u001a\u00020\u00132\u0008\u0010\u0012\u001a\u0004\u0018\u00010\u0001H\u0096\u0002\u00a2\u0006\u0004\u0008\u0014\u0010\u0015J\u000f\u0010\u0016\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u0016\u0010\u0017J\u0016\u0010\u0018\u001a\u0008\u0012\u0004\u0012\u00020\u00030\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008\u0018\u0010\u0019J\u0010\u0010\u001a\u001a\u00020\u0005H\u00c6\u0003\u00a2\u0006\u0004\u0008\u001a\u0010\u001bJ*\u0010\u001c\u001a\u00020\u00002\u000e\u0008\u0002\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00030\u00022\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0005H\u00c6\u0001\u00a2\u0006\u0004\u0008\u001c\u0010\u001dJ\u0010\u0010\u001f\u001a\u00020\u001eH\u00d6\u0001\u00a2\u0006\u0004\u0008\u001f\u0010 R(\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00030\u00028\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0004\u0010!\u001a\u0004\u0008\"\u0010\u0019\"\u0004\u0008#\u0010$R\"\u0010\u0006\u001a\u00020\u00058\u0006@\u0006X\u0086\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0006\u0010%\u001a\u0004\u0008&\u0010\u001b\"\u0004\u0008\'\u0010(\u00a8\u0006)"
    }
    d2 = {
        "Lcom/wultra/android/sslpinning/model/CachedData;",
        "",
        "",
        "Lcom/wultra/android/sslpinning/model/CertificateInfo;",
        "certificates",
        "Ljava/util/Date;",
        "nextUpdate",
        "<init>",
        "([Lcom/wultra/android/sslpinning/model/CertificateInfo;Ljava/util/Date;)V",
        "date",
        "",
        "numberOfValidCertificates$library_release",
        "(Ljava/util/Date;)I",
        "numberOfValidCertificates",
        "Llx0/b0;",
        "sort$library_release",
        "()V",
        "sort",
        "other",
        "",
        "equals",
        "(Ljava/lang/Object;)Z",
        "hashCode",
        "()I",
        "component1",
        "()[Lcom/wultra/android/sslpinning/model/CertificateInfo;",
        "component2",
        "()Ljava/util/Date;",
        "copy",
        "([Lcom/wultra/android/sslpinning/model/CertificateInfo;Ljava/util/Date;)Lcom/wultra/android/sslpinning/model/CachedData;",
        "",
        "toString",
        "()Ljava/lang/String;",
        "[Lcom/wultra/android/sslpinning/model/CertificateInfo;",
        "getCertificates",
        "setCertificates",
        "([Lcom/wultra/android/sslpinning/model/CertificateInfo;)V",
        "Ljava/util/Date;",
        "getNextUpdate",
        "setNextUpdate",
        "(Ljava/util/Date;)V",
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
.field private certificates:[Lcom/wultra/android/sslpinning/model/CertificateInfo;

.field private nextUpdate:Ljava/util/Date;


# direct methods
.method public constructor <init>([Lcom/wultra/android/sslpinning/model/CertificateInfo;Ljava/util/Date;)V
    .locals 1

    .line 1
    const-string v0, "certificates"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "nextUpdate"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lcom/wultra/android/sslpinning/model/CachedData;->certificates:[Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 15
    .line 16
    iput-object p2, p0, Lcom/wultra/android/sslpinning/model/CachedData;->nextUpdate:Ljava/util/Date;

    .line 17
    .line 18
    return-void
.end method

.method public static synthetic copy$default(Lcom/wultra/android/sslpinning/model/CachedData;[Lcom/wultra/android/sslpinning/model/CertificateInfo;Ljava/util/Date;ILjava/lang/Object;)Lcom/wultra/android/sslpinning/model/CachedData;
    .locals 0

    .line 1
    and-int/lit8 p4, p3, 0x1

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcom/wultra/android/sslpinning/model/CachedData;->certificates:[Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p3, p3, 0x2

    .line 8
    .line 9
    if-eqz p3, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcom/wultra/android/sslpinning/model/CachedData;->nextUpdate:Ljava/util/Date;

    .line 12
    .line 13
    :cond_1
    invoke-virtual {p0, p1, p2}, Lcom/wultra/android/sslpinning/model/CachedData;->copy([Lcom/wultra/android/sslpinning/model/CertificateInfo;Ljava/util/Date;)Lcom/wultra/android/sslpinning/model/CachedData;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method


# virtual methods
.method public final component1()[Lcom/wultra/android/sslpinning/model/CertificateInfo;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CachedData;->certificates:[Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CachedData;->nextUpdate:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy([Lcom/wultra/android/sslpinning/model/CertificateInfo;Ljava/util/Date;)Lcom/wultra/android/sslpinning/model/CachedData;
    .locals 0

    .line 1
    const-string p0, "certificates"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "nextUpdate"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Lcom/wultra/android/sslpinning/model/CachedData;

    .line 12
    .line 13
    invoke-direct {p0, p1, p2}, Lcom/wultra/android/sslpinning/model/CachedData;-><init>([Lcom/wultra/android/sslpinning/model/CertificateInfo;Ljava/util/Date;)V

    .line 14
    .line 15
    .line 16
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
    const-class v2, Lcom/wultra/android/sslpinning/model/CachedData;

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
    const-string v1, "null cannot be cast to non-null type com.wultra.android.sslpinning.model.CachedData"

    .line 24
    .line 25
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    check-cast p1, Lcom/wultra/android/sslpinning/model/CachedData;

    .line 29
    .line 30
    iget-object v1, p0, Lcom/wultra/android/sslpinning/model/CachedData;->certificates:[Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 31
    .line 32
    iget-object v3, p1, Lcom/wultra/android/sslpinning/model/CachedData;->certificates:[Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 33
    .line 34
    invoke-static {v1, v3}, Ljava/util/Arrays;->equals([Ljava/lang/Object;[Ljava/lang/Object;)Z

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
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CachedData;->nextUpdate:Ljava/util/Date;

    .line 42
    .line 43
    iget-object p1, p1, Lcom/wultra/android/sslpinning/model/CachedData;->nextUpdate:Ljava/util/Date;

    .line 44
    .line 45
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    if-nez p0, :cond_4

    .line 50
    .line 51
    return v2

    .line 52
    :cond_4
    return v0
.end method

.method public final getCertificates()[Lcom/wultra/android/sslpinning/model/CertificateInfo;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CachedData;->certificates:[Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getNextUpdate()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CachedData;->nextUpdate:Ljava/util/Date;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/wultra/android/sslpinning/model/CachedData;->certificates:[Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CachedData;->nextUpdate:Ljava/util/Date;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/util/Date;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    return p0
.end method

.method public final numberOfValidCertificates$library_release(Ljava/util/Date;)I
    .locals 4

    .line 1
    const-string v0, "date"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CachedData;->certificates:[Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 7
    .line 8
    array-length v0, p0

    .line 9
    const/4 v1, 0x0

    .line 10
    move v2, v1

    .line 11
    :goto_0
    if-ge v1, v0, :cond_1

    .line 12
    .line 13
    aget-object v3, p0, v1

    .line 14
    .line 15
    invoke-virtual {v3, p1}, Lcom/wultra/android/sslpinning/model/CertificateInfo;->isExpired$library_release(Ljava/util/Date;)Z

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    if-nez v3, :cond_0

    .line 20
    .line 21
    add-int/lit8 v2, v2, 0x1

    .line 22
    .line 23
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    return v2
.end method

.method public final setCertificates([Lcom/wultra/android/sslpinning/model/CertificateInfo;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/wultra/android/sslpinning/model/CachedData;->certificates:[Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 7
    .line 8
    return-void
.end method

.method public final setNextUpdate(Ljava/util/Date;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/wultra/android/sslpinning/model/CachedData;->nextUpdate:Ljava/util/Date;

    .line 7
    .line 8
    return-void
.end method

.method public final sort$library_release()V
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CachedData;->certificates:[Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 2
    .line 3
    check-cast p0, [Ljava/lang/Comparable;

    .line 4
    .line 5
    const-string v0, "<this>"

    .line 6
    .line 7
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    array-length v0, p0

    .line 11
    const/4 v1, 0x1

    .line 12
    if-le v0, v1, :cond_0

    .line 13
    .line 14
    invoke-static {p0}, Ljava/util/Arrays;->sort([Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    :cond_0
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "CachedData(certificates="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lcom/wultra/android/sslpinning/model/CachedData;->certificates:[Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 9
    .line 10
    invoke-static {v1}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v1, ", nextUpdate="

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    iget-object p0, p0, Lcom/wultra/android/sslpinning/model/CachedData;->nextUpdate:Ljava/util/Date;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const/16 p0, 0x29

    .line 28
    .line 29
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method
