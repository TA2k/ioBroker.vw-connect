.class public final Lcom/google/android/gms/internal/measurement/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic b:I


# instance fields
.field public final a:I


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public constructor <init>(I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lcom/google/android/gms/internal/measurement/d0;->a:I

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcom/google/android/gms/internal/measurement/d0;

    .line 6
    .line 7
    if-eqz v1, :cond_2

    .line 8
    .line 9
    check-cast p1, Lcom/google/android/gms/internal/measurement/d0;

    .line 10
    .line 11
    iget p1, p1, Lcom/google/android/gms/internal/measurement/d0;->a:I

    .line 12
    .line 13
    iget p0, p0, Lcom/google/android/gms/internal/measurement/d0;->a:I

    .line 14
    .line 15
    if-eqz p0, :cond_1

    .line 16
    .line 17
    if-ne p0, p1, :cond_2

    .line 18
    .line 19
    return v0

    .line 20
    :cond_1
    const/4 p0, 0x0

    .line 21
    throw p0

    .line 22
    :cond_2
    const/4 p0, 0x0

    .line 23
    return p0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/measurement/d0;->a:I

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const v0, -0x1cea24ec

    .line 6
    .line 7
    .line 8
    xor-int/2addr p0, v0

    .line 9
    const v0, 0x22cd8cdb

    .line 10
    .line 11
    .line 12
    mul-int/2addr p0, v0

    .line 13
    xor-int/lit8 p0, p0, 0x1

    .line 14
    .line 15
    return p0

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    throw p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget p0, p0, Lcom/google/android/gms/internal/measurement/d0;->a:I

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    if-eq p0, v0, :cond_3

    .line 5
    .line 6
    const/4 v1, 0x2

    .line 7
    if-eq p0, v1, :cond_2

    .line 8
    .line 9
    const/4 v1, 0x3

    .line 10
    if-eq p0, v1, :cond_1

    .line 11
    .line 12
    const/4 v1, 0x4

    .line 13
    if-eq p0, v1, :cond_0

    .line 14
    .line 15
    const-string p0, "null"

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const-string p0, "NO_CHECKS"

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_1
    const-string p0, "SKIP_SECURITY_CHECK"

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_2
    const-string p0, "SKIP_COMPLIANCE_CHECK"

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_3
    const-string p0, "ALL_CHECKS"

    .line 28
    .line 29
    :goto_0
    const-string v1, ""

    .line 30
    .line 31
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    add-int/lit8 v1, v1, 0x49

    .line 36
    .line 37
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    add-int/2addr v2, v1

    .line 42
    add-int/lit8 v2, v2, 0x5b

    .line 43
    .line 44
    const-string v1, "READ_AND_WRITE"

    .line 45
    .line 46
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    add-int/2addr v3, v2

    .line 51
    new-instance v2, Ljava/lang/StringBuilder;

    .line 52
    .line 53
    add-int/2addr v3, v0

    .line 54
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 55
    .line 56
    .line 57
    const-string v0, "FileComplianceOptions{fileOwner=, hasDifferentDmaOwner=false, fileChecks="

    .line 58
    .line 59
    const-string v3, ", dataForwardingNotAllowedResolver=null, multipleProductIdGroupsResolver=null, filePurpose="

    .line 60
    .line 61
    invoke-static {v2, v0, p0, v3, v1}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    const-string p0, "}"

    .line 65
    .line 66
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0
.end method
