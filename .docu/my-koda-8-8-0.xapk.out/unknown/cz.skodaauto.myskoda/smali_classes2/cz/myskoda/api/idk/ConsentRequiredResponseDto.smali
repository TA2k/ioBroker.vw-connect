.class public final Lcz/myskoda/api/idk/ConsentRequiredResponseDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0017\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0000\u0008\u0086\u0008\u0018\u00002\u00020\u0001B3\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0005\u0012\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u0007\u0012\n\u0008\u0003\u0010\u0008\u001a\u0004\u0018\u00010\t\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\t\u0010\u0019\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u001a\u001a\u00020\u0005H\u00c6\u0003J\u000b\u0010\u001b\u001a\u0004\u0018\u00010\u0007H\u00c6\u0003J\u000b\u0010\u001c\u001a\u0004\u0018\u00010\tH\u00c6\u0003J5\u0010\u001d\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00052\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u00072\n\u0008\u0003\u0010\u0008\u001a\u0004\u0018\u00010\tH\u00c6\u0001J\u0013\u0010\u001e\u001a\u00020\u00032\u0008\u0010\u001f\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010 \u001a\u00020!H\u00d6\u0001J\t\u0010\"\u001a\u00020#H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000c\u0010\r\u001a\u0004\u0008\u000e\u0010\u000fR\u001c\u0010\u0004\u001a\u00020\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0010\u0010\r\u001a\u0004\u0008\u0011\u0010\u0012R\u001e\u0010\u0006\u001a\u0004\u0018\u00010\u00078\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0013\u0010\r\u001a\u0004\u0008\u0014\u0010\u0015R\u001e\u0010\u0008\u001a\u0004\u0018\u00010\t8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0016\u0010\r\u001a\u0004\u0008\u0017\u0010\u0018\u00a8\u0006$"
    }
    d2 = {
        "Lcz/myskoda/api/idk/ConsentRequiredResponseDto;",
        "",
        "consentRequired",
        "",
        "versionDetails",
        "Lcz/myskoda/api/idk/VersionDetailsNoRefsDto;",
        "consent",
        "Lcz/myskoda/api/idk/ConsentNoRefsDto;",
        "verbose",
        "Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;",
        "<init>",
        "(ZLcz/myskoda/api/idk/VersionDetailsNoRefsDto;Lcz/myskoda/api/idk/ConsentNoRefsDto;Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;)V",
        "getConsentRequired$annotations",
        "()V",
        "getConsentRequired",
        "()Z",
        "getVersionDetails$annotations",
        "getVersionDetails",
        "()Lcz/myskoda/api/idk/VersionDetailsNoRefsDto;",
        "getConsent$annotations",
        "getConsent",
        "()Lcz/myskoda/api/idk/ConsentNoRefsDto;",
        "getVerbose$annotations",
        "getVerbose",
        "()Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;",
        "component1",
        "component2",
        "component3",
        "component4",
        "copy",
        "equals",
        "other",
        "hashCode",
        "",
        "toString",
        "",
        "idk-api_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final consent:Lcz/myskoda/api/idk/ConsentNoRefsDto;

.field private final consentRequired:Z

.field private final verbose:Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;

.field private final versionDetails:Lcz/myskoda/api/idk/VersionDetailsNoRefsDto;


# direct methods
.method public constructor <init>(ZLcz/myskoda/api/idk/VersionDetailsNoRefsDto;Lcz/myskoda/api/idk/ConsentNoRefsDto;Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;)V
    .locals 1
    .param p1    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "consentRequired"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/idk/VersionDetailsNoRefsDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "versionDetails"
        .end annotation
    .end param
    .param p3    # Lcz/myskoda/api/idk/ConsentNoRefsDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "consent"
        .end annotation
    .end param
    .param p4    # Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "verbose"
        .end annotation
    .end param

    const-string v0, "versionDetails"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-boolean p1, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->consentRequired:Z

    .line 3
    iput-object p2, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->versionDetails:Lcz/myskoda/api/idk/VersionDetailsNoRefsDto;

    .line 4
    iput-object p3, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->consent:Lcz/myskoda/api/idk/ConsentNoRefsDto;

    .line 5
    iput-object p4, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->verbose:Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;

    return-void
.end method

.method public synthetic constructor <init>(ZLcz/myskoda/api/idk/VersionDetailsNoRefsDto;Lcz/myskoda/api/idk/ConsentNoRefsDto;Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p6, p5, 0x4

    const/4 v0, 0x0

    if-eqz p6, :cond_0

    move-object p3, v0

    :cond_0
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_1

    move-object p4, v0

    .line 6
    :cond_1
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;-><init>(ZLcz/myskoda/api/idk/VersionDetailsNoRefsDto;Lcz/myskoda/api/idk/ConsentNoRefsDto;Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/idk/ConsentRequiredResponseDto;ZLcz/myskoda/api/idk/VersionDetailsNoRefsDto;Lcz/myskoda/api/idk/ConsentNoRefsDto;Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;ILjava/lang/Object;)Lcz/myskoda/api/idk/ConsentRequiredResponseDto;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-boolean p1, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->consentRequired:Z

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->versionDetails:Lcz/myskoda/api/idk/VersionDetailsNoRefsDto;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->consent:Lcz/myskoda/api/idk/ConsentNoRefsDto;

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->verbose:Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->copy(ZLcz/myskoda/api/idk/VersionDetailsNoRefsDto;Lcz/myskoda/api/idk/ConsentNoRefsDto;Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;)Lcz/myskoda/api/idk/ConsentRequiredResponseDto;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static synthetic getConsent$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "consent"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getConsentRequired$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "consentRequired"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getVerbose$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "verbose"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getVersionDetails$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "versionDetails"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->consentRequired:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Lcz/myskoda/api/idk/VersionDetailsNoRefsDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->versionDetails:Lcz/myskoda/api/idk/VersionDetailsNoRefsDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Lcz/myskoda/api/idk/ConsentNoRefsDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->consent:Lcz/myskoda/api/idk/ConsentNoRefsDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->verbose:Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(ZLcz/myskoda/api/idk/VersionDetailsNoRefsDto;Lcz/myskoda/api/idk/ConsentNoRefsDto;Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;)Lcz/myskoda/api/idk/ConsentRequiredResponseDto;
    .locals 0
    .param p1    # Z
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "consentRequired"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/idk/VersionDetailsNoRefsDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "versionDetails"
        .end annotation
    .end param
    .param p3    # Lcz/myskoda/api/idk/ConsentNoRefsDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "consent"
        .end annotation
    .end param
    .param p4    # Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "verbose"
        .end annotation
    .end param

    .line 1
    const-string p0, "versionDetails"

    .line 2
    .line 3
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;-><init>(ZLcz/myskoda/api/idk/VersionDetailsNoRefsDto;Lcz/myskoda/api/idk/ConsentNoRefsDto;Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;)V

    .line 9
    .line 10
    .line 11
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
    instance-of v1, p1, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;

    .line 12
    .line 13
    iget-boolean v1, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->consentRequired:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->consentRequired:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->versionDetails:Lcz/myskoda/api/idk/VersionDetailsNoRefsDto;

    .line 21
    .line 22
    iget-object v3, p1, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->versionDetails:Lcz/myskoda/api/idk/VersionDetailsNoRefsDto;

    .line 23
    .line 24
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-nez v1, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->consent:Lcz/myskoda/api/idk/ConsentNoRefsDto;

    .line 32
    .line 33
    iget-object v3, p1, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->consent:Lcz/myskoda/api/idk/ConsentNoRefsDto;

    .line 34
    .line 35
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-nez v1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object p0, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->verbose:Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;

    .line 43
    .line 44
    iget-object p1, p1, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->verbose:Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;

    .line 45
    .line 46
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    if-nez p0, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    return v0
.end method

.method public final getConsent()Lcz/myskoda/api/idk/ConsentNoRefsDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->consent:Lcz/myskoda/api/idk/ConsentNoRefsDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getConsentRequired()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->consentRequired:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getVerbose()Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->verbose:Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVersionDetails()Lcz/myskoda/api/idk/VersionDetailsNoRefsDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->versionDetails:Lcz/myskoda/api/idk/VersionDetailsNoRefsDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->consentRequired:Z

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->versionDetails:Lcz/myskoda/api/idk/VersionDetailsNoRefsDto;

    .line 10
    .line 11
    invoke-virtual {v1}, Lcz/myskoda/api/idk/VersionDetailsNoRefsDto;->hashCode()I

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
    iget-object v0, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->consent:Lcz/myskoda/api/idk/ConsentNoRefsDto;

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    if-nez v0, :cond_0

    .line 22
    .line 23
    move v0, v2

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    invoke-virtual {v0}, Lcz/myskoda/api/idk/ConsentNoRefsDto;->hashCode()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    :goto_0
    add-int/2addr v1, v0

    .line 30
    mul-int/lit8 v1, v1, 0x1f

    .line 31
    .line 32
    iget-object p0, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->verbose:Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;

    .line 33
    .line 34
    if-nez p0, :cond_1

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    invoke-virtual {p0}, Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;->hashCode()I

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    :goto_1
    add-int/2addr v1, v2

    .line 42
    return v1
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-boolean v0, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->consentRequired:Z

    .line 2
    .line 3
    iget-object v1, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->versionDetails:Lcz/myskoda/api/idk/VersionDetailsNoRefsDto;

    .line 4
    .line 5
    iget-object v2, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->consent:Lcz/myskoda/api/idk/ConsentNoRefsDto;

    .line 6
    .line 7
    iget-object p0, p0, Lcz/myskoda/api/idk/ConsentRequiredResponseDto;->verbose:Lcz/myskoda/api/idk/ConsentRequiredVerboseDto;

    .line 8
    .line 9
    new-instance v3, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v4, "ConsentRequiredResponseDto(consentRequired="

    .line 12
    .line 13
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v0, ", versionDetails="

    .line 20
    .line 21
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v0, ", consent="

    .line 28
    .line 29
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v0, ", verbose="

    .line 36
    .line 37
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string p0, ")"

    .line 44
    .line 45
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method
