.class public final Lcz/myskoda/api/vas/UserStatusResponseDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00006\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0011\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0000\u0008\u0086\u0008\u0018\u00002\u00020\u0001B1\u0012\n\u0008\u0003\u0010\u0002\u001a\u0004\u0018\u00010\u0003\u0012\u0010\u0008\u0003\u0010\u0004\u001a\n\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u0005\u0012\n\u0008\u0003\u0010\u0007\u001a\u0004\u0018\u00010\u0008\u00a2\u0006\u0004\u0008\t\u0010\nJ\u000b\u0010\u0015\u001a\u0004\u0018\u00010\u0003H\u00c6\u0003J\u0011\u0010\u0016\u001a\n\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u0005H\u00c6\u0003J\u000b\u0010\u0017\u001a\u0004\u0018\u00010\u0008H\u00c6\u0003J3\u0010\u0018\u001a\u00020\u00002\n\u0008\u0003\u0010\u0002\u001a\u0004\u0018\u00010\u00032\u0010\u0008\u0003\u0010\u0004\u001a\n\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u00052\n\u0008\u0003\u0010\u0007\u001a\u0004\u0018\u00010\u0008H\u00c6\u0001J\u0013\u0010\u0019\u001a\u00020\u001a2\u0008\u0010\u001b\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u001c\u001a\u00020\u001dH\u00d6\u0001J\t\u0010\u001e\u001a\u00020\u001fH\u00d6\u0001R\u001e\u0010\u0002\u001a\u0004\u0018\u00010\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000b\u0010\u000c\u001a\u0004\u0008\r\u0010\u000eR$\u0010\u0004\u001a\n\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000f\u0010\u000c\u001a\u0004\u0008\u0010\u0010\u0011R\u001e\u0010\u0007\u001a\u0004\u0018\u00010\u00088\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0012\u0010\u000c\u001a\u0004\u0008\u0013\u0010\u0014\u00a8\u0006 "
    }
    d2 = {
        "Lcz/myskoda/api/vas/UserStatusResponseDto;",
        "",
        "userIdentification",
        "Lcz/myskoda/api/vas/UserIdentificationDto;",
        "vehiclesEnrollments",
        "",
        "Lcz/myskoda/api/vas/VehicleEnrollmentDto;",
        "profileEnrichment",
        "Lcz/myskoda/api/vas/ProfileEnrichmentDto;",
        "<init>",
        "(Lcz/myskoda/api/vas/UserIdentificationDto;Ljava/util/List;Lcz/myskoda/api/vas/ProfileEnrichmentDto;)V",
        "getUserIdentification$annotations",
        "()V",
        "getUserIdentification",
        "()Lcz/myskoda/api/vas/UserIdentificationDto;",
        "getVehiclesEnrollments$annotations",
        "getVehiclesEnrollments",
        "()Ljava/util/List;",
        "getProfileEnrichment$annotations",
        "getProfileEnrichment",
        "()Lcz/myskoda/api/vas/ProfileEnrichmentDto;",
        "component1",
        "component2",
        "component3",
        "copy",
        "equals",
        "",
        "other",
        "hashCode",
        "",
        "toString",
        "",
        "vas-api_release"
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
.field private final profileEnrichment:Lcz/myskoda/api/vas/ProfileEnrichmentDto;

.field private final userIdentification:Lcz/myskoda/api/vas/UserIdentificationDto;

.field private final vehiclesEnrollments:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/vas/VehicleEnrollmentDto;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 6

    .line 1
    const/4 v4, 0x7

    const/4 v5, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    move-object v0, p0

    invoke-direct/range {v0 .. v5}, Lcz/myskoda/api/vas/UserStatusResponseDto;-><init>(Lcz/myskoda/api/vas/UserIdentificationDto;Ljava/util/List;Lcz/myskoda/api/vas/ProfileEnrichmentDto;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Lcz/myskoda/api/vas/UserIdentificationDto;Ljava/util/List;Lcz/myskoda/api/vas/ProfileEnrichmentDto;)V
    .locals 0
    .param p1    # Lcz/myskoda/api/vas/UserIdentificationDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "userIdentification"
        .end annotation
    .end param
    .param p2    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "vehiclesEnrollments"
        .end annotation
    .end param
    .param p3    # Lcz/myskoda/api/vas/ProfileEnrichmentDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "profileEnrichment"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/vas/UserIdentificationDto;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/vas/VehicleEnrollmentDto;",
            ">;",
            "Lcz/myskoda/api/vas/ProfileEnrichmentDto;",
            ")V"
        }
    .end annotation

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->userIdentification:Lcz/myskoda/api/vas/UserIdentificationDto;

    .line 4
    iput-object p2, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->vehiclesEnrollments:Ljava/util/List;

    .line 5
    iput-object p3, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->profileEnrichment:Lcz/myskoda/api/vas/ProfileEnrichmentDto;

    return-void
.end method

.method public synthetic constructor <init>(Lcz/myskoda/api/vas/UserIdentificationDto;Ljava/util/List;Lcz/myskoda/api/vas/ProfileEnrichmentDto;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p5, p4, 0x1

    const/4 v0, 0x0

    if-eqz p5, :cond_0

    move-object p1, v0

    :cond_0
    and-int/lit8 p5, p4, 0x2

    if-eqz p5, :cond_1

    move-object p2, v0

    :cond_1
    and-int/lit8 p4, p4, 0x4

    if-eqz p4, :cond_2

    move-object p3, v0

    .line 6
    :cond_2
    invoke-direct {p0, p1, p2, p3}, Lcz/myskoda/api/vas/UserStatusResponseDto;-><init>(Lcz/myskoda/api/vas/UserIdentificationDto;Ljava/util/List;Lcz/myskoda/api/vas/ProfileEnrichmentDto;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/vas/UserStatusResponseDto;Lcz/myskoda/api/vas/UserIdentificationDto;Ljava/util/List;Lcz/myskoda/api/vas/ProfileEnrichmentDto;ILjava/lang/Object;)Lcz/myskoda/api/vas/UserStatusResponseDto;
    .locals 0

    .line 1
    and-int/lit8 p5, p4, 0x1

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->userIdentification:Lcz/myskoda/api/vas/UserIdentificationDto;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p4, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->vehiclesEnrollments:Ljava/util/List;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 14
    .line 15
    if-eqz p4, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->profileEnrichment:Lcz/myskoda/api/vas/ProfileEnrichmentDto;

    .line 18
    .line 19
    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Lcz/myskoda/api/vas/UserStatusResponseDto;->copy(Lcz/myskoda/api/vas/UserIdentificationDto;Ljava/util/List;Lcz/myskoda/api/vas/ProfileEnrichmentDto;)Lcz/myskoda/api/vas/UserStatusResponseDto;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public static synthetic getProfileEnrichment$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "profileEnrichment"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getUserIdentification$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "userIdentification"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getVehiclesEnrollments$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "vehiclesEnrollments"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Lcz/myskoda/api/vas/UserIdentificationDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->userIdentification:Lcz/myskoda/api/vas/UserIdentificationDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/vas/VehicleEnrollmentDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->vehiclesEnrollments:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Lcz/myskoda/api/vas/ProfileEnrichmentDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->profileEnrichment:Lcz/myskoda/api/vas/ProfileEnrichmentDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Lcz/myskoda/api/vas/UserIdentificationDto;Ljava/util/List;Lcz/myskoda/api/vas/ProfileEnrichmentDto;)Lcz/myskoda/api/vas/UserStatusResponseDto;
    .locals 0
    .param p1    # Lcz/myskoda/api/vas/UserIdentificationDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "userIdentification"
        .end annotation
    .end param
    .param p2    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "vehiclesEnrollments"
        .end annotation
    .end param
    .param p3    # Lcz/myskoda/api/vas/ProfileEnrichmentDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "profileEnrichment"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/vas/UserIdentificationDto;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/vas/VehicleEnrollmentDto;",
            ">;",
            "Lcz/myskoda/api/vas/ProfileEnrichmentDto;",
            ")",
            "Lcz/myskoda/api/vas/UserStatusResponseDto;"
        }
    .end annotation

    .line 1
    new-instance p0, Lcz/myskoda/api/vas/UserStatusResponseDto;

    .line 2
    .line 3
    invoke-direct {p0, p1, p2, p3}, Lcz/myskoda/api/vas/UserStatusResponseDto;-><init>(Lcz/myskoda/api/vas/UserIdentificationDto;Ljava/util/List;Lcz/myskoda/api/vas/ProfileEnrichmentDto;)V

    .line 4
    .line 5
    .line 6
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
    instance-of v1, p1, Lcz/myskoda/api/vas/UserStatusResponseDto;

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
    check-cast p1, Lcz/myskoda/api/vas/UserStatusResponseDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->userIdentification:Lcz/myskoda/api/vas/UserIdentificationDto;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/vas/UserStatusResponseDto;->userIdentification:Lcz/myskoda/api/vas/UserIdentificationDto;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->vehiclesEnrollments:Ljava/util/List;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/myskoda/api/vas/UserStatusResponseDto;->vehiclesEnrollments:Ljava/util/List;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object p0, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->profileEnrichment:Lcz/myskoda/api/vas/ProfileEnrichmentDto;

    .line 36
    .line 37
    iget-object p1, p1, Lcz/myskoda/api/vas/UserStatusResponseDto;->profileEnrichment:Lcz/myskoda/api/vas/ProfileEnrichmentDto;

    .line 38
    .line 39
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    if-nez p0, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    return v0
.end method

.method public final getProfileEnrichment()Lcz/myskoda/api/vas/ProfileEnrichmentDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->profileEnrichment:Lcz/myskoda/api/vas/ProfileEnrichmentDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getUserIdentification()Lcz/myskoda/api/vas/UserIdentificationDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->userIdentification:Lcz/myskoda/api/vas/UserIdentificationDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getVehiclesEnrollments()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/vas/VehicleEnrollmentDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->vehiclesEnrollments:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->userIdentification:Lcz/myskoda/api/vas/UserIdentificationDto;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    move v0, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {v0}, Lcz/myskoda/api/vas/UserIdentificationDto;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    :goto_0
    mul-int/lit8 v0, v0, 0x1f

    .line 13
    .line 14
    iget-object v2, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->vehiclesEnrollments:Ljava/util/List;

    .line 15
    .line 16
    if-nez v2, :cond_1

    .line 17
    .line 18
    move v2, v1

    .line 19
    goto :goto_1

    .line 20
    :cond_1
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    :goto_1
    add-int/2addr v0, v2

    .line 25
    mul-int/lit8 v0, v0, 0x1f

    .line 26
    .line 27
    iget-object p0, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->profileEnrichment:Lcz/myskoda/api/vas/ProfileEnrichmentDto;

    .line 28
    .line 29
    if-nez p0, :cond_2

    .line 30
    .line 31
    goto :goto_2

    .line 32
    :cond_2
    invoke-virtual {p0}, Lcz/myskoda/api/vas/ProfileEnrichmentDto;->hashCode()I

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    :goto_2
    add-int/2addr v0, v1

    .line 37
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->userIdentification:Lcz/myskoda/api/vas/UserIdentificationDto;

    .line 2
    .line 3
    iget-object v1, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->vehiclesEnrollments:Ljava/util/List;

    .line 4
    .line 5
    iget-object p0, p0, Lcz/myskoda/api/vas/UserStatusResponseDto;->profileEnrichment:Lcz/myskoda/api/vas/ProfileEnrichmentDto;

    .line 6
    .line 7
    new-instance v2, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v3, "UserStatusResponseDto(userIdentification="

    .line 10
    .line 11
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v0, ", vehiclesEnrollments="

    .line 18
    .line 19
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v0, ", profileEnrichment="

    .line 26
    .line 27
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string p0, ")"

    .line 34
    .line 35
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method
