.class public final Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0007\n\u0002\u0008\u0013\n\u0002\u0010\u000b\n\u0002\u0008\u0004\u0008\u0086\u0008\u0018\u00002\u00020\u0001B)\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\n\u0008\u0003\u0010\u0004\u001a\u0004\u0018\u00010\u0005\u0012\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u0007\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\t\u0010\u0015\u001a\u00020\u0003H\u00c6\u0003J\u000b\u0010\u0016\u001a\u0004\u0018\u00010\u0005H\u00c6\u0003J\u0010\u0010\u0017\u001a\u0004\u0018\u00010\u0007H\u00c6\u0003\u00a2\u0006\u0002\u0010\u0013J0\u0010\u0018\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\n\u0008\u0003\u0010\u0004\u001a\u0004\u0018\u00010\u00052\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u0007H\u00c6\u0001\u00a2\u0006\u0002\u0010\u0019J\u0013\u0010\u001a\u001a\u00020\u001b2\u0008\u0010\u001c\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u001d\u001a\u00020\u0003H\u00d6\u0001J\t\u0010\u001e\u001a\u00020\u0005H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\n\u0010\u000b\u001a\u0004\u0008\u000c\u0010\rR\u001e\u0010\u0004\u001a\u0004\u0018\u00010\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000e\u0010\u000b\u001a\u0004\u0008\u000f\u0010\u0010R \u0010\u0006\u001a\u0004\u0018\u00010\u00078\u0006X\u0087\u0004\u00a2\u0006\u0010\n\u0002\u0010\u0014\u0012\u0004\u0008\u0011\u0010\u000b\u001a\u0004\u0008\u0012\u0010\u0013\u00a8\u0006\u001f"
    }
    d2 = {
        "Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;",
        "",
        "powerInKW",
        "",
        "type",
        "",
        "capacityInLiters",
        "",
        "<init>",
        "(ILjava/lang/String;Ljava/lang/Float;)V",
        "getPowerInKW$annotations",
        "()V",
        "getPowerInKW",
        "()I",
        "getType$annotations",
        "getType",
        "()Ljava/lang/String;",
        "getCapacityInLiters$annotations",
        "getCapacityInLiters",
        "()Ljava/lang/Float;",
        "Ljava/lang/Float;",
        "component1",
        "component2",
        "component3",
        "copy",
        "(ILjava/lang/String;Ljava/lang/Float;)Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;",
        "equals",
        "",
        "other",
        "hashCode",
        "toString",
        "bff-api_release"
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
.field private final capacityInLiters:Ljava/lang/Float;

.field private final powerInKW:I

.field private final type:Ljava/lang/String;


# direct methods
.method public constructor <init>(ILjava/lang/String;Ljava/lang/Float;)V
    .locals 0
    .param p1    # I
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "powerInKW"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "type"
        .end annotation
    .end param
    .param p3    # Ljava/lang/Float;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "capacityInLiters"
        .end annotation
    .end param

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput p1, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->powerInKW:I

    .line 3
    iput-object p2, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->type:Ljava/lang/String;

    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->capacityInLiters:Ljava/lang/Float;

    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/String;Ljava/lang/Float;ILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p5, p4, 0x2

    const/4 v0, 0x0

    if-eqz p5, :cond_0

    move-object p2, v0

    :cond_0
    and-int/lit8 p4, p4, 0x4

    if-eqz p4, :cond_1

    move-object p3, v0

    .line 5
    :cond_1
    invoke-direct {p0, p1, p2, p3}, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;-><init>(ILjava/lang/String;Ljava/lang/Float;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;ILjava/lang/String;Ljava/lang/Float;ILjava/lang/Object;)Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;
    .locals 0

    .line 1
    and-int/lit8 p5, p4, 0x1

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    iget p1, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->powerInKW:I

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p4, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->type:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 14
    .line 15
    if-eqz p4, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->capacityInLiters:Ljava/lang/Float;

    .line 18
    .line 19
    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->copy(ILjava/lang/String;Ljava/lang/Float;)Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public static synthetic getCapacityInLiters$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "capacityInLiters"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getPowerInKW$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "powerInKW"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getType$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "type"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->powerInKW:I

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->type:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/lang/Float;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->capacityInLiters:Ljava/lang/Float;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(ILjava/lang/String;Ljava/lang/Float;)Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;
    .locals 0
    .param p1    # I
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "powerInKW"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "type"
        .end annotation
    .end param
    .param p3    # Ljava/lang/Float;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "capacityInLiters"
        .end annotation
    .end param

    .line 1
    new-instance p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;

    .line 2
    .line 3
    invoke-direct {p0, p1, p2, p3}, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;-><init>(ILjava/lang/String;Ljava/lang/Float;)V

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
    instance-of v1, p1, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;

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
    check-cast p1, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;

    .line 12
    .line 13
    iget v1, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->powerInKW:I

    .line 14
    .line 15
    iget v3, p1, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->powerInKW:I

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->type:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v3, p1, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->type:Ljava/lang/String;

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
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->capacityInLiters:Ljava/lang/Float;

    .line 32
    .line 33
    iget-object p1, p1, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->capacityInLiters:Ljava/lang/Float;

    .line 34
    .line 35
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    if-nez p0, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    return v0
.end method

.method public final getCapacityInLiters()Ljava/lang/Float;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->capacityInLiters:Ljava/lang/Float;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPowerInKW()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->powerInKW:I

    .line 2
    .line 3
    return p0
.end method

.method public final getType()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->type:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->powerInKW:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->hashCode(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->type:Ljava/lang/String;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    if-nez v1, :cond_0

    .line 13
    .line 14
    move v1, v2

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    :goto_0
    add-int/2addr v0, v1

    .line 21
    mul-int/lit8 v0, v0, 0x1f

    .line 22
    .line 23
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->capacityInLiters:Ljava/lang/Float;

    .line 24
    .line 25
    if-nez p0, :cond_1

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    :goto_1
    add-int/2addr v0, v2

    .line 33
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget v0, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->powerInKW:I

    .line 2
    .line 3
    iget-object v1, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->type:Ljava/lang/String;

    .line 4
    .line 5
    iget-object p0, p0, Lcz/myskoda/api/bff_garage/v2/VehicleSpecificationEngineDto;->capacityInLiters:Ljava/lang/Float;

    .line 6
    .line 7
    const-string v2, ", type="

    .line 8
    .line 9
    const-string v3, ", capacityInLiters="

    .line 10
    .line 11
    const-string v4, "VehicleSpecificationEngineDto(powerInKW="

    .line 12
    .line 13
    invoke-static {v4, v0, v2, v1, v3}, Lf2/m0;->o(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string p0, ")"

    .line 21
    .line 22
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method
