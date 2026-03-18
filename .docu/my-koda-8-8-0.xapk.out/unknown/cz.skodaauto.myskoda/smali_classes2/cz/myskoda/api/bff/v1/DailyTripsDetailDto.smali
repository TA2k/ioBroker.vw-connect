.class public final Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00006\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0015\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0000\u0008\u0086\u0008\u0018\u00002\u00020\u0001B7\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u000e\u0008\u0001\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00060\u0005\u0012\u0008\u0008\u0001\u0010\u0007\u001a\u00020\u0008\u0012\n\u0008\u0003\u0010\t\u001a\u0004\u0018\u00010\n\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\t\u0010\u001a\u001a\u00020\u0003H\u00c6\u0003J\u000f\u0010\u001b\u001a\u0008\u0012\u0004\u0012\u00020\u00060\u0005H\u00c6\u0003J\t\u0010\u001c\u001a\u00020\u0008H\u00c6\u0003J\u000b\u0010\u001d\u001a\u0004\u0018\u00010\nH\u00c6\u0003J9\u0010\u001e\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u000e\u0008\u0003\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00060\u00052\u0008\u0008\u0003\u0010\u0007\u001a\u00020\u00082\n\u0008\u0003\u0010\t\u001a\u0004\u0018\u00010\nH\u00c6\u0001J\u0013\u0010\u001f\u001a\u00020 2\u0008\u0010!\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\"\u001a\u00020\u0008H\u00d6\u0001J\t\u0010#\u001a\u00020$H\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\r\u0010\u000e\u001a\u0004\u0008\u000f\u0010\u0010R\"\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00060\u00058\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0011\u0010\u000e\u001a\u0004\u0008\u0012\u0010\u0013R\u001c\u0010\u0007\u001a\u00020\u00088\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0014\u0010\u000e\u001a\u0004\u0008\u0015\u0010\u0016R\u001e\u0010\t\u001a\u0004\u0018\u00010\n8\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0017\u0010\u000e\u001a\u0004\u0008\u0018\u0010\u0019\u00a8\u0006%"
    }
    d2 = {
        "Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;",
        "",
        "date",
        "Ljava/time/LocalDate;",
        "trips",
        "",
        "Lcz/myskoda/api/bff/v1/SingleTripDto;",
        "overallMileage",
        "",
        "overallCost",
        "Lcz/myskoda/api/bff/v1/FuelCostDto;",
        "<init>",
        "(Ljava/time/LocalDate;Ljava/util/List;ILcz/myskoda/api/bff/v1/FuelCostDto;)V",
        "getDate$annotations",
        "()V",
        "getDate",
        "()Ljava/time/LocalDate;",
        "getTrips$annotations",
        "getTrips",
        "()Ljava/util/List;",
        "getOverallMileage$annotations",
        "getOverallMileage",
        "()I",
        "getOverallCost$annotations",
        "getOverallCost",
        "()Lcz/myskoda/api/bff/v1/FuelCostDto;",
        "component1",
        "component2",
        "component3",
        "component4",
        "copy",
        "equals",
        "",
        "other",
        "hashCode",
        "toString",
        "",
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
.field private final date:Ljava/time/LocalDate;

.field private final overallCost:Lcz/myskoda/api/bff/v1/FuelCostDto;

.field private final overallMileage:I

.field private final trips:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/SingleTripDto;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/time/LocalDate;Ljava/util/List;ILcz/myskoda/api/bff/v1/FuelCostDto;)V
    .locals 1
    .param p1    # Ljava/time/LocalDate;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "date"
        .end annotation
    .end param
    .param p2    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "trips"
        .end annotation
    .end param
    .param p3    # I
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallMileage"
        .end annotation
    .end param
    .param p4    # Lcz/myskoda/api/bff/v1/FuelCostDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallCost"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/time/LocalDate;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/SingleTripDto;",
            ">;I",
            "Lcz/myskoda/api/bff/v1/FuelCostDto;",
            ")V"
        }
    .end annotation

    const-string v0, "date"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "trips"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->date:Ljava/time/LocalDate;

    .line 3
    iput-object p2, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->trips:Ljava/util/List;

    .line 4
    iput p3, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->overallMileage:I

    .line 5
    iput-object p4, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->overallCost:Lcz/myskoda/api/bff/v1/FuelCostDto;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/time/LocalDate;Ljava/util/List;ILcz/myskoda/api/bff/v1/FuelCostDto;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_0

    const/4 p4, 0x0

    .line 6
    :cond_0
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;-><init>(Ljava/time/LocalDate;Ljava/util/List;ILcz/myskoda/api/bff/v1/FuelCostDto;)V

    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;Ljava/time/LocalDate;Ljava/util/List;ILcz/myskoda/api/bff/v1/FuelCostDto;ILjava/lang/Object;)Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->date:Ljava/time/LocalDate;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->trips:Ljava/util/List;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget p3, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->overallMileage:I

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->overallCost:Lcz/myskoda/api/bff/v1/FuelCostDto;

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->copy(Ljava/time/LocalDate;Ljava/util/List;ILcz/myskoda/api/bff/v1/FuelCostDto;)Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static synthetic getDate$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "date"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getOverallCost$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "overallCost"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getOverallMileage$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "overallMileage"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getTrips$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "trips"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Ljava/time/LocalDate;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->date:Ljava/time/LocalDate;

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
            "Lcz/myskoda/api/bff/v1/SingleTripDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->trips:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->overallMileage:I

    .line 2
    .line 3
    return p0
.end method

.method public final component4()Lcz/myskoda/api/bff/v1/FuelCostDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->overallCost:Lcz/myskoda/api/bff/v1/FuelCostDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/time/LocalDate;Ljava/util/List;ILcz/myskoda/api/bff/v1/FuelCostDto;)Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;
    .locals 0
    .param p1    # Ljava/time/LocalDate;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "date"
        .end annotation
    .end param
    .param p2    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "trips"
        .end annotation
    .end param
    .param p3    # I
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallMileage"
        .end annotation
    .end param
    .param p4    # Lcz/myskoda/api/bff/v1/FuelCostDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "overallCost"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/time/LocalDate;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/SingleTripDto;",
            ">;I",
            "Lcz/myskoda/api/bff/v1/FuelCostDto;",
            ")",
            "Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;"
        }
    .end annotation

    .line 1
    const-string p0, "date"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "trips"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;

    .line 12
    .line 13
    invoke-direct {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;-><init>(Ljava/time/LocalDate;Ljava/util/List;ILcz/myskoda/api/bff/v1/FuelCostDto;)V

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
    instance-of v1, p1, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;

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
    check-cast p1, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->date:Ljava/time/LocalDate;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->date:Ljava/time/LocalDate;

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
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->trips:Ljava/util/List;

    .line 25
    .line 26
    iget-object v3, p1, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->trips:Ljava/util/List;

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
    iget v1, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->overallMileage:I

    .line 36
    .line 37
    iget v3, p1, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->overallMileage:I

    .line 38
    .line 39
    if-eq v1, v3, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->overallCost:Lcz/myskoda/api/bff/v1/FuelCostDto;

    .line 43
    .line 44
    iget-object p1, p1, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->overallCost:Lcz/myskoda/api/bff/v1/FuelCostDto;

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

.method public final getDate()Ljava/time/LocalDate;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->date:Ljava/time/LocalDate;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOverallCost()Lcz/myskoda/api/bff/v1/FuelCostDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->overallCost:Lcz/myskoda/api/bff/v1/FuelCostDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getOverallMileage()I
    .locals 0

    .line 1
    iget p0, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->overallMileage:I

    .line 2
    .line 3
    return p0
.end method

.method public final getTrips()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff/v1/SingleTripDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->trips:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->date:Ljava/time/LocalDate;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/time/LocalDate;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->trips:Ljava/util/List;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget v2, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->overallMileage:I

    .line 17
    .line 18
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->overallCost:Lcz/myskoda/api/bff/v1/FuelCostDto;

    .line 23
    .line 24
    if-nez p0, :cond_0

    .line 25
    .line 26
    const/4 p0, 0x0

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/FuelCostDto;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    :goto_0
    add-int/2addr v0, p0

    .line 33
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->date:Ljava/time/LocalDate;

    .line 2
    .line 3
    iget-object v1, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->trips:Ljava/util/List;

    .line 4
    .line 5
    iget v2, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->overallMileage:I

    .line 6
    .line 7
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/DailyTripsDetailDto;->overallCost:Lcz/myskoda/api/bff/v1/FuelCostDto;

    .line 8
    .line 9
    new-instance v3, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v4, "DailyTripsDetailDto(date="

    .line 12
    .line 13
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v0, ", trips="

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
    const-string v0, ", overallMileage="

    .line 28
    .line 29
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v0, ", overallCost="

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
