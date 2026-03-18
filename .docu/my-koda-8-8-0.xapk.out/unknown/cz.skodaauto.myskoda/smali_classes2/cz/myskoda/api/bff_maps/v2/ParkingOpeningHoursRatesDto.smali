.class public final Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0008\u0010\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0000\u0008\u0086\u0008\u0018\u00002\u00020\u0001B+\u0012\u0008\u0008\u0001\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0001\u0010\u0004\u001a\u00020\u0003\u0012\u000e\u0008\u0001\u0010\u0005\u001a\u0008\u0012\u0004\u0012\u00020\u00070\u0006\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\t\u0010\u0013\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0014\u001a\u00020\u0003H\u00c6\u0003J\u000f\u0010\u0015\u001a\u0008\u0012\u0004\u0012\u00020\u00070\u0006H\u00c6\u0003J-\u0010\u0016\u001a\u00020\u00002\u0008\u0008\u0003\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0003\u0010\u0004\u001a\u00020\u00032\u000e\u0008\u0003\u0010\u0005\u001a\u0008\u0012\u0004\u0012\u00020\u00070\u0006H\u00c6\u0001J\u0013\u0010\u0017\u001a\u00020\u00182\u0008\u0010\u0019\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u001a\u001a\u00020\u001bH\u00d6\u0001J\t\u0010\u001c\u001a\u00020\u001dH\u00d6\u0001R\u001c\u0010\u0002\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\n\u0010\u000b\u001a\u0004\u0008\u000c\u0010\rR\u001c\u0010\u0004\u001a\u00020\u00038\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u000e\u0010\u000b\u001a\u0004\u0008\u000f\u0010\rR\"\u0010\u0005\u001a\u0008\u0012\u0004\u0012\u00020\u00070\u00068\u0006X\u0087\u0004\u00a2\u0006\u000e\n\u0000\u0012\u0004\u0008\u0010\u0010\u000b\u001a\u0004\u0008\u0011\u0010\u0012\u00a8\u0006\u001e"
    }
    d2 = {
        "Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;",
        "",
        "periodStart",
        "Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;",
        "periodEnd",
        "openingTimesRates",
        "",
        "Lcz/myskoda/api/bff_maps/v2/ParkingOpeningTimeRatesDto;",
        "<init>",
        "(Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;Ljava/util/List;)V",
        "getPeriodStart$annotations",
        "()V",
        "getPeriodStart",
        "()Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;",
        "getPeriodEnd$annotations",
        "getPeriodEnd",
        "getOpeningTimesRates$annotations",
        "getOpeningTimesRates",
        "()Ljava/util/List;",
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
.field private final openingTimesRates:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_maps/v2/ParkingOpeningTimeRatesDto;",
            ">;"
        }
    .end annotation
.end field

.field private final periodEnd:Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;

.field private final periodStart:Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;


# direct methods
.method public constructor <init>(Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;Ljava/util/List;)V
    .locals 1
    .param p1    # Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "periodStart"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "periodEnd"
        .end annotation
    .end param
    .param p3    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "openingTimesRates"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;",
            "Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_maps/v2/ParkingOpeningTimeRatesDto;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "periodStart"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "periodEnd"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "openingTimesRates"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->periodStart:Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;

    .line 20
    .line 21
    iput-object p2, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->periodEnd:Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;

    .line 22
    .line 23
    iput-object p3, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->openingTimesRates:Ljava/util/List;

    .line 24
    .line 25
    return-void
.end method

.method public static synthetic copy$default(Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;Ljava/util/List;ILjava/lang/Object;)Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;
    .locals 0

    .line 1
    and-int/lit8 p5, p4, 0x1

    .line 2
    .line 3
    if-eqz p5, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->periodStart:Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p4, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->periodEnd:Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p4, p4, 0x4

    .line 14
    .line 15
    if-eqz p4, :cond_2

    .line 16
    .line 17
    iget-object p3, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->openingTimesRates:Ljava/util/List;

    .line 18
    .line 19
    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->copy(Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;Ljava/util/List;)Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public static synthetic getOpeningTimesRates$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "openingTimesRates"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getPeriodEnd$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "periodEnd"
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getPeriodStart$annotations()V
    .locals 0
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "periodStart"
    .end annotation

    .line 1
    return-void
.end method


# virtual methods
.method public final component1()Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->periodStart:Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->periodEnd:Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_maps/v2/ParkingOpeningTimeRatesDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->openingTimesRates:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;Ljava/util/List;)Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;
    .locals 0
    .param p1    # Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "periodStart"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "periodEnd"
        .end annotation
    .end param
    .param p3    # Ljava/util/List;
        .annotation runtime Lcom/squareup/moshi/Json;
            name = "openingTimesRates"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;",
            "Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_maps/v2/ParkingOpeningTimeRatesDto;",
            ">;)",
            "Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;"
        }
    .end annotation

    .line 1
    const-string p0, "periodStart"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "periodEnd"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "openingTimesRates"

    .line 12
    .line 13
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;

    .line 17
    .line 18
    invoke-direct {p0, p1, p2, p3}, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;-><init>(Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;Ljava/util/List;)V

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
    instance-of v1, p1, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;

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
    check-cast p1, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;

    .line 12
    .line 13
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->periodStart:Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;

    .line 14
    .line 15
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->periodStart:Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->periodEnd:Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;

    .line 21
    .line 22
    iget-object v3, p1, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->periodEnd:Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->openingTimesRates:Ljava/util/List;

    .line 28
    .line 29
    iget-object p1, p1, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->openingTimesRates:Ljava/util/List;

    .line 30
    .line 31
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    if-nez p0, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    return v0
.end method

.method public final getOpeningTimesRates()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcz/myskoda/api/bff_maps/v2/ParkingOpeningTimeRatesDto;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->openingTimesRates:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPeriodEnd()Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->periodEnd:Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPeriodStart()Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->periodStart:Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->periodStart:Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->periodEnd:Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

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
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->openingTimesRates:Ljava/util/List;

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    add-int/2addr p0, v1

    .line 25
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget-object v0, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->periodStart:Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;

    .line 2
    .line 3
    iget-object v1, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->periodEnd:Lcz/myskoda/api/bff_maps/v2/DayOfWeekDto;

    .line 4
    .line 5
    iget-object p0, p0, Lcz/myskoda/api/bff_maps/v2/ParkingOpeningHoursRatesDto;->openingTimesRates:Ljava/util/List;

    .line 6
    .line 7
    new-instance v2, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v3, "ParkingOpeningHoursRatesDto(periodStart="

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
    const-string v0, ", periodEnd="

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
    const-string v0, ", openingTimesRates="

    .line 26
    .line 27
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v0, ")"

    .line 31
    .line 32
    invoke-static {v2, p0, v0}, Lu/w;->i(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method
