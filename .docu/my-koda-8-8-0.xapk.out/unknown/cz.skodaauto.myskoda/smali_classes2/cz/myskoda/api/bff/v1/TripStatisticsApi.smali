.class public interface abstract Lcz/myskoda/api/bff/v1/TripStatisticsApi;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcz/myskoda/api/bff/v1/TripStatisticsApi$DefaultImpls;,
        Lcz/myskoda/api/bff/v1/TripStatisticsApi$OffsetTypeGetTripStatistics;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000d\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008f\u0018\u00002\u00020\u0001:\u0001\'J*\u0010\u0008\u001a\u0008\u0012\u0004\u0012\u00020\u00070\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u0005\u001a\u00020\u0004H\u00a7@\u00a2\u0006\u0004\u0008\u0008\u0010\tJ*\u0010\u000c\u001a\u0008\u0012\u0004\u0012\u00020\u000b0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\n\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u000c\u0010\rJ4\u0010\u000e\u001a\u0008\u0012\u0004\u0012\u00020\u000b0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\n\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u0005\u001a\u00020\u0004H\u00a7@\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJD\u0010\u0015\u001a\u0008\u0012\u0004\u0012\u00020\u00140\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\n\u0008\u0003\u0010\u0011\u001a\u0004\u0018\u00010\u00102\n\u0008\u0003\u0010\u0012\u001a\u0004\u0018\u00010\u00102\n\u0008\u0003\u0010\u0013\u001a\u0004\u0018\u00010\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0015\u0010\u0016J*\u0010\u0019\u001a\u0008\u0012\u0004\u0012\u00020\u00180\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u0017\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0019\u0010\rJP\u0010\u001c\u001a\u0008\u0012\u0004\u0012\u00020\u001b0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\n\u0008\u0003\u0010\u001a\u001a\u0004\u0018\u00010\u00022\n\u0008\u0003\u0010\u0011\u001a\u0004\u0018\u00010\u00102\n\u0008\u0003\u0010\u0012\u001a\u0004\u0018\u00010\u00102\n\u0008\u0003\u0010\u0013\u001a\u0004\u0018\u00010\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u001c\u0010\u001dJ@\u0010#\u001a\u0008\u0012\u0004\u0012\u00020\"0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u001f\u001a\u00020\u001e2\u0008\u0008\u0001\u0010!\u001a\u00020 2\n\u0008\u0003\u0010\u0013\u001a\u0004\u0018\u00010\u0002H\u00a7@\u00a2\u0006\u0004\u0008#\u0010$J,\u0010&\u001a\u0008\u0012\u0004\u0012\u00020%0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\n\u0008\u0003\u0010\u0013\u001a\u0004\u0018\u00010\u0002H\u00a7@\u00a2\u0006\u0004\u0008&\u0010\r\u00a8\u0006(\u00c0\u0006\u0003"
    }
    d2 = {
        "Lcz/myskoda/api/bff/v1/TripStatisticsApi;",
        "",
        "",
        "vin",
        "Lcz/myskoda/api/bff/v1/FuelPriceRequestDto;",
        "fuelPriceRequestDto",
        "Lretrofit2/Response;",
        "Lcz/myskoda/api/bff/v1/FuelPriceDto;",
        "createFuelPrice",
        "(Ljava/lang/String;Lcz/myskoda/api/bff/v1/FuelPriceRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "fuelPriceId",
        "Llx0/b0;",
        "deleteFuelPrice",
        "(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "editFuelPrice",
        "(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff/v1/FuelPriceRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Ljava/time/OffsetDateTime;",
        "from",
        "to",
        "timezone",
        "Ld01/v0;",
        "exportTrips",
        "(Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "fuelType",
        "Lcz/myskoda/api/bff/v1/FuelPriceResponseDto;",
        "getFuelPrices",
        "cursor",
        "Lcz/myskoda/api/bff/v1/SingleTripStatisticsDto;",
        "getSingleTripStatistics",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff/v1/TripStatisticsApi$OffsetTypeGetTripStatistics;",
        "offsetType",
        "",
        "offset",
        "Lcz/myskoda/api/bff/v1/TripStatisticsDto;",
        "getTripStatistics",
        "(Ljava/lang/String;Lcz/myskoda/api/bff/v1/TripStatisticsApi$OffsetTypeGetTripStatistics;ILjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff/v1/TripsOverviewDto;",
        "getTripsOverview",
        "OffsetTypeGetTripStatistics",
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


# direct methods
.method public static synthetic exportTrips$default(Lcz/myskoda/api/bff/v1/TripStatisticsApi;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/String;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    if-nez p7, :cond_3

    .line 2
    .line 3
    and-int/lit8 p7, p6, 0x2

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p7, :cond_0

    .line 7
    .line 8
    move-object p2, v0

    .line 9
    :cond_0
    and-int/lit8 p7, p6, 0x4

    .line 10
    .line 11
    if-eqz p7, :cond_1

    .line 12
    .line 13
    move-object p3, v0

    .line 14
    :cond_1
    and-int/lit8 p6, p6, 0x8

    .line 15
    .line 16
    if-eqz p6, :cond_2

    .line 17
    .line 18
    move-object p4, v0

    .line 19
    :cond_2
    invoke-interface/range {p0 .. p5}, Lcz/myskoda/api/bff/v1/TripStatisticsApi;->exportTrips(Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    :cond_3
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 25
    .line 26
    const-string p1, "Super calls with default arguments not supported in this target, function: exportTrips"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0
.end method

.method public static synthetic getSingleTripStatistics$default(Lcz/myskoda/api/bff/v1/TripStatisticsApi;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/String;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    if-nez p8, :cond_4

    .line 2
    .line 3
    and-int/lit8 p8, p7, 0x2

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p8, :cond_0

    .line 7
    .line 8
    move-object p2, v0

    .line 9
    :cond_0
    and-int/lit8 p8, p7, 0x4

    .line 10
    .line 11
    if-eqz p8, :cond_1

    .line 12
    .line 13
    move-object p3, v0

    .line 14
    :cond_1
    and-int/lit8 p8, p7, 0x8

    .line 15
    .line 16
    if-eqz p8, :cond_2

    .line 17
    .line 18
    move-object p4, v0

    .line 19
    :cond_2
    and-int/lit8 p7, p7, 0x10

    .line 20
    .line 21
    if-eqz p7, :cond_3

    .line 22
    .line 23
    move-object p5, v0

    .line 24
    :cond_3
    invoke-interface/range {p0 .. p6}, Lcz/myskoda/api/bff/v1/TripStatisticsApi;->getSingleTripStatistics(Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :cond_4
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 30
    .line 31
    const-string p1, "Super calls with default arguments not supported in this target, function: getSingleTripStatistics"

    .line 32
    .line 33
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0
.end method

.method public static synthetic getTripStatistics$default(Lcz/myskoda/api/bff/v1/TripStatisticsApi;Ljava/lang/String;Lcz/myskoda/api/bff/v1/TripStatisticsApi$OffsetTypeGetTripStatistics;ILjava/lang/String;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    if-nez p7, :cond_1

    .line 2
    .line 3
    and-int/lit8 p6, p6, 0x8

    .line 4
    .line 5
    if-eqz p6, :cond_0

    .line 6
    .line 7
    const/4 p4, 0x0

    .line 8
    :cond_0
    move-object v0, p0

    .line 9
    move-object v1, p1

    .line 10
    move-object v2, p2

    .line 11
    move v3, p3

    .line 12
    move-object v4, p4

    .line 13
    move-object v5, p5

    .line 14
    invoke-interface/range {v0 .. v5}, Lcz/myskoda/api/bff/v1/TripStatisticsApi;->getTripStatistics(Ljava/lang/String;Lcz/myskoda/api/bff/v1/TripStatisticsApi$OffsetTypeGetTripStatistics;ILjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 20
    .line 21
    const-string p1, "Super calls with default arguments not supported in this target, function: getTripStatistics"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0
.end method

.method public static synthetic getTripsOverview$default(Lcz/myskoda/api/bff/v1/TripStatisticsApi;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    if-nez p5, :cond_1

    .line 2
    .line 3
    and-int/lit8 p4, p4, 0x2

    .line 4
    .line 5
    if-eqz p4, :cond_0

    .line 6
    .line 7
    const/4 p2, 0x0

    .line 8
    :cond_0
    invoke-interface {p0, p1, p2, p3}, Lcz/myskoda/api/bff/v1/TripStatisticsApi;->getTripsOverview(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 14
    .line 15
    const-string p1, "Super calls with default arguments not supported in this target, function: getTripsOverview"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method


# virtual methods
.method public abstract createFuelPrice(Ljava/lang/String;Lcz/myskoda/api/bff/v1/FuelPriceRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff/v1/FuelPriceRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff/v1/FuelPriceRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff/v1/FuelPriceDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v1/trip-statistics/{vin}/fuel-prices"
    .end annotation
.end method

.method public abstract deleteFuelPrice(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "fuelPriceId"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/DELETE;
        value = "api/v1/trip-statistics/{vin}/fuel-prices/{fuelPriceId}"
    .end annotation
.end method

.method public abstract editFuelPrice(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff/v1/FuelPriceRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "fuelPriceId"
        .end annotation
    .end param
    .param p3    # Lcz/myskoda/api/bff/v1/FuelPriceRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff/v1/FuelPriceRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PUT;
        value = "api/v1/trip-statistics/{vin}/fuel-prices/{fuelPriceId}"
    .end annotation
.end method

.method public abstract exportTrips(Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Ljava/time/OffsetDateTime;
        .annotation runtime Lretrofit2/http/Query;
            value = "from"
        .end annotation
    .end param
    .param p3    # Ljava/time/OffsetDateTime;
        .annotation runtime Lretrofit2/http/Query;
            value = "to"
        .end annotation
    .end param
    .param p4    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "timezone"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/time/OffsetDateTime;",
            "Ljava/time/OffsetDateTime;",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Ld01/v0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v1/trip-statistics/{vin}/single-trips/export"
    .end annotation
.end method

.method public abstract getFuelPrices(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "fuelType"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff/v1/FuelPriceResponseDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v1/trip-statistics/{vin}/fuel-prices"
    .end annotation
.end method

.method public abstract getSingleTripStatistics(Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "cursor"
        .end annotation
    .end param
    .param p3    # Ljava/time/OffsetDateTime;
        .annotation runtime Lretrofit2/http/Query;
            value = "from"
        .end annotation
    .end param
    .param p4    # Ljava/time/OffsetDateTime;
        .annotation runtime Lretrofit2/http/Query;
            value = "to"
        .end annotation
    .end param
    .param p5    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "timezone"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/time/OffsetDateTime;",
            "Ljava/time/OffsetDateTime;",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff/v1/SingleTripStatisticsDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v1/trip-statistics/{vin}/single-trips"
    .end annotation
.end method

.method public abstract getTripStatistics(Ljava/lang/String;Lcz/myskoda/api/bff/v1/TripStatisticsApi$OffsetTypeGetTripStatistics;ILjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff/v1/TripStatisticsApi$OffsetTypeGetTripStatistics;
        .annotation runtime Lretrofit2/http/Query;
            value = "offsetType"
        .end annotation
    .end param
    .param p3    # I
        .annotation runtime Lretrofit2/http/Query;
            value = "offset"
        .end annotation
    .end param
    .param p4    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "timezone"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff/v1/TripStatisticsApi$OffsetTypeGetTripStatistics;",
            "I",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff/v1/TripStatisticsDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v1/trip-statistics/{vin}"
    .end annotation
.end method

.method public abstract getTripsOverview(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "timezone"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff/v1/TripsOverviewDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v1/trip-statistics/{vin}/overview"
    .end annotation
.end method
