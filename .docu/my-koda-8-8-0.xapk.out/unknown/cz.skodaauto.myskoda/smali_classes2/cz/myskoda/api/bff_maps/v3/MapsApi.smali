.class public interface abstract Lcz/myskoda/api/bff_maps/v3/MapsApi;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcz/myskoda/api/bff_maps/v3/MapsApi$DefaultImpls;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00be\u0001\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0004\n\u0002\u0010\u0006\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010 \n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008f\u0018\u00002\u00020\u0001J \u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J \u0010\u000b\u001a\u0008\u0012\u0004\u0012\u00020\n0\u00042\u0008\u0008\u0001\u0010\t\u001a\u00020\u0008H\u00a7@\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ \u0010\u000f\u001a\u0008\u0012\u0004\u0012\u00020\n0\u00042\u0008\u0008\u0001\u0010\u000e\u001a\u00020\rH\u00a7@\u00a2\u0006\u0004\u0008\u000f\u0010\u0010J:\u0010\u0016\u001a\u0008\u0012\u0004\u0012\u00020\u00150\u00042\n\u0008\u0003\u0010\u0011\u001a\u0004\u0018\u00010\r2\n\u0008\u0003\u0010\u0013\u001a\u0004\u0018\u00010\u00122\n\u0008\u0003\u0010\u0014\u001a\u0004\u0018\u00010\u0012H\u00a7@\u00a2\u0006\u0004\u0008\u0016\u0010\u0017JH\u0010\u001f\u001a\u0008\u0012\u0004\u0012\u00020\u001e0\u00042\u0008\u0008\u0001\u0010\u0018\u001a\u00020\u00122\u0008\u0008\u0001\u0010\u0019\u001a\u00020\u00122\u0008\u0008\u0001\u0010\u001b\u001a\u00020\u001a2\u0008\u0008\u0001\u0010\u001c\u001a\u00020\u001a2\u0008\u0008\u0001\u0010\u001d\u001a\u00020\u001aH\u00a7@\u00a2\u0006\u0004\u0008\u001f\u0010 JT\u0010(\u001a\u0008\u0012\u0004\u0012\u00020\'0\u00042\u0008\u0008\u0001\u0010!\u001a\u00020\u00122\u0008\u0008\u0001\u0010\"\u001a\u00020\u00122\u0008\u0008\u0001\u0010#\u001a\u00020\u00122\u0008\u0008\u0001\u0010$\u001a\u00020\u00122\u0008\u0008\u0001\u0010&\u001a\u00020%2\n\u0008\u0003\u0010\u0011\u001a\u0004\u0018\u00010\rH\u00a7@\u00a2\u0006\u0004\u0008(\u0010)JT\u0010-\u001a\u0008\u0012\u0004\u0012\u00020,0\u00042\u0008\u0008\u0001\u0010\u0018\u001a\u00020\u00122\u0008\u0008\u0001\u0010\u0019\u001a\u00020\u00122\n\u0008\u0003\u0010\u0013\u001a\u0004\u0018\u00010\u00122\n\u0008\u0003\u0010\u0014\u001a\u0004\u0018\u00010\u00122\u0010\u0008\u0003\u0010+\u001a\n\u0012\u0004\u0012\u00020\r\u0018\u00010*H\u00a7@\u00a2\u0006\u0004\u0008-\u0010.J\u0090\u0001\u00106\u001a\u0008\u0012\u0004\u0012\u0002050\u00042\u0008\u0008\u0001\u0010\u000e\u001a\u00020\r2\u0008\u0008\u0001\u0010/\u001a\u00020\r2\n\u0008\u0003\u00100\u001a\u0004\u0018\u00010%2\n\u0008\u0003\u00102\u001a\u0004\u0018\u0001012\n\u0008\u0003\u0010\u0011\u001a\u0004\u0018\u00010\r2\n\u0008\u0003\u0010\u0013\u001a\u0004\u0018\u00010\u00122\n\u0008\u0003\u0010\u0014\u001a\u0004\u0018\u00010\u00122\n\u0008\u0003\u00103\u001a\u0004\u0018\u00010\r2\n\u0008\u0003\u00104\u001a\u0004\u0018\u00010%2\u0010\u0008\u0003\u0010+\u001a\n\u0012\u0004\u0012\u00020\r\u0018\u00010*H\u00a7@\u00a2\u0006\u0004\u00086\u00107J>\u0010;\u001a\u0008\u0012\u0004\u0012\u00020:0\u00042\u0008\u0008\u0001\u00108\u001a\u00020\r2\u0008\u0008\u0001\u0010\u0018\u001a\u00020\u00122\u0008\u0008\u0001\u0010\u0019\u001a\u00020\u00122\u0008\u0008\u0001\u00109\u001a\u00020%H\u00a7@\u00a2\u0006\u0004\u0008;\u0010<J8\u0010@\u001a\u0008\u0012\u0004\u0012\u00020?0\u00042\u0008\u0008\u0001\u0010\u0011\u001a\u00020\r2\n\u0008\u0003\u0010=\u001a\u0004\u0018\u00010\u00122\n\u0008\u0003\u0010>\u001a\u0004\u0018\u00010\u0012H\u00a7@\u00a2\u0006\u0004\u0008@\u0010\u0017J*\u0010D\u001a\u0008\u0012\u0004\u0012\u00020C0\u00042\u0008\u0008\u0001\u0010\u000e\u001a\u00020\r2\u0008\u0008\u0001\u0010B\u001a\u00020AH\u00a7@\u00a2\u0006\u0004\u0008D\u0010EJ \u0010I\u001a\u0008\u0012\u0004\u0012\u00020H0\u00042\u0008\u0008\u0001\u0010G\u001a\u00020FH\u00a7@\u00a2\u0006\u0004\u0008I\u0010JJ \u0010M\u001a\u0008\u0012\u0004\u0012\u00020\n0\u00042\u0008\u0008\u0001\u0010L\u001a\u00020KH\u00a7@\u00a2\u0006\u0004\u0008M\u0010NJ*\u0010Q\u001a\u0008\u0012\u0004\u0012\u00020\n0\u00042\u0008\u0008\u0001\u0010\u0011\u001a\u00020\r2\u0008\u0008\u0001\u0010P\u001a\u00020OH\u00a7@\u00a2\u0006\u0004\u0008Q\u0010RJ*\u0010U\u001a\u0008\u0012\u0004\u0012\u00020\n0\u00042\u0008\u0008\u0001\u0010\u000e\u001a\u00020\r2\u0008\u0008\u0001\u0010T\u001a\u00020SH\u00a7@\u00a2\u0006\u0004\u0008U\u0010V\u00a8\u0006W\u00c0\u0006\u0003"
    }
    d2 = {
        "Lcz/myskoda/api/bff_maps/v3/MapsApi;",
        "",
        "Lcz/myskoda/api/bff_maps/v3/CalculateRouteRequestDto;",
        "calculateRouteRequestDto",
        "Lretrofit2/Response;",
        "Lcz/myskoda/api/bff_maps/v3/RouteDto;",
        "calculateRoute",
        "(Lcz/myskoda/api/bff_maps/v3/CalculateRouteRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_maps/v3/FavouritePlaceToCreateDto;",
        "favouritePlaceToCreateDto",
        "Llx0/b0;",
        "createFavouritePlace",
        "(Lcz/myskoda/api/bff_maps/v3/FavouritePlaceToCreateDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "",
        "id",
        "deleteFavouritePlace",
        "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "vin",
        "",
        "currentLatitude",
        "currentLongitude",
        "Lcz/myskoda/api/bff_maps/v3/FavouritePlacesDto;",
        "getFavouritePlaces",
        "(Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "latitude",
        "longitude",
        "",
        "width",
        "height",
        "zoom",
        "Ld01/v0;",
        "getMapImage",
        "(DDIIILkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "minLatitude",
        "minLongitude",
        "maxLatitude",
        "maxLongitude",
        "Ljava/util/UUID;",
        "sessionId",
        "Lcz/myskoda/api/bff_maps/v3/OffersResponseDto;",
        "getOffers",
        "(DDDDLjava/util/UUID;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "",
        "avoidance",
        "Lcz/myskoda/api/bff_maps/v3/PlaceDto;",
        "getPlace",
        "(DDLjava/lang/Double;Ljava/lang/Double;Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "type",
        "token",
        "",
        "hasActiveTariff",
        "offerId",
        "offerSessionId",
        "Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;",
        "getPlaceDetail",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/util/UUID;Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/String;Ljava/util/UUID;Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "searchString",
        "sessionToken",
        "Lcz/myskoda/api/bff_maps/v3/PlacePredictionsResponseDto;",
        "getPlacePredictions",
        "(Ljava/lang/String;DDLjava/util/UUID;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "deviceLatitude",
        "deviceLongitude",
        "Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionResponseDto;",
        "getVehicleParkingPosition",
        "Lcz/myskoda/api/bff_maps/v3/OfferRedemptionRequestDto;",
        "offerRedemptionRequestDto",
        "Lcz/myskoda/api/bff_maps/v3/OfferRedemptionResponseDto;",
        "redeemOffer",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/OfferRedemptionRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_maps/v3/NearbyPlacesRequestDto;",
        "nearbyPlacesRequestDto",
        "Lcz/myskoda/api/bff_maps/v3/NearbyPlacesResponseDto;",
        "searchNearbyPlaces",
        "(Lcz/myskoda/api/bff_maps/v3/NearbyPlacesRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_maps/v3/OffersAnalyticsDataDto;",
        "offersAnalyticsDataDto",
        "sendOffersAnalytics",
        "(Lcz/myskoda/api/bff_maps/v3/OffersAnalyticsDataDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_maps/v3/SendRouteRequestDto;",
        "sendRouteRequestDto",
        "sendRoute",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/SendRouteRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_maps/v3/FavouritePlaceToUpdateDto;",
        "favouritePlaceToUpdateDto",
        "updateFavouritePlace",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/FavouritePlaceToUpdateDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
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
.method public static synthetic getFavouritePlaces$default(Lcz/myskoda/api/bff_maps/v3/MapsApi;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    if-nez p6, :cond_3

    .line 2
    .line 3
    and-int/lit8 p6, p5, 0x1

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p6, :cond_0

    .line 7
    .line 8
    move-object p1, v0

    .line 9
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 10
    .line 11
    if-eqz p6, :cond_1

    .line 12
    .line 13
    move-object p2, v0

    .line 14
    :cond_1
    and-int/lit8 p5, p5, 0x4

    .line 15
    .line 16
    if-eqz p5, :cond_2

    .line 17
    .line 18
    move-object p3, v0

    .line 19
    :cond_2
    invoke-interface {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->getFavouritePlaces(Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    const-string p1, "Super calls with default arguments not supported in this target, function: getFavouritePlaces"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0
.end method

.method public static synthetic getOffers$default(Lcz/myskoda/api/bff_maps/v3/MapsApi;DDDDLjava/util/UUID;Ljava/lang/String;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    if-nez p13, :cond_1

    .line 2
    .line 3
    and-int/lit8 v0, p12, 0x20

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    move-object v11, v0

    .line 9
    :goto_0
    move-object v1, p0

    .line 10
    move-wide v2, p1

    .line 11
    move-wide/from16 v4, p3

    .line 12
    .line 13
    move-wide/from16 v6, p5

    .line 14
    .line 15
    move-wide/from16 v8, p7

    .line 16
    .line 17
    move-object/from16 v10, p9

    .line 18
    .line 19
    move-object/from16 v12, p11

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_0
    move-object/from16 v11, p10

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :goto_1
    invoke-interface/range {v1 .. v12}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->getOffers(DDDDLjava/util/UUID;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 31
    .line 32
    const-string p1, "Super calls with default arguments not supported in this target, function: getOffers"

    .line 33
    .line 34
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0
.end method

.method public static synthetic getPlace$default(Lcz/myskoda/api/bff_maps/v3/MapsApi;DDLjava/lang/Double;Ljava/lang/Double;Ljava/util/List;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    if-nez p10, :cond_3

    .line 2
    .line 3
    and-int/lit8 p10, p9, 0x4

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p10, :cond_0

    .line 7
    .line 8
    move-object p5, v0

    .line 9
    :cond_0
    and-int/lit8 p10, p9, 0x8

    .line 10
    .line 11
    if-eqz p10, :cond_1

    .line 12
    .line 13
    move-object p6, v0

    .line 14
    :cond_1
    and-int/lit8 p9, p9, 0x10

    .line 15
    .line 16
    if-eqz p9, :cond_2

    .line 17
    .line 18
    move-object p7, v0

    .line 19
    :cond_2
    invoke-interface/range {p0 .. p8}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->getPlace(DDLjava/lang/Double;Ljava/lang/Double;Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    const-string p1, "Super calls with default arguments not supported in this target, function: getPlace"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0
.end method

.method public static synthetic getPlaceDetail$default(Lcz/myskoda/api/bff_maps/v3/MapsApi;Ljava/lang/String;Ljava/lang/String;Ljava/util/UUID;Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/String;Ljava/util/UUID;Ljava/util/List;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    if-nez p13, :cond_8

    .line 2
    .line 3
    and-int/lit8 p13, p12, 0x4

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p13, :cond_0

    .line 7
    .line 8
    move-object p3, v0

    .line 9
    :cond_0
    and-int/lit8 p13, p12, 0x8

    .line 10
    .line 11
    if-eqz p13, :cond_1

    .line 12
    .line 13
    sget-object p4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 14
    .line 15
    :cond_1
    and-int/lit8 p13, p12, 0x10

    .line 16
    .line 17
    if-eqz p13, :cond_2

    .line 18
    .line 19
    move-object p5, v0

    .line 20
    :cond_2
    and-int/lit8 p13, p12, 0x20

    .line 21
    .line 22
    if-eqz p13, :cond_3

    .line 23
    .line 24
    move-object p6, v0

    .line 25
    :cond_3
    and-int/lit8 p13, p12, 0x40

    .line 26
    .line 27
    if-eqz p13, :cond_4

    .line 28
    .line 29
    move-object p7, v0

    .line 30
    :cond_4
    and-int/lit16 p13, p12, 0x80

    .line 31
    .line 32
    if-eqz p13, :cond_5

    .line 33
    .line 34
    move-object p8, v0

    .line 35
    :cond_5
    and-int/lit16 p13, p12, 0x100

    .line 36
    .line 37
    if-eqz p13, :cond_6

    .line 38
    .line 39
    move-object p9, v0

    .line 40
    :cond_6
    and-int/lit16 p12, p12, 0x200

    .line 41
    .line 42
    if-eqz p12, :cond_7

    .line 43
    .line 44
    move-object p10, v0

    .line 45
    :cond_7
    invoke-interface/range {p0 .. p11}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->getPlaceDetail(Ljava/lang/String;Ljava/lang/String;Ljava/util/UUID;Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/String;Ljava/util/UUID;Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    return-object p0

    .line 50
    :cond_8
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 51
    .line 52
    const-string p1, "Super calls with default arguments not supported in this target, function: getPlaceDetail"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0
.end method

.method public static synthetic getVehicleParkingPosition$default(Lcz/myskoda/api/bff_maps/v3/MapsApi;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    if-nez p6, :cond_2

    .line 2
    .line 3
    and-int/lit8 p6, p5, 0x2

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p6, :cond_0

    .line 7
    .line 8
    move-object p2, v0

    .line 9
    :cond_0
    and-int/lit8 p5, p5, 0x4

    .line 10
    .line 11
    if-eqz p5, :cond_1

    .line 12
    .line 13
    move-object p3, v0

    .line 14
    :cond_1
    invoke-interface {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->getVehicleParkingPosition(Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :cond_2
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 20
    .line 21
    const-string p1, "Super calls with default arguments not supported in this target, function: getVehicleParkingPosition"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0
.end method


# virtual methods
.method public abstract calculateRoute(Lcz/myskoda/api/bff_maps/v3/CalculateRouteRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff_maps/v3/CalculateRouteRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff_maps/v3/CalculateRouteRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_maps/v3/RouteDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v3/maps/route"
    .end annotation
.end method

.method public abstract createFavouritePlace(Lcz/myskoda/api/bff_maps/v3/FavouritePlaceToCreateDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff_maps/v3/FavouritePlaceToCreateDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff_maps/v3/FavouritePlaceToCreateDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v3/maps/places/favourites"
    .end annotation
.end method

.method public abstract deleteFavouritePlace(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "id"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
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
        value = "api/v3/maps/places/favourites/{id}"
    .end annotation
.end method

.method public abstract getFavouritePlaces(Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Ljava/lang/Double;
        .annotation runtime Lretrofit2/http/Query;
            value = "currentLatitude"
        .end annotation
    .end param
    .param p3    # Ljava/lang/Double;
        .annotation runtime Lretrofit2/http/Query;
            value = "currentLongitude"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/Double;",
            "Ljava/lang/Double;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_maps/v3/FavouritePlacesDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v3/maps/places/favourites"
    .end annotation
.end method

.method public abstract getMapImage(DDIIILkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # D
        .annotation runtime Lretrofit2/http/Query;
            value = "latitude"
        .end annotation
    .end param
    .param p3    # D
        .annotation runtime Lretrofit2/http/Query;
            value = "longitude"
        .end annotation
    .end param
    .param p5    # I
        .annotation runtime Lretrofit2/http/Query;
            value = "width"
        .end annotation
    .end param
    .param p6    # I
        .annotation runtime Lretrofit2/http/Query;
            value = "height"
        .end annotation
    .end param
    .param p7    # I
        .annotation runtime Lretrofit2/http/Query;
            value = "zoom"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(DDIII",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Ld01/v0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v3/maps/image"
    .end annotation
.end method

.method public abstract getOffers(DDDDLjava/util/UUID;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # D
        .annotation runtime Lretrofit2/http/Query;
            value = "minLatitude"
        .end annotation
    .end param
    .param p3    # D
        .annotation runtime Lretrofit2/http/Query;
            value = "minLongitude"
        .end annotation
    .end param
    .param p5    # D
        .annotation runtime Lretrofit2/http/Query;
            value = "maxLatitude"
        .end annotation
    .end param
    .param p7    # D
        .annotation runtime Lretrofit2/http/Query;
            value = "maxLongitude"
        .end annotation
    .end param
    .param p9    # Ljava/util/UUID;
        .annotation runtime Lretrofit2/http/Query;
            value = "sessionId"
        .end annotation
    .end param
    .param p10    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "vin"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(DDDD",
            "Ljava/util/UUID;",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_maps/v3/OffersResponseDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v3/maps/offers"
    .end annotation
.end method

.method public abstract getPlace(DDLjava/lang/Double;Ljava/lang/Double;Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # D
        .annotation runtime Lretrofit2/http/Query;
            value = "latitude"
        .end annotation
    .end param
    .param p3    # D
        .annotation runtime Lretrofit2/http/Query;
            value = "longitude"
        .end annotation
    .end param
    .param p5    # Ljava/lang/Double;
        .annotation runtime Lretrofit2/http/Query;
            value = "currentLatitude"
        .end annotation
    .end param
    .param p6    # Ljava/lang/Double;
        .annotation runtime Lretrofit2/http/Query;
            value = "currentLongitude"
        .end annotation
    .end param
    .param p7    # Ljava/util/List;
        .annotation runtime Lretrofit2/http/Query;
            value = "avoidance"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(DD",
            "Ljava/lang/Double;",
            "Ljava/lang/Double;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_maps/v3/PlaceDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v3/maps/places"
    .end annotation
.end method

.method public abstract getPlaceDetail(Ljava/lang/String;Ljava/lang/String;Ljava/util/UUID;Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/String;Ljava/util/UUID;Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "id"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "type"
        .end annotation
    .end param
    .param p3    # Ljava/util/UUID;
        .annotation runtime Lretrofit2/http/Query;
            value = "token"
        .end annotation
    .end param
    .param p4    # Ljava/lang/Boolean;
        .annotation runtime Lretrofit2/http/Query;
            value = "hasActiveTariff"
        .end annotation
    .end param
    .param p5    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "vin"
        .end annotation
    .end param
    .param p6    # Ljava/lang/Double;
        .annotation runtime Lretrofit2/http/Query;
            value = "currentLatitude"
        .end annotation
    .end param
    .param p7    # Ljava/lang/Double;
        .annotation runtime Lretrofit2/http/Query;
            value = "currentLongitude"
        .end annotation
    .end param
    .param p8    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "offerId"
        .end annotation
    .end param
    .param p9    # Ljava/util/UUID;
        .annotation runtime Lretrofit2/http/Query;
            value = "offerSessionId"
        .end annotation
    .end param
    .param p10    # Ljava/util/List;
        .annotation runtime Lretrofit2/http/Query;
            value = "avoidance"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/UUID;",
            "Ljava/lang/Boolean;",
            "Ljava/lang/String;",
            "Ljava/lang/Double;",
            "Ljava/lang/Double;",
            "Ljava/lang/String;",
            "Ljava/util/UUID;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_maps/v3/PlaceDetailDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v3/maps/places/{id}"
    .end annotation
.end method

.method public abstract getPlacePredictions(Ljava/lang/String;DDLjava/util/UUID;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "searchString"
        .end annotation
    .end param
    .param p2    # D
        .annotation runtime Lretrofit2/http/Query;
            value = "latitude"
        .end annotation
    .end param
    .param p4    # D
        .annotation runtime Lretrofit2/http/Query;
            value = "longitude"
        .end annotation
    .end param
    .param p6    # Ljava/util/UUID;
        .annotation runtime Lretrofit2/http/Query;
            value = "sessionToken"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "DD",
            "Ljava/util/UUID;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_maps/v3/PlacePredictionsResponseDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v3/maps/places/predictions"
    .end annotation
.end method

.method public abstract getVehicleParkingPosition(Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Ljava/lang/Double;
        .annotation runtime Lretrofit2/http/Query;
            value = "deviceLatitude"
        .end annotation
    .end param
    .param p3    # Ljava/lang/Double;
        .annotation runtime Lretrofit2/http/Query;
            value = "deviceLongitude"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/Double;",
            "Ljava/lang/Double;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_maps/v3/VehicleParkingPositionResponseDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v3/maps/positions/vehicles/{vin}/parking"
    .end annotation
.end method

.method public abstract redeemOffer(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/OfferRedemptionRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "id"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_maps/v3/OfferRedemptionRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_maps/v3/OfferRedemptionRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_maps/v3/OfferRedemptionResponseDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v3/maps/offers/{id}/redemption"
    .end annotation
.end method

.method public abstract searchNearbyPlaces(Lcz/myskoda/api/bff_maps/v3/NearbyPlacesRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff_maps/v3/NearbyPlacesRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff_maps/v3/NearbyPlacesRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_maps/v3/NearbyPlacesResponseDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v3/maps/nearby-places"
    .end annotation
.end method

.method public abstract sendOffersAnalytics(Lcz/myskoda/api/bff_maps/v3/OffersAnalyticsDataDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff_maps/v3/OffersAnalyticsDataDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff_maps/v3/OffersAnalyticsDataDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v3/maps/offers/analytics"
    .end annotation
.end method

.method public abstract sendRoute(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/SendRouteRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_maps/v3/SendRouteRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_maps/v3/SendRouteRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PUT;
        value = "api/v3/maps/{vin}/route"
    .end annotation
.end method

.method public abstract updateFavouritePlace(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/FavouritePlaceToUpdateDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "id"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_maps/v3/FavouritePlaceToUpdateDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_maps/v3/FavouritePlaceToUpdateDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PUT;
        value = "api/v3/maps/places/favourites/{id}"
    .end annotation
.end method
