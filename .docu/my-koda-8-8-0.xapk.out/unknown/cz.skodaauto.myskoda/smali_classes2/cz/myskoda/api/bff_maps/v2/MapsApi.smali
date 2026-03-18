.class public interface abstract Lcz/myskoda/api/bff_maps/v2/MapsApi;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcz/myskoda/api/bff_maps/v2/MapsApi$DefaultImpls;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000`\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0006\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008f\u0018\u00002\u00020\u0001J \u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J \u0010\u000b\u001a\u0008\u0012\u0004\u0012\u00020\n0\u00042\u0008\u0008\u0001\u0010\t\u001a\u00020\u0008H\u00a7@\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJZ\u0010\u0016\u001a\u0008\u0012\u0004\u0012\u00020\u00150\u00042\u0008\u0008\u0001\u0010\t\u001a\u00020\u00082\u0008\u0008\u0001\u0010\r\u001a\u00020\u00082\n\u0008\u0003\u0010\u000f\u001a\u0004\u0018\u00010\u000e2\n\u0008\u0003\u0010\u0011\u001a\u0004\u0018\u00010\u00102\n\u0008\u0003\u0010\u0013\u001a\u0004\u0018\u00010\u00122\n\u0008\u0003\u0010\u0014\u001a\u0004\u0018\u00010\u0012H\u00a7@\u00a2\u0006\u0004\u0008\u0016\u0010\u0017J \u0010\u001b\u001a\u0008\u0012\u0004\u0012\u00020\u001a0\u00042\u0008\u0008\u0001\u0010\u0019\u001a\u00020\u0018H\u00a7@\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ*\u0010!\u001a\u0008\u0012\u0004\u0012\u00020 0\u00042\u0008\u0008\u0001\u0010\u001d\u001a\u00020\u00082\u0008\u0008\u0001\u0010\u001f\u001a\u00020\u001eH\u00a7@\u00a2\u0006\u0004\u0008!\u0010\"\u00a8\u0006#\u00c0\u0006\u0003"
    }
    d2 = {
        "Lcz/myskoda/api/bff_maps/v2/MapsApi;",
        "",
        "Lcz/myskoda/api/bff_maps/v2/CalculateRouteRequestDto;",
        "calculateRouteRequestDto",
        "Lretrofit2/Response;",
        "Lcz/myskoda/api/bff_maps/v2/RouteDto;",
        "calculateRoute",
        "(Lcz/myskoda/api/bff_maps/v2/CalculateRouteRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "",
        "id",
        "Lcz/myskoda/api/bff_maps/v2/ChargingStationPricesDto;",
        "getChargingStationPrices",
        "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "type",
        "Ljava/util/UUID;",
        "token",
        "",
        "hasActiveTariff",
        "",
        "currentLatitude",
        "currentLongitude",
        "Lcz/myskoda/api/bff_maps/v2/PlaceDetailDto;",
        "getPlaceDetail",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/util/UUID;Ljava/lang/Boolean;Ljava/lang/Double;Ljava/lang/Double;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;",
        "nearbyPlacesRequestDto",
        "Lcz/myskoda/api/bff_maps/v2/NearbyPlacesResponseDto;",
        "searchNearbyPlaces",
        "(Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "vin",
        "Lcz/myskoda/api/bff_maps/v2/SendRouteRequestDto;",
        "sendRouteRequestDto",
        "Llx0/b0;",
        "sendRoute",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v2/SendRouteRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
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
.method public static synthetic getPlaceDetail$default(Lcz/myskoda/api/bff_maps/v2/MapsApi;Ljava/lang/String;Ljava/lang/String;Ljava/util/UUID;Ljava/lang/Boolean;Ljava/lang/Double;Ljava/lang/Double;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    if-nez p9, :cond_4

    .line 2
    .line 3
    and-int/lit8 p9, p8, 0x4

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p9, :cond_0

    .line 7
    .line 8
    move-object p3, v0

    .line 9
    :cond_0
    and-int/lit8 p9, p8, 0x8

    .line 10
    .line 11
    if-eqz p9, :cond_1

    .line 12
    .line 13
    sget-object p4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 14
    .line 15
    :cond_1
    and-int/lit8 p9, p8, 0x10

    .line 16
    .line 17
    if-eqz p9, :cond_2

    .line 18
    .line 19
    move-object p5, v0

    .line 20
    :cond_2
    and-int/lit8 p8, p8, 0x20

    .line 21
    .line 22
    if-eqz p8, :cond_3

    .line 23
    .line 24
    move-object p6, v0

    .line 25
    :cond_3
    invoke-interface/range {p0 .. p7}, Lcz/myskoda/api/bff_maps/v2/MapsApi;->getPlaceDetail(Ljava/lang/String;Ljava/lang/String;Ljava/util/UUID;Ljava/lang/Boolean;Ljava/lang/Double;Ljava/lang/Double;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :cond_4
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 31
    .line 32
    const-string p1, "Super calls with default arguments not supported in this target, function: getPlaceDetail"

    .line 33
    .line 34
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0
.end method


# virtual methods
.method public abstract calculateRoute(Lcz/myskoda/api/bff_maps/v2/CalculateRouteRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff_maps/v2/CalculateRouteRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff_maps/v2/CalculateRouteRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_maps/v2/RouteDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/maps/route"
    .end annotation
.end method

.method public abstract getChargingStationPrices(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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
            "Lcz/myskoda/api/bff_maps/v2/ChargingStationPricesDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/maps/charging-stations/{id}/prices"
    .end annotation
.end method

.method public abstract getPlaceDetail(Ljava/lang/String;Ljava/lang/String;Ljava/util/UUID;Ljava/lang/Boolean;Ljava/lang/Double;Ljava/lang/Double;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/UUID;",
            "Ljava/lang/Boolean;",
            "Ljava/lang/Double;",
            "Ljava/lang/Double;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_maps/v2/PlaceDetailDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/maps/places/{id}"
    .end annotation
.end method

.method public abstract searchNearbyPlaces(Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff_maps/v2/NearbyPlacesRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_maps/v2/NearbyPlacesResponseDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/maps/nearby-places"
    .end annotation
.end method

.method public abstract sendRoute(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v2/SendRouteRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_maps/v2/SendRouteRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_maps/v2/SendRouteRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PUT;
        value = "api/v2/maps/{vin}/route"
    .end annotation
.end method
