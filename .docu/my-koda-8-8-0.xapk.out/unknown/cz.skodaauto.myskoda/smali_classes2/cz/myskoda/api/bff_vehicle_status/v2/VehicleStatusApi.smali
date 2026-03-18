.class public interface abstract Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$CarTypeGetVehicleRender;,
        Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$DefaultImpls;,
        Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$DimensionGetVehicleRender;,
        Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$ThemeGetVehicleRender;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000P\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\t\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0006\u0008f\u0018\u00002\u00020\u0001:\u0003\u001b\u001c\u001dJ \u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J \u0010\t\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008\t\u0010\u0007JH\u0010\u0014\u001a\u0008\u0012\u0004\u0012\u00020\u00130\u00042\u0008\u0008\u0001\u0010\u000b\u001a\u00020\n2\u0008\u0008\u0001\u0010\u000c\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u000e\u001a\u00020\r2\u0008\u0008\u0001\u0010\u0010\u001a\u00020\u000f2\u0008\u0008\u0001\u0010\u0012\u001a\u00020\u0011H\u00a7@\u00a2\u0006\u0004\u0008\u0014\u0010\u0015J,\u0010\u0019\u001a\u0008\u0012\u0004\u0012\u00020\u00180\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\n\u0008\u0003\u0010\u0017\u001a\u0004\u0018\u00010\u0016H\u00a7@\u00a2\u0006\u0004\u0008\u0019\u0010\u001a\u00a8\u0006\u001e\u00c0\u0006\u0003"
    }
    d2 = {
        "Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi;",
        "",
        "",
        "vin",
        "Lretrofit2/Response;",
        "Lcz/myskoda/api/bff_vehicle_status/v2/VehicleDrivingRangeStatusDto;",
        "getVehicleDrivingRangeStatus",
        "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_vehicle_status/v2/VehicleDrivingScoreDto;",
        "getVehicleDrivingScore",
        "Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$CarTypeGetVehicleRender;",
        "carType",
        "vehicleState",
        "",
        "lastModifiedAt",
        "Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$DimensionGetVehicleRender;",
        "dimension",
        "Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$ThemeGetVehicleRender;",
        "theme",
        "Ld01/v0;",
        "getVehicleRender",
        "(Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$CarTypeGetVehicleRender;Ljava/lang/String;JLcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$DimensionGetVehicleRender;Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$ThemeGetVehicleRender;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "",
        "includeRunningRequests",
        "Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusDto;",
        "getVehicleStatus",
        "(Ljava/lang/String;Ljava/lang/Boolean;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "CarTypeGetVehicleRender",
        "DimensionGetVehicleRender",
        "ThemeGetVehicleRender",
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
.method public static synthetic getVehicleStatus$default(Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi;Ljava/lang/String;Ljava/lang/Boolean;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
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
    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 8
    .line 9
    :cond_0
    invoke-interface {p0, p1, p2, p3}, Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi;->getVehicleStatus(Ljava/lang/String;Ljava/lang/Boolean;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 15
    .line 16
    const-string p1, "Super calls with default arguments not supported in this target, function: getVehicleStatus"

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0
.end method


# virtual methods
.method public abstract getVehicleDrivingRangeStatus(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_vehicle_status/v2/VehicleDrivingRangeStatusDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/vehicle-status/{vin}/driving-range"
    .end annotation
.end method

.method public abstract getVehicleDrivingScore(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_vehicle_status/v2/VehicleDrivingScoreDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/vehicle-status/{vin}/driving-score"
    .end annotation
.end method

.method public abstract getVehicleRender(Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$CarTypeGetVehicleRender;Ljava/lang/String;JLcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$DimensionGetVehicleRender;Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$ThemeGetVehicleRender;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$CarTypeGetVehicleRender;
        .annotation runtime Lretrofit2/http/Query;
            value = "carType"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "vehicleState"
        .end annotation
    .end param
    .param p3    # J
        .annotation runtime Lretrofit2/http/Query;
            value = "lastModifiedAt"
        .end annotation
    .end param
    .param p5    # Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$DimensionGetVehicleRender;
        .annotation runtime Lretrofit2/http/Query;
            value = "dimension"
        .end annotation
    .end param
    .param p6    # Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$ThemeGetVehicleRender;
        .annotation runtime Lretrofit2/http/Query;
            value = "theme"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$CarTypeGetVehicleRender;",
            "Ljava/lang/String;",
            "J",
            "Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$DimensionGetVehicleRender;",
            "Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusApi$ThemeGetVehicleRender;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Ld01/v0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/vehicle-status/render"
    .end annotation
.end method

.method public abstract getVehicleStatus(Ljava/lang/String;Ljava/lang/Boolean;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Ljava/lang/Boolean;
        .annotation runtime Lretrofit2/http/Query;
            value = "includeRunningRequests"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/Boolean;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_vehicle_status/v2/VehicleStatusDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/vehicle-status/{vin}"
    .end annotation
.end method
