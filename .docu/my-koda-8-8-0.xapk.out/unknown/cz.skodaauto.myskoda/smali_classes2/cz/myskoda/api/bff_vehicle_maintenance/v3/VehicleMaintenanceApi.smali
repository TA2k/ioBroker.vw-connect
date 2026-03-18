.class public interface abstract Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi$DefaultImpls;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000h\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0006\n\u0002\u0008\u0002\n\u0002\u0010\u0007\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008f\u0018\u00002\u00020\u0001J*\u0010\u0008\u001a\u0008\u0012\u0004\u0012\u00020\u00070\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u0005\u001a\u00020\u0004H\u00a7@\u00a2\u0006\u0004\u0008\u0008\u0010\tJ \u0010\n\u001a\u0008\u0012\u0004\u0012\u00020\u00070\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008\n\u0010\u000bJb\u0010\u0014\u001a\u0008\u0012\u0004\u0012\u00020\u00130\u00062\u0008\u0008\u0001\u0010\u000c\u001a\u00020\u00022\u0008\u0008\u0001\u0010\r\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u000e\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u0010\u001a\u00020\u000f2\n\u0008\u0003\u0010\u0011\u001a\u0004\u0018\u00010\u00022\n\u0008\u0003\u0010\u0012\u001a\u0004\u0018\u00010\u00022\n\u0008\u0003\u0010\u0003\u001a\u0004\u0018\u00010\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0014\u0010\u0015J \u0010\u0017\u001a\u0008\u0012\u0004\u0012\u00020\u00160\u00062\u0008\u0008\u0001\u0010\u000c\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0017\u0010\u000bJR\u0010!\u001a\u0008\u0012\u0004\u0012\u00020 0\u00062\n\u0008\u0003\u0010\u0018\u001a\u0004\u0018\u00010\u00022\n\u0008\u0003\u0010\u001a\u001a\u0004\u0018\u00010\u00192\n\u0008\u0003\u0010\u001b\u001a\u0004\u0018\u00010\u00192\n\u0008\u0003\u0010\u001d\u001a\u0004\u0018\u00010\u001c2\n\u0008\u0003\u0010\u001f\u001a\u0004\u0018\u00010\u001eH\u00a7@\u00a2\u0006\u0004\u0008!\u0010\"J \u0010$\u001a\u0008\u0012\u0004\u0012\u00020#0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008$\u0010\u000bJ \u0010&\u001a\u0008\u0012\u0004\u0012\u00020%0\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008&\u0010\u000bJ*\u0010)\u001a\u0008\u0012\u0004\u0012\u00020\u00070\u00062\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010(\u001a\u00020\'H\u00a7@\u00a2\u0006\u0004\u0008)\u0010*\u00a8\u0006+\u00c0\u0006\u0003"
    }
    d2 = {
        "Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;",
        "",
        "",
        "vin",
        "Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServiceBookingRequestDto;",
        "serviceBookingRequestDto",
        "Lretrofit2/Response;",
        "Llx0/b0;",
        "createServiceBooking",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServiceBookingRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "deleteServicePartnerFromVehicle",
        "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "servicePartnerId",
        "feature",
        "countryCode",
        "",
        "includePersonalInfo",
        "mileage",
        "licencePlate",
        "Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerEncodedUrlDto;",
        "getEncodedUrl",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;",
        "getServicePartner",
        "searchQuery",
        "",
        "latitude",
        "longitude",
        "",
        "maxDistance",
        "",
        "limit",
        "Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnersDto;",
        "getServicePartners",
        "(Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Float;Ljava/lang/Integer;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_vehicle_maintenance/v3/MaintenanceStatusReportDto;",
        "getVehicleMaintenanceReport",
        "Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceDto;",
        "getVehicleServiceInformation",
        "Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleServicePartnerDto;",
        "vehicleServicePartnerDto",
        "setVehicleServicePartner",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleServicePartnerDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
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
.method public static synthetic getEncodedUrl$default(Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    if-nez p10, :cond_3

    .line 2
    .line 3
    and-int/lit8 p10, p9, 0x10

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
    and-int/lit8 p10, p9, 0x20

    .line 10
    .line 11
    if-eqz p10, :cond_1

    .line 12
    .line 13
    move-object p6, v0

    .line 14
    :cond_1
    and-int/lit8 p9, p9, 0x40

    .line 15
    .line 16
    if-eqz p9, :cond_2

    .line 17
    .line 18
    move-object p7, v0

    .line 19
    :cond_2
    invoke-interface/range {p0 .. p8}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;->getEncodedUrl(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    const-string p1, "Super calls with default arguments not supported in this target, function: getEncodedUrl"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0
.end method

.method public static synthetic getServicePartners$default(Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Float;Ljava/lang/Integer;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    if-nez p8, :cond_5

    .line 2
    .line 3
    and-int/lit8 p8, p7, 0x1

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p8, :cond_0

    .line 7
    .line 8
    move-object p1, v0

    .line 9
    :cond_0
    and-int/lit8 p8, p7, 0x2

    .line 10
    .line 11
    if-eqz p8, :cond_1

    .line 12
    .line 13
    move-object p2, v0

    .line 14
    :cond_1
    and-int/lit8 p8, p7, 0x4

    .line 15
    .line 16
    if-eqz p8, :cond_2

    .line 17
    .line 18
    move-object p3, v0

    .line 19
    :cond_2
    and-int/lit8 p8, p7, 0x8

    .line 20
    .line 21
    if-eqz p8, :cond_3

    .line 22
    .line 23
    const/high16 p4, 0x42c80000    # 100.0f

    .line 24
    .line 25
    invoke-static {p4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 26
    .line 27
    .line 28
    move-result-object p4

    .line 29
    :cond_3
    and-int/lit8 p7, p7, 0x10

    .line 30
    .line 31
    if-eqz p7, :cond_4

    .line 32
    .line 33
    const/16 p5, 0x32

    .line 34
    .line 35
    invoke-static {p5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 36
    .line 37
    .line 38
    move-result-object p5

    .line 39
    :cond_4
    invoke-interface/range {p0 .. p6}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceApi;->getServicePartners(Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Float;Ljava/lang/Integer;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0

    .line 44
    :cond_5
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 45
    .line 46
    const-string p1, "Super calls with default arguments not supported in this target, function: getServicePartners"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0
.end method


# virtual methods
.method public abstract createServiceBooking(Ljava/lang/String;Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServiceBookingRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServiceBookingRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServiceBookingRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v3/vehicle-maintenance/vehicles/{vin}/service-booking"
    .end annotation
.end method

.method public abstract deleteServicePartnerFromVehicle(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/DELETE;
        value = "api/v3/vehicle-maintenance/vehicles/{vin}/service-partner"
    .end annotation
.end method

.method public abstract getEncodedUrl(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "servicePartnerId"
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "feature"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "countryCode"
        .end annotation
    .end param
    .param p4    # Z
        .annotation runtime Lretrofit2/http/Query;
            value = "includePersonalInfo"
        .end annotation
    .end param
    .param p5    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "mileage"
        .end annotation
    .end param
    .param p6    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "licencePlate"
        .end annotation
    .end param
    .param p7    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "vin"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Z",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerEncodedUrlDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v3/vehicle-maintenance/service-partners/{servicePartnerId}/encoded-url"
    .end annotation
.end method

.method public abstract getServicePartner(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "servicePartnerId"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnerDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v3/vehicle-maintenance/service-partners/{servicePartnerId}"
    .end annotation
.end method

.method public abstract getServicePartners(Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Float;Ljava/lang/Integer;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "searchQuery"
        .end annotation
    .end param
    .param p2    # Ljava/lang/Double;
        .annotation runtime Lretrofit2/http/Query;
            value = "latitude"
        .end annotation
    .end param
    .param p3    # Ljava/lang/Double;
        .annotation runtime Lretrofit2/http/Query;
            value = "longitude"
        .end annotation
    .end param
    .param p4    # Ljava/lang/Float;
        .annotation runtime Lretrofit2/http/Query;
            value = "maxDistance"
        .end annotation
    .end param
    .param p5    # Ljava/lang/Integer;
        .annotation runtime Lretrofit2/http/Query;
            value = "limit"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/Double;",
            "Ljava/lang/Double;",
            "Ljava/lang/Float;",
            "Ljava/lang/Integer;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/ServicePartnersDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v3/vehicle-maintenance/service-partners"
    .end annotation
.end method

.method public abstract getVehicleMaintenanceReport(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/MaintenanceStatusReportDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v3/vehicle-maintenance/vehicles/{vin}/report"
    .end annotation
.end method

.method public abstract getVehicleServiceInformation(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleMaintenanceDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v3/vehicle-maintenance/vehicles/{vin}"
    .end annotation
.end method

.method public abstract setVehicleServicePartner(Ljava/lang/String;Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleServicePartnerDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleServicePartnerDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_vehicle_maintenance/v3/VehicleServicePartnerDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/PUT;
        value = "api/v3/vehicle-maintenance/vehicles/{vin}/service-partner"
    .end annotation
.end method
