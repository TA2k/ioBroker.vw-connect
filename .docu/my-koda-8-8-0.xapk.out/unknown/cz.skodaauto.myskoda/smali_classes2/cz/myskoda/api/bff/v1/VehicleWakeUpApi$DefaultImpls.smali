.class public final Lcz/myskoda/api/bff/v1/VehicleWakeUpApi$DefaultImpls;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcz/myskoda/api/bff/v1/VehicleWakeUpApi;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "DefaultImpls"
.end annotation

.annotation runtime Lkotlin/Metadata;
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static synthetic requestVehicleWakeUp$default(Lcz/myskoda/api/bff/v1/VehicleWakeUpApi;Ljava/lang/String;Ljava/lang/Boolean;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static/range {p0 .. p5}, Lcz/myskoda/api/bff/v1/VehicleWakeUpApi;->requestVehicleWakeUp$default(Lcz/myskoda/api/bff/v1/VehicleWakeUpApi;Ljava/lang/String;Ljava/lang/Boolean;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
