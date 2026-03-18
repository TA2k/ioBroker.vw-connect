.class public interface abstract Lcz/myskoda/api/bff/v1/VehicleAutomatizationApi;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcz/myskoda/api/bff/v1/VehicleAutomatizationApi$DefaultImpls;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00008\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008f\u0018\u00002\u00020\u0001J8\u0010\t\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u00072\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\n\u0008\u0003\u0010\u0005\u001a\u0004\u0018\u00010\u00042\n\u0008\u0003\u0010\u0006\u001a\u0004\u0018\u00010\u0002H\u00a7@\u00a2\u0006\u0004\u0008\t\u0010\nJ*\u0010\u000e\u001a\u0008\u0012\u0004\u0012\u00020\r0\u00072\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u000c\u001a\u00020\u000bH\u00a7@\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ*\u0010\u0012\u001a\u0008\u0012\u0004\u0012\u00020\r0\u00072\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u0011\u001a\u00020\u0010H\u00a7@\u00a2\u0006\u0004\u0008\u0012\u0010\u0013\u00a8\u0006\u0014\u00c0\u0006\u0003"
    }
    d2 = {
        "Lcz/myskoda/api/bff/v1/VehicleAutomatizationApi;",
        "",
        "",
        "vin",
        "Ljava/time/OffsetDateTime;",
        "deviceDateTime",
        "timezone",
        "Lretrofit2/Response;",
        "Lcz/myskoda/api/bff/v1/DepartureTimersDto;",
        "getDepartureTimers",
        "(Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff/v1/DepartureTimersRequestDto;",
        "departureTimersRequestDto",
        "Llx0/b0;",
        "updateDepartureTimers",
        "(Ljava/lang/String;Lcz/myskoda/api/bff/v1/DepartureTimersRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff/v1/DepartureTimersSettingsDto;",
        "departureTimersSettingsDto",
        "updateDepartureTimersSettings",
        "(Ljava/lang/String;Lcz/myskoda/api/bff/v1/DepartureTimersSettingsDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
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
.method public static synthetic getDepartureTimers$default(Lcz/myskoda/api/bff/v1/VehicleAutomatizationApi;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Lkotlin/coroutines/Continuation;ILjava/lang/Object;)Ljava/lang/Object;
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
    invoke-interface {p0, p1, p2, p3, p4}, Lcz/myskoda/api/bff/v1/VehicleAutomatizationApi;->getDepartureTimers(Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    const-string p1, "Super calls with default arguments not supported in this target, function: getDepartureTimers"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0
.end method


# virtual methods
.method public abstract getDepartureTimers(Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Ljava/time/OffsetDateTime;
        .annotation runtime Lretrofit2/http/Query;
            value = "deviceDateTime"
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Query;
            value = "timezone"
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/time/OffsetDateTime;",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Lcz/myskoda/api/bff/v1/DepartureTimersDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v1/vehicle-automatization/{vin}/departure/timers"
    .end annotation
.end method

.method public abstract updateDepartureTimers(Ljava/lang/String;Lcz/myskoda/api/bff/v1/DepartureTimersRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff/v1/DepartureTimersRequestDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff/v1/DepartureTimersRequestDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v1/vehicle-automatization/{vin}/departure/timers"
    .end annotation
.end method

.method public abstract updateDepartureTimersSettings(Ljava/lang/String;Lcz/myskoda/api/bff/v1/DepartureTimersSettingsDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff/v1/DepartureTimersSettingsDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff/v1/DepartureTimersSettingsDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v1/vehicle-automatization/{vin}/departure/timers/settings"
    .end annotation
.end method
