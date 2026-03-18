.class public interface abstract Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000|\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\t\u0008f\u0018\u00002\u00020\u0001J \u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J \u0010\t\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008\t\u0010\u0007J \u0010\u000b\u001a\u0008\u0012\u0004\u0012\u00020\n0\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008\u000b\u0010\u0007J*\u0010\u000f\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\r\u001a\u00020\u000cH\u00a7@\u00a2\u0006\u0004\u0008\u000f\u0010\u0010J*\u0010\u0013\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u0012\u001a\u00020\u0011H\u00a7@\u00a2\u0006\u0004\u0008\u0013\u0010\u0014J*\u0010\u0017\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u0016\u001a\u00020\u0015H\u00a7@\u00a2\u0006\u0004\u0008\u0017\u0010\u0018J*\u0010\u001b\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u001a\u001a\u00020\u0019H\u00a7@\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ*\u0010\u001f\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\u001e\u001a\u00020\u001dH\u00a7@\u00a2\u0006\u0004\u0008\u001f\u0010 J*\u0010#\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010\"\u001a\u00020!H\u00a7@\u00a2\u0006\u0004\u0008#\u0010$J*\u0010\'\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010&\u001a\u00020%H\u00a7@\u00a2\u0006\u0004\u0008\'\u0010(J*\u0010+\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010*\u001a\u00020)H\u00a7@\u00a2\u0006\u0004\u0008+\u0010,J \u0010-\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008-\u0010\u0007J*\u00100\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u0010/\u001a\u00020.H\u00a7@\u00a2\u0006\u0004\u00080\u00101J*\u00104\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0001\u00103\u001a\u000202H\u00a7@\u00a2\u0006\u0004\u00084\u00105J \u00106\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u00086\u0010\u0007J \u00107\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u00087\u0010\u0007J \u00108\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u00088\u0010\u0007J \u00109\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u00089\u0010\u0007J \u0010:\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00042\u0008\u0008\u0001\u0010\u0003\u001a\u00020\u0002H\u00a7@\u00a2\u0006\u0004\u0008:\u0010\u0007\u00a8\u0006;\u00c0\u0006\u0003"
    }
    d2 = {
        "Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;",
        "",
        "",
        "vin",
        "Lretrofit2/Response;",
        "Lcz/myskoda/api/bff_air_conditioning/v2/ActiveVentilationDto;",
        "getActiveVentilation",
        "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;",
        "getAirConditioning",
        "Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingDto;",
        "getAuxiliaryHeating",
        "Lcz/myskoda/api/bff_air_conditioning/v2/ActiveVentilationTimersConfigurationDto;",
        "activeVentilationTimersConfigurationDto",
        "Llx0/b0;",
        "setActiveVentilationTimers",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/ActiveVentilationTimersConfigurationDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAtUnlockSettingsDto;",
        "airConditioningAtUnlockSettingsDto",
        "setAirConditioningAtUnlock",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAtUnlockSettingsDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_air_conditioning/v2/SeatHeatingSettingsDto;",
        "seatHeatingSettingsDto",
        "setAirConditioningSeatsHeating",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/SeatHeatingSettingsDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;",
        "airConditioningTargetTemperatureDto",
        "setAirConditioningTargetTemperature",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTimersConfigurationDto;",
        "airConditioningTimersConfigurationDto",
        "setAirConditioningTimers",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTimersConfigurationDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_air_conditioning/v2/WindowHeatingSettingsDto;",
        "windowHeatingSettingsDto",
        "setAirConditioningWindowsHeating",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/WindowHeatingSettingsDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningWithoutExternalPowerSettingsDto;",
        "airConditioningWithoutExternalPowerSettingsDto",
        "setAirConditioningWithoutExternalPower",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningWithoutExternalPowerSettingsDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingTimersConfigurationDto;",
        "auxiliaryHeatingTimersConfigurationDto",
        "setAuxiliaryHeatingTimers",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingTimersConfigurationDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "startActiveVentilation",
        "Lcz/myskoda/api/bff_air_conditioning/v2/StartAirConditioningConfigurationDto;",
        "startAirConditioningConfigurationDto",
        "startAirConditioning",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/StartAirConditioningConfigurationDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto;",
        "startAuxiliaryHeatingConfigurationDto",
        "startAuxiliaryHeating",
        "(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "startWindowHeating",
        "stopActiveVentilation",
        "stopAirConditioning",
        "stopAuxiliaryHeating",
        "stopWindowHeating",
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


# virtual methods
.method public abstract getActiveVentilation(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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
            "Lcz/myskoda/api/bff_air_conditioning/v2/ActiveVentilationDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/air-conditioning/{vin}/active-ventilation"
    .end annotation
.end method

.method public abstract getAirConditioning(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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
            "Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/air-conditioning/{vin}"
    .end annotation
.end method

.method public abstract getAuxiliaryHeating(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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
            "Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingDto;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/GET;
        value = "api/v2/air-conditioning/{vin}/auxiliary-heating"
    .end annotation
.end method

.method public abstract setActiveVentilationTimers(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/ActiveVentilationTimersConfigurationDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_air_conditioning/v2/ActiveVentilationTimersConfigurationDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_air_conditioning/v2/ActiveVentilationTimersConfigurationDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/air-conditioning/{vin}/active-ventilation/timers"
    .end annotation
.end method

.method public abstract setAirConditioningAtUnlock(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAtUnlockSettingsDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAtUnlockSettingsDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAtUnlockSettingsDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/air-conditioning/{vin}/settings/ac-at-unlock"
    .end annotation
.end method

.method public abstract setAirConditioningSeatsHeating(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/SeatHeatingSettingsDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_air_conditioning/v2/SeatHeatingSettingsDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_air_conditioning/v2/SeatHeatingSettingsDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/air-conditioning/{vin}/settings/seats-heating"
    .end annotation
.end method

.method public abstract setAirConditioningTargetTemperature(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/air-conditioning/{vin}/settings/target-temperature"
    .end annotation
.end method

.method public abstract setAirConditioningTimers(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTimersConfigurationDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTimersConfigurationDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTimersConfigurationDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/air-conditioning/{vin}/timers"
    .end annotation
.end method

.method public abstract setAirConditioningWindowsHeating(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/WindowHeatingSettingsDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_air_conditioning/v2/WindowHeatingSettingsDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_air_conditioning/v2/WindowHeatingSettingsDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/air-conditioning/{vin}/settings/windows-heating"
    .end annotation
.end method

.method public abstract setAirConditioningWithoutExternalPower(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningWithoutExternalPowerSettingsDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningWithoutExternalPowerSettingsDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningWithoutExternalPowerSettingsDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/air-conditioning/{vin}/settings/ac-without-external-power"
    .end annotation
.end method

.method public abstract setAuxiliaryHeatingTimers(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingTimersConfigurationDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingTimersConfigurationDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_air_conditioning/v2/AuxiliaryHeatingTimersConfigurationDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/air-conditioning/{vin}/auxiliary-heating/timers"
    .end annotation
.end method

.method public abstract startActiveVentilation(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/air-conditioning/{vin}/active-ventilation/start"
    .end annotation
.end method

.method public abstract startAirConditioning(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/StartAirConditioningConfigurationDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_air_conditioning/v2/StartAirConditioningConfigurationDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_air_conditioning/v2/StartAirConditioningConfigurationDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/air-conditioning/{vin}/start"
    .end annotation
.end method

.method public abstract startAuxiliaryHeating(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .param p1    # Ljava/lang/String;
        .annotation runtime Lretrofit2/http/Path;
            value = "vin"
        .end annotation
    .end param
    .param p2    # Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto;
        .annotation runtime Lretrofit2/http/Body;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lcz/myskoda/api/bff_air_conditioning/v2/StartAuxiliaryHeatingConfigurationDto;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Lretrofit2/Response<",
            "Llx0/b0;",
            ">;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/air-conditioning/{vin}/auxiliary-heating/start"
    .end annotation
.end method

.method public abstract startWindowHeating(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/air-conditioning/{vin}/start-window-heating"
    .end annotation
.end method

.method public abstract stopActiveVentilation(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/air-conditioning/{vin}/active-ventilation/stop"
    .end annotation
.end method

.method public abstract stopAirConditioning(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/air-conditioning/{vin}/stop"
    .end annotation
.end method

.method public abstract stopAuxiliaryHeating(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/air-conditioning/{vin}/auxiliary-heating/stop"
    .end annotation
.end method

.method public abstract stopWindowHeating(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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

    .annotation runtime Lretrofit2/http/POST;
        value = "api/v2/air-conditioning/{vin}/stop-window-heating"
    .end annotation
.end method
