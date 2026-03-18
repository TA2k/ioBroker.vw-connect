.class public abstract Ljb0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lqr0/q;)Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;

    .line 7
    .line 8
    iget-wide v1, p0, Lqr0/q;->a:D

    .line 9
    .line 10
    iget-object p0, p0, Lqr0/q;->b:Lqr0/r;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    if-eqz p0, :cond_1

    .line 17
    .line 18
    const/4 v3, 0x1

    .line 19
    if-ne p0, v3, :cond_0

    .line 20
    .line 21
    sget-object p0, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;->FAHRENHEIT:Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance p0, La8/r0;

    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    sget-object p0, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;->CELSIUS:Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 31
    .line 32
    :goto_0
    invoke-direct {v0, v1, v2, p0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;-><init>(DLcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;)V

    .line 33
    .line 34
    .line 35
    return-object v0
.end method

.method public static final b(Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;)Lqr0/q;
    .locals 3

    .line 1
    invoke-virtual {p0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;->getUnitInCar()Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Ljb0/j;->a:[I

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    aget v0, v1, v0

    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    if-eq v0, v1, :cond_2

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    if-eq v0, v1, :cond_1

    .line 18
    .line 19
    const/4 p0, 0x3

    .line 20
    if-ne v0, p0, :cond_0

    .line 21
    .line 22
    const/4 p0, 0x0

    .line 23
    return-object p0

    .line 24
    :cond_0
    new-instance p0, La8/r0;

    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    new-instance v0, Lqr0/q;

    .line 31
    .line 32
    invoke-virtual {p0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;->getTemperatureValue()D

    .line 33
    .line 34
    .line 35
    move-result-wide v1

    .line 36
    sget-object p0, Lqr0/r;->e:Lqr0/r;

    .line 37
    .line 38
    invoke-direct {v0, v1, v2, p0}, Lqr0/q;-><init>(DLqr0/r;)V

    .line 39
    .line 40
    .line 41
    return-object v0

    .line 42
    :cond_2
    new-instance v0, Lqr0/q;

    .line 43
    .line 44
    invoke-virtual {p0}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;->getTemperatureValue()D

    .line 45
    .line 46
    .line 47
    move-result-wide v1

    .line 48
    sget-object p0, Lqr0/r;->d:Lqr0/r;

    .line 49
    .line 50
    invoke-direct {v0, v1, v2, p0}, Lqr0/q;-><init>(DLqr0/r;)V

    .line 51
    .line 52
    .line 53
    return-object v0
.end method
