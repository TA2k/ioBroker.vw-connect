.class public abstract synthetic Ljb0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:[I


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    invoke-static {}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;->values()[Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    array-length v0, v0

    .line 6
    new-array v0, v0, [I

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    :try_start_0
    sget-object v2, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;->CELSIUS:Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    aput v1, v0, v2
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    .line 17
    :catch_0
    const/4 v2, 0x2

    .line 18
    :try_start_1
    sget-object v3, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;->FAHRENHEIT:Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 19
    .line 20
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    aput v2, v0, v3
    :try_end_1
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1 .. :try_end_1} :catch_1

    .line 25
    .line 26
    :catch_1
    :try_start_2
    sget-object v3, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;->UNKNOWN:Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 27
    .line 28
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    const/4 v4, 0x3

    .line 33
    aput v4, v0, v3
    :try_end_2
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2 .. :try_end_2} :catch_2

    .line 34
    .line 35
    :catch_2
    sput-object v0, Ljb0/j;->a:[I

    .line 36
    .line 37
    invoke-static {}, Lqr0/r;->values()[Lqr0/r;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    array-length v0, v0

    .line 42
    new-array v0, v0, [I

    .line 43
    .line 44
    const/4 v3, 0x0

    .line 45
    :try_start_3
    aput v1, v0, v3
    :try_end_3
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3 .. :try_end_3} :catch_3

    .line 46
    .line 47
    :catch_3
    :try_start_4
    sget-object v3, Lqr0/r;->d:Lqr0/r;

    .line 48
    .line 49
    aput v2, v0, v1
    :try_end_4
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4 .. :try_end_4} :catch_4

    .line 50
    .line 51
    :catch_4
    return-void
.end method
