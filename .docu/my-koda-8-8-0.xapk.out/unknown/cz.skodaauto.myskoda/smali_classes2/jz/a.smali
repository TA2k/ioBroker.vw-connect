.class public abstract synthetic Ljz/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:[I

.field public static final synthetic b:[I


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    invoke-static {}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAuxiliaryHeatingStateDto;->values()[Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAuxiliaryHeatingStateDto;

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
    sget-object v2, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAuxiliaryHeatingStateDto;->OFF:Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAuxiliaryHeatingStateDto;

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
    sget-object v3, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAuxiliaryHeatingStateDto;->PREHEATING:Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAuxiliaryHeatingStateDto;

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
    const/4 v3, 0x3

    .line 27
    :try_start_2
    sget-object v4, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAuxiliaryHeatingStateDto;->HEATING_AUXILIARY:Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAuxiliaryHeatingStateDto;

    .line 28
    .line 29
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    aput v3, v0, v4
    :try_end_2
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2 .. :try_end_2} :catch_2

    .line 34
    .line 35
    :catch_2
    const/4 v4, 0x4

    .line 36
    :try_start_3
    sget-object v5, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAuxiliaryHeatingStateDto;->VENTILATION:Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAuxiliaryHeatingStateDto;

    .line 37
    .line 38
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 39
    .line 40
    .line 41
    move-result v5

    .line 42
    aput v4, v0, v5
    :try_end_3
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3 .. :try_end_3} :catch_3

    .line 43
    .line 44
    :catch_3
    :try_start_4
    sget-object v5, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAuxiliaryHeatingStateDto;->INVALID:Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAuxiliaryHeatingStateDto;

    .line 45
    .line 46
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    const/4 v6, 0x5

    .line 51
    aput v6, v0, v5
    :try_end_4
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4 .. :try_end_4} :catch_4

    .line 52
    .line 53
    :catch_4
    :try_start_5
    sget-object v5, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAuxiliaryHeatingStateDto;->UNSUPPORTED:Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningAuxiliaryHeatingStateDto;

    .line 54
    .line 55
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 56
    .line 57
    .line 58
    move-result v5

    .line 59
    const/4 v6, 0x6

    .line 60
    aput v6, v0, v5
    :try_end_5
    .catch Ljava/lang/NoSuchFieldError; {:try_start_5 .. :try_end_5} :catch_5

    .line 61
    .line 62
    :catch_5
    sput-object v0, Ljz/a;->a:[I

    .line 63
    .line 64
    invoke-static {}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;->values()[Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    array-length v0, v0

    .line 69
    new-array v0, v0, [I

    .line 70
    .line 71
    :try_start_6
    sget-object v5, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;->CELSIUS:Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 72
    .line 73
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 74
    .line 75
    .line 76
    move-result v5

    .line 77
    aput v1, v0, v5
    :try_end_6
    .catch Ljava/lang/NoSuchFieldError; {:try_start_6 .. :try_end_6} :catch_6

    .line 78
    .line 79
    :catch_6
    :try_start_7
    sget-object v5, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;->FAHRENHEIT:Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 80
    .line 81
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 82
    .line 83
    .line 84
    move-result v5

    .line 85
    aput v2, v0, v5
    :try_end_7
    .catch Ljava/lang/NoSuchFieldError; {:try_start_7 .. :try_end_7} :catch_7

    .line 86
    .line 87
    :catch_7
    :try_start_8
    sget-object v5, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;->UNKNOWN:Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 88
    .line 89
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 90
    .line 91
    .line 92
    move-result v5

    .line 93
    aput v3, v0, v5
    :try_end_8
    .catch Ljava/lang/NoSuchFieldError; {:try_start_8 .. :try_end_8} :catch_8

    .line 94
    .line 95
    :catch_8
    sput-object v0, Ljz/a;->b:[I

    .line 96
    .line 97
    invoke-static {}, Lmz/a;->values()[Lmz/a;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    array-length v0, v0

    .line 102
    new-array v0, v0, [I

    .line 103
    .line 104
    const/4 v5, 0x0

    .line 105
    :try_start_9
    aput v1, v0, v5
    :try_end_9
    .catch Ljava/lang/NoSuchFieldError; {:try_start_9 .. :try_end_9} :catch_9

    .line 106
    .line 107
    :catch_9
    :try_start_a
    sget-object v6, Lmz/a;->d:Lmz/a;

    .line 108
    .line 109
    aput v2, v0, v1
    :try_end_a
    .catch Ljava/lang/NoSuchFieldError; {:try_start_a .. :try_end_a} :catch_a

    .line 110
    .line 111
    :catch_a
    :try_start_b
    sget-object v6, Lmz/a;->d:Lmz/a;

    .line 112
    .line 113
    aput v3, v0, v2
    :try_end_b
    .catch Ljava/lang/NoSuchFieldError; {:try_start_b .. :try_end_b} :catch_b

    .line 114
    .line 115
    :catch_b
    invoke-static {}, Lqr0/r;->values()[Lqr0/r;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    array-length v0, v0

    .line 120
    new-array v0, v0, [I

    .line 121
    .line 122
    :try_start_c
    aput v1, v0, v5
    :try_end_c
    .catch Ljava/lang/NoSuchFieldError; {:try_start_c .. :try_end_c} :catch_c

    .line 123
    .line 124
    :catch_c
    :try_start_d
    sget-object v6, Lqr0/r;->d:Lqr0/r;

    .line 125
    .line 126
    aput v2, v0, v1
    :try_end_d
    .catch Ljava/lang/NoSuchFieldError; {:try_start_d .. :try_end_d} :catch_d

    .line 127
    .line 128
    :catch_d
    invoke-static {}, Lmz/d;->values()[Lmz/d;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    array-length v0, v0

    .line 133
    new-array v0, v0, [I

    .line 134
    .line 135
    :try_start_e
    aput v1, v0, v5
    :try_end_e
    .catch Ljava/lang/NoSuchFieldError; {:try_start_e .. :try_end_e} :catch_e

    .line 136
    .line 137
    :catch_e
    :try_start_f
    sget-object v5, Lmz/d;->d:Lmz/d;

    .line 138
    .line 139
    aput v2, v0, v1
    :try_end_f
    .catch Ljava/lang/NoSuchFieldError; {:try_start_f .. :try_end_f} :catch_f

    .line 140
    .line 141
    :catch_f
    :try_start_10
    sget-object v1, Lmz/d;->d:Lmz/d;

    .line 142
    .line 143
    aput v3, v0, v2
    :try_end_10
    .catch Ljava/lang/NoSuchFieldError; {:try_start_10 .. :try_end_10} :catch_10

    .line 144
    .line 145
    :catch_10
    :try_start_11
    sget-object v1, Lmz/d;->d:Lmz/d;

    .line 146
    .line 147
    aput v4, v0, v3
    :try_end_11
    .catch Ljava/lang/NoSuchFieldError; {:try_start_11 .. :try_end_11} :catch_11

    .line 148
    .line 149
    :catch_11
    return-void
.end method
