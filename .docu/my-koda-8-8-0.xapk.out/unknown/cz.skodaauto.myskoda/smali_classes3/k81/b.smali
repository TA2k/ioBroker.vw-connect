.class public abstract synthetic Lk81/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:[I


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    invoke-static {}, Ls71/h;->values()[Ls71/h;

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
    sget-object v2, Ls71/h;->d:Ls71/h;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    aput v1, v0, v2
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    .line 14
    :catch_0
    const/4 v2, 0x2

    .line 15
    :try_start_1
    sget-object v3, Ls71/h;->d:Ls71/h;

    .line 16
    .line 17
    aput v2, v0, v1
    :try_end_1
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1 .. :try_end_1} :catch_1

    .line 18
    .line 19
    :catch_1
    const/4 v3, 0x3

    .line 20
    :try_start_2
    sget-object v4, Ls71/h;->d:Ls71/h;

    .line 21
    .line 22
    aput v3, v0, v3
    :try_end_2
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2 .. :try_end_2} :catch_2

    .line 23
    .line 24
    :catch_2
    const/4 v4, 0x4

    .line 25
    :try_start_3
    sget-object v5, Ls71/h;->d:Ls71/h;

    .line 26
    .line 27
    aput v4, v0, v2
    :try_end_3
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3 .. :try_end_3} :catch_3

    .line 28
    .line 29
    :catch_3
    :try_start_4
    sget-object v5, Ls71/h;->d:Ls71/h;

    .line 30
    .line 31
    const/4 v5, 0x5

    .line 32
    aput v5, v0, v4
    :try_end_4
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4 .. :try_end_4} :catch_4

    .line 33
    .line 34
    :catch_4
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    array-length v0, v0

    .line 39
    new-array v0, v0, [I

    .line 40
    .line 41
    :try_start_5
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;->NOT_AVAILABLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

    .line 42
    .line 43
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    aput v1, v0, v4
    :try_end_5
    .catch Ljava/lang/NoSuchFieldError; {:try_start_5 .. :try_end_5} :catch_5

    .line 48
    .line 49
    :catch_5
    :try_start_6
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;->PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

    .line 50
    .line 51
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    aput v2, v0, v4
    :try_end_6
    .catch Ljava/lang/NoSuchFieldError; {:try_start_6 .. :try_end_6} :catch_6

    .line 56
    .line 57
    :catch_6
    :try_start_7
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;->PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/FunctionAvailabilityStatusMEB;

    .line 58
    .line 59
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    aput v3, v0, v4
    :try_end_7
    .catch Ljava/lang/NoSuchFieldError; {:try_start_7 .. :try_end_7} :catch_7

    .line 64
    .line 65
    :catch_7
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    array-length v0, v0

    .line 70
    new-array v0, v0, [I

    .line 71
    .line 72
    :try_start_8
    sget-object v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;->INIT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 73
    .line 74
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 75
    .line 76
    .line 77
    move-result v4

    .line 78
    aput v1, v0, v4
    :try_end_8
    .catch Ljava/lang/NoSuchFieldError; {:try_start_8 .. :try_end_8} :catch_8

    .line 79
    .line 80
    :catch_8
    :try_start_9
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;->PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 81
    .line 82
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 83
    .line 84
    .line 85
    move-result v1

    .line 86
    aput v2, v0, v1
    :try_end_9
    .catch Ljava/lang/NoSuchFieldError; {:try_start_9 .. :try_end_9} :catch_9

    .line 87
    .line 88
    :catch_9
    :try_start_a
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;->PARKING_OUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 89
    .line 90
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    aput v3, v0, v1
    :try_end_a
    .catch Ljava/lang/NoSuchFieldError; {:try_start_a .. :try_end_a} :catch_a

    .line 95
    .line 96
    :catch_a
    sput-object v0, Lk81/b;->a:[I

    .line 97
    .line 98
    return-void
.end method
