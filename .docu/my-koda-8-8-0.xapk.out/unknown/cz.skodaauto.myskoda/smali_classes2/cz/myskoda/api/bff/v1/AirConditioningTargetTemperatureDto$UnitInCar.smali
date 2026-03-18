.class public final enum Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lcom/squareup/moshi/JsonClass;
    generateAdapter = false
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "UnitInCar"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0007\u0008\u0087\u0081\u0002\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00000\u0001B\u0011\u0008\u0002\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007j\u0002\u0008\u0008j\u0002\u0008\t\u00a8\u0006\n"
    }
    d2 = {
        "Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;",
        "",
        "value",
        "",
        "<init>",
        "(Ljava/lang/String;ILjava/lang/String;)V",
        "getValue",
        "()Ljava/lang/String;",
        "CELSIUS",
        "FAHRENHEIT",
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


# static fields
.field private static final synthetic $ENTRIES:Lsx0/a;

.field private static final synthetic $VALUES:[Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;

.field public static final enum CELSIUS:Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "CELSIUS"
    .end annotation
.end field

.field public static final enum FAHRENHEIT:Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;
    .annotation runtime Lcom/squareup/moshi/Json;
        name = "FAHRENHEIT"
    .end annotation
.end field


# instance fields
.field private final value:Ljava/lang/String;


# direct methods
.method private static final synthetic $values()[Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;
    .locals 2

    .line 1
    sget-object v0, Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;->CELSIUS:Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 2
    .line 3
    sget-object v1, Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;->FAHRENHEIT:Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 4
    .line 5
    filled-new-array {v0, v1}, [Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 2
    .line 3
    const-string v1, "CELSIUS"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;->CELSIUS:Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 10
    .line 11
    new-instance v0, Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 12
    .line 13
    const-string v1, "FAHRENHEIT"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2, v1}, Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;->FAHRENHEIT:Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 20
    .line 21
    invoke-static {}, Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;->$values()[Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;->$VALUES:[Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 26
    .line 27
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;->$ENTRIES:Lsx0/a;

    .line 32
    .line 33
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;->value:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static getEntries()Lsx0/a;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lsx0/a;"
        }
    .end annotation

    .line 1
    sget-object v0, Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;
    .locals 1

    .line 1
    const-class v0, Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;
    .locals 1

    .line 1
    sget-object v0, Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;->$VALUES:[Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final getValue()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcz/myskoda/api/bff/v1/AirConditioningTargetTemperatureDto$UnitInCar;->value:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
