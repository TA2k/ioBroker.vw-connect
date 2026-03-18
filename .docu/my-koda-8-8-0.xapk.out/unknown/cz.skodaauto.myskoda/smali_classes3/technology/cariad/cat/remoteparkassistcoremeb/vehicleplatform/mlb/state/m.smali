.class public abstract synthetic Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:[I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->values()[Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

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
    :try_start_0
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->IN_PROGRESS:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 9
    .line 10
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    const/4 v2, 0x1

    .line 15
    aput v2, v0, v1
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    .line 17
    :catch_0
    :try_start_1
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->ABORTED_RESUMING_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    const/4 v2, 0x2

    .line 24
    aput v2, v0, v1
    :try_end_1
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1 .. :try_end_1} :catch_1

    .line 25
    .line 26
    :catch_1
    sput-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/m;->a:[I

    .line 27
    .line 28
    return-void
.end method
