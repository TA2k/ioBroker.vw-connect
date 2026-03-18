.class public final Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoRequest;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0002\u0008\u0003\u0008\u00c0\u0002\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003R\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007\u00a8\u0006\u0008"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoRequest;",
        "",
        "<init>",
        "()V",
        "byteArray",
        "",
        "getByteArray",
        "()[B",
        "genx_release"
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
.field public static final INSTANCE:Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoRequest;

.field private static final byteArray:[B


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoRequest;

    .line 2
    .line 3
    invoke-direct {v0}, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoRequest;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoRequest;->INSTANCE:Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoRequest;

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    new-array v0, v0, [B

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    aput-byte v1, v0, v1

    .line 13
    .line 14
    sput-object v0, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoRequest;->byteArray:[B

    .line 15
    .line 16
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final getByteArray()[B
    .locals 0

    .line 1
    sget-object p0, Ltechnology/cariad/cat/genx/services/kes/VehicleKeyInfoRequest;->byteArray:[B

    .line 2
    .line 3
    return-object p0
.end method
