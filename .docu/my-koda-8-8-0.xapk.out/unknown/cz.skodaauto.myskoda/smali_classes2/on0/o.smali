.class public final enum Lon0/o;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Lon0/o;

.field public static final enum f:Lon0/o;

.field public static final enum g:Lon0/o;

.field public static final enum h:Lon0/o;

.field public static final enum i:Lon0/o;

.field public static final synthetic j:[Lon0/o;


# instance fields
.field public final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Lon0/o;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "INVALID_OPERATION_TRANSACTION_BLOCKED"

    .line 5
    .line 6
    const-string v3, "InvalidOperationTransactionBlocked"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Lon0/o;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lon0/o;->e:Lon0/o;

    .line 12
    .line 13
    new-instance v1, Lon0/o;

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    const-string v3, "VENDOR_ERROR"

    .line 17
    .line 18
    const-string v4, "VendorError"

    .line 19
    .line 20
    invoke-direct {v1, v4, v2, v3}, Lon0/o;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    sput-object v1, Lon0/o;->f:Lon0/o;

    .line 24
    .line 25
    new-instance v2, Lon0/o;

    .line 26
    .line 27
    const/4 v3, 0x2

    .line 28
    const-string v4, "NO_DEFAULT_VEHICLE"

    .line 29
    .line 30
    const-string v5, "NoDefaultVehicle"

    .line 31
    .line 32
    invoke-direct {v2, v5, v3, v4}, Lon0/o;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 33
    .line 34
    .line 35
    sput-object v2, Lon0/o;->g:Lon0/o;

    .line 36
    .line 37
    new-instance v3, Lon0/o;

    .line 38
    .line 39
    const/4 v4, 0x3

    .line 40
    const-string v5, "PROCESSING_ERROR"

    .line 41
    .line 42
    const-string v6, "ProcessingError"

    .line 43
    .line 44
    invoke-direct {v3, v6, v4, v5}, Lon0/o;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 45
    .line 46
    .line 47
    sput-object v3, Lon0/o;->h:Lon0/o;

    .line 48
    .line 49
    new-instance v4, Lon0/o;

    .line 50
    .line 51
    const/4 v5, 0x4

    .line 52
    const-string v6, "UNKNOWN"

    .line 53
    .line 54
    const-string v7, "Unknown"

    .line 55
    .line 56
    invoke-direct {v4, v7, v5, v6}, Lon0/o;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 57
    .line 58
    .line 59
    sput-object v4, Lon0/o;->i:Lon0/o;

    .line 60
    .line 61
    filled-new-array {v0, v1, v2, v3, v4}, [Lon0/o;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    sput-object v0, Lon0/o;->j:[Lon0/o;

    .line 66
    .line 67
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 68
    .line 69
    .line 70
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lon0/o;->d:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lon0/o;
    .locals 1

    .line 1
    const-class v0, Lon0/o;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lon0/o;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lon0/o;
    .locals 1

    .line 1
    sget-object v0, Lon0/o;->j:[Lon0/o;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lon0/o;

    .line 8
    .line 9
    return-object v0
.end method
