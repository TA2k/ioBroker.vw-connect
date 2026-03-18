.class public final enum Lkj/b;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum e:Lkj/b;

.field public static final synthetic f:[Lkj/b;

.field public static final synthetic g:Lsx0/b;


# instance fields
.field public final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Lkj/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, "OK"

    .line 5
    .line 6
    const-string v3, "Ok"

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Lkj/b;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lkj/b;->e:Lkj/b;

    .line 12
    .line 13
    new-instance v1, Lkj/b;

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    const-string v3, "UNSUPPORTED_QRCODE"

    .line 17
    .line 18
    const-string v4, "UnsupportedQrCode"

    .line 19
    .line 20
    invoke-direct {v1, v4, v2, v3}, Lkj/b;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    new-instance v2, Lkj/b;

    .line 24
    .line 25
    const/4 v3, 0x2

    .line 26
    const-string v4, "UNSUPPORTED_CHARGING_POINT"

    .line 27
    .line 28
    const-string v5, "UnsupportedChargingPoint"

    .line 29
    .line 30
    invoke-direct {v2, v5, v3, v4}, Lkj/b;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 31
    .line 32
    .line 33
    new-instance v3, Lkj/b;

    .line 34
    .line 35
    const/4 v4, 0x3

    .line 36
    const-string v5, "NO_ACTIVE_SUBSCRIPTION"

    .line 37
    .line 38
    const-string v6, "NoActiveSubscription"

    .line 39
    .line 40
    invoke-direct {v3, v6, v4, v5}, Lkj/b;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 41
    .line 42
    .line 43
    filled-new-array {v0, v1, v2, v3}, [Lkj/b;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    sput-object v0, Lkj/b;->f:[Lkj/b;

    .line 48
    .line 49
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    sput-object v0, Lkj/b;->g:Lsx0/b;

    .line 54
    .line 55
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lkj/b;->d:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lkj/b;
    .locals 1

    .line 1
    const-class v0, Lkj/b;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lkj/b;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lkj/b;
    .locals 1

    .line 1
    sget-object v0, Lkj/b;->f:[Lkj/b;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lkj/b;

    .line 8
    .line 9
    return-object v0
.end method
