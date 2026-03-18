.class public final enum Lf20/c;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic e:[Lf20/c;

.field public static final synthetic f:Lsx0/b;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    new-instance v0, Lf20/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const v2, 0x7f120273

    .line 5
    .line 6
    .line 7
    const-string v3, "Braking"

    .line 8
    .line 9
    invoke-direct {v0, v3, v1, v2}, Lf20/c;-><init>(Ljava/lang/String;II)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Lf20/c;

    .line 13
    .line 14
    const/4 v2, 0x1

    .line 15
    const v3, 0x7f120278

    .line 16
    .line 17
    .line 18
    const-string v4, "Speeding"

    .line 19
    .line 20
    invoke-direct {v1, v4, v2, v3}, Lf20/c;-><init>(Ljava/lang/String;II)V

    .line 21
    .line 22
    .line 23
    new-instance v2, Lf20/c;

    .line 24
    .line 25
    const/4 v3, 0x2

    .line 26
    const v4, 0x7f120272

    .line 27
    .line 28
    .line 29
    const-string v5, "Acceleration"

    .line 30
    .line 31
    invoke-direct {v2, v5, v3, v4}, Lf20/c;-><init>(Ljava/lang/String;II)V

    .line 32
    .line 33
    .line 34
    new-instance v3, Lf20/c;

    .line 35
    .line 36
    const/4 v4, 0x3

    .line 37
    const v5, 0x7f120275

    .line 38
    .line 39
    .line 40
    const-string v6, "FuelBatteryLevel"

    .line 41
    .line 42
    invoke-direct {v3, v6, v4, v5}, Lf20/c;-><init>(Ljava/lang/String;II)V

    .line 43
    .line 44
    .line 45
    new-instance v4, Lf20/c;

    .line 46
    .line 47
    const/4 v5, 0x4

    .line 48
    const v6, 0x7f120277

    .line 49
    .line 50
    .line 51
    const-string v7, "NightDrive"

    .line 52
    .line 53
    invoke-direct {v4, v7, v5, v6}, Lf20/c;-><init>(Ljava/lang/String;II)V

    .line 54
    .line 55
    .line 56
    new-instance v5, Lf20/c;

    .line 57
    .line 58
    const/4 v6, 0x5

    .line 59
    const v7, 0x7f120274

    .line 60
    .line 61
    .line 62
    const-string v8, "ExcessiveTripLength"

    .line 63
    .line 64
    invoke-direct {v5, v8, v6, v7}, Lf20/c;-><init>(Ljava/lang/String;II)V

    .line 65
    .line 66
    .line 67
    filled-new-array/range {v0 .. v5}, [Lf20/c;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    sput-object v0, Lf20/c;->e:[Lf20/c;

    .line 72
    .line 73
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    sput-object v0, Lf20/c;->f:Lsx0/b;

    .line 78
    .line 79
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lf20/c;->d:I

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lf20/c;
    .locals 1

    .line 1
    const-class v0, Lf20/c;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lf20/c;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lf20/c;
    .locals 1

    .line 1
    sget-object v0, Lf20/c;->e:[Lf20/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lf20/c;

    .line 8
    .line 9
    return-object v0
.end method
