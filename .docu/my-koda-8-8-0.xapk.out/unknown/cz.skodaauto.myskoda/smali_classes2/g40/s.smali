.class public final enum Lg40/s;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Lg40/s;

.field public static final enum e:Lg40/s;

.field public static final enum f:Lg40/s;

.field public static final enum g:Lg40/s;

.field public static final enum h:Lg40/s;

.field public static final enum i:Lg40/s;

.field public static final enum j:Lg40/s;

.field public static final enum k:Lg40/s;

.field public static final synthetic l:[Lg40/s;


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    new-instance v0, Lg40/s;

    .line 2
    .line 3
    const-string v1, "CarInGarage"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lg40/s;->d:Lg40/s;

    .line 10
    .line 11
    new-instance v1, Lg40/s;

    .line 12
    .line 13
    const-string v2, "MarketingConsent"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lg40/s;->e:Lg40/s;

    .line 20
    .line 21
    new-instance v2, Lg40/s;

    .line 22
    .line 23
    const-string v3, "PreferredDealerSelection"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Lg40/s;->f:Lg40/s;

    .line 30
    .line 31
    new-instance v3, Lg40/s;

    .line 32
    .line 33
    const-string v4, "Prolongation"

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v3, Lg40/s;->g:Lg40/s;

    .line 40
    .line 41
    new-instance v4, Lg40/s;

    .line 42
    .line 43
    const-string v5, "ServiceAppointment"

    .line 44
    .line 45
    const/4 v6, 0x4

    .line 46
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    sput-object v4, Lg40/s;->h:Lg40/s;

    .line 50
    .line 51
    new-instance v5, Lg40/s;

    .line 52
    .line 53
    const-string v6, "Telemetric"

    .line 54
    .line 55
    const/4 v7, 0x5

    .line 56
    invoke-direct {v5, v6, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 57
    .line 58
    .line 59
    sput-object v5, Lg40/s;->i:Lg40/s;

    .line 60
    .line 61
    new-instance v6, Lg40/s;

    .line 62
    .line 63
    const-string v7, "ThirdPartyConsent"

    .line 64
    .line 65
    const/4 v8, 0x6

    .line 66
    invoke-direct {v6, v7, v8}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 67
    .line 68
    .line 69
    sput-object v6, Lg40/s;->j:Lg40/s;

    .line 70
    .line 71
    new-instance v7, Lg40/s;

    .line 72
    .line 73
    const-string v8, "Unknown"

    .line 74
    .line 75
    const/4 v9, 0x7

    .line 76
    invoke-direct {v7, v8, v9}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 77
    .line 78
    .line 79
    sput-object v7, Lg40/s;->k:Lg40/s;

    .line 80
    .line 81
    filled-new-array/range {v0 .. v7}, [Lg40/s;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    sput-object v0, Lg40/s;->l:[Lg40/s;

    .line 86
    .line 87
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 88
    .line 89
    .line 90
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lg40/s;
    .locals 1

    .line 1
    const-class v0, Lg40/s;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lg40/s;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lg40/s;
    .locals 1

    .line 1
    sget-object v0, Lg40/s;->l:[Lg40/s;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lg40/s;

    .line 8
    .line 9
    return-object v0
.end method
