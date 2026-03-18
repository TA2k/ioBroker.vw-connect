.class public final enum Llf0/h;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final enum d:Llf0/h;

.field public static final enum e:Llf0/h;

.field public static final enum f:Llf0/h;

.field public static final enum g:Llf0/h;

.field public static final enum h:Llf0/h;

.field public static final enum i:Llf0/h;

.field public static final enum j:Llf0/h;

.field public static final enum k:Llf0/h;

.field public static final synthetic l:[Llf0/h;


# direct methods
.method static constructor <clinit>()V
    .locals 11

    .line 1
    new-instance v0, Llf0/h;

    .line 2
    .line 3
    const-string v1, "Inactive"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Llf0/h;->d:Llf0/h;

    .line 10
    .line 11
    new-instance v1, Llf0/h;

    .line 12
    .line 13
    const-string v2, "ResetSpin"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Llf0/h;->e:Llf0/h;

    .line 20
    .line 21
    new-instance v2, Llf0/h;

    .line 22
    .line 23
    const-string v3, "MissingData"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Llf0/h;->f:Llf0/h;

    .line 30
    .line 31
    new-instance v3, Llf0/h;

    .line 32
    .line 33
    const-string v4, "WorkshopMode"

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v3, Llf0/h;->g:Llf0/h;

    .line 40
    .line 41
    new-instance v4, Llf0/h;

    .line 42
    .line 43
    const-string v5, "PrivacyMode"

    .line 44
    .line 45
    const/4 v6, 0x4

    .line 46
    invoke-direct {v4, v5, v6}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    new-instance v5, Llf0/h;

    .line 50
    .line 51
    const-string v6, "ActivationFailed"

    .line 52
    .line 53
    const/4 v7, 0x5

    .line 54
    invoke-direct {v5, v6, v7}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 55
    .line 56
    .line 57
    sput-object v5, Llf0/h;->h:Llf0/h;

    .line 58
    .line 59
    new-instance v6, Llf0/h;

    .line 60
    .line 61
    const-string v7, "GuestInactive"

    .line 62
    .line 63
    const/4 v8, 0x6

    .line 64
    invoke-direct {v6, v7, v8}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 65
    .line 66
    .line 67
    sput-object v6, Llf0/h;->i:Llf0/h;

    .line 68
    .line 69
    new-instance v7, Llf0/h;

    .line 70
    .line 71
    const-string v8, "GuestWaiting"

    .line 72
    .line 73
    const/4 v9, 0x7

    .line 74
    invoke-direct {v7, v8, v9}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 75
    .line 76
    .line 77
    sput-object v7, Llf0/h;->j:Llf0/h;

    .line 78
    .line 79
    new-instance v8, Llf0/h;

    .line 80
    .line 81
    const-string v9, "Usable"

    .line 82
    .line 83
    const/16 v10, 0x8

    .line 84
    .line 85
    invoke-direct {v8, v9, v10}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 86
    .line 87
    .line 88
    sput-object v8, Llf0/h;->k:Llf0/h;

    .line 89
    .line 90
    filled-new-array/range {v0 .. v8}, [Llf0/h;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    sput-object v0, Llf0/h;->l:[Llf0/h;

    .line 95
    .line 96
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 97
    .line 98
    .line 99
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llf0/h;
    .locals 1

    .line 1
    const-class v0, Llf0/h;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Llf0/h;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Llf0/h;
    .locals 1

    .line 1
    sget-object v0, Llf0/h;->l:[Llf0/h;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Llf0/h;

    .line 8
    .line 9
    return-object v0
.end method
