.class public final enum Lcom/google/android/filament/Texture$Type;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/Texture;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "Type"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/google/android/filament/Texture$Type;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lcom/google/android/filament/Texture$Type;

.field public static final enum BYTE:Lcom/google/android/filament/Texture$Type;

.field public static final enum COMPRESSED:Lcom/google/android/filament/Texture$Type;

.field public static final enum FLOAT:Lcom/google/android/filament/Texture$Type;

.field public static final enum HALF:Lcom/google/android/filament/Texture$Type;

.field public static final enum INT:Lcom/google/android/filament/Texture$Type;

.field public static final enum SHORT:Lcom/google/android/filament/Texture$Type;

.field public static final enum UBYTE:Lcom/google/android/filament/Texture$Type;

.field public static final enum UINT:Lcom/google/android/filament/Texture$Type;

.field public static final enum UINT_10F_11F_11F_REV:Lcom/google/android/filament/Texture$Type;

.field public static final enum USHORT:Lcom/google/android/filament/Texture$Type;

.field public static final enum USHORT_565:Lcom/google/android/filament/Texture$Type;


# direct methods
.method private static synthetic $values()[Lcom/google/android/filament/Texture$Type;
    .locals 11

    .line 1
    sget-object v0, Lcom/google/android/filament/Texture$Type;->UBYTE:Lcom/google/android/filament/Texture$Type;

    .line 2
    .line 3
    sget-object v1, Lcom/google/android/filament/Texture$Type;->BYTE:Lcom/google/android/filament/Texture$Type;

    .line 4
    .line 5
    sget-object v2, Lcom/google/android/filament/Texture$Type;->USHORT:Lcom/google/android/filament/Texture$Type;

    .line 6
    .line 7
    sget-object v3, Lcom/google/android/filament/Texture$Type;->SHORT:Lcom/google/android/filament/Texture$Type;

    .line 8
    .line 9
    sget-object v4, Lcom/google/android/filament/Texture$Type;->UINT:Lcom/google/android/filament/Texture$Type;

    .line 10
    .line 11
    sget-object v5, Lcom/google/android/filament/Texture$Type;->INT:Lcom/google/android/filament/Texture$Type;

    .line 12
    .line 13
    sget-object v6, Lcom/google/android/filament/Texture$Type;->HALF:Lcom/google/android/filament/Texture$Type;

    .line 14
    .line 15
    sget-object v7, Lcom/google/android/filament/Texture$Type;->FLOAT:Lcom/google/android/filament/Texture$Type;

    .line 16
    .line 17
    sget-object v8, Lcom/google/android/filament/Texture$Type;->COMPRESSED:Lcom/google/android/filament/Texture$Type;

    .line 18
    .line 19
    sget-object v9, Lcom/google/android/filament/Texture$Type;->UINT_10F_11F_11F_REV:Lcom/google/android/filament/Texture$Type;

    .line 20
    .line 21
    sget-object v10, Lcom/google/android/filament/Texture$Type;->USHORT_565:Lcom/google/android/filament/Texture$Type;

    .line 22
    .line 23
    filled-new-array/range {v0 .. v10}, [Lcom/google/android/filament/Texture$Type;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcom/google/android/filament/Texture$Type;

    .line 2
    .line 3
    const-string v1, "UBYTE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Texture$Type;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/google/android/filament/Texture$Type;->UBYTE:Lcom/google/android/filament/Texture$Type;

    .line 10
    .line 11
    new-instance v0, Lcom/google/android/filament/Texture$Type;

    .line 12
    .line 13
    const-string v1, "BYTE"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Texture$Type;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcom/google/android/filament/Texture$Type;->BYTE:Lcom/google/android/filament/Texture$Type;

    .line 20
    .line 21
    new-instance v0, Lcom/google/android/filament/Texture$Type;

    .line 22
    .line 23
    const-string v1, "USHORT"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Texture$Type;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lcom/google/android/filament/Texture$Type;->USHORT:Lcom/google/android/filament/Texture$Type;

    .line 30
    .line 31
    new-instance v0, Lcom/google/android/filament/Texture$Type;

    .line 32
    .line 33
    const-string v1, "SHORT"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Texture$Type;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lcom/google/android/filament/Texture$Type;->SHORT:Lcom/google/android/filament/Texture$Type;

    .line 40
    .line 41
    new-instance v0, Lcom/google/android/filament/Texture$Type;

    .line 42
    .line 43
    const-string v1, "UINT"

    .line 44
    .line 45
    const/4 v2, 0x4

    .line 46
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Texture$Type;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Lcom/google/android/filament/Texture$Type;->UINT:Lcom/google/android/filament/Texture$Type;

    .line 50
    .line 51
    new-instance v0, Lcom/google/android/filament/Texture$Type;

    .line 52
    .line 53
    const-string v1, "INT"

    .line 54
    .line 55
    const/4 v2, 0x5

    .line 56
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Texture$Type;-><init>(Ljava/lang/String;I)V

    .line 57
    .line 58
    .line 59
    sput-object v0, Lcom/google/android/filament/Texture$Type;->INT:Lcom/google/android/filament/Texture$Type;

    .line 60
    .line 61
    new-instance v0, Lcom/google/android/filament/Texture$Type;

    .line 62
    .line 63
    const-string v1, "HALF"

    .line 64
    .line 65
    const/4 v2, 0x6

    .line 66
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Texture$Type;-><init>(Ljava/lang/String;I)V

    .line 67
    .line 68
    .line 69
    sput-object v0, Lcom/google/android/filament/Texture$Type;->HALF:Lcom/google/android/filament/Texture$Type;

    .line 70
    .line 71
    new-instance v0, Lcom/google/android/filament/Texture$Type;

    .line 72
    .line 73
    const-string v1, "FLOAT"

    .line 74
    .line 75
    const/4 v2, 0x7

    .line 76
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Texture$Type;-><init>(Ljava/lang/String;I)V

    .line 77
    .line 78
    .line 79
    sput-object v0, Lcom/google/android/filament/Texture$Type;->FLOAT:Lcom/google/android/filament/Texture$Type;

    .line 80
    .line 81
    new-instance v0, Lcom/google/android/filament/Texture$Type;

    .line 82
    .line 83
    const-string v1, "COMPRESSED"

    .line 84
    .line 85
    const/16 v2, 0x8

    .line 86
    .line 87
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Texture$Type;-><init>(Ljava/lang/String;I)V

    .line 88
    .line 89
    .line 90
    sput-object v0, Lcom/google/android/filament/Texture$Type;->COMPRESSED:Lcom/google/android/filament/Texture$Type;

    .line 91
    .line 92
    new-instance v0, Lcom/google/android/filament/Texture$Type;

    .line 93
    .line 94
    const-string v1, "UINT_10F_11F_11F_REV"

    .line 95
    .line 96
    const/16 v2, 0x9

    .line 97
    .line 98
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Texture$Type;-><init>(Ljava/lang/String;I)V

    .line 99
    .line 100
    .line 101
    sput-object v0, Lcom/google/android/filament/Texture$Type;->UINT_10F_11F_11F_REV:Lcom/google/android/filament/Texture$Type;

    .line 102
    .line 103
    new-instance v0, Lcom/google/android/filament/Texture$Type;

    .line 104
    .line 105
    const-string v1, "USHORT_565"

    .line 106
    .line 107
    const/16 v2, 0xa

    .line 108
    .line 109
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Texture$Type;-><init>(Ljava/lang/String;I)V

    .line 110
    .line 111
    .line 112
    sput-object v0, Lcom/google/android/filament/Texture$Type;->USHORT_565:Lcom/google/android/filament/Texture$Type;

    .line 113
    .line 114
    invoke-static {}, Lcom/google/android/filament/Texture$Type;->$values()[Lcom/google/android/filament/Texture$Type;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    sput-object v0, Lcom/google/android/filament/Texture$Type;->$VALUES:[Lcom/google/android/filament/Texture$Type;

    .line 119
    .line 120
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;I)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/google/android/filament/Texture$Type;
    .locals 1

    .line 1
    const-class v0, Lcom/google/android/filament/Texture$Type;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/google/android/filament/Texture$Type;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/google/android/filament/Texture$Type;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/filament/Texture$Type;->$VALUES:[Lcom/google/android/filament/Texture$Type;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/google/android/filament/Texture$Type;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/google/android/filament/Texture$Type;

    .line 8
    .line 9
    return-object v0
.end method
