.class final enum Lcom/google/android/filament/NioUtils$BufferType;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/NioUtils;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "BufferType"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/google/android/filament/NioUtils$BufferType;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lcom/google/android/filament/NioUtils$BufferType;

.field public static final enum BYTE:Lcom/google/android/filament/NioUtils$BufferType;

.field public static final enum CHAR:Lcom/google/android/filament/NioUtils$BufferType;

.field public static final enum DOUBLE:Lcom/google/android/filament/NioUtils$BufferType;

.field public static final enum FLOAT:Lcom/google/android/filament/NioUtils$BufferType;

.field public static final enum INT:Lcom/google/android/filament/NioUtils$BufferType;

.field public static final enum LONG:Lcom/google/android/filament/NioUtils$BufferType;

.field public static final enum SHORT:Lcom/google/android/filament/NioUtils$BufferType;


# direct methods
.method private static synthetic $values()[Lcom/google/android/filament/NioUtils$BufferType;
    .locals 7

    .line 1
    sget-object v0, Lcom/google/android/filament/NioUtils$BufferType;->BYTE:Lcom/google/android/filament/NioUtils$BufferType;

    .line 2
    .line 3
    sget-object v1, Lcom/google/android/filament/NioUtils$BufferType;->CHAR:Lcom/google/android/filament/NioUtils$BufferType;

    .line 4
    .line 5
    sget-object v2, Lcom/google/android/filament/NioUtils$BufferType;->SHORT:Lcom/google/android/filament/NioUtils$BufferType;

    .line 6
    .line 7
    sget-object v3, Lcom/google/android/filament/NioUtils$BufferType;->INT:Lcom/google/android/filament/NioUtils$BufferType;

    .line 8
    .line 9
    sget-object v4, Lcom/google/android/filament/NioUtils$BufferType;->LONG:Lcom/google/android/filament/NioUtils$BufferType;

    .line 10
    .line 11
    sget-object v5, Lcom/google/android/filament/NioUtils$BufferType;->FLOAT:Lcom/google/android/filament/NioUtils$BufferType;

    .line 12
    .line 13
    sget-object v6, Lcom/google/android/filament/NioUtils$BufferType;->DOUBLE:Lcom/google/android/filament/NioUtils$BufferType;

    .line 14
    .line 15
    filled-new-array/range {v0 .. v6}, [Lcom/google/android/filament/NioUtils$BufferType;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcom/google/android/filament/NioUtils$BufferType;

    .line 2
    .line 3
    const-string v1, "BYTE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/NioUtils$BufferType;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/google/android/filament/NioUtils$BufferType;->BYTE:Lcom/google/android/filament/NioUtils$BufferType;

    .line 10
    .line 11
    new-instance v0, Lcom/google/android/filament/NioUtils$BufferType;

    .line 12
    .line 13
    const-string v1, "CHAR"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/NioUtils$BufferType;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcom/google/android/filament/NioUtils$BufferType;->CHAR:Lcom/google/android/filament/NioUtils$BufferType;

    .line 20
    .line 21
    new-instance v0, Lcom/google/android/filament/NioUtils$BufferType;

    .line 22
    .line 23
    const-string v1, "SHORT"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/NioUtils$BufferType;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lcom/google/android/filament/NioUtils$BufferType;->SHORT:Lcom/google/android/filament/NioUtils$BufferType;

    .line 30
    .line 31
    new-instance v0, Lcom/google/android/filament/NioUtils$BufferType;

    .line 32
    .line 33
    const-string v1, "INT"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/NioUtils$BufferType;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lcom/google/android/filament/NioUtils$BufferType;->INT:Lcom/google/android/filament/NioUtils$BufferType;

    .line 40
    .line 41
    new-instance v0, Lcom/google/android/filament/NioUtils$BufferType;

    .line 42
    .line 43
    const-string v1, "LONG"

    .line 44
    .line 45
    const/4 v2, 0x4

    .line 46
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/NioUtils$BufferType;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Lcom/google/android/filament/NioUtils$BufferType;->LONG:Lcom/google/android/filament/NioUtils$BufferType;

    .line 50
    .line 51
    new-instance v0, Lcom/google/android/filament/NioUtils$BufferType;

    .line 52
    .line 53
    const-string v1, "FLOAT"

    .line 54
    .line 55
    const/4 v2, 0x5

    .line 56
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/NioUtils$BufferType;-><init>(Ljava/lang/String;I)V

    .line 57
    .line 58
    .line 59
    sput-object v0, Lcom/google/android/filament/NioUtils$BufferType;->FLOAT:Lcom/google/android/filament/NioUtils$BufferType;

    .line 60
    .line 61
    new-instance v0, Lcom/google/android/filament/NioUtils$BufferType;

    .line 62
    .line 63
    const-string v1, "DOUBLE"

    .line 64
    .line 65
    const/4 v2, 0x6

    .line 66
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/NioUtils$BufferType;-><init>(Ljava/lang/String;I)V

    .line 67
    .line 68
    .line 69
    sput-object v0, Lcom/google/android/filament/NioUtils$BufferType;->DOUBLE:Lcom/google/android/filament/NioUtils$BufferType;

    .line 70
    .line 71
    invoke-static {}, Lcom/google/android/filament/NioUtils$BufferType;->$values()[Lcom/google/android/filament/NioUtils$BufferType;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    sput-object v0, Lcom/google/android/filament/NioUtils$BufferType;->$VALUES:[Lcom/google/android/filament/NioUtils$BufferType;

    .line 76
    .line 77
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

.method public static valueOf(Ljava/lang/String;)Lcom/google/android/filament/NioUtils$BufferType;
    .locals 1

    .line 1
    const-class v0, Lcom/google/android/filament/NioUtils$BufferType;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/google/android/filament/NioUtils$BufferType;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/google/android/filament/NioUtils$BufferType;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/filament/NioUtils$BufferType;->$VALUES:[Lcom/google/android/filament/NioUtils$BufferType;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/google/android/filament/NioUtils$BufferType;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/google/android/filament/NioUtils$BufferType;

    .line 8
    .line 9
    return-object v0
.end method
