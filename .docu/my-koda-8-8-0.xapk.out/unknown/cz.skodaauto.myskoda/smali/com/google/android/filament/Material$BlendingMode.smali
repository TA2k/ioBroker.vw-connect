.class public final enum Lcom/google/android/filament/Material$BlendingMode;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/Material;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "BlendingMode"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/google/android/filament/Material$BlendingMode;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lcom/google/android/filament/Material$BlendingMode;

.field public static final enum ADD:Lcom/google/android/filament/Material$BlendingMode;

.field public static final enum FADE:Lcom/google/android/filament/Material$BlendingMode;

.field public static final enum MASKED:Lcom/google/android/filament/Material$BlendingMode;

.field public static final enum MULTIPLY:Lcom/google/android/filament/Material$BlendingMode;

.field public static final enum OPAQUE:Lcom/google/android/filament/Material$BlendingMode;

.field public static final enum SCREEN:Lcom/google/android/filament/Material$BlendingMode;

.field public static final enum TRANSPARENT:Lcom/google/android/filament/Material$BlendingMode;


# direct methods
.method private static synthetic $values()[Lcom/google/android/filament/Material$BlendingMode;
    .locals 7

    .line 1
    sget-object v0, Lcom/google/android/filament/Material$BlendingMode;->OPAQUE:Lcom/google/android/filament/Material$BlendingMode;

    .line 2
    .line 3
    sget-object v1, Lcom/google/android/filament/Material$BlendingMode;->TRANSPARENT:Lcom/google/android/filament/Material$BlendingMode;

    .line 4
    .line 5
    sget-object v2, Lcom/google/android/filament/Material$BlendingMode;->ADD:Lcom/google/android/filament/Material$BlendingMode;

    .line 6
    .line 7
    sget-object v3, Lcom/google/android/filament/Material$BlendingMode;->MASKED:Lcom/google/android/filament/Material$BlendingMode;

    .line 8
    .line 9
    sget-object v4, Lcom/google/android/filament/Material$BlendingMode;->FADE:Lcom/google/android/filament/Material$BlendingMode;

    .line 10
    .line 11
    sget-object v5, Lcom/google/android/filament/Material$BlendingMode;->MULTIPLY:Lcom/google/android/filament/Material$BlendingMode;

    .line 12
    .line 13
    sget-object v6, Lcom/google/android/filament/Material$BlendingMode;->SCREEN:Lcom/google/android/filament/Material$BlendingMode;

    .line 14
    .line 15
    filled-new-array/range {v0 .. v6}, [Lcom/google/android/filament/Material$BlendingMode;

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
    new-instance v0, Lcom/google/android/filament/Material$BlendingMode;

    .line 2
    .line 3
    const-string v1, "OPAQUE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Material$BlendingMode;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/google/android/filament/Material$BlendingMode;->OPAQUE:Lcom/google/android/filament/Material$BlendingMode;

    .line 10
    .line 11
    new-instance v0, Lcom/google/android/filament/Material$BlendingMode;

    .line 12
    .line 13
    const-string v1, "TRANSPARENT"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Material$BlendingMode;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcom/google/android/filament/Material$BlendingMode;->TRANSPARENT:Lcom/google/android/filament/Material$BlendingMode;

    .line 20
    .line 21
    new-instance v0, Lcom/google/android/filament/Material$BlendingMode;

    .line 22
    .line 23
    const-string v1, "ADD"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Material$BlendingMode;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lcom/google/android/filament/Material$BlendingMode;->ADD:Lcom/google/android/filament/Material$BlendingMode;

    .line 30
    .line 31
    new-instance v0, Lcom/google/android/filament/Material$BlendingMode;

    .line 32
    .line 33
    const-string v1, "MASKED"

    .line 34
    .line 35
    const/4 v2, 0x3

    .line 36
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Material$BlendingMode;-><init>(Ljava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lcom/google/android/filament/Material$BlendingMode;->MASKED:Lcom/google/android/filament/Material$BlendingMode;

    .line 40
    .line 41
    new-instance v0, Lcom/google/android/filament/Material$BlendingMode;

    .line 42
    .line 43
    const-string v1, "FADE"

    .line 44
    .line 45
    const/4 v2, 0x4

    .line 46
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Material$BlendingMode;-><init>(Ljava/lang/String;I)V

    .line 47
    .line 48
    .line 49
    sput-object v0, Lcom/google/android/filament/Material$BlendingMode;->FADE:Lcom/google/android/filament/Material$BlendingMode;

    .line 50
    .line 51
    new-instance v0, Lcom/google/android/filament/Material$BlendingMode;

    .line 52
    .line 53
    const-string v1, "MULTIPLY"

    .line 54
    .line 55
    const/4 v2, 0x5

    .line 56
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Material$BlendingMode;-><init>(Ljava/lang/String;I)V

    .line 57
    .line 58
    .line 59
    sput-object v0, Lcom/google/android/filament/Material$BlendingMode;->MULTIPLY:Lcom/google/android/filament/Material$BlendingMode;

    .line 60
    .line 61
    new-instance v0, Lcom/google/android/filament/Material$BlendingMode;

    .line 62
    .line 63
    const-string v1, "SCREEN"

    .line 64
    .line 65
    const/4 v2, 0x6

    .line 66
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/Material$BlendingMode;-><init>(Ljava/lang/String;I)V

    .line 67
    .line 68
    .line 69
    sput-object v0, Lcom/google/android/filament/Material$BlendingMode;->SCREEN:Lcom/google/android/filament/Material$BlendingMode;

    .line 70
    .line 71
    invoke-static {}, Lcom/google/android/filament/Material$BlendingMode;->$values()[Lcom/google/android/filament/Material$BlendingMode;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    sput-object v0, Lcom/google/android/filament/Material$BlendingMode;->$VALUES:[Lcom/google/android/filament/Material$BlendingMode;

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

.method public static valueOf(Ljava/lang/String;)Lcom/google/android/filament/Material$BlendingMode;
    .locals 1

    .line 1
    const-class v0, Lcom/google/android/filament/Material$BlendingMode;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/google/android/filament/Material$BlendingMode;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/google/android/filament/Material$BlendingMode;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/filament/Material$BlendingMode;->$VALUES:[Lcom/google/android/filament/Material$BlendingMode;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/google/android/filament/Material$BlendingMode;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/google/android/filament/Material$BlendingMode;

    .line 8
    .line 9
    return-object v0
.end method
