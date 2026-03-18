.class public final enum Lcom/google/android/filament/RenderableManager$PrimitiveType;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/RenderableManager;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "PrimitiveType"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/google/android/filament/RenderableManager$PrimitiveType;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lcom/google/android/filament/RenderableManager$PrimitiveType;

.field public static final enum LINES:Lcom/google/android/filament/RenderableManager$PrimitiveType;

.field public static final enum LINE_STRIP:Lcom/google/android/filament/RenderableManager$PrimitiveType;

.field public static final enum POINTS:Lcom/google/android/filament/RenderableManager$PrimitiveType;

.field public static final enum TRIANGLES:Lcom/google/android/filament/RenderableManager$PrimitiveType;

.field public static final enum TRIANGLE_STRIP:Lcom/google/android/filament/RenderableManager$PrimitiveType;


# instance fields
.field private final mType:I


# direct methods
.method private static synthetic $values()[Lcom/google/android/filament/RenderableManager$PrimitiveType;
    .locals 5

    .line 1
    sget-object v0, Lcom/google/android/filament/RenderableManager$PrimitiveType;->POINTS:Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 2
    .line 3
    sget-object v1, Lcom/google/android/filament/RenderableManager$PrimitiveType;->LINES:Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 4
    .line 5
    sget-object v2, Lcom/google/android/filament/RenderableManager$PrimitiveType;->LINE_STRIP:Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 6
    .line 7
    sget-object v3, Lcom/google/android/filament/RenderableManager$PrimitiveType;->TRIANGLES:Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 8
    .line 9
    sget-object v4, Lcom/google/android/filament/RenderableManager$PrimitiveType;->TRIANGLE_STRIP:Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 10
    .line 11
    filled-new-array {v0, v1, v2, v3, v4}, [Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 2
    .line 3
    const-string v1, "POINTS"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Lcom/google/android/filament/RenderableManager$PrimitiveType;-><init>(Ljava/lang/String;II)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/google/android/filament/RenderableManager$PrimitiveType;->POINTS:Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 10
    .line 11
    new-instance v0, Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 12
    .line 13
    const-string v1, "LINES"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2, v2}, Lcom/google/android/filament/RenderableManager$PrimitiveType;-><init>(Ljava/lang/String;II)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcom/google/android/filament/RenderableManager$PrimitiveType;->LINES:Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 20
    .line 21
    new-instance v0, Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 22
    .line 23
    const-string v1, "LINE_STRIP"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    const/4 v3, 0x3

    .line 27
    invoke-direct {v0, v1, v2, v3}, Lcom/google/android/filament/RenderableManager$PrimitiveType;-><init>(Ljava/lang/String;II)V

    .line 28
    .line 29
    .line 30
    sput-object v0, Lcom/google/android/filament/RenderableManager$PrimitiveType;->LINE_STRIP:Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 31
    .line 32
    new-instance v0, Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 33
    .line 34
    const-string v1, "TRIANGLES"

    .line 35
    .line 36
    const/4 v2, 0x4

    .line 37
    invoke-direct {v0, v1, v3, v2}, Lcom/google/android/filament/RenderableManager$PrimitiveType;-><init>(Ljava/lang/String;II)V

    .line 38
    .line 39
    .line 40
    sput-object v0, Lcom/google/android/filament/RenderableManager$PrimitiveType;->TRIANGLES:Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 41
    .line 42
    new-instance v0, Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 43
    .line 44
    const-string v1, "TRIANGLE_STRIP"

    .line 45
    .line 46
    const/4 v3, 0x5

    .line 47
    invoke-direct {v0, v1, v2, v3}, Lcom/google/android/filament/RenderableManager$PrimitiveType;-><init>(Ljava/lang/String;II)V

    .line 48
    .line 49
    .line 50
    sput-object v0, Lcom/google/android/filament/RenderableManager$PrimitiveType;->TRIANGLE_STRIP:Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 51
    .line 52
    invoke-static {}, Lcom/google/android/filament/RenderableManager$PrimitiveType;->$values()[Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    sput-object v0, Lcom/google/android/filament/RenderableManager$PrimitiveType;->$VALUES:[Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 57
    .line 58
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;II)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lcom/google/android/filament/RenderableManager$PrimitiveType;->mType:I

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/google/android/filament/RenderableManager$PrimitiveType;
    .locals 1

    .line 1
    const-class v0, Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/google/android/filament/RenderableManager$PrimitiveType;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/filament/RenderableManager$PrimitiveType;->$VALUES:[Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/google/android/filament/RenderableManager$PrimitiveType;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/google/android/filament/RenderableManager$PrimitiveType;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public getValue()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/RenderableManager$PrimitiveType;->mType:I

    .line 2
    .line 3
    return p0
.end method
