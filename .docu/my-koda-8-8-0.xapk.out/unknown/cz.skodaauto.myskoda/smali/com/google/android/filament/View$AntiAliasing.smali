.class public final enum Lcom/google/android/filament/View$AntiAliasing;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/View;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "AntiAliasing"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/google/android/filament/View$AntiAliasing;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lcom/google/android/filament/View$AntiAliasing;

.field public static final enum FXAA:Lcom/google/android/filament/View$AntiAliasing;

.field public static final enum NONE:Lcom/google/android/filament/View$AntiAliasing;


# direct methods
.method private static synthetic $values()[Lcom/google/android/filament/View$AntiAliasing;
    .locals 2

    .line 1
    sget-object v0, Lcom/google/android/filament/View$AntiAliasing;->NONE:Lcom/google/android/filament/View$AntiAliasing;

    .line 2
    .line 3
    sget-object v1, Lcom/google/android/filament/View$AntiAliasing;->FXAA:Lcom/google/android/filament/View$AntiAliasing;

    .line 4
    .line 5
    filled-new-array {v0, v1}, [Lcom/google/android/filament/View$AntiAliasing;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcom/google/android/filament/View$AntiAliasing;

    .line 2
    .line 3
    const-string v1, "NONE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/View$AntiAliasing;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/google/android/filament/View$AntiAliasing;->NONE:Lcom/google/android/filament/View$AntiAliasing;

    .line 10
    .line 11
    new-instance v0, Lcom/google/android/filament/View$AntiAliasing;

    .line 12
    .line 13
    const-string v1, "FXAA"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Lcom/google/android/filament/View$AntiAliasing;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lcom/google/android/filament/View$AntiAliasing;->FXAA:Lcom/google/android/filament/View$AntiAliasing;

    .line 20
    .line 21
    invoke-static {}, Lcom/google/android/filament/View$AntiAliasing;->$values()[Lcom/google/android/filament/View$AntiAliasing;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Lcom/google/android/filament/View$AntiAliasing;->$VALUES:[Lcom/google/android/filament/View$AntiAliasing;

    .line 26
    .line 27
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

.method public static valueOf(Ljava/lang/String;)Lcom/google/android/filament/View$AntiAliasing;
    .locals 1

    .line 1
    const-class v0, Lcom/google/android/filament/View$AntiAliasing;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/google/android/filament/View$AntiAliasing;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/google/android/filament/View$AntiAliasing;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/filament/View$AntiAliasing;->$VALUES:[Lcom/google/android/filament/View$AntiAliasing;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/google/android/filament/View$AntiAliasing;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/google/android/filament/View$AntiAliasing;

    .line 8
    .line 9
    return-object v0
.end method
