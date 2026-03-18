.class public final enum Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/google/android/filament/proguard/UsedByNative;
    value = "material_java_wrappers.h"
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/ar/sceneform/rendering/Texture$Sampler;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "WrapMode"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;",
        ">;"
    }
.end annotation


# static fields
.field public static final enum CLAMP_TO_EDGE:Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;
    .annotation build Lcom/google/android/filament/proguard/UsedByNative;
        value = "material_java_wrappers.h"
    .end annotation
.end field

.field public static final enum MIRRORED_REPEAT:Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;
    .annotation build Lcom/google/android/filament/proguard/UsedByNative;
        value = "material_java_wrappers.h"
    .end annotation
.end field

.field public static final enum REPEAT:Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;
    .annotation build Lcom/google/android/filament/proguard/UsedByNative;
        value = "material_java_wrappers.h"
    .end annotation
.end field

.field public static final synthetic d:[Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;

    .line 2
    .line 3
    const-string v1, "CLAMP_TO_EDGE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;->CLAMP_TO_EDGE:Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;

    .line 10
    .line 11
    new-instance v1, Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;

    .line 12
    .line 13
    const-string v2, "REPEAT"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;->REPEAT:Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;

    .line 20
    .line 21
    new-instance v2, Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;

    .line 22
    .line 23
    const-string v3, "MIRRORED_REPEAT"

    .line 24
    .line 25
    const/4 v4, 0x2

    .line 26
    invoke-direct {v2, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;->MIRRORED_REPEAT:Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;

    .line 30
    .line 31
    filled-new-array {v0, v1, v2}, [Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    sput-object v0, Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;->d:[Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;

    .line 36
    .line 37
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;
    .locals 1

    .line 1
    const-class v0, Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;->d:[Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/google/ar/sceneform/rendering/Texture$Sampler$WrapMode;

    .line 8
    .line 9
    return-object v0
.end method
