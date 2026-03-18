.class public final enum Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;
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
    name = "MagFilter"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;",
        ">;"
    }
.end annotation


# static fields
.field public static final enum LINEAR:Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;
    .annotation build Lcom/google/android/filament/proguard/UsedByNative;
        value = "material_java_wrappers.h"
    .end annotation
.end field

.field public static final enum NEAREST:Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;
    .annotation build Lcom/google/android/filament/proguard/UsedByNative;
        value = "material_java_wrappers.h"
    .end annotation
.end field

.field public static final synthetic d:[Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;

    .line 2
    .line 3
    const-string v1, "NEAREST"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;->NEAREST:Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;

    .line 10
    .line 11
    new-instance v1, Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;

    .line 12
    .line 13
    const-string v2, "LINEAR"

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v1, v2, v3}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v1, Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;->LINEAR:Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;

    .line 20
    .line 21
    filled-new-array {v0, v1}, [Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;->d:[Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;

    .line 26
    .line 27
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;
    .locals 1

    .line 1
    const-class v0, Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;->d:[Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/google/ar/sceneform/rendering/Texture$Sampler$MagFilter;

    .line 8
    .line 9
    return-object v0
.end method
