.class public interface abstract Lcom/google/android/filament/gltfio/MaterialProvider;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/google/android/filament/proguard/UsedByNative;
    value = "AssetLoader.cpp"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/gltfio/MaterialProvider$MaterialKey;
    }
.end annotation


# virtual methods
.method public abstract createMaterialInstance(Lcom/google/android/filament/gltfio/MaterialProvider$MaterialKey;[ILjava/lang/String;Ljava/lang/String;)Lcom/google/android/filament/MaterialInstance;
.end method

.method public abstract destroy()V
.end method

.method public abstract destroyMaterials()V
.end method

.method public abstract getMaterial(Lcom/google/android/filament/gltfio/MaterialProvider$MaterialKey;[ILjava/lang/String;)Lcom/google/android/filament/Material;
.end method

.method public abstract getMaterials()[Lcom/google/android/filament/Material;
.end method

.method public abstract needsDummyData(I)Z
.end method
