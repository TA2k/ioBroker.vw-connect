.class public interface abstract Lkotlin/reflect/jvm/internal/impl/descriptors/TypeParameterDescriptor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/reflect/jvm/internal/impl/descriptors/ClassifierDescriptor;
.implements Lkotlin/reflect/jvm/internal/impl/types/model/TypeParameterMarker;


# virtual methods
.method public abstract getIndex()I
.end method

.method public abstract getOriginal()Lkotlin/reflect/jvm/internal/impl/descriptors/TypeParameterDescriptor;
.end method

.method public abstract getStorageManager()Lkotlin/reflect/jvm/internal/impl/storage/StorageManager;
.end method

.method public abstract getTypeConstructor()Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;
.end method

.method public abstract getUpperBounds()Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/types/KotlinType;",
            ">;"
        }
    .end annotation
.end method

.method public abstract getVariance()Lkotlin/reflect/jvm/internal/impl/types/Variance;
.end method

.method public abstract isCapturedFromOuterDeclaration()Z
.end method

.method public abstract isReified()Z
.end method
