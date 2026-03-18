.class public interface abstract Lkotlin/reflect/jvm/internal/impl/descriptors/ClassifierDescriptorWithTypeParameters;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/reflect/jvm/internal/impl/descriptors/ClassifierDescriptor;
.implements Lkotlin/reflect/jvm/internal/impl/descriptors/MemberDescriptor;
.implements Lkotlin/reflect/jvm/internal/impl/descriptors/Substitutable;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lkotlin/reflect/jvm/internal/impl/descriptors/ClassifierDescriptor;",
        "Lkotlin/reflect/jvm/internal/impl/descriptors/MemberDescriptor;",
        "Lkotlin/reflect/jvm/internal/impl/descriptors/Substitutable<",
        "Lkotlin/reflect/jvm/internal/impl/descriptors/ClassifierDescriptorWithTypeParameters;",
        ">;"
    }
.end annotation


# virtual methods
.method public abstract getDeclaredTypeParameters()Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/descriptors/TypeParameterDescriptor;",
            ">;"
        }
    .end annotation
.end method

.method public abstract isInner()Z
.end method
