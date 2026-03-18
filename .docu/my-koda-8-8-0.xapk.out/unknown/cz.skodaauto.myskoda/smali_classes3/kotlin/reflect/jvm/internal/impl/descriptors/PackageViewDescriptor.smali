.class public interface abstract Lkotlin/reflect/jvm/internal/impl/descriptors/PackageViewDescriptor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/reflect/jvm/internal/impl/descriptors/DeclarationDescriptor;


# virtual methods
.method public abstract getFqName()Lkotlin/reflect/jvm/internal/impl/name/FqName;
.end method

.method public abstract getFragments()Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/descriptors/PackageFragmentDescriptor;",
            ">;"
        }
    .end annotation
.end method

.method public abstract getMemberScope()Lkotlin/reflect/jvm/internal/impl/resolve/scopes/MemberScope;
.end method

.method public abstract getModule()Lkotlin/reflect/jvm/internal/impl/descriptors/ModuleDescriptor;
.end method

.method public abstract isEmpty()Z
.end method
