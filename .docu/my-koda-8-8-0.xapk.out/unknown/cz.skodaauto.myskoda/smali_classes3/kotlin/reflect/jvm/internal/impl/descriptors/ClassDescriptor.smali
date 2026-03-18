.class public interface abstract Lkotlin/reflect/jvm/internal/impl/descriptors/ClassDescriptor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/reflect/jvm/internal/impl/descriptors/ClassOrPackageFragmentDescriptor;
.implements Lkotlin/reflect/jvm/internal/impl/descriptors/ClassifierDescriptorWithTypeParameters;


# virtual methods
.method public abstract getCompanionObjectDescriptor()Lkotlin/reflect/jvm/internal/impl/descriptors/ClassDescriptor;
.end method

.method public abstract getConstructors()Ljava/util/Collection;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Collection<",
            "Lkotlin/reflect/jvm/internal/impl/descriptors/ClassConstructorDescriptor;",
            ">;"
        }
    .end annotation
.end method

.method public abstract getContainingDeclaration()Lkotlin/reflect/jvm/internal/impl/descriptors/DeclarationDescriptor;
.end method

.method public abstract getContextReceivers()Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/descriptors/ReceiverParameterDescriptor;",
            ">;"
        }
    .end annotation
.end method

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

.method public abstract getDefaultType()Lkotlin/reflect/jvm/internal/impl/types/SimpleType;
.end method

.method public abstract getKind()Lkotlin/reflect/jvm/internal/impl/descriptors/ClassKind;
.end method

.method public abstract getMemberScope(Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitution;)Lkotlin/reflect/jvm/internal/impl/resolve/scopes/MemberScope;
.end method

.method public abstract getModality()Lkotlin/reflect/jvm/internal/impl/descriptors/Modality;
.end method

.method public abstract getOriginal()Lkotlin/reflect/jvm/internal/impl/descriptors/ClassDescriptor;
.end method

.method public abstract getStaticScope()Lkotlin/reflect/jvm/internal/impl/resolve/scopes/MemberScope;
.end method

.method public abstract getThisAsReceiverParameter()Lkotlin/reflect/jvm/internal/impl/descriptors/ReceiverParameterDescriptor;
.end method

.method public abstract getUnsubstitutedInnerClassesScope()Lkotlin/reflect/jvm/internal/impl/resolve/scopes/MemberScope;
.end method

.method public abstract getUnsubstitutedMemberScope()Lkotlin/reflect/jvm/internal/impl/resolve/scopes/MemberScope;
.end method

.method public abstract getUnsubstitutedPrimaryConstructor()Lkotlin/reflect/jvm/internal/impl/descriptors/ClassConstructorDescriptor;
.end method

.method public abstract getValueClassRepresentation()Lkotlin/reflect/jvm/internal/impl/descriptors/ValueClassRepresentation;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lkotlin/reflect/jvm/internal/impl/descriptors/ValueClassRepresentation<",
            "Lkotlin/reflect/jvm/internal/impl/types/SimpleType;",
            ">;"
        }
    .end annotation
.end method

.method public abstract getVisibility()Lkotlin/reflect/jvm/internal/impl/descriptors/DescriptorVisibility;
.end method

.method public abstract isCompanionObject()Z
.end method

.method public abstract isData()Z
.end method

.method public abstract isFun()Z
.end method

.method public abstract isInline()Z
.end method

.method public abstract isValue()Z
.end method
