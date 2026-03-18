.class public interface abstract Lkotlin/reflect/jvm/internal/impl/descriptors/ValueParameterDescriptor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/reflect/jvm/internal/impl/descriptors/ParameterDescriptor;
.implements Lkotlin/reflect/jvm/internal/impl/descriptors/VariableDescriptor;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lkotlin/reflect/jvm/internal/impl/descriptors/ValueParameterDescriptor$DefaultImpls;
    }
.end annotation


# virtual methods
.method public abstract copy(Lkotlin/reflect/jvm/internal/impl/descriptors/CallableDescriptor;Lkotlin/reflect/jvm/internal/impl/name/Name;I)Lkotlin/reflect/jvm/internal/impl/descriptors/ValueParameterDescriptor;
.end method

.method public abstract declaresDefaultValue()Z
.end method

.method public abstract getContainingDeclaration()Lkotlin/reflect/jvm/internal/impl/descriptors/CallableDescriptor;
.end method

.method public abstract getIndex()I
.end method

.method public abstract getOriginal()Lkotlin/reflect/jvm/internal/impl/descriptors/ValueParameterDescriptor;
.end method

.method public abstract getOverriddenDescriptors()Ljava/util/Collection;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Collection<",
            "Lkotlin/reflect/jvm/internal/impl/descriptors/ValueParameterDescriptor;",
            ">;"
        }
    .end annotation
.end method

.method public abstract getVarargElementType()Lkotlin/reflect/jvm/internal/impl/types/KotlinType;
.end method

.method public abstract isCrossinline()Z
.end method

.method public abstract isNoinline()Z
.end method
