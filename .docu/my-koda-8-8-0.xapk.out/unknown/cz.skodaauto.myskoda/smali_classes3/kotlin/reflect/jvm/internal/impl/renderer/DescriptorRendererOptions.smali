.class public interface abstract Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererOptions$DefaultImpls;
    }
.end annotation


# virtual methods
.method public abstract getAnnotationArgumentsRenderingPolicy()Lkotlin/reflect/jvm/internal/impl/renderer/AnnotationArgumentsRenderingPolicy;
.end method

.method public abstract getDebugMode()Z
.end method

.method public abstract getEnhancedTypes()Z
.end method

.method public abstract getExcludedTypeAnnotationClasses()Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;"
        }
    .end annotation
.end method

.method public abstract setAnnotationArgumentsRenderingPolicy(Lkotlin/reflect/jvm/internal/impl/renderer/AnnotationArgumentsRenderingPolicy;)V
.end method

.method public abstract setClassifierNamePolicy(Lkotlin/reflect/jvm/internal/impl/renderer/ClassifierNamePolicy;)V
.end method

.method public abstract setDebugMode(Z)V
.end method

.method public abstract setExcludedTypeAnnotationClasses(Ljava/util/Set;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "Lkotlin/reflect/jvm/internal/impl/name/FqName;",
            ">;)V"
        }
    .end annotation
.end method

.method public abstract setModifiers(Ljava/util/Set;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "+",
            "Lkotlin/reflect/jvm/internal/impl/renderer/DescriptorRendererModifier;",
            ">;)V"
        }
    .end annotation
.end method

.method public abstract setParameterNameRenderingPolicy(Lkotlin/reflect/jvm/internal/impl/renderer/ParameterNameRenderingPolicy;)V
.end method

.method public abstract setReceiverAfterName(Z)V
.end method

.method public abstract setRenderCompanionObjectName(Z)V
.end method

.method public abstract setStartFromName(Z)V
.end method

.method public abstract setTextFormat(Lkotlin/reflect/jvm/internal/impl/renderer/RenderingFormat;)V
.end method

.method public abstract setVerbose(Z)V
.end method

.method public abstract setWithDefinedIn(Z)V
.end method

.method public abstract setWithoutSuperTypes(Z)V
.end method

.method public abstract setWithoutTypeParameters(Z)V
.end method
