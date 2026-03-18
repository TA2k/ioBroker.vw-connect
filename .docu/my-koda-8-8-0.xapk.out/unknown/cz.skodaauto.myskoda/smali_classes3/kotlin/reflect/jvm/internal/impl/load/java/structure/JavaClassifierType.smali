.class public interface abstract Lkotlin/reflect/jvm/internal/impl/load/java/structure/JavaClassifierType;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/reflect/jvm/internal/impl/load/java/structure/JavaType;


# virtual methods
.method public abstract getClassifier()Lkotlin/reflect/jvm/internal/impl/load/java/structure/JavaClassifier;
.end method

.method public abstract getClassifierQualifiedName()Ljava/lang/String;
.end method

.method public abstract getPresentableText()Ljava/lang/String;
.end method

.method public abstract getTypeArguments()Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lkotlin/reflect/jvm/internal/impl/load/java/structure/JavaType;",
            ">;"
        }
    .end annotation
.end method

.method public abstract isRaw()Z
.end method
