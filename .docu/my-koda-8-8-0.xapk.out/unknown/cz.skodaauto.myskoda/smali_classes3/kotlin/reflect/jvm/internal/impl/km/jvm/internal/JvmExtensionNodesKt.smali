.class public final Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmExtensionNodesKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final getJvm(Lkotlin/reflect/jvm/internal/impl/km/KmClass;)Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmClassExtension;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmClassExtension;->Companion:Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmClassExtension$Companion;

    invoke-virtual {v0}, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmClassExtension$Companion;->getTYPE()Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;

    move-result-object v0

    invoke-static {p0, v0}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/ExtensionNodesKt;->getExtension(Lkotlin/reflect/jvm/internal/impl/km/KmClass;Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;)Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmClassExtension;

    move-result-object p0

    const-string v0, "null cannot be cast to non-null type kotlin.metadata.jvm.internal.JvmClassExtension"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmClassExtension;

    return-object p0
.end method

.method public static final getJvm(Lkotlin/reflect/jvm/internal/impl/km/KmConstructor;)Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmConstructorExtension;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmConstructorExtension;->TYPE:Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;

    invoke-static {p0, v0}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/ExtensionNodesKt;->getExtension(Lkotlin/reflect/jvm/internal/impl/km/KmConstructor;Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;)Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmConstructorExtension;

    move-result-object p0

    const-string v0, "null cannot be cast to non-null type kotlin.metadata.jvm.internal.JvmConstructorExtension"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmConstructorExtension;

    return-object p0
.end method

.method public static final getJvm(Lkotlin/reflect/jvm/internal/impl/km/KmFunction;)Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmFunctionExtension;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmFunctionExtension;->TYPE:Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;

    invoke-static {p0, v0}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/ExtensionNodesKt;->getExtension(Lkotlin/reflect/jvm/internal/impl/km/KmFunction;Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;)Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmFunctionExtension;

    move-result-object p0

    const-string v0, "null cannot be cast to non-null type kotlin.metadata.jvm.internal.JvmFunctionExtension"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmFunctionExtension;

    return-object p0
.end method

.method public static final getJvm(Lkotlin/reflect/jvm/internal/impl/km/KmPackage;)Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmPackageExtension;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmPackageExtension;->TYPE:Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;

    invoke-static {p0, v0}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/ExtensionNodesKt;->getExtension(Lkotlin/reflect/jvm/internal/impl/km/KmPackage;Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;)Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmPackageExtension;

    move-result-object p0

    const-string v0, "null cannot be cast to non-null type kotlin.metadata.jvm.internal.JvmPackageExtension"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmPackageExtension;

    return-object p0
.end method

.method public static final getJvm(Lkotlin/reflect/jvm/internal/impl/km/KmProperty;)Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmPropertyExtension;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmPropertyExtension;->TYPE:Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;

    invoke-static {p0, v0}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/ExtensionNodesKt;->getExtension(Lkotlin/reflect/jvm/internal/impl/km/KmProperty;Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;)Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmPropertyExtension;

    move-result-object p0

    const-string v0, "null cannot be cast to non-null type kotlin.metadata.jvm.internal.JvmPropertyExtension"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmPropertyExtension;

    return-object p0
.end method

.method public static final getJvm(Lkotlin/reflect/jvm/internal/impl/km/KmType;)Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmTypeExtension;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmTypeExtension;->TYPE:Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;

    invoke-static {p0, v0}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/ExtensionNodesKt;->getExtension(Lkotlin/reflect/jvm/internal/impl/km/KmType;Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;)Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmTypeExtension;

    move-result-object p0

    const-string v0, "null cannot be cast to non-null type kotlin.metadata.jvm.internal.JvmTypeExtension"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmTypeExtension;

    return-object p0
.end method

.method public static final getJvm(Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;)Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmTypeParameterExtension;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmTypeParameterExtension;->TYPE:Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;

    invoke-static {p0, v0}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/ExtensionNodesKt;->getExtension(Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;)Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmTypeParameterExtension;

    move-result-object p0

    const-string v0, "null cannot be cast to non-null type kotlin.metadata.jvm.internal.JvmTypeParameterExtension"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmTypeParameterExtension;

    return-object p0
.end method
