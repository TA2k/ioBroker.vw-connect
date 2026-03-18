.class public Lkotlin/reflect/jvm/internal/ReflectionFactoryImpl;
.super Lkotlin/jvm/internal/h0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static clearCaches()V
    .locals 0

    .line 1
    invoke-static {}, Lkotlin/reflect/jvm/internal/CachesKt;->clearCaches()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lkotlin/reflect/jvm/internal/ModuleByClassLoaderKt;->clearModuleByClassLoaderCache()V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method private static getOwner(Lkotlin/jvm/internal/d;)Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lkotlin/jvm/internal/d;->getOwner()Lhy0/f;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    instance-of v0, p0, Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    check-cast p0, Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object p0, Lkotlin/reflect/jvm/internal/EmptyContainerForLocal;->INSTANCE:Lkotlin/reflect/jvm/internal/EmptyContainerForLocal;

    .line 13
    .line 14
    return-object p0
.end method


# virtual methods
.method public createKotlinClass(Ljava/lang/Class;)Lhy0/d;
    .locals 0

    .line 1
    new-instance p0, Lkotlin/reflect/jvm/internal/KClassImpl;

    invoke-direct {p0, p1}, Lkotlin/reflect/jvm/internal/KClassImpl;-><init>(Ljava/lang/Class;)V

    return-object p0
.end method

.method public createKotlinClass(Ljava/lang/Class;Ljava/lang/String;)Lhy0/d;
    .locals 0

    .line 2
    new-instance p0, Lkotlin/reflect/jvm/internal/KClassImpl;

    invoke-direct {p0, p1}, Lkotlin/reflect/jvm/internal/KClassImpl;-><init>(Ljava/lang/Class;)V

    return-object p0
.end method

.method public function(Lkotlin/jvm/internal/j;)Lhy0/g;
    .locals 3

    .line 1
    new-instance p0, Lkotlin/reflect/jvm/internal/KFunctionImpl;

    .line 2
    .line 3
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/ReflectionFactoryImpl;->getOwner(Lkotlin/jvm/internal/d;)Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p1}, Lkotlin/jvm/internal/d;->getName()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-virtual {p1}, Lkotlin/jvm/internal/d;->getSignature()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    invoke-virtual {p1}, Lkotlin/jvm/internal/d;->getBoundReceiver()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-direct {p0, v0, v1, v2, p1}, Lkotlin/reflect/jvm/internal/KFunctionImpl;-><init>(Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-object p0
.end method

.method public getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;
    .locals 0

    .line 1
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/CachesKt;->getOrCreateKotlinClass(Ljava/lang/Class;)Lkotlin/reflect/jvm/internal/KClassImpl;

    move-result-object p0

    return-object p0
.end method

.method public getOrCreateKotlinClass(Ljava/lang/Class;Ljava/lang/String;)Lhy0/d;
    .locals 0

    .line 2
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/CachesKt;->getOrCreateKotlinClass(Ljava/lang/Class;)Lkotlin/reflect/jvm/internal/KClassImpl;

    move-result-object p0

    return-object p0
.end method

.method public getOrCreateKotlinPackage(Ljava/lang/Class;Ljava/lang/String;)Lhy0/f;
    .locals 0

    .line 1
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/CachesKt;->getOrCreateKotlinPackage(Ljava/lang/Class;)Lhy0/f;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public mutableCollectionType(Lhy0/a0;)Lhy0/a0;
    .locals 0

    .line 1
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/TypeOfImplKt;->createMutableCollectionKType(Lhy0/a0;)Lhy0/a0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public mutableProperty0(Lkotlin/jvm/internal/o;)Lhy0/j;
    .locals 3

    .line 1
    new-instance p0, Lkotlin/reflect/jvm/internal/KMutableProperty0Impl;

    .line 2
    .line 3
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/ReflectionFactoryImpl;->getOwner(Lkotlin/jvm/internal/d;)Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p1}, Lkotlin/jvm/internal/d;->getName()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-virtual {p1}, Lkotlin/jvm/internal/d;->getSignature()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    invoke-virtual {p1}, Lkotlin/jvm/internal/d;->getBoundReceiver()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-direct {p0, v0, v1, v2, p1}, Lkotlin/reflect/jvm/internal/KMutableProperty0Impl;-><init>(Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-object p0
.end method

.method public mutableProperty1(Lkotlin/jvm/internal/q;)Lhy0/l;
    .locals 3

    .line 1
    new-instance p0, Lkotlin/reflect/jvm/internal/KMutableProperty1Impl;

    .line 2
    .line 3
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/ReflectionFactoryImpl;->getOwner(Lkotlin/jvm/internal/d;)Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p1}, Lkotlin/jvm/internal/d;->getName()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-virtual {p1}, Lkotlin/jvm/internal/d;->getSignature()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    invoke-virtual {p1}, Lkotlin/jvm/internal/d;->getBoundReceiver()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-direct {p0, v0, v1, v2, p1}, Lkotlin/reflect/jvm/internal/KMutableProperty1Impl;-><init>(Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-object p0
.end method

.method public mutableProperty2(Lkotlin/jvm/internal/s;)Lhy0/n;
    .locals 0

    .line 1
    new-instance p0, Lkotlin/reflect/jvm/internal/KMutableProperty2Impl;

    .line 2
    .line 3
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/ReflectionFactoryImpl;->getOwner(Lkotlin/jvm/internal/d;)Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    throw p0
.end method

.method public nothingType(Lhy0/a0;)Lhy0/a0;
    .locals 0

    .line 1
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/TypeOfImplKt;->createNothingType(Lhy0/a0;)Lhy0/a0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public platformType(Lhy0/a0;Lhy0/a0;)Lhy0/a0;
    .locals 0

    .line 1
    invoke-static {p1, p2}, Lkotlin/reflect/jvm/internal/TypeOfImplKt;->createPlatformKType(Lhy0/a0;Lhy0/a0;)Lhy0/a0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public property0(Lkotlin/jvm/internal/v;)Lhy0/u;
    .locals 3

    .line 1
    new-instance p0, Lkotlin/reflect/jvm/internal/KProperty0Impl;

    .line 2
    .line 3
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/ReflectionFactoryImpl;->getOwner(Lkotlin/jvm/internal/d;)Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p1}, Lkotlin/jvm/internal/d;->getName()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-virtual {p1}, Lkotlin/jvm/internal/d;->getSignature()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    invoke-virtual {p1}, Lkotlin/jvm/internal/d;->getBoundReceiver()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-direct {p0, v0, v1, v2, p1}, Lkotlin/reflect/jvm/internal/KProperty0Impl;-><init>(Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-object p0
.end method

.method public property1(Lkotlin/jvm/internal/w;)Lhy0/w;
    .locals 3

    .line 1
    new-instance p0, Lkotlin/reflect/jvm/internal/KProperty1Impl;

    .line 2
    .line 3
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/ReflectionFactoryImpl;->getOwner(Lkotlin/jvm/internal/d;)Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p1}, Lkotlin/jvm/internal/d;->getName()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-virtual {p1}, Lkotlin/jvm/internal/d;->getSignature()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    invoke-virtual {p1}, Lkotlin/jvm/internal/d;->getBoundReceiver()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-direct {p0, v0, v1, v2, p1}, Lkotlin/reflect/jvm/internal/KProperty1Impl;-><init>(Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-object p0
.end method

.method public property2(Lkotlin/jvm/internal/y;)Lhy0/y;
    .locals 2

    .line 1
    new-instance p0, Lkotlin/reflect/jvm/internal/KProperty2Impl;

    .line 2
    .line 3
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/ReflectionFactoryImpl;->getOwner(Lkotlin/jvm/internal/d;)Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p1}, Lkotlin/jvm/internal/d;->getName()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-virtual {p1}, Lkotlin/jvm/internal/d;->getSignature()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-direct {p0, v0, v1, p1}, Lkotlin/reflect/jvm/internal/KProperty2Impl;-><init>(Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;Ljava/lang/String;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    return-object p0
.end method

.method public renderLambdaToString(Lkotlin/jvm/internal/i;)Ljava/lang/String;
    .locals 9

    .line 1
    const-string v0, "<this>"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    const-class v1, Lkotlin/Metadata;

    invoke-virtual {v0, v1}, Ljava/lang/Class;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object v0

    check-cast v0, Lkotlin/Metadata;

    const/4 v1, 0x0

    if-nez v0, :cond_0

    goto :goto_1

    .line 3
    :cond_0
    invoke-interface {v0}, Lkotlin/Metadata;->d1()[Ljava/lang/String;

    move-result-object v2

    array-length v3, v2

    if-nez v3, :cond_1

    move-object v2, v1

    :cond_1
    if-nez v2, :cond_2

    goto :goto_1

    .line 4
    :cond_2
    invoke-interface {v0}, Lkotlin/Metadata;->d2()[Ljava/lang/String;

    move-result-object v1

    invoke-static {v2, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/jvm/deserialization/JvmProtoBufUtil;->readFunctionDataFrom([Ljava/lang/String;[Ljava/lang/String;)Llx0/l;

    move-result-object v1

    .line 5
    iget-object v2, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 6
    move-object v5, v2

    check-cast v5, Lkotlin/reflect/jvm/internal/impl/metadata/jvm/deserialization/JvmNameResolver;

    .line 7
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 8
    move-object v4, v1

    check-cast v4, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Function;

    .line 9
    new-instance v7, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/MetadataVersion;

    .line 10
    invoke-interface {v0}, Lkotlin/Metadata;->mv()[I

    move-result-object v1

    .line 11
    invoke-interface {v0}, Lkotlin/Metadata;->xi()I

    move-result v0

    and-int/lit8 v0, v0, 0x8

    if-eqz v0, :cond_3

    const/4 v0, 0x1

    goto :goto_0

    :cond_3
    const/4 v0, 0x0

    .line 12
    :goto_0
    invoke-direct {v7, v1, v0}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/MetadataVersion;-><init>([IZ)V

    .line 13
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    new-instance v6, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/TypeTable;

    invoke-virtual {v4}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Function;->getTypeTable()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeTable;

    move-result-object v0

    const-string v1, "getTypeTable(...)"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v6, v0}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/TypeTable;-><init>(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeTable;)V

    sget-object v8, Ljy0/b;->d:Ljy0/b;

    .line 14
    invoke-static/range {v3 .. v8}, Lkotlin/reflect/jvm/internal/UtilKt;->deserializeToDescriptor(Ljava/lang/Class;Lkotlin/reflect/jvm/internal/impl/protobuf/MessageLite;Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/NameResolver;Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/TypeTable;Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/BinaryVersion;Lay0/n;)Lkotlin/reflect/jvm/internal/impl/descriptors/CallableDescriptor;

    move-result-object v0

    check-cast v0, Lkotlin/reflect/jvm/internal/impl/descriptors/SimpleFunctionDescriptor;

    .line 15
    new-instance v1, Lkotlin/reflect/jvm/internal/KFunctionImpl;

    sget-object v2, Lkotlin/reflect/jvm/internal/EmptyContainerForLocal;->INSTANCE:Lkotlin/reflect/jvm/internal/EmptyContainerForLocal;

    invoke-direct {v1, v2, v0}, Lkotlin/reflect/jvm/internal/KFunctionImpl;-><init>(Lkotlin/reflect/jvm/internal/KDeclarationContainerImpl;Lkotlin/reflect/jvm/internal/impl/descriptors/FunctionDescriptor;)V

    :goto_1
    if-eqz v1, :cond_4

    .line 16
    invoke-static {v1}, Lkotlin/reflect/jvm/internal/UtilKt;->asKFunctionImpl(Ljava/lang/Object;)Lkotlin/reflect/jvm/internal/KFunctionImpl;

    move-result-object v0

    if-eqz v0, :cond_4

    .line 17
    sget-object p0, Lkotlin/reflect/jvm/internal/ReflectionObjectRenderer;->INSTANCE:Lkotlin/reflect/jvm/internal/ReflectionObjectRenderer;

    invoke-virtual {p0, v0}, Lkotlin/reflect/jvm/internal/ReflectionObjectRenderer;->renderLambda(Lhy0/g;)Ljava/lang/String;

    move-result-object p0

    return-object p0

    .line 18
    :cond_4
    invoke-super {p0, p1}, Lkotlin/jvm/internal/h0;->renderLambdaToString(Lkotlin/jvm/internal/i;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public renderLambdaToString(Lkotlin/jvm/internal/n;)Ljava/lang/String;
    .locals 0

    .line 19
    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/ReflectionFactoryImpl;->renderLambdaToString(Lkotlin/jvm/internal/i;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public setUpperBounds(Lhy0/b0;Ljava/util/List;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lhy0/b0;",
            "Ljava/util/List<",
            "Lhy0/a0;",
            ">;)V"
        }
    .end annotation

    .line 1
    return-void
.end method

.method public typeOf(Lhy0/e;Ljava/util/List;Z)Lhy0/a0;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lhy0/e;",
            "Ljava/util/List<",
            "Lhy0/d0;",
            ">;Z)",
            "Lhy0/a0;"
        }
    .end annotation

    .line 1
    instance-of p0, p1, Lkotlin/jvm/internal/e;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lkotlin/jvm/internal/e;

    .line 6
    .line 7
    invoke-interface {p1}, Lkotlin/jvm/internal/e;->getJClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-static {p0, p2, p3}, Lkotlin/reflect/jvm/internal/CachesKt;->getOrCreateKType(Ljava/lang/Class;Ljava/util/List;Z)Lhy0/a0;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_0
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 17
    .line 18
    invoke-static {p1, p2, p3, p0}, Liy0/b;->a(Lhy0/e;Ljava/util/List;ZLjava/util/List;)Lkotlin/reflect/jvm/internal/KTypeImpl;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public typeParameter(Ljava/lang/Object;Ljava/lang/String;Lhy0/e0;Z)Lhy0/b0;
    .locals 0

    .line 1
    instance-of p0, p1, Lhy0/d;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    move-object p0, p1

    .line 6
    check-cast p0, Lhy0/d;

    .line 7
    .line 8
    invoke-interface {p0}, Lhy0/d;->getTypeParameters()Ljava/util/List;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    instance-of p0, p1, Lhy0/c;

    .line 14
    .line 15
    if-eqz p0, :cond_3

    .line 16
    .line 17
    move-object p0, p1

    .line 18
    check-cast p0, Lhy0/c;

    .line 19
    .line 20
    invoke-interface {p0}, Lhy0/c;->getTypeParameters()Ljava/util/List;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    :goto_0
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    :cond_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 29
    .line 30
    .line 31
    move-result p3

    .line 32
    if-eqz p3, :cond_2

    .line 33
    .line 34
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p3

    .line 38
    check-cast p3, Lhy0/b0;

    .line 39
    .line 40
    invoke-interface {p3}, Lhy0/b0;->getName()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p4

    .line 44
    invoke-virtual {p4, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result p4

    .line 48
    if-eqz p4, :cond_1

    .line 49
    .line 50
    return-object p3

    .line 51
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 52
    .line 53
    new-instance p3, Ljava/lang/StringBuilder;

    .line 54
    .line 55
    const-string p4, "Type parameter "

    .line 56
    .line 57
    invoke-direct {p3, p4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string p2, " is not found in container: "

    .line 64
    .line 65
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    throw p0

    .line 79
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 80
    .line 81
    const-string p2, "Type parameter container must be a class or a callable: "

    .line 82
    .line 83
    invoke-static {p1, p2}, Lkx/a;->i(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    throw p0
.end method
