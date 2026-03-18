.class public Lkotlin/jvm/internal/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final KOTLIN_JVM_FUNCTIONS:Ljava/lang/String; = "kotlin.jvm.functions."


# virtual methods
.method public function(Lkotlin/jvm/internal/j;)Lhy0/g;
    .locals 0

    .line 1
    return-object p1
.end method

.method public getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;
    .locals 0

    .line 1
    new-instance p0, Lkotlin/jvm/internal/f;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/f;-><init>(Ljava/lang/Class;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public getOrCreateKotlinPackage(Ljava/lang/Class;Ljava/lang/String;)Lhy0/f;
    .locals 0

    .line 1
    new-instance p0, Lkotlin/jvm/internal/u;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/u;-><init>(Ljava/lang/Class;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public mutableCollectionType(Lhy0/a0;)Lhy0/a0;
    .locals 2

    .line 1
    move-object p0, p1

    .line 2
    check-cast p0, Lkotlin/jvm/internal/l0;

    .line 3
    .line 4
    new-instance v0, Lkotlin/jvm/internal/l0;

    .line 5
    .line 6
    invoke-interface {p1}, Lhy0/a0;->getClassifier()Lhy0/e;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-interface {p1}, Lhy0/a0;->getArguments()Ljava/util/List;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    iget p0, p0, Lkotlin/jvm/internal/l0;->f:I

    .line 18
    .line 19
    or-int/lit8 p0, p0, 0x2

    .line 20
    .line 21
    invoke-direct {v0, v1, p1, p0}, Lkotlin/jvm/internal/l0;-><init>(Lhy0/e;Ljava/util/List;I)V

    .line 22
    .line 23
    .line 24
    return-object v0
.end method

.method public mutableProperty0(Lkotlin/jvm/internal/o;)Lhy0/j;
    .locals 0

    .line 1
    return-object p1
.end method

.method public mutableProperty1(Lkotlin/jvm/internal/q;)Lhy0/l;
    .locals 0

    .line 1
    return-object p1
.end method

.method public property0(Lkotlin/jvm/internal/v;)Lhy0/u;
    .locals 0

    .line 1
    return-object p1
.end method

.method public property1(Lkotlin/jvm/internal/w;)Lhy0/w;
    .locals 0

    .line 1
    return-object p1
.end method

.method public property2(Lkotlin/jvm/internal/y;)Lhy0/y;
    .locals 0

    .line 1
    return-object p1
.end method

.method public renderLambdaToString(Lkotlin/jvm/internal/i;)Ljava/lang/String;
    .locals 0

    .line 2
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Class;->getGenericInterfaces()[Ljava/lang/reflect/Type;

    move-result-object p0

    const/4 p1, 0x0

    aget-object p0, p0, p1

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    .line 3
    const-string p1, "kotlin.jvm.functions."

    invoke-virtual {p0, p1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/16 p1, 0x15

    invoke-virtual {p0, p1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p0

    :cond_0
    return-object p0
.end method

.method public renderLambdaToString(Lkotlin/jvm/internal/n;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lkotlin/jvm/internal/h0;->renderLambdaToString(Lkotlin/jvm/internal/i;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public setUpperBounds(Lhy0/b0;Ljava/util/List;)V
    .locals 1

    .line 1
    check-cast p1, Lkotlin/jvm/internal/k0;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const-string p0, "upperBounds"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p1, Lkotlin/jvm/internal/k0;->e:Ljava/util/List;

    .line 12
    .line 13
    if-nez p0, :cond_0

    .line 14
    .line 15
    iput-object p2, p1, Lkotlin/jvm/internal/k0;->e:Ljava/util/List;

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 19
    .line 20
    new-instance p2, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    const-string v0, "Upper bounds of type parameter \'"

    .line 23
    .line 24
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string p1, "\' have already been initialized."

    .line 31
    .line 32
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw p0
.end method

.method public typeOf(Lhy0/e;Ljava/util/List;Z)Lhy0/a0;
    .locals 1

    .line 1
    new-instance p0, Lkotlin/jvm/internal/l0;

    .line 2
    .line 3
    const-string v0, "classifier"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "arguments"

    .line 9
    .line 10
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, p1, p2, p3}, Lkotlin/jvm/internal/l0;-><init>(Lhy0/e;Ljava/util/List;I)V

    .line 14
    .line 15
    .line 16
    return-object p0
.end method

.method public typeParameter(Ljava/lang/Object;Ljava/lang/String;Lhy0/e0;Z)Lhy0/b0;
    .locals 0

    .line 1
    sget-object p0, Lhy0/e0;->d:Lhy0/e0;

    .line 2
    .line 3
    new-instance p0, Lkotlin/jvm/internal/k0;

    .line 4
    .line 5
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/k0;-><init>(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-object p0
.end method
