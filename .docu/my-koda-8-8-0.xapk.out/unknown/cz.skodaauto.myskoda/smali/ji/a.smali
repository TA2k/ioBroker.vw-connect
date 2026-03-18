.class public final Lji/a;
.super Lretrofit2/CallAdapter$Factory;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static d(Ljava/lang/reflect/Type;Ljava/lang/Class;I)Ljava/lang/reflect/Type;
    .locals 1

    .line 1
    instance-of v0, p0, Ljava/lang/reflect/ParameterizedType;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    invoke-static {p0}, Lretrofit2/CallAdapter$Factory;->c(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    if-nez p1, :cond_1

    .line 15
    .line 16
    :goto_0
    const/4 p0, 0x0

    .line 17
    return-object p0

    .line 18
    :cond_1
    check-cast p0, Ljava/lang/reflect/ParameterizedType;

    .line 19
    .line 20
    invoke-static {p2, p0}, Lretrofit2/CallAdapter$Factory;->b(ILjava/lang/reflect/ParameterizedType;)Ljava/lang/reflect/Type;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method


# virtual methods
.method public final a(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;Lretrofit2/Retrofit;)Lretrofit2/CallAdapter;
    .locals 2

    .line 1
    const-string p0, "returnType"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "annotations"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-class p0, Lretrofit2/Call;

    .line 12
    .line 13
    const/4 p2, 0x0

    .line 14
    invoke-static {p1, p0, p2}, Lji/a;->d(Ljava/lang/reflect/Type;Ljava/lang/Class;I)Ljava/lang/reflect/Type;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    const-class v1, Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;

    .line 21
    .line 22
    invoke-static {v0, v1, p2}, Lji/a;->d(Ljava/lang/reflect/Type;Ljava/lang/Class;I)Ljava/lang/reflect/Type;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    invoke-static {p1, p0, p2}, Lji/a;->d(Ljava/lang/reflect/Type;Ljava/lang/Class;I)Ljava/lang/reflect/Type;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    if-eqz p0, :cond_0

    .line 33
    .line 34
    const/4 p1, 0x1

    .line 35
    invoke-static {p0, v1, p1}, Lji/a;->d(Ljava/lang/reflect/Type;Ljava/lang/Class;I)Ljava/lang/reflect/Type;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    if-eqz p0, :cond_0

    .line 40
    .line 41
    invoke-static {v0}, Lretrofit2/CallAdapter$Factory;->c(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    new-instance v0, Lcariad/charging/multicharge/retrofit/coroutineAdapter/a;

    .line 46
    .line 47
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    new-array p2, p2, [Ljava/lang/annotation/Annotation;

    .line 51
    .line 52
    invoke-virtual {p3, p0, p2}, Lretrofit2/Retrofit;->d(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;)Lretrofit2/Converter;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-direct {v0, p1, p0}, Lcariad/charging/multicharge/retrofit/coroutineAdapter/a;-><init>(Ljava/lang/Class;Lretrofit2/Converter;)V

    .line 57
    .line 58
    .line 59
    new-instance p0, Lc2/k;

    .line 60
    .line 61
    const/16 p2, 0xb

    .line 62
    .line 63
    invoke-direct {p0, p2, v0, p1}, Lc2/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    return-object p0

    .line 67
    :cond_0
    const/4 p0, 0x0

    .line 68
    return-object p0
.end method
