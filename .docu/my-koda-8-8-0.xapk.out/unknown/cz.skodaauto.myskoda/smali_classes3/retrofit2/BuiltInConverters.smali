.class final Lretrofit2/BuiltInConverters;
.super Lretrofit2/Converter$Factory;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lretrofit2/BuiltInConverters$ToStringConverter;,
        Lretrofit2/BuiltInConverters$BufferingResponseBodyConverter;,
        Lretrofit2/BuiltInConverters$StreamingResponseBodyConverter;,
        Lretrofit2/BuiltInConverters$RequestBodyConverter;,
        Lretrofit2/BuiltInConverters$UnitResponseBodyConverter;,
        Lretrofit2/BuiltInConverters$VoidResponseBodyConverter;
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lretrofit2/Converter$Factory;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;[Ljava/lang/annotation/Annotation;Lretrofit2/Retrofit;)Lretrofit2/Converter;
    .locals 0

    .line 1
    const-class p0, Ld01/r0;

    .line 2
    .line 3
    invoke-static {p1}, Lretrofit2/Utils;->e(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    sget-object p0, Lretrofit2/BuiltInConverters$RequestBodyConverter;->d:Lretrofit2/BuiltInConverters$RequestBodyConverter;

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    return-object p0
.end method

.method public final b(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;Lretrofit2/Retrofit;)Lretrofit2/Converter;
    .locals 0

    .line 1
    const-class p0, Ld01/v0;

    .line 2
    .line 3
    if-ne p1, p0, :cond_1

    .line 4
    .line 5
    const-class p0, Lretrofit2/http/Streaming;

    .line 6
    .line 7
    invoke-static {p2, p0}, Lretrofit2/Utils;->h([Ljava/lang/annotation/Annotation;Ljava/lang/Class;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    sget-object p0, Lretrofit2/BuiltInConverters$StreamingResponseBodyConverter;->d:Lretrofit2/BuiltInConverters$StreamingResponseBodyConverter;

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    sget-object p0, Lretrofit2/BuiltInConverters$BufferingResponseBodyConverter;->d:Lretrofit2/BuiltInConverters$BufferingResponseBodyConverter;

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_1
    const-class p0, Ljava/lang/Void;

    .line 20
    .line 21
    if-ne p1, p0, :cond_2

    .line 22
    .line 23
    sget-object p0, Lretrofit2/BuiltInConverters$VoidResponseBodyConverter;->d:Lretrofit2/BuiltInConverters$VoidResponseBodyConverter;

    .line 24
    .line 25
    return-object p0

    .line 26
    :cond_2
    sget-boolean p0, Lretrofit2/Utils;->b:Z

    .line 27
    .line 28
    if-eqz p0, :cond_3

    .line 29
    .line 30
    :try_start_0
    const-class p0, Llx0/b0;
    :try_end_0
    .catch Ljava/lang/NoClassDefFoundError; {:try_start_0 .. :try_end_0} :catch_0

    .line 31
    .line 32
    if-ne p1, p0, :cond_3

    .line 33
    .line 34
    sget-object p0, Lretrofit2/BuiltInConverters$UnitResponseBodyConverter;->d:Lretrofit2/BuiltInConverters$UnitResponseBodyConverter;

    .line 35
    .line 36
    return-object p0

    .line 37
    :catch_0
    const/4 p0, 0x0

    .line 38
    sput-boolean p0, Lretrofit2/Utils;->b:Z

    .line 39
    .line 40
    :cond_3
    const/4 p0, 0x0

    .line 41
    return-object p0
.end method
