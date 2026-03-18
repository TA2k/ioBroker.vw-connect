.class abstract Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/squareup/moshi/AdapterMethodsFactory;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x409
    name = "AdapterMethod"
.end annotation


# instance fields
.field public final a:Ljava/lang/reflect/Type;

.field public final b:Ljava/util/Set;

.field public final c:Ljava/lang/Object;

.field public final d:Ljava/lang/reflect/Method;

.field public final e:I

.field public final f:[Lcom/squareup/moshi/JsonAdapter;

.field public final g:Z


# direct methods
.method public constructor <init>(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/Object;Ljava/lang/reflect/Method;IIZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lax/b;->a(Ljava/lang/reflect/Type;)Ljava/lang/reflect/Type;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    iput-object p1, p0, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->a:Ljava/lang/reflect/Type;

    .line 9
    .line 10
    iput-object p2, p0, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->b:Ljava/util/Set;

    .line 11
    .line 12
    iput-object p3, p0, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->c:Ljava/lang/Object;

    .line 13
    .line 14
    iput-object p4, p0, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->d:Ljava/lang/reflect/Method;

    .line 15
    .line 16
    iput p6, p0, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->e:I

    .line 17
    .line 18
    sub-int/2addr p5, p6

    .line 19
    new-array p1, p5, [Lcom/squareup/moshi/JsonAdapter;

    .line 20
    .line 21
    iput-object p1, p0, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->f:[Lcom/squareup/moshi/JsonAdapter;

    .line 22
    .line 23
    iput-boolean p7, p0, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->g:Z

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public a(Lcom/squareup/moshi/Moshi;Lcom/squareup/moshi/JsonAdapter$Factory;)V
    .locals 10

    .line 1
    iget-object v0, p0, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->f:[Lcom/squareup/moshi/JsonAdapter;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    if-lez v1, :cond_1

    .line 5
    .line 6
    iget-object v1, p0, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->d:Ljava/lang/reflect/Method;

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/lang/reflect/Method;->getGenericParameterTypes()[Ljava/lang/reflect/Type;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    invoke-virtual {v1}, Ljava/lang/reflect/Method;->getParameterAnnotations()[[Ljava/lang/annotation/Annotation;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    array-length v3, v2

    .line 17
    iget v4, p0, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->e:I

    .line 18
    .line 19
    move v5, v4

    .line 20
    :goto_0
    if-ge v5, v3, :cond_1

    .line 21
    .line 22
    aget-object v6, v2, v5

    .line 23
    .line 24
    check-cast v6, Ljava/lang/reflect/ParameterizedType;

    .line 25
    .line 26
    invoke-interface {v6}, Ljava/lang/reflect/ParameterizedType;->getActualTypeArguments()[Ljava/lang/reflect/Type;

    .line 27
    .line 28
    .line 29
    move-result-object v6

    .line 30
    const/4 v7, 0x0

    .line 31
    aget-object v6, v6, v7

    .line 32
    .line 33
    aget-object v7, v1, v5

    .line 34
    .line 35
    invoke-static {v7}, Lax/b;->f([Ljava/lang/annotation/Annotation;)Ljava/util/Set;

    .line 36
    .line 37
    .line 38
    move-result-object v7

    .line 39
    sub-int v8, v5, v4

    .line 40
    .line 41
    iget-object v9, p0, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->a:Ljava/lang/reflect/Type;

    .line 42
    .line 43
    invoke-static {v9, v6}, Lcom/squareup/moshi/Types;->b(Ljava/lang/reflect/Type;Ljava/lang/reflect/Type;)Z

    .line 44
    .line 45
    .line 46
    move-result v9

    .line 47
    if-eqz v9, :cond_0

    .line 48
    .line 49
    iget-object v9, p0, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->b:Ljava/util/Set;

    .line 50
    .line 51
    invoke-interface {v9, v7}, Ljava/util/Set;->equals(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v9

    .line 55
    if-eqz v9, :cond_0

    .line 56
    .line 57
    invoke-virtual {p1, p2, v6, v7}, Lcom/squareup/moshi/Moshi;->b(Lcom/squareup/moshi/JsonAdapter$Factory;Ljava/lang/reflect/Type;Ljava/util/Set;)Lcom/squareup/moshi/JsonAdapter;

    .line 58
    .line 59
    .line 60
    move-result-object v6

    .line 61
    goto :goto_1

    .line 62
    :cond_0
    const/4 v9, 0x0

    .line 63
    invoke-virtual {p1, v6, v7, v9}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 64
    .line 65
    .line 66
    move-result-object v6

    .line 67
    :goto_1
    aput-object v6, v0, v8

    .line 68
    .line 69
    add-int/lit8 v5, v5, 0x1

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_1
    return-void
.end method

.method public b(Lcom/squareup/moshi/JsonReader;)Ljava/lang/Object;
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/AssertionError;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/AssertionError;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method

.method public final c(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->f:[Lcom/squareup/moshi/JsonAdapter;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    const/4 v2, 0x1

    .line 5
    add-int/2addr v1, v2

    .line 6
    new-array v1, v1, [Ljava/lang/Object;

    .line 7
    .line 8
    const/4 v3, 0x0

    .line 9
    aput-object p1, v1, v3

    .line 10
    .line 11
    array-length p1, v0

    .line 12
    invoke-static {v0, v3, v1, v2, p1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 13
    .line 14
    .line 15
    :try_start_0
    iget-object p1, p0, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->d:Ljava/lang/reflect/Method;

    .line 16
    .line 17
    iget-object p0, p0, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->c:Ljava/lang/Object;

    .line 18
    .line 19
    invoke-virtual {p1, p0, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0

    .line 23
    return-object p0

    .line 24
    :catch_0
    new-instance p0, Ljava/lang/AssertionError;

    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/AssertionError;-><init>()V

    .line 27
    .line 28
    .line 29
    throw p0
.end method

.method public d(Lcom/squareup/moshi/JsonWriter;Ljava/lang/Object;)V
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/AssertionError;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/AssertionError;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method
