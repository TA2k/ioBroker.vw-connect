.class final Lcom/squareup/moshi/AdapterMethodsFactory;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/squareup/moshi/JsonAdapter$Factory;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;
    }
.end annotation


# instance fields
.field public final a:Ljava/util/ArrayList;

.field public final b:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Ljava/util/ArrayList;Ljava/util/ArrayList;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/squareup/moshi/AdapterMethodsFactory;->a:Ljava/util/ArrayList;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/squareup/moshi/AdapterMethodsFactory;->b:Ljava/util/ArrayList;

    .line 7
    .line 8
    return-void
.end method

.method public static b(Ljava/util/ArrayList;Ljava/lang/reflect/Type;Ljava/util/Set;)Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;
    .locals 4

    .line 1
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :goto_0
    if-ge v1, v0, :cond_1

    .line 7
    .line 8
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    check-cast v2, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;

    .line 13
    .line 14
    iget-object v3, v2, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->a:Ljava/lang/reflect/Type;

    .line 15
    .line 16
    invoke-static {v3, p1}, Lcom/squareup/moshi/Types;->b(Ljava/lang/reflect/Type;Ljava/lang/reflect/Type;)Z

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    if-eqz v3, :cond_0

    .line 21
    .line 22
    iget-object v3, v2, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->b:Ljava/util/Set;

    .line 23
    .line 24
    invoke-interface {v3, p2}, Ljava/util/Set;->equals(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    if-eqz v3, :cond_0

    .line 29
    .line 30
    return-object v2

    .line 31
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    const/4 p0, 0x0

    .line 35
    return-object p0
.end method


# virtual methods
.method public final a(Ljava/lang/reflect/Type;Ljava/util/Set;Lcom/squareup/moshi/Moshi;)Lcom/squareup/moshi/JsonAdapter;
    .locals 8

    .line 1
    iget-object v0, p0, Lcom/squareup/moshi/AdapterMethodsFactory;->a:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-static {v0, p1, p2}, Lcom/squareup/moshi/AdapterMethodsFactory;->b(Ljava/util/ArrayList;Ljava/lang/reflect/Type;Ljava/util/Set;)Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;

    .line 4
    .line 5
    .line 6
    move-result-object v2

    .line 7
    iget-object v0, p0, Lcom/squareup/moshi/AdapterMethodsFactory;->b:Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-static {v0, p1, p2}, Lcom/squareup/moshi/AdapterMethodsFactory;->b(Ljava/util/ArrayList;Ljava/lang/reflect/Type;Ljava/util/Set;)Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;

    .line 10
    .line 11
    .line 12
    move-result-object v5

    .line 13
    const/4 v0, 0x0

    .line 14
    if-nez v2, :cond_0

    .line 15
    .line 16
    if-nez v5, :cond_0

    .line 17
    .line 18
    return-object v0

    .line 19
    :cond_0
    if-eqz v2, :cond_2

    .line 20
    .line 21
    if-nez v5, :cond_1

    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_1
    :goto_0
    move-object v3, v0

    .line 25
    goto :goto_2

    .line 26
    :cond_2
    :goto_1
    :try_start_0
    invoke-virtual {p3, p0, p1, p2}, Lcom/squareup/moshi/Moshi;->b(Lcom/squareup/moshi/JsonAdapter$Factory;Ljava/lang/reflect/Type;Ljava/util/Set;)Lcom/squareup/moshi/JsonAdapter;

    .line 27
    .line 28
    .line 29
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 30
    goto :goto_0

    .line 31
    :goto_2
    if-eqz v2, :cond_3

    .line 32
    .line 33
    invoke-virtual {v2, p3, p0}, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->a(Lcom/squareup/moshi/Moshi;Lcom/squareup/moshi/JsonAdapter$Factory;)V

    .line 34
    .line 35
    .line 36
    :cond_3
    if-eqz v5, :cond_4

    .line 37
    .line 38
    invoke-virtual {v5, p3, p0}, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->a(Lcom/squareup/moshi/Moshi;Lcom/squareup/moshi/JsonAdapter$Factory;)V

    .line 39
    .line 40
    .line 41
    :cond_4
    new-instance v1, Lcom/squareup/moshi/AdapterMethodsFactory$1;

    .line 42
    .line 43
    move-object v7, p1

    .line 44
    move-object v6, p2

    .line 45
    move-object v4, p3

    .line 46
    invoke-direct/range {v1 .. v7}, Lcom/squareup/moshi/AdapterMethodsFactory$1;-><init>(Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;Lcom/squareup/moshi/JsonAdapter;Lcom/squareup/moshi/Moshi;Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;Ljava/util/Set;Ljava/lang/reflect/Type;)V

    .line 47
    .line 48
    .line 49
    return-object v1

    .line 50
    :catch_0
    move-exception v0

    .line 51
    move-object v7, p1

    .line 52
    move-object v6, p2

    .line 53
    move-object p0, v0

    .line 54
    if-nez v2, :cond_5

    .line 55
    .line 56
    const-string p1, "@ToJson"

    .line 57
    .line 58
    goto :goto_3

    .line 59
    :cond_5
    const-string p1, "@FromJson"

    .line 60
    .line 61
    :goto_3
    new-instance p2, Ljava/lang/IllegalArgumentException;

    .line 62
    .line 63
    const-string p3, "No "

    .line 64
    .line 65
    const-string v0, " adapter for "

    .line 66
    .line 67
    invoke-static {p3, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    invoke-static {v7, v6}, Lax/b;->j(Ljava/lang/reflect/Type;Ljava/util/Set;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p3

    .line 75
    invoke-virtual {p1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    invoke-direct {p2, p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 83
    .line 84
    .line 85
    throw p2
.end method
