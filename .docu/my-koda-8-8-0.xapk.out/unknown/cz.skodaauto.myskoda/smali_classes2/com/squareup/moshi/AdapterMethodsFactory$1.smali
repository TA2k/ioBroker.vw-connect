.class Lcom/squareup/moshi/AdapterMethodsFactory$1;
.super Lcom/squareup/moshi/JsonAdapter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lcom/squareup/moshi/JsonAdapter<",
        "Ljava/lang/Object;",
        ">;"
    }
.end annotation


# instance fields
.field public final synthetic a:Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;

.field public final synthetic b:Lcom/squareup/moshi/JsonAdapter;

.field public final synthetic c:Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;

.field public final synthetic d:Ljava/util/Set;

.field public final synthetic e:Ljava/lang/reflect/Type;


# direct methods
.method public constructor <init>(Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;Lcom/squareup/moshi/JsonAdapter;Lcom/squareup/moshi/Moshi;Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;Ljava/util/Set;Ljava/lang/reflect/Type;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/squareup/moshi/AdapterMethodsFactory$1;->a:Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/squareup/moshi/AdapterMethodsFactory$1;->b:Lcom/squareup/moshi/JsonAdapter;

    .line 4
    .line 5
    iput-object p4, p0, Lcom/squareup/moshi/AdapterMethodsFactory$1;->c:Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;

    .line 6
    .line 7
    iput-object p5, p0, Lcom/squareup/moshi/AdapterMethodsFactory$1;->d:Ljava/util/Set;

    .line 8
    .line 9
    iput-object p6, p0, Lcom/squareup/moshi/AdapterMethodsFactory$1;->e:Ljava/lang/reflect/Type;

    .line 10
    .line 11
    invoke-direct {p0}, Lcom/squareup/moshi/JsonAdapter;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Lcom/squareup/moshi/JsonReader;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/squareup/moshi/AdapterMethodsFactory$1;->c:Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lcom/squareup/moshi/AdapterMethodsFactory$1;->b:Lcom/squareup/moshi/JsonAdapter;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/JsonAdapter;->a(Lcom/squareup/moshi/JsonReader;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    iget-boolean p0, v0, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->g:Z

    .line 13
    .line 14
    if-nez p0, :cond_1

    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonReader;->T()Lcom/squareup/moshi/JsonReader$Token;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    sget-object v1, Lcom/squareup/moshi/JsonReader$Token;->l:Lcom/squareup/moshi/JsonReader$Token;

    .line 21
    .line 22
    if-ne p0, v1, :cond_1

    .line 23
    .line 24
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonReader;->E()V

    .line 25
    .line 26
    .line 27
    const/4 p0, 0x0

    .line 28
    return-object p0

    .line 29
    :cond_1
    :try_start_0
    invoke-virtual {v0, p1}, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->b(Lcom/squareup/moshi/JsonReader;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_0 .. :try_end_0} :catch_0

    .line 33
    return-object p0

    .line 34
    :catch_0
    move-exception p0

    .line 35
    invoke-virtual {p0}, Ljava/lang/reflect/InvocationTargetException;->getCause()Ljava/lang/Throwable;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    instance-of v0, p0, Ljava/io/IOException;

    .line 40
    .line 41
    if-eqz v0, :cond_2

    .line 42
    .line 43
    check-cast p0, Ljava/io/IOException;

    .line 44
    .line 45
    throw p0

    .line 46
    :cond_2
    new-instance v0, Lcom/squareup/moshi/JsonDataException;

    .line 47
    .line 48
    new-instance v1, Ljava/lang/StringBuilder;

    .line 49
    .line 50
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    const-string v2, " at "

    .line 57
    .line 58
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonReader;->g()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    invoke-direct {v0, p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 73
    .line 74
    .line 75
    throw v0
.end method

.method public final e(Lcom/squareup/moshi/JsonWriter;Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/squareup/moshi/AdapterMethodsFactory$1;->a:Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lcom/squareup/moshi/AdapterMethodsFactory$1;->b:Lcom/squareup/moshi/JsonAdapter;

    .line 6
    .line 7
    invoke-virtual {p0, p1, p2}, Lcom/squareup/moshi/JsonAdapter;->e(Lcom/squareup/moshi/JsonWriter;Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    iget-boolean p0, v0, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->g:Z

    .line 12
    .line 13
    if-nez p0, :cond_1

    .line 14
    .line 15
    if-nez p2, :cond_1

    .line 16
    .line 17
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonWriter;->k()Lcom/squareup/moshi/JsonWriter;

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_1
    :try_start_0
    invoke-virtual {v0, p1, p2}, Lcom/squareup/moshi/AdapterMethodsFactory$AdapterMethod;->d(Lcom/squareup/moshi/JsonWriter;Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_0 .. :try_end_0} :catch_0

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :catch_0
    move-exception p0

    .line 26
    invoke-virtual {p0}, Ljava/lang/reflect/InvocationTargetException;->getCause()Ljava/lang/Throwable;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    instance-of p2, p0, Ljava/io/IOException;

    .line 31
    .line 32
    if-eqz p2, :cond_2

    .line 33
    .line 34
    check-cast p0, Ljava/io/IOException;

    .line 35
    .line 36
    throw p0

    .line 37
    :cond_2
    new-instance p2, Lcom/squareup/moshi/JsonDataException;

    .line 38
    .line 39
    new-instance v0, Ljava/lang/StringBuilder;

    .line 40
    .line 41
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string v1, " at "

    .line 48
    .line 49
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {p1}, Lcom/squareup/moshi/JsonWriter;->h()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    invoke-direct {p2, p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 64
    .line 65
    .line 66
    throw p2
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "JsonAdapter"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lcom/squareup/moshi/AdapterMethodsFactory$1;->d:Ljava/util/Set;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, "("

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lcom/squareup/moshi/AdapterMethodsFactory$1;->e:Ljava/lang/reflect/Type;

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, ")"

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
