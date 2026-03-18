.class final Lcom/squareup/moshi/Moshi$LookupChain;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/squareup/moshi/Moshi;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x11
    name = "LookupChain"
.end annotation


# instance fields
.field public final a:Ljava/util/ArrayList;

.field public final b:Ljava/util/ArrayDeque;

.field public c:Z

.field public final synthetic d:Lcom/squareup/moshi/Moshi;


# direct methods
.method public constructor <init>(Lcom/squareup/moshi/Moshi;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/squareup/moshi/Moshi$LookupChain;->d:Lcom/squareup/moshi/Moshi;

    .line 5
    .line 6
    new-instance p1, Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lcom/squareup/moshi/Moshi$LookupChain;->a:Ljava/util/ArrayList;

    .line 12
    .line 13
    new-instance p1, Ljava/util/ArrayDeque;

    .line 14
    .line 15
    invoke-direct {p1}, Ljava/util/ArrayDeque;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lcom/squareup/moshi/Moshi$LookupChain;->b:Ljava/util/ArrayDeque;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/IllegalArgumentException;)Ljava/lang/IllegalArgumentException;
    .locals 3

    .line 1
    iget-boolean v0, p0, Lcom/squareup/moshi/Moshi$LookupChain;->c:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    const/4 v0, 0x1

    .line 7
    iput-boolean v0, p0, Lcom/squareup/moshi/Moshi$LookupChain;->c:Z

    .line 8
    .line 9
    iget-object p0, p0, Lcom/squareup/moshi/Moshi$LookupChain;->b:Ljava/util/ArrayDeque;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->size()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-ne v1, v0, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->getFirst()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Lcom/squareup/moshi/Moshi$Lookup;

    .line 22
    .line 23
    iget-object v0, v0, Lcom/squareup/moshi/Moshi$Lookup;->b:Ljava/lang/String;

    .line 24
    .line 25
    if-nez v0, :cond_1

    .line 26
    .line 27
    :goto_0
    return-object p1

    .line 28
    :cond_1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 29
    .line 30
    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->descendingIterator()Ljava/util/Iterator;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    :cond_2
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    if-eqz v1, :cond_3

    .line 46
    .line 47
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    check-cast v1, Lcom/squareup/moshi/Moshi$Lookup;

    .line 52
    .line 53
    const-string v2, "\nfor "

    .line 54
    .line 55
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v2, v1, Lcom/squareup/moshi/Moshi$Lookup;->a:Ljava/lang/reflect/Type;

    .line 59
    .line 60
    iget-object v1, v1, Lcom/squareup/moshi/Moshi$Lookup;->b:Ljava/lang/String;

    .line 61
    .line 62
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    if-eqz v1, :cond_2

    .line 66
    .line 67
    const/16 v2, 0x20

    .line 68
    .line 69
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 77
    .line 78
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    invoke-direct {p0, v0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 83
    .line 84
    .line 85
    return-object p0
.end method

.method public final b(Z)V
    .locals 6

    .line 1
    iget-object v0, p0, Lcom/squareup/moshi/Moshi$LookupChain;->b:Ljava/util/ArrayDeque;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->removeLast()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/squareup/moshi/Moshi$LookupChain;->b:Ljava/util/ArrayDeque;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    goto :goto_3

    .line 15
    :cond_0
    iget-object v0, p0, Lcom/squareup/moshi/Moshi$LookupChain;->d:Lcom/squareup/moshi/Moshi;

    .line 16
    .line 17
    iget-object v0, v0, Lcom/squareup/moshi/Moshi;->b:Ljava/lang/ThreadLocal;

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->remove()V

    .line 20
    .line 21
    .line 22
    if-eqz p1, :cond_3

    .line 23
    .line 24
    iget-object p1, p0, Lcom/squareup/moshi/Moshi$LookupChain;->d:Lcom/squareup/moshi/Moshi;

    .line 25
    .line 26
    iget-object p1, p1, Lcom/squareup/moshi/Moshi;->c:Ljava/util/LinkedHashMap;

    .line 27
    .line 28
    monitor-enter p1

    .line 29
    :try_start_0
    iget-object v0, p0, Lcom/squareup/moshi/Moshi$LookupChain;->a:Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    const/4 v1, 0x0

    .line 36
    :goto_0
    if-ge v1, v0, :cond_2

    .line 37
    .line 38
    iget-object v2, p0, Lcom/squareup/moshi/Moshi$LookupChain;->a:Ljava/util/ArrayList;

    .line 39
    .line 40
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    check-cast v2, Lcom/squareup/moshi/Moshi$Lookup;

    .line 45
    .line 46
    iget-object v3, p0, Lcom/squareup/moshi/Moshi$LookupChain;->d:Lcom/squareup/moshi/Moshi;

    .line 47
    .line 48
    iget-object v3, v3, Lcom/squareup/moshi/Moshi;->c:Ljava/util/LinkedHashMap;

    .line 49
    .line 50
    iget-object v4, v2, Lcom/squareup/moshi/Moshi$Lookup;->c:Ljava/lang/Object;

    .line 51
    .line 52
    iget-object v5, v2, Lcom/squareup/moshi/Moshi$Lookup;->d:Lcom/squareup/moshi/JsonAdapter;

    .line 53
    .line 54
    invoke-interface {v3, v4, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v3

    .line 58
    check-cast v3, Lcom/squareup/moshi/JsonAdapter;

    .line 59
    .line 60
    if-eqz v3, :cond_1

    .line 61
    .line 62
    iput-object v3, v2, Lcom/squareup/moshi/Moshi$Lookup;->d:Lcom/squareup/moshi/JsonAdapter;

    .line 63
    .line 64
    iget-object v4, p0, Lcom/squareup/moshi/Moshi$LookupChain;->d:Lcom/squareup/moshi/Moshi;

    .line 65
    .line 66
    iget-object v4, v4, Lcom/squareup/moshi/Moshi;->c:Ljava/util/LinkedHashMap;

    .line 67
    .line 68
    iget-object v2, v2, Lcom/squareup/moshi/Moshi$Lookup;->c:Ljava/lang/Object;

    .line 69
    .line 70
    invoke-interface {v4, v2, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    goto :goto_1

    .line 74
    :catchall_0
    move-exception p0

    .line 75
    goto :goto_2

    .line 76
    :cond_1
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_2
    monitor-exit p1

    .line 80
    return-void

    .line 81
    :goto_2
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 82
    throw p0

    .line 83
    :cond_3
    :goto_3
    return-void
.end method
