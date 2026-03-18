.class public final Lcom/google/gson/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lcom/google/gson/internal/Excluder;

.field public final b:I

.field public final c:Lcom/google/gson/a;

.field public final d:Ljava/util/HashMap;

.field public final e:Ljava/util/ArrayList;

.field public final f:Ljava/util/ArrayList;

.field public final g:I

.field public final h:I

.field public final i:Z

.field public final j:Lcom/google/gson/i;

.field public final k:Z

.field public final l:Lcom/google/gson/t;

.field public final m:Lcom/google/gson/u;

.field public final n:Ljava/util/ArrayDeque;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lcom/google/gson/internal/Excluder;->f:Lcom/google/gson/internal/Excluder;

    .line 5
    .line 6
    iput-object v0, p0, Lcom/google/gson/k;->a:Lcom/google/gson/internal/Excluder;

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    iput v0, p0, Lcom/google/gson/k;->b:I

    .line 10
    .line 11
    sget-object v1, Lcom/google/gson/h;->d:Lcom/google/gson/a;

    .line 12
    .line 13
    iput-object v1, p0, Lcom/google/gson/k;->c:Lcom/google/gson/a;

    .line 14
    .line 15
    new-instance v1, Ljava/util/HashMap;

    .line 16
    .line 17
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object v1, p0, Lcom/google/gson/k;->d:Ljava/util/HashMap;

    .line 21
    .line 22
    new-instance v1, Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 25
    .line 26
    .line 27
    iput-object v1, p0, Lcom/google/gson/k;->e:Ljava/util/ArrayList;

    .line 28
    .line 29
    new-instance v1, Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object v1, p0, Lcom/google/gson/k;->f:Ljava/util/ArrayList;

    .line 35
    .line 36
    sget-object v1, Lcom/google/gson/j;->k:Lcom/google/gson/i;

    .line 37
    .line 38
    const/4 v1, 0x2

    .line 39
    iput v1, p0, Lcom/google/gson/k;->g:I

    .line 40
    .line 41
    iput v1, p0, Lcom/google/gson/k;->h:I

    .line 42
    .line 43
    iput-boolean v0, p0, Lcom/google/gson/k;->i:Z

    .line 44
    .line 45
    sget-object v1, Lcom/google/gson/j;->k:Lcom/google/gson/i;

    .line 46
    .line 47
    iput-object v1, p0, Lcom/google/gson/k;->j:Lcom/google/gson/i;

    .line 48
    .line 49
    iput-boolean v0, p0, Lcom/google/gson/k;->k:Z

    .line 50
    .line 51
    sget-object v0, Lcom/google/gson/j;->m:Lcom/google/gson/t;

    .line 52
    .line 53
    iput-object v0, p0, Lcom/google/gson/k;->l:Lcom/google/gson/t;

    .line 54
    .line 55
    sget-object v0, Lcom/google/gson/j;->n:Lcom/google/gson/u;

    .line 56
    .line 57
    iput-object v0, p0, Lcom/google/gson/k;->m:Lcom/google/gson/u;

    .line 58
    .line 59
    new-instance v0, Ljava/util/ArrayDeque;

    .line 60
    .line 61
    invoke-direct {v0}, Ljava/util/ArrayDeque;-><init>()V

    .line 62
    .line 63
    .line 64
    iput-object v0, p0, Lcom/google/gson/k;->n:Ljava/util/ArrayDeque;

    .line 65
    .line 66
    return-void
.end method


# virtual methods
.method public final a()Lcom/google/gson/j;
    .locals 14

    .line 1
    new-instance v10, Ljava/util/ArrayList;

    .line 2
    .line 3
    iget-object v0, p0, Lcom/google/gson/k;->e:Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    iget-object v2, p0, Lcom/google/gson/k;->f:Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    add-int/2addr v3, v1

    .line 16
    add-int/lit8 v3, v3, 0x3

    .line 17
    .line 18
    invoke-direct {v10, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v10, v0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 22
    .line 23
    .line 24
    invoke-static {v10}, Ljava/util/Collections;->reverse(Ljava/util/List;)V

    .line 25
    .line 26
    .line 27
    new-instance v1, Ljava/util/ArrayList;

    .line 28
    .line 29
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v1}, Ljava/util/Collections;->reverse(Ljava/util/List;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v10, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 36
    .line 37
    .line 38
    sget-boolean v1, Lcom/google/gson/internal/sql/b;->a:Z

    .line 39
    .line 40
    iget v3, p0, Lcom/google/gson/k;->g:I

    .line 41
    .line 42
    iget v4, p0, Lcom/google/gson/k;->h:I

    .line 43
    .line 44
    const/4 v5, 0x2

    .line 45
    if-ne v3, v5, :cond_0

    .line 46
    .line 47
    if-eq v4, v5, :cond_2

    .line 48
    .line 49
    :cond_0
    sget-object v5, Lcom/google/gson/internal/bind/b;->b:Lcom/google/gson/internal/bind/a;

    .line 50
    .line 51
    invoke-virtual {v5, v3, v4}, Lcom/google/gson/internal/bind/b;->a(II)Lcom/google/gson/z;

    .line 52
    .line 53
    .line 54
    move-result-object v5

    .line 55
    if-eqz v1, :cond_1

    .line 56
    .line 57
    sget-object v6, Lcom/google/gson/internal/sql/b;->c:Lcom/google/gson/internal/sql/a;

    .line 58
    .line 59
    invoke-virtual {v6, v3, v4}, Lcom/google/gson/internal/bind/b;->a(II)Lcom/google/gson/z;

    .line 60
    .line 61
    .line 62
    move-result-object v6

    .line 63
    sget-object v7, Lcom/google/gson/internal/sql/b;->b:Lcom/google/gson/internal/sql/a;

    .line 64
    .line 65
    invoke-virtual {v7, v3, v4}, Lcom/google/gson/internal/bind/b;->a(II)Lcom/google/gson/z;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    goto :goto_0

    .line 70
    :cond_1
    const/4 v6, 0x0

    .line 71
    move-object v3, v6

    .line 72
    :goto_0
    invoke-virtual {v10, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    if-eqz v1, :cond_2

    .line 76
    .line 77
    invoke-virtual {v10, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    invoke-virtual {v10, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    :cond_2
    move-object v1, v0

    .line 84
    new-instance v0, Lcom/google/gson/j;

    .line 85
    .line 86
    new-instance v3, Ljava/util/HashMap;

    .line 87
    .line 88
    iget-object v4, p0, Lcom/google/gson/k;->d:Ljava/util/HashMap;

    .line 89
    .line 90
    invoke-direct {v3, v4}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 91
    .line 92
    .line 93
    new-instance v8, Ljava/util/ArrayList;

    .line 94
    .line 95
    invoke-direct {v8, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 96
    .line 97
    .line 98
    new-instance v9, Ljava/util/ArrayList;

    .line 99
    .line 100
    invoke-direct {v9, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 101
    .line 102
    .line 103
    new-instance v13, Ljava/util/ArrayList;

    .line 104
    .line 105
    iget-object v1, p0, Lcom/google/gson/k;->n:Ljava/util/ArrayDeque;

    .line 106
    .line 107
    invoke-direct {v13, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 108
    .line 109
    .line 110
    iget-object v1, p0, Lcom/google/gson/k;->a:Lcom/google/gson/internal/Excluder;

    .line 111
    .line 112
    iget-object v2, p0, Lcom/google/gson/k;->c:Lcom/google/gson/a;

    .line 113
    .line 114
    iget-boolean v4, p0, Lcom/google/gson/k;->i:Z

    .line 115
    .line 116
    iget-object v5, p0, Lcom/google/gson/k;->j:Lcom/google/gson/i;

    .line 117
    .line 118
    iget-boolean v6, p0, Lcom/google/gson/k;->k:Z

    .line 119
    .line 120
    iget v7, p0, Lcom/google/gson/k;->b:I

    .line 121
    .line 122
    iget-object v11, p0, Lcom/google/gson/k;->l:Lcom/google/gson/t;

    .line 123
    .line 124
    iget-object v12, p0, Lcom/google/gson/k;->m:Lcom/google/gson/u;

    .line 125
    .line 126
    invoke-direct/range {v0 .. v13}, Lcom/google/gson/j;-><init>(Lcom/google/gson/internal/Excluder;Lcom/google/gson/h;Ljava/util/Map;ZLcom/google/gson/i;ZILjava/util/List;Ljava/util/List;Ljava/util/List;Lcom/google/gson/x;Lcom/google/gson/x;Ljava/util/List;)V

    .line 127
    .line 128
    .line 129
    return-object v0
.end method

.method public final b(Ljava/lang/Class;Lcom/google/gson/m;)V
    .locals 1

    .line 1
    const-class v0, Ljava/lang/Object;

    .line 2
    .line 3
    if-eq p1, v0, :cond_1

    .line 4
    .line 5
    invoke-static {p1}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/reflect/Type;)Lcom/google/gson/reflect/TypeToken;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {v0, p2}, Lcom/google/gson/internal/bind/TreeTypeAdapter;->e(Lcom/google/gson/reflect/TypeToken;Lcom/google/gson/m;)Lcom/google/gson/z;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object p0, p0, Lcom/google/gson/k;->e:Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    instance-of v0, p2, Lcom/google/gson/y;

    .line 19
    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    invoke-static {p1}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/reflect/Type;)Lcom/google/gson/reflect/TypeToken;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    check-cast p2, Lcom/google/gson/y;

    .line 27
    .line 28
    invoke-static {p1, p2}, Lcom/google/gson/internal/bind/e;->a(Lcom/google/gson/reflect/TypeToken;Lcom/google/gson/y;)Lcom/google/gson/z;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    :cond_0
    return-void

    .line 36
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 37
    .line 38
    new-instance p2, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    const-string v0, "Cannot override built-in adapter for "

    .line 41
    .line 42
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0
.end method
