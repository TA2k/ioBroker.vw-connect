.class public final Lvu/l;
.super Lsu/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic A:I


# instance fields
.field public final t:Landroid/content/Context;

.field public final u:Lvy0/b0;

.field public final v:Ll2/b1;

.field public final w:Ll2/b1;

.field public final x:Ll2/b1;

.field public final y:Landroid/graphics/Canvas;

.field public final z:Ljava/util/LinkedHashMap;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lvy0/b0;Lqp/g;Lqu/c;Ll2/b1;Ll2/b1;Ll2/b1;)V
    .locals 1

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "scope"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "map"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0, p1, p3, p4}, Lsu/i;-><init>(Landroid/content/Context;Lqp/g;Lqu/c;)V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lvu/l;->t:Landroid/content/Context;

    .line 20
    .line 21
    iput-object p2, p0, Lvu/l;->u:Lvy0/b0;

    .line 22
    .line 23
    iput-object p5, p0, Lvu/l;->v:Ll2/b1;

    .line 24
    .line 25
    iput-object p6, p0, Lvu/l;->w:Ll2/b1;

    .line 26
    .line 27
    iput-object p7, p0, Lvu/l;->x:Ll2/b1;

    .line 28
    .line 29
    new-instance p1, Landroid/graphics/Canvas;

    .line 30
    .line 31
    invoke-direct {p1}, Landroid/graphics/Canvas;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object p1, p0, Lvu/l;->y:Landroid/graphics/Canvas;

    .line 35
    .line 36
    new-instance p1, Ljava/util/LinkedHashMap;

    .line 37
    .line 38
    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 39
    .line 40
    .line 41
    iput-object p1, p0, Lvu/l;->z:Ljava/util/LinkedHashMap;

    .line 42
    .line 43
    return-void
.end method


# virtual methods
.method public final a(Ljava/util/Set;)V
    .locals 4

    .line 1
    const-string v0, "clusters"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Lsu/i;->a(Ljava/util/Set;)V

    .line 7
    .line 8
    .line 9
    check-cast p1, Ljava/lang/Iterable;

    .line 10
    .line 11
    new-instance v0, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 14
    .line 15
    .line 16
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_0

    .line 25
    .line 26
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    check-cast v1, Lqu/a;

    .line 31
    .line 32
    invoke-virtual {p0, v1}, Lvu/l;->f(Lqu/a;)Ljava/util/Set;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    check-cast v1, Ljava/lang/Iterable;

    .line 37
    .line 38
    invoke-static {v1, v0}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    iget-object p1, p0, Lvu/l;->z:Ljava/util/LinkedHashMap;

    .line 43
    .line 44
    invoke-virtual {p1}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    :cond_1
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    if-eqz v2, :cond_2

    .line 57
    .line 58
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    check-cast v2, Ljava/util/Map$Entry;

    .line 63
    .line 64
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    check-cast v3, Lvu/i;

    .line 69
    .line 70
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    check-cast v2, Lvu/f;

    .line 75
    .line 76
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    if-nez v3, :cond_1

    .line 81
    .line 82
    invoke-interface {v1}, Ljava/util/Iterator;->remove()V

    .line 83
    .line 84
    .line 85
    iget-object v2, v2, Lvu/f;->b:Lvu/d;

    .line 86
    .line 87
    invoke-virtual {v2}, Lvu/d;->invoke()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_2
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    :cond_3
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    if-eqz v1, :cond_4

    .line 100
    .line 101
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    check-cast v1, Lvu/i;

    .line 106
    .line 107
    invoke-virtual {p1}, Ljava/util/LinkedHashMap;->keySet()Ljava/util/Set;

    .line 108
    .line 109
    .line 110
    move-result-object v2

    .line 111
    invoke-interface {v2, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v2

    .line 115
    if-nez v2, :cond_3

    .line 116
    .line 117
    invoke-virtual {p0, v1}, Lvu/l;->g(Lvu/i;)Lvu/f;

    .line 118
    .line 119
    .line 120
    goto :goto_2

    .line 121
    :cond_4
    return-void
.end method

.method public final c(Lqu/a;)Lsp/b;
    .locals 5

    .line 1
    iget-object v0, p0, Lvu/l;->w:Ll2/b1;

    .line 2
    .line 3
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-eqz v0, :cond_5

    .line 8
    .line 9
    iget-object v0, p0, Lvu/l;->z:Ljava/util/LinkedHashMap;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Ljava/lang/Iterable;

    .line 16
    .line 17
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    const/4 v2, 0x0

    .line 26
    if-eqz v1, :cond_3

    .line 27
    .line 28
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    move-object v3, v1

    .line 33
    check-cast v3, Ljava/util/Map$Entry;

    .line 34
    .line 35
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    check-cast v3, Lvu/i;

    .line 40
    .line 41
    instance-of v4, v3, Lvu/g;

    .line 42
    .line 43
    if-eqz v4, :cond_1

    .line 44
    .line 45
    check-cast v3, Lvu/g;

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    move-object v3, v2

    .line 49
    :goto_0
    if-eqz v3, :cond_2

    .line 50
    .line 51
    iget-object v2, v3, Lvu/g;->a:Lqu/a;

    .line 52
    .line 53
    :cond_2
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    if-eqz v2, :cond_0

    .line 58
    .line 59
    move-object v2, v1

    .line 60
    :cond_3
    check-cast v2, Ljava/util/Map$Entry;

    .line 61
    .line 62
    if-eqz v2, :cond_4

    .line 63
    .line 64
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    check-cast v0, Lvu/f;

    .line 69
    .line 70
    if-eqz v0, :cond_4

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_4
    invoke-virtual {p0, p1}, Lvu/l;->f(Lqu/a;)Ljava/util/Set;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    check-cast p1, Ljava/lang/Iterable;

    .line 78
    .line 79
    invoke-static {p1}, Lmx0/q;->I(Ljava/lang/Iterable;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    check-cast p1, Lvu/i;

    .line 84
    .line 85
    invoke-virtual {p0, p1}, Lvu/l;->g(Lvu/i;)Lvu/f;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    :goto_1
    iget-object p1, v0, Lvu/f;->a:Lvu/e;

    .line 90
    .line 91
    invoke-virtual {p0, p1}, Lvu/l;->h(Lw3/a;)Lsp/b;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    return-object p0

    .line 96
    :cond_5
    invoke-super {p0, p1}, Lsu/i;->c(Lqu/a;)Lsp/b;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    return-object p0
.end method

.method public final e(Lzj0/c;Lsp/l;)V
    .locals 5

    .line 1
    const-string v0, "item"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lvu/l;->x:Ll2/b1;

    .line 7
    .line 8
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    if-eqz v0, :cond_5

    .line 13
    .line 14
    iget-object v0, p0, Lvu/l;->z:Ljava/util/LinkedHashMap;

    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    check-cast v0, Ljava/lang/Iterable;

    .line 21
    .line 22
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    const/4 v2, 0x0

    .line 31
    if-eqz v1, :cond_3

    .line 32
    .line 33
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    move-object v3, v1

    .line 38
    check-cast v3, Ljava/util/Map$Entry;

    .line 39
    .line 40
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    check-cast v3, Lvu/i;

    .line 45
    .line 46
    instance-of v4, v3, Lvu/h;

    .line 47
    .line 48
    if-eqz v4, :cond_1

    .line 49
    .line 50
    check-cast v3, Lvu/h;

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_1
    move-object v3, v2

    .line 54
    :goto_0
    if-eqz v3, :cond_2

    .line 55
    .line 56
    iget-object v2, v3, Lvu/h;->a:Lzj0/c;

    .line 57
    .line 58
    :cond_2
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    if-eqz v2, :cond_0

    .line 63
    .line 64
    move-object v2, v1

    .line 65
    :cond_3
    check-cast v2, Ljava/util/Map$Entry;

    .line 66
    .line 67
    if-eqz v2, :cond_4

    .line 68
    .line 69
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    check-cast v0, Lvu/f;

    .line 74
    .line 75
    if-eqz v0, :cond_4

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_4
    new-instance v0, Lvu/h;

    .line 79
    .line 80
    invoke-direct {v0, p1}, Lvu/h;-><init>(Lzj0/c;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p0, v0}, Lvu/l;->g(Lvu/i;)Lvu/f;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    :goto_1
    iget-object p1, v0, Lvu/f;->a:Lvu/e;

    .line 88
    .line 89
    invoke-virtual {p0, p1}, Lvu/l;->h(Lw3/a;)Lsp/b;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    iput-object p0, p2, Lsp/l;->g:Lsp/b;

    .line 94
    .line 95
    :cond_5
    return-void
.end method

.method public final f(Lqu/a;)Ljava/util/Set;
    .locals 2

    .line 1
    invoke-interface {p1}, Lqu/a;->a()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget p0, p0, Lsu/i;->k:I

    .line 6
    .line 7
    if-lt v0, p0, :cond_0

    .line 8
    .line 9
    new-instance p0, Lvu/g;

    .line 10
    .line 11
    invoke-direct {p0, p1}, Lvu/g;-><init>(Lqu/a;)V

    .line 12
    .line 13
    .line 14
    invoke-static {p0}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :cond_0
    invoke-interface {p1}, Lqu/a;->b()Ljava/util/Collection;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const-string p1, "getItems(...)"

    .line 24
    .line 25
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    check-cast p0, Ljava/lang/Iterable;

    .line 29
    .line 30
    new-instance p1, Ljava/util/LinkedHashSet;

    .line 31
    .line 32
    invoke-direct {p1}, Ljava/util/LinkedHashSet;-><init>()V

    .line 33
    .line 34
    .line 35
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_1

    .line 44
    .line 45
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    check-cast v0, Lzj0/c;

    .line 50
    .line 51
    new-instance v1, Lvu/h;

    .line 52
    .line 53
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    invoke-direct {v1, v0}, Lvu/h;-><init>(Lzj0/c;)V

    .line 57
    .line 58
    .line 59
    invoke-interface {p1, v1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_1
    return-object p1
.end method

.method public final g(Lvu/i;)Lvu/f;
    .locals 7

    .line 1
    new-instance v4, Lvu/e;

    .line 2
    .line 3
    instance-of v0, p1, Lvu/g;

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    new-instance v0, Lvu/c;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    invoke-direct {v0, p0, p1, v2}, Lvu/c;-><init>(Lvu/l;Lvu/i;I)V

    .line 12
    .line 13
    .line 14
    new-instance v2, Lt2/b;

    .line 15
    .line 16
    const v3, -0xdc82d20

    .line 17
    .line 18
    .line 19
    invoke-direct {v2, v0, v1, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    instance-of v0, p1, Lvu/h;

    .line 24
    .line 25
    if-eqz v0, :cond_1

    .line 26
    .line 27
    new-instance v0, Lvu/c;

    .line 28
    .line 29
    const/4 v2, 0x1

    .line 30
    invoke-direct {v0, p0, p1, v2}, Lvu/c;-><init>(Lvu/l;Lvu/i;I)V

    .line 31
    .line 32
    .line 33
    new-instance v2, Lt2/b;

    .line 34
    .line 35
    const v3, -0x7046e029

    .line 36
    .line 37
    .line 38
    invoke-direct {v2, v0, v1, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 39
    .line 40
    .line 41
    :goto_0
    iget-object v0, p0, Lvu/l;->t:Landroid/content/Context;

    .line 42
    .line 43
    invoke-direct {v4, v0, v2}, Lvu/e;-><init>(Landroid/content/Context;Lt2/b;)V

    .line 44
    .line 45
    .line 46
    iget-object v0, p0, Lvu/l;->v:Ll2/b1;

    .line 47
    .line 48
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    check-cast v0, Luu/o0;

    .line 53
    .line 54
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 55
    .line 56
    .line 57
    iget-object v1, v0, Luu/o0;->a:Lqp/h;

    .line 58
    .line 59
    iget-object v0, v0, Luu/o0;->b:Ll2/r;

    .line 60
    .line 61
    invoke-static {v1, v4, v0}, Llp/ga;->b(Lqp/h;Lw3/a;Ll2/r;)Luu/p0;

    .line 62
    .line 63
    .line 64
    move-result-object v6

    .line 65
    new-instance v0, Ltr0/e;

    .line 66
    .line 67
    const/16 v1, 0x15

    .line 68
    .line 69
    const/4 v5, 0x0

    .line 70
    move-object v2, p0

    .line 71
    move-object v3, p1

    .line 72
    invoke-direct/range {v0 .. v5}, Ltr0/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 73
    .line 74
    .line 75
    const/4 p0, 0x3

    .line 76
    iget-object p1, v2, Lvu/l;->u:Lvy0/b0;

    .line 77
    .line 78
    invoke-static {p1, v5, v5, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    new-instance p1, Lvu/f;

    .line 83
    .line 84
    new-instance v0, Lvu/d;

    .line 85
    .line 86
    const/4 v1, 0x0

    .line 87
    invoke-direct {v0, v1, p0, v6}, Lvu/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    invoke-direct {p1, v4, v0}, Lvu/f;-><init>(Lvu/e;Lvu/d;)V

    .line 91
    .line 92
    .line 93
    iget-object p0, v2, Lvu/l;->z:Ljava/util/LinkedHashMap;

    .line 94
    .line 95
    invoke-interface {p0, v3, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    return-object p1

    .line 99
    :cond_1
    new-instance p0, La8/r0;

    .line 100
    .line 101
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 102
    .line 103
    .line 104
    throw p0
.end method

.method public final h(Lw3/a;)Lsp/b;
    .locals 4

    .line 1
    iget-object p0, p0, Lvu/l;->y:Landroid/graphics/Canvas;

    .line 2
    .line 3
    invoke-virtual {p1, p0}, Landroid/view/View;->draw(Landroid/graphics/Canvas;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    instance-of v0, p0, Landroid/view/ViewGroup;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    check-cast p0, Landroid/view/ViewGroup;

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move-object p0, v1

    .line 19
    :goto_0
    if-nez p0, :cond_1

    .line 20
    .line 21
    sget-object p0, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 22
    .line 23
    const/16 p1, 0x14

    .line 24
    .line 25
    invoke-static {p1, p1, p0}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-static {p0}, Lkp/m8;->b(Landroid/graphics/Bitmap;)Lsp/b;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :cond_1
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    const/high16 v2, -0x80000000

    .line 39
    .line 40
    invoke-static {v0, v2}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    invoke-static {p0, v2}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    invoke-virtual {p1, v0, p0}, Landroid/view/View;->measure(II)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p1}, Landroid/view/View;->getMeasuredWidth()I

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    invoke-virtual {p1}, Landroid/view/View;->getMeasuredHeight()I

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    const/4 v2, 0x0

    .line 64
    invoke-virtual {p1, v2, v2, p0, v0}, Landroid/view/View;->layout(IIII)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {p1}, Landroid/view/View;->getMeasuredWidth()I

    .line 68
    .line 69
    .line 70
    move-result p0

    .line 71
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    if-lez p0, :cond_2

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_2
    move-object v0, v1

    .line 79
    :goto_1
    const/4 p0, 0x1

    .line 80
    if-eqz v0, :cond_3

    .line 81
    .line 82
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    goto :goto_2

    .line 87
    :cond_3
    move v0, p0

    .line 88
    :goto_2
    invoke-virtual {p1}, Landroid/view/View;->getMeasuredHeight()I

    .line 89
    .line 90
    .line 91
    move-result v2

    .line 92
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 93
    .line 94
    .line 95
    move-result-object v3

    .line 96
    if-lez v2, :cond_4

    .line 97
    .line 98
    move-object v1, v3

    .line 99
    :cond_4
    if-eqz v1, :cond_5

    .line 100
    .line 101
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 102
    .line 103
    .line 104
    move-result p0

    .line 105
    :cond_5
    sget-object v1, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 106
    .line 107
    invoke-static {v0, p0, v1}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    const-string v0, "createBitmap(...)"

    .line 112
    .line 113
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    new-instance v0, Landroid/graphics/Canvas;

    .line 117
    .line 118
    invoke-direct {v0, p0}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {p1, v0}, Landroid/view/View;->draw(Landroid/graphics/Canvas;)V

    .line 122
    .line 123
    .line 124
    invoke-static {p0}, Lkp/m8;->b(Landroid/graphics/Bitmap;)Lsp/b;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    return-object p0
.end method
