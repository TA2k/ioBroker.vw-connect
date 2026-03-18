.class public final La7/f1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final g:La7/a0;


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Ljava/util/LinkedHashMap;

.field public c:I

.field public final d:I

.field public final e:Ljava/util/LinkedHashSet;

.field public final f:Ljava/util/Set;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, La7/a0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, La7/f1;->g:La7/a0;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/util/LinkedHashMap;IILjava/util/Set;)V
    .locals 1

    .line 1
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, La7/f1;->a:Landroid/content/Context;

    .line 10
    .line 11
    iput-object p2, p0, La7/f1;->b:Ljava/util/LinkedHashMap;

    .line 12
    .line 13
    iput p3, p0, La7/f1;->c:I

    .line 14
    .line 15
    iput p4, p0, La7/f1;->d:I

    .line 16
    .line 17
    iput-object v0, p0, La7/f1;->e:Ljava/util/LinkedHashSet;

    .line 18
    .line 19
    iput-object p5, p0, La7/f1;->f:Ljava/util/Set;

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final a(Ly6/n;)I
    .locals 3

    .line 1
    invoke-static {p1}, Ljb0/b;->b(Ly6/l;)Lc7/i;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    monitor-enter p0

    .line 6
    :try_start_0
    iget-object v0, p0, La7/f1;->b:Ljava/util/LinkedHashMap;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Ljava/lang/Integer;

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iget-object v1, p0, La7/f1;->e:Ljava/util/LinkedHashSet;

    .line 25
    .line 26
    invoke-interface {v1, v0}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    .line 28
    .line 29
    monitor-exit p0

    .line 30
    return p1

    .line 31
    :catchall_0
    move-exception p1

    .line 32
    goto :goto_1

    .line 33
    :cond_0
    :try_start_1
    iget v0, p0, La7/f1;->c:I

    .line 34
    .line 35
    :goto_0
    iget-object v1, p0, La7/f1;->f:Ljava/util/Set;

    .line 36
    .line 37
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    invoke-interface {v1, v2}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    if-eqz v1, :cond_2

    .line 46
    .line 47
    add-int/lit8 v0, v0, 0x1

    .line 48
    .line 49
    sget v1, La7/j1;->c:I

    .line 50
    .line 51
    rem-int/2addr v0, v1

    .line 52
    iget v1, p0, La7/f1;->c:I

    .line 53
    .line 54
    if-eq v0, v1, :cond_1

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_1
    const-string p1, "Cannot assign a valid layout index to the new layout: no free index left."

    .line 58
    .line 59
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 60
    .line 61
    invoke-direct {v0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :cond_2
    add-int/lit8 v1, v0, 0x1

    .line 66
    .line 67
    sget v2, La7/j1;->c:I

    .line 68
    .line 69
    rem-int/2addr v1, v2

    .line 70
    iput v1, p0, La7/f1;->c:I

    .line 71
    .line 72
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    iget-object v2, p0, La7/f1;->e:Ljava/util/LinkedHashSet;

    .line 77
    .line 78
    invoke-interface {v2, v1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    iget-object v2, p0, La7/f1;->f:Ljava/util/Set;

    .line 86
    .line 87
    check-cast v2, Ljava/util/Collection;

    .line 88
    .line 89
    invoke-interface {v2, v1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    iget-object v2, p0, La7/f1;->b:Ljava/util/LinkedHashMap;

    .line 97
    .line 98
    invoke-interface {v2, p1, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 99
    .line 100
    .line 101
    monitor-exit p0

    .line 102
    return v0

    .line 103
    :goto_1
    monitor-exit p0

    .line 104
    throw p1
.end method

.method public final b(La7/h;)Ljava/lang/Object;
    .locals 6

    .line 1
    sget-object v0, Li7/f;->a:Li7/f;

    .line 2
    .line 3
    iget v1, p0, La7/f1;->d:I

    .line 4
    .line 5
    const-string v2, "appWidgetLayout-"

    .line 6
    .line 7
    invoke-static {v1, v2}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    new-instance v4, La60/f;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    const/4 v2, 0x2

    .line 15
    invoke-direct {v4, p0, v1, v2}, La60/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, La7/f1;->a:Landroid/content/Context;

    .line 19
    .line 20
    sget-object v2, La7/l1;->a:La7/l1;

    .line 21
    .line 22
    move-object v5, p1

    .line 23
    invoke-virtual/range {v0 .. v5}, Li7/f;->d(Landroid/content/Context;La7/l1;Ljava/lang/String;La60/f;Lrx0/c;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    if-ne p0, p1, :cond_0

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0
.end method
