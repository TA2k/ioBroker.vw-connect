.class public final Lla/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lla/u;

.field public final b:Lla/l0;

.field public final c:Ljava/util/LinkedHashMap;

.field public final d:Ljava/util/concurrent/locks/ReentrantLock;

.field public final e:Lla/g;

.field public final f:Lla/g;

.field public final g:Ljava/lang/Object;


# direct methods
.method public varargs constructor <init>(Lla/u;Ljava/util/LinkedHashMap;Ljava/util/LinkedHashMap;[Ljava/lang/String;)V
    .locals 10

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lla/h;->a:Lla/u;

    .line 5
    .line 6
    new-instance v8, Lla/l0;

    .line 7
    .line 8
    iget-boolean v9, p1, Lla/u;->k:Z

    .line 9
    .line 10
    new-instance v0, Ll20/g;

    .line 11
    .line 12
    const/4 v6, 0x0

    .line 13
    const/4 v7, 0x5

    .line 14
    const/4 v1, 0x1

    .line 15
    const-class v3, Lla/h;

    .line 16
    .line 17
    const-string v4, "notifyInvalidatedObservers"

    .line 18
    .line 19
    const-string v5, "notifyInvalidatedObservers(Ljava/util/Set;)V"

    .line 20
    .line 21
    move-object v2, p0

    .line 22
    invoke-direct/range {v0 .. v7}, Ll20/g;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 23
    .line 24
    .line 25
    move-object v1, p1

    .line 26
    move-object v2, p2

    .line 27
    move-object v3, p3

    .line 28
    move-object v4, p4

    .line 29
    move-object v6, v0

    .line 30
    move-object v0, v8

    .line 31
    move v5, v9

    .line 32
    invoke-direct/range {v0 .. v6}, Lla/l0;-><init>(Lla/u;Ljava/util/LinkedHashMap;Ljava/util/LinkedHashMap;[Ljava/lang/String;ZLl20/g;)V

    .line 33
    .line 34
    .line 35
    iput-object v0, p0, Lla/h;->b:Lla/l0;

    .line 36
    .line 37
    new-instance v1, Ljava/util/LinkedHashMap;

    .line 38
    .line 39
    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 40
    .line 41
    .line 42
    iput-object v1, p0, Lla/h;->c:Ljava/util/LinkedHashMap;

    .line 43
    .line 44
    new-instance v1, Ljava/util/concurrent/locks/ReentrantLock;

    .line 45
    .line 46
    invoke-direct {v1}, Ljava/util/concurrent/locks/ReentrantLock;-><init>()V

    .line 47
    .line 48
    .line 49
    iput-object v1, p0, Lla/h;->d:Ljava/util/concurrent/locks/ReentrantLock;

    .line 50
    .line 51
    new-instance v1, Lla/g;

    .line 52
    .line 53
    const/4 v2, 0x0

    .line 54
    invoke-direct {v1, p0, v2}, Lla/g;-><init>(Lla/h;I)V

    .line 55
    .line 56
    .line 57
    iput-object v1, p0, Lla/h;->e:Lla/g;

    .line 58
    .line 59
    new-instance v1, Lla/g;

    .line 60
    .line 61
    const/4 v2, 0x1

    .line 62
    invoke-direct {v1, p0, v2}, Lla/g;-><init>(Lla/h;I)V

    .line 63
    .line 64
    .line 65
    iput-object v1, p0, Lla/h;->f:Lla/g;

    .line 66
    .line 67
    new-instance v1, Ljava/util/IdentityHashMap;

    .line 68
    .line 69
    invoke-direct {v1}, Ljava/util/IdentityHashMap;-><init>()V

    .line 70
    .line 71
    .line 72
    invoke-static {v1}, Ljava/util/Collections;->newSetFromMap(Ljava/util/Map;)Ljava/util/Set;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    const-string v2, "newSetFromMap(...)"

    .line 77
    .line 78
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    new-instance v1, Ljava/lang/Object;

    .line 82
    .line 83
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 84
    .line 85
    .line 86
    iput-object v1, p0, Lla/h;->g:Ljava/lang/Object;

    .line 87
    .line 88
    new-instance v1, Lla/g;

    .line 89
    .line 90
    const/4 v2, 0x2

    .line 91
    invoke-direct {v1, p0, v2}, Lla/g;-><init>(Lla/h;I)V

    .line 92
    .line 93
    .line 94
    iput-object v1, v0, Lla/l0;->k:Lay0/a;

    .line 95
    .line 96
    return-void
.end method


# virtual methods
.method public final a(Lrx0/i;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lla/h;->b:Lla/l0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lla/l0;->f(Lrx0/c;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    if-ne p0, p1, :cond_0

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    return-object p0
.end method
