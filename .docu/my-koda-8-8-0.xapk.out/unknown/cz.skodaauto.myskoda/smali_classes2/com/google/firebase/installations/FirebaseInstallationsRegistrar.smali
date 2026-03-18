.class public Lcom/google/firebase/installations/FirebaseInstallationsRegistrar;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/firebase/components/ComponentRegistrar;


# annotations
.annotation build Landroidx/annotation/Keep;
.end annotation


# static fields
.field private static final LIBRARY_NAME:Ljava/lang/String; = "fire-installations"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a(Lin/z1;)Lht/d;
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/google/firebase/installations/FirebaseInstallationsRegistrar;->lambda$getComponents$0(Lgs/c;)Lht/d;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static lambda$getComponents$0(Lgs/c;)Lht/d;
    .locals 7

    .line 1
    new-instance v0, Lht/c;

    .line 2
    .line 3
    const-class v1, Lsr/f;

    .line 4
    .line 5
    invoke-interface {p0, v1}, Lgs/c;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    check-cast v1, Lsr/f;

    .line 10
    .line 11
    const-class v2, Let/e;

    .line 12
    .line 13
    invoke-interface {p0, v2}, Lgs/c;->f(Ljava/lang/Class;)Lgt/b;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    new-instance v3, Lgs/s;

    .line 18
    .line 19
    const-class v4, Lyr/a;

    .line 20
    .line 21
    const-class v5, Ljava/util/concurrent/ExecutorService;

    .line 22
    .line 23
    invoke-direct {v3, v4, v5}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 24
    .line 25
    .line 26
    invoke-interface {p0, v3}, Lgs/c;->b(Lgs/s;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    check-cast v3, Ljava/util/concurrent/ExecutorService;

    .line 31
    .line 32
    new-instance v4, Lgs/s;

    .line 33
    .line 34
    const-class v5, Lyr/b;

    .line 35
    .line 36
    const-class v6, Ljava/util/concurrent/Executor;

    .line 37
    .line 38
    invoke-direct {v4, v5, v6}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 39
    .line 40
    .line 41
    invoke-interface {p0, v4}, Lgs/c;->b(Lgs/s;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    check-cast p0, Ljava/util/concurrent/Executor;

    .line 46
    .line 47
    new-instance v4, Lhs/k;

    .line 48
    .line 49
    invoke-direct {v4, p0}, Lhs/k;-><init>(Ljava/util/concurrent/Executor;)V

    .line 50
    .line 51
    .line 52
    invoke-direct {v0, v1, v2, v3, v4}, Lht/c;-><init>(Lsr/f;Lgt/b;Ljava/util/concurrent/ExecutorService;Lhs/k;)V

    .line 53
    .line 54
    .line 55
    return-object v0
.end method


# virtual methods
.method public getComponents()Ljava/util/List;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lgs/b;",
            ">;"
        }
    .end annotation

    .line 1
    const-class p0, Lht/d;

    .line 2
    .line 3
    invoke-static {p0}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "fire-installations"

    .line 8
    .line 9
    iput-object v0, p0, Lgs/a;->a:Ljava/lang/String;

    .line 10
    .line 11
    const-class v1, Lsr/f;

    .line 12
    .line 13
    invoke-static {v1}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-virtual {p0, v1}, Lgs/a;->a(Lgs/k;)V

    .line 18
    .line 19
    .line 20
    const-class v1, Let/e;

    .line 21
    .line 22
    invoke-static {v1}, Lgs/k;->a(Ljava/lang/Class;)Lgs/k;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-virtual {p0, v1}, Lgs/a;->a(Lgs/k;)V

    .line 27
    .line 28
    .line 29
    new-instance v1, Lgs/s;

    .line 30
    .line 31
    const-class v2, Lyr/a;

    .line 32
    .line 33
    const-class v3, Ljava/util/concurrent/ExecutorService;

    .line 34
    .line 35
    invoke-direct {v1, v2, v3}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 36
    .line 37
    .line 38
    new-instance v2, Lgs/k;

    .line 39
    .line 40
    const/4 v3, 0x1

    .line 41
    const/4 v4, 0x0

    .line 42
    invoke-direct {v2, v1, v3, v4}, Lgs/k;-><init>(Lgs/s;II)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0, v2}, Lgs/a;->a(Lgs/k;)V

    .line 46
    .line 47
    .line 48
    new-instance v1, Lgs/s;

    .line 49
    .line 50
    const-class v2, Lyr/b;

    .line 51
    .line 52
    const-class v5, Ljava/util/concurrent/Executor;

    .line 53
    .line 54
    invoke-direct {v1, v2, v5}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 55
    .line 56
    .line 57
    new-instance v2, Lgs/k;

    .line 58
    .line 59
    invoke-direct {v2, v1, v3, v4}, Lgs/k;-><init>(Lgs/s;II)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p0, v2}, Lgs/a;->a(Lgs/k;)V

    .line 63
    .line 64
    .line 65
    new-instance v1, Lf3/d;

    .line 66
    .line 67
    const/16 v2, 0x12

    .line 68
    .line 69
    invoke-direct {v1, v2}, Lf3/d;-><init>(I)V

    .line 70
    .line 71
    .line 72
    iput-object v1, p0, Lgs/a;->f:Lgs/e;

    .line 73
    .line 74
    invoke-virtual {p0}, Lgs/a;->b()Lgs/b;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    new-instance v1, Let/d;

    .line 79
    .line 80
    const/4 v2, 0x0

    .line 81
    invoke-direct {v1, v2}, Let/d;-><init>(I)V

    .line 82
    .line 83
    .line 84
    const-class v2, Let/d;

    .line 85
    .line 86
    invoke-static {v2}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 87
    .line 88
    .line 89
    move-result-object v2

    .line 90
    iput v3, v2, Lgs/a;->e:I

    .line 91
    .line 92
    new-instance v3, Lb8/c;

    .line 93
    .line 94
    invoke-direct {v3, v1}, Lb8/c;-><init>(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    iput-object v3, v2, Lgs/a;->f:Lgs/e;

    .line 98
    .line 99
    invoke-virtual {v2}, Lgs/a;->b()Lgs/b;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    const-string v2, "19.0.1"

    .line 104
    .line 105
    invoke-static {v0, v2}, Ljp/gb;->a(Ljava/lang/String;Ljava/lang/String;)Lgs/b;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    filled-new-array {p0, v1, v0}, [Lgs/b;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    invoke-static {p0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    return-object p0
.end method
