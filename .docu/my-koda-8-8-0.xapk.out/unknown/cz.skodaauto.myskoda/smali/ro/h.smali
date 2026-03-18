.class public final Lro/h;
.super Lko/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final n:Lc2/k;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lko/d;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lbp/l;

    .line 7
    .line 8
    const/4 v2, 0x5

    .line 9
    invoke-direct {v1, v2}, Lbp/l;-><init>(I)V

    .line 10
    .line 11
    .line 12
    new-instance v2, Lc2/k;

    .line 13
    .line 14
    const-string v3, "ModuleInstall.API"

    .line 15
    .line 16
    invoke-direct {v2, v3, v1, v0}, Lc2/k;-><init>(Ljava/lang/String;Llp/wd;Lko/d;)V

    .line 17
    .line 18
    .line 19
    sput-object v2, Lro/h;->n:Lc2/k;

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final varargs f([Lko/m;)Laq/t;
    .locals 6

    .line 1
    array-length v0, p1

    .line 2
    const/4 v1, 0x0

    .line 3
    const/4 v2, 0x1

    .line 4
    if-lez v0, :cond_0

    .line 5
    .line 6
    move v3, v2

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    move v3, v1

    .line 9
    :goto_0
    const-string v4, "Please provide at least one OptionalModuleApi."

    .line 10
    .line 11
    invoke-static {v3, v4}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 12
    .line 13
    .line 14
    move v3, v1

    .line 15
    :goto_1
    if-ge v3, v0, :cond_1

    .line 16
    .line 17
    aget-object v4, p1, v3

    .line 18
    .line 19
    const-string v5, "Requested API must not be null."

    .line 20
    .line 21
    invoke-static {v4, v5}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    add-int/lit8 v3, v3, 0x1

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    invoke-static {p1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    invoke-static {p1, v1}, Lro/a;->x0(Ljava/util/List;Z)Lro/a;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    iget-object v0, p1, Lro/a;->d:Ljava/util/List;

    .line 36
    .line 37
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-eqz v0, :cond_2

    .line 42
    .line 43
    new-instance p0, Lqo/a;

    .line 44
    .line 45
    invoke-direct {p0, v1, v2}, Lqo/a;-><init>(IZ)V

    .line 46
    .line 47
    .line 48
    invoke-static {p0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0

    .line 53
    :cond_2
    invoke-static {}, Lhr/b0;->e()Lh6/i;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    sget-object v2, Lcp/b;->c:Ljo/d;

    .line 58
    .line 59
    filled-new-array {v2}, [Ljo/d;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    iput-object v2, v0, Lh6/i;->e:Ljava/lang/Object;

    .line 64
    .line 65
    const/16 v2, 0x6aa5

    .line 66
    .line 67
    iput v2, v0, Lh6/i;->b:I

    .line 68
    .line 69
    iput-boolean v1, v0, Lh6/i;->c:Z

    .line 70
    .line 71
    new-instance v2, Lro/f;

    .line 72
    .line 73
    invoke-direct {v2, p0, p1}, Lro/f;-><init>(Lro/h;Lro/a;)V

    .line 74
    .line 75
    .line 76
    iput-object v2, v0, Lh6/i;->d:Ljava/lang/Object;

    .line 77
    .line 78
    invoke-virtual {v0}, Lh6/i;->a()Lbp/s;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    invoke-virtual {p0, v1, p1}, Lko/i;->e(ILhr/b0;)Laq/t;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    return-object p0
.end method
