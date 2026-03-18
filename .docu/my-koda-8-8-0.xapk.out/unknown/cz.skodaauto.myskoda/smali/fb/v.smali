.class public final synthetic Lfb/v;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/r;


# static fields
.field public static final d:Lfb/v;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lfb/v;

    .line 2
    .line 3
    const-string v4, "createSchedulers(Landroid/content/Context;Landroidx/work/Configuration;Landroidx/work/impl/utils/taskexecutor/TaskExecutor;Landroidx/work/impl/WorkDatabase;Landroidx/work/impl/constraints/trackers/Trackers;Landroidx/work/impl/Processor;)Ljava/util/List;"

    .line 4
    .line 5
    const/4 v5, 0x1

    .line 6
    const/4 v1, 0x6

    .line 7
    const-class v2, Lfb/w;

    .line 8
    .line 9
    const-string v3, "createSchedulers"

    .line 10
    .line 11
    invoke-direct/range {v0 .. v5}, Lkotlin/jvm/internal/k;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lfb/v;->d:Lfb/v;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Landroid/content/Context;

    .line 2
    .line 3
    check-cast p2, Leb/b;

    .line 4
    .line 5
    check-cast p3, Lob/a;

    .line 6
    .line 7
    check-cast p4, Landroidx/work/impl/WorkDatabase;

    .line 8
    .line 9
    check-cast p5, Lkb/i;

    .line 10
    .line 11
    check-cast p6, Lfb/e;

    .line 12
    .line 13
    const-string p0, "p0"

    .line 14
    .line 15
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    const-string p0, "p1"

    .line 19
    .line 20
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    const-string p0, "p2"

    .line 24
    .line 25
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const-string p0, "p3"

    .line 29
    .line 30
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    const-string p0, "p4"

    .line 34
    .line 35
    invoke-static {p5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    sget-object p0, Lfb/i;->a:Ljava/lang/String;

    .line 39
    .line 40
    new-instance v0, Lhb/c;

    .line 41
    .line 42
    invoke-direct {v0, p1, p4, p2}, Lhb/c;-><init>(Landroid/content/Context;Landroidx/work/impl/WorkDatabase;Leb/b;)V

    .line 43
    .line 44
    .line 45
    const-class p0, Landroidx/work/impl/background/systemjob/SystemJobService;

    .line 46
    .line 47
    const/4 v1, 0x1

    .line 48
    invoke-static {p1, p0, v1}, Lnb/f;->a(Landroid/content/Context;Ljava/lang/Class;Z)V

    .line 49
    .line 50
    .line 51
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    sget-object p4, Lfb/i;->a:Ljava/lang/String;

    .line 56
    .line 57
    const-string v2, "Created SystemJobScheduler and enabled SystemJobService"

    .line 58
    .line 59
    invoke-virtual {p0, p4, v2}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    new-instance p0, Lgb/c;

    .line 63
    .line 64
    move-object p4, p6

    .line 65
    move-object p6, p3

    .line 66
    move-object p3, p5

    .line 67
    new-instance p5, Lb81/b;

    .line 68
    .line 69
    invoke-direct {p5, p4, p6}, Lb81/b;-><init>(Lfb/e;Lob/a;)V

    .line 70
    .line 71
    .line 72
    invoke-direct/range {p0 .. p6}, Lgb/c;-><init>(Landroid/content/Context;Leb/b;Lkb/i;Lfb/e;Lb81/b;Lob/a;)V

    .line 73
    .line 74
    .line 75
    const/4 p1, 0x2

    .line 76
    new-array p1, p1, [Lfb/g;

    .line 77
    .line 78
    const/4 p2, 0x0

    .line 79
    aput-object v0, p1, p2

    .line 80
    .line 81
    aput-object p0, p1, v1

    .line 82
    .line 83
    invoke-static {p1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0
.end method
