.class public abstract Lza0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Leb/z;


# direct methods
.method static constructor <clinit>()V
    .locals 14

    .line 1
    new-instance v0, Leb/y;

    .line 2
    .line 3
    const-class v1, Lcz/skodaauto/myskoda/feature/widget/system/LocalWidgetWorker;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v2, v1}, Leb/y;-><init>(ILjava/lang/Class;)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lnb/d;

    .line 10
    .line 11
    sget-object v1, Leb/x;->d:Leb/x;

    .line 12
    .line 13
    new-instance v1, Ljava/util/LinkedHashSet;

    .line 14
    .line 15
    invoke-direct {v1}, Ljava/util/LinkedHashSet;-><init>()V

    .line 16
    .line 17
    .line 18
    sget-object v4, Leb/x;->e:Leb/x;

    .line 19
    .line 20
    new-instance v3, Lnb/d;

    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    invoke-direct {v3, v2}, Lnb/d;-><init>(Landroid/net/NetworkRequest;)V

    .line 24
    .line 25
    .line 26
    invoke-static {v1}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 27
    .line 28
    .line 29
    move-result-object v13

    .line 30
    new-instance v2, Leb/e;

    .line 31
    .line 32
    const/4 v5, 0x0

    .line 33
    const/4 v6, 0x0

    .line 34
    const/4 v7, 0x0

    .line 35
    const/4 v8, 0x0

    .line 36
    const-wide/16 v9, -0x1

    .line 37
    .line 38
    move-wide v11, v9

    .line 39
    invoke-direct/range {v2 .. v13}, Leb/e;-><init>(Lnb/d;Leb/x;ZZZZJJLjava/util/Set;)V

    .line 40
    .line 41
    .line 42
    iget-object v1, v0, Leb/j0;->f:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v1, Lmb/o;

    .line 45
    .line 46
    iput-object v2, v1, Lmb/o;->j:Leb/e;

    .line 47
    .line 48
    sget v1, Lmy0/c;->g:I

    .line 49
    .line 50
    sget-object v1, Lmy0/e;->h:Lmy0/e;

    .line 51
    .line 52
    const/16 v2, 0xa

    .line 53
    .line 54
    invoke-static {v2, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 55
    .line 56
    .line 57
    move-result-wide v2

    .line 58
    invoke-static {v2, v3, v1}, Lmy0/c;->n(JLmy0/e;)J

    .line 59
    .line 60
    .line 61
    move-result-wide v4

    .line 62
    invoke-static {v2, v3}, Lmy0/c;->f(J)I

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    int-to-long v1, v1

    .line 67
    invoke-static {v4, v5, v1, v2}, Ljava/time/Duration;->ofSeconds(JJ)Ljava/time/Duration;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    const-string v2, "toComponents-impl(...)"

    .line 72
    .line 73
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    iget-object v2, v0, Leb/j0;->f:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v2, Lmb/o;

    .line 79
    .line 80
    invoke-virtual {v1}, Ljava/time/Duration;->toMillis()J

    .line 81
    .line 82
    .line 83
    move-result-wide v3

    .line 84
    iput-wide v3, v2, Lmb/o;->o:J

    .line 85
    .line 86
    invoke-virtual {v0}, Leb/j0;->h()Leb/k0;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    check-cast v0, Leb/z;

    .line 91
    .line 92
    sput-object v0, Lza0/d;->a:Leb/z;

    .line 93
    .line 94
    return-void
.end method
