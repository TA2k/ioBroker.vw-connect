.class public final Lo1/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lay0/k;

.field public final b:Lil/g;

.field public c:La8/b;

.field public d:I

.field public e:I

.field public f:I


# direct methods
.method public constructor <init>(Lay0/k;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lil/g;

    .line 5
    .line 6
    const/16 v1, 0x13

    .line 7
    .line 8
    invoke-direct {v0, v1}, Lil/g;-><init>(I)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Lo1/l0;->b:Lil/g;

    .line 12
    .line 13
    const/4 v0, -0x1

    .line 14
    iput v0, p0, Lo1/l0;->d:I

    .line 15
    .line 16
    iput v0, p0, Lo1/l0;->e:I

    .line 17
    .line 18
    iput-object p1, p0, Lo1/l0;->a:Lay0/k;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final a(IJZLay0/k;)Lo1/k0;
    .locals 4

    .line 1
    iget-object v0, p0, Lo1/l0;->c:La8/b;

    .line 2
    .line 3
    if-eqz v0, :cond_3

    .line 4
    .line 5
    new-instance v1, Lo1/y0;

    .line 6
    .line 7
    iget-object v2, v0, La8/b;->h:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v2, Lo1/z0;

    .line 10
    .line 11
    instance-of v3, v2, Lo1/a;

    .line 12
    .line 13
    iget-object p0, p0, Lo1/l0;->b:Lil/g;

    .line 14
    .line 15
    invoke-direct {v1, v0, p1, p0, p5}, Lo1/y0;-><init>(La8/b;ILil/g;Lay0/k;)V

    .line 16
    .line 17
    .line 18
    new-instance p0, Lt4/a;

    .line 19
    .line 20
    invoke-direct {p0, p2, p3}, Lt4/a;-><init>(J)V

    .line 21
    .line 22
    .line 23
    iput-object p0, v1, Lo1/y0;->d:Lt4/a;

    .line 24
    .line 25
    if-eqz v3, :cond_1

    .line 26
    .line 27
    const/4 p0, 0x1

    .line 28
    if-eqz p4, :cond_0

    .line 29
    .line 30
    check-cast v2, Lo1/a;

    .line 31
    .line 32
    iget-object p2, v2, Lo1/a;->e:Ljava/util/PriorityQueue;

    .line 33
    .line 34
    new-instance p3, Lo1/c1;

    .line 35
    .line 36
    invoke-direct {p3, p0, v1}, Lo1/c1;-><init>(ILo1/y0;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p2, p3}, Ljava/util/PriorityQueue;->add(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    iget-boolean p2, v2, Lo1/a;->f:Z

    .line 43
    .line 44
    if-nez p2, :cond_2

    .line 45
    .line 46
    iput-boolean p0, v2, Lo1/a;->f:Z

    .line 47
    .line 48
    iget-object p0, v2, Lo1/a;->d:Landroid/view/View;

    .line 49
    .line 50
    invoke-virtual {p0, v2}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    check-cast v2, Lo1/a;

    .line 55
    .line 56
    iget-object p2, v2, Lo1/a;->e:Ljava/util/PriorityQueue;

    .line 57
    .line 58
    new-instance p3, Lo1/c1;

    .line 59
    .line 60
    const/4 p4, 0x0

    .line 61
    invoke-direct {p3, p4, v1}, Lo1/c1;-><init>(ILo1/y0;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p2, p3}, Ljava/util/PriorityQueue;->add(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    iget-boolean p2, v2, Lo1/a;->f:Z

    .line 68
    .line 69
    if-nez p2, :cond_2

    .line 70
    .line 71
    iput-boolean p0, v2, Lo1/a;->f:Z

    .line 72
    .line 73
    iget-object p0, v2, Lo1/a;->d:Landroid/view/View;

    .line 74
    .line 75
    invoke-virtual {p0, v2}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 76
    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_1
    invoke-interface {v2, v1}, Lo1/z0;->a(Lo1/y0;)V

    .line 80
    .line 81
    .line 82
    :cond_2
    :goto_0
    const-string p0, "compose:lazy:schedule_prefetch:index"

    .line 83
    .line 84
    int-to-long p1, p1

    .line 85
    invoke-static {p0, p1, p2}, Landroid/os/Trace;->setCounter(Ljava/lang/String;J)V

    .line 86
    .line 87
    .line 88
    return-object v1

    .line 89
    :cond_3
    sget-object p0, Lo1/g;->a:Lo1/g;

    .line 90
    .line 91
    return-object p0
.end method
