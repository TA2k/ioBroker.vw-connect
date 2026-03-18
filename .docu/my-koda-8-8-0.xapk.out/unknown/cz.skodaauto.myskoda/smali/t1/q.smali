.class public final synthetic Lt1/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Lt1/p0;

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Ll4/w;

.field public final synthetic h:Ll4/v;

.field public final synthetic i:Ll4/j;

.field public final synthetic j:Ll4/p;

.field public final synthetic k:Le2/w0;

.field public final synthetic l:Lvy0/b0;

.field public final synthetic m:Lq1/b;


# direct methods
.method public synthetic constructor <init>(Lt1/p0;ZZLl4/w;Ll4/v;Ll4/j;Ll4/p;Le2/w0;Lvy0/b0;Lq1/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt1/q;->d:Lt1/p0;

    .line 5
    .line 6
    iput-boolean p2, p0, Lt1/q;->e:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Lt1/q;->f:Z

    .line 9
    .line 10
    iput-object p4, p0, Lt1/q;->g:Ll4/w;

    .line 11
    .line 12
    iput-object p5, p0, Lt1/q;->h:Ll4/v;

    .line 13
    .line 14
    iput-object p6, p0, Lt1/q;->i:Ll4/j;

    .line 15
    .line 16
    iput-object p7, p0, Lt1/q;->j:Ll4/p;

    .line 17
    .line 18
    iput-object p8, p0, Lt1/q;->k:Le2/w0;

    .line 19
    .line 20
    iput-object p9, p0, Lt1/q;->l:Lvy0/b0;

    .line 21
    .line 22
    iput-object p10, p0, Lt1/q;->m:Lq1/b;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    check-cast p1, Lc3/t;

    .line 2
    .line 3
    iget-object v3, p0, Lt1/q;->d:Lt1/p0;

    .line 4
    .line 5
    invoke-virtual {v3}, Lt1/p0;->b()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    check-cast p1, Lc3/u;

    .line 10
    .line 11
    invoke-virtual {p1}, Lc3/u;->b()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-ne v0, v1, :cond_0

    .line 16
    .line 17
    goto :goto_1

    .line 18
    :cond_0
    invoke-virtual {p1}, Lc3/u;->b()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v1, v3, Lt1/p0;->f:Ll2/j1;

    .line 23
    .line 24
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-virtual {v1, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v3}, Lt1/p0;->b()Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    iget-object v2, p0, Lt1/q;->h:Ll4/v;

    .line 36
    .line 37
    iget-object v5, p0, Lt1/q;->j:Ll4/p;

    .line 38
    .line 39
    if-eqz v0, :cond_1

    .line 40
    .line 41
    iget-boolean v0, p0, Lt1/q;->e:Z

    .line 42
    .line 43
    if-eqz v0, :cond_1

    .line 44
    .line 45
    iget-boolean v0, p0, Lt1/q;->f:Z

    .line 46
    .line 47
    if-nez v0, :cond_1

    .line 48
    .line 49
    iget-object v0, p0, Lt1/q;->g:Ll4/w;

    .line 50
    .line 51
    iget-object v1, p0, Lt1/q;->i:Ll4/j;

    .line 52
    .line 53
    invoke-static {v0, v3, v2, v1, v5}, Lt1/l0;->x(Ll4/w;Lt1/p0;Ll4/v;Ll4/j;Ll4/p;)V

    .line 54
    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_1
    invoke-static {v3}, Lt1/l0;->p(Lt1/p0;)V

    .line 58
    .line 59
    .line 60
    :goto_0
    invoke-virtual {p1}, Lc3/u;->b()Z

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    const/4 v8, 0x0

    .line 65
    if-eqz v0, :cond_2

    .line 66
    .line 67
    invoke-virtual {v3}, Lt1/p0;->d()Lt1/j1;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    if-eqz v4, :cond_2

    .line 72
    .line 73
    new-instance v0, Laa/i0;

    .line 74
    .line 75
    const/4 v6, 0x0

    .line 76
    const/16 v7, 0x14

    .line 77
    .line 78
    iget-object v1, p0, Lt1/q;->m:Lq1/b;

    .line 79
    .line 80
    invoke-direct/range {v0 .. v7}, Laa/i0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 81
    .line 82
    .line 83
    const/4 v1, 0x3

    .line 84
    iget-object v2, p0, Lt1/q;->l:Lvy0/b0;

    .line 85
    .line 86
    invoke-static {v2, v8, v8, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 87
    .line 88
    .line 89
    :cond_2
    invoke-virtual {p1}, Lc3/u;->b()Z

    .line 90
    .line 91
    .line 92
    move-result p1

    .line 93
    if-nez p1, :cond_3

    .line 94
    .line 95
    iget-object p0, p0, Lt1/q;->k:Le2/w0;

    .line 96
    .line 97
    invoke-virtual {p0, v8}, Le2/w0;->g(Ld3/b;)V

    .line 98
    .line 99
    .line 100
    :cond_3
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 101
    .line 102
    return-object p0
.end method
