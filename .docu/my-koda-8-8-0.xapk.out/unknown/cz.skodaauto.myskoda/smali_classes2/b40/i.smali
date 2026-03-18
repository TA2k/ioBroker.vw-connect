.class public final Lb40/i;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lij0/a;

.field public final i:Lz30/f;

.field public final j:Lkc0/i0;


# direct methods
.method public constructor <init>(Lij0/a;Lz30/f;Lkc0/i0;)V
    .locals 2

    .line 1
    new-instance v0, Lb40/h;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lb40/h;-><init>(Lql0/g;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lb40/i;->h:Lij0/a;

    .line 11
    .line 12
    iput-object p2, p0, Lb40/i;->i:Lz30/f;

    .line 13
    .line 14
    iput-object p3, p0, Lb40/i;->j:Lkc0/i0;

    .line 15
    .line 16
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    new-instance p2, La10/a;

    .line 21
    .line 22
    const/4 p3, 0x3

    .line 23
    invoke-direct {p2, p0, v1, p3}, La10/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    const/4 p0, 0x3

    .line 27
    invoke-static {p1, v1, v1, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 28
    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final h()V
    .locals 10

    .line 1
    iget-object v0, p0, Lb40/i;->j:Lkc0/i0;

    .line 2
    .line 3
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Lne0/c;

    .line 9
    .line 10
    if-eqz v1, :cond_1

    .line 11
    .line 12
    iget-object v0, v1, Lne0/c;->a:Ljava/lang/Throwable;

    .line 13
    .line 14
    instance-of v0, v0, Llc0/i;

    .line 15
    .line 16
    iget-object v2, p0, Lb40/i;->h:Lij0/a;

    .line 17
    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    invoke-static {v1, v2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v0, 0x0

    .line 26
    new-array v3, v0, [Ljava/lang/Object;

    .line 27
    .line 28
    move-object v4, v2

    .line 29
    iget-object v2, p0, Lb40/i;->h:Lij0/a;

    .line 30
    .line 31
    move-object v5, v2

    .line 32
    check-cast v5, Ljj0/f;

    .line 33
    .line 34
    const v6, 0x7f1202b8

    .line 35
    .line 36
    .line 37
    invoke-virtual {v5, v6, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    new-array v5, v0, [Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v4, Ljj0/f;

    .line 44
    .line 45
    const v6, 0x7f1202b7

    .line 46
    .line 47
    .line 48
    invoke-virtual {v4, v6, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v5

    .line 52
    const v6, 0x7f12038c

    .line 53
    .line 54
    .line 55
    new-array v0, v0, [Ljava/lang/Object;

    .line 56
    .line 57
    invoke-virtual {v4, v6, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    const/4 v8, 0x0

    .line 62
    const/16 v9, 0x70

    .line 63
    .line 64
    const/4 v6, 0x0

    .line 65
    const/4 v7, 0x0

    .line 66
    move-object v4, v5

    .line 67
    move-object v5, v0

    .line 68
    invoke-static/range {v1 .. v9}, Ljp/rf;->d(Lne0/c;Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLql0/f;I)Lql0/g;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    :goto_0
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    check-cast v1, Lb40/h;

    .line 77
    .line 78
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 79
    .line 80
    .line 81
    new-instance v1, Lb40/h;

    .line 82
    .line 83
    invoke-direct {v1, v0}, Lb40/h;-><init>(Lql0/g;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 87
    .line 88
    .line 89
    return-void

    .line 90
    :cond_1
    iget-object p0, p0, Lb40/i;->i:Lz30/f;

    .line 91
    .line 92
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    return-void
.end method
