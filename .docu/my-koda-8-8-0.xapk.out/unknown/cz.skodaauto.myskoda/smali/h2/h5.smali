.class public final Lh2/h5;
.super Lv3/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/l;


# instance fields
.field public A:Lh2/eb;

.field public B:Lc1/c;

.field public C:Le3/n0;

.field public final D:Lc1/c;

.field public final E:Lb3/c;

.field public t:Z

.field public u:Z

.field public v:Li1/l;

.field public w:F

.field public x:F

.field public y:Z

.field public z:Lvy0/x1;


# direct methods
.method public constructor <init>(ZZLi1/l;Lh2/eb;Le3/n0;)V
    .locals 2

    .line 1
    sget v0, Lh2/hb;->e:F

    .line 2
    .line 3
    sget v1, Lh2/hb;->d:F

    .line 4
    .line 5
    invoke-direct {p0}, Lv3/n;-><init>()V

    .line 6
    .line 7
    .line 8
    iput-boolean p1, p0, Lh2/h5;->t:Z

    .line 9
    .line 10
    iput-boolean p2, p0, Lh2/h5;->u:Z

    .line 11
    .line 12
    iput-object p3, p0, Lh2/h5;->v:Li1/l;

    .line 13
    .line 14
    iput v0, p0, Lh2/h5;->w:F

    .line 15
    .line 16
    iput v1, p0, Lh2/h5;->x:F

    .line 17
    .line 18
    iput-object p4, p0, Lh2/h5;->A:Lh2/eb;

    .line 19
    .line 20
    iput-object p5, p0, Lh2/h5;->C:Le3/n0;

    .line 21
    .line 22
    new-instance p2, Lc1/c;

    .line 23
    .line 24
    iget-boolean p3, p0, Lh2/h5;->y:Z

    .line 25
    .line 26
    if-eqz p3, :cond_0

    .line 27
    .line 28
    if-eqz p1, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    move v0, v1

    .line 32
    :goto_0
    new-instance p1, Lt4/f;

    .line 33
    .line 34
    invoke-direct {p1, v0}, Lt4/f;-><init>(F)V

    .line 35
    .line 36
    .line 37
    sget-object p3, Lc1/d;->l:Lc1/b2;

    .line 38
    .line 39
    const/4 p4, 0x0

    .line 40
    const/16 p5, 0xc

    .line 41
    .line 42
    invoke-direct {p2, p1, p3, p4, p5}, Lc1/c;-><init>(Ljava/lang/Object;Lc1/b2;Ljava/lang/Object;I)V

    .line 43
    .line 44
    .line 45
    iput-object p2, p0, Lh2/h5;->D:Lc1/c;

    .line 46
    .line 47
    new-instance p1, Le81/w;

    .line 48
    .line 49
    const/16 p2, 0x10

    .line 50
    .line 51
    invoke-direct {p1, p0, p2}, Le81/w;-><init>(Ljava/lang/Object;I)V

    .line 52
    .line 53
    .line 54
    new-instance p2, Lb3/c;

    .line 55
    .line 56
    new-instance p3, Lb3/d;

    .line 57
    .line 58
    invoke-direct {p3}, Lb3/d;-><init>()V

    .line 59
    .line 60
    .line 61
    invoke-direct {p2, p3, p1}, Lb3/c;-><init>(Lb3/d;Lay0/k;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p0, p2}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    .line 65
    .line 66
    .line 67
    iput-object p2, p0, Lh2/h5;->E:Lb3/c;

    .line 68
    .line 69
    return-void
.end method

.method public static final a1(Lh2/h5;Lrx0/i;)Ljava/lang/Object;
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lh2/h5;->y:Z

    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iget-object v1, p0, Lh2/h5;->v:Li1/l;

    .line 10
    .line 11
    iget-object v1, v1, Li1/l;->a:Lyy0/q1;

    .line 12
    .line 13
    new-instance v2, Lai/k;

    .line 14
    .line 15
    const/16 v3, 0x17

    .line 16
    .line 17
    invoke-direct {v2, v3, v0, p0}, Lai/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, v2, p1}, Lyy0/q1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 24
    .line 25
    return-object p0
.end method


# virtual methods
.method public final M0()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final P0()V
    .locals 7

    .line 1
    invoke-virtual {p0}, Lx2/r;->L0()Lvy0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lh2/g5;

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    const/4 v3, 0x0

    .line 9
    invoke-direct {v1, p0, v3, v2}, Lh2/g5;-><init>(Lh2/h5;Lkotlin/coroutines/Continuation;I)V

    .line 10
    .line 11
    .line 12
    const/4 v2, 0x3

    .line 13
    invoke-static {v0, v3, v3, v1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    iput-object v0, p0, Lh2/h5;->z:Lvy0/x1;

    .line 18
    .line 19
    iget-object v0, p0, Lh2/h5;->B:Lc1/c;

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    iget-object v0, p0, Lh2/h5;->A:Lh2/eb;

    .line 24
    .line 25
    if-nez v0, :cond_0

    .line 26
    .line 27
    sget-object v0, Lh2/hb;->a:Lh2/hb;

    .line 28
    .line 29
    sget-object v0, Lh2/g1;->a:Ll2/u2;

    .line 30
    .line 31
    invoke-static {p0, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    check-cast v0, Lh2/f1;

    .line 36
    .line 37
    sget-object v1, Le2/e1;->a:Ll2/e0;

    .line 38
    .line 39
    invoke-static {p0, v1}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    check-cast v1, Le2/d1;

    .line 44
    .line 45
    invoke-static {v0, v1}, Lh2/hb;->f(Lh2/f1;Le2/d1;)Lh2/eb;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    :cond_0
    iget-boolean v1, p0, Lh2/h5;->t:Z

    .line 50
    .line 51
    iget-boolean v2, p0, Lh2/h5;->u:Z

    .line 52
    .line 53
    iget-boolean v4, p0, Lh2/h5;->y:Z

    .line 54
    .line 55
    invoke-virtual {v0, v1, v2, v4}, Lh2/eb;->c(ZZZ)J

    .line 56
    .line 57
    .line 58
    move-result-wide v0

    .line 59
    new-instance v2, Lc1/c;

    .line 60
    .line 61
    new-instance v4, Le3/s;

    .line 62
    .line 63
    invoke-direct {v4, v0, v1}, Le3/s;-><init>(J)V

    .line 64
    .line 65
    .line 66
    invoke-static {v0, v1}, Le3/s;->f(J)Lf3/c;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    sget-object v1, Lb1/c;->l:Lb1/c;

    .line 71
    .line 72
    new-instance v5, La3/f;

    .line 73
    .line 74
    const/4 v6, 0x7

    .line 75
    invoke-direct {v5, v0, v6}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 76
    .line 77
    .line 78
    new-instance v0, Lc1/b2;

    .line 79
    .line 80
    invoke-direct {v0, v1, v5}, Lc1/b2;-><init>(Lay0/k;Lay0/k;)V

    .line 81
    .line 82
    .line 83
    const/16 v1, 0xc

    .line 84
    .line 85
    invoke-direct {v2, v4, v0, v3, v1}, Lc1/c;-><init>(Ljava/lang/Object;Lc1/b2;Ljava/lang/Object;I)V

    .line 86
    .line 87
    .line 88
    iput-object v2, p0, Lh2/h5;->B:Lc1/c;

    .line 89
    .line 90
    :cond_1
    return-void
.end method

.method public final b1()V
    .locals 5

    .line 1
    invoke-virtual {p0}, Lx2/r;->L0()Lvy0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lh2/g5;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    invoke-direct {v1, p0, v3, v2}, Lh2/g5;-><init>(Lh2/h5;Lkotlin/coroutines/Continuation;I)V

    .line 10
    .line 11
    .line 12
    const/4 v2, 0x3

    .line 13
    invoke-static {v0, v3, v3, v1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0}, Lx2/r;->L0()Lvy0/b0;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    new-instance v1, Lh2/g5;

    .line 21
    .line 22
    const/4 v4, 0x1

    .line 23
    invoke-direct {v1, p0, v3, v4}, Lh2/g5;-><init>(Lh2/h5;Lkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    invoke-static {v0, v3, v3, v1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 27
    .line 28
    .line 29
    return-void
.end method
