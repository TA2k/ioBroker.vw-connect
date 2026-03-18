.class public final Lo1/u0;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/x1;


# instance fields
.field public r:Lay0/a;

.field public s:Lo1/r0;

.field public t:Lg1/w1;

.field public u:Z

.field public v:Z

.field public w:Ld4/j;

.field public final x:Lo1/s0;

.field public y:Lo1/s0;


# direct methods
.method public constructor <init>(Lay0/a;Lo1/r0;Lg1/w1;ZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lx2/r;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo1/u0;->r:Lay0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lo1/u0;->s:Lo1/r0;

    .line 7
    .line 8
    iput-object p3, p0, Lo1/u0;->t:Lg1/w1;

    .line 9
    .line 10
    iput-boolean p4, p0, Lo1/u0;->u:Z

    .line 11
    .line 12
    iput-boolean p5, p0, Lo1/u0;->v:Z

    .line 13
    .line 14
    new-instance p1, Lo1/s0;

    .line 15
    .line 16
    const/4 p2, 0x0

    .line 17
    invoke-direct {p1, p0, p2}, Lo1/s0;-><init>(Lo1/u0;I)V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Lo1/u0;->x:Lo1/s0;

    .line 21
    .line 22
    invoke-virtual {p0}, Lo1/u0;->X0()V

    .line 23
    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final M0()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final X0()V
    .locals 4

    .line 1
    new-instance v0, Ld4/j;

    .line 2
    .line 3
    new-instance v1, Lo1/t0;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v1, p0, v2}, Lo1/t0;-><init>(Lo1/u0;I)V

    .line 7
    .line 8
    .line 9
    new-instance v2, Lo1/t0;

    .line 10
    .line 11
    const/4 v3, 0x1

    .line 12
    invoke-direct {v2, p0, v3}, Lo1/t0;-><init>(Lo1/u0;I)V

    .line 13
    .line 14
    .line 15
    iget-boolean v3, p0, Lo1/u0;->v:Z

    .line 16
    .line 17
    invoke-direct {v0, v1, v2, v3}, Ld4/j;-><init>(Lay0/a;Lay0/a;Z)V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Lo1/u0;->w:Ld4/j;

    .line 21
    .line 22
    iget-boolean v0, p0, Lo1/u0;->u:Z

    .line 23
    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    new-instance v0, Lo1/s0;

    .line 27
    .line 28
    const/4 v1, 0x1

    .line 29
    invoke-direct {v0, p0, v1}, Lo1/s0;-><init>(Lo1/u0;I)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/4 v0, 0x0

    .line 34
    :goto_0
    iput-object v0, p0, Lo1/u0;->y:Lo1/s0;

    .line 35
    .line 36
    return-void
.end method

.method public final a0(Ld4/l;)V
    .locals 6

    .line 1
    invoke-static {p1}, Ld4/x;->l(Ld4/l;)V

    .line 2
    .line 3
    .line 4
    sget-object v0, Ld4/v;->L:Ld4/z;

    .line 5
    .line 6
    iget-object v1, p0, Lo1/u0;->x:Lo1/s0;

    .line 7
    .line 8
    invoke-virtual {p1, v0, v1}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lo1/u0;->t:Lg1/w1;

    .line 12
    .line 13
    sget-object v1, Lg1/w1;->d:Lg1/w1;

    .line 14
    .line 15
    const-string v2, "scrollAxisRange"

    .line 16
    .line 17
    const/4 v3, 0x0

    .line 18
    if-ne v0, v1, :cond_1

    .line 19
    .line 20
    iget-object v0, p0, Lo1/u0;->w:Ld4/j;

    .line 21
    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    sget-object v1, Ld4/v;->u:Ld4/z;

    .line 25
    .line 26
    sget-object v2, Ld4/x;->a:[Lhy0/z;

    .line 27
    .line 28
    const/16 v4, 0xc

    .line 29
    .line 30
    aget-object v2, v2, v4

    .line 31
    .line 32
    invoke-virtual {v1, p1, v0}, Ld4/z;->a(Ld4/l;Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw v3

    .line 40
    :cond_1
    iget-object v0, p0, Lo1/u0;->w:Ld4/j;

    .line 41
    .line 42
    if-eqz v0, :cond_3

    .line 43
    .line 44
    sget-object v1, Ld4/v;->t:Ld4/z;

    .line 45
    .line 46
    sget-object v2, Ld4/x;->a:[Lhy0/z;

    .line 47
    .line 48
    const/16 v4, 0xb

    .line 49
    .line 50
    aget-object v2, v2, v4

    .line 51
    .line 52
    invoke-virtual {v1, p1, v0}, Ld4/z;->a(Ld4/l;Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    :goto_0
    iget-object v0, p0, Lo1/u0;->y:Lo1/s0;

    .line 56
    .line 57
    if-eqz v0, :cond_2

    .line 58
    .line 59
    sget-object v1, Ld4/k;->f:Ld4/z;

    .line 60
    .line 61
    new-instance v2, Ld4/a;

    .line 62
    .line 63
    invoke-direct {v2, v3, v0}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p1, v1, v2}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    :cond_2
    new-instance v0, Lo1/t0;

    .line 70
    .line 71
    const/4 v1, 0x2

    .line 72
    invoke-direct {v0, p0, v1}, Lo1/t0;-><init>(Lo1/u0;I)V

    .line 73
    .line 74
    .line 75
    sget-object v1, Ld4/k;->B:Ld4/z;

    .line 76
    .line 77
    new-instance v2, Ld4/a;

    .line 78
    .line 79
    new-instance v4, La3/f;

    .line 80
    .line 81
    const/16 v5, 0xd

    .line 82
    .line 83
    invoke-direct {v4, v0, v5}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 84
    .line 85
    .line 86
    invoke-direct {v2, v3, v4}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {p1, v1, v2}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    iget-object p0, p0, Lo1/u0;->s:Lo1/r0;

    .line 93
    .line 94
    invoke-interface {p0}, Lo1/r0;->c()Ld4/b;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    sget-object v0, Ld4/v;->f:Ld4/z;

    .line 99
    .line 100
    sget-object v1, Ld4/x;->a:[Lhy0/z;

    .line 101
    .line 102
    const/16 v2, 0x16

    .line 103
    .line 104
    aget-object v1, v1, v2

    .line 105
    .line 106
    invoke-virtual {v0, p1, p0}, Ld4/z;->a(Ld4/l;Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    return-void

    .line 110
    :cond_3
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    throw v3
.end method
