.class public abstract Lh5/k;
.super Lh5/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public A0:I

.field public B0:I

.field public final C0:Li5/b;

.field public D0:Li5/c;

.field public t0:I

.field public u0:I

.field public v0:I

.field public w0:I

.field public x0:I

.field public y0:I

.field public z0:Z


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lh5/i;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lh5/k;->t0:I

    .line 6
    .line 7
    iput v0, p0, Lh5/k;->u0:I

    .line 8
    .line 9
    iput v0, p0, Lh5/k;->v0:I

    .line 10
    .line 11
    iput v0, p0, Lh5/k;->w0:I

    .line 12
    .line 13
    iput v0, p0, Lh5/k;->x0:I

    .line 14
    .line 15
    iput v0, p0, Lh5/k;->y0:I

    .line 16
    .line 17
    iput-boolean v0, p0, Lh5/k;->z0:Z

    .line 18
    .line 19
    iput v0, p0, Lh5/k;->A0:I

    .line 20
    .line 21
    iput v0, p0, Lh5/k;->B0:I

    .line 22
    .line 23
    new-instance v0, Li5/b;

    .line 24
    .line 25
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 26
    .line 27
    .line 28
    iput-object v0, p0, Lh5/k;->C0:Li5/b;

    .line 29
    .line 30
    const/4 v0, 0x0

    .line 31
    iput-object v0, p0, Lh5/k;->D0:Li5/c;

    .line 32
    .line 33
    return-void
.end method


# virtual methods
.method public final X()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    iget v1, p0, Lh5/i;->s0:I

    .line 3
    .line 4
    if-ge v0, v1, :cond_1

    .line 5
    .line 6
    iget-object v1, p0, Lh5/i;->r0:[Lh5/d;

    .line 7
    .line 8
    aget-object v1, v1, v0

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    iput-boolean v2, v1, Lh5/d;->G:Z

    .line 14
    .line 15
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_1
    return-void
.end method

.method public abstract Y(IIII)V
.end method

.method public final Z(IIIILh5/d;)V
    .locals 2

    .line 1
    :goto_0
    iget-object v0, p0, Lh5/k;->D0:Li5/c;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v1, p0, Lh5/d;->U:Lh5/e;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    iget-object v0, v1, Lh5/e;->v0:Li5/c;

    .line 10
    .line 11
    iput-object v0, p0, Lh5/k;->D0:Li5/c;

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    iget-object p0, p0, Lh5/k;->C0:Li5/b;

    .line 15
    .line 16
    iput p1, p0, Li5/b;->a:I

    .line 17
    .line 18
    iput p3, p0, Li5/b;->b:I

    .line 19
    .line 20
    iput p2, p0, Li5/b;->c:I

    .line 21
    .line 22
    iput p4, p0, Li5/b;->d:I

    .line 23
    .line 24
    invoke-interface {v0, p5, p0}, Li5/c;->b(Lh5/d;Li5/b;)V

    .line 25
    .line 26
    .line 27
    iget p1, p0, Li5/b;->e:I

    .line 28
    .line 29
    invoke-virtual {p5, p1}, Lh5/d;->S(I)V

    .line 30
    .line 31
    .line 32
    iget p1, p0, Li5/b;->f:I

    .line 33
    .line 34
    invoke-virtual {p5, p1}, Lh5/d;->N(I)V

    .line 35
    .line 36
    .line 37
    iget-boolean p1, p0, Li5/b;->h:Z

    .line 38
    .line 39
    iput-boolean p1, p5, Lh5/d;->F:Z

    .line 40
    .line 41
    iget p0, p0, Li5/b;->g:I

    .line 42
    .line 43
    invoke-virtual {p5, p0}, Lh5/d;->J(I)V

    .line 44
    .line 45
    .line 46
    return-void
.end method
