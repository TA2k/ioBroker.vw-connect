.class public final Ldz0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:Lay0/o;

.field public final c:Lay0/o;

.field public final d:Ljava/lang/Object;

.field public final e:Lrx0/i;

.field public final f:Lay0/o;

.field public g:Ljava/lang/Object;

.field public h:I

.field public final synthetic i:Ldz0/e;


# direct methods
.method public constructor <init>(Ldz0/e;Ljava/lang/Object;Lay0/o;Lay0/o;Lj51/i;Lrx0/i;Lay0/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ldz0/c;->i:Ldz0/e;

    .line 5
    .line 6
    iput-object p2, p0, Ldz0/c;->a:Ljava/lang/Object;

    .line 7
    .line 8
    iput-object p3, p0, Ldz0/c;->b:Lay0/o;

    .line 9
    .line 10
    iput-object p4, p0, Ldz0/c;->c:Lay0/o;

    .line 11
    .line 12
    iput-object p5, p0, Ldz0/c;->d:Ljava/lang/Object;

    .line 13
    .line 14
    iput-object p6, p0, Ldz0/c;->e:Lrx0/i;

    .line 15
    .line 16
    iput-object p7, p0, Ldz0/c;->f:Lay0/o;

    .line 17
    .line 18
    const/4 p1, -0x1

    .line 19
    iput p1, p0, Ldz0/c;->h:I

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    iget-object v0, p0, Ldz0/c;->g:Ljava/lang/Object;

    .line 2
    .line 3
    instance-of v1, v0, Laz0/q;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    check-cast v0, Laz0/q;

    .line 8
    .line 9
    iget v1, p0, Ldz0/c;->h:I

    .line 10
    .line 11
    iget-object p0, p0, Ldz0/c;->i:Ldz0/e;

    .line 12
    .line 13
    iget-object p0, p0, Ldz0/e;->d:Lpx0/g;

    .line 14
    .line 15
    invoke-virtual {v0, v1, p0}, Laz0/q;->h(ILpx0/g;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    instance-of p0, v0, Lvy0/r0;

    .line 20
    .line 21
    if-eqz p0, :cond_1

    .line 22
    .line 23
    check-cast v0, Lvy0/r0;

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    const/4 v0, 0x0

    .line 27
    :goto_0
    if-eqz v0, :cond_2

    .line 28
    .line 29
    invoke-interface {v0}, Lvy0/r0;->dispose()V

    .line 30
    .line 31
    .line 32
    :cond_2
    return-void
.end method
