.class public final Lz9/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lz9/a0;

.field public b:Z

.field public c:Z

.field public d:I

.field public e:Ljava/lang/String;

.field public f:Z

.field public g:Z

.field public h:Lhy0/d;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lz9/a0;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    const/4 v1, -0x1

    .line 10
    iput v1, v0, Lz9/a0;->c:I

    .line 11
    .line 12
    iput v1, v0, Lz9/a0;->h:I

    .line 13
    .line 14
    iput v1, v0, Lz9/a0;->i:I

    .line 15
    .line 16
    iput-object v0, p0, Lz9/c0;->a:Lz9/a0;

    .line 17
    .line 18
    const/4 v0, -0x1

    .line 19
    iput v0, p0, Lz9/c0;->d:I

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final a(ILay0/k;)V
    .locals 0

    .line 1
    iput p1, p0, Lz9/c0;->d:I

    .line 2
    .line 3
    const/4 p1, 0x0

    .line 4
    iput-boolean p1, p0, Lz9/c0;->f:Z

    .line 5
    .line 6
    new-instance p1, Lz9/l0;

    .line 7
    .line 8
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    invoke-interface {p2, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    iget-boolean p2, p1, Lz9/l0;->a:Z

    .line 15
    .line 16
    iput-boolean p2, p0, Lz9/c0;->f:Z

    .line 17
    .line 18
    iget-boolean p1, p1, Lz9/l0;->b:Z

    .line 19
    .line 20
    iput-boolean p1, p0, Lz9/c0;->g:Z

    .line 21
    .line 22
    return-void
.end method

.method public final b(Ljava/lang/String;Lay0/k;)V
    .locals 1

    .line 1
    const-string v0, "route"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    iput-object p1, p0, Lz9/c0;->e:Ljava/lang/String;

    .line 13
    .line 14
    const/4 p1, -0x1

    .line 15
    iput p1, p0, Lz9/c0;->d:I

    .line 16
    .line 17
    const/4 p1, 0x0

    .line 18
    iput-boolean p1, p0, Lz9/c0;->f:Z

    .line 19
    .line 20
    new-instance p1, Lz9/l0;

    .line 21
    .line 22
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 23
    .line 24
    .line 25
    invoke-interface {p2, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    iget-boolean p2, p1, Lz9/l0;->a:Z

    .line 29
    .line 30
    iput-boolean p2, p0, Lz9/c0;->f:Z

    .line 31
    .line 32
    iget-boolean p1, p1, Lz9/l0;->b:Z

    .line 33
    .line 34
    iput-boolean p1, p0, Lz9/c0;->g:Z

    .line 35
    .line 36
    return-void

    .line 37
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 38
    .line 39
    const-string p1, "Cannot pop up to an empty route"

    .line 40
    .line 41
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0
.end method
