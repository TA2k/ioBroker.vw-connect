.class public final Lx71/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lx71/h;

.field public final b:Lx71/h;

.field public final c:Lx71/h;

.field public final d:Lx71/h;

.field public e:D

.field public f:Lx71/m;

.field public g:Lx71/e;

.field public h:I

.field public i:I

.field public j:I

.field public k:I

.field public l:Lx71/n;

.field public m:Lx71/n;

.field public n:Lx71/n;

.field public o:Lx71/n;

.field public p:Lx71/n;

.field public q:Lx71/n;

.field public r:Lx71/n;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lx71/h;

    .line 5
    .line 6
    invoke-direct {v0}, Lx71/h;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lx71/n;->a:Lx71/h;

    .line 10
    .line 11
    new-instance v0, Lx71/h;

    .line 12
    .line 13
    invoke-direct {v0}, Lx71/h;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lx71/n;->b:Lx71/h;

    .line 17
    .line 18
    new-instance v0, Lx71/h;

    .line 19
    .line 20
    invoke-direct {v0}, Lx71/h;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lx71/n;->c:Lx71/h;

    .line 24
    .line 25
    new-instance v0, Lx71/h;

    .line 26
    .line 27
    invoke-direct {v0}, Lx71/h;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object v0, p0, Lx71/n;->d:Lx71/h;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final a()Lx71/n;
    .locals 0

    .line 1
    iget-object p0, p0, Lx71/n;->l:Lx71/n;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    const-string p0, "next"

    .line 7
    .line 8
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    throw p0
.end method

.method public final b()Lx71/n;
    .locals 0

    .line 1
    iget-object p0, p0, Lx71/n;->m:Lx71/n;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    const-string p0, "prev"

    .line 7
    .line 8
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    throw p0
.end method
