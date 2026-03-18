.class public final Lt1/v0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lg4/g;

.field public final b:Lg4/p0;

.field public final c:I

.field public final d:I

.field public final e:Z

.field public final f:I

.field public final g:Lt4/c;

.field public final h:Lk4/m;

.field public final i:Ljava/util/List;

.field public j:Landroidx/lifecycle/c1;

.field public k:Lt4/m;


# direct methods
.method public constructor <init>(Lg4/g;Lg4/p0;ZLt4/c;Lk4/m;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt1/v0;->a:Lg4/g;

    .line 5
    .line 6
    iput-object p2, p0, Lt1/v0;->b:Lg4/p0;

    .line 7
    .line 8
    const p1, 0x7fffffff

    .line 9
    .line 10
    .line 11
    iput p1, p0, Lt1/v0;->c:I

    .line 12
    .line 13
    const/4 p1, 0x1

    .line 14
    iput p1, p0, Lt1/v0;->d:I

    .line 15
    .line 16
    iput-boolean p3, p0, Lt1/v0;->e:Z

    .line 17
    .line 18
    iput p1, p0, Lt1/v0;->f:I

    .line 19
    .line 20
    iput-object p4, p0, Lt1/v0;->g:Lt4/c;

    .line 21
    .line 22
    iput-object p5, p0, Lt1/v0;->h:Lk4/m;

    .line 23
    .line 24
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 25
    .line 26
    iput-object p1, p0, Lt1/v0;->i:Ljava/util/List;

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final a(Lt4/m;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lt1/v0;->j:Landroidx/lifecycle/c1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v1, p0, Lt1/v0;->k:Lt4/m;

    .line 6
    .line 7
    if-ne p1, v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0}, Landroidx/lifecycle/c1;->a()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    :cond_0
    iput-object p1, p0, Lt1/v0;->k:Lt4/m;

    .line 16
    .line 17
    iget-object v0, p0, Lt1/v0;->b:Lg4/p0;

    .line 18
    .line 19
    invoke-static {v0, p1}, Lg4/f0;->h(Lg4/p0;Lt4/m;)Lg4/p0;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    new-instance v1, Landroidx/lifecycle/c1;

    .line 24
    .line 25
    iget-object v2, p0, Lt1/v0;->a:Lg4/g;

    .line 26
    .line 27
    iget-object v4, p0, Lt1/v0;->i:Ljava/util/List;

    .line 28
    .line 29
    iget-object v5, p0, Lt1/v0;->g:Lt4/c;

    .line 30
    .line 31
    iget-object v6, p0, Lt1/v0;->h:Lk4/m;

    .line 32
    .line 33
    invoke-direct/range {v1 .. v6}, Landroidx/lifecycle/c1;-><init>(Lg4/g;Lg4/p0;Ljava/util/List;Lt4/c;Lk4/m;)V

    .line 34
    .line 35
    .line 36
    move-object v0, v1

    .line 37
    :cond_1
    iput-object v0, p0, Lt1/v0;->j:Landroidx/lifecycle/c1;

    .line 38
    .line 39
    return-void
.end method
