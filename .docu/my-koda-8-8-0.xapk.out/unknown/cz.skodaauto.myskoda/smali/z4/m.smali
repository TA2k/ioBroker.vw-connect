.class public final Lz4/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/z1;


# instance fields
.field public final d:Lz4/k;

.field public e:Landroid/os/Handler;

.field public final f:Lv2/r;

.field public g:Z

.field public final h:Lz4/l;

.field public final i:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Lz4/k;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz4/m;->d:Lz4/k;

    .line 5
    .line 6
    new-instance p1, Lv2/r;

    .line 7
    .line 8
    new-instance v0, Lz4/l;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-direct {v0, p0, v1}, Lz4/l;-><init>(Lz4/m;I)V

    .line 12
    .line 13
    .line 14
    invoke-direct {p1, v0}, Lv2/r;-><init>(Lay0/k;)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lz4/m;->f:Lv2/r;

    .line 18
    .line 19
    const/4 p1, 0x1

    .line 20
    iput-boolean p1, p0, Lz4/m;->g:Z

    .line 21
    .line 22
    new-instance p1, Lz4/l;

    .line 23
    .line 24
    const/4 v0, 0x1

    .line 25
    invoke-direct {p1, p0, v0}, Lz4/l;-><init>(Lz4/m;I)V

    .line 26
    .line 27
    .line 28
    iput-object p1, p0, Lz4/m;->h:Lz4/l;

    .line 29
    .line 30
    new-instance p1, Ljava/util/ArrayList;

    .line 31
    .line 32
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 33
    .line 34
    .line 35
    iput-object p1, p0, Lz4/m;->i:Ljava/util/ArrayList;

    .line 36
    .line 37
    return-void
.end method


# virtual methods
.method public final c()V
    .locals 0

    .line 1
    iget-object p0, p0, Lz4/m;->f:Lv2/r;

    .line 2
    .line 3
    invoke-virtual {p0}, Lv2/r;->e()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final e()V
    .locals 0

    .line 1
    return-void
.end method

.method public final h()V
    .locals 1

    .line 1
    iget-object p0, p0, Lz4/m;->f:Lv2/r;

    .line 2
    .line 3
    iget-object v0, p0, Lv2/r;->h:Lrx/b;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {v0}, Lrx/b;->d()V

    .line 8
    .line 9
    .line 10
    :cond_0
    invoke-virtual {p0}, Lv2/r;->a()V

    .line 11
    .line 12
    .line 13
    return-void
.end method
