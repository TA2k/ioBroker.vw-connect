.class public final Laa/j;
.super Lvp/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final g:Laa/i;

.field public final h:Lay0/p;

.field public i:Lay0/k;

.field public j:Lay0/k;

.field public k:Lay0/k;

.field public l:Lay0/k;


# direct methods
.method public constructor <init>(Laa/i;Lhy0/d;Lt2/b;)V
    .locals 1

    sget-object v0, Lmx0/t;->d:Lmx0/t;

    .line 4
    invoke-direct {p0, p1, p2, v0}, Lvp/c;-><init>(Lz9/j0;Lhy0/d;Ljava/util/Map;)V

    .line 5
    iput-object p1, p0, Laa/j;->g:Laa/i;

    .line 6
    iput-object p3, p0, Laa/j;->h:Lay0/p;

    return-void
.end method

.method public constructor <init>(Laa/i;Ljava/lang/String;Lay0/p;)V
    .locals 1

    const/4 v0, -0x1

    .line 1
    invoke-direct {p0, p1, v0, p2}, Lvp/c;-><init>(Lz9/j0;ILjava/lang/String;)V

    .line 2
    iput-object p1, p0, Laa/j;->g:Laa/i;

    .line 3
    iput-object p3, p0, Laa/j;->h:Lay0/p;

    return-void
.end method


# virtual methods
.method public final a()Lz9/u;
    .locals 2

    .line 1
    invoke-super {p0}, Lvp/c;->a()Lz9/u;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Laa/h;

    .line 6
    .line 7
    iget-object v1, p0, Laa/j;->i:Lay0/k;

    .line 8
    .line 9
    iput-object v1, v0, Laa/h;->j:Lay0/k;

    .line 10
    .line 11
    iget-object v1, p0, Laa/j;->j:Lay0/k;

    .line 12
    .line 13
    iput-object v1, v0, Laa/h;->k:Lay0/k;

    .line 14
    .line 15
    iget-object v1, p0, Laa/j;->k:Lay0/k;

    .line 16
    .line 17
    iput-object v1, v0, Laa/h;->l:Lay0/k;

    .line 18
    .line 19
    iget-object p0, p0, Laa/j;->l:Lay0/k;

    .line 20
    .line 21
    iput-object p0, v0, Laa/h;->m:Lay0/k;

    .line 22
    .line 23
    return-object v0
.end method

.method public final b()Lz9/u;
    .locals 2

    .line 1
    new-instance v0, Laa/h;

    .line 2
    .line 3
    iget-object v1, p0, Laa/j;->g:Laa/i;

    .line 4
    .line 5
    iget-object p0, p0, Laa/j;->h:Lay0/p;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0}, Laa/h;-><init>(Laa/i;Lay0/p;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method
