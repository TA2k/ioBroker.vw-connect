.class public final Lc80/m;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lij0/a;

.field public final i:Lzd0/a;

.field public final j:Lwq0/p0;

.field public final k:Lwq0/j;

.field public final l:Lwq0/t0;

.field public final m:Lwq0/u0;

.field public final n:Lwq0/g0;

.field public final o:Lwq0/g;

.field public final p:Lwq0/k;


# direct methods
.method public constructor <init>(Lij0/a;Lzd0/a;Lwq0/p0;Lwq0/j;Lwq0/t0;Lwq0/u0;Lwq0/g0;Lwq0/g;Lwq0/k;)V
    .locals 1

    .line 1
    new-instance v0, Lc80/k;

    .line 2
    .line 3
    invoke-direct {v0}, Lc80/k;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lc80/m;->h:Lij0/a;

    .line 10
    .line 11
    iput-object p2, p0, Lc80/m;->i:Lzd0/a;

    .line 12
    .line 13
    iput-object p3, p0, Lc80/m;->j:Lwq0/p0;

    .line 14
    .line 15
    iput-object p4, p0, Lc80/m;->k:Lwq0/j;

    .line 16
    .line 17
    iput-object p5, p0, Lc80/m;->l:Lwq0/t0;

    .line 18
    .line 19
    iput-object p6, p0, Lc80/m;->m:Lwq0/u0;

    .line 20
    .line 21
    iput-object p7, p0, Lc80/m;->n:Lwq0/g0;

    .line 22
    .line 23
    iput-object p8, p0, Lc80/m;->o:Lwq0/g;

    .line 24
    .line 25
    iput-object p9, p0, Lc80/m;->p:Lwq0/k;

    .line 26
    .line 27
    return-void
.end method


# virtual methods
.method public final h(Ljava/lang/String;)V
    .locals 10

    .line 1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    move-object v1, v0

    .line 6
    check-cast v1, Lc80/k;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    new-array v0, v0, [Ljava/lang/Object;

    .line 10
    .line 11
    iget-object v2, p0, Lc80/m;->h:Lij0/a;

    .line 12
    .line 13
    check-cast v2, Ljj0/f;

    .line 14
    .line 15
    const v3, 0x7f12124b

    .line 16
    .line 17
    .line 18
    invoke-virtual {v2, v3, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v5

    .line 22
    const/4 v8, 0x0

    .line 23
    const/16 v9, 0x64

    .line 24
    .line 25
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 26
    .line 27
    const/4 v3, 0x0

    .line 28
    const/4 v4, 0x0

    .line 29
    const/4 v7, 0x0

    .line 30
    move-object v6, p1

    .line 31
    invoke-static/range {v1 .. v9}, Lc80/k;->a(Lc80/k;Ljava/util/List;Ljava/lang/String;Lql0/g;Ljava/lang/String;Ljava/lang/String;ZZI)Lc80/k;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method
