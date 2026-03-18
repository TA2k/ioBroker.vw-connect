.class public final Ls10/l;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lq10/u;

.field public final i:Lrq0/f;

.field public final j:Ljn0/c;

.field public final k:Lyt0/b;

.field public final l:Lij0/a;

.field public final m:Lq10/w;

.field public n:Ljava/util/List;


# direct methods
.method public constructor <init>(Lq10/l;Lq10/q;Lq10/u;Lrq0/f;Ljn0/c;Lyt0/b;Lij0/a;Lq10/w;)V
    .locals 3

    .line 1
    new-instance v0, Ls10/j;

    .line 2
    .line 3
    const/4 v1, 0x7

    .line 4
    move-object v2, p5

    .line 5
    const/4 p5, 0x0

    .line 6
    invoke-direct {v0, p5, v1}, Ls10/j;-><init>(Ljava/util/List;I)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p3, p0, Ls10/l;->h:Lq10/u;

    .line 13
    .line 14
    iput-object p4, p0, Ls10/l;->i:Lrq0/f;

    .line 15
    .line 16
    iput-object v2, p0, Ls10/l;->j:Ljn0/c;

    .line 17
    .line 18
    iput-object p6, p0, Ls10/l;->k:Lyt0/b;

    .line 19
    .line 20
    iput-object p7, p0, Ls10/l;->l:Lij0/a;

    .line 21
    .line 22
    iput-object p8, p0, Ls10/l;->m:Lq10/w;

    .line 23
    .line 24
    sget-object p3, Lmx0/s;->d:Lmx0/s;

    .line 25
    .line 26
    iput-object p3, p0, Ls10/l;->n:Ljava/util/List;

    .line 27
    .line 28
    move-object p4, p2

    .line 29
    move-object p2, p0

    .line 30
    new-instance p0, Lny/f0;

    .line 31
    .line 32
    move-object p3, p1

    .line 33
    const/16 p1, 0x18

    .line 34
    .line 35
    invoke-direct/range {p0 .. p5}, Lny/f0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p2, p0}, Lql0/j;->b(Lay0/n;)V

    .line 39
    .line 40
    .line 41
    return-void
.end method
