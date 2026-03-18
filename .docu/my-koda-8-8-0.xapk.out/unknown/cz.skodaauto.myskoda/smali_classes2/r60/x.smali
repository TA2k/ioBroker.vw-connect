.class public final Lr60/x;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lnn0/c0;

.field public final i:Lnn0/e0;

.field public final j:Lp60/x;

.field public final k:Lp60/r;

.field public final l:Lij0/a;

.field public final m:Ltr0/b;

.field public final n:Lnn0/j;

.field public o:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lp60/f;Lnn0/c0;Lnn0/e0;Lp60/x;Lp60/r;Lij0/a;Ltr0/b;Lnn0/j;)V
    .locals 4

    .line 1
    new-instance v0, Lr60/w;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 5
    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v2, v3, v3, v1}, Lr60/w;-><init>(Ljava/util/List;Lon0/e;Lql0/g;Z)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p2, p0, Lr60/x;->h:Lnn0/c0;

    .line 14
    .line 15
    iput-object p3, p0, Lr60/x;->i:Lnn0/e0;

    .line 16
    .line 17
    iput-object p4, p0, Lr60/x;->j:Lp60/x;

    .line 18
    .line 19
    iput-object p5, p0, Lr60/x;->k:Lp60/r;

    .line 20
    .line 21
    iput-object p6, p0, Lr60/x;->l:Lij0/a;

    .line 22
    .line 23
    iput-object p7, p0, Lr60/x;->m:Ltr0/b;

    .line 24
    .line 25
    iput-object p8, p0, Lr60/x;->n:Lnn0/j;

    .line 26
    .line 27
    iput-object v2, p0, Lr60/x;->o:Ljava/lang/Object;

    .line 28
    .line 29
    new-instance p2, Lr60/t;

    .line 30
    .line 31
    const/4 p3, 0x0

    .line 32
    invoke-direct {p2, p3, p1, p0, v3}, Lr60/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0, p2}, Lql0/j;->b(Lay0/n;)V

    .line 36
    .line 37
    .line 38
    new-instance p1, Ln00/f;

    .line 39
    .line 40
    const/16 p2, 0x17

    .line 41
    .line 42
    invoke-direct {p1, p0, v3, p2}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 46
    .line 47
    .line 48
    return-void
.end method
