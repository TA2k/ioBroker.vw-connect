.class public final Lc00/t;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Llb0/p;

.field public final j:Llb0/w;

.field public final k:Ljn0/c;

.field public final l:Llb0/i;

.field public final m:Lrq0/f;

.field public final n:Lyt0/b;

.field public final o:Lij0/a;


# direct methods
.method public constructor <init>(Ltr0/b;Llb0/p;Llb0/w;Ljn0/c;Llb0/i;Lrq0/f;Lyt0/b;Lij0/a;)V
    .locals 2

    .line 1
    new-instance v0, Lc00/s;

    .line 2
    .line 3
    sget-object v1, Lc00/r;->g:Lc00/r;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lc00/s;-><init>(Lc00/r;)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lc00/t;->h:Ltr0/b;

    .line 12
    .line 13
    iput-object p2, p0, Lc00/t;->i:Llb0/p;

    .line 14
    .line 15
    iput-object p3, p0, Lc00/t;->j:Llb0/w;

    .line 16
    .line 17
    iput-object p4, p0, Lc00/t;->k:Ljn0/c;

    .line 18
    .line 19
    iput-object p5, p0, Lc00/t;->l:Llb0/i;

    .line 20
    .line 21
    iput-object p6, p0, Lc00/t;->m:Lrq0/f;

    .line 22
    .line 23
    iput-object p7, p0, Lc00/t;->n:Lyt0/b;

    .line 24
    .line 25
    iput-object p8, p0, Lc00/t;->o:Lij0/a;

    .line 26
    .line 27
    new-instance p1, La50/a;

    .line 28
    .line 29
    const/4 p2, 0x0

    .line 30
    const/16 p3, 0xf

    .line 31
    .line 32
    invoke-direct {p1, p0, p2, p3}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method
