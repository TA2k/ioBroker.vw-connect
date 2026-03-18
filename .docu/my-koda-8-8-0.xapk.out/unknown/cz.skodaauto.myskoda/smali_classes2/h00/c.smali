.class public final Lh00/c;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lgn0/f;

.field public final j:Lgn0/a;

.field public final k:Lks0/s;

.field public final l:Lug0/a;

.field public final m:Lug0/c;

.field public final n:Lij0/a;


# direct methods
.method public constructor <init>(Ltr0/b;Lgn0/f;Lgn0/a;Lks0/s;Lug0/a;Lug0/c;Lij0/a;)V
    .locals 6

    .line 1
    new-instance v0, Lh00/b;

    .line 2
    .line 3
    const-string v2, ""

    .line 4
    .line 5
    const/4 v4, 0x0

    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v5, 0x0

    .line 9
    invoke-direct/range {v0 .. v5}, Lh00/b;-><init>(Lhp0/e;Ljava/lang/String;Ljava/lang/String;ZLql0/g;)V

    .line 10
    .line 11
    .line 12
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Lh00/c;->h:Ltr0/b;

    .line 16
    .line 17
    iput-object p2, p0, Lh00/c;->i:Lgn0/f;

    .line 18
    .line 19
    iput-object p3, p0, Lh00/c;->j:Lgn0/a;

    .line 20
    .line 21
    iput-object p4, p0, Lh00/c;->k:Lks0/s;

    .line 22
    .line 23
    iput-object p5, p0, Lh00/c;->l:Lug0/a;

    .line 24
    .line 25
    iput-object p6, p0, Lh00/c;->m:Lug0/c;

    .line 26
    .line 27
    iput-object p7, p0, Lh00/c;->n:Lij0/a;

    .line 28
    .line 29
    new-instance p1, Lg60/w;

    .line 30
    .line 31
    const/4 p2, 0x6

    .line 32
    const/4 p3, 0x0

    .line 33
    invoke-direct {p1, p0, p3, p2}, Lg60/w;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 37
    .line 38
    .line 39
    new-instance p1, Lh00/a;

    .line 40
    .line 41
    const/4 p2, 0x0

    .line 42
    invoke-direct {p1, p0, p3, p2}, Lh00/a;-><init>(Lh00/c;Lkotlin/coroutines/Continuation;I)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 46
    .line 47
    .line 48
    return-void
.end method
