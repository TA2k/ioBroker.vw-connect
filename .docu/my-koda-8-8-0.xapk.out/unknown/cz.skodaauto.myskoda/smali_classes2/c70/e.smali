.class public final Lc70/e;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lkf0/e0;

.field public final i:Lkf0/b0;

.field public final j:Lep0/g;

.field public final k:Lcs0/l;

.field public final l:La70/d;

.field public final m:Lij0/a;

.field public final n:Lep0/b;

.field public final o:Lcf0/e;


# direct methods
.method public constructor <init>(Lkf0/e0;Lkf0/b0;Lep0/g;Lcs0/l;La70/d;Lij0/a;Lep0/b;Lcf0/e;)V
    .locals 3

    .line 1
    new-instance v0, Lc70/d;

    .line 2
    .line 3
    const/16 v1, 0x7fff

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Lc70/d;-><init>(ILjava/lang/String;Llf0/i;)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lc70/e;->h:Lkf0/e0;

    .line 13
    .line 14
    iput-object p2, p0, Lc70/e;->i:Lkf0/b0;

    .line 15
    .line 16
    iput-object p3, p0, Lc70/e;->j:Lep0/g;

    .line 17
    .line 18
    iput-object p4, p0, Lc70/e;->k:Lcs0/l;

    .line 19
    .line 20
    iput-object p5, p0, Lc70/e;->l:La70/d;

    .line 21
    .line 22
    iput-object p6, p0, Lc70/e;->m:Lij0/a;

    .line 23
    .line 24
    iput-object p7, p0, Lc70/e;->n:Lep0/b;

    .line 25
    .line 26
    iput-object p8, p0, Lc70/e;->o:Lcf0/e;

    .line 27
    .line 28
    new-instance p1, Lc70/c;

    .line 29
    .line 30
    const/4 p2, 0x0

    .line 31
    invoke-direct {p1, p0, v2, p2}, Lc70/c;-><init>(Lc70/e;Lkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 35
    .line 36
    .line 37
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    new-instance p2, Lc70/c;

    .line 42
    .line 43
    const/4 p3, 0x1

    .line 44
    invoke-direct {p2, p0, v2, p3}, Lc70/c;-><init>(Lc70/e;Lkotlin/coroutines/Continuation;I)V

    .line 45
    .line 46
    .line 47
    const/4 p3, 0x3

    .line 48
    invoke-static {p1, v2, v2, p2, p3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 49
    .line 50
    .line 51
    new-instance p1, Lc70/c;

    .line 52
    .line 53
    const/4 p2, 0x2

    .line 54
    invoke-direct {p1, p0, v2, p2}, Lc70/c;-><init>(Lc70/e;Lkotlin/coroutines/Continuation;I)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 58
    .line 59
    .line 60
    return-void
.end method
