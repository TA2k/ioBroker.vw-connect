.class public final Ls10/d0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lq10/l;

.field public final i:Lkf0/e0;

.field public final j:Lkf0/b0;

.field public final k:Lq10/c;

.field public final l:Lq10/h;

.field public final m:Lq10/t;

.field public final n:Lij0/a;

.field public final o:Lq10/j;

.field public final p:Lcf0/e;


# direct methods
.method public constructor <init>(Lq10/l;Lkf0/e0;Lkf0/b0;Lq10/c;Lq10/h;Lq10/t;Lij0/a;Lq10/j;Lcf0/e;)V
    .locals 3

    .line 1
    new-instance v0, Ls10/c0;

    .line 2
    .line 3
    const/16 v1, 0xff

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v2, v1}, Ls10/c0;-><init>(Llf0/i;I)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Ls10/d0;->h:Lq10/l;

    .line 13
    .line 14
    iput-object p2, p0, Ls10/d0;->i:Lkf0/e0;

    .line 15
    .line 16
    iput-object p3, p0, Ls10/d0;->j:Lkf0/b0;

    .line 17
    .line 18
    iput-object p4, p0, Ls10/d0;->k:Lq10/c;

    .line 19
    .line 20
    iput-object p5, p0, Ls10/d0;->l:Lq10/h;

    .line 21
    .line 22
    iput-object p6, p0, Ls10/d0;->m:Lq10/t;

    .line 23
    .line 24
    iput-object p7, p0, Ls10/d0;->n:Lij0/a;

    .line 25
    .line 26
    iput-object p8, p0, Ls10/d0;->o:Lq10/j;

    .line 27
    .line 28
    iput-object p9, p0, Ls10/d0;->p:Lcf0/e;

    .line 29
    .line 30
    new-instance p1, Ls10/a0;

    .line 31
    .line 32
    const/4 p2, 0x0

    .line 33
    invoke-direct {p1, p0, v2, p2}, Ls10/a0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 37
    .line 38
    .line 39
    new-instance p1, Ls10/z;

    .line 40
    .line 41
    const/4 p2, 0x2

    .line 42
    invoke-direct {p1, p0, v2, p2}, Ls10/z;-><init>(Ls10/d0;Lkotlin/coroutines/Continuation;I)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 46
    .line 47
    .line 48
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    new-instance p2, Ls10/z;

    .line 53
    .line 54
    const/4 p3, 0x3

    .line 55
    invoke-direct {p2, p0, v2, p3}, Ls10/z;-><init>(Ls10/d0;Lkotlin/coroutines/Continuation;I)V

    .line 56
    .line 57
    .line 58
    const/4 p0, 0x3

    .line 59
    invoke-static {p1, v2, v2, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 60
    .line 61
    .line 62
    return-void
.end method
