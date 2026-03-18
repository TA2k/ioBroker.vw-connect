.class public final Ln50/m0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Ll50/c0;

.field public final j:Lrq0/f;

.field public final k:Ll50/m0;

.field public final l:Lij0/a;

.field public final m:Lhl0/b;


# direct methods
.method public constructor <init>(Ll50/p;Lgl0/b;Ltr0/b;Ll50/c0;Lrq0/f;Ll50/m0;Lij0/a;)V
    .locals 2

    .line 1
    new-instance v0, Ln50/l0;

    .line 2
    .line 3
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ln50/l0;-><init>(Ljava/util/List;)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p3, p0, Ln50/m0;->h:Ltr0/b;

    .line 12
    .line 13
    iput-object p4, p0, Ln50/m0;->i:Ll50/c0;

    .line 14
    .line 15
    iput-object p5, p0, Ln50/m0;->j:Lrq0/f;

    .line 16
    .line 17
    iput-object p6, p0, Ln50/m0;->k:Ll50/m0;

    .line 18
    .line 19
    iput-object p7, p0, Ln50/m0;->l:Lij0/a;

    .line 20
    .line 21
    invoke-virtual {p2}, Lgl0/b;->invoke()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p2

    .line 25
    check-cast p2, Lhl0/b;

    .line 26
    .line 27
    iput-object p2, p0, Ln50/m0;->m:Lhl0/b;

    .line 28
    .line 29
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 30
    .line 31
    .line 32
    move-result-object p2

    .line 33
    new-instance p3, Lm70/i0;

    .line 34
    .line 35
    const/16 p4, 0x12

    .line 36
    .line 37
    const/4 p5, 0x0

    .line 38
    invoke-direct {p3, p4, p1, p0, p5}, Lm70/i0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 39
    .line 40
    .line 41
    const/4 p0, 0x3

    .line 42
    invoke-static {p2, p5, p5, p3, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 43
    .line 44
    .line 45
    return-void
.end method
