.class public final Lbz/g;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lzy/x;

.field public final i:Lzy/l;

.field public final j:Lzy/q;

.field public final k:Ltr0/b;

.field public final l:Lij0/a;


# direct methods
.method public constructor <init>(Lzy/x;Lzy/l;Lzy/q;Ltr0/b;Lij0/a;)V
    .locals 1

    .line 1
    sget-object v0, Lbz/f;->a:Lbz/f;

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lbz/g;->h:Lzy/x;

    .line 7
    .line 8
    iput-object p2, p0, Lbz/g;->i:Lzy/l;

    .line 9
    .line 10
    iput-object p3, p0, Lbz/g;->j:Lzy/q;

    .line 11
    .line 12
    iput-object p4, p0, Lbz/g;->k:Ltr0/b;

    .line 13
    .line 14
    iput-object p5, p0, Lbz/g;->l:Lij0/a;

    .line 15
    .line 16
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    new-instance p2, La50/a;

    .line 21
    .line 22
    const/16 p3, 0xd

    .line 23
    .line 24
    const/4 p4, 0x0

    .line 25
    invoke-direct {p2, p0, p4, p3}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x3

    .line 29
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 30
    .line 31
    .line 32
    return-void
.end method
