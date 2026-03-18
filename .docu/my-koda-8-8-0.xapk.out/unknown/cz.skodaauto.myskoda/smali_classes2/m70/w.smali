.class public final Lm70/w;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lkf0/e0;

.field public final i:Lk70/y0;


# direct methods
.method public constructor <init>(Lkf0/e0;Lk70/y0;)V
    .locals 2

    .line 1
    new-instance v0, Lm70/v;

    .line 2
    .line 3
    sget-object v1, Llf0/i;->e:Llf0/i;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lm70/v;-><init>(Llf0/i;)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lm70/w;->h:Lkf0/e0;

    .line 12
    .line 13
    iput-object p2, p0, Lm70/w;->i:Lk70/y0;

    .line 14
    .line 15
    new-instance p1, Lk20/a;

    .line 16
    .line 17
    const/4 p2, 0x0

    .line 18
    const/16 v0, 0x10

    .line 19
    .line 20
    invoke-direct {p1, p0, p2, v0}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method
