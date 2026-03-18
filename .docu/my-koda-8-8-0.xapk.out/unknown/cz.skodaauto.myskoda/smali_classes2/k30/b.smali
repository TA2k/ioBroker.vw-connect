.class public final Lk30/b;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Li30/f;

.field public final i:Lij0/a;

.field public final j:Lkf0/e0;

.field public final k:Li30/e;

.field public final l:Lkf0/k;


# direct methods
.method public constructor <init>(Li30/f;Lij0/a;Lkf0/e0;Li30/e;Lkf0/k;)V
    .locals 5

    .line 1
    new-instance v0, Lk30/a;

    .line 2
    .line 3
    sget-object v1, Llf0/i;->j:Llf0/i;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const-string v3, ""

    .line 7
    .line 8
    const/4 v4, 0x1

    .line 9
    invoke-direct {v0, v4, v1, v2, v3}, Lk30/a;-><init>(ZLlf0/i;ZLjava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Lk30/b;->h:Li30/f;

    .line 16
    .line 17
    iput-object p2, p0, Lk30/b;->i:Lij0/a;

    .line 18
    .line 19
    iput-object p3, p0, Lk30/b;->j:Lkf0/e0;

    .line 20
    .line 21
    iput-object p4, p0, Lk30/b;->k:Li30/e;

    .line 22
    .line 23
    iput-object p5, p0, Lk30/b;->l:Lkf0/k;

    .line 24
    .line 25
    new-instance p1, Lif0/d0;

    .line 26
    .line 27
    const/4 p2, 0x0

    .line 28
    const/16 p3, 0x18

    .line 29
    .line 30
    invoke-direct {p1, p0, p2, p3}, Lif0/d0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 34
    .line 35
    .line 36
    return-void
.end method
