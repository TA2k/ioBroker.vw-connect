.class public final Lxg0/b;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lkf0/o;

.field public final i:Lud0/b;

.field public final j:Lrq0/f;

.field public final k:Lij0/a;


# direct methods
.method public constructor <init>(Lkf0/o;Lud0/b;Lrq0/f;Lij0/a;)V
    .locals 2

    .line 1
    new-instance v0, Lxg0/a;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lxg0/a;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lxg0/b;->h:Lkf0/o;

    .line 12
    .line 13
    iput-object p2, p0, Lxg0/b;->i:Lud0/b;

    .line 14
    .line 15
    iput-object p3, p0, Lxg0/b;->j:Lrq0/f;

    .line 16
    .line 17
    iput-object p4, p0, Lxg0/b;->k:Lij0/a;

    .line 18
    .line 19
    new-instance p1, Lvo0/e;

    .line 20
    .line 21
    const/4 p2, 0x0

    .line 22
    const/16 p3, 0x18

    .line 23
    .line 24
    invoke-direct {p1, p0, p2, p3}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 28
    .line 29
    .line 30
    return-void
.end method
