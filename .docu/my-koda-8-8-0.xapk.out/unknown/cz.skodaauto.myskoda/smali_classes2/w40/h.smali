.class public final Lw40/h;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lnn0/u;

.field public final i:Lnn0/v;

.field public final j:Lu40/m;

.field public final k:Lud0/b;

.field public final l:Lrq0/f;

.field public final m:Lij0/a;


# direct methods
.method public constructor <init>(Lnn0/u;Lnn0/v;Lu40/m;Lud0/b;Lrq0/f;Lij0/a;)V
    .locals 3

    .line 1
    new-instance v0, Lw40/g;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    invoke-direct {v0, v1, v1, v2}, Lw40/g;-><init>(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lw40/h;->h:Lnn0/u;

    .line 13
    .line 14
    iput-object p2, p0, Lw40/h;->i:Lnn0/v;

    .line 15
    .line 16
    iput-object p3, p0, Lw40/h;->j:Lu40/m;

    .line 17
    .line 18
    iput-object p4, p0, Lw40/h;->k:Lud0/b;

    .line 19
    .line 20
    iput-object p5, p0, Lw40/h;->l:Lrq0/f;

    .line 21
    .line 22
    iput-object p6, p0, Lw40/h;->m:Lij0/a;

    .line 23
    .line 24
    new-instance p1, Lw40/f;

    .line 25
    .line 26
    const/4 p2, 0x0

    .line 27
    const/4 p3, 0x0

    .line 28
    invoke-direct {p1, p0, p2, p3}, Lw40/f;-><init>(Lw40/h;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 32
    .line 33
    .line 34
    return-void
.end method
